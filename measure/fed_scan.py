#!/usr/bin/env python3
"""Declared versus deployed on federal systems: scan each linked repository
together with its endpoint's RQ2 records, and let pqscope reconcile them.

    python3 measure/fed_scan.py scan       # clone, scan, write measure/_out/fed/findings/
    python3 measure/fed_scan.py analyze    # write paper/data/fed_pairs.csv and the raw archive

For each current link in paper/data/fed_links_current.csv, the endpoint's
findings are taken from RQ2's raw records (paper/data/raw/rq2_net.jsonl.gz):
nothing is probed. The repository is cloned shallow at its default branch,
scanned with `pqscope scan --with <endpoint findings> --json` (source, config,
deps and binary layers, reconciliation on), and deleted. Nothing in it is built
or run. Standard library only, plus git and the pqscope binary.
"""

import concurrent.futures
import csv
import gzip
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "paper", "data")
OUT = os.path.join(ROOT, "measure", "_out", "fed")
PQ = os.path.join(OUT, "pqscope")
TIMEOUT = 1800
JOBS = 3


def endpoint_findings():
    """Each probed host's findings from the RQ2 records."""
    by_host = {}
    with gzip.open(os.path.join(DATA, "raw", "rq2_net.jsonl.gz"), "rt", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            host = rec["target"].rsplit(":", 1)[0].lower()
            by_host[host] = rec.get("findings") or []
    return by_host


def links():
    with open(os.path.join(DATA, "fed_links_current.csv"), newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def scan_one(link, net_findings):
    repo, host = link["repo"], link["host"]
    key = repo.replace("/", "__")
    work = os.path.join(OUT, "clones", key)
    net = os.path.join(OUT, "net", key + ".json")
    dest = os.path.join(OUT, "findings", key + ".json")
    start = time.time()
    if os.path.exists(dest):
        return repo, "scanned (cached)", "", 0
    with open(net, "w") as f:
        json.dump(net_findings.get(host, []), f)
    shutil.rmtree(work, ignore_errors=True)
    env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1")
    status, commit = "", ""
    for attempt in range(2):
        p = subprocess.run(["git", "clone", "-q", "--depth", "1", "--single-branch", "--no-tags",
                            f"https://github.com/{repo}.git", work], env=env, capture_output=True, text=True)
        if p.returncode == 0:
            break
        shutil.rmtree(work, ignore_errors=True)
    else:
        status = "clone failed"
    if not status:
        commit = subprocess.run(["git", "-C", work, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        try:
            p = subprocess.run([PQ, "scan", work, "--with", net, "--json"], capture_output=True, text=True, timeout=TIMEOUT)
            if p.returncode == 0:
                findings = json.loads(p.stdout)
                # Paths relative to the clone, as RQ3 records them.
                with open(dest, "w") as f:
                    json.dump(findings, f)
                status = "scanned"
            else:
                status = f"scan failed (exit {p.returncode})"
        except subprocess.TimeoutExpired:
            status = f"scan timed out after {TIMEOUT}s"
    shutil.rmtree(work, ignore_errors=True)
    with open(os.path.join(OUT, "scans.tsv"), "a") as f:
        f.write(f"{repo}\t{commit}\t{status}\t{int(time.time() - start)}\n")
    return repo, status, commit, int(time.time() - start)


def scan():
    for d in ("clones", "net", "findings"):
        os.makedirs(os.path.join(OUT, d), exist_ok=True)
    subprocess.run(["go", "build", "-o", PQ, "./cmd/pqscope"], cwd=ROOT, check=True)
    net = endpoint_findings()
    todo = links()
    with concurrent.futures.ThreadPoolExecutor(JOBS) as ex:
        for repo, status, commit, secs in ex.map(lambda l: scan_one(l, net), todo):
            print(f"  {repo}: {status} ({secs}s)", flush=True)


QUANTUM_SAFE = {"safe", "hybrid"}


def analyze():
    scans = {}
    with open(os.path.join(OUT, "scans.tsv")) as f:
        for line in f:
            repo, commit, status, secs = line.rstrip("\n").split("\t")
            if status != "scanned (cached)":
                scans[repo] = (commit, status)
    rows = []
    for link in links():
        repo = link["repo"]
        commit, status = scans.get(repo, ("", "not run"))
        row = {k: link[k] for k in ("repo", "host", "agency", "link", "link_evidence", "status", "group", "asn", "as_description")}
        row.update({"commit": commit, "scan_status": status})
        path = os.path.join(OUT, "findings", repo.replace("/", "__") + ".json")
        if status == "scanned" and os.path.exists(path):
            fs = json.load(open(path))
            layer = lambda f: f["location"]["layer"]
            found = [f for f in fs if not f.get("derived")]
            pq = [f for f in found if f["asset"]["quantum"] in QUANTUM_SAFE and layer(f) != "network"]
            row["declares_pq_source"] = sum(1 for f in pq if layer(f) == "source")
            row["declares_pq_deps"] = sum(1 for f in pq if layer(f) == "deps")
            row["declares_pq_config"] = sum(1 for f in pq if layer(f) == "config")
            row["pq_libraries"] = ";".join(sorted({f["rule_id"].removeprefix("deps.") for f in pq if layer(f) == "deps"}))
            row["vulnerable_findings"] = sum(1 for f in found if f["asset"]["quantum"] == "vulnerable" and layer(f) != "network")
            for t in ("declared-pqc-deployed-classical", "config-overrides-library", "stale-dependency", "binary-without-source"):
                row["derived_" + t.replace("-", "_")] = sum(1 for f in fs if f.get("derived") == t)
        rows.append(row)
    fields = list(rows[0])
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    dest = os.path.join(DATA, "fed_pairs.csv")
    with open(dest, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    # Raw evidence, without owner names in the archive headers.
    os.makedirs(os.path.join(DATA, "raw"), exist_ok=True)
    arc = os.path.join(DATA, "raw", "fed_findings.tar.gz")
    with tarfile.open(arc, "w:gz") as tar:
        for name in sorted(os.listdir(os.path.join(OUT, "findings"))):
            info = tar.gettarinfo(os.path.join(OUT, "findings", name), arcname="./" + name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with open(os.path.join(OUT, "findings", name), "rb") as fh:
                tar.addfile(info, fh)
    print(f"{len(rows)} pairs -> {os.path.relpath(dest, ROOT)}; raw findings -> {os.path.relpath(arc, ROOT)}")


if __name__ == "__main__":
    {"scan": scan, "analyze": analyze}[sys.argv[1]]()
