#!/usr/bin/env python3
"""Link federal GitHub repositories to the federal .gov endpoints RQ2 measured.

    python3 measure/fed_link.py orgs     # list U.S. federal GitHub organizations
    python3 measure/fed_link.py repos    # list their public repositories (gh API)
    python3 measure/fed_link.py link     # write paper/data/fed_links.csv

The organizations are those GitHub lists under "U.S. Federal" in its public
registry of government accounts (github/government.github.com), at a pinned
commit. A repository is linked to an endpoint when its homepage field names
the endpoint's host exactly: the apex or www name of a federal .gov domain
that RQ2 probed. Nothing is probed here; the deployed side comes from RQ2's
records. Standard library and the gh CLI only.
"""

import csv
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "paper", "data")
OUT = os.path.join(ROOT, "measure", "_out", "fed")

REGISTRY_COMMIT = "f8acaec52db0631fea775feeaa6a829cd2e2781f"
REGISTRY_URL = (f"https://raw.githubusercontent.com/github/government.github.com/"
                f"{REGISTRY_COMMIT}/_data/governments.yml")


def orgs():
    with urllib.request.urlopen(REGISTRY_URL, timeout=60) as r:
        text = r.read().decode("utf-8")
    names, inside = [], False
    for line in text.splitlines():
        if line.startswith("U.S. Federal:"):
            inside = True
            continue
        if inside and line and not line.startswith((" ", "-", "#")):
            break
        if inside and line.strip().startswith("- "):
            names.append(line.strip()[2:].strip())
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "orgs.txt"), "w") as f:
        f.write("\n".join(names) + "\n")
    print(f"{len(names)} U.S. federal organizations (registry {REGISTRY_COMMIT[:7]})")


def repos():
    with open(os.path.join(OUT, "orgs.txt")) as f:
        names = [l.strip() for l in f if l.strip()]
    rows, missing = [], []
    for org in names:
        p = subprocess.run(["gh", "api", "--paginate", f"orgs/{org}/repos?per_page=100&type=public",
                            "--jq", ".[] | [.full_name, (.homepage // \"\"), .archived, .fork, .size, "
                                    ".pushed_at, .default_branch, (.language // \"\")] | @tsv"],
                           capture_output=True, text=True)
        if p.returncode != 0:
            missing.append(org)  # renamed, a user account, or gone
            continue
        for line in p.stdout.splitlines():
            rows.append(line.split("\t"))
    with open(os.path.join(OUT, "repos.tsv"), "w") as f:
        for r in rows:
            f.write("\t".join(r) + "\n")
    print(f"{len(rows)} public repositories; {len(missing)} organizations not listable: {', '.join(missing)}")


def host_of(homepage):
    h = homepage.strip()
    if not h:
        return ""
    if "://" not in h:
        h = "https://" + h
    try:
        return (urllib.parse.urlsplit(h).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def link():
    endpoints = {}
    with open(os.path.join(DATA, "rq2_endpoints.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            endpoints[r["host"].lower()] = r
    out = []
    with open(os.path.join(OUT, "repos.tsv")) as f:
        for line in f:
            full, homepage, archived, fork, size, pushed, branch, lang = line.rstrip("\n").split("\t")
            host = host_of(homepage)
            if host in endpoints:
                e = endpoints[host]
                out.append({"repo": full, "homepage": homepage, "host": host, "agency": e["agency"],
                            "status": e["status"], "group": e["group"], "asn": e["asn"],
                            "as_description": e["as_description"], "archived": archived, "fork": fork,
                            "size_kb": size, "pushed_at": pushed, "default_branch": branch, "language": lang})
    out.sort(key=lambda r: (r["host"], r["repo"]))
    dest = os.path.join(DATA, "fed_links.csv")
    with open(dest, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]) if out else ["repo"])
        w.writeheader()
        w.writerows(out)
    print(f"{len(out)} repositories linked to {len({r['host'] for r in out})} RQ2 endpoints -> {os.path.relpath(dest, ROOT)}")


def strength():
    """Mark each current link strong (the repository is the site) or weak (homepage only).

    Strong: a GitHub Pages CNAME file in the repository names the host, or the
    repository's name contains the whole domain (cfpb/consumerfinance.gov,
    cisagov/manage.get.gov). The rule is conservative on purpose: site
    repositories named otherwise (fecgov/fec-cms) count as weak.
    Only current links are kept: not archived, not a fork, and an endpoint
    that speaks TLS.
    """
    path = os.path.join(DATA, "fed_links.csv")
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    keep = [r for r in rows if r["archived"] == "false" and r["fork"] == "false"
            and r["status"] in ("hybrid", "pq-only", "classical", "tls1.2-or-lower")]
    for r in keep:
        p = subprocess.run(["gh", "api", f"repos/{r['repo']}/contents/CNAME", "--jq", ".content"],
                           capture_output=True, text=True)
        cname = ""
        if p.returncode == 0 and p.stdout.strip():
            import base64
            cname = base64.b64decode(p.stdout.strip()).decode("utf-8", "replace").strip().lower()
        name = r["repo"].split("/", 1)[1].lower()
        domain = r["host"].removeprefix("www.")
        if cname and cname.rstrip(".") == r["host"]:
            r["link"], r["link_evidence"] = "strong", f"CNAME file names {cname}"
        elif domain in name:
            r["link"], r["link_evidence"] = "strong", f"repository name contains {domain}"
        else:
            r["link"], r["link_evidence"] = "weak", "homepage field only"
    dest = os.path.join(DATA, "fed_links_current.csv")
    with open(dest, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(keep[0]))
        w.writeheader()
        w.writerows(keep)
    strong = [r for r in keep if r["link"] == "strong"]
    print(f"{len(keep)} current links: {len(strong)} strong, {len(keep) - len(strong)} weak -> {os.path.relpath(dest, ROOT)}")
    for r in strong:
        print(f"  {r['repo']:50} {r['host']:32} {r['status']:16} {r['link_evidence']}")


def meta():
    """paper/data/fed_meta.csv: what was listed, from where, and when."""
    import datetime
    with open(os.path.join(OUT, "orgs.txt")) as f:
        names = [l.strip() for l in f if l.strip()]
    owners, repos_n = set(), 0
    with open(os.path.join(OUT, "repos.tsv")) as f:
        for line in f:
            owners.add(line.split("\t", 1)[0].split("/", 1)[0].lower())
            repos_n += 1
    absent = [o for o in names if o.lower() not in owners]
    unlistable = [o for o in absent if subprocess.run(["gh", "api", f"orgs/{o}"], capture_output=True).returncode != 0]
    listed_at = datetime.datetime.fromtimestamp(os.path.getmtime(os.path.join(OUT, "repos.tsv")),
                                                datetime.timezone.utc).strftime("%Y-%m-%d")
    rows = [["key", "value"], ["registry_source", REGISTRY_URL], ["organizations", len(names)],
            ["organizations_unlistable", len(unlistable)], ["organizations_unlistable_names", ";".join(unlistable)],
            ["organizations_without_public_repos", len(absent) - len(unlistable)],
            ["repositories_listed", repos_n], ["listed_utc_date", listed_at],
            ["link_rule", "repository homepage host equals an RQ2 endpoint host"],
            ["strong_link_rule", "CNAME file names the host, or the repository name contains the whole domain"],
            ["current_rule", "not archived, not a fork, endpoint speaks TLS"]]
    with open(os.path.join(DATA, "fed_meta.csv"), "w", newline="") as f:
        csv.writer(f).writerows(rows)
    for r in rows[1:]:
        print(*r, sep="\t")


if __name__ == "__main__":
    {"orgs": orgs, "repos": repos, "link": link, "strength": strength, "meta": meta}[sys.argv[1]]()
