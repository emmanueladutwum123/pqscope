#!/usr/bin/env python3
"""Manual audit of RQ3's findings: a precision estimate in the wild.

    python3 measure/rq3_audit.py sample     # write paper/data/rq3_audit_sample.csv
    python3 measure/rq3_audit.py fetch      # gather evidence for each sampled finding
    python3 measure/rq3_audit.py verify     # OpenSSL reading of each config finding's certificate or key
    python3 measure/rq3_audit.py sheet      # local HTML page for confirming the labels
    python3 measure/rq3_audit.py report     # write paper/data/rq3_audit_summary.csv

`sample` draws a seeded random sample of quantum-vulnerable findings found by a
layer (not derived), stratified by layer: PER_LAYER from each layer, or all of
a layer with fewer. Within a layer every finding is equally likely, so the
sample estimates that layer's precision over its findings.

`fetch` downloads, for each sampled finding, the file it points at from the
project's repository at the scanned commit, and writes what an auditor needs
to measure/_out/audit/: the lines around the finding, an independent OpenSSL
reading of certificates and keys, and whether a binary contains the symbols
the finding names. It reads public files only and runs nothing it downloads.

Labels are recorded in paper/data/rq3_audit.csv (see docs/measurement.md).
Standard library only; certificates and keys are read with the openssl CLI.
"""

import csv
import json
import os
import random
import re
import subprocess
import sys
import tarfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "paper", "data")
ARCHIVE = os.path.join(DATA, "raw", "rq3_findings.tar.gz")
SAMPLE = os.path.join(DATA, "rq3_audit_sample.csv")
OUT = os.path.join(ROOT, "measure", "_out", "audit")

SEED = 20261110
PER_LAYER = 50
LAYERS = ["source", "config", "deps", "binary"]
CONTEXT = 4  # lines either side of the finding

FIELDS = ["audit_id", "repo", "commit", "layer", "path", "line", "symbol", "algorithm",
          "params", "primitive", "rule_id", "evidence", "url"]


def load_findings():
    commits = {}
    with open(os.path.join(DATA, "rq3_projects.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["status"] == "scanned":
                commits[r["repo"]] = r["commit"]
    by_layer = {l: [] for l in LAYERS}
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        for m in tar.getmembers():
            name = os.path.basename(m.name)
            if not m.isfile() or not name.endswith(".json") or name.startswith("._"):
                continue
            repo = name[:-5].replace("__", "/", 1)
            for f in json.load(tar.extractfile(m)):
                if f.get("derived") or f["asset"]["quantum"] != "vulnerable":
                    continue
                by_layer[f["location"]["layer"]].append((repo, commits[repo], f))
    for l in by_layer:
        by_layer[l].sort(key=lambda t: (t[0], t[2]["id"]))
    return by_layer


def sample():
    by_layer = load_findings()
    rng = random.Random(SEED)
    rows = []
    for layer in LAYERS:
        pool = by_layer[layer]
        picked = pool if len(pool) <= PER_LAYER else rng.sample(pool, PER_LAYER)
        for repo, commit, f in sorted(picked, key=lambda t: (t[0], t[2]["location"]["path"], t[2]["location"].get("line", 0))):
            loc = f["location"]
            line = loc.get("line", 0) or 0
            url = f"https://github.com/{repo}/blob/{commit}/{loc['path']}" + (f"#L{line}" if line else "")
            rows.append({
                "repo": repo, "commit": commit, "layer": layer, "path": loc["path"], "line": line,
                "symbol": loc.get("symbol", ""), "algorithm": f["asset"]["algorithm"],
                "params": f["asset"]["params"], "primitive": f["asset"]["primitive"],
                "rule_id": f["rule_id"], "evidence": f.get("evidence", "")[:300], "url": url,
            })
    for i, r in enumerate(rows, 1):
        r["audit_id"] = f"A{i:03d}"
    with open(SAMPLE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    sizes = {l: len(by_layer[l]) for l in LAYERS}
    print(f"population {sizes}; sampled {len(rows)} (seed {SEED}, {PER_LAYER} per layer) -> {os.path.relpath(SAMPLE, ROOT)}")


def fetch_bytes(repo, commit, path):
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/{urllib.request.quote(path)}"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                return r.read()
        except Exception as e:  # noqa: BLE001 - report and retry any fetch failure
            err = e
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"{url}: {err}")


def openssl_reading(data):
    """Algorithm and size of each certificate or key in PEM data, read by openssl."""
    out = []
    text = data.decode("latin-1")
    for m in re.finditer(r"(-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \2-----)", text, re.S):
        pem, kind = m.group(1), m.group(2)
        if "CERTIFICATE" in kind and "REQUEST" not in kind:
            cmd = ["openssl", "x509", "-noout", "-text"]
        elif "PRIVATE KEY" in kind:
            out.append(f"{kind}: private key present (not read)")
            continue
        elif "PUBLIC KEY" in kind:
            cmd = ["openssl", "pkey", "-pubin", "-noout", "-text_pub"]
        elif "REQUEST" in kind:
            cmd = ["openssl", "req", "-noout", "-text"]
        else:
            out.append(f"{kind}: not parsed")
            continue
        p = subprocess.run(cmd, input=pem.encode(), capture_output=True)
        txt = p.stdout.decode("latin-1")
        keep = [l.strip() for l in txt.splitlines()
                if re.search(r"Public Key Algorithm|Public-Key:|ASN1 OID|NIST CURVE|Signature Algorithm", l)]
        out.append(f"{kind}: " + ("; ".join(dict.fromkeys(keep)) if keep else f"openssl could not parse ({p.stderr.decode()[:80].strip()})"))
    return out


def read_one(kind, pem_or_der, der=False):
    """OpenSSL's reading of one certificate, CSR or key: algorithm, size, signature."""
    if "CERTIFICATE" in kind and "REQUEST" not in kind:
        cmd = ["openssl", "x509", "-noout", "-text"] + (["-inform", "DER"] if der else [])
    elif "REQUEST" in kind:
        cmd = ["openssl", "req", "-noout", "-text"]
    elif "PUBLIC KEY" in kind:
        cmd = ["openssl", "pkey", "-pubin", "-noout", "-text_pub"]
    else:  # a private key: print only its public half
        cmd = ["openssl", "pkey", "-noout", "-text_pub"]
    p = subprocess.run(cmd, input=pem_or_der, capture_output=True)
    txt = p.stdout.decode("latin-1")
    keep = [l.strip() for l in txt.splitlines()
            if re.search(r"Public Key Algorithm|Public-Key:|ASN1 OID|NIST CURVE|Signature Algorithm|ED25519|ED448", l)]
    return "; ".join(dict.fromkeys(keep)) if keep else f"unreadable ({p.stderr.decode('latin-1')[:80].strip()})"


def at_line(data, line):
    """The PEM block that starts at or encloses `line`, else the whole file as DER."""
    text = data.decode("latin-1")
    starts = [m for m in re.finditer(r"-----BEGIN ([A-Z0-9 ]+)-----", text)]
    if not starts:
        return "DER", read_one("CERTIFICATE", data, der=True)
    best = None
    for m in starts:
        if text.count("\n", 0, m.start()) + 1 <= max(line, 1):
            best = m
    best = best or starts[0]
    end = text.find(f"-----END {best.group(1)}-----", best.end())
    pem = text[best.start():end + len(best.group(1)) + 14]
    return best.group(1), read_one(best.group(1), pem.encode("latin-1"))


def verify():
    """Add OpenSSL's reading of the exact certificate or key behind each config finding."""
    with open(SAMPLE, newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["layer"] == "config"]
    for r in rows:
        dest = os.path.join(OUT, r["audit_id"] + ".json")
        rec = json.load(open(dest, encoding="utf-8"))
        data = fetch_bytes(r["repo"], r["commit"], r["path"])
        kind, reading = at_line(data, int(r["line"] or 0))
        rec["openssl_at_line"] = f"{kind}: {reading}"
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=1)
        print(r["audit_id"], rec["openssl_at_line"][:200])


def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return p, max(0.0, c - h), min(1.0, c + h)


# Library capabilities the audit found wrong: these libraries offer RSA for
# signatures only, so an RSA key-transport (pke) finding from them is false.
RSA_SIGNATURE_ONLY = {"deps.rustls", "deps.ring"}


def report():
    """Precision per layer and weighted, and what the found error classes change."""
    with open(os.path.join(DATA, "rq3_audit.csv"), newline="", encoding="utf-8") as f:
        labels = list(csv.DictReader(f))
    by_layer = load_findings()
    pop = {l: len(by_layer[l]) for l in LAYERS}
    rows = [["scope", "metric", "k", "n", "share", "ci95_low", "ci95_high", "population"]]
    weighted = 0.0
    for layer in LAYERS:
        ls = [r for r in labels if r["layer"] == layer]
        k = sum(r["quantum_vulnerable_correct"] == "yes" for r in ls)
        ka = sum(r["algorithm_correct"] == "yes" and r["quantum_vulnerable_correct"] == "yes" for r in ls)
        for metric, kk in (("precision", k), ("precision_exact_algorithm", ka)):
            p, lo, hi = wilson(kk, len(ls))
            rows.append([layer, metric, kk, len(ls), f"{p:.4f}", f"{lo:.4f}", f"{hi:.4f}", pop[layer]])
        weighted += pop[layer] * k / len(ls)
    total = sum(pop.values())
    rows.append(["all", "precision_weighted_by_layer", "", sum(1 for _ in labels), f"{weighted / total:.4f}", "", "", total])
    k = sum(r["quantum_vulnerable_correct"] == "yes" for r in labels)
    rows.append(["all", "unconfirmed_labels", sum(1 for r in labels if not r["confirmed_by"]), len(labels), "", "", "", ""])

    # Population checks for the error classes the audit found.
    projects = {}
    for layer in LAYERS:
        for repo, _, f in by_layer[layer]:
            projects.setdefault(repo, []).append(f)
    scanned = sum(1 for _ in csv.DictReader(open(os.path.join(DATA, "rq3_projects.csv"), encoding="utf-8")) if _["status"] == "scanned")

    def is_rsa_pke_error(f):
        return f["rule_id"] in RSA_SIGNATURE_ONLY and f["asset"]["algorithm"] == "RSA" and f["asset"]["primitive"] == "pke"

    errs = sum(is_rsa_pke_error(f) for fs in projects.values() for f in fs)
    any_changed = sum(1 for fs in projects.values() if all(is_rsa_pke_error(f) for f in fs))
    rows.append(["deps", "rsa_pke_from_signature_only_libraries", errs, pop["deps"], f"{errs / pop['deps']:.4f}", "", "", ""])
    rows.append(["projects", "any_layer_status_changed_by_rsa_pke_errors", any_changed, scanned, "", "", "", ""])

    deps_projects = [repo for repo, fs in projects.items() if any(f["location"]["layer"] == "deps" for f in fs)]
    stdlib_only = [repo for repo in deps_projects
                   if all(f["rule_id"] == "deps.go-stdlib" for f in projects[repo] if f["location"]["layer"] == "deps")]
    stdlib_findings = sum(f["rule_id"] == "deps.go-stdlib" for _, _, f in by_layer["deps"])
    rows.append(["deps", "findings_from_go_toolchain_directive", stdlib_findings, pop["deps"], f"{stdlib_findings / pop['deps']:.4f}", "", "", ""])
    rows.append(["projects", "deps_vulnerable", len(deps_projects), scanned, f"{len(deps_projects) / scanned:.4f}", "", "", ""])
    rows.append(["projects", "deps_vulnerable_only_via_go_toolchain", len(stdlib_only), scanned, f"{len(stdlib_only) / scanned:.4f}", "", "", ""])
    out = os.path.join(DATA, "rq3_audit_summary.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)
    for r in rows:
        print("\t".join(str(x) for x in r))


def sheet():
    """A local HTML page for confirming the labels: one card per finding."""
    import html
    with open(SAMPLE, newline="", encoding="utf-8") as f:
        sample = {r["audit_id"]: r for r in csv.DictReader(f)}
    with open(os.path.join(DATA, "rq3_audit.csv"), newline="", encoding="utf-8") as f:
        labels = list(csv.DictReader(f))
    cards = []
    for lab in labels:
        s = sample[lab["audit_id"]]
        ev = json.load(open(os.path.join(OUT, lab["audit_id"] + ".json"), encoding="utf-8"))
        detail = ev.get("openssl_at_line") or "\n".join(ev.get("context", [])) or json.dumps(ev.get("binary_contains", {}))
        ok = lab["quantum_vulnerable_correct"] == "yes"
        cards.append(f"""<section class="{'ok' if ok else 'bad'}">
<h2>{lab['audit_id']} &middot; {html.escape(s['layer'])} &middot; proposed: {'correct' if ok else 'FALSE POSITIVE'} ({html.escape(lab['category'])})</h2>
<p><b>{html.escape(s['algorithm'])} {html.escape(s['params'])} {html.escape(s['primitive'])}</b> in <a href="{html.escape(s['url'])}" target="_blank">{html.escape(s['repo'])}/{html.escape(s['path'])}{':' + s['line'] if s['line'] not in ('', '0') else ''}</a></p>
<p>pqscope said: {html.escape(s['evidence'])}</p>
<pre>{html.escape(detail)}</pre>
<p><i>Reason:</i> {html.escape(lab['reason'])}</p></section>""")
    page = f"""<!doctype html><meta charset="utf-8"><title>RQ3 audit review</title>
<style>body{{font:14px/1.45 -apple-system,sans-serif;max-width:900px;margin:2em auto;padding:0 1em}}
section{{border:1px solid #ccc;border-left:6px solid #2a7;border-radius:6px;padding:.6em 1em;margin:1em 0}}
section.bad{{border-left-color:#c33}} h2{{font-size:15px;margin:.2em 0}} pre{{background:#f5f5f5;padding:.5em;overflow-x:auto;font-size:12px}}</style>
<h1>RQ3 audit: {len(labels)} findings to confirm</h1>
<p>For each card, open the link, check the proposed label, and fix it in paper/data/rq3_audit.csv if you disagree.
When you have checked a row, put your name in its confirmed_by column.</p>
{''.join(cards)}"""
    dest = os.path.join(OUT, "review.html")
    with open(dest, "w", encoding="utf-8") as f:
        f.write(page)
    print(os.path.relpath(dest, ROOT))


def fetch():
    os.makedirs(OUT, exist_ok=True)
    with open(SAMPLE, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    cache = {}
    for r in rows:
        dest = os.path.join(OUT, r["audit_id"] + ".json")
        if os.path.exists(dest):
            continue
        key = (r["repo"], r["commit"], r["path"])
        rec = {k: r[k] for k in FIELDS}
        try:
            if key not in cache:
                cache[key] = fetch_bytes(*key)
                time.sleep(0.3)
            data = cache[key]
            rec["size"] = len(data)
            line = int(r["line"] or 0)
            binary = b"\0" in data[:8000]
            if r["layer"] == "binary" or binary:
                syms = re.findall(r"[A-Za-z_][A-Za-z0-9_]+", r["evidence"])
                rec["binary_contains"] = {s: (s.encode() in data) for s in syms if "_" in s or s.isupper()}
            else:
                lines = data.decode("utf-8", "replace").splitlines()
                lo, hi = max(1, line - CONTEXT), min(len(lines), line + CONTEXT) if line else min(len(lines), 12)
                rec["context"] = [f"{n}: {lines[n - 1]}" for n in range(lo if line else 1, hi + 1)]
                if r["layer"] == "config" and b"-----BEGIN" in data:
                    rec["openssl"] = openssl_reading(data)
        except Exception as e:  # noqa: BLE001 - record the failure for the auditor
            rec["fetch_error"] = str(e)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=1)
    errors = sum(1 for r in rows if "fetch_error" in json.load(open(os.path.join(OUT, r["audit_id"] + ".json"))))
    print(f"evidence for {len(rows)} findings in {os.path.relpath(OUT, ROOT)} ({errors} fetch errors)")


if __name__ == "__main__":
    {"sample": sample, "fetch": fetch, "verify": verify, "report": report, "sheet": sheet}[sys.argv[1] if len(sys.argv) > 1 else "sample"]()
