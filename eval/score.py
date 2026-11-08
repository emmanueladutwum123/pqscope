#!/usr/bin/env python3
"""Recompute RQ1 precision, recall and F1 from rq1_items.csv.

`pqscope eval` writes both the per-item outcomes (rq1_items.csv) and the
aggregate table (rq1_summary.csv). This script recomputes the aggregates from
the items with an independent implementation and exits non-zero if any number
differs, so the published table cannot drift from the evidence.

Usage: eval/score.py [paper/data]
Standard library only.
"""
import csv
import sys
from collections import defaultdict
from pathlib import Path


def ratio(a, b):
    return 1.0 if b == 0 else a / b


def metrics(tp, fp, fn):
    p, r = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = 0.0 if p + r == 0 else 2 * p * r / (p + r)
    return p, r, f1


def main(data_dir):
    d = Path(data_dir)
    with open(d / "rq1_items.csv", newline="") as f:
        items = list(csv.DictReader(f))
    with open(d / "rq1_corpus.csv", newline="") as f:
        corpus = list(csv.DictReader(f))
    with open(d / "rq1_tools.csv", newline="") as f:
        tools = [t["tool"] for t in csv.DictReader(f) if t["status"] in ("ran", "partial")]
    with open(d / "rq1_summary.csv", newline="") as f:
        summary = {(r["tool"], r["granularity"], r["layer"], r["language"]): r for r in csv.DictReader(f)}

    counts = defaultdict(lambda: [0, 0, 0])
    cases = defaultdict(set)
    index = {"tp": 0, "fp": 1, "fn": 2}
    for it in items:
        for key in ((it["layer"], it["language"]), (it["layer"], "all"), ("all", "all")):
            k = (it["tool"], it["granularity"]) + key
            counts[k][index[it["outcome"]]] += 1
            cases[k].add(it["case"])
    for tool in tools:
        for g in ("file", "line"):
            for c in corpus:
                for key in ((c["layer"], c["language"]), (c["layer"], "all"), ("all", "all")):
                    k = (tool, g) + key
                    counts.setdefault(k, [0, 0, 0])
                    cases[k].add(c["case"])

    problems = []
    for k, (tp, fp, fn) in counts.items():
        row = summary.get(k)
        if row is None:
            problems.append(f"{k}: missing from rq1_summary.csv")
            continue
        p, r, f1 = metrics(tp, fp, fn)
        expected = {"cases": len(cases[k]), "tp": tp, "fp": fp, "fn": fn}
        for field, value in expected.items():
            if int(row[field]) != value:
                problems.append(f"{k}: {field} {row[field]} != {value}")
        for field, value in (("precision", p), ("recall", r), ("f1", f1)):
            if abs(float(row[field]) - round(value, 4)) > 1e-9:
                problems.append(f"{k}: {field} {row[field]} != {value:.4f}")
    for k in summary:
        if k not in counts:
            problems.append(f"{k}: in rq1_summary.csv but has no items")

    if problems:
        print("rq1_summary.csv disagrees with rq1_items.csv:", file=sys.stderr)
        for p in problems[:20]:
            print("  " + p, file=sys.stderr)
        return 1
    print(f"score.py: {len(counts)} summary rows recomputed from {len(items)} items; all agree")
    for tool in sorted({k[0] for k in counts}):
        tp, fp, fn = counts[(tool, "file", "all", "all")]
        p, r, f1 = metrics(tp, fp, fn)
        print(f"  {tool:16s} file-level  P={p:.4f} R={r:.4f} F1={f1:.4f}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "paper/data"))
