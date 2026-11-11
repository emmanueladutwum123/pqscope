#!/usr/bin/env python3
"""Does the hosting provider or the agency explain RQ2's hybrid adoption?

    python3 measure/rq2_grouping.py    # write paper/data/rq2_grouping.csv

Over TLS-speaking endpoints, the outcome is whether the endpoint negotiated a
hybrid group. For a grouping G (autonomous system, or agency) we report the
information it carries about the outcome, I(Y;G) = H(Y) - H(Y|G), in bits and
as a share of H(Y), and the conditional informations I(Y;AS|agency) and
I(Y;agency|AS): what each grouping adds once the other is known. Groupings
with many small groups carry information by chance, so each value is compared
with the same statistic after shuffling the grouping's labels (within strata
of the other grouping for the conditional ones), repeated PERMUTATIONS times
with a fixed seed: we report the excess over the shuffled mean and the share
of shuffles that reach the observed value. Standard library only.
"""

import csv
import math
import os
import random
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "paper", "data")
SEED = 20261111
PERMUTATIONS = 2000
TLS = {"hybrid", "pq-only", "classical", "tls1.2-or-lower"}


def entropy(counts):
    n = sum(counts)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def cond_entropy(y, g):
    """H(Y | G) for parallel lists."""
    by = defaultdict(Counter)
    for yi, gi in zip(y, g):
        by[gi][yi] += 1
    n = len(y)
    return sum(sum(c.values()) / n * entropy(list(c.values())) for c in by.values())


def info(y, g):
    return entropy(list(Counter(y).values())) - cond_entropy(y, g)


def cond_info(y, g, z):
    """I(Y; G | Z) = H(Y|Z) - H(Y|G,Z)."""
    return cond_entropy(y, z) - cond_entropy(y, list(zip(g, z)))


def shuffled(labels, strata, rng):
    """Labels permuted within each stratum (one stratum when strata is None)."""
    if strata is None:
        out = labels[:]
        rng.shuffle(out)
        return out
    idx = defaultdict(list)
    for i, s in enumerate(strata):
        idx[s].append(i)
    out = labels[:]
    for ids in idx.values():
        vals = [labels[i] for i in ids]
        rng.shuffle(vals)
        for i, v in zip(ids, vals):
            out[i] = v
    return out


def main():
    rows = [r for r in csv.DictReader(open(os.path.join(DATA, "rq2_endpoints.csv"), newline="", encoding="utf-8"))
            if r["status"] in TLS and r["asn"]]
    y = [r["status"] == "hybrid" for r in rows]
    asn = [r["asn"] for r in rows]
    agency = [r["agency"] for r in rows]
    hy = entropy(list(Counter(y).values()))
    rng = random.Random(SEED)
    stats = [
        ("I(Y;AS)", lambda g=asn: info(y, g), asn, None),
        ("I(Y;agency)", lambda g=agency: info(y, g), agency, None),
        ("I(Y;AS|agency)", lambda g=asn: cond_info(y, g, agency), asn, agency),
        ("I(Y;agency|AS)", lambda g=agency: cond_info(y, g, asn), agency, asn),
    ]
    out = [["statistic", "bits", "share_of_entropy", "shuffled_mean_bits", "excess_bits",
            "excess_share_of_entropy", "p_value", "endpoints", "groups"]]
    for name, fn, labels, strata in stats:
        obs = fn()
        draws = [fn(shuffled(labels, strata, rng)) for _ in range(PERMUTATIONS)]
        mean = sum(draws) / len(draws)
        p = (1 + sum(d >= obs for d in draws)) / (1 + len(draws))
        out.append([name, f"{obs:.4f}", f"{obs / hy:.4f}", f"{mean:.4f}", f"{obs - mean:.4f}",
                    f"{(obs - mean) / hy:.4f}", f"{p:.4f}", len(rows), len(set(labels))])
    out.append(["H(Y)", f"{hy:.4f}", "1.0000", "", "", "", "", len(rows), ""])
    with open(os.path.join(DATA, "rq2_grouping.csv"), "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(out)
    for r in out:
        print("\t".join(str(x) for x in r))


if __name__ == "__main__":
    main()
