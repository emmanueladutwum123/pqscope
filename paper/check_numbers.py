#!/usr/bin/env python3
"""Fail if a number is typed into the paper's sources instead of generated.

Every measured number must come from paper/data through gen.py and \\data{key}.
This strips commands that carry no prose (\\data, \\cite, \\ref, \\input, ...)
and names that contain digits but are not measurements (X25519, FIPS 203,
TLS 1.3, ...), then reports any digit left in main.tex or sections/*.tex.

    python3 paper/check_numbers.py
"""

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Commands whose arguments are not prose.
STRIP_COMMANDS = re.compile(
    r"\\(data|cite[tp]?|ref|label|input|url|setlength|begin|end)\*?(\[[^\]]*\])?(\{[^{}]*\})+"
)

# Names and fixed constants that contain digits. Each is a standard, an
# algorithm, a protocol version, a policy date or a method constant, never a
# measurement.
ALLOWED = [
    r"X25519MLKEM768", r"X25519", r"X448", r"Ed25519",
    r"ML-KEM-\d+", r"ML-DSA-\d+", r"SLH-DSA-\d+[sf]?", r"RSA-\d+", r"P-\d+",
    r"AES-\d+", r"SHA-\d+", r"secp\d+r1",
    r"FIPS~\d+(-\d+)?", r"IR~8547", r"RFC~\d+", r"SP~800-131A", r"EO~14412",
    r"Executive\s+Order~14412", r"M-26-15", r"CNSA~2\.0", r"TLS~1\.[23]",
    r"SARIF~2\.1\.0", r"CycloneDX~1\.6", r"Go~1\.24", r"version\s+3\.5", r"OpenSSL~3\.5",
    r"Apache~2\.0", r"\\RQ\{\d\}", r"RQ\d", r"port\s+443", r"95\\%",
    r"\bF1\b", r"\bp50\b", r"\bp99\b", r"\$\\le\$1\.2", r"rq\d\.sh",
    # SP 800-131A's minimum security strength.
    r"112\s+bits",
    # Policy dates from IR 8547 and the standards' publication years.
    r"\b(2024|2030|2035)\b", r"October\s+2026",
]
ALLOWED_RE = re.compile("|".join(f"(?:{a})" for a in ALLOWED))


def strip(text):
    # Comments, but not escaped percent signs.
    text = re.sub(r"(?<!\\)%.*", "", text)
    prev = None
    while prev != text:
        prev = text
        text = STRIP_COMMANDS.sub(" ", text)
    return text


def check(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if os.path.basename(path) == "main.tex":
        # The preamble is layout, not prose.
        raw = raw[raw.index("\\begin{document}"):]
    problems = []
    text = strip(raw)
    # Join lines so names split across a line break still match.
    flat = re.sub(r"\s+", " ", text)
    flat = ALLOWED_RE.sub(" ", flat)
    for m in re.finditer(r"\S*\d\S*", flat):
        start = max(0, m.start() - 40)
        problems.append(f"{os.path.relpath(path, HERE)}: '{m.group(0)}' in ...{flat[start:m.end() + 40]}...")
    return problems


def main():
    files = [os.path.join(HERE, "main.tex")] + sorted(glob.glob(os.path.join(HERE, "sections", "*.tex")))
    problems = []
    for path in files:
        problems += check(path)
    if problems:
        print("numbers typed into the paper; generate them with gen.py and \\data{key}:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1
    print(f"no typed numbers in {len(files)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
