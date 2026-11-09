#!/usr/bin/env python3
"""Tests for the paper's generator and number check. Standard library only.

    python3 -m unittest discover -s paper -p 'test_*.py'
"""

import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import check_numbers  # noqa: E402
import gen  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def check_text(text):
    with tempfile.NamedTemporaryFile("w", suffix=".tex", delete=False, encoding="utf-8") as f:
        f.write(text)
    try:
        return check_numbers.check(f.name)
    finally:
        os.unlink(f.name)


class CheckNumbersTest(unittest.TestCase):
    def test_typed_number_fails(self):
        self.assertTrue(check_text("Adoption is 57.6\\% of endpoints."))
        self.assertTrue(check_text("We scanned 97 projects."))
        self.assertTrue(check_text("a 1,429-byte ClientHello"))

    def test_generated_and_named_pass(self):
        self.assertEqual(check_text("Adoption is \\data{rqtwo-ep-share} of endpoints."), [])
        self.assertEqual(check_text("X25519MLKEM768 and ML-KEM-768 under TLS~1.3 and FIPS~203"), [])
        self.assertEqual(check_text("as \\cite{fips203,ir8547} says, see Table~\\ref{tab:rq1-tools}"), [])
        self.assertEqual(check_text("% a comment with 42 in it\nprose"), [])

    def test_name_split_across_lines(self):
        self.assertEqual(check_text("OpenSSL ships ML-KEM since version\n3.5"), [])

    def test_sources_pass(self):
        self.assertEqual(check_numbers.main(), 0)


class GenerateTest(unittest.TestCase):
    def test_generated_is_current(self):
        self.assertEqual(run_check(), 0)

    def test_every_data_key_is_defined(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen.generate(tmp)
            with open(os.path.join(tmp, "numbers.tex"), encoding="utf-8") as f:
                defined = set(re.findall(r"\\csname pqd@([a-z0-9-]+)\\endcsname", f.read()))
        used = set()
        for root, _, files in os.walk(HERE):
            if "generated" in root:
                continue
            for name in files:
                if name.endswith(".tex"):
                    with open(os.path.join(root, name), encoding="utf-8") as f:
                        text = re.sub(r"(?<!\\)%.*", "", f.read())
                        used |= set(re.findall(r"\\data\{([^}]+)\}", text))
        self.assertEqual(sorted(used - defined), [])

    def test_formatting(self):
        self.assertEqual(gen.num(1130), "1,130")
        self.assertEqual(gen.pct(0.5765), "57.6\\%")
        self.assertEqual(gen.pct_ci(0.5545, 0.5982), "55.5--59.8\\%")
        self.assertEqual(gen.dur(70708), "70.7\\,\\textmu s")
        self.assertEqual(gen.dur(151481584), "151\\,ms")
        self.assertEqual(gen.dur(2597166), "2.60\\,ms")
        self.assertEqual(gen.tex("a_b & 50%"), "a\\_b \\& 50\\%")


def run_check():
    argv = sys.argv
    sys.argv = ["gen.py", "--check"]
    try:
        return gen.main()
    finally:
        sys.argv = argv


if __name__ == "__main__":
    unittest.main()
