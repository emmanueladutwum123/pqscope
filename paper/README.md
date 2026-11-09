# Paper

*Declared vs. Deployed: A Multi-Layer Measurement of Post-Quantum Readiness in U.S. Federal and
Critical Open-Source Infrastructure.* Draft.

Two builds share every section and generated number:

| File | What it is |
|---|---|
| `main.tex` → `main.pdf` | The named preprint, for arXiv |
| `imc.tex` → `imc.pdf` | The anonymous submission to ACM IMC 2027, Cycle 2 (abstract 31 March 2027, paper 7 April 2027). It uses the format IMC requires: `acmart` with `sigconf,anonymous,nonacm`, 10pt, letter paper, numbered pages, at most 13 pages before the references. It hides the author, the repository link and the revision hashes, and calls the tool AnonPQ. |

`common.tex` holds the shared preamble, and `sections/body.tex` the page-limited body. The
appendices hold the sections IMC requires: Ethics, Open Science and Generative AI.

**Before submitting:**

- Write the Generative AI appendix (`sections/appendix.tex`). IMC requires it, and the
  placeholder says what it needs to cover.
- Create the anonymized artifact repository with [Anonymous GitHub](https://anonymous.4open.science)
  and put its link on the submission site. It exists:
  `https://anonymous.4open.science/r/pq-readiness-imc27`, pinned to a commit, expiring
  7 November 2027. Matching is case-insensitive but whole-word, and `_` is part of a word, so
  compounds need their own lines, longest first:

  ```
  emmanueladutwum123
  emmanueladutwum
  Emmanuel
  Adutwum
  PQSCOPE_REQUIRE_DOCKER=>ANONPQ_REQUIRE_DOCKER
  PQSCOPE_RUN_MAIN=>ANONPQ_RUN_MAIN
  pqscope_revision=>anonpq_revision
  pqscope_version=>anonpq_version
  pqscopeFindingId=>anonpqFindingId
  pqscope_1=>anonpq_1
  pqscope_=>anonpq_
  pqscope=>anonpq
  ```

  Before submitting, point it at the latest commit and recheck it for leaks. It can't see
  inside compressed files,
  so `paper/data/raw/` must stay free of names: the archives there carry no owner names, and
  `measure/rq3.sh` writes them that way.

```sh
make paper          # regenerate numbers, check them, build main.pdf and imc.pdf (needs tectonic)
make paper-check    # what CI runs: generated files current, no typed numbers, tests
```

## No number is typed by hand

| Path | What it is | Edited by |
|---|---|---|
| `data/` | Measurement outputs; see [data/README.md](data/README.md) | `make eval`, `make bench`, `measure/rq2.sh`, `measure/rq3.sh` |
| `gen.py` | Reads `data/`, writes `generated/` | hand |
| `generated/` | `numbers.tex` (one `\data{key}` per value), tables, figures | `gen.py` only |
| `main.tex`, `sections/` | The prose | hand, numbers only through `\data{key}` |
| `refs.bib` | References, each checked against its source | hand |

To use a number in the text, compute it in `gen.py`, give it a key with `o.put(...)`, and write
`\data{key}`. An undefined key stops the LaTeX build. `check_numbers.py` fails on digits in the
prose, except names that contain them (X25519, FIPS 203, TLS 1.3, IR 8547 ...) and IR 8547's
dates. When the text claims something about the data in words, such as "every miss is a hard
positive", `gen.py` checks it and stops if new data contradict it, naming the section to
revise.

`generated/` is committed so the paper builds without Python, and CI fails if it is out of date.

## Building

[tectonic](https://tectonic-typesetting.github.io) builds the PDF and downloads the LaTeX
packages it needs on first use. The draft uses the two-column `article` class; switching to a
venue's template means changing `main.tex` only.
