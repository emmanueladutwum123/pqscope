# Paper

*Declared vs. Deployed: A Multi-Layer Measurement of Post-Quantum Readiness in U.S. Federal and
Critical Open-Source Infrastructure.* Draft.

```sh
make paper          # regenerate numbers, check them, build paper/main.pdf (needs tectonic)
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
