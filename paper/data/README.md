# Paper data

Every file here is generated. Never edit one by hand: rerun the target that writes it.

| Files | Written by | Research question |
|---|---|---|
| `rq1_*.csv` | `make eval` (or `make eval-score`), see [eval/README.md](../../eval/README.md) | RQ1: multi-layer versus single-layer detection, and layer ablation |
| `rq4_*.csv` | `make bench`, see [docs/bench.md](../../docs/bench.md) | RQ4: migration cost in bytes and latency |

`rq1_tools.csv` records which tools actually ran for the committed files. A tool listed as
`unavailable` contributed no rows to the other files.

`rq4_environment.csv` records the machine, kernel, Go version and pqscope revision the `rq4_*`
files were measured on. Latencies describe that machine only.
