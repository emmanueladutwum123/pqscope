# Paper data

Every file here is generated. Never edit one by hand: rerun the target that writes it.

| Files | Written by | Research question |
|---|---|---|
| `rq1_*.csv` | `make eval` (or `make eval-score`), see [eval/README.md](../../eval/README.md) | RQ1: multi-layer versus single-layer detection, and layer ablation |
| `rq2_*.csv`, `raw/rq2_net.jsonl.gz` | `measure/rq2.sh`, see [docs/measurement.md](../../docs/measurement.md) | RQ2: hybrid key exchange on federal .gov |
| `rq2_trend/<YYYY-MM>/` | `measure/rq2-monthly.sh` (monthly, see [docs/measurement.md](../../docs/measurement.md#monthly-repeats)) | RQ2 repeated monthly from the same vantage point, for the trend |
| `rq3_*.csv`, `raw/rq3_findings.tar.gz` | `measure/rq3.sh`, see [docs/measurement.md](../../docs/measurement.md) | RQ3: quantum-vulnerable cryptography in critical open source |
| `rq3_audit*.csv` | `measure/rq3_audit.py`, see [docs/measurement.md](../../docs/measurement.md#audit-of-rq3s-findings) | RQ3: precision of a stratified sample of findings, from two independent annotations and the author's decisions |
| `risk_ablation*.csv` | `make risk-ablation`, see [docs/risk.md](../../docs/risk.md#ablation) | Risk score: how much each factor changes the ranking of RQ3's findings |
| `rq4_*.csv` | `make bench`, see [docs/bench.md](../../docs/bench.md) | RQ4: migration cost in bytes and latency |

`rq1_tools.csv` records which tools actually ran for the committed files. A tool listed as
`unavailable` contributed no rows to the other files.

`rq4_environment.csv` records the machine, kernel, Go version and pqscope revision the `rq4_*`
files were measured on. Latencies describe that machine only.
