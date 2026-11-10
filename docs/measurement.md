# Measurement runs (RQ2, RQ3)

Two scripts produce the paper's measurement datasets. Each writes summary tables to
`paper/data/` and its raw evidence to `paper/data/raw/`, with a `*_meta.csv` recording sources,
hashes, dates and the pqscope revision. Every number in the tables is computed by
`pqscope measure` from the raw files. To recompute the tables from the raw evidence, rerun the
same subcommand on it.

## RQ2: hybrid key exchange on federal .gov

> What fraction of public federal `.gov` TLS endpoints negotiate hybrid post-quantum key
> exchange as of the scan date? Broken down by agency and hosting provider.

```sh
VANTAGE="where this runs" measure/rq2.sh
```

**Targets.** Every domain in CISA's federal `.gov` list (`current-federal.csv` in
[cisagov/dotgov-data](https://github.com/cisagov/dotgov-data)), at the commit current when the
run starts, which is recorded. The list holds registered domains, not websites. For each domain
the scan probes the two names a visitor types, the apex and `www.`, on port 443.

**Probe.** `pqscope net` with its defaults, at 10 connections per second, under the limits in
[scanning.md](scanning.md). Hosts on the opt-out list `measure/exclude.txt` are never contacted.
Each endpoint gets:

1. pqscope's own TLS 1.3 ClientHello. It offers X25519MLKEM768, X25519 and secp256r1, with key
   shares for the first two, as current browsers do. The probe reads the ServerHello and
   closes.
2. A standard `crypto/tls` handshake, which records the certificate chain and the TLS version.

**Classification** (`internal/measure.Classify`), from best to worst:

| Status | Meaning |
|---|---|
| `hybrid` | The ServerHello (or HelloRetryRequest) selected a hybrid group, such as X25519MLKEM768 |
| `pq-only` | It selected a pure post-quantum group |
| `classical` | It selected a classical group: X25519, P-256, ... |
| `tls1.2-or-lower` | No TLS 1.3 ServerHello, but the standard handshake succeeded below TLS 1.3 |
| `tls-error` | A TCP connection, but no usable handshake |
| `unreachable` | No TCP connection on 443 |
| `unresolvable` | No address in DNS |
| `excluded` | On the opt-out list |

The probe's ServerHello decides. The standard handshake decides only when the probe got none.
A domain takes the best status of its two endpoints.

**Adoption** is hybrid endpoints over endpoints that speak TLS: `hybrid`, `pq-only`,
`classical` or `tls1.2-or-lower`. It comes with a Wilson 95% interval. It is reported for
endpoints and domains, overall, by branch (executive, legislative, judicial), by agency, and
for endpoints by autonomous system. The AS comes from the address probed, mapped with
iptoasn.com's table (public domain), whose hash and Last-Modified date are recorded.

**Files:**

| File | Contents |
|---|---|
| `rq2_endpoints.csv` | One row per endpoint: domain, agency, address, AS, status, group, TLS version, leaf certificate algorithms, error |
| `rq2_summary.csv` | Counts per status and adoption share with interval, per scope and grouping |
| `rq2_certificates.csv` | Leaf certificate key and signature algorithms over TLS-speaking endpoints |
| `rq2_meta.csv` | Sources, hashes, run times, rate, vantage, revision |
| `raw/rq2_net.jsonl.gz` | Every `pqscope net` record |

`pqscope measure rq2` fails if any endpoint lacks a record, so a partial scan can't be
published as a complete one.

**Limits:**

- **Server software is not measured.** It would need an HTTP request, and the probe sends
  nothing beyond the handshake (§6.5 of the spec). The hosting breakdown uses the autonomous
  system, which identifies CDNs and clouds, not server software.
- **One vantage point, one moment.** CDNs answer from the edge nearest the scanner. Results can
  differ by location and over time; the longitudinal stretch goal repeats the scan.
- **Apex and `www.` only.** Federal services on other names (`login.`, `api.`, subdomains of
  agency sites) are not in the list and not measured.
- **One address per name.** The probe connects to the first resolved address. A name behind
  several providers is measured at one of them.
- **Hybrid when offered.** A server that supports hybrid groups but prefers X25519 when both
  are offered counts as classical. That is what a browser negotiates with it.
- **No reverse DNS.** The scan's source address may not point back to the project. See the
  vantage recorded in `rq2_meta.csv`.

### Monthly repeats

The scan in `paper/data/rq2_*` is the baseline. Monthly repeats make it a trend:

```sh
measure/rq2-monthly-install.sh            # once, from the baseline's network
measure/rq2-monthly-install.sh --remove   # to stop
```

The installer adds a launchd job for the current user. It runs `measure/rq2-monthly.sh` on the
8th of each month at 12:48 local time, or at the next wake if the Mac was asleep. Each run
writes `paper/data/rq2_trend/<YYYY-MM>/`, with the same tables and raw records as the baseline,
the same rate and the same opt-out list. The script never commits or pushes: review each
snapshot, then commit it.

The vantage point is part of the measurement. The installer records the default gateway's
hardware address, and a run on any other network is skipped with a notification, so every
snapshot comes from the same connection. A month that already has a snapshot is skipped too.
Progress and failures go to `measure/_out/monthly/monthly.log`, and a failed run keeps nothing.

## RQ3: quantum-vulnerable cryptography in critical open source

> How prevalent is quantum-vulnerable crypto in the top-N critical open-source projects
> (OpenSSF Criticality Score), by layer, and how often is it reachable from network-facing
> code?

```sh
measure/rq3.sh            # N=100 JOBS=3 by default; resumable
```

**Projects.** OpenSSF Criticality Score's latest published snapshot, 2025-07-25. The
`ossf-criticality-score` bucket now refuses downloads, so the copy in the project's repository
is used, pinned by commit and SHA-256. Candidates are the top 200 GitHub repositories by score.
Walking down them, a repository whose root commit matches a higher-ranked one is a duplicate
code base and is skipped. Kernel trees, Android framework mirrors, and Docker's moby and docs
all collapse this way. The first 100 distinct code bases are the sample. Repositories over
20 GB (GitHub's size field) are counted in the 100 but not cloned, and are listed as skipped:
chromium/chromium and MicrosoftDocs/azure-docs. A project whose clone fails twice is listed
with that status. In the published run, that was aws/aws-cdk, whose checkout the remote cut
off.

**Scan.** Each project is cloned shallow at its default branch's head (commit recorded, LFS
files not fetched) and scanned with `pqscope scan --json`: source, config, deps and binary
layers, with reconciliation. Nothing in the project is built or run. Clones are deleted after
scanning, and each scan has a 30-minute limit.

**Counting** (`internal/measure.AnalyzeRQ3`). A finding counts when its asset is quantum
vulnerable (RSA, ECDSA, ECDH, X25519, DH, DSA, EdDSA, ...) and it was found by a layer, not
derived by reconciliation. Derived findings are counted separately by type. Per project, the
tables record counts by layer and by exposure class from the risk engine ([risk.md](risk.md)):

- `network`: network or config layer, or a TLS or SSH API;
- `test`: test or example paths;
- `internal`: everything else.

`rq3_summary.csv` gives the share of scanned projects with at least one finding, overall, in
code (source, config or binary, without deps), per layer and per exposure, with Wilson 95%
intervals.

**Files:**

| File | Contents |
|---|---|
| `rq3_selection.csv` | Every candidate considered, with root commit, size and fate |
| `rq3_projects.csv` | One row per selected project: commit, scan status, counts by layer and exposure, derived findings |
| `rq3_summary.csv` | Prevalence shares with intervals |
| `rq3_algorithms.csv` | Each vulnerable algorithm: projects using it, findings |
| `rq3_meta.csv` | Sources, hashes, settings, revision |
| `raw/rq3_findings.tar.gz` | Every scanned project's findings |

**Limits:**

- **Library calls, not implementations.** pqscope's rules match cryptographic APIs, libraries
  and configuration. A project that implements an algorithm itself, as the Linux kernel does,
  shows few findings. A low count there means few library calls, not little cryptography.
- **"Reachable from network-facing code" is a path and API heuristic.** pqscope does no
  call-graph analysis (see [risk.md](risk.md)). The `network` class is a lower bound for code
  that handles network traffic, and an upper bound for code that is actually reached.
- **Totals are dominated by a few projects; shares are not.** Config findings count each
  certificate and key, so a vendored CA bundle or a directory of test certificates adds
  hundreds. Projects that implement cryptography (golang/go) add hundreds of source findings.
  Read the per-project shares in `rq3_summary.csv`, not the `findings` column, as prevalence.
- **Deps findings are capabilities.** They say a library is present, not that the project uses
  its quantum-vulnerable algorithms. The summary reports them apart.
- **Languages outside the rule packs** (PHP, Ruby, Rust, Scala, Dart, ...) get no source
  findings. Their config, deps and binary layers are still scanned.
- **Default branch, shallow.** One commit per project. The clone runs on macOS, whose
  case-insensitive file system drops one of each pair of paths that differ only in case.
- **Same author for rules and measurement.** See RQ1 for the scanner's measured precision and
  recall on the labeled corpus.

### Audit of RQ3's findings

```sh
python3 measure/rq3_audit.py sample   # paper/data/rq3_audit_sample.csv (seeded, stratified by layer)
python3 measure/rq3_audit.py fetch    # evidence for each finding, in measure/_out/audit/
python3 measure/rq3_audit.py verify   # OpenSSL's reading of each config finding's certificate or key
python3 measure/rq3_audit.py sheet    # measure/_out/audit/review.html, every finding with its evidence
python3 measure/rq3_audit.py compare  # agreement of the two annotations, and the disagreements
python3 measure/rq3_audit.py report   # paper/data/rq3_audit_summary.csv
```

The audit estimates precision on real code:

- **Sample:** 50 random quantum-vulnerable findings from each of source, config and deps, and
  every binary finding. Within a layer every finding is equally likely to be picked (seed
  20261110).
- **Evidence:** for each one, `fetch` downloads the file at the scanned commit. `verify` reads
  the exact certificate or key at the reported line with OpenSSL, not with pqscope's parser.
- **Labels:** each finding gets two answers: is there quantum-vulnerable cryptography at that
  location, and is the algorithm family named correctly. Two annotators labeled independently,
  both AI assistants: `rq3_audit_first.csv` comes from the one that gathered the evidence, and
  `rq3_audit_second.csv` from a second that never saw the first's labels.
  `rq3_audit_agreement.csv` has their agreement and Cohen's kappa. The final labels are in
  `rq3_audit.csv`, and `decided_by` says how each was settled: by agreement, or by the author
  for disagreements and for the rule on binaries. While any label is undecided, the paper prints
  a red notice beside the audit's numbers.
- **Results:** `report` writes per-layer precision with Wilson intervals, precision weighted by
  layer size, and the effect of each error class across the whole scan.

## Ethics

The RQ2 probes are standard, unauthenticated handshakes, the same a browser starts, sent at a
low rate under limits enforced in code. Nothing is exploited, no credentials are tried, and no
application data is requested. The opt-out process and what each probe sends are public in
[scanning.md](scanning.md), and opt-outs go into `measure/exclude.txt`, which every published
run honours. Notable findings about federal systems are reported through CISA. RQ3 reads public
source code and runs none of it.
