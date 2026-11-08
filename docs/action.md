# GitHub Action

The repository is a GitHub Action. It builds pqscope from the tagged source, scans a directory,
uploads the SARIF log to code scanning, and can gate the build on a policy.

```yaml
name: pqscope
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for the code scanning upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: emmanueladutwum123/pqscope@v1
        with:
          fail-on: disallowed-2035   # optional gate; omit to report only
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan, relative to the repository root |
| `layers` | `source,config,deps,binary` | Layers to scan |
| `sarif` | `pqscope.sarif` | Where to write the SARIF log |
| `cbom` | | Where to write a CycloneDX 1.6 CBOM; empty to skip |
| `upload` | `true` | Upload the SARIF log to code scanning |
| `category` | `pqscope` | Code scanning category, to keep several runs apart |
| `policy` | `nist-ir-8547-2026` | Policy for the gate: `nist-ir-8547-2026` or `cnsa-2.0` |
| `fail-on` | | Fail when any asset reaches this status: `deprecated-2030`, `disallowed-2035`, `disallowed-now`, `broken-now`. Empty reports without failing. |

Outputs: `sarif` (the log's path) and `findings` (how many).

## Notes

- **Composite action, not Docker.** A Docker action can't call `upload-sarif` itself, so the
  scan-and-upload would take two steps in every caller's workflow. As a composite action, it
  runs on Linux and macOS runners, not Windows, because the tree-sitter grammars need cgo and a
  C compiler.
- **Go on PATH.** The action installs Go with `actions/setup-go` to build pqscope, so later
  steps in the same job see that Go. The build takes about a minute; nothing is downloaded at
  run time beyond Go and the module dependencies in `go.sum`.
- **Pinned dependencies.** The third-party actions it uses are pinned by commit.
- **Repository-relative paths.** When `path` is a subdirectory, the SARIF paths are prefixed
  with it (`pqscope scan --sarif-root`), so code scanning finds the files.
- **Report-only mode never fails on findings,** but still fails if the policy can't be
  evaluated.
- **Network layer.** Probing endpoints from CI isn't part of the action. Run `pqscope net`
  separately, against hosts you operate, and merge with `scan --with`.

CI runs the action on itself (`uses: ./`) on every push. It checks the outputs, the SARIF
paths, and that the gate passes on post-quantum code and fails on classical code.
