# Changelog

## Unreleased

### Milestone 1: skeleton

- Add the repository layout, `Makefile` and CI for lint, test and the race detector.
- Add `internal/model` with `Finding`, `Asset`, `Location` and stable finding IDs.
- Add `internal/knowledge`, a cited algorithm database that validates itself on load.
- Add the CLI with a working `version` command. All other commands exit non-zero as
  "not implemented".

Known limits:

- CNSA 2.0 is cited through an IETF profile draft, because the NSA PDF could not be fetched
  by script. Replace this with the NSA document before the policy work in milestone 4.
- IR 8547 is cited at document level. Section numbers still need to be read from the report
  itself for milestone 4.
- Sizes for RSA-1024, RSA-4096, P-224, Ed448, X448 and DH, and ECDSA public keys, come from
  the cited standards and are not cross-checked against an implementation.
