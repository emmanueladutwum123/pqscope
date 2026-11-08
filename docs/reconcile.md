# Reconciliation

Each discovery layer sees part of a system. Reconciliation puts the parts together:

- source shows what the code calls;
- dependencies show what libraries make available;
- configuration shows what is allowed;
- binaries show what was shipped;
- the network shows what is actually negotiated.

`pqscope scan` reconciles by default. To include network results, run `pqscope net` first and
merge its findings:

```sh
pqscope net --targets hosts.txt --findings net.json -o net.jsonl
pqscope scan ./service --with net.json
```

## Components

Findings are linked only within a component. By default the whole scan, including every merged
endpoint, is one component. Use `--components` to split a monorepo or a fleet:

```yaml
components:
  - name: web
    paths: [services/web]          # path prefixes, relative to the scan root
    hosts: [web.example.org:443]   # host or host:port; "*" for all
  - name: api
    paths: [services/api]
    hosts: [api.example.org]
```

A finding belongs to the first component that matches it. Findings that match no component are
kept, but they aren't linked to anything.

## Derived findings

Each derived finding is a `model.Finding` with `derived` set, `rule_id` set to `reconcile.<type>`,
evidence explaining the link, and `linked_ids` pointing to the findings it rests on. Its location
and asset are those of the finding it is about. The reports list derived findings in their own
section and don't count them with observed findings. The CBOM leaves them out, because it is the
inventory. SARIF includes them as results of `reconcile.*` rules.

| Type | Emitted when | Located at |
|---|---|---|
| `declared-pqc-deployed-classical` | The component declares post-quantum key establishment, either in source (such as ML-KEM or X25519MLKEM768 calls) or as a dependency capability, but a TLS endpoint negotiates only classical groups, or an SSH server offers only classical key exchange | The endpoint |
| `config-overrides-library` | A dependency supports a hybrid group for the protocol (X25519MLKEM768 and its SecP variants for TLS, mlkem768x25519 or sntrup761x25519 for SSH), but a configuration directive listing groups names only classical ones | The directive |
| `binary-without-source` | A binary contains an algorithm family (by import, symbol, Go function or constant) that no source finding in the component uses | The binary |
| `stale-dependency` | A pinned dependency's version provides no post-quantum algorithms, and the library capability table shows a later version that adds them | The manifest line |

Some rules decline on purpose:

- **declared-pqc-deployed-classical** is not raised for an endpoint that negotiates or offers any
  hybrid or post-quantum group.
- **stale-dependency** is not raised for unpinned versions, whose staleness can't be judged, or for
  libraries with no post-quantum algorithms in any version (pycryptodome, node-forge, jsrsasign,
  ring). Upgrading those would not help.
- **binary-without-source** is raised for every family in a binary when the component has no
  source, such as a release directory. That is intended: none of that crypto is visible in source.

## Confidence fusion

- **Corroboration.** When the same algorithm family (algorithm and primitive) is observed in two or
  more layers of a component, among source, config, binary and network, each finding's confidence
  becomes `1 - (1 - c)(1 - c')`. Here `c'` is the strongest observation in another layer. The
  corroborating findings are added to `linked_ids`. Values are computed from the original
  confidences, so the result doesn't depend on order.
- **Contradiction.** When a TLS endpoint negotiates a group that a group directive in the same
  component doesn't list, or an SSH server offers a key exchange that `KexAlgorithms` doesn't list,
  both the directive's findings and the network finding get a `review` reason. The scanned file
  may not be the deployed configuration.
- **Dependencies are left out of both.** They show what is available, not what is used, so they
  neither corroborate nor contradict, and their confidence stays at 0.5.

## Limits

- Components are matched by path prefix and host name. pqscope does not discover which endpoint
  serves which code.
- `config-overrides-library` takes "a library in the component supports a hybrid" from the
  dependency layer. It does not know which library the server process actually loads. For example,
  nginx usually uses the system OpenSSL, which no manifest lists.
- Findings merged with `--with` keep their own paths. Merge only findings whose file paths are
  relative to the same root.
