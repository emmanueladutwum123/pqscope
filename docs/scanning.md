# Network scanning: what pqscope sends, and how to opt out

pqscope's `net` command measures which key exchange a server negotiates, such as
post-quantum hybrid X25519MLKEM768 or classical X25519. It does this with standard,
unauthenticated handshakes. This page is the public project page that the probes point
to.

## If you operate a server and saw pqscope connect

**How to recognise pqscope:**

- **SSH:** pqscope identifies itself in its identification string:
  `SSH-2.0-pqscope_<version> +https://github.com/emmanueladutwum123/pqscope`.
- **TLS:** there is no field for a contact string. The ClientHello offers only TLS 1.3 with
  three cipher suites, and the connection closes right after your ServerHello.

**To opt out:**

1. Open an issue at <https://github.com/emmanueladutwum123/pqscope/issues> with the title
   `opt-out`, listing your hostnames, IP addresses or CIDR ranges. The list is published in
   the repository, so don't include anything you want kept private.
2. Your entries go on the project's exclude list,
   [`measure/exclude.txt`](../measure/exclude.txt). That list is applied to every
   measurement run the project publishes, through `--exclude`, which is checked against
   host names and every resolved address.

Other people can run pqscope themselves. The limits below are built into the tool, but
an exclude list only applies to runs that use it.

## What each probe sends

| Probe | Sent | Then |
|---|---|---|
| TLS ServerHello | One TLS 1.3 ClientHello with SNI (when the target is a name), a supported_groups list, and fresh key shares for the first two groups | Reads one ServerHello, HelloRetryRequest or alert, then closes. The key exchange is never completed. |
| TLS certificates | A standard `crypto/tls` handshake (TLS 1.0 to 1.3) | Reads the certificate chain, sends close_notify, and closes. No application data. |
| SSH | The identification string above | Reads the server's banner and KEXINIT, then closes. No KEXINIT is sent, so no key exchange starts. |

No vulnerability is tested and no credentials are tried.

## Limits enforced in code

These are checked by `internal/discover/network` itself. Options outside them are
rejected, and tests cover each limit.

| Limit | Default | Bound |
|---|---|---|
| Connections per second, across all hosts | 50 | at most 1000 |
| Concurrent connections per host | 1 | fixed |
| Timeout per connection | 5 s | at most 30 s |
| Retries after a failed connection | 1 | at most 2 |
| Exclude list | `--exclude` | names, `.domain` suffixes, IPs and CIDRs, checked against every resolved address |

The rate limiter spaces connection attempts evenly with no burst. All probes for one host
run one after another. Distinct hosts are probed in parallel, still under the global rate.

## For researchers using pqscope

Follow established Internet-measurement practice, for example the ZMap project's
scanning guidelines:

- run from addresses with reverse DNS that identifies the scan, ideally pointing to a page
  like this one;
- keep rates low;
- honour opt-outs promptly.

Report notable findings through coordinated disclosure: for U.S. federal systems, through
CISA.
