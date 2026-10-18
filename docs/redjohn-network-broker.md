# Explicit network and DNS jobs

RedJohn implements `naabu_ports` with Naabu 2.6.1 and `dnsx_resolve` with dnsx
1.3.1. These selected engines use the existing durable scheduler, host resource
pool, cancellation, job leases and immutable evidence store. Listing capabilities
and composing an unconfigured runtime do not start scanner processes.

Install explicitly on a Linux x64/ARM64 runner:

```sh
PYTHON=python bash RedJohn/scripts/install-network-scanners.sh
```

The installer verifies official release archive SHA256, exact source commit and
MIT license SHA256. It extracts one named ELF executable and records its binary
hash, version, archive and license identities in `receipt.json`. It refuses to
overwrite an existing installation. The shared bounded extraction helper is the
reviewed source-scanner installer; neither installer invokes project build or
package scripts. Naabu's upstream runtime dependency on libpcap must be available
and recorded by the host/CI environment. Missing dependencies are blocked,
not a successful negative scan.

## Independent authority

Web origins and their `allowed_ips` do **not** authorize port scanning or DNS
queries. Network policy is explicit and independent:

```json
{
  "policy": {
    "engagement_id": "owned-network-lab",
    "owner_id": "operator",
    "allowed_origins": [],
    "target_domains": ["network"],
    "profile": "isolated-lab",
    "egress_mode": "unavailable",
    "allowed_networks": ["127.0.0.1/32"],
    "allowed_tcp_ports": ["9000"],
    "network_request_budget": 16
  },
  "naabu": {
    "binary": {
      "path": "/absolute/RedJohn/.tools/naabu/2.6.1/naabu",
      "version": "2.6.1",
      "sha256": "<receipt binary_sha256>"
    }
  },
  "network_jobs": [{
    "capability": "naabu_ports", "address": "127.0.0.1", "port": "9000",
    "timeout_seconds": 20
  }]
}
```

DNS jobs instead use `allowed_dns_zones` and explicit numeric
`allowed_dns_resolvers`, e.g. `"127.0.0.1:9053"` or `"[::1]:9053"`. Configure
`dnsx.binary` at reviewed version `1.3.1`, then select:

```json
{
  "capability": "dnsx_resolve", "name": "owned.test", "query_type": "A",
  "address": "127.0.0.1", "port": "9053", "timeout_seconds": 20
}
```

Each job names exactly one numeric IP/port or one canonical ASCII DNS name,
query type and resolver tuple. The policy accepts at most 128 entries per grant
list; configuration accepts at most 64 jobs and the existing 64KiB JSON limit.
There is no CIDR expansion, default top-port expansion, hostname-to-network
promotion, ASN import, recursive discovery or implicit public resolver.
Supported DNS types are A, AAAA and CNAME. Both capabilities require an active
staging or isolated lab profile, explicit independent network budget and Linux
kernel isolation. Source and old HTTP policy/surface/job hashes remain stable
when new fields are empty.

Surfaces have no fabricated URL. `network_endpoint` binds a real `ip_address`
inventory asset and TCP service; `dns_name` binds a real DNS asset. Import and
DNS results never create execution grants. Retired assets/services also block
already queued jobs at dispatch and broker admission.

## Actual transport boundary

The worker has attested Linux user/mount/PID/network namespaces, loopback only
and dropped capabilities. Existing authenticated Unix byte-relay transport
reaches a **distinct SOCKS5 controller**, not an HTTP authorization proxy. There
is no host-network or privileged scanner fallback. The selected binary is
hash-verified, copied into a private read-only payload (maximum 64MiB), and
verified by the supervisor before launch.

The broker requires a per-job nonce, current exact scheduler owner/attempt/lease,
current policy and active inventory binding. It permits numeric IPv4/IPv6 SOCKS5
CONNECT only, rejects domain CONNECT/BIND/UDP, and requires the exact surface
tuple. It returns SOCKS success only after the actual authorized upstream TCP
connection succeeds. A local listener's SYN-ACK is never used as evidence that
a remote port is open.

Naabu uses fixed CONNECT mode `-s c`, one worker, rate 1, stream mode and disabled
host discovery/update checks. Raw scans, payloads, passive databases, CDN
queries, Nmap chaining and arbitrary CLI options are excluded. An open
observation must match both native output and a real broker connection; a
refusal is `closed_or_unreachable`, not proof of global safety.

For dnsx the reviewed `retryabledns` version forces TCP with a SOCKS proxy. The
controller parses one bounded question, validates QNAME/QTYPE against both the
policy zone and exact job, rebuilds it, and forwards it only to the approved
resolver. Its empty EDNS0 OPT is validated and removed; client-subnet/cookie
extensions, compression in questions, ANY/AXFR/IXFR, trace and wildcard discovery
are rejected. No raw DNS query data channel is forwarded. Responses are limited
to 4096 bytes/64 resource records and must match ID/question, be untruncated and
have a completed native result. NXDOMAIN is distinguished from missing engine,
parser failure, refusal, truncation and blocked access.

Bounds are two controller connections, eight upstream attempts per job,
minimum 100ms connection spacing, at most 5s per controller lifecycle, one DNS
exchange per connection, 16 output rows/64 normalized DNS answers, 512KiB native
stdout/stderr, existing per-process file limits, shared resource admission and
job deadline. Actual upstream connects and validated DNS questions each consume
one durable `network_request_budget` unit. Thus a completed DNS exchange normally
costs two units. The HTTP request counter remains separate. Counter updates are
atomic and survive restart. Cleanup closes accepted transports before awaiting
the listener, including Python 3.13 cancellation behavior.

## Execution and verification

```sh
cd RedJohn
../.venv/bin/python -m redjohn assess run --config /absolute/network.json --output /absolute/run
```

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_network_broker_contract.py \
  RedJohn/tests/test_network_tools_contract.py -q

REDJOHN_REQUIRE_NETWORK_SCANNER_E2E=1 PYTHONPATH=RedJohn python -m pytest \
  RedJohn/tests/test_network_tools_live.py -q
```

The broker tests use actual owned loopback sockets, TCP DNS and SQLite; they do
not execute scanners. The argument/parser tests use synthetic metadata and are
not native integration evidence. Eight separate native cases cover Naabu
open/closed, dnsx A/AAAA/CNAME/NXDOMAIN, persisted restart deduplication,
cancellation cleanup, and direct-connect/raw-socket namespace bypass denial.
Missing engines or Linux isolation fail the required CI invocation. Ordinary
macOS runs label these eight capabilities blocked/skipped.

Nmap is not executed through this broker yet. Its `--proxies` option excludes
port scanning, and a naive local relay falsely makes closed upstream ports
appear open. A later service-only adapter must discard relay port-state claims
and require upstream response proof; transparent remote Nmap scanning requires
an independently proved connect-preserving boundary. Nmap 7.992 is NPSL 0.95,
not MIT/GPL-only, and needs explicit packaging/license treatment. Amass and
Subfinder remain deferred alternatives rather than duplicate automatic research.

Primary references: [Naabu tagged CONNECT implementation](https://github.com/projectdiscovery/naabu/blob/5a0ca8bde91b5bb16213e9e8b5c6871eac954bd8/pkg/scan/scan.go),
[dnsx pinned dependencies](https://github.com/projectdiscovery/dnsx/blob/01e315f216db7d36198ec326fac13dd7846b1bec/go.mod),
[reviewed resolver TCP behavior](https://github.com/projectdiscovery/retryabledns/blob/v1.0.116/client.go),
[Nmap tagged manual](https://github.com/nmap/nmap/blob/0ee561663c1d7d2d4e708cd414dccfd3d9df30d9/docs/nmap.1).
