# Legacy advisory cache and sandbox lifecycle

The native CVE tool retains RedJohn's OSV, NVD, KEV and EPSS integrations. It now
uses the same bounded JSON LRU implementation as the assessment stack instead of
an unbounded Python dictionary and a process-lifetime KEV catalog.

## Limits and semantics

| Resource | Default enforced limit |
| --- | --- |
| In-process serialized advisory cache | 8 MiB, 128 entries |
| SQLite advisory payloads | 64 MiB, 4096 entries |
| Advisory lookup TTL | 6 hours |
| KEV catalog TTL | 12 hours |
| In-flight distinct refreshes | 8 |
| Network refresh deadline | 30 seconds, including publication deadline fence |
| Individual waiter deadline | 33 seconds |
| Decoded upstream response body | 4 MiB before JSON parsing |
| Shared-governor refresh reservation | 64 MiB, one in-process worker |
| Active/provisioning/cancelled-provisioning sandbox sessions | 64 |
| Provisioning caller deadline | 180 seconds |
| Session deletion deadline | 120 seconds |

RAM accounting counts stored serialized bytes. Entry count bounds Python/key
overhead; the transient decoded JSON and provider buffers remain additional
memory accounted for by the shared worker reservation and process measurement.
SQLite limits count stored payload bytes, excluding database page, index and WAL
overhead. This is not a filesystem hard quota. SQLite eviction is performed in
SQL with a bounded pager and disk-backed temporary storage; migration does not
build an unbounded Python list of historical keys.

When the SDK context supplies its shared `assessment_governor`, advisory refreshes
acquire its worker lease. The refresh owns that lease until completion, including
when its original caller is cancelled. Cache hits do not start another worker.
The RAM quota can shrink to the governor's cache quota; memory pressure clears
the hot set and prevents refill until pressure clears. The global process cache
never increases its quota in response to a later caller's larger envelope.

Keys are SHA-256 digests of versioned, unambiguous query references. Package and
version case is retained. They contain no raw cookies, tokens or API keys. Cache
database mode is `0600`. Successful results carry retrieval/source/version
metadata. TTL and LRU operate independently from evidence and campaign state;
no evidence is stored here. Provider failure, malformed collection, timeout,
oversized response and partial-source empty results are not cached successful
negative lookups. An intelligence match does not establish a target finding.

Concurrent identical refreshes share one bounded task. A cancelled or timed-out
waiter leaves other waiters intact. Expired publication is fenced in both RAM
and SQLite. SQLite connections are closed explicitly after every transaction;
transaction context exit alone would leave their descriptors open until GC.

## Sandbox ownership

Per-scan create/reuse and cleanup share a weakly registered lock. Callers and
waiters retain strong ownership while operating; completed scan IDs do not
accumulate locks. Live sessions are never expired or evicted to admit another
scan. Admission fails explicitly when all slots are occupied. The operator may
set `REDJOHN_MAX_CACHED_SESSIONS` to an integer from 1 to 1024.

Cleanup is serialized and shielded from caller cancellation. A failed or timed
out deletion retains the original client/session bundle for an explicit cleanup
retry; reuse of that bundle is blocked. A successful container delete followed
by a failed Docker-client close retries only client close. Late backend results
from cancelled or timed-out provisioning remain owned and consume admission
capacity until discarded. This can reduce capacity if a backend never returns;
the implementation does not forget an unknown resource to manufacture capacity.

`lifecycle_snapshot()` exposes aggregate active/provisioning/discard/cleanup/lock
counts without scan IDs or credentials. Teardown failures propagate rather than
being reported as completed cleanup.

## Focused verification

From the repository root:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_legacy_cache_lifecycle.py \
  RedJohn/tests/test_legacy_cache_live.py \
  RedJohn/tests/test_host_binding_contract.py \
  RedJohn/tests/test_runner_assessment_contract.py -q
```

`test_legacy_cache_live.py` exercises a real owned loopback HTTP server, twelve
concurrent clients, actual HTTPX and SQLite, one upstream refresh and subsequent
cache reuse. It does not claim public advisory provider availability.
`test_legacy_cache_lifecycle.py` tests actual byte/item limits, expiry, SQLite
migration/permissions/FD closure, deadline fencing, single-flight and shared
governor lease lifetime; provider schema/outage and sandbox backend cases are
explicitly injected contracts. The session cycle test completes 200 owned
synthetic bundles and verifies zero retained sessions, cleanup tasks and locks.
Actual Docker backend deletion and public OSV/NVD/KEV/EPSS availability require
separate integration evidence and are not asserted by these contracts.
