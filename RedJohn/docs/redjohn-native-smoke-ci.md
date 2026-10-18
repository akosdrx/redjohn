# Independent native component smoke

`.github/workflows/redjohn-native-components.yml` provides fast, separate native
feedback on GitHub-hosted Ubuntu 24.04 x64 and ARM64. It runs on push, pull
request and manual dispatch, with a separate concurrency group and a 60-minute
job timeout. It does not cancel or replace the full Ubuntu matrix or its soak.
All evidence is tied to the checked-out commit SHA; its summary always records
`full_project_validated: false` even when `native_smoke_success` is true.

The scope is exactly:

| File | Required cases | Evidence |
| --- | ---: | --- |
| `test_network_tools_live.py` | 8 | Real owned Naabu/dnsx transport, namespace and cleanup |
| `test_service_tools_live.py` | 4 | Real owned Nmap service fixtures and cancellation |
| `test_preparation_native.py` | 1 | Real copied kube-bench version-only deny-all namespace; no Kubernetes audit |
| `test_owned_memory_live.py` | 6 | Real kernel aggregate memory, writable-cgroup denial, process cleanup and terminal inheritance |
| `test_cleanup_quarantine_live.py` | 1 | Actual small owned Python child and shared SQLite admission retained until reap; no scanner or kernel-limit claim |

The browser-containing memory case
`RedJohn/tests/test_owned_memory_live.py::test_actual_browser_sdk_mcp_and_native_worker_inherit_the_owner_hard_fence`
is recorded explicitly as `out_of_scope_not_executed`. It is neither skipped nor
passed in native smoke. The full workflow retains all seven memory cases and its
default real Chromium capability probe. Native smoke installs no Chromium;
`capabilities.py --native-only` requires the same AppArmor, UID/capability drop,
network namespace and memory/cgroup controls, while recording the browser probe
as not requested for this declared profile.

Native engines install sequentially: pinned Naabu, dnsx, the explicit Nmap
`--owned-fixture-build` and pinned kube-bench. The shared installers preserve
version, source/license, compiler/library and binary checksum receipts. Runtime
uses the enforcing job-owned AppArmor profile, retains both global user-namespace
restrictions at `1`, drops to the original runner UID, and owns a uniquely named
cgroup. Missing dependencies or runner capabilities are failures in required
mode; protection is never disabled to make smoke pass.

`linux-tests.sh native` runs each reviewed suite in a separate bounded command,
with its own JUnit file, log and external resource samples. It continues to
collect independent suite results after a test failure. Always-run steps record
the cgroup before cleanup, remove only owned processes/groups and AppArmor
profile, and verify the global restrictions remain enabled. Logs, JUnit, tool
receipts, source hashes, version data and resource measurements are uploaded on
failure too. Private authentication state is outside this native scope.

`native-summary.py` rejects missing commands, commit mismatches, leaked
descendants, missing/relaxed capability controls, wrong tool receipt hashes,
unexpected test files, duplicate cases, any failure/error/skip or an unexpected
case count. It also requires the actual kube-bench version-only JUnit proof and
the exact explicit browser-case exclusion. Python regression contracts also run
separately under the existing unprivileged launcher, with their mock/mixed labels
retained and a strict no-error/failure/skip gate. Their JUnit, log and source hashes
are uploaded immediately before longer work, so diagnosis does not wait for the
full matrix or its soak. The full workflow has the same early checkpoint.

A green smoke is evidence only for
these 20 component cases and the separately reported Python regression; it proves no frontend/TUI, browser,
external cloud account or Kubernetes node audit result.

Manual dispatch uses the correct repository:

```sh
gh workflow run redjohn-native-components.yml --repo akosdrx/redjohn --ref <reviewed-branch>
```

Fast local verification of the evidence code uses synthetic contract fixtures,
not actual hosted integration proof:

```sh
PYTHONPATH=RedJohn:.github/scripts .venv/bin/python -m unittest discover -s .github/tests -v
bash -n .github/scripts/linux-tests.sh
```
