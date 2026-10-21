# First completed native component candidate

[Run 39155024691](https://github.com/akosdrx/redjohn/actions/runs/39155024691)
completed with **failure** on both native Ubuntu 24.04 architectures at source
`6481a38def1383b06b00bfeb72e3391392a075f3`.

| Platform | Naabu/dnsx | Nmap service | kube-bench version only | Owned memory | Total |
| --- | --- | --- | --- | --- | --- |
| x64 | 8 passed | 4 failed | 1 passed | 6 passed | 15 passed, 4 failed |
| ARM64 | 8 passed | 4 failed | 1 passed | 6 passed | 15 passed, 4 failed |

There were zero skipped/error cases. The browser-memory overlap case is
explicitly outside native smoke and remains mandatory in the separate complete
workflow. This result has `full_project_validated=false`.

The actual pinned Nmap 7.992 engine built successfully on both runners, with
Lua/NSE/OpenSSL excluded and the source/version/license/probe identity checked.
Built binary SHA256 values:

- x64: `9d04247ab955fc49b358400d4956909f308449e525fa4401b127371fb3957193`
- ARM64: `5051107a5f8757daa8af27222580d36e17e62721fa6979c00a3f1f1890db00b5`

All four service assertions were interrupted by a test-helper error:
`store.jobs()` already returns decoded spec dictionaries, while
`selected_nmap_row()` attempted `json.loads()` on each dictionary. A built
binary is not a passed scheduled service test; the four cases remain failed
until the corrected helper and actual assertions complete. No production
admission/normalization assertion or protection is relaxed to address this.

The native network, isolated kube-bench version and kernel-memory cases actually
ran. kube-bench's version result is not a Kubernetes audit. Both runners used
UID 1001, a job-owned enforcing AppArmor profile, global restrictions 1/1,
successful unauthorized-profile/raw-socket negative controls and verified own
cgroup removal with no leaked processes.

All **740 source hashes** and **59 indexed evidence hashes** match independently
per platform. Artifact ZIP SHA256 values:

- x64: `c7704b2dd500ae3db7d5e8de610dbed9e9ab983557a11b0cb31d4604ffc4f5d5`
- ARM64: `4c8d32202ad1d5c76abf1f2caf9df8f812ab09fc3f2b99ec501776c79d62af4f`

Full logs, original JUnit, native scope, capabilities, build/toolchain/library
receipts, resource/cleanup data and independent verification are retained under
`docs/measurements/master-completion-20261018/github-phase4-native/`. Generated
evidence remains outside source publication. The failed run is retained even
after the focused helper fix is published and checked in a subsequent run.

## Completed helper-corrected run

[Run 39155614617](https://github.com/akosdrx/redjohn/actions/runs/39155614617)
at `22d787223cb5e6f6b3b860b79048697504b5d2f2` completed with **18 passed,
1 failed, 0 skipped/errors per architecture**. The HTTP service, closed-after-open
negative control and cancellation cases passed with the real engine. SSH was
identified by Nmap, but the broker classified an authenticated early TCP reset
as a policy denial. The overall native result remains failed.

A real owned TCP banner/reset contract reproduced `connected=1, denied=1`
before the transport fix. The correction distinguishes only known peer-close
exceptions after nonce authentication and a fresh current-job fence. Missing
nonce, incomplete/extra probes, expired/cancelled jobs, byte/connection budgets
and policy exceptions remain denials, including concurrent reset/policy-error
ordering. This changes transport classification, not permitted payloads or
execution authority. Actual corrected native service proof is required from a
subsequent hosted run; a contract pass alone is insufficient.

All **741 source hashes** and **59 indexed evidence hashes** match independently
on both platforms. Corrected-helper run ZIP digests:

- x64: `32b08834d710ffa4482a105ac9b3112509d79e895e26bda81cb9997cda9a8505`
- ARM64: `537ca85d7602db67c3773a2f2ddfbf628e1e64c970003594eb922977894b23ac`

These original artifacts and logs are preserved separately under
`docs/measurements/master-completion-20261018/github-phase4-selection-native/`.
# Completed authenticated peer-close correction

[Native run 39157069204](https://github.com/akosdrx/redjohn/actions/runs/39157069204) completed successfully for source `61f209e0d0e9bc094316017da0de613b907aeecf`, tree `46aa7915af350d120e2ddfe9b6251cad888642a6`. Each Ubuntu 24.04 architecture executed 19 actual native component cases: network 8, service 4, preparation version-only 1 and memory 6; failures/errors/skips were all zero. SSH, HTTP, the false relay-open control and cancellation cleanup all passed. This validates the fixed authenticated reset classification with the existing nonce, exact-probe and current-job gates intact.

Both artifact ZIP SHA256 digests, all 741 source identities and all 59 indexed evidence identities per architecture were independently checked. Full logs, JUnit, versions and measurements are saved under `docs/measurements/master-completion-20261018/github-phase4-reset-native/`. The native workflow explicitly reports `full_project_validated=false`, excludes the browser/SDK/MCP overlap case, and performs no live cloud or Kubernetes audit. Those remain distinct from the full Chromium matrix. Global AppArmor restrictions remained enabled and run-owned cleanup passed on both architectures.

# Completed 24-case native smoke and full Ubuntu validation (2026-10-19)

[Native run 39241380785](https://github.com/akosdrx/redjohn/actions/runs/39241380785) and [Full Ubuntu validation run 39241380765](https://github.com/akosdrx/redjohn/actions/runs/39241380765) completed with **success** on both `Ubuntu 24.04 x64 / Python 3.13.16` and `Ubuntu 24.04 arm64 / Python 3.12.3` for source `fd7c0d41df9204e57d8136194336bee2e2378a93` (tree `1cda168ca12323c4c078e221e6a2e51e87a6c8ec`):

| Workflow | Platform | Python regression | Native / Integration | Soak | Failures / Skips |
| --- | --- | --- | --- | --- | --- |
| Native smoke (`39241380785`) | x64 & ARM64 | 1548 passed | 24 passed (`network`: 8, `service`: 4, `preparation`: 1, `memory`: 6, `cleanup-proof`: 1, `lab`: 4) | N/A | 0 failed, 0 errors, 0 skipped |
| Ubuntu validation (`39241380765`) | x64 & ARM64 | 1548 passed | 443 passed (`real_integration`), 14 frontend, 21 Go | 120 cycles (`x64`: 1206.78s, `ARM64`: 1206.21s) | 0 failed, 0 errors, 0 skipped |

All **789 tracked source SHA256 hashes**, **73 native smoke evidence hashes**, and **295 full Ubuntu validation evidence hashes** per architecture are verified and archived under `docs/measurements/master-completion-20261019/`.
