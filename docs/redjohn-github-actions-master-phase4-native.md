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
