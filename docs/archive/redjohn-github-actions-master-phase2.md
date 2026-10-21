# Completed candidate evidence and next corrections

The [phase 2 hosted run](https://github.com/akosdrx/redjohn/actions/runs/39147621368)
completed with **failure on both native Ubuntu 24.04 architectures**. Source head:
`1ba82ce568c12fdda1468a47c6e08056fd5942df`; executed PR merge:
`d3b1f737611a3c93153263d4af347f844410b1fc`; identical source tree:
`3ed418081cb9b068823df663559e298d6872682b`.

| Architecture | Python regression | Actual integration | Frontend |
| --- | --- | --- | --- |
| x64 / Python 3.13.16 | 1081 passed, 1 failed, 0 skipped | 350 passed, 4 failed, 0 skipped | 14 passed |
| ARM64 / Python 3.12.3 | 1081 passed, 1 failed, 0 skipped | 350 passed, 4 failed, 0 skipped | 14 passed |

The frontend cases include six reviewed fetch doubles; they are not fourteen
network E2Es. Both artifacts' raw JUnit retains the earlier coarse classifier.
The corrected classifier preserves counts and identifies those six names even
in Node 22 JUnit without file attributes.

The strict Linux type gate also failed on a Darwin-only branch. The focused
fix uses the typed OS helper without globally changing Python platform state.
The regression failure is an outdated dynamic `asdict` oracle: the real legacy
GET key already correctly omitted new empty extension fields. The active test
now uses the explicit original payload/golden identity, preserving persisted
legacy job identities rather than changing production keys to match the oracle.

Actual failures comprise two Semgrep native positive/fixed cases and two new
XML/UTF-16 Nuclei cases. Trivy and the other 350 integration cases passed.
Semgrep needed a valid public trust anchor for native TLS initialization and
its pinned native `--experimental` dispatch. Neither change grants network
access: its deny-all namespace and readonly source snapshot remain required.
The Nuclei failure was the old public-template MIME validator, documented with
actual before/after proof in `redjohn-extended-wire-replay.md`.

All 668 source hashes and 222 indexed evidence hashes were independently checked
per architecture. Artifact ZIP SHA256 values also match GitHub's metadata:

- x64: `f025741c8c65104f3d4e5e541c8b98d06dc82dd7b2e9a7bcf5254a8c4f5ca5a7`
- ARM64: `2573ef73e8c0af4bde7675a3fddbbecd92a69d9bdb7f1819977485b0176b710b`

Full logs, original JUnit, source/evidence indexes and independent verification
are preserved under `docs/measurements/master-completion-20261018/github-phase2/`.
The earlier [completed successful baseline](https://github.com/akosdrx/redjohn/actions/runs/39144694827)
remains separately tied to `5cfd51d286c65558b92a6c070bcd7edd5a8b432b`;
its success does not certify these later changes.

Live cloud/Kubernetes authorization has been explicitly deferred by the owner.
No live account/cluster result or original missing RCE-fixture reproduction is
claimed by these controlled tests.
