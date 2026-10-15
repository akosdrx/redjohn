---
name: 65-supply-chain-integrity
description: Use when integrity of build and update paths is in question - CI/CD workflow injection via pull_request_target with PR-controlled scripts, unsigned update channels, squattable or unverified dependency names, and lockfile drift between environments.
---

# Supply chain integrity (P7)

How code, builds and updates arrive — and whether integrity holds. Mostly
offline analysis of operator-provided source, CI config and lockfiles;
anything live goes through `20`/`50` under the guard.

## The way

- The classic injection triad — `pull_request_target` + PR-head checkout
  + PR-controlled execution — runs fork code with base-repo secrets.
  Regex triage finds candidates; the job context confirms (`if:` guards
  and reusable-workflow indirection need eyes).
- `${{ github.event.* }}` interpolated into `run:` is script injection
  with a branch-name payload; the remediation marker is env-indirection
  plus quoting.
- Secret *names* in findings, never values.
- A checksum fetched from the same channel is not integrity; a
  signed-but-older artifact the client accepts is a rollback channel.
- Drift is comparative: the same dependency resolving differently across
  environments (prod vs CI vs image) — compare lockfiles pairwise.
- Confusion and typosquat rows are heuristic leads until a registry or
  config proof attaches.

## Handoffs

Pinned versions -> `70` for CVE correlation; secret exposure ->
`30`/`90` (names only); live update-endpoint probing -> `50`/`20`.

## Tools

`workflow_scan.py`, `lockfile_drift.py` (both offline by design — that
boundary is part of the verification story). Pattern catalog and
checklists in `references/`.
