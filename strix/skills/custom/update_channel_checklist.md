---
name: update_channel_checklist
description: 'Update channel integrity: signature, pinning, downgrade checklist (from
  supply_chain_integrity specialist reference library)'
---

# Update channel integrity: signature, pinning, downgrade checklist

For applications that ship updates (desktop apps, agents, plugins, CLI
self-update). Everything below is answered from PROVIDED artifacts (update
URLs in source/config, captured manifests, binaries, public keys); live
probing goes to `20`/`50` under the scope guard.

## 1. Transport checklist

| Check | Question | Evidence from |
|---|---|---|
| T1 | All update/version-check URLs https-only? | source/config grep: `http://` near `update`, `feed`, `download`, `version` |
| T2 | Certificate validation ON (no `--insecure`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`) in the updater path? | updater source/config |
| T3 | Redirects followed to arbitrary hosts? (signed-http -> unsigned-CDN style chains) | updater logic / captured redirect chain |
| T4 | Update metadata and the artifacts themselves on the same trust level? | manifest + artifact URLs |

TLS-version/cipher depth belongs to `35-cryptographic-failures`.

## 2. Signature verification checklist

| Check | Question | Insecure signal |
|---|---|---|
| S1 | Does the updater verify ANY signature on the update? | "download -> checksum -> run" with no key check |
| S2 | Manifest AND binaries signed, or manifest only? | unsigned binary referenced by signed manifest (binary must carry its own signature) |
| S3 | Which scheme: detached GPG/minisign, OS code signing, sigstore? | scheme absent = S1 finding |
| S4 | Is the verification key pinned in the client (hardcoded/embedded public key)? | key fetched from the same channel = same-origin compromise passes |
| S5 | Is failure fatal (refuse to install) or log-only? | log-only downgrade of S1 |
| S6 | Checksums: fetched from where? | checksums from the same origin as the binary are NOT integrity |

Client-side grep leads: `minisign`, `gpg --verify`, `codesign --verify`,
`WinVerifyTrust`, `sigstore/cosign`, `checksum`, `sha256(`, `md5(`
(MD5 as update checksum = weak, `35`).

## 3. Downgrade protection checklist

| Check | Question | Insecure signal |
|---|---|---|
| D1 | Client rejects versions OLDER than installed? | any validly-signed older artifact installs |
| D2 | Version monotonicity enforced at signature layer (anti-rollback counters/VDF) or only client logic? | client-only check = bypassable logic |
| D3 | Can the version-check endpoint force "no update available" and freeze the client on a known-vulnerable version? | silent no-update response with no freshness proof |
| D4 | Rollback windows: is the previous-version binary still accepted side-by-side after update? | accepted old binary with old vulnerabilities = rollback path |

## 4. Pinning checklist (pinned vs floating)

| Check | Question |
|---|---|
| P1 | Update feed URL pinned (exact host) or wildcard/DNS-discoverable? |
| P2 | Channel/stable-vs-beta selection enforced by signature or by request parameter? |
| P3 | Plugin/extension IDs validated against a signed allowlist before load? |
| P4 | Docker/base images in the build pinned by digest, or by mutable tag? |

## 5. Findings mapping

| Failure class | CWE (canonical) | Severity reasoning |
|---|---|---|
| No signature verification on update (S1+S4) | CWE-494 (Download of Code Without Integrity Check) | HIGH; remote code delivery depends on network position |
| Same-origin checksum only (S6) | CWE-493 (Critical Private Resource Sourced from Untrusted Repository variant) / CWE-345 | MEDIUM-HIGH |
| Downgrade accepted (D1/D2) | CWE-862-class logic gap (missing anti-rollback) | MEDIUM |
| http:// update URL (T1) | CWE-319 (Cleartext Transmission of Sensitive Information) | HIGH for code channels |
| Log-only verification failure (S5) | CWE-755 | MEDIUM |

Claims stay at the observed layer: "the updater executes downloaded
binaries without signature verification" is the finding; "attacker can RCE
every client" is impact language that needs the D2/D3 evidence discipline
before it enters a report.

## 6. Evidence expectations

- The updater's verification code path quoted (file:line) OR the captured
  unsigned exchange (request+response pair via `20` when live probing is
  authorized and in scope).
- The pinned-key material location (not the key value if secret — public
  keys may be quoted).
- One clean diagram row per check (T1-T4, S1-S6, D1-D4, P1-P4) in the run
  notes even when passing — the coverage statement for `90` comes from it.

