---
name: proxmox_api_surface
description: Proxmox API surface (from proxmox_ve_security specialist reference library)
---

# Proxmox API surface

Endpoint map (unauthenticated vs ticket vs token), the auth flow in text, and
the token audit checklist.

## 1. Endpoint map by access class

| Endpoint | Access class | Notes |
|---|---|---|
| `GET /api2/json/version` | unauthenticated (default installs) | version fingerprint anchor |
| `GET /api2/json/cluster/status` | unauthenticated on many installs (record 200 vs 401) | cluster name/nodes/quorum disclosure when open |
| `GET /` | unauthenticated | web UI shell; login redirect; Proxmox-branded title |
| `POST /api2/json/access/ticket` | unauthenticated (credentials in body) | issues ticket + CSRF token; watch lockout policy |
| `GET /api2/json/access/permissions` | ticket or token | caller's effective permission map — core authz evidence |
| `GET /api2/json/cluster/resources` | authenticated | all objects the caller can see (vms/nodes/storages) |
| `GET /api2/json/nodes` | authenticated | node list |
| `GET /api2/json/nodes/{node}/qemu` , `/lxc` | authenticated (needs node perms) | guest inventory |
| `GET /api2/json/nodes/{node}/qemu/{vmid}/config` | authenticated | read-only guest config pull |
| `GET /api2/json/nodes/{node}/version` | authenticated | node package/kernel version detail |
| `GET /api2/json/access/users` , `/access/users/{userid}/token/{tokenid}` | authenticated, privileged | token audit (needs appropriate privileges) |

Observation rule: status codes are findings either way — 200-disclosure rows
and 401-hardened rows both go to the evidence file. Never POST/PUT anywhere
from this mapping phase.

## 2. Auth flow in text

1. **Ticket auth (users)**: `POST /api2/json/access/ticket` with
   `username=user@realm&password=...` returns JSON `data` containing
   `ticket` and `CSRFPreventionToken` (plus `clustername` on clusters).
2. Subsequent requests send `Cookie: PVEAuthCookie=<ticket>`.
3. Every method other than GET/HEAD must ALSO send header
   `CSRFPreventionToken: <token>` — this is enforced by the API; a
   ticket-only POST failing with 401/400 is EXPECTED behavior, not a finding.
   Record a misconfiguration only if state changes succeed without the CSRF
   header.
4. **Token auth**: header `Authorization: PVEAPIToken=<user@realm!tokenid>=<secret>`
   (id and secret separated by `=`). Tokens bypass the ticket flow entirely
   and never need the CSRF header.
5. Tickets expire; tokens carry their own `expire` field.

## 3. Token audit checklist

Run when a privileged read credential exists; otherwise request the output
from the operator. For every token found:

- [ ] id format `user@realm!tokenid` recorded (mask the secret — it is not
      retrievable anyway after creation, only resettable).
- [ ] `expire` field: missing/empty/zero = never expires -> finding candidate
      (no rotation).
- [ ] `privsep` (privilege separation): disabled means the token carries the
      FULL user permissions -> finding candidate when the user is privileged.
- [ ] Owning user's realm: `pam` tokens (root@pam especially) vs `pve`;
      admin-owned tokens shared across services are the classic over-scope.
- [ ] Comment field: tokens without owner/comments are attribution gaps.
- [ ] Where the token is used from: correlate with operator knowledge;
      session/API logs if the operator provides excerpts (data-access gated).
- [ ] Brute-force exposure (bounded, operator-approved): does repeated
      wrong-secret auth get throttled; is the failure indistinguishable from
      unknown-token failure (user enumeration via token endpoint)?

Output rows feed `30-auth-access-control` (takeover matrix) and `90`.

## 4. Version anchors and reading rules

- `GET /api2/json/version` -> `version` (pve-manager), `release`, `repoid`,
  sometimes `console`/`managerVersion`-style extra fields — record the whole
  JSON verbatim.
- Shell equivalent: `pveversion` -> `pve-manager/8.x.y (running kernel:
  6.x.y-z-pve)`.
- Component separation for `70` correlation: pve-manager, pve-kernel, QEMU
  (per-node `GET /nodes/{node}/version`), pveproxy — each is a distinct
  component with distinct advisories; never correlate a manager version
  against QEMU CVEs or vice versa.
- Debian base: PVE is Debian-based; distro-backport caveats from `70` apply
  to kernel/QEMU packages (upstream version frozen, patches backported).

