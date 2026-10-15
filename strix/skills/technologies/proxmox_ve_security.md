---
name: proxmox_ve_security
description: Use when a Proxmox VE host or cluster is in scope - pveproxy on :8006
  and API token audit, PAM and PVE realm privilege checks, cluster and node attack
  surface, VM and container boundary checks, and Proxmox CVE correlation by version.
---

# Proxmox VE (P8)

Surface mapping, auth-model audit and boundary observation for PVE hosts
and clusters. Default posture: unauthenticated fingerprinting plus
credentialed read-only reads.

## The way

- The version anchor is `/api2/json/version` (or `pveversion`) — and
  manager, kernel and QEMU are *different components with different
  advisories*; each goes to `70` separately.
- `/api2/json/cluster/status` answering unauthenticated is itself a
  finding; the hardened 401 is recorded as the good outcome, not as
  nothing.
- Ticket flow discipline: state-changing methods need the cookie *and*
  the CSRF token — a ticket-only state change is a misconfiguration
  candidate.
- With a read credential, `/access/permissions` is the core authz
  exhibit: effective privileges vs least-privilege expectation. Token
  audit = expiry, privilege separation, admin-user tokens.
- Boundary defaults are conservative: version correlation and read-only
  config pulls. Escape testing, cluster-plane traffic, VNC attach and
  token brute force are RoE-gated and OFF by default — the boundary
  table in `references/` is the gate.

## Handoffs

Pinned versions -> `70`; token/realm findings -> `30`; authorized depth
-> `45`; replay pairs -> `20`.

## Tools

`proxmox_surface_probe.py` (guarded). Endpoint map, authz model and the
default-vs-gated boundary table in `references/`.

---

## Reference Module: `proxmox-api-surface`

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


---

## Reference Module: `proxmox-authz`

# Proxmox authorization model and audit procedure

Realms, path-based permissions, the built-in roles, and the credentialed
audit procedure.

## 1. Realms

| Realm | Backing store | Meaning |
|---|---|---|
| `pam` | Linux `/etc/passwd`/PAM on the node | system users; `root@pam` is the node superuser — full cluster admin by default |
| `pve` | Proxmox cluster user database (`/etc/pve/user.cfg`) | PVE-native users, managed via API/GUI |
| (others: ldap/ad/oidc/openssh-style) | external IdP backends when configured | treat per engagement; note SSO trust implications in the report |

User id: `user@realm`. API token id: `user@realm!tokenid`.

## 2. Path-based permissions

Permissions attach to object paths and grant roles:

| Path | Object |
|---|---|
| `/vms/<vmid>` | one VM or container |
| `/nodes/<node>` | one node |
| `/pool/<pool>` | resource pool (grouping vms + storage) |
| `/storage/<storeid>` | storage |
| `/access/groups/<group>` | user group |
| `/` | root — grants on `/` are effectively global |

Rules:

- ACL entries carry user/group, role, path and a `propagate` flag (children
  inherit unless off).
- Effective access of a credential = union of matching ACLs for its user
  (and groups), possibly restricted for tokens with privilege separation
  enabled.
- `/access/permissions` returns exactly this map for the caller — it is the
  authoritative evidence; do not infer permissions from UI behavior.

## 3. Built-in roles (common set)

Verify the full table against the Proxmox VE Administration Guide at
authoring time; the commonly audited set:

| Role | Scope of power (summary) |
|---|---|
| `Administrator` | full control on the path (and children when propagating) |
| `PVEAdmin` | administer the object but not permissions (no user/ACL management) |
| `PVEAuditor` | read-only visibility |
| `PVEVMAdmin` | full control of VM/console incl. power operations |
| `PVEVMUser` | use VM (console, power) without config changes |
| `PVEDatastoreAdmin` / `PVEDatastoreUser` | storage management / usage |
| `PVEUserAdmin` | user management on the path |

Reading rules: `PVEVMAdmin` includes guest-agent-based commands and console
access — treat as high impact on multi-tenant clusters; `PVEAuditor` on `/`
still discloses the full inventory (data-value finding, not low).

## 4. Credentialed audit procedure

1. Authenticate with the supplied token/ticket (env-held secret).
2. `GET /api2/json/access/permissions` — save verbatim; this is the
   effective-privilege exhibit.
3. `GET /api2/json/cluster/resources` — everything visible; note objects
   outside the engagement's expected tenant/pool.
4. For each visible node: `GET /nodes`, `/nodes/{node}/qemu`, `/lxc`,
   `/nodes/{node}/version` — inventory + versions (-> `70`).
5. Compare the permission map against the engagement's least-privilege
   statement: expected paths vs actual; role per path; propagate surprises
   (grant on `/` or on `/nodes` root).
6. Cross-tenant check: for an object the credential should NOT touch (another
   pool), attempt the READ only (`GET .../config`); a 200 = D1 boundary
   finding -> `30`; do not attempt writes.
7. Record negative results ("403 on all out-of-tenant reads") — they are the
   authorization coverage statement for the report.

## 5. Common findings vocabulary

- Over-privileged token (role X on `/` vs expected `/vms/123`).
- Never-expiring token (`expire` empty) on an admin user.
- Privilege separation disabled on a shared token.
- `PVEVMAdmin`+ console on multi-tenant node (escape-adjacent, feeds the
  boundary discussion, not an escape claim by itself).
- Permission map absent/hard to obtain = monitoring gap note for `85`.


---

## Reference Module: `proxmox-boundary-rules`

# Proxmox boundary rules: default-allowed vs RoE-gated

What this skill may do without further approval, and what needs written RoE.
Default = the engagement scope file alone; RoE-gated = explicit written
authorization naming the action class and target.

## Default-allowed (with scope file only)

- TCP connect checks + TLS handshake on 8006; GET `/`, `/api2/json/version`,
  `/api2/json/cluster/status` (unauthenticated reads; record everything).
- sshd banner read on 22 (no auth attempts).
- Connect-observation of 3128 (SPICE proxy) and 5900-5999 (VNC) — port
  open/closed only, NO handshake beyond what a plain connect does, NO VNC
  attach, NO authentication attempts.
- corosync UDP 5405-5412: port-answering observation from a position that can
  see them; no corosync protocol interaction.
- Credentialed read-only API reads with an operator-supplied credential
  (GET-only per the endpoint map): version, permissions, resources, node and
  guest configs, token inventory.
- Version correlation via `70` (offline advisories preferred).

## RoE-gated (default OFF)

| Action class | Gate | Reason |
|---|---|---|
| Guest escape testing (QEMU/LXC exploit attempts, `45`-style) | written authorization; disposable test VM only | impact on shared host |
| Corosync/cluster-plane interaction beyond observation (join attempts, packet injection, quorum games) | written authorization; realistically only in a lab cluster | cluster integrity |
| VNC/SPICE console attach (even with valid creds) | written authorization | console input is guest-state modification |
| qemu-guest-agent command execution via API (`/agent/...` endpoints) | written authorization + guest owner sign-off | agent exec is arbitrary command execution inside the guest |
| Token/account brute-force beyond single-digit verification attempts | bounded plan, operator-approved ceiling, lockout policy confirmed first | lockout/DoS risk on shared infra |
| Any state-changing API call (VM start/stop/migrate/create, storage ops, ACL changes) | outside this skill entirely | prove writability with a read-equivalent or document the API contract, do not execute |
| Host shell via sshd with operator creds | engagement's general host-testing rules, not this skill | separate surface |

## Node-to-node trust (concept level, for report narrative)

- PVE clusters replicate config via pmxcfs (corosync-delivered); nodes hold
  shared cluster secrets. Compromise of one node therefore implies potential
  cluster-wide config manipulation — a risk statement for the report, derived
  from evidence of node compromise, never demonstrated by pivoting between
  nodes inside this skill.
- Join information (fingerprints, addresses) visible to low-privilege users
  is a recon finding; attempting to forge a join is cluster manipulation
  (gated above).

## Guest-agent observation notes

- Config field `agent: 1` on a qemu guest = qemu-guest-agent channel enabled;
  privileged API users can execute guest-side commands through it.
- Record enablement per guest as an observation row; the exec itself is gated.
- Agent channels also leak guest details (interfaces, filesystems) to the
  host — relevant to the tenant-boundary narrative in the report.

## Stop conditions

- Any unexpected production impact (a guest acting strangely, API errors
  spiking): stop, record the observation, notify the operator — per the
  master stop rule, a committed stop cancels all further requests.

