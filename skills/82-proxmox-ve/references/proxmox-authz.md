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
