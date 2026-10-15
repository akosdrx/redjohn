---
name: proxmox_boundary_rules
description: 'Proxmox boundary rules: default-allowed vs RoE-gated (from proxmox_ve_security
  specialist reference library)'
---

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

