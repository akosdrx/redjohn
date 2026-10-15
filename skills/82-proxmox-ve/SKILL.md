---
name: 82-proxmox-ve
description: Use when a Proxmox VE host or cluster is in scope - pveproxy on :8006 and API token audit, PAM and PVE realm privilege checks, cluster and node attack surface, VM and container boundary checks, and Proxmox CVE correlation by version.
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
