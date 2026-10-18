# Remote assessment worker egress

Remote execution uses `redjohn.assessment.egress.LinuxEgressBoundary`. The host controller runs the inspected HTTP/TLS proxy. Every scanner or Chromium worker starts in a fresh Linux user, mount, PID, IPC, UTS and network namespace created by Bubblewrap. Its network namespace contains only loopback. No veth interface, external route, host DNS or UDP gateway is installed.

The only gateway is a namespace-local TCP listener on the proxy's loopback port. The trusted helper forwards that listener through one private Unix socket to the exact host proxy selected by the controller. Workers cannot select another host destination through this relay. The proxy remains responsible for origin, method, actor, request budget, rate limit, TLS and connection-time IP approval.

Before starting an actual worker, the helper requests attestation. The controller reads Linux `SO_PEERCRED` and `/proc/<peer>/...` itself: network, user, mount and PID namespaces must differ from the controller; only `lo` may exist; effective capabilities must be zero; `NoNewPrivs` must be set. A forwarding permit belongs to that live helper PID and its network namespace. Each stream is checked again. A host process cannot obtain a forwarding permit by sending a marker or changing `egress_mode`.

The mount namespace contains system runtime directories, explicit read-only tool/browser resources, a private writable workspace, a private `/tmp`, a minimal `/dev` and its own `/proc`. Host home directories, host `/run`, Docker sockets and host `/tmp` are not mounted. Controller launch shims are outside all worker-writable mounts. Chromium's existing sandbox stays enabled and its UID remains the caller's UID; run browser workers as a non-root account. Only the normal Playwright DevTools pipe descriptors 3 and 4 are preserved when `--remote-debugging-pipe` is present. Scanner workers inherit no extra host descriptors.

`start()` prepares the gateway. `attest()` executes a harmless child through the actual namespace launcher and fails closed on missing Bubblewrap or unavailable user namespaces. Only then do `assert_active()`, `wrap_argv()` and `executable_wrapper()` permit remote launches. Closing the boundary revokes the gateway and terminates its own still-attested helper processes, with a namespace identity check before signalling to protect against PID reuse.

The host proxy still has networking by design. This boundary confines workers; it does not constrain a target application's own outbound requests, prove that an arbitrary GET is free of application side effects, or provide a general container image. OS/kernel or same-user controller compromise is outside this boundary.

## Verification

The initial isolated Linux probe passed before the browser/cancellation additions. Its CI location was incorrect and the created branch/runs were removed after the repository owner correction. Current end-to-end acceptance must be established on the local Linux runner or in `akosdrx/redjohn`; an inaccessible/deleted CI URL is not current verification evidence.

On the current macOS development host, kernel-isolation tests are explicitly skipped, and actual remote execution is blocked with `blocked_linux_network_namespace_required`. Docker has no running daemon and no Colima/Lima instance exists. These are capability gaps, not negative security findings.

Linux prerequisite: install the distribution's `bubblewrap` package and allow unprivileged user namespaces for the RedJohn service account. A system policy that denies namespace creation yields a blocked capability. Do not automatically alter a production host's AppArmor or namespace policy to make a test pass.

```bash
python -m pytest tests/test_assessment_egress.py -q
```

The implementation calls Bubblewrap as an external program; it does not copy its code. Bubblewrap is LGPL-2.0-or-later. Record the installed distribution package version in each deployment's verification artifact. References: [Bubblewrap's own security model](https://github.com/containers/bubblewrap/blob/main/README.md), [Bubblewrap manual](https://manpages.debian.org/bookworm/bubblewrap/bwrap.1.en.html).
