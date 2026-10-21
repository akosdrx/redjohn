# Owned local header-regression capability

This capability implements a restricted part of master sections 5.4, 5.5 and
16. It is explicitly configured in the public assessment runtime, uses the same
durable scheduler and shared resource governor, and joins verified paired proof
into reports. The original RCE remains `not_reproduced_missing_fixture`.

Enable it with `"lab_validation":{"version":"redjohn-owned-header-lab-1"}`
alongside the existing `os_memory` configuration. Composition is inert: no
fixture, generated worker, browser or scanner starts merely from configuration.
The registry reports a configuration block when this section is absent.

The trusted host must hold and explicitly register an actual live
`asyncio.subprocess.Process` through `runtime.bind_owned_lab_fixture(binding)`.
JSON/PID metadata cannot grant authority. The API then uses
`create_owned_lab_plan(candidate_ref, surface_id, fixture_key)`,
`submit_owned_lab(plan_ref, phase, fixture_key, retest_revision=...)`, and
`runtime.scheduler.run_batch(max_jobs=1)`. After a distinct fixed deployment,
`validate_owned_lab(plan_ref, before_job, fixed_job)` verifies the durable pair
and records the exact graph edge. Reopened runtimes must rebind live host-owned
fixtures before further execution; completed proof can be read without keeping
the old fixture running.

## Implemented scope

The input is an actual completed, current-policy `headers_audit` candidate for
missing `X-Content-Type-Options`, its job-owned complete HTTP capture, and a
trusted host's `OwnedFixtureBinding`. The binding holds the real child-process
object, kernel PID/start identity, exact literal-loopback `/regression` URL,
fixture reference, source digest and deployment identity. Its asset must match
the existing inventory link. Target responses, imported scanner summaries and
job arguments cannot register a fixture or provide executable code.

`LabValidation` stores immutable plans and phase records in the existing SQLite
database. All execution still uses the existing `rj_job` queue and `Scheduler`.
Plans are limited to 32, fixture bindings to 64, phases to 64 and validation
assertions to 32 per engagement. Existing evidence quotas still apply. The
phase ledger is a transmission/proof ledger, not a second scheduler.

The host submits candidate and fixed-control phases using plan/fixture references.
Each job is explicitly non-idempotent for retry accounting, although its sole
permitted HTTP operation is a GET. A fixed phase needs a completed positive phase
in the same retest cohort and a distinct source/process/deployment. Phase
reservation, request charging and admission are fenced by the real current job,
attempt, owner, policy and kill switch. Shared persistent origin rate limits
apply. An incomplete reservation is not automatically replayed after restart;
an explicit retest revision is required. Reopening also requires a live trusted
host fixture binding. Cancellation respects the scheduler's existing campaign
stop behavior; this component never clears that stop.

## Actual execution boundary

`LabWorker` accepts no source, shell command or arbitrary argv. It generates one
constant header-regression artifact with a public carrier, validates exact source
and AST syntax, records its digest, and mounts its separate payload directory
read-only. The artifact uses a standard-library HTTP client and reports a bounded
JSON assertion. The real controller proxy separately records the fully framed
response, and both records must agree. The proxy admits exactly one generated
carrier and maps it only to the registered fixture GET; a target or worker cannot
select another destination, route, method or credential.

Execution requires the existing actual owned Linux memory fence and its current
namespace/control guard. It inherits that kernel hard budget. The generated
process additionally sets kernel limits of 2 CPU seconds, 128 MiB virtual address
space, 64 KiB file output, 64 descriptors and zero core-dump bytes. The existing
attested Linux egress namespace permits only the controller relay. Standard input
is `/dev/null`, environment is cleared, and each output stream is limited to 8 KiB.
Scheduler/worker deadlines, process groups, namespace descendants, proxy tasks
and temporary files are cleaned on success, failure, timeout and cancellation.
An unsuccessful cleanup propagates rather than producing successful evidence.
Pending process delivery is tracked before its first await and bounded at
acquisition. An unresolved delivery or unreaped process retains the **same**
governor reservation through the scheduler's cleanup guard, including its durable
host claim. A matching late-delivery reaper can prove cleanup later; only the
original trusted guard can then release the reservation through
`governor.recover_cleanup()`. There is no TTL-based capacity replacement.

Before the generated assertion runs, fixed negative controls require a direct
fixture socket to fail, an unreviewed proxy carrier to receive 403, and a payload
`chmod` to fail with `EROFS`. The generated artifact checks the read-only mount
again and reports actual CPU/address-space limit readback. These controls do not
turn arbitrary code into an accepted input.

A missing namespace, cgroup delegation or matching current memory proof blocks
this execution profile. There is no host execution fallback. Native macOS and
Docker generated-regression execution are not established by this component.
Address-space limits, cgroup charged memory and sampled RSS remain distinct.
The outside memory receipt supervisor and external daemon workloads retain the
limitations documented for the owned memory envelope.

## Proof-bound correlation

`ProofBoundCorrelation` requires separately completed candidate/fixed jobs, exact
policy/actor/session/workflow/asset/fixture context, source/process independence,
phase order, matching retest revisions, current template/artifact hashes,
namespace negative controls and complete controller-observed HTTP evidence.
Only then can it create an owned header assertion and its exact reachability
edge. A scanner message, confidence value, existing evidence reference or
caller-supplied `validated_in_lab` label is insufficient for this verifier.
`VulnerabilityCorrelator(..., lab_validation=runtime.lab_validation)` requires
this proof both when adding an edge and when querying persisted historical
edges. A generic unbound correlator rejects validated labels, including old
stored rows, rather than trusting their fixture/assertion strings. Current
policy, active inventory context and both completed phase jobs are revalidated.

The assertion records expected/observed/fixed behavior, exact evidence references,
tool/template versions, scoped CWE-693 classification, low technical severity,
and `business_risk=not_assessed`. It confirms only the missing-header condition
in this owned fixture. It proves no RCE, CVE impact, credential access, command
injection, SSTI or general exploit chain. The existing historical finding is not
silently rewritten: the report shows a separate scoped owned-lab assertion,
while the scanner candidate retains its original provenance/status. Reports
receive a typed `lab_validation` instance and reject a different store or
engagement. `ConfiguredAssessment.metrics()` also includes revalidated
`owned_lab` status. Invalid or stale proof is blocked/inconclusive, never a
confirmed or negative test result.

The compatibility `SafeReproducerGenerator`/`AIExploitGenerator` still supports
its old observe/export APIs. `validate_pair()` now returns a candidate,
`measurement_only=true` and `promotion_status=blocked_persisted_paired_lab_proof_required`.
Caller-provided deployment labels no longer produce `confirmed_weakness`.
An explicitly bound `validate_owned_pair()` delegates to the same durable verifier.

## Verification and remaining scope

Local `test_lab_validation_contract.py` uses explicitly synthetic process/proof
state to check authority, immutable source, inventory/candidate binding, durable
queue deduplication, admission fencing, unknown outcomes, storage failure and
kill-switch behavior. Those are contract tests, not kernel integration evidence.

The original component-only receipt remains retained separately (52 passed).
The public-integration contract group adds schema/lazy composition, live-binding
rejection, shared queue deduplication/rebind, immutable historical graph checks,
stale policy/asset/phase/memory/assertion proof, and proof-joined reporting. The
worker lifecycle fault group separately tests pending delivery, cancellation,
late reaping and an unreaped child retaining its original reservation. These
records are synthetic contracts, not native process/namespace proof.

The final public-slice focused run completed **97 passed, 0 failed, 0 skipped
in 11.85 seconds** on macOS. It includes 17 public integration contracts,
3 synthetic lifecycle faults, 24 lab authority contracts, 28 preserved active
reproducer/intelligence checks and 25 existing registry/runtime/host-resource
checks. Strict mypy passes all 11 production modules for Linux and Darwin;
Ruff, formatting and bytecode compilation pass. No full local suite or VM run
was substituted for the four hosted native cases.

The separate Linux-only `test_lab_validation_live.py` prepares four real cases:
positive/fixed source deployments with actual database reopen, slow response,
oversized response, and cancellation after actual target admission followed by
restart. They exercise existing scheduler jobs, real generated artifacts,
namespaces, cgroups, evidence, correlation and the public report. All four cases
compose `AssessmentRuntime`; no test registry injection remains. Run them only
with a private delegated cgroup; required hosted jobs must fail on missing
capabilities rather than count them as negative results:

```sh
REDJOHN_REQUIRE_OS_MEMORY=1 \
REDJOHN_TEST_CGROUP_ROOT=/sys/fs/cgroup/OPERATOR_PRIVATE_TEST_ROOT \
REDJOHN_OS_MEMORY_MEASUREMENTS=/ABSOLUTE/PRIVATE/measurements \
.venv/bin/python -m pytest -q tests/test_lab_validation_live.py \
  --junitxml=/ABSOLUTE/PRIVATE/lab-live.junit.xml
```

All four native cases (`positive`, `slow`, `oversized`, `cancel`) in `test_lab_validation_live.py`
have been **executed and verified green on both `Ubuntu 24.04 x64` and `Ubuntu 24.04 ARM64`**
at frozen commit `fd7c0d41df9204e57d8136194336bee2e2378a93` (tree `1cda168ca12323c4c078e221e6a2e51e87a6c8ec`)
in both [Native smoke run 39241380785](https://github.com/akosdrx/redjohn/actions/runs/39241380785)
(`4/4 passed`, `0 failed`, `0 skipped` in the `lab` suite) and
[Full Ubuntu validation run 39241380765](https://github.com/akosdrx/redjohn/actions/runs/39241380765)
(`443/443 passed` across the complete real integration suite). Two live transport/authority
details were hardened for this proof:
1. `LabWorker.execute` provisions `LinuxEgressBoundary(..., max_connections=4)` so the
   isolated `_egress_worker.py` can maintain its persistent `b"A"` attestation socket while
   opening `b"S"` HTTP stream relays, and attaches `response_policy=inspect_response` to
   `BrowserEgressProxy` so raw `X-Content-Type-Options` headers are captured before
   `on_complete` records transport proof.
2. In `tests/owned_lab_driver.py`, the `cancel` scenario invokes `await coordinator.cancel()`
   on the campaign coordinator after cancelling the active job task, ensuring reopened
   validation authority is blocked by the campaign kill-switch as required.

There is no automatic lab deployment from CLI JSON and no arbitrary source-execution
entry point. A host owner must manage each exact fixture deployment. Automatic
canonical finding promotion, authenticated fixtures and additional mechanisms
remain outside this restricted header capability.
Nmap imported endpoints or summaries cannot supply observed service proof; a
future service correlation requires its completed job, validated transport proof
and actual inventory service observation.
