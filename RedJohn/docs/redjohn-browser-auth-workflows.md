# Reviewed browser login, MFA and logout

RedJohn can run explicitly reviewed browser authentication plans in the existing
persistent scheduler. They use the existing sandboxed headless Chromium service,
resource governor, proxy, namespace enforcement and cleanup. This adds no generic
script runner, free-form click API, JavaScript evaluation or implicit account
permissions. No optional scanner starts during configuration.

A plan has at most eight typed `navigate`, `fill`, `submit`, or `wait` actions.
Selectors identify exactly one element by ID or field name. A submit action must
match the reviewed POST form action/method, exact field set, private filled
values, and a named DOM nonce. Unreviewed requests and forms are denied before
upstream admission. Navigation is limited to the plan's explicit GET URLs and
all POST endpoints must independently satisfy the existing HTTPS replay policy.
Form responses currently require HTTP 200; redirects and other authentication
protocols are not silently generalized.

Authentication becomes ready only after a real browser request to the reviewed
identity endpoint returns HTTP 200 JSON with exactly the expected `actor` and
`tenant` values. Successful logout requires the reviewed form POST followed by
an identity request returning 401/403. A login increments the numeric session
revision; verified logout increments it again and marks the identity revoked.
MFA is an explicitly supplied private single-use code. External push approval,
WebAuthn, OAuth discovery, CAPTCHA solving, password resets, code guessing and
automatic TOTP generation are not implemented by this plan executor.

## Protected configuration

The assessment JSON may include:

```json
{
  "browser_auth_flow": {
    "private_inputs_file": "/absolute/private/auth-inputs.json",
    "private_state_file": "/absolute/private/browser-state.json",
    "plans": [{
      "name": "alice-login",
      "revision": "1",
      "actor_id": "alice",
      "tenant_id": "owned",
      "allowed_get_urls": [
        "https://approved.example/login",
        "https://approved.example/whoami"
      ],
      "identity_url": "https://approved.example/whoami",
      "outcome": "authenticated",
      "actions": [
        {"kind":"navigate","url":"https://approved.example/login"},
        {"kind":"fill","selector":"#username","input_ref":"alice:username"},
        {"kind":"fill","selector":"#password","input_ref":"alice:password"},
        {"kind":"submit","selector":"#login_form",
         "url":"https://approved.example/login","nonce_selector":"#csrf",
         "nonce_field":"csrf","fields":["username","password","csrf"]},
        {"kind":"fill","selector":"#otp","input_ref":"alice:otp"},
        {"kind":"submit","selector":"#mfa_form",
         "url":"https://approved.example/mfa","nonce_selector":"#csrf",
         "nonce_field":"csrf","fields":["otp","csrf"]},
        {"kind":"wait","selector":"#authenticated"}
      ]
    }]
  }
}
```

The current policy separately needs the named actor and exact approved login/MFA
POST URLs. The example is a declared contract, not automatic website discovery.
A matching logout plan uses a reviewed account page and explicit logout form;
the normal read-only logout prohibition remains intact.

Both private files must already exist as regular, owner-owned, mode-0600 files.
The existing private-file reader and atomic writer reject unsafe file shapes,
links and permission changes. They must never enter Git, prompts, screenshots,
trace/HAR exports, public artifacts or command-line arguments.

The inputs file contains `version: 1`, `engagement_id`, `owner_id`,
`policy_revision`, a random 32-byte `state_key_base64`, and an `inputs` array.
Each input has exactly `reference`, `actor_id`, `tenant_id`, `purpose`, `value`,
`single_use`, and `expires_at`. Purposes are `username`, `password`, `mfa_code`,
or `nonce`; MFA/nonce inputs must be single use. Values total at most 16 KiB,
individual values at most 4 KiB, with at most 64 records. A fresh one-use input
requires a fresh opaque reference in the reviewed plan; changing an already
consumed reference's value never makes it reusable.

The initial private state file contains `version: 1`, `engagement_id`, `owner_id`,
`policy_revision`, and `flows: {}`. The host records bounded storage/checkpoint
state there (64 entries, 256 KiB total). SQLite stores only references and public
identity/state metadata. DOM nonce identities use a keyed HMAC, not a public
low-entropy OTP/cookie hash. State writes compare the fingerprint recorded when
loading, so concurrent actors cannot silently overwrite each other's checkpoint.

## Starting and resuming

The normal launcher remains:

```sh
redjohn assess run --config /absolute/approved.json --output /absolute/run --max-jobs 16
```

Configuration registers selected plans without implicitly signing in. The
owner-bound control operations are `auth_plan_search`, `auth_flow_start`
(`plan_id`, `run_key`), `auth_flow_get` (`flow_id`), and `auth_flow_submit`
(`flow_id`, `expected_revision`). Every call also requires the current
`policy_revision`. For example, an authorized host application can use the same
composition and scheduler as the CLI:

```python
async with ConfiguredAssessment(config, output, caller="operator") as assessment:
    control = assessment.runtime.control
    plans = await control.call("auth_plan_search", {"policy_revision": "1"})
    started = await control.call("auth_flow_start", {
        "policy_revision": "1", "plan_id": selected_plan_id, "run_key": "owned-login-1"
    })
    flow_id = started["result"]["flow_id"]
    await control.call("auth_flow_submit", {
        "policy_revision": "1", "flow_id": flow_id, "expected_revision": 1
    })
    await assessment.runtime.scheduler.run_until_idle(max_jobs=16)
```

Input values are never accepted through that control API. If a required private
input is missing/expired after a completed challenge, the host checkpoints the
challenge as `awaiting_input`, closes page/context/browser resources, and returns
blocked coverage with `workflow_private_input_required`. After updating the
protected input file, inspect the current flow revision and explicitly submit
that revision. Restart restores the committed private challenge without
repeating the completed login POST. Removed plans cannot be started, submitted
or executed through the current configuration; historical outcomes stay readable.

## Admission, uncertainty and capture

One-use references are consumed in the same SQLite transaction as admission,
before numeric upstream connect. A completed checkpoint settles them but never
makes them reusable. Cancellation/lease loss before an uncheckpointed admission
can pause at the prior committed checkpoint. After admission, an unknown outcome
stays uncertain and blocks automatic reuse/retry. A crash must not be reported
as an exactly-once network guarantee. There is no invented rollback or broad
cleanup against an unknown account/object.

An authentication job and existing session/workflow fences preserve actor,
tenant, policy and session revision. Private checkpoint/evidence writes precede
the ready CAS; the ready session UPDATE must change exactly one row. A failure
in the subsequent capture/bootstrap callback downgrades the committed identity
to uncertain rather than leaving a successful-looking session.

Restart also reconciles at most 128 interrupted authentication flows. An exact
still-leased producing job remains untouched. A dead producer with no unsettled
admission can become `awaiting_input` only when its protected private checkpoint
matches the committed action index and identity; a checkpoint ahead of SQLite,
missing required checkpoint, legacy unknown producer, or admitted request stays
`uncertain`. The normal scheduler's expired-job recovery also fences abandoned
auth flows conservatively when no protected checkpoint is available. No path
resets consumed one-use references or automatically repeats the request.

When reviewed `browser_capture_file`, `auth_vault_file`, and optional continuous
replay rules are configured, the capture service validates the real
`auth_flow_outcome`, current ready flow/session, producing scheduler job and
exact protected checkpoint. It derives only cookie-scoped approved GET start
bindings, then atomically updates the private replay vault. The runtime queues
only that actor/tenant's reviewed current capture starts. The existing proxy
produces exact POST evidence; existing configured replay can then queue Nuclei.
The callback never turns an arbitrary browser/storage-state dictionary into
execution permission.

Authentication proof expires after 300 seconds. Expired, revoked or superseded
checkpoints are skipped on restart; bootstrap rejection is recorded as
`auth_restore_blocked` for that identity. It does not abort unrelated identities
or repopulate stale browser state. Session/CSRF-sensitive cache entries are
invalidated on successful state changes.

## Verification

Focused commands:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_auth_flow_state_contract.py \
  RedJohn/tests/test_browser_auth_flow_live.py -q
```

The contract file uses real SQLite and protected files. Its manufactured
checkpoint/commit records and no-browser trap are explicitly contract coverage,
not live authentication evidence. It checks one-use persistence, cancellation
admission, callback failure, session CAS, private-file CAS, actor/tenant binding,
removed plans and independent network-budget concurrency/restart fences.

The five real cases use an owned CA-verified HTTPS application and actual
sandboxed Chromium. The positive case performs two actors' login/MFA/whoami,
Alice's missing-input pause and SQLite restart, private session restore,
automatic browser POST capture, two actual pinned Nuclei positive replays and
two fixed retests, restart deduplication, and logout/revocation. The oracle checks
2 login POSTs, 2 MFA POSTs, 2 logout POSTs, 2 automatic capture POSTs, 4 Nuclei
replay POSTs, 8 settled one-use references, and zero final server sessions or
challenges. JUnit suite properties retain these counts. Negative real cases
cover wrong MFA, an off-scope form blocked before any POST, and wrong identity.
The fifth case cancels a real MFA POST after the owned server has consumed its
code and created a session but before returning a response. It proves local
cleanup and a persistent uncertain outcome with no repeated POST; the server's
unknown session is reported explicitly and is not described as rolled back.
Uncertain negative application sessions are not described as rolled back.

All cases assert browser context cleanup; runtime/fixture teardown closes the
owned browser/listener and deletes its ephemeral CA. No external credentials or
LLM/provider are used. The loopback run does not claim remote namespace/cgroup
proof: those remain separate active hosted Linux tests. Missing real Chromium
or Nuclei is a blocked capability/skip, never a successful integration. Full
x64/ARM64 regression runs in hosted Actions rather than a replacement local suite.
