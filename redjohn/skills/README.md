# RedJohn skills

Skills are short contracts injected into an agent prompt. They state the proof bar and the traps a model usually gets wrong. They do not list the steps of a test.

The twelve core skills are always available alongside the optional assessment catalog.

Always loaded, and not selectable:

| Skill | Who |
| --- | --- |
| `coordination/root` | The coordinator. Decompose, spawn, reconcile. Do not test. |
| `analysis/safety` | Every specialist. Closure, severity, impact ceiling. |
| `tooling/sandbox` | Every specialist. Browser sessions, `exec_command`, Caido, the Python venv. |

The coordinator picks one or two of these per specialist:

`recon`, `auth`, `injection`, `rce`, `client`, `logic`, `api`, `supply`, `whitebox`.

`whitebox` is also loaded automatically when the run has source. Scan depth (`quick`, `standard`, `deep`, and diff scope) is part of the system prompt, not a skill.

A new skill has to earn a slot: it must be a RedJohn constraint or a trap the model reliably misses. A vulnerability class the model already knows does not get a file.

The `assessment/manifest.json` catalog indexes 47 additional English assessment contracts.
Their bodies load only when requested; eligibility comes from actual capability health,
target domain, impact profile, actor, fixture and input-format checks. A listed skill does
not imply that its optional scanner adapter is implemented or available.

English adaptations preserve each original `source_sha256`. Their separate
`content_sha256` identifies the current English document, and
`translation_input_sha256` identifies the preceding RedJohn contract. User-supplied
source packages outside this repository remain unchanged. These references do not
grant licenses to external scanner tools or import upstream Strix/HexStrike code.
