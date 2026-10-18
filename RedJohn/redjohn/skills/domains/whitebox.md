---
name: whitebox
description: Read the code to find reachable sinks, then prove them. A scanner hit without a path is an open proof gap, not a finding.
---

# Whitebox

Source tells you where to look. It does not replace the proof bar.

## How to read

Start from entry points that an attacker can reach: routes, queue consumers, CLI args, uploaded files, webhooks. Trace data to a sink (query, template, process, deserializer, path, outbound request, auth decision). Note the control that is supposed to stop it, and check that the control sees this path. A helper that escapes HTML does nothing for a SQL identifier. A decorator on the common route does nothing for the sibling.

Semgrep, ast-grep, gitleaks, and trivy are triage. A rule match is a candidate. Confirm the path or leave `needs_follow_up`. Do not file the match.

Secrets in git history are a finding when the secret is real and still useful. A test fixture, a rotated key, and a high-entropy string you cannot place are not.

## Diffs

When the scope is a change, report what this change introduced, re-opened, or newly made reachable. A pre-existing bug in a file you opened for context is a note, not a finding against the change. A deleted check is a finding even though no new sink was added. Read the diff, not the pull-request description.

If you cannot run the app, a complete source → control → sink → impact trace is reportable at medium confidence, and you say the runtime proof is missing. A candidate you can neither confirm nor tie to a named control stays `needs_follow_up`.

## The fix is part of the report

The specialist who confirms the bug writes the fix in `create_vulnerability_report`: `code_locations` with the before and after, and `fix_pr_body`. The fix has to close the path you proved, including the sibling you noticed. Do not spawn another agent to re-derive it.

A fix you have not compared against the sink is a suggestion. If you are unsure it holds, say so in the report rather than inventing a patch that does not compile.
