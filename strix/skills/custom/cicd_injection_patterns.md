---
name: cicd_injection_patterns
description: 'CI/CD injection patterns: catalog, detection, severity (from supply_chain_integrity
  specialist reference library)'
---

# CI/CD injection patterns: catalog, detection, severity

Doc-example workflows only (`example-org/example-repo`); adapt to the
engagement's real workflows. Detection regexes mirror
`scripts/workflow_scan.py` — the script triages, the operator confirms
(regexes cannot see `if:` guards, reusable-workflow indirection, or
composite actions in other repos).

## Pattern 1: pull_request_target + PR-head checkout + PR-controlled
execution (the classic triad)

Severity: CRITICAL when the triad is in one job; the trigger alone is
MEDIUM context. CWE-78 class (script injection) executed in CI context.

Doc-example vulnerable workflow (`.github/workflows/ci.yml`):

```yaml
name: CI
on:
  pull_request_target:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build and test the PR
        run: make test
      - name: Report
        run: echo "Testing ${{ github.event.pull_request.title }}"
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
```

Why it is vulnerable:

1. `pull_request_target` runs the workflow definition from the BASE branch
   with base-repo secrets and write access.
2. `ref: ${{ github.event.pull_request.head.sha }}` checks out the FORK's
   commit — from here, the workspace content is attacker-controlled.
3. `make test` executes the PR's own Makefile (same for `npm test` /
   `npm ci && npm run build` / `go test ./...` — any tool that reads
   workspace files), so the attacker's build file runs with
   `secrets.REPORT_TOKEN` in the environment.

Detection regexes (what workflow_scan.py looks for):

| Signal | Regex |
|---|---|
| Fork-context trigger | `\bpull_request_target\b` |
| PR-head checkout | `github\.event\.pull_request\.head\.(sha\|ref)` or `ref:\s*refs/pull/` |
| PR-controlled execution | `run:` block invoking `make`, `npm ci`, `npm (run\|test)`, `go (test\|build)`, `pytest`, `bash scripts/`, `./gradlew` in the same job as the PR-head checkout |

Secure doc-example shape (what good looks like):

```yaml
name: CI (labels only for forks)
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
jobs:
  label:
    if: github.repository == 'example-org/example-repo'
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/labeler@<full-commit-sha>
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
```

`pull_request` (without `_target`) checks out the PR merge ref WITHOUT
secrets — running PR code belongs there, never under `_target`.

## Pattern 2: script injection via `run:` interpolation

Severity: HIGH when a user-controlled `github.event.*` field (or
`github.head_ref`) is interpolated directly into a `run:` block; MEDIUM for
non-user-controlled context fields (still a hygiene issue).

Vulnerable doc examples:

```yaml
      - run: echo "PR title: ${{ github.event.pull_request.title }}"
      - run: echo "branch: ${{ github.head_ref }}"
      - run: ./ci/comment.sh "${{ github.event.issue.title }}"
      - run: echo "commit: ${{ github.event.head_commit.message }}"
```

Payloads (string reaches the shell verbatim): `` `id` ``, `$(id)`,
`$(curl ...)` inside the PR title, branch name, issue title or commit
message.

User-controlled field prefixes (the script's list):

- `github.event.pull_request.title` / `.body` / `.head.ref` / `.head.label`
  / `.head.repo.*` (attacker's fork metadata)
- `github.event.issue.title` / `.body` (`issues.*` variants)
- `github.event.comment.body`, `github.event.review.body`,
  `github.event.review_comment.body`
- `github.event.discussion.title` / `.body`
- `github.event.commits[*].message`, `github.event.head_commit.message`
- `github.head_ref` (context-level branch name — separate regex)

Remediation marker (env indirection + quoting):

```yaml
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "PR title: $PR_TITLE"
```

Env indirection passes the value as an environment variable instead of
template-substituting into the shell text — its presence next to the
`secrets`/event reference is what downgrades the finding.

Detection regex: `\$\{\{\s*github\.(event\.[A-Za-z0-9_.\[\]"]*|head_ref)\s*\}\}`
found inside a `run:` block (the script tracks block-scalar continuation
lines by indentation).

## Pattern 3: secrets in fork-reachable jobs

Severity: HIGH. Any `secrets.<NAME>` referenced in a job whose workflow
triggers include `pull_request_target` (or that runs on
`github.event.pull_request` payloads of a `_target` workflow via
`workflow_run` chains — check those too) is exposed to fork authors once
patterns 1/2 land.

Detection regex: `secrets\.[A-Za-z_][A-Za-z0-9_]*` in a job block of a
workflow whose `on:` contains `pull_request_target`.

Evidence rule: record the secret NAME and the job context only. Never
attempt to exfiltrate the value; impact is argued from the code path
(D1/D2), and any value handling needs explicit written authorization.

## Pattern 4: artifact poisoning (concept check)

Severity: observation -> finding depending on the consumption chain. Jobs
that BUILD from PR code under `pull_request_target` (or `pull_request` with
write permissions) and `upload-artifact`; a later trusted job
(`needs:`-chained or scheduled deploy) downloads that artifact and
publishes/executes it. The regex scan flags `upload-artifact` /
`download-artifact` adjacency across trust boundaries; confirm by reading
the `needs:` graph manually.

## Pattern 5: floating action references

Severity: LOW observation. `uses: example-org/action@v4` or `@main` —
mutable tags; a tag can be repointed. Full 40-char SHA pins
(`uses: example-org/action@<full-sha>`) are the control. Record per-action
rows; mass-unpinned actions raise the supply-chain posture note in the
report.

Detection regex: `uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?![0-9a-f]{40})(\S+)`

## Other CI families (generic job-template review)

The same three questions, family-agnostic:

1. Does an untrusted string (MR title/branch, issue text, fork env var)
   reach a shell script block by template interpolation?
2. Which secrets are scoped to which job, and are any reachable from
   untrusted-trigger jobs? (GitLab: protected refs; Jenkins: credentials
   binding + branch restrictions; Azure Pipelines: `resources.repositories`
   trust + `variables` mapping.)
3. Does a job execute files fetched from the untrusted ref?

## Severity reasoning summary

| Combination | Severity |
|---|---|
| Triad complete (target trigger + head checkout + PR-run) | CRITICAL |
| User-controlled interpolation into `run:` | HIGH |
| Secrets referenced in fork-reachable job | HIGH (with 1/2) / MEDIUM (alone, context) |
| `pull_request_target` present (no triad) | MEDIUM (review trigger) |
| Artifact crossing trust boundary | MEDIUM (chain-dependent) |
| Floating action tag | LOW observation |

