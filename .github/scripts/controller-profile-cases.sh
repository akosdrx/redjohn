#!/usr/bin/env bash
# Fixed fresh-process controls; no arbitrary target/command parameters.
set -euo pipefail
test "$(id -u)" -ne 0
test "$#" -eq 1
task_python="$1"
test -x "$task_python"
task_failed=0
for task_case in idle playwright_import tls_fixture synthetic_pressure traced untraced; do
  task_command=("$task_python" RedJohn/benchmarks/controller_probe.py --case "$task_case" --output "$GITHUB_WORKSPACE/artifacts/controller-$task_case")
  if test "$task_case" = traced || test "$task_case" = untraced; then
    task_tracing=on
    if test "$task_case" = untraced; then task_tracing=off; fi
    task_command=("$task_python" RedJohn/benchmarks/mixed_soak.py
      --output "$GITHUB_WORKSPACE/artifacts/controller-$task_case"
      --nuclei-lock "$REDJOHN_NUCLEI_LOCK"
      --httpx-receipt "$GITHUB_WORKSPACE/RedJohn/.tools/httpx/1.12.0/receipt.json"
      --cycles 2 --warmup 1 --interval-seconds 0 --minimum-seconds 0
      --allocation-tracing "$task_tracing" --controller-details)
  fi
  if ! "$task_python" .github/scripts/ci.py run --name "controller-$task_case" -- \
    timeout --signal=TERM --kill-after=20s 5m \
    "$task_python" -m redjohn.assessment.memory_exec \
    --delegated-root "$REDJOHN_TEST_CGROUP_ROOT" \
    --memory-budget-mib 2048 --aggregate-budget-mib 4096 \
    --pool-state-directory "$RUNNER_TEMP/controller-$task_case-memory-pool" \
    --receipt "$GITHUB_WORKSPACE/artifacts/controller-$task_case-owner/receipt.json" \
    --timeout-seconds 240 -- "${task_command[@]}"; then
    task_failed=1
  fi
done
exit "$task_failed"
