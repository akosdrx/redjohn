#!/usr/bin/env bash
# Fixed fresh-process controls; no arbitrary target/command parameters.
set -euo pipefail
test "$(id -u)" -ne 0
test "$#" -eq 1
task_python="$1"
test -x "$task_python"
task_failed=0
for task_case in idle playwright_import tls_fixture synthetic_pressure traced compact untraced; do
  task_cycles=2
  task_minimum=0
  task_interval=0
  task_owner_timeout=240
  task_outer_timeout=5m
  task_command=("$task_python" benchmarks/controller_probe.py --case "$task_case" --output "$GITHUB_WORKSPACE/artifacts/controller-$task_case")
  if test "$task_case" = traced || test "$task_case" = compact || test "$task_case" = untraced; then
    if test "${REDJOHN_CONTROLLER_PROFILE_LONG:-0}" = 1 && test "$task_case" != compact; then
      task_cycles=120
      task_minimum=1200
      task_interval=10
      task_owner_timeout=4140
      task_outer_timeout=70m
    fi
    task_tracing=on
    task_snapshot_mode=legacy
    if test "$task_case" = compact; then task_snapshot_mode=compact; fi
    if test "$task_case" = untraced; then task_tracing=off; fi
    task_command=("$task_python" benchmarks/mixed_soak.py
      --output "$GITHUB_WORKSPACE/artifacts/controller-$task_case"
      --nuclei-lock "$REDJOHN_NUCLEI_LOCK"
      --httpx-receipt "$GITHUB_WORKSPACE/.tools/httpx/1.12.0/receipt.json"
      --cycles "$task_cycles" --warmup 1 --interval-seconds "$task_interval" --minimum-seconds "$task_minimum"
      --allocation-tracing "$task_tracing" --snapshot-mode "$task_snapshot_mode" --controller-details)
  fi
  if ! "$task_python" .github/scripts/ci.py run --name "controller-$task_case" -- \
    timeout --signal=TERM --kill-after=20s "$task_outer_timeout" \
    "$task_python" -m redjohn.assessment.memory_exec \
    --delegated-root "$REDJOHN_TEST_CGROUP_ROOT" \
    --memory-budget-mib 2048 --aggregate-budget-mib 4096 \
    --pool-state-directory "$RUNNER_TEMP/controller-attribution-memory-pool" \
    --receipt "$GITHUB_WORKSPACE/artifacts/controller-$task_case-owner/receipt.json" \
    --timeout-seconds "$task_owner_timeout" -- "${task_command[@]}"; then
    task_failed=1
  fi
done
exit "$task_failed"
