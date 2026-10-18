#!/usr/bin/env bash
# This script runs as root only long enough to join the delegated launcher.
# The test process always execs as the original unprivileged runner account.
set -euo pipefail
test "$(id -u)" -eq 0
test -n "${SUDO_UID:?}"
test "$SUDO_UID" -ne 0
case "${REDJOHN_TEST_CGROUP_ROOT:?}" in
  /sys/fs/cgroup/redjohn-ci-[0-9]*-X64|/sys/fs/cgroup/redjohn-ci-[0-9]*-ARM64) ;;
  *) exit 2 ;;
esac
test "$#" -eq 2
task_python="$1"
task_suite="$2"
task_workspace="$(pwd -P)"
test "$task_workspace" = "$GITHUB_WORKSPACE"
case "$task_suite" in regression|integration|capability|soak) ;; *) exit 2 ;; esac
test -x "$task_python"
if test "$task_suite" = capability; then
  # Profile entry happens while privileged, but all probes run after UID/GID
  # and host capabilities have been dropped, just like the real E2E suite.
  exec aa-exec -p "${REDJOHN_CI_APPARMOR_PROFILE:?}" -- \
    /usr/bin/setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
    env USER="$SUDO_USER" LOGNAME="$SUDO_USER" \
    PYTHONPATH="$task_workspace/RedJohn:$task_workspace/.github/scripts" \
    "$task_python" .github/scripts/capabilities.py
fi
printf '%s' "$$" > "$REDJOHN_TEST_CGROUP_ROOT/launcher-$task_suite/cgroup.procs"
task_profile=()
if test "$task_suite" = integration || test "$task_suite" = soak; then
  task_profile=(aa-exec -p "${REDJOHN_CI_APPARMOR_PROFILE:?}" --)
fi
if test "$task_suite" = soak; then
  exec "${task_profile[@]}" /usr/bin/setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
    env USER="$SUDO_USER" LOGNAME="$SUDO_USER" \
    PYTHONPATH="$task_workspace/RedJohn:$task_workspace/.github/scripts" \
    "$task_python" .github/scripts/ci.py run --name mixed-soak -- \
    timeout --signal=TERM --kill-after=20s 70m "$task_python" RedJohn/benchmarks/mixed_soak.py \
    --output "$task_workspace/artifacts/mixed-soak" \
    --nuclei-lock "$REDJOHN_NUCLEI_LOCK" \
    --httpx-receipt "$task_workspace/RedJohn/.tools/httpx/1.12.0/receipt.json" \
    --cycles "${REDJOHN_SOAK_CYCLES:?}" --warmup 1 --interval-seconds 10 \
    --minimum-seconds "${REDJOHN_SOAK_MINIMUM_SECONDS:?}"
fi
exec "${task_profile[@]}" /usr/bin/setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
  env USER="$SUDO_USER" LOGNAME="$SUDO_USER" \
  PYTHONPATH="$task_workspace/RedJohn:$task_workspace/.github/scripts" \
  "$task_python" .github/scripts/ci.py run --name "python-$task_suite" -- \
  timeout --signal=TERM --kill-after=20s 45m "$task_python" -m pytest \
  RedJohn/tests -q -s -p no:cacheprovider -p pytest_evidence --ci-suite="$task_suite" \
  -o junit_family=xunit1 --junitxml="artifacts/$task_suite.junit.xml" \
  --basetemp="$RUNNER_TEMP/redjohn-$task_suite"
