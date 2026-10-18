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
test "$#" -eq 1
task_python="$1"
test -x "$task_python"
printf '%s' "$$" > "$REDJOHN_TEST_CGROUP_ROOT/launcher/cgroup.procs"
exec /usr/bin/setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
  env USER="$SUDO_USER" LOGNAME="$SUDO_USER" \
  "$task_python" .github/scripts/ci.py run --name python-integration -- \
  timeout --signal=TERM --kill-after=20s 45m "$task_python" -m pytest \
  RedJohn/tests -q -s -p no:cacheprovider -p pytest_evidence --ci-suite=integration \
  -o junit_family=xunit1 --junitxml=artifacts/integration.junit.xml \
  --basetemp="$RUNNER_TEMP/redjohn-integration"
