#!/usr/bin/env bash
# Enter only the job-owned enforcing profile, then drop host privileges.
set -euo pipefail
test "$(id -u)" -eq 0
test "${SUDO_UID:?}" -ne 0
test "$#" -eq 1
test -x "$1"
test "$(pwd -P)" = "${GITHUB_WORKSPACE:?}"
case "${REDJOHN_TEST_CGROUP_ROOT:?}" in
  /sys/fs/cgroup/redjohn-ci-[0-9]*-X64|/sys/fs/cgroup/redjohn-ci-[0-9]*-ARM64) ;;
  *) exit 2 ;;
esac
printf '%s' "$$" > "$REDJOHN_TEST_CGROUP_ROOT/launcher-integration/cgroup.procs"
exec aa-exec -p "${REDJOHN_CI_APPARMOR_PROFILE:?}" -- \
  /usr/bin/setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
  env USER="$SUDO_USER" LOGNAME="$SUDO_USER" \
  "$1" .github/scripts/live-model-e2e.py \
  --work "${RUNNER_TEMP:?}/redjohn-live-model-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}" \
  --output "$GITHUB_WORKSPACE/artifacts/live-model"
