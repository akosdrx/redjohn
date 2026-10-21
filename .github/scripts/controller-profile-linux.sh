#!/usr/bin/env bash
# Root enters the existing profile; every workload runs as the original runner.
set -euo pipefail
test "$(id -u)" -eq 0
test "${SUDO_UID:?}" -ne 0
test "$#" -eq 1
test "$(pwd -P)" = "${GITHUB_WORKSPACE:?}"
task_workspace="$(pwd -P)"
case "${REDJOHN_TEST_CGROUP_ROOT:?}" in
  /sys/fs/cgroup/redjohn-ci-[0-9]*-X64|/sys/fs/cgroup/redjohn-ci-[0-9]*-ARM64) ;; *) exit 2 ;;
esac
printf '%s' "$$" > "$REDJOHN_TEST_CGROUP_ROOT/launcher-soak/cgroup.procs"
exec aa-exec -p "${REDJOHN_CI_APPARMOR_PROFILE:?}" -- \
  /usr/bin/setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups \
  env USER="$SUDO_USER" LOGNAME="$SUDO_USER" \
  PYTHONPATH="$task_workspace/RedJohn:$task_workspace/.github/scripts" \
  bash .github/scripts/controller-profile-cases.sh "$1"
