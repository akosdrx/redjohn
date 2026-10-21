#!/usr/bin/env bash
# Delegate a unique CI subtree. Never change AppArmor or other sysctls.
set -euo pipefail
test "$(id -u)" -ne 0
case "${REDJOHN_TEST_CGROUP_ROOT:?}" in
  /sys/fs/cgroup/redjohn-ci-[0-9]*-X64|/sys/fs/cgroup/redjohn-ci-[0-9]*-ARM64) ;;
  *) exit 2 ;;
esac
test -e /sys/fs/cgroup/cgroup.controllers
test ! -e "$REDJOHN_TEST_CGROUP_ROOT"
sudo mkdir "$REDJOHN_TEST_CGROUP_ROOT"
sudo mkdir "$REDJOHN_TEST_CGROUP_ROOT/launcher-regression" "$REDJOHN_TEST_CGROUP_ROOT/launcher-integration" "$REDJOHN_TEST_CGROUP_ROOT/launcher-soak"
printf '%s' '+memory +pids' | sudo tee "$REDJOHN_TEST_CGROUP_ROOT/cgroup.subtree_control" > /dev/null
sudo chown -R "$(id -u):$(id -g)" "$REDJOHN_TEST_CGROUP_ROOT"
python - <<'PY'
from pathlib import Path
from tests.remote_https_fixture import fixture_host
Path('artifacts/fixture-hosts.txt').write_text(fixture_host()+' redjohn-owned-fixture.test\n')
PY
sudo tee -a /etc/hosts < artifacts/fixture-hosts.txt > /dev/null
