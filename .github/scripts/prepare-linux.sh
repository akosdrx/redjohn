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
sudo mkdir "$REDJOHN_TEST_CGROUP_ROOT/launcher-regression" "$REDJOHN_TEST_CGROUP_ROOT/launcher-integration"
printf '%s' '+memory +pids' | sudo tee "$REDJOHN_TEST_CGROUP_ROOT/cgroup.subtree_control" > /dev/null
sudo chown -R "$(id -u):$(id -g)" "$REDJOHN_TEST_CGROUP_ROOT"
python - <<'PY'
import hashlib,json,os,subprocess
from pathlib import Path
source=Path('.github/fixtures/skill-source')
manifest=json.loads((source/'manifest.json').read_text())
# Compatibility for the existing unmodified provenance regression, only on CI.
target=Path('/Users/akosdrx/Documents/headless_strix_skillpack')
if target.exists():raise SystemExit('refuse_to_overwrite_existing_skill_source')
subprocess.run(['sudo','install','-d','-o',str(os.getuid()),'-g',str(os.getgid()),str(target)],check=True)
for relative,digest in manifest['sha256'].items():
    data=(source/relative).read_bytes()
    if hashlib.sha256(data).hexdigest()!=digest:raise SystemExit('skill_source_digest_mismatch')
    out=target/relative;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
from tests.remote_https_fixture import fixture_host
Path('artifacts/fixture-hosts.txt').write_text(fixture_host()+' redjohn-owned-fixture.test\n')
PY
sudo tee -a /etc/hosts < artifacts/fixture-hosts.txt > /dev/null
