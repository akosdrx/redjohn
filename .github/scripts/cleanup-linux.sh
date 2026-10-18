#!/usr/bin/env bash
# Record before cleaning only the uniquely named, job-owned CI cgroup.
set -euo pipefail
case "${REDJOHN_TEST_CGROUP_ROOT:?}" in
  /sys/fs/cgroup/redjohn-ci-[0-9]*-X64|/sys/fs/cgroup/redjohn-ci-[0-9]*-ARM64) ;;
  *) exit 2 ;;
esac
python - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['REDJOHN_TEST_CGROUP_ROOT'])
result={'root':str(root),'groups':{},'populated_before_cleanup':False}
if root.exists():
    for group in [root,*sorted(root.rglob('*'))]:
        if not group.is_dir():continue
        data={}
        for name in ('cgroup.events','cgroup.procs','memory.current','memory.peak','memory.events','memory.max','pids.current','pids.max'):
            path=group/name
            if path.exists():data[name]=path.read_text().strip()
        result['groups'][str(group.relative_to(root))]=data
    result['populated_before_cleanup']='populated 1' in (root/'cgroup.events').read_text()
Path('artifacts').mkdir(exist_ok=True)
Path('artifacts/cgroup-before-cleanup.json').write_text(json.dumps(result,indent=2)+'\n')
PY
if test -d "$REDJOHN_TEST_CGROUP_ROOT"; then
  printf 1 | sudo tee "$REDJOHN_TEST_CGROUP_ROOT/cgroup.kill" > /dev/null
  for task_wait in $(seq 1 50); do
    if ! grep -q 'populated 1' "$REDJOHN_TEST_CGROUP_ROOT/cgroup.events"; then break; fi
    sleep 0.1
  done
  ! grep -q 'populated 1' "$REDJOHN_TEST_CGROUP_ROOT/cgroup.events"
  sudo find "$REDJOHN_TEST_CGROUP_ROOT" -mindepth 1 -depth -type d -exec rmdir '{}' +
  sudo rmdir "$REDJOHN_TEST_CGROUP_ROOT"
fi
python - <<'PY'
import json,os
from pathlib import Path
root=Path(os.environ['REDJOHN_TEST_CGROUP_ROOT'])
before=json.loads(Path('artifacts/cgroup-before-cleanup.json').read_text())
result={'removed':not root.exists(),'leaked_processes':before['populated_before_cleanup']}
Path('artifacts/cgroup-cleanup.json').write_text(json.dumps(result,indent=2)+'\n')
if not result['removed'] or result['leaked_processes']:
    raise SystemExit('owned_process_cleanup_incomplete_before_final_safety_cleanup')
PY
