#!/usr/bin/env bash
set -euo pipefail
mkdir -p artifacts/tool-receipts
python RedJohn/scripts/install-nuclei-pinned.py > artifacts/tool-receipts/nuclei.json
python RedJohn/scripts/create-nuclei-fixture-lock.py
python RedJohn/scripts/install-ffuf-pinned.py > artifacts/tool-receipts/ffuf.json
for task_tool in httpx katana vulnx; do
  python RedJohn/scripts/install-projectdiscovery-pinned.py "$task_tool" > "artifacts/tool-receipts/$task_tool.json"
done
for task_tool in arjun sqlmap dalfox; do
  python RedJohn/scripts/install-specialists-pinned.py "$task_tool" > "artifacts/tool-receipts/$task_tool.json"
done
for task_tool in tinja schemathesis interactsh; do
  python RedJohn/scripts/install-schema-oast-pinned.py "$task_tool" > "artifacts/tool-receipts/$task_tool.json"
done
python - <<'PY'
import hashlib, importlib.metadata, json, platform, subprocess
from pathlib import Path
versions = {'machine': platform.machine(), 'python_distributions':
            {d.metadata['Name']: d.version for d in importlib.metadata.distributions()},
            'tools': {}}
for path in sorted(Path('RedJohn/.tools').glob('*/*/*')):
    if path.is_file() and path.name != 'fixture-lock.json':
        versions['tools'][str(path)] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                      'bytes': path.stat().st_size}
for name, argv in {'nuclei': ['RedJohn/.tools/nuclei/3.11.1/nuclei', '-version'],
                   'go': ['go', 'version'], 'node': ['node', '--version'],
                   'npm': ['npm', '--version'], 'bubblewrap': ['bwrap', '--version']}.items():
    result = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=True)
    versions[name] = (result.stdout + result.stderr).strip()
Path('artifacts/versions.json').write_text(json.dumps(versions, indent=2) + '\n')
PY
