#!/usr/bin/env bash
# Build on the target OS/architecture using a Python environment containing
# the installed redjohn-core wheel (including its anthropic extra) and PyInstaller.
# REDJOHN_BUILD_PYTHON selects that interpreter; no sibling checkout at runtime.
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD_PYTHON="${REDJOHN_BUILD_PYTHON:-python3}"
OUT="resources/engine"
mkdir -p "$OUT" "resources/memory"
# Local OpenViking memory is optional (disabled by default via RJ_MEMORY_AUTO_START=0).
if [ "${BUILD_NATIVE_MEMORY:-0}" = "1" ] && [ -z "${SKIP_NATIVE_MEMORY:-}" ]; then
  "$BUILD_PYTHON" scripts/build-native-memory.py
fi
# Assessment tools are NOT bundled. The lightweight single-binary scanners are
# downloaded on demand into the profile at first run (redjohn_core.tool_provisioner,
# pinned by packaging/tool-versions.json); heavier tools are optional (system PATH).
# scripts/build-native-tools.py + build-metasploit.py remain for an optional manual
# bundle only and are no longer part of the default build.
"$BUILD_PYTHON" -c 'import PyInstaller, redjohn_core, anthropic, openai, websockets'
MIGRATIONS_DIR=$("$BUILD_PYTHON" -c 'from redjohn_core.migrate import MIGRATIONS_DIR; print(MIGRATIONS_DIR)')
[ -d "$MIGRATIONS_DIR" ] || { echo "Core migration data missing from the installed package" >&2; exit 1; }

BUNDLE_ARGS=(--noconfirm --clean)
if [ -d "${PWD}/skills" ]; then
  BUNDLE_ARGS+=(--add-data "${PWD}/skills:redjohn_core/skill_library")
fi
if [ -f "${PWD}/contracts/run-event.schema.json" ]; then
  BUNDLE_ARGS+=(--add-data "${PWD}/contracts/run-event.schema.json:redjohn_core/contracts")
fi
if [ "$("$BUILD_PYTHON" -c 'import sys; print(sys.platform)')" = linux ]; then
  # ctypes loads seccomp by a runtime name, so PyInstaller cannot infer it.
  # Resolve the loaded native file, then bundle its stable SONAME explicitly.
  mkdir -p "$OUT/.native"
  "$BUILD_PYTHON" - "$OUT/.native/libseccomp.so.2" <<'PYSECCOMP'
import ctypes, ctypes.util, shutil, sys
from pathlib import Path
library = ctypes.util.find_library("seccomp")
if not library:
    raise SystemExit("Linux engine build requires libseccomp2")
handle = ctypes.CDLL(library)
paths = {Path(line.split(maxsplit=5)[5]) for line in Path("/proc/self/maps").read_text().splitlines()
         if len(line.split(maxsplit=5)) == 6 and "/libseccomp.so." in line}
if len(paths) != 1:
    raise SystemExit("Unable to locate exactly one loaded libseccomp native library")
shutil.copy2(paths.pop(), sys.argv[1])
PYSECCOMP
  BUNDLE_ARGS+=(--add-binary "${PWD}/${OUT}/.native/libseccomp.so.2:.")
fi

"$BUILD_PYTHON" -m PyInstaller \
  --name redjohn-engine --onefile \
  --distpath "$OUT" --workpath "$OUT/.build" --specpath "$OUT/.build" \
  --collect-all redjohn_core --collect-all uvicorn --collect-all websockets --collect-all openai \
  --copy-metadata redjohn-core \
  --hidden-import sqlalchemy.dialects.sqlite.aiosqlite \
  --hidden-import sqlalchemy.dialects.sqlite.pysqlite \
  --add-data "${MIGRATIONS_DIR}:redjohn_core/migrations" \
  "${BUNDLE_ARGS[@]}" \
  scripts/engine-launcher.py

BIN="$OUT/redjohn-engine"
[ -f "$BIN" ] || { echo "PyInstaller did not produce $BIN" >&2; exit 1; }
"$BUILD_PYTHON" scripts/verify-engine.py "$BIN"
"$BUILD_PYTHON" - "$BIN" <<'PYINFO'
import datetime, hashlib, json, platform, sys
from pathlib import Path
binary = Path(sys.argv[1])
arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x64", "AMD64": "x64"}.get(platform.machine(), platform.machine())
data = {
    "platform": sys.platform,
    "arch": arch,
    "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    "built_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
(binary.parent / "build-info.json").write_text(json.dumps(data, indent=2))
PYINFO
echo "[ok] engine packaged and authenticated startup verified: $BIN"
