"""Use the app's shared isolated Python with the bundled scanner dependencies."""
from pathlib import Path
import runpy
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "python"))
selected = sys.argv.pop(1)
if selected == "arjun":
    runpy.run_module("arjun", run_name="__main__")
elif selected == "sqlmap":
    sys.path.insert(0, str(root / "python" / "sqlmap"))
    runpy.run_path(str(root / "python" / "sqlmap" / "sqlmap.py"), run_name="__main__")
else:
    raise SystemExit("Unknown bundled Python tool")
