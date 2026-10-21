"""Private, verified source snapshots for optional Python CLI processes.

No site packages, user startup, package installers or host Python imports are
visible to these tools. Their source/data/dependencies are a single pinned tar.
"""

from __future__ import annotations

import hashlib
import sys
import tarfile
from pathlib import Path, PurePosixPath

from redjohn.assessment.pinned_tools import PinnedToolRunner


BOOTSTRAP = """import sys,runpy
root,tool=sys.argv[1:3]
sys.path.insert(0,root)
sys.argv=[tool]+sys.argv[3:]
if tool=='arjun' and sys.argv[1:]==['--version']:
 import arjun
 print(arjun.__version__)
elif tool=='arjun':
 runpy.run_module('arjun',run_name='__main__')
elif tool=='schemathesis':
 from importlib.metadata import version
 from schemathesis.engine.run import probes
 expected=('NullByteInHeader','UnsafePathDecoder')
 if version('schemathesis')!='4.31.1' or tuple(p.__name__ for p in probes.PROBES)!=expected:
  raise ValueError('unreviewed_schemathesis_internal_probes')
 # These two unconditional CLI probes leave the selected operation and send
 # control characters. Disable only this verified version's preflight probes.
 # Real positive-integer case generation, transport and checks remain upstream.
 probes.run=lambda _ctx: [probes.ProbeRun(p(),probes.ProbeOutcome.SKIP) for p in probes.PROBES]
 from schemathesis.cli import schemathesis
 schemathesis()
else:
 runpy.run_path(root+'/sqlmap.py',run_name='__main__')
"""


class PinnedPythonToolRunner(PinnedToolRunner):
    proxy_url = ""

    def _prepare_payload(self) -> tuple[Path, ...]:
        assert self.workspace is not None
        byte_limit = (128 if self.tool == "schemathesis" else 64) * 1024**2
        file_limit = 8192 if self.tool == "schemathesis" else 4096
        if (
            self.binary.path.is_symlink()
            or self.binary.path.stat().st_size > byte_limit
            or hashlib.sha256(self.binary.path.read_bytes()).hexdigest() != self.binary.sha256
        ):
            raise ValueError("python_tool_bundle_digest_mismatch")
        total, count = 0, 0
        seen: set[str] = set()
        root = self.workspace / "source"
        root.mkdir(mode=0o700)
        with tarfile.open(self.binary.path) as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                total += member.size
                count += 1
                if (
                    not member.isfile()
                    or path.is_absolute()
                    or ".." in path.parts
                    or str(path) in seen
                    or path.parts[0] not in {"package", "dependency-licenses"}
                    or total > byte_limit
                    or count > file_limit
                ):
                    raise ValueError("python_tool_bundle_schema_error")
                seen.add(str(path))
                target = root / str(path)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                handle = archive.extractfile(member)
                assert handle is not None
                target.write_bytes(handle.read())
                target.chmod(0o400)
        if self.tool == "arjun":
            # Upstream always merges its special data, even with a custom
            # wordlist. A private derived data snapshot disables that expansion.
            # Source code is unchanged; the host approves every parameter name.
            special = root / "package/arjun/db/special.json"
            special.chmod(0o600)
            special.write_text("{}\n")
            special.chmod(0o400)
        return self.binary.path, root

    def _worker_argv(self, argv: list[str]) -> list[str]:
        assert self.workspace is not None
        return [
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            BOOTSTRAP,
            str(self.workspace / "source/package"),
            self.tool,
            *argv[1:],
        ]

    def _tool_environment(self) -> dict[str, str]:
        if self.tool != "arjun":
            return {}
        return {"HTTP_PROXY": self.proxy_url, "HTTPS_PROXY": self.proxy_url, "NO_PROXY": ""}
