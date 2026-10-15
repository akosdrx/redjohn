"""Frozen desktop engine entry point. Never depends on a sibling checkout."""
import sys
from multiprocessing import freeze_support

if __name__ == "__main__":
    freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "--sandbox-helper":
        from redjohn_core.linux_sandbox import main
        raise SystemExit(main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--tool-mcp":
        from redjohn_core.native_tool_mcp import main
        raise SystemExit(main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--vuln-intel-mcp":
        from redjohn_core.vuln_intel_mcp import main
        raise SystemExit(main(sys.argv[2:]))
    from redjohn_core.serve import main
    raise SystemExit(main())
