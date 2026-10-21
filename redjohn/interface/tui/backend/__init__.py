"""Backend bridge for external TUI clients."""

from redjohn.interface.tui.backend.controller import TuiController
from redjohn.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]
