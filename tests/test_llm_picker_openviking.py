"""Regression tests for the openviking TUI action contracts (K-audit M2/M3)."""

from __future__ import annotations

import pytest

from redjohn.config import loader


def test_save_openviking_selection_accepts_grouped_clear(monkeypatch) -> None:
    # The inherit action passes the grouped clear flags; a TypeError here is
    # exactly the M2 regression (clear_vlm_model was never a real kwarg).
    monkeypatch.setattr(loader, "persist_current", lambda **_kwargs: None, raising=False)
    env_before = dict(loader.os.environ)
    try:
        loader.save_openviking_selection(
            enabled=True,
            clear_vlm=True,
            clear_vlm_api_key=True,
            clear_vlm_api_base=True,
        )
    finally:
        loader.os.environ.clear()
        loader.os.environ.update(env_before)

    assert loader.os.environ.get("REDJOHN_OPENVIKING_ENABLED") in {None, "true"}


def test_save_openviking_selection_rejects_unknown_clear_kwarg(monkeypatch) -> None:
    monkeypatch.setattr(loader, "persist_current", lambda **_kwargs: None, raising=False)
    env_before = dict(loader.os.environ)
    try:
        with pytest.raises(TypeError):
            loader.save_openviking_selection(  # type: ignore[call-arg]
                enabled=True,
                clear_vlm_model=True,
            )
    finally:
        loader.os.environ.clear()
        loader.os.environ.update(env_before)
