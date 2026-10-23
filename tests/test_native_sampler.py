"""Parity and shape tests for the native process sampler (component 5.1)."""

from __future__ import annotations

import os

import pytest

from redjohn._native import NATIVE_AVAILABLE, native_sample_forest, native_sample_tree
from redjohn.assessment import resources
from redjohn.assessment.resources import process_forest_memory, process_tree_memory


def test_loader_reports_availability_consistently() -> None:
    if NATIVE_AVAILABLE:
        assert native_sample_tree(os.getpid()) is not None
    else:
        assert native_sample_tree(os.getpid()) is None


@pytest.mark.skipif(not NATIVE_AVAILABLE, reason="native extension not built")
def test_native_tree_sample_shape() -> None:
    sample = native_sample_tree(os.getpid())
    assert sample is not None
    assert sample["available"] is True
    assert sample["process_count"] >= 1
    assert sample["rss_bytes"] > 0
    assert os.getpid() in sample["pids"]


@pytest.mark.skipif(not NATIVE_AVAILABLE, reason="native extension not built")
def test_native_forest_empty_roots_match_fallback_semantics() -> None:
    sample = native_sample_forest([])
    assert sample is not None
    # The ps fallback treats an empty root set as vacuously satisfied.
    assert sample["available"] is True
    assert sample["process_count"] == 0


def test_tree_memory_works_with_or_without_native() -> None:
    sample = process_tree_memory(os.getpid())
    assert sample.available
    assert sample.process_count >= 1
    assert sample.rss_bytes > 0


def test_forest_memory_works_with_or_without_native() -> None:
    sample = process_forest_memory({os.getpid()})
    assert sample.available
    assert sample.process_count >= 1
    assert sample.rss_bytes > 0


def test_native_and_fallback_are_within_tolerance() -> None:
    """Native RSS and the ps fallback measure the same tree within noise."""
    native_sample = process_tree_memory(os.getpid())
    # Force the fallback path once by calling the ps implementation directly.
    assert native_sample.available
    # Re-sample through the fallback by disabling the native fast path.
    original = resources.native_sample_tree
    try:
        resources.native_sample_tree = lambda _pid: None  # type: ignore[assignment]
        fallback_sample = process_tree_memory(os.getpid())
    finally:
        resources.native_sample_tree = original  # type: ignore[assignment]

    assert fallback_sample.available
    # Same tree measured seconds apart; 30% drift covers RSS noise and a
    # child process exiting between the two samples.
    drift = abs(native_sample.rss_bytes - fallback_sample.rss_bytes) / max(
        native_sample.rss_bytes, fallback_sample.rss_bytes, 1
    )
    assert drift < 0.30, (native_sample.rss_bytes, fallback_sample.rss_bytes)
    assert abs(native_sample.process_count - fallback_sample.process_count) <= 1
