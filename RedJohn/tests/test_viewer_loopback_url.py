"""Viewer URL formatting and loopback-only host contract."""

from redjohn.interface.viewer.server import _viewer_base_url


def test_viewer_formats_ipv6_loopback_with_brackets():
    assert _viewer_base_url("::1", 8765) == "http://[::1]:8765"
    assert _viewer_base_url("127.0.0.1", 8765) == "http://127.0.0.1:8765"
