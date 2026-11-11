"""
Unit tests for the modernized About dialog debug info collector.
"""

from unittest.mock import patch
import pytest

from krunbox.ui.window import _collect_about_debug_info


def test_collect_about_debug_info_content():
    """Verify that _collect_about_debug_info produces all expected diagnostic fields."""
    info = _collect_about_debug_info(cached_sandboxes_count=3)

    assert "=== Krunbox System & Diagnostic Info ===" in info
    assert "Krunbox: 2.0.0" in info
    assert "OS:" in info
    assert "Kernel:" in info
    assert "Python:" in info
    assert "Active Sandboxes: 3" in info
    assert "=== Virtualization & Runtimes ===" in info
    assert "Podman:" in info
    assert "Krun / crun-krun:" in info
    assert "KVM Hardware Acceleration:" in info
    assert "passt (Network Virtualization):" in info
    assert "Rootless SubUIDs:" in info
    assert "OpenSSH:" in info


def test_collect_about_debug_info_handles_missing_binaries():
    """Verify that debug info collector does not fail even if binaries are missing or raise exceptions."""
    with patch("shutil.which", return_value=None), patch("pathlib.Path.exists", return_value=False):
        info = _collect_about_debug_info(cached_sandboxes_count=0)
        assert "Not installed" in info
        assert "Not available" in info
        assert "Active Sandboxes: 0" in info
