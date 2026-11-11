"""
Unit tests for host diagnostics, nftables, and secret-tool checks.
"""

from unittest.mock import patch
from pathlib import Path
from krunbox.core.doctor import Doctor


def test_doctor_checks():
    doc = Doctor()
    checks = doc.check_all()
    assert len(checks) >= 11

    components = [c["component"] for c in checks]
    assert any("Hardware Virtualization" in c for c in components)
    assert any("Podman" in c for c in components)
    assert any("passt" in c for c in components)
    assert any("GTK4" in c for c in components)
    assert any("nftables" in c for c in components)
    assert any("Secret Tool" in c for c in components)

    for c in checks:
        assert c["status"] in ("ok", "warn", "fail")


def test_doctor_check_nft():
    doc = Doctor()
    with patch("shutil.which", return_value="/usr/sbin/nft"):
        res = doc.check_nft()
        assert res["status"] == "ok"
        assert "/usr/sbin/nft" in res["message"]

    with patch("shutil.which", return_value=None):
        res = doc.check_nft()
        assert res["status"] == "fail"
        assert "nftables" in res["remediation"]


def test_doctor_check_secrets_tool():
    doc = Doctor()
    with patch("shutil.which", return_value="/usr/bin/secret-tool"):
        res = doc.check_secrets_tool()
        assert res["status"] == "ok"

    with patch("shutil.which", return_value=None):
        res = doc.check_secrets_tool()
        assert res["status"] == "fail"
        assert "secret" in res["remediation"]


def test_doctor_distro_remediation(tmp_path, monkeypatch):
    doc = Doctor()
    monkeypatch.setattr("pathlib.Path.exists", lambda self: True)
    monkeypatch.setattr("pathlib.Path.read_text", lambda self, encoding="utf-8": 'ID=debian\n')

    assert doc.detect_distro() == "debian"
    with patch("shutil.which", return_value=None):
        res = doc.check_nft()
        assert "apt install nftables" in res["remediation"]

    monkeypatch.setattr("pathlib.Path.read_text", lambda self, encoding="utf-8": 'ID=arch\n')
    assert doc.detect_distro() == "arch"
    with patch("shutil.which", return_value=None):
        res = doc.check_nft()
        assert "pacman -S nftables" in res["remediation"]
