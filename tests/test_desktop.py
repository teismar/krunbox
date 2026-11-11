import os
import shutil
import subprocess
from pathlib import Path
import pytest

from krunbox.core.desktop import install_desktop_integration, DATA_DIR

def test_desktop_file_validity():
    desktop_file = DATA_DIR / "io.krunbox.Krunbox.desktop"
    assert desktop_file.exists()
    if shutil.which("desktop-file-validate"):
        res = subprocess.run(["desktop-file-validate", str(desktop_file)], capture_output=True, text=True)
        assert res.returncode == 0, f"Validation failed: {res.stderr}"

def test_metainfo_validity():
    metainfo_file = DATA_DIR / "io.krunbox.Krunbox.metainfo.xml"
    assert metainfo_file.exists()
    if shutil.which("appstreamcli"):
        res = subprocess.run(["appstreamcli", "validate", "--no-net", str(metainfo_file)], capture_output=True, text=True)
        assert res.returncode == 0, f"Validation failed: {res.stderr}"

def test_icon_assets_exist():
    icons_dir = DATA_DIR / "icons"
    svg_main = icons_dir / "io.krunbox.Krunbox.svg"
    svg_sym = icons_dir / "io.krunbox.Krunbox-symbolic.svg"
    assert svg_main.exists() and svg_main.stat().st_size > 0
    assert svg_sym.exists() and svg_sym.stat().st_size > 0

    sizes = [16, 24, 32, 48, 64, 128, 256, 512]
    for sz in sizes:
        png_file = icons_dir / f"{sz}x{sz}" / "io.krunbox.Krunbox.png"
        assert png_file.exists() and png_file.stat().st_size > 0

def test_install_desktop_integration(tmp_path, monkeypatch):
    fake_local = tmp_path / "share"
    fake_local.mkdir(parents=True)
    monkeypatch.setattr("os.path.expanduser", lambda p: str(fake_local) if "~/.local/share" in p else p)

    result = install_desktop_integration(system=False)
    assert result["success"] is True
    assert result["files_count"] >= 10

    # Verify desktop file placed
    installed_desktop = fake_local / "applications" / "io.krunbox.Krunbox.desktop"
    assert installed_desktop.exists()

    # Verify metainfo placed
    installed_metainfo = fake_local / "metainfo" / "io.krunbox.Krunbox.metainfo.xml"
    assert installed_metainfo.exists()

    # Verify scalable svg placed
    installed_svg = fake_local / "icons" / "hicolor" / "scalable" / "apps" / "io.krunbox.Krunbox.svg"
    assert installed_svg.exists()

    # Verify symbolic svg placed
    installed_sym = fake_local / "icons" / "hicolor" / "symbolic" / "apps" / "io.krunbox.Krunbox-symbolic.svg"
    assert installed_sym.exists()

def test_cli_install_desktop():
    from krunbox.cli.commands import cmd_install_desktop
    code = cmd_install_desktop(system=False)
    assert code == 0
