"""
Desktop integration and icon installation for GNOME App Manager, Software, and Shell.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

DATA_DIR = Path(__file__).parent.parent / "data"

def get_target_directories(system: bool = False) -> Dict[str, Path]:
    if system and os.geteuid() == 0:
        base = Path("/usr/share")
    else:
        base = Path(os.path.expanduser("~/.local/share"))
    
    return {
        "applications": base / "applications",
        "metainfo": base / "metainfo",
        "icons": base / "icons" / "hicolor"
    }

def install_desktop_integration(system: bool = False) -> Dict[str, any]:
    """
    Installs the desktop entry, AppStream metainfo, and multi-resolution icons
    into standard Freedesktop/GNOME locations and updates system caches.
    """
    dirs = get_target_directories(system=system)
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    installed_files: List[str] = []

    # 1. Desktop Entry
    desktop_src = DATA_DIR / "io.krunbox.Krunbox.desktop"
    if desktop_src.exists():
        dest = dirs["applications"] / "io.krunbox.Krunbox.desktop"
        shutil.copy2(desktop_src, dest)
        installed_files.append(str(dest))

    # 2. AppStream Metainfo
    metainfo_src = DATA_DIR / "io.krunbox.Krunbox.metainfo.xml"
    if metainfo_src.exists():
        dest = dirs["metainfo"] / "io.krunbox.Krunbox.metainfo.xml"
        shutil.copy2(metainfo_src, dest)
        installed_files.append(str(dest))

    # 3. Scalable Vector Icons
    scalable_dir = dirs["icons"] / "scalable" / "apps"
    scalable_dir.mkdir(parents=True, exist_ok=True)
    svg_src = DATA_DIR / "icons" / "io.krunbox.Krunbox.svg"
    if svg_src.exists():
        dest = scalable_dir / "io.krunbox.Krunbox.svg"
        shutil.copy2(svg_src, dest)
        installed_files.append(str(dest))

    symbolic_dir = dirs["icons"] / "symbolic" / "apps"
    symbolic_dir.mkdir(parents=True, exist_ok=True)
    sym_src = DATA_DIR / "icons" / "io.krunbox.Krunbox-symbolic.svg"
    if sym_src.exists():
        dest = symbolic_dir / "io.krunbox.Krunbox-symbolic.svg"
        shutil.copy2(sym_src, dest)
        installed_files.append(str(dest))

    # 4. Raster PNG Icons
    sizes = [16, 24, 32, 48, 64, 128, 256, 512]
    for sz in sizes:
        png_src = DATA_DIR / "icons" / f"{sz}x{sz}" / "io.krunbox.Krunbox.png"
        if png_src.exists():
            dest_dir = dirs["icons"] / f"{sz}x{sz}" / "apps"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / "io.krunbox.Krunbox.png"
            shutil.copy2(png_src, dest)
            installed_files.append(str(dest))

    # 5. Refresh Freedesktop & GNOME caches
    cache_refreshed = False
    for bin_name in ["gtk4-update-icon-cache", "gtk-update-icon-cache"]:
        if shutil.which(bin_name):
            try:
                subprocess.run(
                    [bin_name, "-f", "-t", str(dirs["icons"])],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                cache_refreshed = True
                break
            except Exception:
                pass

    if shutil.which("update-desktop-database"):
        try:
            subprocess.run(
                ["update-desktop-database", str(dirs["applications"])],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    return {
        "success": True,
        "files_count": len(installed_files),
        "target_base": str(dirs["applications"].parent),
        "cache_refreshed": cache_refreshed
    }
