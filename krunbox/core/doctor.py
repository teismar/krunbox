"""
Diagnostic health checks and environment validation for Fedora, Ubuntu, Debian, Arch, and Linux hosts.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
from .images import ImageManager


class Doctor:
    @staticmethod
    def detect_distro() -> str:
        """Detect Linux distribution from /etc/os-release (e.g. fedora, ubuntu, debian, arch, opensuse)."""
        os_release = Path("/etc/os-release")
        if not os_release.exists():
            return "fedora"
        try:
            content = os_release.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("ID="):
                    return line.split("=", 1)[1].strip('"\'').lower()
        except Exception:
            pass
        return "fedora"

    @classmethod
    def get_install_command(cls, package_map: Dict[str, str], default_pkg: str) -> str:
        """Return distro-appropriate package installation command."""
        distro = cls.detect_distro()
        if distro in ("fedora", "rhel", "centos", "rocky", "alma"):
            pkg = package_map.get("dnf", default_pkg)
            return f"sudo dnf install {pkg}"
        elif distro in ("debian", "ubuntu", "linuxmint", "pop"):
            pkg = package_map.get("apt", default_pkg)
            return f"sudo apt install {pkg}"
        elif distro in ("arch", "manjaro", "endeavouros"):
            pkg = package_map.get("pacman", default_pkg)
            return f"sudo pacman -S {pkg}"
        elif distro in ("opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"):
            pkg = package_map.get("zypper", default_pkg)
            return f"sudo zypper install {pkg}"
        else:
            pkg = package_map.get("dnf", default_pkg)
            return f"sudo dnf install {pkg}"

    def check_all(self) -> List[dict]:
        checks = [
            self.check_kvm(),
            self.check_krun(),
            self.check_passt(),
            self.check_podman(),
            self.check_subuids(),
            self.check_tun(),
            self.check_fuse(),
            self.check_gtk(),
            self.check_ssh(),
            self.check_nft(),
            self.check_secrets_tool(),
            self.check_images(),
        ]
        return checks

    def check_kvm(self) -> dict:
        kvm_path = Path("/dev/kvm")
        exists = kvm_path.exists()
        readable = os.access(kvm_path, os.R_OK | os.W_OK) if exists else False
        status = "ok" if (exists and readable) else ("warn" if exists else "fail")
        msg = "KVM hardware virtualization acceleration available" if (exists and readable) else (
            "KVM device found but permission denied (add user to 'kvm' group)" if exists else
            "No /dev/kvm detected (enable virtualization in BIOS / nested virt)"
        )
        return {
            "component": "Hardware Virtualization (/dev/kvm)",
            "status": status,
            "message": msg,
            "remediation": "sudo usermod -aG kvm $USER" if exists else "Enable Intel VT-x / AMD-V in BIOS"
        }

    def check_krun(self) -> dict:
        krun_bin = shutil.which("krun")
        status = "ok" if krun_bin else "warn"
        remediation = self.get_install_command(
            {"dnf": "crun-krun", "apt": "crun", "pacman": "crun-krun", "zypper": "crun-krun"},
            default_pkg="crun-krun"
        )
        return {
            "component": "crun-krun MicroVM Runtime",
            "status": status,
            "message": f"Found at {krun_bin}" if krun_bin else "krun runtime not installed (fallback to container isolation)",
            "remediation": remediation
        }

    def check_passt(self) -> dict:
        passt_bin = shutil.which("passt")
        status = "ok" if passt_bin else "warn"
        remediation = self.get_install_command(
            {"dnf": "passt", "apt": "passt", "pacman": "passt", "zypper": "passt"},
            default_pkg="passt"
        )
        return {
            "component": "passt (MicroVM Network Virtualization)",
            "status": status,
            "message": f"Found at {passt_bin}" if passt_bin else "passt not found on host",
            "remediation": remediation
        }

    def check_podman(self) -> dict:
        podman_bin = shutil.which("podman")
        if not podman_bin:
            return {
                "component": "Podman Engine",
                "status": "fail",
                "message": "Podman not found in system PATH",
                "remediation": self.get_install_command(
                    {"dnf": "podman", "apt": "podman", "pacman": "podman", "zypper": "podman"},
                    default_pkg="podman"
                )
            }
        try:
            ver = subprocess.run(["podman", "--version"], capture_output=True, text=True).stdout.strip()
            return {
                "component": "Podman Engine",
                "status": "ok",
                "message": ver,
                "remediation": ""
            }
        except Exception:
            return {
                "component": "Podman Engine",
                "status": "warn",
                "message": "Podman executable failed to run",
                "remediation": self.get_install_command(
                    {"dnf": "podman", "apt": "podman", "pacman": "podman", "zypper": "podman"},
                    default_pkg="podman"
                )
            }

    def check_subuids(self) -> dict:
        subuid = Path("/etc/subuid")
        user = os.environ.get("USER", "root")
        has_subuid = False
        if subuid.exists():
            try:
                content = subuid.read_text()
                has_subuid = user in content or "1000" in content
            except Exception:
                pass
        return {
            "component": "Rootless SubUID Mappings",
            "status": "ok" if has_subuid else "warn",
            "message": f"SubUIDs configured for rootless containers" if has_subuid else "SubUID map entry missing for user",
            "remediation": f"sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {user}"
        }

    def check_gtk(self) -> dict:
        try:
            import gi
            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
            from gi.repository import Gtk, Adw

            gtk_ver = (Gtk.get_major_version(), Gtk.get_minor_version(), Gtk.get_micro_version())
            adw_ver = (Adw.get_major_version(), Adw.get_minor_version(), Adw.get_micro_version())
            has_modern_adw = hasattr(Adw, "AlertDialog") and hasattr(Adw, "AboutDialog")
            ver_str = f"GTK {gtk_ver[0]}.{gtk_ver[1]}.{gtk_ver[2]}, Libadwaita {adw_ver[0]}.{adw_ver[1]}.{adw_ver[2]}"

            if not has_modern_adw or adw_ver < (1, 5, 0):
                return {
                    "component": "GTK4 and Libadwaita Desktop Stack",
                    "status": "warn",
                    "message": f"{ver_str} (Libadwaita >= 1.5 recommended for modern adaptive dialogs)",
                    "remediation": self.get_install_command(
                        {
                            "dnf": "gtk4 libadwaita",
                            "apt": "gir1.2-gtk-4.0 gir1.2-adw-1",
                            "pacman": "gtk4 libadwaita",
                            "zypper": "gtk4 libadwaita",
                        },
                        default_pkg="gtk4 libadwaita",
                    ),
                }

            return {
                "component": "GTK4 and Libadwaita Desktop Stack",
                "status": "ok",
                "message": f"{ver_str} (modern Adw.Dialog & AlertDialog stack operational)",
                "remediation": "",
            }
        except Exception as e:
            remediation = self.get_install_command(
                {
                    "dnf": "python3-gobject gtk4 libadwaita",
                    "apt": "python3-gi gir1.2-gtk-4.0 gir1.2-adw-1",
                    "pacman": "python-gobject gtk4 libadwaita",
                    "zypper": "python3-gobject gtk4 libadwaita",
                },
                default_pkg="python3-gobject gtk4 libadwaita"
            )
            return {
                "component": "GTK4 and Libadwaita Desktop Stack",
                "status": "warn",
                "message": f"GUI library issue: {e}",
                "remediation": remediation
            }

    def check_ssh(self) -> dict:
        ssh_bin = shutil.which("ssh")
        keygen_bin = shutil.which("ssh-keygen")
        status = "ok" if (ssh_bin and keygen_bin) else "fail"
        remediation = self.get_install_command(
            {"dnf": "openssh-clients", "apt": "openssh-client", "pacman": "openssh", "zypper": "openssh"},
            default_pkg="openssh-clients"
        )
        return {
            "component": "OpenSSH Client Tooling",
            "status": status,
            "message": "OpenSSH client and keygen available" if (ssh_bin and keygen_bin) else "Missing ssh or ssh-keygen",
            "remediation": remediation
        }

    def check_tun(self) -> dict:
        tun_path = Path("/dev/net/tun")
        exists = tun_path.exists()
        readable = os.access(tun_path, os.R_OK | os.W_OK) if exists else False
        status = "ok" if (exists and readable) else ("warn" if exists else "fail")
        return {
            "component": "Network Tunnel Device (/dev/net/tun)",
            "status": status,
            "message": "Tunnel device accessible for rootless microVM networking" if (exists and readable) else (
                "Device permissions restrict unprivileged access" if exists else "Device not found"
            ),
            "remediation": "sudo chmod 666 /dev/net/tun"
        }

    def check_fuse(self) -> dict:
        fuse_path = Path("/dev/fuse")
        exists = fuse_path.exists()
        readable = os.access(fuse_path, os.R_OK | os.W_OK) if exists else False
        status = "ok" if (exists and readable) else ("warn" if exists else "fail")
        return {
            "component": "FUSE Filesystem Device (/dev/fuse)",
            "status": status,
            "message": "FUSE device accessible for rootless overlay storage" if (exists and readable) else (
                "Device permissions restrict unprivileged access" if exists else "Device not found"
            ),
            "remediation": "sudo chmod 666 /dev/fuse"
        }

    def check_nft(self) -> dict:
        nft_bin = shutil.which("nft")
        status = "ok" if nft_bin else "fail"
        remediation = ""
        if not nft_bin:
            remediation = self.get_install_command(
                {"dnf": "nftables", "apt": "nftables", "pacman": "nftables", "zypper": "nftables"},
                default_pkg="nftables",
            )
        return {
            "component": "nftables Tooling (nft)",
            "status": status,
            "message": f"Found at {nft_bin}" if nft_bin else "nftables binary (nft) not found on host",
            "remediation": remediation,
        }

    def check_secrets_tool(self) -> dict:
        st_bin = shutil.which("secret-tool")
        status = "ok" if st_bin else "fail"
        remediation = ""
        if not st_bin:
            remediation = self.get_install_command(
                {"dnf": "libsecret", "apt": "libsecret-tools", "pacman": "libsecret", "zypper": "libsecret-tools"},
                default_pkg="libsecret",
            )
        return {
            "component": "Secret Tool (libsecret)",
            "status": status,
            "message": f"Found at {st_bin}" if st_bin else "secret-tool not found on host",
            "remediation": remediation,
        }

    def check_images(self) -> dict:
        mgr = ImageManager()
        missing = []
        outdated = []
        for img in mgr.list_images():
            if not img["is_present"]:
                missing.append(img["id"])
            elif img.get("needs_rebuild"):
                outdated.append(f"{img['id']} ({img.get('rebuild_reason', 'outdated/spec')})")
        if missing or outdated:
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if outdated:
                details.append(f"needs update: {', '.join(outdated)}")
            return {
                "component": "Base Container Images",
                "status": "warn",
                "message": f"Images require build ({'; '.join(details)})",
                "remediation": "krunbox images build all"
            }
        return {
            "component": "Base Container Images",
            "status": "ok",
            "message": "All builtin base images are present and up to date",
            "remediation": ""
        }
