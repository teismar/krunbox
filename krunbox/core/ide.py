"""
1-Click IDE and SFTP file-manager launchers for krunbox sandboxes over OpenSSH.
"""

import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .ssh import get_supported_terminals, launch_ssh_terminal, sanitize_ssh_identifier

IDE_SPECS: Dict[str, Dict[str, Any]] = {
    "terminal": {
        "key": "terminal",
        "name": "SSH Terminal",
        "label": "SSH Terminal",
        "short_name": "SSH Terminal",
        "binaries": [],
    },
    "vscode": {
        "key": "vscode",
        "name": "VS Code (Remote-SSH)",
        "label": "VS Code (Remote-SSH)",
        "short_name": "VS Code",
        "binaries": ["code", "code-insiders", "codium"],
    },
    "cursor": {
        "key": "cursor",
        "name": "Cursor (Remote-SSH)",
        "label": "Cursor (Remote-SSH)",
        "short_name": "Cursor",
        "binaries": ["cursor"],
    },
    "zed": {
        "key": "zed",
        "name": "Zed (Remote-SSH)",
        "label": "Zed (Remote-SSH)",
        "short_name": "Zed",
        "binaries": ["zed", "zeditor"],
    },
    "jetbrains": {
        "key": "jetbrains",
        "name": "JetBrains Gateway (SSH)",
        "label": "JetBrains Gateway (SSH)",
        "short_name": "JetBrains Gateway",
        "binaries": ["jetbrains-gateway", "gateway"],
    },
    "sftp": {
        "key": "sftp",
        "name": "File Manager (SFTP)",
        "label": "File Manager (SFTP)",
        "short_name": "File Manager",
        "binaries": ["gio", "xdg-open", "nautilus", "dolphin", "thunar"],
    },
}

_UNSAFE_PATH_CHARS = re.compile(r"[\s\x00-\x1f\x7f;|&`$<>?#\"'\\]")


def _validate_remote_path(remote_path: str) -> Optional[str]:
    """Validate remote POSIX workspace path, rejecting whitespace, control, and shell/URI metacharacters."""
    if not isinstance(remote_path, str):
        return None
    if not remote_path.startswith("/"):
        return None
    if _UNSAFE_PATH_CHARS.search(remote_path):
        return None
    return remote_path


def detect_installed_ides() -> Dict[str, Optional[str]]:
    """Detect which supported IDE / terminal / SFTP binaries are installed on the host."""
    detected: Dict[str, Optional[str]] = {}
    for ide_key, spec in IDE_SPECS.items():
        if ide_key == "terminal":
            found_term: Optional[str] = None
            seen = set()
            for cmd in get_supported_terminals("krunbox"):
                bin_name = cmd[0]
                if bin_name in seen:
                    continue
                seen.add(bin_name)
                resolved = shutil.which(bin_name)
                if resolved:
                    found_term = resolved
                    break
            detected[ide_key] = found_term
            continue

        found_bin: Optional[str] = None
        for bin_name in spec["binaries"]:
            resolved = shutil.which(bin_name)
            if resolved:
                found_bin = resolved
                break
        detected[ide_key] = found_bin
    return detected


def _build_ide_command(
    ide_key: str,
    bin_name: str,
    clean_target: str,
    safe_remote_path: str,
    ssh_port: int,
) -> List[str]:
    if ide_key in ("vscode", "cursor"):
        return [bin_name, "--remote", f"ssh-remote+{clean_target}", safe_remote_path]
    if ide_key == "zed":
        return [bin_name, f"ssh://{clean_target}{safe_remote_path}"]
    if ide_key == "jetbrains":
        return [bin_name, f"ssh://vscode@127.0.0.1:{ssh_port}{safe_remote_path}"]
    if ide_key == "sftp":
        uri = f"sftp://{clean_target}{safe_remote_path}"
        if bin_name == "gio":
            return ["gio", "open", uri]
        return [bin_name, uri]
    raise ValueError(f"Unsupported IDE launcher key: {ide_key!r}")


def _missing_binary_message(
    ide_key: str,
    clean_target: str,
    safe_remote_path: str,
    ssh_port: int,
) -> str:
    if ide_key == "vscode":
        return (
            f"VS Code is not installed on host "
            f"(connect manually with: code --remote ssh-remote+{clean_target} {safe_remote_path})"
        )
    if ide_key == "cursor":
        return (
            f"Cursor is not installed on host "
            f"(connect manually with: cursor --remote ssh-remote+{clean_target} {safe_remote_path})"
        )
    if ide_key == "zed":
        return (
            f"Zed is not installed on host "
            f"(connect manually with: zed ssh://{clean_target}{safe_remote_path})"
        )
    if ide_key == "jetbrains":
        return (
            f"JetBrains Gateway is not installed on host "
            f"(connect manually with: jetbrains-gateway ssh://vscode@127.0.0.1:{ssh_port}{safe_remote_path})"
        )
    if ide_key == "sftp":
        return (
            f"File Manager (SFTP) is not installed on host "
            f"(connect manually with: gio open sftp://{clean_target}{safe_remote_path})"
        )
    return f"{ide_key} is not installed on host"


def launch_ide(
    sandbox_name: str,
    ide_key: str,
    remote_path: str = "/workspace",
    ssh_port: int = 2222,
) -> Tuple[bool, str]:
    """Launch the requested IDE or file manager attached to sandbox_name over OpenSSH."""
    if not isinstance(sandbox_name, str):
        return False, f"Invalid target identifier for IDE connection: {sandbox_name!r}"

    clean_target = sanitize_ssh_identifier(sandbox_name)
    if (
        not clean_target
        or clean_target.startswith("-")
        or clean_target != sandbox_name.strip().lower()
    ):
        return False, f"Invalid target identifier for IDE connection: {sandbox_name!r}"

    safe_remote_path = _validate_remote_path(remote_path)
    if not safe_remote_path:
        return False, f"Invalid remote workspace path: {remote_path!r}"

    if isinstance(ssh_port, bool) or not isinstance(ssh_port, int) or not (1 <= ssh_port <= 65535):
        return False, f"Invalid SSH port: {ssh_port!r}"

    normalized_key = (ide_key or "").strip().lower()
    if normalized_key not in IDE_SPECS:
        return False, f"Unsupported IDE launcher: {ide_key!r}"

    if normalized_key == "terminal":
        return launch_ssh_terminal(clean_target)

    spec = IDE_SPECS[normalized_key]
    for bin_name in spec["binaries"]:
        if shutil.which(bin_name):
            cmd = _build_ide_command(
                normalized_key,
                bin_name,
                clean_target,
                safe_remote_path,
                ssh_port,
            )
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return True, f"Launched {spec['short_name']} via {bin_name} (PID {proc.pid})"
            except Exception:
                continue

    return False, _missing_binary_message(normalized_key, clean_target, safe_remote_path, ssh_port)
