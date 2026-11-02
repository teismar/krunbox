"""
Scoped secret and environment variable vault for krunbox sandboxes.

Supports libsecret / GNOME Keyring ('secret-tool') with automatic fallback to a
0600 private JSON vault and zero-wiped in-memory runtime '--env-file' staging
so secret values never appear on CLI process command lines ('ps aux').
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional

from . import config as core_config
from .config import DATA_DIR
from .ssh import sanitize_ssh_identifier

_INITIAL_DATA_DIR = DATA_DIR

ENV_KEY_REGEX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

FORBIDDEN_ENV_KEYS = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "SSH_AUTH_KEYS",
    "IFS",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "PYTHONPATH",
    "NODE_OPTIONS",
}

_FORBIDDEN_ENV_KEYS_UPPER = frozenset(k.upper() for k in FORBIDDEN_ENV_KEYS)
_KEYRING_ATTR_KEY_REGEX = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$")


def is_valid_env_key(key: str) -> bool:
    """Validate environment variable name and reject dangerous loader/shell variables."""
    if not isinstance(key, str) or not key:
        return False
    if not ENV_KEY_REGEX.match(key):
        return False
    if key.upper() in _FORBIDDEN_ENV_KEYS_UPPER:
        return False
    return True


def sanitize_env_value(val: str) -> str:
    """Strip NUL, CR, and LF bytes to prevent '--env-file' line-break variable injection."""
    if val is None:
        return ""
    text = str(val)
    return text.replace("\x00", "").replace("\r", "").replace("\n", "")


class SecretVaultManager:
    """Manages per-sandbox secrets via libsecret keyring or 0600 local vault files."""

    def __init__(
        self,
        secrets_dir: Optional[Path] = None,
        runtime_dir: Optional[Path] = None,
    ):
        if secrets_dir is not None:
            self.secrets_dir = Path(secrets_dir)
        elif DATA_DIR != _INITIAL_DATA_DIR:
            self.secrets_dir = Path(DATA_DIR) / "secrets"
        else:
            self.secrets_dir = core_config.DATA_DIR / "secrets"
        self.runtime_dir = Path(runtime_dir) if runtime_dir is not None else None
        self._ensure_private_dir(self.secrets_dir)

    @staticmethod
    def _ensure_private_dir(directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except Exception:
            pass

    @staticmethod
    def _safe_sandbox_name(sandbox_name: str) -> str:
        safe = sanitize_ssh_identifier(sandbox_name or "")
        if not safe or safe.startswith("-"):
            raise ValueError(f"Invalid sandbox name for secret vault: {sandbox_name!r}")
        return safe

    def _vault_path(self, safe_sandbox: str) -> Path:
        self._ensure_private_dir(self.secrets_dir)
        base_resolved = self.secrets_dir.resolve()
        vault_path = (self.secrets_dir / f"{safe_sandbox}.vault.json").resolve()
        if vault_path.parent != base_resolved:
            raise ValueError(f"Path traversal detected in vault path: {safe_sandbox!r}")
        return vault_path

    def _read_vault(self, safe_sandbox: str) -> Dict[str, str]:
        vault_path = self._vault_path(safe_sandbox)
        if not vault_path.exists():
            return {}
        try:
            raw = vault_path.read_text(encoding="utf-8")
            if not raw.strip():
                return {}
            data = json.loads(raw)
            if not isinstance(data, dict):
                return {}
            cleaned: Dict[str, str] = {}
            for k, v in data.items():
                if isinstance(k, str) and is_valid_env_key(k) and v is not None:
                    cleaned[k] = sanitize_env_value(str(v))
            return cleaned
        except Exception:
            return {}

    def _write_vault(self, safe_sandbox: str, data: Dict[str, str]) -> Path:
        vault_path = self._vault_path(safe_sandbox)
        serialized = json.dumps(data, indent=2, sort_keys=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(vault_path), flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, serialized.encode("utf-8"))
        finally:
            os.close(fd)
        return vault_path

    def _delete_vault_key(self, safe_sandbox: str, key: str) -> bool:
        vault_path = self._vault_path(safe_sandbox)
        if not vault_path.exists():
            return False
        data = self._read_vault(safe_sandbox)
        if key not in data:
            return False
        del data[key]
        if data:
            self._write_vault(safe_sandbox, data)
        else:
            self.cleanup_runtime_env_file(vault_path)
        return True

    def has_keyring(self) -> bool:
        """Return True when 'secret-tool' is installed and a D-Bus session bus is active."""
        if not shutil.which("secret-tool"):
            return False
        dbus_addr = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "").strip()
        return bool(dbus_addr)

    def set_secret(
        self,
        sandbox_name: str,
        key: str,
        value: str,
        prefer_keyring: bool = True,
    ) -> str:
        """Store a scoped secret in GNOME Keyring (if available) or the 0600 local vault."""
        if not is_valid_env_key(key):
            raise ValueError(f"Invalid or forbidden secret key: {key!r}")
        safe_sandbox = self._safe_sandbox_name(sandbox_name)
        clean_value = sanitize_env_value(value)

        if prefer_keyring and self.has_keyring():
            try:
                res = subprocess.run(
                    [
                        "secret-tool",
                        "store",
                        f"--label=krunbox:{safe_sandbox}:{key}",
                        "application",
                        "krunbox",
                        "sandbox",
                        safe_sandbox,
                        "key",
                        key,
                    ],
                    input=clean_value,
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode == 0:
                    self._delete_vault_key(safe_sandbox, key)
                    return "keyring"
            except Exception:
                pass

        data = self._read_vault(safe_sandbox)
        data[key] = clean_value
        self._write_vault(safe_sandbox, data)
        return "vault"

    def get_secret(self, sandbox_name: str, key: str) -> Optional[str]:
        """Retrieve a scoped secret from GNOME Keyring first, falling back to local vault."""
        if not is_valid_env_key(key):
            return None
        safe_sandbox = self._safe_sandbox_name(sandbox_name)

        if self.has_keyring():
            try:
                res = subprocess.run(
                    [
                        "secret-tool",
                        "lookup",
                        "application",
                        "krunbox",
                        "sandbox",
                        safe_sandbox,
                        "key",
                        key,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode == 0 and res.stdout != "":
                    return sanitize_env_value(res.stdout.rstrip("\r\n"))
            except Exception:
                pass

        data = self._read_vault(safe_sandbox)
        if key in data:
            return sanitize_env_value(data[key])
        return None

    def lookup_system_keyring(self, attributes: Dict[str, str]) -> Optional[str]:
        """Look up an existing secret from the user's GNOME Keyring via attribute pairs."""
        if not isinstance(attributes, dict) or not attributes:
            raise ValueError("Keyring lookup requires at least one attribute pair")

        cmd = ["secret-tool", "lookup"]
        for raw_k, raw_v in attributes.items():
            if not isinstance(raw_k, str) or not isinstance(raw_v, str):
                raise ValueError("Keyring attribute keys and values must be strings")
            k = raw_k.strip()
            v = raw_v.strip()
            if not k or not v:
                raise ValueError("Keyring attribute keys and values cannot be empty")
            if k.startswith("-") or v.startswith("-"):
                raise ValueError(
                    f"Option flag injection rejected in keyring lookup attributes: {raw_k!r}={raw_v!r}"
                )
            if "\x00" in k or "\x00" in v or "\n" in k or "\r" in k or "\n" in v or "\r" in v:
                raise ValueError("Control characters rejected in keyring lookup attributes")
            if not _KEYRING_ATTR_KEY_REGEX.match(k):
                raise ValueError(f"Invalid keyring attribute name: {raw_k!r}")
            cmd.extend([k, v])

        if not self.has_keyring():
            return None

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if res.returncode == 0 and res.stdout != "":
                return sanitize_env_value(res.stdout.rstrip("\r\n"))
        except Exception:
            pass
        return None

    def delete_secret(self, sandbox_name: str, key: str) -> bool:
        """Remove a secret from both GNOME Keyring (if active) and the local vault."""
        if not is_valid_env_key(key):
            return False
        safe_sandbox = self._safe_sandbox_name(sandbox_name)
        deleted = False

        if self.has_keyring():
            try:
                res = subprocess.run(
                    [
                        "secret-tool",
                        "clear",
                        "application",
                        "krunbox",
                        "sandbox",
                        safe_sandbox,
                        "key",
                        key,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if res.returncode == 0:
                    deleted = True
            except Exception:
                pass

        if self._delete_vault_key(safe_sandbox, key):
            deleted = True

        return deleted

    def list_secret_keys(
        self,
        sandbox_name: str,
        known_keys: Optional[List[str]] = None,
    ) -> List[str]:
        """Return sorted unique valid secret keys from local vault merged with known_keys."""
        safe_sandbox = self._safe_sandbox_name(sandbox_name)
        keys = set(self._read_vault(safe_sandbox).keys())
        if known_keys:
            for key in known_keys:
                if is_valid_env_key(key):
                    keys.add(key)
        return sorted(keys)

    def _select_runtime_dir(self) -> Path:
        candidates: List[Path] = []
        if self.runtime_dir is not None:
            candidates.append(self.runtime_dir)
        else:
            uid = os.getuid()
            shm_root = Path("/dev/shm")
            if shm_root.is_dir() and os.access(str(shm_root), os.W_OK | os.X_OK):
                candidates.append(shm_root / f"krunbox-secrets-{uid}")
            xdg_rt = os.environ.get("XDG_RUNTIME_DIR", "").strip()
            if xdg_rt:
                candidates.append(Path(xdg_rt) / "krunbox-secrets")
            candidates.append(self.secrets_dir / "runtime")

        uid = os.getuid()
        for candidate in candidates:
            try:
                if candidate.is_symlink():
                    continue
                candidate.mkdir(parents=True, exist_ok=True)
                if candidate.is_symlink():
                    continue
                st = candidate.stat()
                if st.st_uid != uid:
                    continue
                os.chmod(candidate, 0o700)
                return candidate
            except Exception:
                continue

        fallback = self.secrets_dir / "runtime"
        self._ensure_private_dir(fallback)
        return fallback

    def prepare_runtime_env_file(
        self,
        sandbox_name: str,
        plain_env: Optional[Dict[str, str]] = None,
        secret_keys: Optional[List[str]] = None,
        host_env_passthrough: Optional[List[str]] = None,
    ) -> Optional[Path]:
        """
        Stage sanitized environment variables and resolved secrets into a temporary
        0600 tmpfs file suitable for 'podman run --env-file <path>'.
        """
        safe_sandbox = self._safe_sandbox_name(sandbox_name)
        resolved: Dict[str, str] = {}

        if plain_env:
            for key, val in plain_env.items():
                if is_valid_env_key(key) and val is not None:
                    resolved[key] = sanitize_env_value(val)

        if host_env_passthrough:
            for key in host_env_passthrough:
                if is_valid_env_key(key):
                    host_val = os.environ.get(key)
                    if host_val is not None:
                        resolved[key] = sanitize_env_value(host_val)

        if secret_keys:
            for key in secret_keys:
                if is_valid_env_key(key):
                    sec_val = self.get_secret(sandbox_name, key)
                    if sec_val is not None:
                        resolved[key] = sanitize_env_value(sec_val)

        if not resolved:
            return None

        rt_dir = self._select_runtime_dir()
        fd, tmp_path_str = tempfile.mkstemp(
            prefix=f"{safe_sandbox}-",
            suffix=".env",
            dir=str(rt_dir),
        )
        try:
            os.fchmod(fd, 0o600)
            payload = "".join(f"{k}={v}\n" for k, v in sorted(resolved.items()))
            os.write(fd, payload.encode("utf-8"))
            try:
                os.fsync(fd)
            except Exception:
                pass
        except Exception:
            os.close(fd)
            try:
                os.unlink(tmp_path_str)
            except Exception:
                pass
            raise
        else:
            os.close(fd)

        return Path(tmp_path_str)

    @staticmethod
    def cleanup_runtime_env_file(env_file: Optional[Path]) -> None:
        """Zero-wipe file contents and unlink a staged runtime '--env-file'."""
        if env_file is None:
            return
        path = Path(env_file)
        try:
            if path.is_symlink():
                path.unlink(missing_ok=True)
                return
            if not path.exists():
                return
            if path.is_file():
                flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(str(path), flags)
                try:
                    size = os.fstat(fd).st_size
                    if size > 0:
                        os.lseek(fd, 0, os.SEEK_SET)
                        chunk = b"\x00" * min(size, 65536)
                        remaining = size
                        while remaining > 0:
                            step = min(remaining, len(chunk))
                            written = os.write(fd, chunk[:step])
                            if written <= 0:
                                break
                            remaining -= written
                        try:
                            os.fsync(fd)
                        except Exception:
                            pass
                finally:
                    os.close(fd)
        except Exception:
            pass
        finally:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass

    def rename_sandbox_secrets(
        self,
        old_name: str,
        new_name: str,
        secret_keys: Optional[List[str]] = None,
    ) -> None:
        """Migrate all keyring and local vault secrets from old_name to new_name."""
        old_safe = self._safe_sandbox_name(old_name)
        new_safe = self._safe_sandbox_name(new_name)
        if old_safe == new_safe:
            return

        keys = self.list_secret_keys(old_name, known_keys=secret_keys)
        old_vault = self._read_vault(old_safe)

        for key in keys:
            val = self.get_secret(old_name, key)
            if val is None and key in old_vault:
                val = old_vault[key]
            if val is not None:
                prefer_kr = self.has_keyring() and (key not in old_vault or secret_keys is not None)
                self.set_secret(new_name, key, val, prefer_keyring=prefer_kr)
            self.delete_secret(old_name, key)

        old_vault_path = self._vault_path(old_safe)
        if old_vault_path.exists():
            self.cleanup_runtime_env_file(old_vault_path)

    def delete_sandbox_secrets(
        self,
        sandbox_name: str,
        secret_keys: Optional[List[str]] = None,
    ) -> None:
        """Delete all secrets associated with a sandbox from keyring and local vault."""
        safe_sandbox = self._safe_sandbox_name(sandbox_name)
        keys = self.list_secret_keys(sandbox_name, known_keys=secret_keys)
        for key in keys:
            self.delete_secret(sandbox_name, key)

        vault_path = self._vault_path(safe_sandbox)
        if vault_path.exists():
            self.cleanup_runtime_env_file(vault_path)
