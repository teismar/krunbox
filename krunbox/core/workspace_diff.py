"""
Workspace Git guardrails and pre-run workspace snapshot, diff, and rollback subsystem.
"""

from dataclasses import dataclass
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from . import config as _config
from .config import DATA_DIR

_IMPORT_DATA_DIR = DATA_DIR
SNAPSHOTS_DIR = DATA_DIR / "snapshots"

GIT_EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

_ENV_TEMPLATE_NAMES = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
    }
)

_ARCHIVE_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
    }
)

MAX_ARCHIVE_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB per file
MAX_ARCHIVE_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB total archive cap


def _resolve_active_data_dir() -> Path:
    """Resolve current DATA_DIR respecting runtime monkeypatching in tests."""
    if DATA_DIR != _IMPORT_DATA_DIR:
        return Path(DATA_DIR)
    return Path(_config.DATA_DIR)


def _resolve_default_snapshots_dir() -> Path:
    if SNAPSHOTS_DIR != _IMPORT_DATA_DIR / "snapshots":
        return Path(SNAPSHOTS_DIR)
    return _resolve_active_data_dir() / "snapshots"


def _ensure_private_dir(path: Path, mode: int = 0o700) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(mode)
    except OSError:
        pass
    return path


def _is_binary_bytes(data: Optional[bytes]) -> bool:
    if not data:
        return False
    return b"\x00" in data[:8192]


def build_git_guardrail_mounts(
    dir_path: str,
    protect_git_hooks: bool = True,
    protect_git_config: bool = False,
    protect_env_files: bool = False,
    guardrails_dir: Optional[Path] = None,
) -> List[str]:
    """
    Build read-only Podman bind-mount flags (`["-v", "<src>:<dst>:ro", ...]`) to append
    after `-v <dir_path>:/workspace` so untrusted agents inside `/workspace` cannot plant
    host-executing `.git/hooks`, tamper with `.git/config`, or overwrite `.env` secrets.
    """
    if not dir_path or not isinstance(dir_path, str):
        return []

    try:
        ws = Path(dir_path).resolve()
    except OSError:
        return []

    if not ws.is_dir():
        return []

    resolved_guardrails_dir = (
        Path(guardrails_dir)
        if guardrails_dir is not None
        else (_resolve_active_data_dir() / "guardrails")
    )

    def _get_empty_hooks_dir() -> Path:
        _ensure_private_dir(resolved_guardrails_dir, 0o700)
        empty_dir = resolved_guardrails_dir / "empty_hooks"
        empty_dir.mkdir(parents=True, exist_ok=True)
        try:
            empty_dir.chmod(0o755)
        except OSError:
            pass
        return empty_dir

    mounts: List[str] = []
    git_entry = ws / ".git"
    has_real_git_dir = not git_entry.is_symlink() and git_entry.is_dir()

    if protect_git_hooks and has_real_git_dir:
        hooks_dir = git_entry / "hooks"
        if hooks_dir.is_symlink():
            empty_hooks = _get_empty_hooks_dir()
            mounts.extend(["-v", f"{empty_hooks}:/workspace/.git/hooks:ro"])
        elif hooks_dir.is_dir():
            mounts.extend(["-v", f"{hooks_dir}:/workspace/.git/hooks:ro"])
        elif not hooks_dir.exists():
            hooks_dir.mkdir(parents=True, exist_ok=True)
            mounts.extend(["-v", f"{hooks_dir}:/workspace/.git/hooks:ro"])
        elif hooks_dir.is_file():
            mounts.extend(["-v", f"{hooks_dir}:/workspace/.git/hooks:ro"])

    if protect_git_config and has_real_git_dir:
        cfg_file = git_entry / "config"
        if not cfg_file.is_symlink() and cfg_file.is_file():
            mounts.extend(["-v", f"{cfg_file}:/workspace/.git/config:ro"])

    if protect_env_files:
        try:
            entries = sorted(ws.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for entry in entries:
            name = entry.name
            if ":" in name or "\n" in name or "\r" in name or "\x00" in name:
                continue
            if entry.is_symlink() or not entry.is_file():
                continue
            if name == ".env" or name.startswith(".env."):
                if name.lower() in _ENV_TEMPLATE_NAMES:
                    continue
                mounts.extend(["-v", f"{entry}:/workspace/{name}:ro"])

    return mounts


@dataclass
class FileChange:
    """Represents a single modified, added, deleted, or renamed workspace file."""

    path: str
    status: str  # "modified", "added", "deleted", "renamed"
    additions: int = 0
    deletions: int = 0
    old_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status": self.status,
            "additions": self.additions,
            "deletions": self.deletions,
            "old_path": self.old_path,
        }


class WorkspaceSnapshotManager:
    """
    Captures lightweight pre-run workspace baselines and computes unified diffs
    and file/workspace rollbacks for both Git repositories and plain directories.
    """

    def __init__(self, snapshots_dir: Optional[Path] = None):
        self._explicit_snapshots_dir: Optional[Path] = (
            Path(snapshots_dir) if snapshots_dir is not None else None
        )

    @property
    def snapshots_dir(self) -> Path:
        if self._explicit_snapshots_dir is not None:
            return self._explicit_snapshots_dir
        return _resolve_default_snapshots_dir()

    @staticmethod
    def _safe_key(sandbox_name: str) -> str:
        raw = str(sandbox_name or "").strip()
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "-", raw)
        cleaned = re.sub(r"\.{2,}", ".", cleaned).strip(".-")
        return cleaned or "unknown"

    def _get_snap_dir(self, sandbox_name: str, create: bool = False) -> Path:
        base = self.snapshots_dir
        if create:
            _ensure_private_dir(base, 0o700)
        key = self._safe_key(sandbox_name)
        snap_dir = base / key
        if create:
            _ensure_private_dir(snap_dir, 0o700)
        return snap_dir

    @staticmethod
    def _validate_rel_path(ws: Path, rel_path: str) -> Path:
        """
        Validate a POSIX workspace-relative path, rejecting empty paths, absolute paths,
        `..` traversal segments, `.git` internal paths, symlinked parent directories,
        and targets resolving outside `ws.resolve()`.
        """
        if not isinstance(rel_path, str) or not rel_path or "\x00" in rel_path:
            raise ValueError("Relative path must be a non-empty string")
        if rel_path.startswith("/") or rel_path.startswith("\\") or "\\" in rel_path:
            raise ValueError(f"Absolute or backslash path not allowed: {rel_path!r}")

        ws_resolved = ws.resolve()
        posix_path = PurePosixPath(rel_path)
        if posix_path.is_absolute():
            raise ValueError(f"Absolute path not allowed: {rel_path!r}")

        parts = posix_path.parts
        if not parts:
            raise ValueError("Empty relative path")

        for part in parts:
            if part in ("", ".", ".."):
                raise ValueError(f"Unsafe path traversal segment in {rel_path!r}")

        if parts[0] == ".git":
            raise ValueError("Direct access to .git metadata is not permitted")

        # Verify no ancestor directory is a symlink or resolves outside ws_resolved
        cur = ws_resolved
        for part in parts[:-1]:
            cur = cur / part
            if cur.is_symlink():
                raise ValueError(f"Symlink ancestor directory not allowed: {rel_path!r}")
            if cur.exists():
                resolved_cur = cur.resolve(strict=False)
                if not resolved_cur.is_relative_to(ws_resolved):
                    raise ValueError(f"Parent directory escapes workspace: {rel_path!r}")

        target = ws_resolved / Path(*parts)
        resolved_parent = target.parent.resolve(strict=False)
        if not resolved_parent.is_relative_to(ws_resolved):
            raise ValueError(f"Target parent resolves outside workspace: {rel_path!r}")

        resolved_target = target.resolve(strict=False)
        if not resolved_target.is_relative_to(ws_resolved):
            raise ValueError(f"Target path resolves outside workspace: {rel_path!r}")

        return target

    # ------------------------------------------------------------------
    # Git helpers (read/plumbing via temporary index; never touches .git/index)
    # ------------------------------------------------------------------

    @staticmethod
    def _git_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = dict(os.environ)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_OPTIONAL_LOCKS"] = "0"
        if extra:
            env.update(extra)
        return env

    def _run_git(
        self,
        ws: Path,
        args: List[str],
        extra_env: Optional[Dict[str, str]] = None,
        text: bool = True,
        timeout: int = 20,
    ) -> subprocess.CompletedProcess:
        cmd = [
            "git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotepath=false",
            "-C",
            str(ws),
            *args,
        ]
        return subprocess.run(
            cmd,
            env=self._git_env(extra_env),
            capture_output=True,
            text=text,
            timeout=timeout,
            check=False,
        )

    def _is_git_workspace(self, ws: Path) -> bool:
        if shutil.which("git") is None:
            return False
        git_entry = ws / ".git"
        if git_entry.is_symlink() or not git_entry.exists():
            return False
        try:
            proc = self._run_git(ws, ["rev-parse", "--is-inside-work-tree"], timeout=10)
            return proc.returncode == 0 and proc.stdout.strip() == "true"
        except Exception:
            return False

    def _get_git_head_sha(self, ws: Path) -> Optional[str]:
        proc = self._run_git(ws, ["rev-parse", "--verify", "HEAD"])
        if proc.returncode == 0:
            sha = proc.stdout.strip()
            if re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                return sha
        return None

    def _git_tree_exists(self, ws: Path, tree_sha: Optional[str]) -> bool:
        if not tree_sha or not re.fullmatch(r"[0-9a-fA-F]{40}", str(tree_sha)):
            return False
        proc = self._run_git(ws, ["cat-file", "-e", f"{tree_sha}^{{tree}}"])
        return proc.returncode == 0

    def _resolve_real_git_index(self, ws: Path) -> Optional[Path]:
        git_dir = ws / ".git"
        if not git_dir.is_symlink() and git_dir.is_dir():
            idx = git_dir / "index"
            return idx if idx.is_file() else None
        proc = self._run_git(ws, ["rev-parse", "--git-path", "index"])
        if proc.returncode == 0 and proc.stdout.strip():
            candidate = Path(proc.stdout.strip())
            if not candidate.is_absolute():
                candidate = ws / candidate
            if candidate.is_file():
                return candidate
        return None

    def _stage_worktree_to_temp_index(self, ws: Path, tmp_dir: Path) -> Path:
        """
        Populate a temporary GIT_INDEX_FILE outside `ws` with all tracked + modified
        + untracked files via `git add -A` without touching the repository's real index.
        """
        tmp_idx = tmp_dir / "git_temp_index"
        real_idx = self._resolve_real_git_index(ws)
        if real_idx is not None:
            try:
                if real_idx.stat().st_size > 0:
                    shutil.copy2(real_idx, tmp_idx)
            except OSError:
                pass

        idx_env = {"GIT_INDEX_FILE": str(tmp_idx)}
        add_proc = self._run_git(ws, ["add", "-A"], extra_env=idx_env, timeout=30)
        if add_proc.returncode != 0:
            # Fallback if real index had unmerged conflict entries
            if tmp_idx.exists():
                tmp_idx.unlink()
            head_sha = self._get_git_head_sha(ws)
            if head_sha:
                self._run_git(ws, ["read-tree", head_sha], extra_env=idx_env)
            retry = self._run_git(ws, ["add", "-A"], extra_env=idx_env, timeout=30)
            if retry.returncode != 0:
                err = (retry.stderr or add_proc.stderr or "git add -A failed").strip()
                raise RuntimeError(err)
        return tmp_idx

    def _determine_git_baseline_ref(self, sandbox_name: str, ws: Path) -> str:
        meta = self.get_snapshot_info(sandbox_name)
        if meta and meta.get("mode") == "git":
            try:
                meta_ws = Path(str(meta.get("dir_path", ""))).resolve()
            except OSError:
                meta_ws = None
            if meta_ws == ws and self._git_tree_exists(ws, meta.get("tree_sha")):
                return str(meta["tree_sha"])

        head_sha = self._get_git_head_sha(ws)
        if head_sha:
            return head_sha

        # Ensure the canonical empty tree object exists or is recognized
        if not self._git_tree_exists(ws, GIT_EMPTY_TREE_SHA):
            subprocess.run(
                ["git", "-C", str(ws), "hash-object", "-t", "tree", "-w", "--stdin"],
                input=b"",
                env=self._git_env(),
                capture_output=True,
                check=False,
            )
        return GIT_EMPTY_TREE_SHA

    def _read_git_baseline_blob(
        self, ws: Path, ref: str, rel_path: str
    ) -> Optional[Tuple[bytes, int]]:
        """
        Return `(raw_bytes, file_mode)` if `rel_path` existed as a regular file blob
        in `ref`, otherwise `None`.
        """
        if ref == GIT_EMPTY_TREE_SHA:
            return None

        ls_proc = self._run_git(ws, ["ls-tree", "-z", ref, "--", rel_path])
        if ls_proc.returncode != 0 or not ls_proc.stdout:
            return None

        entry = ls_proc.stdout.split("\0", 1)[0]
        if "\t" not in entry:
            return None

        meta_part, _entry_path = entry.split("\t", 1)
        fields = meta_part.split()
        if len(fields) < 3:
            return None

        git_mode, obj_type, blob_sha = fields[0], fields[1], fields[2]
        if obj_type != "blob" or git_mode == "120000":
            return None

        file_mode = 0o755 if git_mode.endswith("755") else 0o644
        blob_proc = self._run_git(ws, ["cat-file", "blob", blob_sha], text=False)
        if blob_proc.returncode != 0:
            show_proc = self._run_git(ws, ["show", f"{ref}:{rel_path}"], text=False)
            if show_proc.returncode != 0:
                return None
            return show_proc.stdout, file_mode

        return blob_proc.stdout, file_mode

    # ------------------------------------------------------------------
    # Archive fallback helpers (non-Git directories)
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_archive_candidates(ws: Path) -> List[Tuple[str, Path, os.stat_result]]:
        """
        Deterministically enumerate regular non-symlink workspace files eligible for
        archive snapshots (skipping heavy cache/vendor dirs and files > 10 MiB).
        """
        candidates: List[Tuple[str, Path, os.stat_result]] = []
        for dirpath, dirnames, filenames in os.walk(ws, topdown=True, followlinks=False):
            parent = Path(dirpath)
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in _ARCHIVE_SKIP_DIRS and not (parent / d).is_symlink()
            )
            for fname in sorted(filenames):
                fpath = parent / fname
                try:
                    if fpath.is_symlink():
                        continue
                    st = fpath.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_size > MAX_ARCHIVE_FILE_BYTES:
                    continue
                rel = fpath.relative_to(ws).as_posix()
                candidates.append((rel, fpath, st))
        candidates.sort(key=lambda item: item[0])
        return candidates

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fp:
            while True:
                chunk = fp.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _read_archive_member(tar_path: Path, rel_path: str) -> Optional[bytes]:
        if not tar_path.is_file():
            return None
        try:
            with tarfile.open(tar_path, "r:gz") as tf:
                try:
                    member = tf.getmember(rel_path)
                except KeyError:
                    return None
                if not member.isfile():
                    return None
                extracted = tf.extractfile(member)
                if extracted is None:
                    return None
                return extracted.read()
        except (tarfile.TarError, OSError):
            return None

    @staticmethod
    def _line_diff_counts(old_bytes: Optional[bytes], new_bytes: Optional[bytes]) -> Tuple[int, int]:
        if _is_binary_bytes(old_bytes) or _is_binary_bytes(new_bytes):
            return 0, 0
        old_lines = (
            old_bytes.decode("utf-8", errors="replace").splitlines()
            if old_bytes is not None
            else []
        )
        new_lines = (
            new_bytes.decode("utf-8", errors="replace").splitlines()
            if new_bytes is not None
            else []
        )
        if not old_lines:
            return len(new_lines), 0
        if not new_lines:
            return 0, len(old_lines)

        additions = 0
        deletions = 0
        matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "insert":
                additions += j2 - j1
            elif tag == "delete":
                deletions += i2 - i1
            elif tag == "replace":
                deletions += i2 - i1
                additions += j2 - j1
        return additions, deletions

    def _effective_mode_for_workspace(self, sandbox_name: str, ws: Path) -> str:
        """
        Determine whether to evaluate `ws` using `"git"` or `"archive"` mode.
        """
        meta = self.get_snapshot_info(sandbox_name)
        snap_dir = self._get_snap_dir(sandbox_name, create=False)
        if meta:
            try:
                same_ws = Path(str(meta.get("dir_path", ""))).resolve() == ws
            except OSError:
                same_ws = False
            if same_ws:
                if (
                    meta.get("mode") == "git"
                    and self._is_git_workspace(ws)
                    and self._git_tree_exists(ws, meta.get("tree_sha"))
                ):
                    return "git"
                if (
                    meta.get("mode") == "archive"
                    and (snap_dir / "manifest.json").is_file()
                ):
                    return "archive"

        if self._is_git_workspace(ws):
            return "git"
        return "archive"

    # ------------------------------------------------------------------
    # Public Snapshot Lifecycle API
    # ------------------------------------------------------------------

    def create_snapshot(self, sandbox_name: str, dir_path: str) -> Tuple[bool, str, dict]:
        """
        Capture a baseline snapshot of `dir_path` for `sandbox_name` using Git
        temporary-index plumbing (`git write-tree`) when `dir_path` is a Git worktree,
        or a capped compressed archive + SHA-256 manifest otherwise.
        """
        if not dir_path:
            return False, "Workspace directory path is empty.", {}

        try:
            ws = Path(dir_path).resolve()
        except OSError as exc:
            return False, f"Invalid workspace path: {exc}", {}

        if not ws.is_dir():
            return False, f"Workspace directory does not exist: {dir_path}", {}

        snap_dir = self._get_snap_dir(sandbox_name, create=True)
        now = time.time()

        if self._is_git_workspace(ws):
            try:
                with tempfile.TemporaryDirectory(prefix="krunbox-git-snap-") as tmp_str:
                    tmp_dir = Path(tmp_str)
                    tmp_idx = self._stage_worktree_to_temp_index(ws, tmp_dir)
                    idx_env = {"GIT_INDEX_FILE": str(tmp_idx)}
                    wt_proc = self._run_git(ws, ["write-tree"], extra_env=idx_env)
                    if wt_proc.returncode != 0:
                        err = (wt_proc.stderr or "git write-tree failed").strip()
                        return False, f"Failed to write Git snapshot tree: {err}", {}
                    tree_sha = wt_proc.stdout.strip()

                head_sha = self._get_git_head_sha(ws)
                untracked_proc = self._run_git(
                    ws, ["ls-files", "-z", "--others", "--exclude-standard"]
                )
                untracked_files = (
                    [p for p in untracked_proc.stdout.split("\0") if p]
                    if untracked_proc.returncode == 0
                    else []
                )
                ls_proc = self._run_git(ws, ["ls-tree", "-r", "-z", "--name-only", tree_sha])
                file_count = (
                    len([p for p in ls_proc.stdout.split("\0") if p])
                    if ls_proc.returncode == 0
                    else 0
                )

                # Remove any stale archive artifacts if workspace converted to Git
                for stale_name in ("baseline.tar.gz", "manifest.json"):
                    stale_file = snap_dir / stale_name
                    if stale_file.exists():
                        stale_file.unlink()

                metadata = {
                    "sandbox_name": sandbox_name,
                    "dir_path": str(ws),
                    "timestamp": now,
                    "mode": "git",
                    "tree_sha": tree_sha,
                    "head_sha": head_sha,
                    "untracked_files": untracked_files,
                    "file_count": file_count,
                }
                self._write_json_private(snap_dir / "metadata.json", metadata)
                return (
                    True,
                    f"Captured Git workspace snapshot ({tree_sha[:8]}, {file_count} files).",
                    metadata,
                )
            except Exception as exc:
                return False, f"Failed to capture Git snapshot: {exc}", {}

        # Archive fallback mode (non-Git directory)
        try:
            tar_path = snap_dir / "baseline.tar.gz"
            manifest_path = snap_dir / "manifest.json"
            manifest: Dict[str, dict] = {}
            total_bytes = 0

            candidates = self._iter_archive_candidates(ws)
            with tarfile.open(tar_path, "w:gz") as tf:
                for rel_path, fpath, st in candidates:
                    if total_bytes + st.st_size > MAX_ARCHIVE_TOTAL_BYTES:
                        break
                    try:
                        sha256_hex = self._sha256_file(fpath)
                        tf.add(str(fpath), arcname=rel_path, recursive=False)
                    except OSError:
                        continue
                    total_bytes += st.st_size
                    manifest[rel_path] = {
                        "sha256": sha256_hex,
                        "size": int(st.st_size),
                        "mode": int(stat.S_IMODE(st.st_mode)),
                    }

            try:
                tar_path.chmod(0o600)
            except OSError:
                pass

            self._write_json_private(manifest_path, manifest)
            metadata = {
                "sandbox_name": sandbox_name,
                "dir_path": str(ws),
                "timestamp": now,
                "mode": "archive",
                "tree_sha": None,
                "head_sha": None,
                "file_count": len(manifest),
                "archived_bytes": total_bytes,
            }
            self._write_json_private(snap_dir / "metadata.json", metadata)
            return (
                True,
                f"Captured archive workspace snapshot ({len(manifest)} files).",
                metadata,
            )
        except Exception as exc:
            return False, f"Failed to capture archive snapshot: {exc}", {}

    @staticmethod
    def _write_json_private(path: Path, payload: dict) -> None:
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            tmp_path.chmod(0o600)
        except OSError:
            pass
        os.replace(tmp_path, path)

    def get_snapshot_info(self, sandbox_name: str) -> Optional[dict]:
        """Read `metadata.json` for `sandbox_name` if present."""
        snap_dir = self._get_snap_dir(sandbox_name, create=False)
        meta_file = snap_dir / "metadata.json"
        if not meta_file.is_file():
            return None
        try:
            data = json.loads(meta_file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def ensure_snapshot(self, sandbox_name: str, dir_path: str) -> dict:
        """
        Return existing snapshot metadata if valid for `dir_path`, otherwise create a fresh snapshot.
        """
        try:
            ws = Path(dir_path).resolve()
        except OSError:
            ws = None

        info = self.get_snapshot_info(sandbox_name)
        if info is not None and ws is not None:
            try:
                info_ws = Path(str(info.get("dir_path", ""))).resolve()
            except OSError:
                info_ws = None
            if info_ws == ws:
                mode = info.get("mode")
                snap_dir = self._get_snap_dir(sandbox_name, create=False)
                if mode == "git" and self._is_git_workspace(ws):
                    if self._git_tree_exists(ws, info.get("tree_sha")):
                        return info
                elif mode == "archive":
                    if (snap_dir / "manifest.json").is_file() and (
                        snap_dir / "baseline.tar.gz"
                    ).is_file():
                        return info

        _ok, _msg, meta = self.create_snapshot(sandbox_name, dir_path)
        return meta

    def list_changes(self, sandbox_name: str, dir_path: str) -> List[FileChange]:
        """
        List all modified, added, deleted, and renamed files in `dir_path`
        compared to `sandbox_name`'s baseline snapshot.
        """
        try:
            ws = Path(dir_path).resolve()
        except OSError:
            return []
        if not ws.is_dir():
            return []

        mode = self._effective_mode_for_workspace(sandbox_name, ws)
        if mode == "git":
            return self._list_changes_git(sandbox_name, ws)
        return self._list_changes_archive(sandbox_name, ws)

    def _list_changes_git(self, sandbox_name: str, ws: Path) -> List[FileChange]:
        ref = self._determine_git_baseline_ref(sandbox_name, ws)
        try:
            with tempfile.TemporaryDirectory(prefix="krunbox-git-diff-") as tmp_str:
                tmp_idx = self._stage_worktree_to_temp_index(ws, Path(tmp_str))
                idx_env = {"GIT_INDEX_FILE": str(tmp_idx)}
                ns_proc = self._run_git(
                    ws,
                    ["diff", "--no-ext-diff", "--cached", "--name-status", "-M", "-z", ref],
                    extra_env=idx_env,
                )
                num_proc = self._run_git(
                    ws,
                    ["diff", "--no-ext-diff", "--cached", "--numstat", "-M", "-z", ref],
                    extra_env=idx_env,
                )
        except Exception:
            return []

        if ns_proc.returncode != 0:
            return []

        # Parse --numstat -z:
        # Normal entry: "<add>\t<del>\t<path>\0"
        # Rename/Copy:  "<add>\t<del>\t\0<old_path>\0<new_path>\0"
        stats_by_path: Dict[str, Tuple[int, int]] = {}
        if num_proc.returncode == 0 and num_proc.stdout:
            tokens = num_proc.stdout.split("\0")
            idx = 0
            while idx < len(tokens):
                tok = tokens[idx]
                if not tok:
                    idx += 1
                    continue
                parts = tok.split("\t", 2)
                if len(parts) < 3:
                    idx += 1
                    continue
                add_s, del_s, inline_path = parts
                add_n = int(add_s) if add_s.isdigit() else 0
                del_n = int(del_s) if del_s.isdigit() else 0
                if inline_path == "" and idx + 2 < len(tokens):
                    _old_p = tokens[idx + 1]
                    new_p = tokens[idx + 2]
                    stats_by_path[new_p] = (add_n, del_n)
                    idx += 3
                else:
                    stats_by_path[inline_path] = (add_n, del_n)
                    idx += 1

        # Parse --name-status -z:
        # Normal entry: "<status>\0<path>\0"
        # Rename/Copy:  "<Rxxx|Cxxx>\0<old_path>\0<new_path>\0"
        changes: List[FileChange] = []
        ns_tokens = ns_proc.stdout.split("\0")
        idx = 0
        while idx < len(ns_tokens):
            raw_status = ns_tokens[idx]
            if not raw_status:
                idx += 1
                continue
            code = raw_status[0].upper()
            if code in ("R", "C") and idx + 2 < len(ns_tokens):
                old_p = ns_tokens[idx + 1]
                new_p = ns_tokens[idx + 2]
                idx += 3
                add_n, del_n = stats_by_path.get(new_p, (0, 0))
                status_str = "renamed" if code == "R" else "added"
                changes.append(
                    FileChange(
                        path=new_p,
                        status=status_str,
                        additions=add_n,
                        deletions=del_n,
                        old_path=old_p if code == "R" else None,
                    )
                )
            elif idx + 1 < len(ns_tokens):
                file_p = ns_tokens[idx + 1]
                idx += 2
                add_n, del_n = stats_by_path.get(file_p, (0, 0))
                if code == "A":
                    status_str = "added"
                elif code == "D":
                    status_str = "deleted"
                else:
                    status_str = "modified"
                changes.append(
                    FileChange(
                        path=file_p,
                        status=status_str,
                        additions=add_n,
                        deletions=del_n,
                    )
                )
            else:
                idx += 1

        changes.sort(key=lambda c: c.path)
        return changes

    def _list_changes_archive(self, sandbox_name: str, ws: Path) -> List[FileChange]:
        snap_dir = self._get_snap_dir(sandbox_name, create=False)
        manifest_file = snap_dir / "manifest.json"
        tar_path = snap_dir / "baseline.tar.gz"
        if not manifest_file.is_file():
            return []

        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                return []
        except (OSError, json.JSONDecodeError):
            return []

        current_files: Dict[str, Tuple[Path, os.stat_result]] = {}
        total_bytes = 0
        for rel_path, fpath, st in self._iter_archive_candidates(ws):
            if rel_path not in manifest and total_bytes + st.st_size > MAX_ARCHIVE_TOTAL_BYTES:
                continue
            total_bytes += st.st_size
            current_files[rel_path] = (fpath, st)

        changes: List[FileChange] = []

        # Modified and deleted files
        for rel_path, entry in manifest.items():
            if rel_path not in current_files:
                old_bytes = self._read_archive_member(tar_path, rel_path)
                _add, del_n = self._line_diff_counts(old_bytes, None)
                changes.append(
                    FileChange(
                        path=rel_path,
                        status="deleted",
                        additions=0,
                        deletions=del_n,
                    )
                )
            else:
                fpath, st = current_files[rel_path]
                expected_size = int(entry.get("size", -1))
                expected_sha = str(entry.get("sha256", ""))
                try:
                    changed = st.st_size != expected_size or self._sha256_file(fpath) != expected_sha
                except OSError:
                    continue
                if changed:
                    old_bytes = self._read_archive_member(tar_path, rel_path)
                    try:
                        new_bytes = fpath.read_bytes()
                    except OSError:
                        new_bytes = b""
                    add_n, del_n = self._line_diff_counts(old_bytes, new_bytes)
                    changes.append(
                        FileChange(
                            path=rel_path,
                            status="modified",
                            additions=add_n,
                            deletions=del_n,
                        )
                    )

        # Added files
        for rel_path, (fpath, _st) in current_files.items():
            if rel_path not in manifest:
                try:
                    new_bytes = fpath.read_bytes()
                except OSError:
                    new_bytes = b""
                add_n, _del = self._line_diff_counts(None, new_bytes)
                changes.append(
                    FileChange(
                        path=rel_path,
                        status="added",
                        additions=add_n,
                        deletions=0,
                    )
                )

        changes.sort(key=lambda c: c.path)
        return changes

    def get_file_diff(
        self,
        sandbox_name: str,
        dir_path: str,
        rel_path: str,
        max_bytes: int = 200_000,
    ) -> str:
        """
        Compute a unified diff comparing the baseline snapshot against the current
        working tree file at `rel_path`. Rejects path traversal and symlink escapes.
        """
        ws = Path(dir_path).resolve()
        if not ws.is_dir():
            raise ValueError(f"Workspace directory does not exist: {dir_path}")

        target = self._validate_rel_path(ws, rel_path)
        mode = self._effective_mode_for_workspace(sandbox_name, ws)

        old_bytes: Optional[bytes] = None
        old_rel_label = rel_path

        if mode == "git":
            ref = self._determine_git_baseline_ref(sandbox_name, ws)
            blob_info = self._read_git_baseline_blob(ws, ref, rel_path)
            if blob_info is not None:
                old_bytes = blob_info[0]
            else:
                # Check if rel_path was renamed from an old_path in baseline
                for ch in self._list_changes_git(sandbox_name, ws):
                    if ch.path == rel_path and ch.status == "renamed" and ch.old_path:
                        self._validate_rel_path(ws, ch.old_path)
                        renamed_blob = self._read_git_baseline_blob(ws, ref, ch.old_path)
                        if renamed_blob is not None:
                            old_bytes = renamed_blob[0]
                            old_rel_label = ch.old_path
                        break
        else:
            snap_dir = self._get_snap_dir(sandbox_name, create=False)
            tar_path = snap_dir / "baseline.tar.gz"
            old_bytes = self._read_archive_member(tar_path, rel_path)

        new_bytes: Optional[bytes] = None
        if not target.is_symlink() and target.is_file():
            try:
                new_bytes = target.read_bytes()
            except OSError:
                new_bytes = None

        if _is_binary_bytes(old_bytes) or _is_binary_bytes(new_bytes):
            return f"Binary file changed: {rel_path}\n"

        if old_bytes == new_bytes:
            return ""

        old_text = old_bytes.decode("utf-8", errors="replace") if old_bytes is not None else ""
        new_text = new_bytes.decode("utf-8", errors="replace") if new_bytes is not None else ""

        old_lines = old_text.splitlines() if old_bytes is not None else []
        new_lines = new_text.splitlines() if new_bytes is not None else []

        from_file = f"a/{old_rel_label}" if old_bytes is not None else "/dev/null"
        to_file = f"b/{rel_path}" if new_bytes is not None else "/dev/null"

        diff_lines = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=from_file,
                tofile=to_file,
                lineterm="",
            )
        )
        if not diff_lines and old_text != new_text:
            diff_text = (
                f"--- {from_file}\n"
                f"+++ {to_file}\n"
                "@@ -1 +1 @@\n"
                "\\ Trailing newline changed at end of file\n"
            )
        else:
            diff_text = "\n".join(diff_lines) + ("\n" if diff_lines else "")

        encoded = diff_text.encode("utf-8")
        if max_bytes > 0 and len(encoded) > max_bytes:
            clipped = encoded[:max_bytes].decode("utf-8", errors="ignore")
            last_nl = clipped.rfind("\n")
            if last_nl > 0:
                clipped = clipped[:last_nl]
            diff_text = f"{clipped}\n... [diff truncated at {max_bytes} bytes] ...\n"

        return diff_text

    def _lookup_baseline_file(
        self, sandbox_name: str, ws: Path, mode: str, rel_path: str
    ) -> Optional[Tuple[bytes, int]]:
        if mode == "git":
            ref = self._determine_git_baseline_ref(sandbox_name, ws)
            return self._read_git_baseline_blob(ws, ref, rel_path)

        snap_dir = self._get_snap_dir(sandbox_name, create=False)
        manifest_file = snap_dir / "manifest.json"
        tar_path = snap_dir / "baseline.tar.gz"
        if not manifest_file.is_file():
            return None
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(manifest, dict) or rel_path not in manifest:
            return None

        raw_bytes = self._read_archive_member(tar_path, rel_path)
        if raw_bytes is None:
            return None
        entry = manifest[rel_path]
        file_mode = int(entry.get("mode", 0o644)) & 0o777
        return raw_bytes, (file_mode or 0o644)

    def _apply_single_path_revert(
        self,
        sandbox_name: str,
        ws: Path,
        mode: str,
        rel_path: str,
    ) -> None:
        target = self._validate_rel_path(ws, rel_path)
        baseline = self._lookup_baseline_file(sandbox_name, ws, mode, rel_path)

        if baseline is not None:
            raw_bytes, file_mode = baseline
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)

            fd, tmp_name = tempfile.mkstemp(prefix=".krunbox-rev-", dir=str(target.parent))
            tmp_file = Path(tmp_name)
            try:
                with os.fdopen(fd, "wb") as fp:
                    fp.write(raw_bytes)
                os.chmod(tmp_file, file_mode)
                os.replace(tmp_file, target)
            except Exception:
                if tmp_file.exists():
                    tmp_file.unlink()
                raise
        else:
            if target.is_symlink() or target.is_file():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)

            # Prune empty parent directories up to ws
            parent = target.parent
            while parent != ws and parent.is_relative_to(ws):
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent

    def revert_file(self, sandbox_name: str, dir_path: str, rel_path: str) -> Tuple[bool, str]:
        """
        Revert a single workspace file at `rel_path` back to its baseline state
        (restoring bytes and permissions if it existed, or deleting it if newly added).
        """
        try:
            ws = Path(dir_path).resolve()
        except OSError as exc:
            return False, f"Invalid workspace path: {exc}"

        if not ws.is_dir():
            return False, f"Workspace directory does not exist: {dir_path}"

        try:
            self._validate_rel_path(ws, rel_path)
        except ValueError as exc:
            return False, f"Rejected unsafe path '{rel_path}': {exc}"

        mode = self._effective_mode_for_workspace(sandbox_name, ws)
        renamed_old_path: Optional[str] = None
        if mode == "git":
            for ch in self._list_changes_git(sandbox_name, ws):
                if ch.path == rel_path and ch.status == "renamed" and ch.old_path:
                    try:
                        self._validate_rel_path(ws, ch.old_path)
                        renamed_old_path = ch.old_path
                    except ValueError as exc:
                        return False, f"Rejected unsafe rename source '{ch.old_path}': {exc}"
                    break

        try:
            self._apply_single_path_revert(sandbox_name, ws, mode, rel_path)
            if renamed_old_path and renamed_old_path != rel_path:
                self._apply_single_path_revert(sandbox_name, ws, mode, renamed_old_path)
        except Exception as exc:
            return False, f"Failed to revert '{rel_path}': {exc}"

        return True, f"Reverted '{rel_path}' to baseline snapshot."

    def rollback_all(self, sandbox_name: str, dir_path: str) -> Tuple[bool, str]:
        """
        Revert all modified, added, deleted, and renamed files in `dir_path` back
        to the baseline snapshot.
        """
        try:
            ws = Path(dir_path).resolve()
        except OSError as exc:
            return False, f"Invalid workspace path: {exc}"

        if not ws.is_dir():
            return False, f"Workspace directory does not exist: {dir_path}"

        changes = self.list_changes(sandbox_name, dir_path)
        if not changes:
            return True, "Workspace already matches baseline snapshot."

        mode = self._effective_mode_for_workspace(sandbox_name, ws)
        paths_to_process: List[str] = []
        seen = set()
        for ch in changes:
            if ch.path not in seen:
                seen.add(ch.path)
                paths_to_process.append(ch.path)
            if ch.old_path and ch.old_path not in seen:
                seen.add(ch.old_path)
                paths_to_process.append(ch.old_path)

        # Validate all target paths up front before mutating disk
        for p in paths_to_process:
            try:
                self._validate_rel_path(ws, p)
            except ValueError as exc:
                return False, f"Aborted rollback due to unsafe path '{p}': {exc}"

        try:
            # First unlink paths not in baseline, then restore baseline files (safe for renames)
            to_unlink: List[str] = []
            to_restore: List[str] = []
            for p in paths_to_process:
                if self._lookup_baseline_file(sandbox_name, ws, mode, p) is None:
                    to_unlink.append(p)
                else:
                    to_restore.append(p)

            for p in to_unlink:
                self._apply_single_path_revert(sandbox_name, ws, mode, p)
            for p in to_restore:
                self._apply_single_path_revert(sandbox_name, ws, mode, p)
        except Exception as exc:
            return False, f"Rollback failed: {exc}"

        return True, f"Rolled back {len(changes)} file(s) to baseline snapshot."

    def accept_changes(self, sandbox_name: str, dir_path: str) -> Tuple[bool, str]:
        """Advance the baseline snapshot for `sandbox_name` to the current workspace state."""
        ok, msg, _meta = self.create_snapshot(sandbox_name, dir_path)
        return ok, msg

    def rename_snapshot(self, old_name: str, new_name: str) -> None:
        """Migrate snapshot directory and metadata when a sandbox is renamed."""
        if not old_name or not new_name:
            return
        old_dir = self._get_snap_dir(old_name, create=False)
        if not old_dir.exists():
            return

        new_dir = self._get_snap_dir(new_name, create=True)
        if old_dir.resolve() != new_dir.resolve():
            if new_dir.exists():
                shutil.rmtree(new_dir, ignore_errors=True)
            old_dir.rename(new_dir)

        meta_file = new_dir / "metadata.json"
        if meta_file.is_file():
            try:
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    data["sandbox_name"] = new_name
                    self._write_json_private(meta_file, data)
            except (OSError, json.JSONDecodeError):
                pass

    def delete_snapshot(self, sandbox_name: str) -> None:
        """Remove stored baseline snapshot artifacts for `sandbox_name`."""
        if not sandbox_name:
            return
        snap_dir = self._get_snap_dir(sandbox_name, create=False)
        if snap_dir.exists():
            shutil.rmtree(snap_dir, ignore_errors=True)
