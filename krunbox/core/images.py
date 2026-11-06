"""
Base image registry, detection, and lifecycle management for krunbox.
Supports automatic building, stale image detection by age, and spec file change detection.
"""

import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .config import BUILTIN_IMAGES, DATA_DIR

DEFAULT_MAX_IMAGE_AGE_DAYS = int(os.environ.get("KRUNBOX_IMAGE_MAX_AGE_DAYS", "14"))


class ImageManager:
    def __init__(self, data_dir: Optional[Path] = None):
        self.builtin_images = dict(BUILTIN_IMAGES)
        self.data_dir = Path(data_dir) if data_dir else DATA_DIR
        self.meta_file = self.data_dir / "images_metadata.json"
        self.default_max_age_days = DEFAULT_MAX_IMAGE_AGE_DAYS

    # -------------------------------------------------------------------------
    # Target and Path Resolution
    # -------------------------------------------------------------------------

    def get_target_key(self, target_or_tag: str) -> Optional[str]:
        """Normalize target name, alias, or full OCI tag to a canonical BUILTIN_IMAGES key."""
        if not target_or_tag or not isinstance(target_or_tag, str):
            return None
        clean = target_or_tag.strip().lower()

        # Direct key match
        if clean in self.builtin_images:
            return clean

        # Match against tag or fallback tag
        for key, info in self.builtin_images.items():
            tag = info.get("tag", "").lower()
            fallback = info.get("fallback_tag", "").lower()
            if clean == tag or clean == fallback:
                return key
            # Also match without localhost/ prefix
            if tag.startswith("localhost/") and clean == tag.replace("localhost/", ""):
                return key

        # Common aliases
        alias_map = {
            "base": "debian-minimal",
            "debian": "debian-minimal",
            "debian-minimal": "debian-minimal",
            "python": "python-data",
            "python-data": "python-data",
            "python-data-ml": "python-data",
            "node": "node-fullstack",
            "node-fullstack": "node-fullstack",
            "fullstack-web": "node-fullstack",
            "agent": "agent-box",
            "agent-box": "agent-box",
            "standard-agent": "agent-box",
            "reversing": "reversing",
            "reverse": "reversing",
            "reverse-engineering": "reversing",
            "krunbox-reversing": "reversing",
        }
        return alias_map.get(clean)

    def _get_candidate_roots(self) -> List[Path]:
        """Return candidate project roots to find Containerfiles across local and container environments."""
        candidates = []
        try:
            # Source tree root (parent of krunbox/ package)
            repo_root = Path(__file__).resolve().parent.parent.parent
            candidates.append(repo_root)
        except Exception:
            pass

        cwd = Path.cwd()
        if cwd not in candidates:
            candidates.append(cwd)

        workspace = Path("/workspace")
        if workspace not in candidates:
            candidates.append(workspace)

        if self.data_dir not in candidates:
            candidates.append(self.data_dir)

        return candidates

    def find_spec_and_context(self, target: str, explicit_path: Optional[str] = None) -> Tuple[Optional[Path], Optional[Path]]:
        """
        Locate the Containerfile and build context directory for a target or explicit path.
        Returns (containerfile_path, context_dir) or (None, None).
        """
        candidate_roots = self._get_candidate_roots()

        if explicit_path:
            p = Path(explicit_path)
            if p.exists():
                return p.resolve(), p.parent.resolve()
            # If explicit path has /workspace/ prefix or is relative, try candidate roots
            rel_str = str(explicit_path)
            if rel_str.startswith("/workspace/"):
                rel_str = rel_str[len("/workspace/"):]
            for root in candidate_roots:
                candidate = (root / rel_str).resolve()
                if candidate.exists():
                    return candidate, candidate.parent.resolve()

        key = self.get_target_key(target)
        if not key:
            return None, None

        info = self.builtin_images.get(key, {})
        rel_containerfile = info.get("containerfile")
        if not rel_containerfile:
            return None, None

        for root in candidate_roots:
            candidate = (root / rel_containerfile).resolve()
            if candidate.exists():
                context = candidate.parent if key != "agent-box" else root.resolve()
                return candidate, context

        return None, None

    # -------------------------------------------------------------------------
    # Spec Hashing, Timestamps & Inspection
    # -------------------------------------------------------------------------

    def _get_spec_files(self, containerfile_path: Path, context_dir: Optional[Path] = None) -> List[Path]:
        """Collect Containerfile and relevant local context files that define the build."""
        files = [containerfile_path]
        if context_dir and context_dir.exists() and context_dir != containerfile_path.parent.parent:
            # Only include small script/config files in context directory, skip build artifacts
            for item in context_dir.iterdir():
                if item.is_file() and item != containerfile_path and not item.name.startswith("."):
                    if item.suffix in (".sh", ".conf", ".cfg", ".json", ".txt") or item.name in ("entrypoint.sh",):
                        files.append(item)
        return files

    def compute_spec_hash(self, containerfile_path: Path, context_dir: Optional[Path] = None) -> str:
        """Calculate a combined SHA-256 hash of the Containerfile and auxiliary build assets."""
        hasher = hashlib.sha256()
        for f in sorted(self._get_spec_files(containerfile_path, context_dir), key=lambda p: p.name):
            try:
                hasher.update(f.name.encode("utf-8"))
                hasher.update(f.read_bytes())
            except Exception:
                pass
        return hasher.hexdigest()

    def get_spec_mtime(self, containerfile_path: Path, context_dir: Optional[Path] = None) -> float:
        """Get the latest modification timestamp among the spec files."""
        mtimes = [0.0]
        for f in self._get_spec_files(containerfile_path, context_dir):
            try:
                mtimes.append(f.stat().st_mtime)
            except Exception:
                pass
        return max(mtimes)

    def is_image_present(self, tag: str) -> bool:
        """Check if an image tag is available in local container storage."""
        if not tag:
            return False
        try:
            res = subprocess.run(["podman", "image", "exists", tag], capture_output=True, timeout=5)
            if res.returncode == 0:
                return True
        except Exception:
            pass

        # Fallback to listing tags
        local_tags = self._get_local_podman_tags()
        clean = tag.strip()
        return clean in local_tags or any(clean.split(":")[-1] in t for t in local_tags if clean.split(":")[0] in t)

    def get_image_created_at(self, tag: str) -> Optional[datetime.datetime]:
        """Query podman inspect for image creation timestamp parsed as UTC datetime."""
        try:
            cmd = ["podman", "image", "inspect", tag, "--format", "{{json .Created}}"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                ts_str = res.stdout.strip().strip('"').rstrip("Z")
                if "." in ts_str:
                    main_ts, frac = ts_str.split(".", 1)
                    frac = frac[:6].ljust(6, "0")
                    ts_str = f"{main_ts}.{frac}+00:00"
                else:
                    ts_str = f"{ts_str}+00:00"
                return datetime.datetime.fromisoformat(ts_str)
        except Exception:
            pass
        return None

    def get_image_id(self, tag: str) -> Optional[str]:
        """Query podman inspect for the 12-char hex image ID."""
        try:
            cmd = ["podman", "image", "inspect", tag, "--format", "{{.Id}}"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                raw = res.stdout.strip()
                return raw[:12] if not raw.startswith("sha256:") else raw[7:19]
        except Exception:
            pass
        return None

    # -------------------------------------------------------------------------
    # Build Metadata Persistence
    # -------------------------------------------------------------------------

    def _load_all_meta(self) -> dict:
        if self.meta_file.exists():
            try:
                return json.loads(self.meta_file.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def get_build_metadata(self, tag: str) -> Optional[dict]:
        """Retrieve stored spec hash and build timestamp for an image tag."""
        all_meta = self._load_all_meta()
        return all_meta.get(tag)

    def save_build_metadata(self, tag: str, target: str, spec_path: Path, spec_hash: str) -> None:
        """Record build metadata to data directory upon successful build."""
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            all_meta = self._load_all_meta()
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            img_id = self.get_image_id(tag)
            all_meta[tag] = {
                "target": target,
                "spec_path": str(spec_path),
                "spec_hash": spec_hash,
                "built_at": now_iso,
                "image_id": img_id,
            }
            tmp = self.meta_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(all_meta, indent=2), encoding="utf-8")
            tmp.replace(self.meta_file)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Rebuild & Staleness Detection
    # -------------------------------------------------------------------------

    def should_build_or_update(
        self,
        target_or_tag: str,
        max_age_days: Optional[int] = None,
        force: bool = False
    ) -> Tuple[bool, str]:
        """
        Determine if an image needs to be built or updated.
        Conditions evaluated:
        1. Force rebuild requested
        2. Image not found locally in Podman storage
        3. Spec file modified since image build (mtime or content hash)
        4. Image age exceeds max_age_days threshold
        5. Prerequisite parent image needs rebuild or is newer than child
        """
        if force:
            return True, f"Force rebuild requested for '{target_or_tag}'"

        target_key = self.get_target_key(target_or_tag)

        # Non-builtin or untracked image
        if not target_key:
            if not self.is_image_present(target_or_tag):
                return True, f"Image '{target_or_tag}' is not found locally"
            return False, f"Image '{target_or_tag}' is present locally"

        info = self.builtin_images.get(target_key, {})
        tag = info.get("tag", target_or_tag)

        # 1. Check local presence
        if not self.is_image_present(tag):
            return True, f"Image '{tag}' is not found locally"

        # Locate spec file
        cpath, cdir = self.find_spec_and_context(target_key)
        if not cpath or not cpath.exists():
            # Image is present locally and no spec file to compare with
            return False, f"Image '{tag}' is present locally (no local spec file)"

        created_at = self.get_image_created_at(tag)
        max_days = max_age_days if max_age_days is not None else self.default_max_age_days

        # 2. Check age threshold
        if created_at is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
            age_seconds = (now - created_at).total_seconds()
            age_days = age_seconds / 86400.0
            if age_days >= max_days:
                return True, f"Image '{tag}' is {age_days:.1f} days old (exceeds {max_days}-day limit)"

        # 3. Check spec file modification time
        if created_at is not None:
            spec_mtime = self.get_spec_mtime(cpath, cdir)
            if spec_mtime > created_at.timestamp():
                return True, f"Spec file '{cpath.name}' was modified after image build"

        # 4. Check spec content hash against stored build metadata
        current_hash = self.compute_spec_hash(cpath, cdir)
        stored_meta = self.get_build_metadata(tag)
        if stored_meta and stored_meta.get("spec_hash"):
            if stored_meta["spec_hash"] != current_hash:
                return True, f"Spec file '{cpath.name}' content changed since last build"

        # 5. Check prerequisite dependencies (e.g. python-data, node-fullstack, reversing depend on debian-minimal)
        if target_key in ("python-data", "node-fullstack", "reversing"):
            base_key = "debian-minimal"
            base_tag = self.builtin_images[base_key]["tag"]
            base_needs, base_reason = self.should_build_or_update(base_key, max_age_days=max_days)
            if base_needs:
                return True, f"Prerequisite base image needs rebuild: {base_reason}"
            base_created = self.get_image_created_at(base_tag)
            if base_created and created_at and base_created > created_at:
                return True, f"Prerequisite base image was rebuilt after '{tag}'"

        return False, f"Image '{tag}' is up to date"

    # -------------------------------------------------------------------------
    # Listing & Querying
    # -------------------------------------------------------------------------

    def list_images(self) -> List[dict]:
        """List all supported base images, their availability, staleness, and age."""
        images = []
        now = datetime.datetime.now(datetime.timezone.utc)

        for key, info in self.builtin_images.items():
            tag = info["tag"]
            is_present = self.is_image_present(tag)
            needs_rebuild, reason = self.should_build_or_update(key)
            created_at = self.get_image_created_at(tag) if is_present else None
            age_days = (now - created_at).total_seconds() / 86400.0 if created_at else None

            images.append({
                "id": key,
                "tag": tag,
                "description": info["description"],
                "default": info.get("default", False),
                "is_present": is_present,
                "needs_rebuild": needs_rebuild,
                "rebuild_reason": reason,
                "age_days": round(age_days, 1) if age_days is not None else None,
                "created_at": created_at.isoformat() if created_at else None,
            })

        return images

    def _get_local_podman_tags(self) -> List[str]:
        """Query podman for locally available image tags."""
        tags = []
        try:
            cmd = ["podman", "images", "--format", "json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                for img in data:
                    names = img.get("Names") or img.get("names") or []
                    tags.extend(names)
        except Exception:
            pass
        return tags

    def pull_image(self, tag: str) -> Tuple[bool, str]:
        """Pull an image from container registry."""
        try:
            res = subprocess.run(["podman", "pull", tag], capture_output=True, text=True, timeout=180)
            if res.returncode == 0:
                return True, f"Successfully pulled {tag}"
            return False, res.stderr.strip() or res.stdout.strip()
        except Exception as e:
            return False, str(e)

    # -------------------------------------------------------------------------
    # Build Execution
    # -------------------------------------------------------------------------

    def _run_podman_build(
        self,
        tag: str,
        containerfile_path: Path,
        context_dir: Path,
        timeout: int = 900,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Execute podman build with pasta networking."""
        try:
            env = dict(os.environ)
            tmp_storage = Path.home() / ".local" / "share" / "containers" / "storage" / "tmp"
            if tmp_storage.exists():
                env.setdefault("TMPDIR", str(tmp_storage))
            cmd = [
                "podman", "build",
                "--net=pasta",
                "-t", tag,
                "-f", str(containerfile_path),
                str(context_dir)
            ]

            if on_progress is not None:
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        env=env,
                        bufsize=1,
                    )
                    captured_lines: List[str] = []
                    if hasattr(proc, "stdout") and proc.stdout is not None:
                        for raw_line in iter(proc.stdout.readline, ""):
                            line = raw_line.strip()
                            if line:
                                captured_lines.append(line)
                                on_progress(line)
                    proc.wait(timeout=timeout)
                    retcode = getattr(proc, "returncode", 0)
                    if retcode == 0:
                        spec_hash = self.compute_spec_hash(containerfile_path, context_dir)
                        target_key = self.get_target_key(tag) or tag
                        self.save_build_metadata(tag, target_key, containerfile_path, spec_hash)
                        return True, f"Successfully built {tag}"
                    err = "\n".join(captured_lines[-10:]) if captured_lines else "Build failed"
                    return False, err
                except Exception as e:
                    return False, str(e)

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            if res.returncode == 0:
                # Record build metadata on success
                spec_hash = self.compute_spec_hash(containerfile_path, context_dir)
                target_key = self.get_target_key(tag) or tag
                self.save_build_metadata(tag, target_key, containerfile_path, spec_hash)
                return True, f"Successfully built {tag}"
            return False, res.stderr.strip() or res.stdout.strip()
        except Exception as e:
            return False, str(e)

    def build_base_image(
        self,
        containerfile_path: Optional[str] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Build the custom lightweight debian base image (localhost/krunbox-base:latest)."""
        cpath, cdir = self.find_spec_and_context("debian-minimal", explicit_path=containerfile_path)
        if not cpath or not cpath.exists():
            return False, f"Base Containerfile not found at {containerfile_path or 'images/base/Containerfile'}"
        return self._run_podman_build("localhost/krunbox-base:latest", cpath, cdir, on_progress=on_progress)

    def build_python_image(
        self,
        containerfile_path: Optional[str] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Build the Python Data & ML image depending on localhost/krunbox-base:latest."""
        # Ensure base image is present or build it first
        local_tags = self._get_local_podman_tags()
        if not any("krunbox-base" in t for t in local_tags):
            ok_base, msg_base = self.build_base_image(on_progress=on_progress)
            if not ok_base:
                return False, f"Failed to build prerequisite base image: {msg_base}"
        cpath, cdir = self.find_spec_and_context("python-data", explicit_path=containerfile_path)
        if not cpath or not cpath.exists():
            return False, f"Python Containerfile not found at {containerfile_path or 'images/python/Containerfile'}"
        return self._run_podman_build("localhost/krunbox-python:latest", cpath, cdir, on_progress=on_progress)

    def build_node_image(
        self,
        containerfile_path: Optional[str] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Build the Node Fullstack image depending on localhost/krunbox-base:latest."""
        local_tags = self._get_local_podman_tags()
        if not any("krunbox-base" in t for t in local_tags):
            ok_base, msg_base = self.build_base_image(on_progress=on_progress)
            if not ok_base:
                return False, f"Failed to build prerequisite base image: {msg_base}"
        cpath, cdir = self.find_spec_and_context("node-fullstack", explicit_path=containerfile_path)
        if not cpath or not cpath.exists():
            return False, f"Node Containerfile not found at {containerfile_path or 'images/node/Containerfile'}"
        return self._run_podman_build("localhost/krunbox-node:latest", cpath, cdir, on_progress=on_progress)

    def build_reversing_image(
        self,
        containerfile_path: Optional[str] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Build the Reversing & Binary Analysis image depending on localhost/krunbox-base:latest."""
        local_tags = self._get_local_podman_tags()
        if not any("krunbox-base" in t for t in local_tags):
            ok_base, msg_base = self.build_base_image(on_progress=on_progress)
            if not ok_base:
                return False, f"Failed to build prerequisite base image: {msg_base}"
        cpath, cdir = self.find_spec_and_context("reversing", explicit_path=containerfile_path)
        if not cpath or not cpath.exists():
            return False, f"Reversing Containerfile not found at {containerfile_path or 'images/reversing/Containerfile'}"
        return self._run_podman_build("localhost/krunbox-reversing:latest", cpath, cdir, on_progress=on_progress)

    def build_agent_box(
        self,
        containerfile_path: Optional[str] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Build the default localhost/agent-box:latest image."""
        cpath, cdir = self.find_spec_and_context("agent-box", explicit_path=containerfile_path)
        if not cpath or not cpath.exists():
            return False, f"Agent-box Containerfile not found at {containerfile_path or 'Containerfile'}"
        return self._run_podman_build("localhost/agent-box:latest", cpath, cdir, on_progress=on_progress)

    def build_image(
        self,
        target: str = "base",
        containerfile_path: Optional[str] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Tuple[bool, str]:
        """Build a specific image target ('base', 'debian-minimal', 'python', 'python-data', 'node', 'node-fullstack', 'reversing', 'agent-box', or 'all')."""
        clean = (target or "base").lower().strip()
        if clean in ("base", "debian-minimal", "debian"):
            return self.build_base_image(containerfile_path, on_progress=on_progress)
        elif clean in ("python", "python-data", "python-data-ml"):
            return self.build_python_image(containerfile_path, on_progress=on_progress)
        elif clean in ("node", "node-fullstack"):
            return self.build_node_image(containerfile_path, on_progress=on_progress)
        elif clean in ("reversing", "reverse", "reverse-engineering"):
            return self.build_reversing_image(containerfile_path, on_progress=on_progress)
        elif clean in ("agent-box", "agent"):
            return self.build_agent_box(containerfile_path, on_progress=on_progress)
        elif clean in ("all", "*"):
            def _all_cb(tgt: str, line: str):
                if on_progress:
                    on_progress(f"[{tgt}] {line}")
            results = self.build_all_images(on_progress=_all_cb if on_progress else None)
            failures = [f"{t}: {err}" for t, ok, err in results if not ok]
            if failures:
                return False, f"Some images failed to build: {'; '.join(failures)}"
            return True, "Successfully built all images (base, python, node, reversing, agent-box)"
        return False, f"Unknown image target '{target}'"

    def build_all_images(
        self,
        on_progress: Optional[Callable[[str, str], None]] = None,
        on_image_complete: Optional[Callable[[str, bool, str], None]] = None,
    ) -> List[Tuple[str, bool, str]]:
        """Build all images in dependency order: base, python, node, reversing, agent-box."""
        results = []

        def _step_cb(target_key: str):
            if on_progress:
                return lambda line: on_progress(target_key, line)
            return None

        # 1. Prerequisite base image
        ok_base, msg_base = self.build_base_image(on_progress=_step_cb("base"))
        results.append(("base", ok_base, msg_base))
        if on_image_complete:
            on_image_complete("base", ok_base, msg_base)

        if ok_base:
            # 2. Python image
            ok_py, msg_py = self.build_python_image(on_progress=_step_cb("python"))
            results.append(("python", ok_py, msg_py))
            if on_image_complete:
                on_image_complete("python", ok_py, msg_py)

            # 3. Node image
            ok_node, msg_node = self.build_node_image(on_progress=_step_cb("node"))
            results.append(("node", ok_node, msg_node))
            if on_image_complete:
                on_image_complete("node", ok_node, msg_node)

            # 4. Reversing image
            ok_rev, msg_rev = self.build_reversing_image(on_progress=_step_cb("reversing"))
            results.append(("reversing", ok_rev, msg_rev))
            if on_image_complete:
                on_image_complete("reversing", ok_rev, msg_rev)

        # 5. Agent Box
        ok_ab, msg_ab = self.build_agent_box(on_progress=_step_cb("agent-box"))
        results.append(("agent-box", ok_ab, msg_ab))
        if on_image_complete:
            on_image_complete("agent-box", ok_ab, msg_ab)

        return results

    # -------------------------------------------------------------------------
    # Automatic On-Demand Readiness
    # -------------------------------------------------------------------------

    def ensure_image_ready(
        self,
        target_or_tag: str,
        max_age_days: Optional[int] = None,
        force: bool = False,
        on_progress: Optional[Callable[[str], None]] = None
    ) -> Tuple[bool, str]:
        """
        Verify that target_or_tag is available, up-to-date, and matches current spec.
        If missing, outdated, or spec changed, automatically builds or pulls it.
        """
        needs_build, reason = self.should_build_or_update(target_or_tag, max_age_days=max_age_days, force=force)
        target_key = self.get_target_key(target_or_tag)

        if not needs_build:
            resolved_tag = self.builtin_images[target_key]["tag"] if target_key else target_or_tag
            return True, f"Image '{resolved_tag}' is ready"

        if target_key:
            tag = self.builtin_images[target_key]["tag"]
            if on_progress:
                on_progress(f"Building {tag} ({reason})…")

            # Prerequisite base image must be ready first
            if target_key in ("python-data", "node-fullstack", "reversing"):
                ok_base, msg_base = self.ensure_image_ready(
                    "debian-minimal",
                    max_age_days=max_age_days,
                    force=force,
                    on_progress=on_progress
                )
                if not ok_base:
                    return False, f"Prerequisite base image build failed: {msg_base}"

            return self.build_image(target_key)

        # External non-builtin image
        if on_progress:
            on_progress(f"Pulling container image '{target_or_tag}'…")
        return self.pull_image(target_or_tag)

    def ensure_all_required_images(
        self,
        max_age_days: Optional[int] = None,
        force: bool = False,
        on_progress: Optional[Callable[[str], None]] = None
    ) -> List[Tuple[str, bool, str]]:
        """
        Check all builtin required images and build any that are missing, outdated, or whose spec changed.
        Execution order: debian-minimal -> python-data -> node-fullstack -> reversing -> agent-box.
        """
        targets = ["debian-minimal", "python-data", "node-fullstack", "reversing", "agent-box"]
        results = []
        for target in targets:
            ok, msg = self.ensure_image_ready(
                target,
                max_age_days=max_age_days,
                force=force,
                on_progress=on_progress
            )
            results.append((target, ok, msg))
        return results
