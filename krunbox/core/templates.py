"""
Curated and user-defined sandbox preset templates for krunbox.
"""

from dataclasses import dataclass, field, asdict, fields
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from . import config as core_config
from .config import CONFIG_DIR, BUILTIN_IMAGES, NETWORK_PROFILES

TEMPLATES_FILE = CONFIG_DIR / "templates.json"
_INITIAL_TEMPLATES_FILE = TEMPLATES_FILE


@dataclass
class SandboxTemplate:
    id: str
    name: str
    description: str = ""
    builtin: bool = False
    base_image: str = "agent-box"
    cpus: int = 4
    ram_mib: int = 4096
    is_persistent: bool = False
    network_profile: str = "full"
    allowed_domains: List[str] = field(default_factory=list)
    denied_domains: List[str] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    protect_git_hooks: bool = True
    protect_git_config: bool = False
    protect_env_files: bool = False
    host_egress_lockdown: bool = False
    idle_timeout_minutes: int = 0
    idle_action: str = "stop"

    def resolved_image_tag(self) -> str:
        """Resolve a builtin image key (e.g. 'agent-box') or full OCI tag."""
        img = (self.base_image or "agent-box").strip()
        if img in BUILTIN_IMAGES:
            return str(BUILTIN_IMAGES[img]["tag"])
        return img

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SandboxTemplate":
        if not isinstance(data, dict):
            raise ValueError("Template payload must be a dictionary")
        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        for list_field in ("allowed_domains", "denied_domains", "ports"):
            if list_field in filtered:
                val = filtered[list_field]
                filtered[list_field] = [str(item) for item in val] if isinstance(val, list) else []
        if "network_profile" in filtered and filtered["network_profile"] not in NETWORK_PROFILES:
            filtered["network_profile"] = "custom"
        return cls(**filtered)


BUILTIN_TEMPLATES: List[SandboxTemplate] = [
    SandboxTemplate(
        id="standard-agent",
        name="Standard AI Agent",
        description="Balanced microVM for autonomous coding agents with full internet access and git hook protection.",
        builtin=True,
        base_image="agent-box",
        cpus=4,
        ram_mib=4096,
        is_persistent=False,
        network_profile="full",
        ports=["3000"],
        protect_git_hooks=True,
    ),
    SandboxTemplate(
        id="locked-down-reviewer",
        name="Locked-Down Reviewer",
        description="Offline zero-egress environment for untrusted code review and static auditing.",
        builtin=True,
        base_image="agent-box",
        cpus=2,
        ram_mib=2048,
        is_persistent=False,
        network_profile="offline",
        ports=[],
        protect_git_hooks=True,
        protect_git_config=True,
        protect_env_files=True,
        host_egress_lockdown=True,
        idle_timeout_minutes=30,
        idle_action="stop",
    ),
    SandboxTemplate(
        id="ai-only-coder",
        name="AI-Only Coding Agent",
        description="Coding workspace restricted exclusively to major AI model provider endpoints with host egress lockdown.",
        builtin=True,
        base_image="agent-box",
        cpus=4,
        ram_mib=4096,
        is_persistent=False,
        network_profile="ai-only",
        ports=["3000"],
        protect_git_hooks=True,
        host_egress_lockdown=True,
        idle_timeout_minutes=30,
        idle_action="stop",
    ),
    SandboxTemplate(
        id="fullstack-web",
        name="Full-Stack Web Agent",
        description="Web application preset exposing common dev server ports with package registry and AI API access.",
        builtin=True,
        base_image="agent-box",
        cpus=4,
        ram_mib=4096,
        is_persistent=False,
        network_profile="dev-common",
        ports=["3000", "5173", "8000"],
        protect_git_hooks=True,
    ),
    SandboxTemplate(
        id="python-data-ml",
        name="Python Data & ML",
        description="Persistent high-memory Python 3.12 data science and ML workspace with Jupyter port 8888.",
        builtin=True,
        base_image="python-data",
        cpus=4,
        ram_mib=8192,
        is_persistent=True,
        network_profile="dev-common",
        ports=["8888"],
        protect_git_hooks=True,
    ),
    SandboxTemplate(
        id="reversing",
        name="Reverse Engineering & Binary Analysis",
        description="Dedicated binary analysis, decompilation, and application reversing environment equipped with storytold/craft-anything, morluto/rea, NSA Ghidra, Ghidra MCP, Rizin, and GDB.",
        builtin=True,
        base_image="reversing",
        cpus=4,
        ram_mib=8192,
        is_persistent=True,
        network_profile="full",
        ports=["3000", "8000", "8089"],
        protect_git_hooks=True,
    ),
]

BUILTIN_TEMPLATE_IDS = frozenset(t.id for t in BUILTIN_TEMPLATES)


class TemplateManager:
    """Manages built-in and custom user-saved sandbox templates."""

    def __init__(self, templates_file: Optional[Path] = None):
        if templates_file is not None:
            self.templates_file = Path(templates_file)
        elif TEMPLATES_FILE != _INITIAL_TEMPLATES_FILE:
            self.templates_file = Path(TEMPLATES_FILE)
        else:
            self.templates_file = core_config.CONFIG_DIR / "templates.json"

    @staticmethod
    def slugify_id(name: str) -> str:
        """Convert a human-readable template name into a safe lowercase slug ID."""
        cleaned = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip().lower()).strip("-")
        if not cleaned:
            return "custom-template"
        return cleaned[:64].rstrip("-") or "custom-template"

    def _load_custom_templates_map(self) -> Dict[str, SandboxTemplate]:
        if not self.templates_file.exists():
            return {}
        try:
            raw_text = self.templates_file.read_text(encoding="utf-8")
            if not raw_text.strip():
                return {}
            data = json.loads(raw_text)
        except Exception:
            return {}

        items: List[dict] = []
        if isinstance(data, dict):
            if "templates" in data and isinstance(data["templates"], list):
                items = [entry for entry in data["templates"] if isinstance(entry, dict)]
            else:
                for key, val in data.items():
                    if isinstance(val, dict):
                        entry = dict(val)
                        entry.setdefault("id", str(key))
                        items.append(entry)
        elif isinstance(data, list):
            items = [entry for entry in data if isinstance(entry, dict)]

        custom_map: Dict[str, SandboxTemplate] = {}
        for entry in items:
            try:
                tmpl = SandboxTemplate.from_dict(entry)
                tmpl.builtin = False
                tmpl.id = self.slugify_id(tmpl.id or tmpl.name)
                if tmpl.id in BUILTIN_TEMPLATE_IDS:
                    continue
                custom_map[tmpl.id] = tmpl
            except Exception:
                continue
        return custom_map

    def _write_custom_templates_map(self, custom_map: Dict[str, SandboxTemplate]) -> None:
        self.templates_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            tid: tmpl.to_dict()
            for tid, tmpl in sorted(custom_map.items(), key=lambda kv: kv[1].name.lower())
        }
        serialized = json.dumps(payload, indent=2)
        fd = os.open(
            str(self.templates_file),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            try:
                os.fchmod(fd, 0o600)
            except Exception:
                pass
            os.write(fd, serialized.encode("utf-8"))
        finally:
            os.close(fd)

    def list_templates(self) -> List[SandboxTemplate]:
        """Return built-in presets followed by custom user templates sorted by name."""
        builtins = [SandboxTemplate.from_dict(t.to_dict()) for t in BUILTIN_TEMPLATES]
        custom_map = self._load_custom_templates_map()
        customs = sorted(custom_map.values(), key=lambda t: (t.name.lower(), t.id))
        return builtins + customs

    def get_template(self, id_or_name: str) -> Optional[SandboxTemplate]:
        """Look up a template by exact ID or case-insensitive ID/name."""
        needle = (id_or_name or "").strip()
        if not needle:
            return None
        needle_lower = needle.lower()
        all_templates = self.list_templates()
        for tmpl in all_templates:
            if tmpl.id == needle:
                return tmpl
        alias_map = {
            "reverse-engineering": "reversing",
            "reverse": "reversing",
            "binary-analysis": "reversing",
        }
        target_id = alias_map.get(needle_lower)
        if target_id:
            for tmpl in all_templates:
                if tmpl.id == target_id:
                    return tmpl
        for tmpl in all_templates:
            if tmpl.id.lower() == needle_lower or tmpl.name.lower() == needle_lower:
                return tmpl
        return None

    def save_custom_template(self, template: SandboxTemplate) -> SandboxTemplate:
        """Persist a custom template, suffixing '-custom' if its ID collides with a built-in."""
        saved = SandboxTemplate.from_dict(template.to_dict())
        saved.builtin = False
        raw_id = saved.id.strip() if saved.id else saved.name
        candidate_id = self.slugify_id(raw_id)
        while candidate_id in BUILTIN_TEMPLATE_IDS:
            candidate_id = f"{candidate_id}-custom"
        saved.id = candidate_id
        if not saved.name.strip():
            saved.name = candidate_id

        custom_map = self._load_custom_templates_map()
        custom_map[saved.id] = saved
        self._write_custom_templates_map(custom_map)
        return saved

    def delete_custom_template(self, template_id: str) -> bool:
        """Delete a custom template by ID; returns False for built-ins or unknown IDs."""
        tid = (template_id or "").strip().lower()
        if not tid or tid in BUILTIN_TEMPLATE_IDS:
            return False
        custom_map = self._load_custom_templates_map()
        if tid not in custom_map:
            return False
        del custom_map[tid]
        self._write_custom_templates_map(custom_map)
        return True
