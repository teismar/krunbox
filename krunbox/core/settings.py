"""
User settings persistence and theme preferences for krunbox.
"""

import json
from pathlib import Path
from typing import Dict, Any
from .config import CONFIG_DIR

SETTINGS_FILE = CONFIG_DIR / "settings.json"

DEFAULT_SETTINGS: Dict[str, Any] = {
    "schema_version": 2,
    "color_scheme": "system",  # "system", "light", "dark"
    "default_cpus": 4,
    "default_ram_mib": 4096,
    "default_image": "agent-box",
    "default_network": "full",
    "default_persistent": False,
    "auto_refresh_seconds": 3,
    "default_protect_git_hooks": True,
    "default_protect_git_config": False,
    "default_protect_env_files": False,
    "default_host_egress_lockdown": False,
    "default_idle_timeout_minutes": 0,
    "default_idle_action": "stop",
    "enable_desktop_notifications": True,
    "mem_pressure_threshold_percent": 90,
    "blocked_egress_spike_threshold": 5,
    "default_max_tokens_budget": 0,
    "default_max_cost_usd_budget": 0.0,
}


def load_settings() -> Dict[str, Any]:
    """Load settings from ~/.config/krunbox/settings.json or return defaults."""
    if not SETTINGS_FILE.exists():
        return dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return dict(DEFAULT_SETTINGS)
        merged = dict(DEFAULT_SETTINGS)
        merged.update(data)
        # Migrate unedited v1 resource defaults (8 CPU / 8192 MiB -> 4 CPU / 4096 MiB)
        if int(data.get("schema_version", 1)) < 2:
            if data.get("default_cpus") == 8:
                merged["default_cpus"] = 4
            if data.get("default_ram_mib") == 8192:
                merged["default_ram_mib"] = 4096
            merged["schema_version"] = 2
        return merged
    except Exception:
        return dict(DEFAULT_SETTINGS)


def save_settings(settings: Dict[str, Any]) -> None:
    """Save settings to ~/.config/krunbox/settings.json."""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(settings)
    payload.setdefault("schema_version", 2)
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except Exception as e:
        print(f"[krunbox] Warning: Failed to save settings: {e}")
