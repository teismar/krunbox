"""
Global pytest fixtures ensuring hermetic isolation of krunbox config, data,
egress logs, telemetry, and SSH host fragments during test runs.
"""

import sys
from pathlib import Path
import pytest

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import krunbox.core.config as core_config
import krunbox.core.settings as core_settings
import krunbox.core.manager as core_manager
import krunbox.core.egress_traffic as core_egress
import krunbox.core.telemetry as core_telemetry
import krunbox.core.ssh as core_ssh
import krunbox.core.templates as core_templates
import krunbox.core.secrets as core_secrets
import krunbox.core.workspace_diff as core_workspace_diff


@pytest.fixture(autouse=True)
def _isolate_krunbox_host_paths(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "_krunbox_cfg"
    data_dir = tmp_path / "_krunbox_data"
    egress_logs = data_dir / "egress_logs"
    telem_dir = data_dir / "telemetry"
    ssh_dir = tmp_path / "_krunbox_ssh" / "config.d"
    ssh_cfg = tmp_path / "_krunbox_ssh" / "config"

    cfg_dir.mkdir(parents=True, exist_ok=True)
    egress_logs.mkdir(parents=True, exist_ok=True)
    telem_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(core_config, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(core_config, "DATA_DIR", data_dir)
    monkeypatch.setattr(core_config, "STATE_FILE", cfg_dir / "sandboxes.json")
    monkeypatch.setattr(core_config, "TEMPLATES_FILE", cfg_dir / "templates.json", raising=False)
    monkeypatch.setattr(core_config, "EGRESS_LOGS_DIR", egress_logs)
    monkeypatch.setattr(core_config, "SNAPSHOTS_DIR", data_dir / "snapshots", raising=False)
    monkeypatch.setattr(core_config, "SECRETS_DIR", data_dir / "secrets", raising=False)
    monkeypatch.setattr(core_config, "TELEMETRY_DIR", telem_dir)
    monkeypatch.setattr(core_config, "SSH_CONF_DIR", ssh_dir)
    monkeypatch.setattr(core_config, "SSH_CONFIG_FILE", ssh_cfg)

    monkeypatch.setattr(core_settings, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(core_settings, "SETTINGS_FILE", cfg_dir / "settings.json")

    monkeypatch.setattr(core_manager, "DATA_DIR", data_dir)
    monkeypatch.setattr(core_manager, "STATE_FILE", cfg_dir / "sandboxes.json")

    monkeypatch.setattr(core_egress, "EGRESS_LOGS_DIR", egress_logs)

    monkeypatch.setattr(core_telemetry, "TELEMETRY_DIR", telem_dir)

    monkeypatch.setattr(core_ssh, "SSH_CONF_DIR", ssh_dir)
    monkeypatch.setattr(core_ssh, "SSH_CONFIG_FILE", ssh_cfg)

    monkeypatch.setattr(core_templates, "TEMPLATES_FILE", cfg_dir / "templates.json")
    monkeypatch.setattr(core_secrets, "DATA_DIR", data_dir)
    monkeypatch.setattr(core_workspace_diff, "DATA_DIR", data_dir)
    monkeypatch.setattr(core_workspace_diff, "SNAPSHOTS_DIR", data_dir / "snapshots")
