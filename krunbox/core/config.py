"""
System configuration and default profiles for krunbox.
"""

import os
from pathlib import Path
from typing import Dict, List

# Storage and Configuration Paths
HOME_DIR = Path.home()
CONFIG_DIR = HOME_DIR / ".config" / "krunbox"
DATA_DIR = HOME_DIR / ".local" / "share" / "krunbox"
TELEMETRY_DIR = DATA_DIR / "telemetry"
EGRESS_LOGS_DIR = DATA_DIR / "egress_logs"
SNAPSHOTS_DIR = DATA_DIR / "snapshots"
SECRETS_DIR = DATA_DIR / "secrets"
STATE_FILE = CONFIG_DIR / "sandboxes.json"
TEMPLATES_FILE = CONFIG_DIR / "templates.json"
SSH_CONF_DIR = HOME_DIR / ".ssh" / "config.d"
SSH_CONFIG_FILE = HOME_DIR / ".ssh" / "config"

# Subuid-capable runtime directory for rootless Podman / runc
STORAGE_RUNTIME_DIR = HOME_DIR / ".local" / "share" / "containers" / "storage" / "runtime"
if STORAGE_RUNTIME_DIR.exists():
    if not os.environ.get("XDG_RUNTIME_DIR") or os.environ.get("XDG_RUNTIME_DIR", "").startswith("/tmp"):  # nosec B108
        os.environ["XDG_RUNTIME_DIR"] = str(STORAGE_RUNTIME_DIR)

# Hardware Constraints
DEFAULT_RAM_MIB = int(os.environ.get("KRUN_RAM_MIB", "4096"))
DEFAULT_CPUS = int(os.environ.get("KRUN_CPUS", "4"))
DEFAULT_SSH_PORT = 2222

# Standard Base Images
BUILTIN_IMAGES: Dict[str, dict] = {
    "agent-box": {
        "tag": "localhost/agent-box:latest",
        "description": "Standard AI Agent (Debian Bookworm, DinD, Antigravity, Vibe, Chrome CDP)",
        "default": True,
        "runtime": "krun",
        "containerfile": "images/agent-box/Containerfile",
    },
    "debian-minimal": {
        "tag": "localhost/krunbox-base:latest",
        "fallback_tag": "docker.io/library/debian:bookworm-slim",
        "description": "Minimal Debian MicroVM with OpenSSH (Debian Bookworm base)",
        "default": False,
        "runtime": "krun",
        "containerfile": "images/base/Containerfile",
    },
    "python-data": {
        "tag": "localhost/krunbox-python:latest",
        "fallback_tag": "ghcr.io/astral-sh/uv:python3.12-bookworm-slim",
        "description": "Python Data Science & ML (Python 3.12, uv, Jupyter, Data stack)",
        "default": False,
        "runtime": "krun",
        "containerfile": "images/python/Containerfile",
    },
    "node-fullstack": {
        "tag": "localhost/krunbox-node:latest",
        "fallback_tag": "docker.io/library/node:22-bookworm-slim",
        "description": "Fullstack Web Development (Node.js 22 LTS, npm, pnpm)",
        "default": False,
        "runtime": "krun",
        "containerfile": "images/node/Containerfile",
    },
    "reversing": {
        "tag": "localhost/krunbox-reversing:latest",
        "fallback_tag": "docker.io/library/debian:bookworm-slim",
        "description": "Reverse Engineering & Binary Analysis (craft-anything, rea-agents, ghidra-mcp, rizin, gdb)",
        "default": False,
        "runtime": "krun",
        "containerfile": "images/reversing/Containerfile",
    },
}

# Network Egress Profiles
NETWORK_PROFILES: Dict[str, dict] = {
    "full": {
        "name": "Full Access",
        "description": "Unrestricted outbound internet and DNS access",
        "domains": []
    },
    "ai-only": {
        "name": "AI APIs Only",
        "description": "Restricted exclusively to major AI model provider endpoints",
        "domains": [
            # Google Antigravity, Gemini & Google Cloud Code
            "*.googleapis.com",
            "googleapis.com",
            "aicode.googleapis.com",
            "businessaicode.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "autopush-cloudcode-pa.sandbox.googleapis.com",
            "preprod-daily-cloudcode-pa.sandbox.googleapis.com",
            "alkalimakersuiteapplets.pa.googleapis.com",
            "autopush-aicode.sandbox.googleapis.com",
            "play.googleapis.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "oauth2.googleapis.com",
            "accounts.google.com",
            "www.googleapis.com",
            "antigravity.google",
            "antigravity.google.com",
            "aistudio.google.com",
            "ai.google.dev",
            "*.gstatic.com",
            "www.gstatic.com",
            "fonts.gstatic.com",
            "fonts.googleapis.com",
            "*.googleusercontent.com",
            "lh3.googleusercontent.com",
            "*.run.app",
            "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
            # Anthropic Claude
            "api.anthropic.com",
            "auth.anthropic.com",
            "statsig.anthropic.com",
            "claude.ai",
            "*.anthropic.com",
            # OpenAI & ChatGPT
            "api.openai.com",
            "auth.openai.com",
            "chatgpt.com",
            "*.chatgpt.com",
            "platform.openai.com",
            "*.oaistatic.com",
            "*.oaiusercontent.com",
            # Mistral Vibe & Codestral
            "api.mistral.ai",
            "codestral.mistral.ai",
            "auth.mistral.ai",
            "console.mistral.ai",
            # GitHub Copilot
            "api.githubcopilot.com",
            "copilot-proxy.githubusercontent.com",
            "default.exp-tas.com",
            # Leading Model & Inference APIs
            "api.groq.com",
            "api.cohere.ai",
            "api.cohere.com",
            "api.deepseek.com",
            "api.together.xyz",
            "openrouter.ai",
            "api.perplexity.ai",
            "api-inference.huggingface.co",
            "huggingface.co",
        ]
    },
    "dev-common": {
        "name": "Developer Repositories & AI",
        "description": "AI APIs plus GitHub, NPM, PyPI, Docker registries, and OS mirrors",
        "domains": [
            # Google Antigravity, Gemini & Google Cloud Code
            "*.googleapis.com",
            "googleapis.com",
            "aicode.googleapis.com",
            "businessaicode.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "daily-cloudcode-pa.googleapis.com",
            "autopush-cloudcode-pa.sandbox.googleapis.com",
            "preprod-daily-cloudcode-pa.sandbox.googleapis.com",
            "alkalimakersuiteapplets.pa.googleapis.com",
            "autopush-aicode.sandbox.googleapis.com",
            "play.googleapis.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
            "oauth2.googleapis.com",
            "accounts.google.com",
            "www.googleapis.com",
            "antigravity.google",
            "antigravity.google.com",
            "aistudio.google.com",
            "ai.google.dev",
            "*.gstatic.com",
            "www.gstatic.com",
            "fonts.gstatic.com",
            "fonts.googleapis.com",
            "*.googleusercontent.com",
            "lh3.googleusercontent.com",
            "*.run.app",
            "antigravity-cli-auto-updater-974169037036.us-central1.run.app",
            # Anthropic Claude
            "api.anthropic.com",
            "auth.anthropic.com",
            "statsig.anthropic.com",
            "claude.ai",
            "*.anthropic.com",
            # OpenAI & ChatGPT
            "api.openai.com",
            "auth.openai.com",
            "chatgpt.com",
            "*.chatgpt.com",
            "platform.openai.com",
            "*.oaistatic.com",
            "*.oaiusercontent.com",
            # Mistral Vibe & Codestral
            "api.mistral.ai",
            "codestral.mistral.ai",
            "auth.mistral.ai",
            "console.mistral.ai",
            # GitHub Copilot
            "api.githubcopilot.com",
            "copilot-proxy.githubusercontent.com",
            "default.exp-tas.com",
            # Leading Model & Inference APIs
            "api.groq.com",
            "api.cohere.ai",
            "api.cohere.com",
            "api.deepseek.com",
            "api.together.xyz",
            "openrouter.ai",
            "api.perplexity.ai",
            "api-inference.huggingface.co",
            "huggingface.co",
            # Package Registries
            "registry.npmjs.org",
            "registry.yarnpkg.com",
            "pypi.org",
            "files.pythonhosted.org",
            "rubygems.org",
            "crates.io",
            "proxy.golang.org",
            "sum.golang.org",
            # Repositories & Distro
            "github.com",
            "api.github.com",
            "raw.githubusercontent.com",
            "codeload.github.com",
            "objects.githubusercontent.com",
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "deb.debian.org",
            "registry-1.docker.io",
            "auth.docker.io",
            "production.cloudflare.docker.com",
        ]
    },
    "offline": {
        "name": "Offline / Airgapped",
        "description": "Zero outbound internet access; loopback and local host communications only",
        "domains": []
    },
    "custom": {
        "name": "Custom Whitelist",
        "description": "Explicit user-defined domain and IP CIDR whitelist",
        "domains": []
    }
}

# Ensure base directories exist
for _d in (CONFIG_DIR, DATA_DIR, TELEMETRY_DIR, EGRESS_LOGS_DIR, SNAPSHOTS_DIR, SECRETS_DIR, SSH_CONF_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

for _priv_dir in (EGRESS_LOGS_DIR, SNAPSHOTS_DIR, SECRETS_DIR, SSH_CONF_DIR):
    try:
        _priv_dir.chmod(0o700)
    except Exception:
        pass
