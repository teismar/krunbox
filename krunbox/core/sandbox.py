"""
Data structures and domain models for krunbox.
"""

from dataclasses import dataclass, field, asdict, fields
from typing import Dict, List, Optional
import time

@dataclass
class PortMapping:
    host_port: int
    guest_port: int
    protocol: str = "tcp"
    is_tunnel: bool = False
    tunnel_pid: Optional[int] = None
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "PortMapping":
        return cls(**data)


@dataclass
class NetworkPolicy:
    profile: str = "full"  # "full", "ai-only", "dev-common", "offline", "custom"
    allowed_domains: List[str] = field(default_factory=list)
    denied_domains: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "NetworkPolicy":
        return cls(
            profile=data.get("profile", "full"),
            allowed_domains=list(data.get("allowed_domains", [])),
            denied_domains=list(data.get("denied_domains", []))
        )


@dataclass
class ApiCallRecord:
    timestamp: float
    provider: str  # "OpenAI", "Anthropic", "Google Gemini", "Mistral", "HuggingFace", "Other"
    endpoint: str  # "/v1/chat/completions", etc.
    model: str
    status_code: int = 200
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ApiCallRecord":
        return cls(**data)


@dataclass
class EgressEvent:
    timestamp: float
    sandbox_name: str
    domain: str
    action: str = "allowed"   # "allowed" or "blocked"
    protocol: str = "https"   # "dns", "http", "https", "tcp"
    port: int = 443
    category: str = "Web / External"
    reason: str = ""
    bytes_sent: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "EgressEvent":
        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)


@dataclass
class SandboxInfo:
    name: str  # e.g. "krunbox-my-project"
    dir_path: str  # Host directory mounted to /workspace
    hostname: str  # MicroVM guest hostname
    container_name: str  # Podman container name
    ssh_port: int  # Mapped SSH port
    base_image: str = "localhost/agent-box:latest"
    is_persistent: bool = False  # False = Ephemeral (default), True = Persistent
    network_policy: NetworkPolicy = field(default_factory=NetworkPolicy)
    published_ports: List[PortMapping] = field(default_factory=list)
    dynamic_tunnels: List[PortMapping] = field(default_factory=list)
    ram_mib: int = 4096
    cpus: int = 4
    persist_docker: bool = False
    volume_prefix: Optional[str] = None
    committed_image: Optional[str] = None
    protect_git_hooks: bool = True
    protect_git_config: bool = False
    protect_env_files: bool = False
    host_egress_lockdown: bool = False
    idle_timeout_minutes: int = 0
    idle_action: str = "stop"  # "pause" or "stop"
    env_vars: Dict[str, str] = field(default_factory=dict)
    secret_keys: List[str] = field(default_factory=list)
    host_env_passthrough: List[str] = field(default_factory=list)
    max_tokens_budget: int = 0
    max_cost_usd_budget: float = 0.0
    budget_exceeded_action: str = "alert"  # "alert", "pause", "stop"
    template_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    container_id: Optional[str] = None
    status: str = "stopped"  # "running", "stopped", "paused", "exited"
    cpu_percent: float = 0.0
    mem_usage: str = ""
    mem_percent: float = 0.0
    total_api_calls: int = 0

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def all_ports(self) -> List[PortMapping]:
        return self.published_ports + self.dynamic_tunnels

    def to_dict(self) -> dict:
        d = asdict(self)
        d["network_policy"] = self.network_policy.to_dict()
        d["published_ports"] = [p.to_dict() for p in self.published_ports]
        d["dynamic_tunnels"] = [p.to_dict() for p in self.dynamic_tunnels]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "SandboxInfo":
        data_copy = dict(data)
        if "network_policy" in data_copy and isinstance(data_copy["network_policy"], dict):
            data_copy["network_policy"] = NetworkPolicy.from_dict(data_copy["network_policy"])
        elif not isinstance(data_copy.get("network_policy"), NetworkPolicy):
            data_copy["network_policy"] = NetworkPolicy()

        pub = [
            p if isinstance(p, PortMapping) else PortMapping.from_dict(p)
            for p in data_copy.get("published_ports", [])
        ]
        tun = [
            p if isinstance(p, PortMapping) else PortMapping.from_dict(p)
            for p in data_copy.get("dynamic_tunnels", [])
        ]
        data_copy["published_ports"] = pub
        data_copy["dynamic_tunnels"] = tun
        known_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data_copy.items() if k in known_fields}
        return cls(**filtered)
