"""
Outbound domain egress traffic monitoring, categorization, and frequency analytics for krunbox.
"""

import csv
import json
import math
import os
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union

from .config import EGRESS_LOGS_DIR
from .network import is_safe_domain_or_ip
from .sandbox import EgressEvent

MAX_READ_BYTES = 4 * 1024 * 1024  # 4 MiB tail read bound per file
MAX_LINES_PER_FILE = 5000

_CATEGORY_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    (
        "Container Registry",
        (
            "docker.io",
            "docker.com",
            "ghcr.io",
            "quay.io",
            "gcr.io",
            "mcr.microsoft.com",
        ),
    ),
    (
        "OS & System Mirror",
        (
            "ubuntu.com",
            "debian.org",
            "fedoraproject.org",
            "canonical.com",
            "dl.google.com",
            "nodesource.com",
        ),
    ),
    (
        "AI Provider",
        (
            "openai",
            "anthropic",
            "claude",
            "googleapis",
            "gemini",
            "vertex",
            "mistral",
            "vibe",
            "huggingface",
            "hf.co",
            "groq",
            "cohere",
            "deepseek",
            "openrouter",
            "ollama",
            "antigravity",
            "googleusercontent",
        ),
    ),
    (
        "Package Registry",
        (
            "npmjs",
            "yarnpkg",
            "pnpm",
            "pypi",
            "pythonhosted",
            "crates.io",
            "rustup",
            "rubygems",
            "pkg.go.dev",
            "proxy.golang.org",
            "maven",
            "packagist",
        ),
    ),
    (
        "Git & Source Control",
        (
            "github",
            "githubusercontent",
            "gitlab",
            "bitbucket",
            "codeberg",
        ),
    ),
]

_IGNORED_DOMAINS = {
    "localhost",
    "local",
    "localhost.localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "in-addr.arpa",
    "ip6.arpa",
    "127.0.0.1",
    "0.0.0.0",
}


def sanitize_egress_domain(raw: object) -> Optional[str]:
    """Validate and normalize an outbound domain or IPv4 string, filtering internal noise."""
    if not isinstance(raw, str):
        return None
    val = raw.strip().lower().rstrip(".")
    if not val or len(val) > 253:
        return None
    if not val.isascii() or not val.isprintable():
        return None
    if val.startswith("*."):
        val = val[2:]
    if val in _IGNORED_DOMAINS:
        return None
    if val.endswith(".in-addr.arpa") or val.endswith(".ip6.arpa"):
        return None
    if not is_safe_domain_or_ip(val):
        return None
    return val


def _domain_matches_keyword(domain: str, keyword: str) -> bool:
    if "." in keyword:
        return domain == keyword or domain.endswith("." + keyword)
    labels = domain.split(".")
    return any(keyword in lbl for lbl in labels)


def categorize_domain(domain: str) -> str:
    """Classify an outbound domain into a human-friendly corporate security category."""
    clean = sanitize_egress_domain(domain)
    if not clean:
        clean = str(domain or "").strip().lower().rstrip(".")
    if not clean:
        return "Web / External"

    for category, patterns in _CATEGORY_RULES:
        for pat in patterns:
            if _domain_matches_keyword(clean, pat):
                return category
    return "Web / External"


class EgressTrafficManager:
    """Manages host and guest-mounted JSONL egress traffic logs and domain statistics."""

    def __init__(self, logs_dir: Optional[Path] = None):
        self.logs_dir: Path = Path(logs_dir) if logs_dir is not None else EGRESS_LOGS_DIR
        self._ensure_logs_dir()

    def _ensure_logs_dir(self) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.logs_dir.chmod(0o700)
        except Exception:
            pass

    @staticmethod
    def _safe_key(sandbox_name: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "-", str(sandbox_name or "").strip()).strip(".-")
        return cleaned or "unknown"

    def get_sandbox_bundle_dir(self, sandbox_name: str) -> Path:
        """Return the host directory mounted at /run/krunbox-egress for a sandbox."""
        self._ensure_logs_dir()
        bdir = self.logs_dir / self._safe_key(sandbox_name)
        bdir.mkdir(parents=True, exist_ok=True)
        try:
            bdir.chmod(0o700)
        except Exception:
            pass
        return bdir

    def record_event(
        self,
        sandbox_name: str,
        domain: str,
        action: str = "allowed",
        protocol: str = "https",
        port: int = 443,
        reason: str = "",
        bytes_sent: int = 0,
        timestamp: Optional[float] = None,
    ) -> Optional[EgressEvent]:
        """Validate and append an outbound domain event to the sandbox's egress JSONL log."""
        clean_domain = sanitize_egress_domain(domain)
        if not clean_domain:
            return None

        self._ensure_logs_dir()
        safe_box = self._safe_key(sandbox_name)
        norm_action = "blocked" if str(action).strip().lower() == "blocked" else "allowed"
        norm_proto = re.sub(r"[^a-z0-9_-]", "", str(protocol or "https").strip().lower())[:16] or "https"
        try:
            norm_port = max(0, min(65535, int(port)))
        except (ValueError, TypeError):
            norm_port = 443
        try:
            norm_bytes = max(0, int(bytes_sent))
        except (ValueError, TypeError):
            norm_bytes = 0

        ts = float(timestamp) if timestamp is not None else time.time()
        if not math.isfinite(ts):
            ts = time.time()

        event = EgressEvent(
            timestamp=ts,
            sandbox_name=sandbox_name.strip() or safe_box,
            domain=clean_domain,
            action=norm_action,
            protocol=norm_proto,
            port=norm_port,
            category=categorize_domain(clean_domain),
            reason=str(reason or "")[:200],
            bytes_sent=norm_bytes,
        )

        log_path = self.logs_dir / f"{safe_box}.jsonl"
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
            try:
                log_path.chmod(0o600)
            except Exception:
                pass
        except Exception:
            pass
        return event

    def _read_jsonl_file(self, path: Path, fallback_sandbox: str) -> List[EgressEvent]:
        events: List[EgressEvent] = []
        if not path.is_file():
            return events
        try:
            size = path.stat().st_size
            with open(path, "rb") as bf:
                if size > MAX_READ_BYTES:
                    bf.seek(size - MAX_READ_BYTES)
                    raw_bytes = bf.read()
                    nl = raw_bytes.find(b"\n")
                    if nl != -1:
                        raw_bytes = raw_bytes[nl + 1 :]
                else:
                    raw_bytes = bf.read()
            text = raw_bytes.decode("utf-8", errors="replace")
            lines = text.splitlines()[-MAX_LINES_PER_FILE:]
        except Exception:
            return events

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    continue
                clean_domain = sanitize_egress_domain(obj.get("domain"))
                if not clean_domain:
                    continue
                raw_ts = float(obj.get("timestamp", 0.0))
                if not math.isfinite(raw_ts):
                    raw_ts = 0.0
                act = "blocked" if str(obj.get("action", "allowed")).strip().lower() == "blocked" else "allowed"
                proto = re.sub(r"[^a-z0-9_-]", "", str(obj.get("protocol", "https")).strip().lower())[:16] or "https"
                try:
                    prt = max(0, min(65535, int(obj.get("port", 443))))
                except (ValueError, TypeError):
                    prt = 443
                try:
                    bsent = max(0, int(obj.get("bytes_sent", 0)))
                except (ValueError, TypeError):
                    bsent = 0

                box_name = str(obj.get("sandbox_name") or fallback_sandbox).strip() or fallback_sandbox
                cat = categorize_domain(clean_domain)
                events.append(
                    EgressEvent(
                        timestamp=raw_ts,
                        sandbox_name=box_name,
                        domain=clean_domain,
                        action=act,
                        protocol=proto,
                        port=prt,
                        category=cat,
                        reason=str(obj.get("reason", ""))[:200],
                        bytes_sent=bsent,
                    )
                )
            except Exception:
                continue
        return events

    def _resolve_sandbox_keys(self, sandbox_name: Optional[str]) -> List[str]:
        if not self.logs_dir.exists():
            return []
        if sandbox_name is not None:
            key = self._safe_key(sandbox_name)
            has_exact = (
                (self.logs_dir / f"{key}.jsonl").is_file()
                or (self.logs_dir / key / "traffic.jsonl").is_file()
            )
            if has_exact:
                return [key]
            if not key.startswith("krunbox-"):
                prefixed = f"krunbox-{key}"
                has_prefixed = (
                    (self.logs_dir / f"{prefixed}.jsonl").is_file()
                    or (self.logs_dir / prefixed / "traffic.jsonl").is_file()
                )
                if has_prefixed:
                    return [prefixed]
            return [key]

        keys: Set[str] = set()
        try:
            for entry in self.logs_dir.iterdir():
                if entry.is_file() and entry.name.endswith(".jsonl"):
                    keys.add(entry.name[:-6])
                elif entry.is_dir() and (entry / "traffic.jsonl").is_file():
                    keys.add(entry.name)
        except Exception:
            pass
        return sorted(keys)

    def _load_all_events(self, sandbox_name: Optional[str] = None) -> List[EgressEvent]:
        events: List[EgressEvent] = []
        for key in self._resolve_sandbox_keys(sandbox_name):
            flat_file = self.logs_dir / f"{key}.jsonl"
            guest_file = self.logs_dir / key / "traffic.jsonl"
            events.extend(self._read_jsonl_file(flat_file, key))
            events.extend(self._read_jsonl_file(guest_file, key))
        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events

    def get_events(self, sandbox_name: Optional[str] = None, limit: int = 200) -> List[EgressEvent]:
        """Return recent egress events sorted newest-first up to `limit`."""
        events = self._load_all_events(sandbox_name=sandbox_name)
        if limit > 0:
            return events[:limit]
        return events

    def get_domain_stats(self, sandbox_name: Optional[str] = None) -> dict:
        """Aggregate domain call frequency, category breakdown, and allowed/blocked totals."""
        events = self._load_all_events(sandbox_name=sandbox_name)
        total_requests = len(events)
        allowed_requests = 0
        blocked_requests = 0
        by_category: Dict[str, int] = {}
        domain_map: Dict[str, dict] = {}

        for ev in events:
            if ev.action == "blocked":
                blocked_requests += 1
            else:
                allowed_requests += 1

            by_category[ev.category] = by_category.get(ev.category, 0) + 1

            entry = domain_map.get(ev.domain)
            if entry is None:
                entry = {
                    "domain": ev.domain,
                    "category": ev.category,
                    "total_count": 0,
                    "allowed_count": 0,
                    "blocked_count": 0,
                    "last_seen": ev.timestamp,
                    "first_seen": ev.timestamp,
                    "last_action": ev.action,
                    "_ports": set(),
                    "_sandboxes": set(),
                }
                domain_map[ev.domain] = entry

            entry["total_count"] += 1
            if ev.action == "blocked":
                entry["blocked_count"] += 1
            else:
                entry["allowed_count"] += 1

            if ev.timestamp >= entry["last_seen"]:
                entry["last_seen"] = ev.timestamp
                entry["last_action"] = ev.action
            if ev.timestamp < entry["first_seen"]:
                entry["first_seen"] = ev.timestamp

            entry["_ports"].add(ev.port)
            if ev.sandbox_name:
                entry["_sandboxes"].add(ev.sandbox_name)

        sites = []
        for entry in domain_map.values():
            sites.append(
                {
                    "domain": entry["domain"],
                    "category": entry["category"],
                    "total_count": entry["total_count"],
                    "allowed_count": entry["allowed_count"],
                    "blocked_count": entry["blocked_count"],
                    "last_seen": entry["last_seen"],
                    "first_seen": entry["first_seen"],
                    "last_action": entry["last_action"],
                    "ports": sorted(entry["_ports"]),
                    "sandboxes": sorted(entry["_sandboxes"]),
                }
            )

        sites.sort(key=lambda s: (-s["total_count"], -s["last_seen"], s["domain"]))
        sorted_categories = dict(sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0])))

        return {
            "total_requests": total_requests,
            "unique_domains": len(sites),
            "allowed_requests": allowed_requests,
            "blocked_requests": blocked_requests,
            "by_category": sorted_categories,
            "sites": sites,
        }

    def _rewrite_sandbox_name_in_jsonl(self, path: Path, new_name: str) -> None:
        if not path.is_file():
            return
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            rewritten = []
            for line in lines:
                s = line.strip()
                if not s:
                    continue
                try:
                    obj = json.loads(s)
                    if isinstance(obj, dict):
                        obj["sandbox_name"] = new_name
                        rewritten.append(json.dumps(obj))
                    else:
                        rewritten.append(s)
                except Exception:
                    rewritten.append(s)
            path.write_text("\n".join(rewritten) + ("\n" if rewritten else ""), encoding="utf-8")
        except Exception:
            pass

    def rename_logs(self, old_name: str, new_name: str) -> None:
        """Migrate host and guest-mounted egress logs when a sandbox is renamed."""
        old_key = self._safe_key(old_name)
        new_key = self._safe_key(new_name)
        if old_key == new_key or not self.logs_dir.exists():
            return

        old_flat = self.logs_dir / f"{old_key}.jsonl"
        new_flat = self.logs_dir / f"{new_key}.jsonl"
        if old_flat.is_file():
            try:
                if new_flat.is_file():
                    with open(new_flat, "a", encoding="utf-8") as nf:
                        nf.write(old_flat.read_text(encoding="utf-8", errors="replace"))
                    old_flat.unlink(missing_ok=True)
                else:
                    old_flat.rename(new_flat)
                self._rewrite_sandbox_name_in_jsonl(new_flat, new_name)
            except Exception:
                pass

        old_dir = self.logs_dir / old_key
        new_dir = self.logs_dir / new_key
        if old_dir.is_dir():
            try:
                if not new_dir.exists():
                    # os.rename preserves the directory inode for any active bind mount!
                    old_dir.rename(new_dir)
                else:
                    old_guest = old_dir / "traffic.jsonl"
                    new_guest = new_dir / "traffic.jsonl"
                    if old_guest.is_file():
                        with open(new_guest, "a", encoding="utf-8") as ng:
                            ng.write(old_guest.read_text(encoding="utf-8", errors="replace"))
                    shutil.rmtree(old_dir, ignore_errors=True)
                self._rewrite_sandbox_name_in_jsonl(new_dir / "traffic.jsonl", new_name)
            except Exception:
                pass

    def clear_logs(self, sandbox_name: Optional[str] = None) -> None:
        """Truncate or delete recorded egress traffic logs for one sandbox or all sandboxes."""
        if not self.logs_dir.exists():
            return

        if sandbox_name is not None:
            for key in self._resolve_sandbox_keys(sandbox_name):
                flat_file = self.logs_dir / f"{key}.jsonl"
                flat_file.unlink(missing_ok=True)
                guest_file = self.logs_dir / key / "traffic.jsonl"
                if guest_file.is_file():
                    try:
                        guest_file.write_text("", encoding="utf-8")
                    except Exception:
                        guest_file.unlink(missing_ok=True)
            return

        try:
            for entry in self.logs_dir.iterdir():
                if entry.is_file() and entry.name.endswith(".jsonl"):
                    entry.unlink(missing_ok=True)
                elif entry.is_dir():
                    guest_file = entry / "traffic.jsonl"
                    if guest_file.is_file():
                        try:
                            guest_file.write_text("", encoding="utf-8")
                        except Exception:
                            guest_file.unlink(missing_ok=True)
        except Exception:
            pass

    def export_domain_stats(
        self,
        target_path: Union[str, Path],
        sandbox_name: Optional[str] = None,
        fmt: Optional[str] = None,
        sites: Optional[List[dict]] = None,
    ) -> Tuple[bool, str]:
        """Export domain egress statistics and call frequency to CSV or JSON file."""
        try:
            path = Path(target_path).expanduser().resolve()
            if path.is_dir():
                return False, f"Target path '{target_path}' is an existing directory. Please specify a file name."
            path.parent.mkdir(parents=True, exist_ok=True)

            format_type = (fmt or "").strip().lower()
            if not format_type:
                ext = path.suffix.lower()
                if ext == ".json":
                    format_type = "json"
                elif ext == ".csv":
                    format_type = "csv"
                else:
                    format_type = "csv"

            if format_type not in ("csv", "json"):
                return False, f"Unsupported export format '{format_type}'. Use 'csv' or 'json'."

            if sites is None:
                stats = self.get_domain_stats(sandbox_name=sandbox_name)
                sites_data = list(stats.get("sites", []))
            else:
                sites_data = list(sites)

            if format_type == "csv":
                fieldnames = [
                    "domain",
                    "category",
                    "total_count",
                    "allowed_count",
                    "blocked_count",
                    "last_seen",
                    "first_seen",
                    "last_action",
                    "ports",
                    "sandboxes",
                ]
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(fieldnames)
                    for s in sites_data:
                        last_ts = float(s.get("last_seen", 0.0) or 0.0)
                        first_ts = float(s.get("first_seen", 0.0) or 0.0)
                        last_str = datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S") if last_ts > 0 else ""
                        first_str = datetime.fromtimestamp(first_ts).strftime("%Y-%m-%d %H:%M:%S") if first_ts > 0 else ""
                        ports_str = ";".join(str(p) for p in (s.get("ports") or []))
                        sandboxes_str = ";".join(str(sb) for sb in (s.get("sandboxes") or []))
                        writer.writerow([
                            s.get("domain", ""),
                            s.get("category", ""),
                            s.get("total_count", 0),
                            s.get("allowed_count", 0),
                            s.get("blocked_count", 0),
                            last_str,
                            first_str,
                            s.get("last_action", ""),
                            ports_str,
                            sandboxes_str,
                        ])
            else:
                payload = {
                    "exported_at": datetime.now().isoformat(),
                    "sandbox": sandbox_name or "all",
                    "total_sites": len(sites_data),
                    "sites": sites_data,
                }
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, default=str)

            return True, f"Exported {len(sites_data)} domain records to {target_path}"
        except Exception as e:
            return False, str(e)
