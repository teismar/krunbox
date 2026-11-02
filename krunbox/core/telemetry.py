"""
AI API Telemetry, Model Call Interception, and Audit Analytics for krunbox.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from .config import TELEMETRY_DIR
from .sandbox import ApiCallRecord

# Cost estimates per 1,000 tokens (indicative for corporate cost estimation)
PROVIDER_COST_PER_1K: Dict[str, float] = {
    "openai": 0.005,
    "anthropic": 0.008,
    "google": 0.002,
    "mistral": 0.002,
    "huggingface": 0.001,
    "default": 0.003
}

def identify_provider(host_or_endpoint: str) -> str:
    """Identify AI provider from hostname or endpoint."""
    target = host_or_endpoint.lower()
    if "openai" in target:
        return "OpenAI"
    elif "anthropic" in target or "claude" in target:
        return "Anthropic"
    elif "googleapis.com" in target or "gemini" in target or "vertex" in target:
        return "Google Gemini"
    elif "mistral" in target or "vibe" in target:
        return "Mistral"
    elif "huggingface" in target:
        return "HuggingFace"
    elif "groq" in target:
        return "Groq"
    elif "cohere" in target:
        return "Cohere"
    elif "ollama" in target or "localhost:11434" in target:
        return "Ollama (Local)"
    return "Other"

class TelemetryManager:
    def __init__(self, telemetry_dir: Path = TELEMETRY_DIR):
        self.telemetry_dir = telemetry_dir
        try:
            self.telemetry_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _get_log_path(self, sandbox_name: str) -> Path:
        return self.telemetry_dir / f"{sandbox_name}.jsonl"

    def record_call(
        self,
        sandbox_name: str,
        provider: str,
        endpoint: str,
        model: str,
        status_code: int = 200,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        latency_ms: float = 0.0
    ) -> ApiCallRecord:
        """Log a structured AI model invocation."""
        record = ApiCallRecord(
            timestamp=time.time(),
            provider=provider,
            endpoint=endpoint,
            model=model,
            status_code=status_code,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_ms=latency_ms
        )
        log_file = self._get_log_path(sandbox_name)
        with open(log_file, "a") as f:
            f.write(json.dumps(record.to_dict()) + "\n")
        return record

    def get_calls(self, sandbox_name: Optional[str] = None, limit: int = 100) -> List[ApiCallRecord]:
        """Retrieve recent API call records."""
        calls = []
        files = [self._get_log_path(sandbox_name)] if sandbox_name else list(self.telemetry_dir.glob("*.jsonl"))

        for f in files:
            if not f.exists():
                continue
            try:
                with open(f, "r") as fp:
                    for line in fp:
                        if line.strip():
                            data = json.loads(line)
                            calls.append(ApiCallRecord.from_dict(data))
            except Exception:
                pass

        calls.sort(key=lambda c: c.timestamp, reverse=True)
        return calls[:limit]

    def get_summary(self, sandbox_name: Optional[str] = None) -> dict:
        """Generate executive audit summary metrics across calls."""
        calls = self.get_calls(sandbox_name=sandbox_name, limit=5000)

        total_calls = len(calls)
        total_tokens = sum(c.total_tokens for c in calls)
        by_provider: Dict[str, int] = {}
        by_model: Dict[str, int] = {}
        error_count = 0
        est_cost = 0.0

        for c in calls:
            by_provider[c.provider] = by_provider.get(c.provider, 0) + 1
            if c.model:
                by_model[c.model] = by_model.get(c.model, 0) + 1
            if c.status_code >= 400:
                error_count += 1

            prov_key = c.provider.lower()
            cost_rate = PROVIDER_COST_PER_1K.get(prov_key, PROVIDER_COST_PER_1K["default"])
            est_cost += (c.total_tokens / 1000.0) * cost_rate

        return {
            "total_calls": total_calls,
            "total_tokens": total_tokens,
            "estimated_cost_usd": round(est_cost, 4),
            "error_count": error_count,
            "success_rate": round(((total_calls - error_count) / total_calls * 100) if total_calls else 100.0, 1),
            "by_provider": by_provider,
            "by_model": by_model
        }
