"""
Zero-Secret Host API Proxy Daemon for krunbox.

Enforces cryptographic API credential isolation outside guest microVMs (SEC-06).
Provides per-sandbox Unix domain socket listeners, route dispatching, caller
header sanitization, provider ACL enforcement, spend guardrails, and SSE token accounting.
"""

import http.client
import http.server
import json
import math
import os
import re
import socket
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from . import config as core_config
from .sandbox import SandboxInfo
from .secrets import SecretVaultManager
from .telemetry import TelemetryManager

MAX_REQUEST_BODY_SIZE = 32 * 1024 * 1024  # 32 MiB
MAX_HEADER_SIZE = 16 * 1024               # 16 KiB

HOP_BY_HOP_HEADERS = frozenset([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
])

UNTRUSTED_HEADERS = frozenset([
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-goog-api-key",
    "cookie",
    "set-cookie",
    "host",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "openai-organization",
    "openai-project",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
])


def set_dumpable_false() -> None:
    """Set PR_SET_DUMPABLE to 0 to prevent host core dumps spilling bearer credentials."""
    try:
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        PR_SET_DUMPABLE = 4
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except Exception:
        pass


def validate_request_target(raw_target: str) -> Tuple[bool, str, int]:
    """
    Enforce Invariant 1: Anti-SSRF and strict path canonicalization.
    Rejects absolute URIs, control characters, backslashes, NUL bytes, and path traversal.
    """
    if raw_target.startswith(("http://", "https://", "//")):
        return False, "Absolute URI rejected (anti-SSRF Invariant 1)", 400

    for ch in raw_target:
        cp = ord(ch)
        if cp < 32 or cp == 127:
            return False, "Control characters rejected in request URI", 400

    if "\\" in raw_target:
        return False, "Backslashes rejected in request URI", 400

    parts = urlsplit(raw_target)
    path = parts.path
    unquoted = unquote(path)

    if "\x00" in unquoted or "\\0" in unquoted:
        return False, "NUL bytes rejected in request URI", 400

    segments = [s for s in unquoted.split("/") if s]
    if ".." in segments or "." in segments:
        return False, "Path traversal rejected in request URI", 400

    lower_raw = raw_target.lower()
    if "%2e" in lower_raw or "%2f" in lower_raw or ".." in raw_target:
        if any(seg == ".." or seg.startswith("..") or seg.endswith("..") for seg in segments):
            return False, "Path traversal rejected in request URI", 400

    return True, "", 200


def match_and_normalize_route(raw_target: str) -> Optional[Dict[str, Any]]:
    """
    Match incoming URL path against static provider routing table.
    Normalizes accidental double prefixes (e.g. /openai/v1/v1/chat/completions -> /v1/chat/completions).
    Scrubs ?key= query parameters for Google Gemini endpoints.
    """
    parts = urlsplit(raw_target)
    path = parts.path
    query = parts.query

    matched_provider = None
    target_host = ""
    target_base = ""
    secret_key = ""
    auth_header_type = ""
    strip_query_key = False
    remainder = ""

    if path.startswith("/openai/v1"):
        matched_provider = "OpenAI"
        target_host = "api.openai.com"
        target_base = "/v1"
        secret_key = "OPENAI_API_KEY"
        auth_header_type = "bearer"
        remainder = path[len("/openai/v1"):]
    elif path.startswith("/anthropic/v1"):
        matched_provider = "Anthropic"
        target_host = "api.anthropic.com"
        target_base = "/v1"
        secret_key = "ANTHROPIC_API_KEY"
        auth_header_type = "x-api-key"
        remainder = path[len("/anthropic/v1"):]
    elif path.startswith("/anthropic"):
        matched_provider = "Anthropic"
        target_host = "api.anthropic.com"
        target_base = "/v1"
        secret_key = "ANTHROPIC_API_KEY"
        auth_header_type = "x-api-key"
        remainder = path[len("/anthropic"):]
    elif path.startswith("/gemini/v1beta"):
        matched_provider = "Google Gemini"
        target_host = "generativelanguage.googleapis.com"
        target_base = "/v1beta"
        secret_key = "GEMINI_API_KEY"
        auth_header_type = "x-goog-api-key"
        strip_query_key = True
        remainder = path[len("/gemini/v1beta"):]
    elif path.startswith("/gemini/v1"):
        matched_provider = "Google Gemini"
        target_host = "generativelanguage.googleapis.com"
        target_base = "/v1"
        secret_key = "GEMINI_API_KEY"
        auth_header_type = "x-goog-api-key"
        strip_query_key = True
        remainder = path[len("/gemini/v1"):]
    elif path.startswith("/mistral/v1"):
        matched_provider = "Mistral"
        target_host = "api.mistral.ai"
        target_base = "/v1"
        secret_key = "MISTRAL_API_KEY"
        auth_header_type = "bearer"
        remainder = path[len("/mistral/v1"):]
    else:
        return None

    # Duplicate prefix tolerance: /v1/v1 -> /v1 or /v1beta/v1beta -> /v1beta
    if target_base == "/v1":
        if remainder.startswith("/v1/"):
            remainder = remainder[3:]
        elif remainder == "/v1":
            remainder = ""
    elif target_base == "/v1beta":
        if remainder.startswith("/v1beta/"):
            remainder = remainder[7:]
        elif remainder == "/v1beta":
            remainder = ""

    if remainder and not remainder.startswith("/"):
        remainder = "/" + remainder

    upstream_path = target_base + remainder

    clean_query = query
    if strip_query_key and query:
        params = parse_qsl(query, keep_blank_values=True)
        filtered = [(k, v) for k, v in params if k != "key"]
        clean_query = urlencode(filtered)

    requested_model = ""
    m = re.search(r"models/([^/:]+)", upstream_path)
    if m:
        requested_model = m.group(1)

    return {
        "provider": matched_provider,
        "target_host": target_host,
        "target_port": 443,
        "upstream_path": upstream_path,
        "query": clean_query,
        "required_secret_key": secret_key,
        "auth_header_type": auth_header_type,
        "requested_model": requested_model,
    }


def is_provider_authorized(sandbox_info: SandboxInfo, required_key: str) -> bool:
    """Enforce Invariant 3: Per-sandbox provider ACL check."""
    keys = getattr(sandbox_info, "secret_keys", []) or []
    target_keys = {required_key}
    if required_key == "GEMINI_API_KEY":
        target_keys.add("GOOGLE_API_KEY")

    for k in keys:
        base_k = k.split(":", 1)[0]
        if base_k in target_keys:
            return True
    return False


def sanitize_and_inject_headers(
    incoming_headers: Any,
    route_info: Dict[str, Any],
    secret: str,
    body_len: int,
) -> Dict[str, str]:
    """Enforce Invariant 2: Strip untrusted caller headers and inject real auth."""
    out_headers: Dict[str, str] = {}
    items = incoming_headers.items() if hasattr(incoming_headers, "items") else incoming_headers
    for k, v in items:
        lower_k = k.lower()
        if lower_k in UNTRUSTED_HEADERS or lower_k.startswith("x-forwarded-"):
            continue
        if "\r" in k or "\n" in k or "\x00" in k or "\r" in v or "\n" in v or "\x00" in v:
            continue
        out_headers[k] = str(v)

    out_headers["Host"] = route_info["target_host"]
    auth_type = route_info["auth_header_type"]
    if auth_type == "bearer":
        out_headers["Authorization"] = f"Bearer {secret}"
    elif auth_type == "x-api-key":
        out_headers["x-api-key"] = secret
    elif auth_type == "x-goog-api-key":
        out_headers["x-goog-api-key"] = secret

    if body_len > 0:
        out_headers["Content-Length"] = str(body_len)
    elif "Content-Length" in out_headers:
        out_headers["Content-Length"] = "0"

    return out_headers


def extract_json_usage(provider: str, body: dict) -> Tuple[int, int, str]:
    """Extract prompt tokens, completion tokens, and model name from non-streaming JSON responses."""
    model = ""
    prompt_tokens = 0
    completion_tokens = 0

    if provider == "OpenAI":
        model = str(body.get("model", ""))
        usage = body.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0)
        completion_tokens = int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0)
    elif provider == "Anthropic":
        model = str(body.get("model", ""))
        usage = body.get("usage") or {}
        prompt_tokens = (
            int(usage.get("input_tokens", 0) or 0)
            + int(usage.get("cache_creation_input_tokens", 0) or 0)
            + int(usage.get("cache_read_input_tokens", 0) or 0)
        )
        completion_tokens = int(usage.get("output_tokens", 0) or 0)
    elif provider == "Google Gemini":
        model = str(body.get("modelVersion", ""))
        usage = body.get("usageMetadata") or {}
        prompt_tokens = int(usage.get("promptTokenCount", 0) or 0)
        completion_tokens = int(usage.get("candidatesTokenCount", 0) or 0) + int(usage.get("thoughtsTokenCount", 0) or 0)
    elif provider == "Mistral":
        model = str(body.get("model", ""))
        usage = body.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        completion_tokens = int(usage.get("completion_tokens", 0) or 0)

    return prompt_tokens, completion_tokens, model


class SseUsageAccumulator:
    """Non-blocking line-framed state machine for streaming SSE usage extraction."""

    def __init__(self, provider: str, default_model: str = ""):
        self.provider = provider
        self.model = default_model
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.streamed_completion_chars = 0
        self._buffer = ""
        self._current_event = ""

    def feed(self, chunk: bytes | str) -> None:
        if isinstance(chunk, bytes):
            text = chunk.decode("utf-8", errors="replace")
        else:
            text = str(chunk)
        self._buffer += text

        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            line = line.rstrip("\r")

            if not line:
                self._current_event = ""
                continue

            if line.startswith("event:"):
                self._current_event = line[6:].strip()
                continue

            if line.startswith("data:"):
                data_str = line[5:].strip()
                if data_str == "[DONE]":
                    continue
                try:
                    data = json.loads(data_str)
                    if isinstance(data, dict):
                        self._process_data(data)
                except Exception:
                    pass

    def _process_data(self, data: dict) -> None:
        if self.provider == "Anthropic":
            msg_type = data.get("type", "") or self._current_event
            if msg_type == "message_start":
                msg = data.get("message", {})
                if "model" in msg:
                    self.model = str(msg["model"])
                usage = msg.get("usage", {})
                self.prompt_tokens = (
                    int(usage.get("input_tokens", 0) or 0)
                    + int(usage.get("cache_creation_input_tokens", 0) or 0)
                    + int(usage.get("cache_read_input_tokens", 0) or 0)
                )
            elif msg_type == "message_delta":
                usage = data.get("usage", {})
                if "output_tokens" in usage:
                    self.completion_tokens = int(usage["output_tokens"] or 0)
            elif msg_type == "content_block_delta":
                delta = data.get("delta", {})
                txt = delta.get("text", "")
                if txt:
                    self.streamed_completion_chars += len(txt)

        elif self.provider == "OpenAI":
            if "model" in data and not self.model:
                self.model = str(data["model"])
            usage = data.get("usage")
            if usage and isinstance(usage, dict):
                p_tok = usage.get("prompt_tokens", usage.get("input_tokens"))
                c_tok = usage.get("completion_tokens", usage.get("output_tokens"))
                if p_tok is not None:
                    self.prompt_tokens = int(p_tok)
                if c_tok is not None:
                    self.completion_tokens = int(c_tok)
            for choice in data.get("choices", []):
                delta = choice.get("delta", {})
                content = delta.get("content", "")
                if content:
                    self.streamed_completion_chars += len(content)

        elif self.provider == "Google Gemini":
            if data.get("modelVersion"):
                self.model = str(data["modelVersion"])
            usage = data.get("usageMetadata", {})
            if usage:
                if "promptTokenCount" in usage:
                    self.prompt_tokens = int(usage["promptTokenCount"] or 0)
                self.completion_tokens = (
                    int(usage.get("candidatesTokenCount", 0) or 0)
                    + int(usage.get("thoughtsTokenCount", 0) or 0)
                )
            for cand in data.get("candidates", []):
                content = cand.get("content", {})
                for part in content.get("parts", []):
                    txt = part.get("text", "")
                    if txt:
                        self.streamed_completion_chars += len(txt)

        elif self.provider == "Mistral":
            if "model" in data and not self.model:
                self.model = str(data["model"])
            usage = data.get("usage")
            if usage and isinstance(usage, dict):
                if "prompt_tokens" in usage:
                    self.prompt_tokens = int(usage["prompt_tokens"] or 0)
                if "completion_tokens" in usage:
                    self.completion_tokens = int(usage["completion_tokens"] or 0)
            for choice in data.get("choices", []):
                delta = choice.get("delta", {})
                content = delta.get("content", "")
                if content:
                    self.streamed_completion_chars += len(content)

    def finalize(self) -> None:
        """Fallback to byte/character estimator if stream severed mid-flight."""
        if self.completion_tokens == 0 and self.streamed_completion_chars > 0:
            self.completion_tokens = math.ceil(self.streamed_completion_chars / 4)


class UpstreamResponse:
    """Wrapper around upstream response supporting streaming iter_chunks."""

    def __init__(
        self,
        status: int,
        reason: str,
        headers: Dict[str, str],
        body_stream: Any,
        connection: Any = None,
    ):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body_stream = body_stream
        self.connection = connection

    def iter_chunks(self, chunk_size: int = 4096):
        if hasattr(self.body_stream, "read"):
            while True:
                chunk = self.body_stream.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        elif isinstance(self.body_stream, (bytes, bytearray)):
            yield bytes(self.body_stream)
        elif hasattr(self.body_stream, "__iter__"):
            for item in self.body_stream:
                if isinstance(item, str):
                    yield item.encode("utf-8")
                else:
                    yield bytes(item)

    def close(self):
        if hasattr(self.body_stream, "close"):
            try:
                self.body_stream.close()
            except Exception:
                pass
        if self.connection is not None and hasattr(self.connection, "close"):
            try:
                self.connection.close()
            except Exception:
                pass


class ProxyHttpRequestHandler(http.server.BaseHTTPRequestHandler):
    """Handles incoming guest HTTP requests over per-sandbox Unix domain socket."""

    def address_string(self) -> str:
        return "unix-socket"

    def log_message(self, format, *args) -> None:
        pass

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request()

    def do_OPTIONS(self):
        self._handle_request()

    def _send_error_json(self, status: int, err_type: str, message: str, code: Optional[str] = None) -> None:
        payload = {
            "type": "error",
            "error": {
                "type": err_type,
                "code": code or err_type,
                "message": message,
            },
        }
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle_request(self) -> None:
        daemon = getattr(self.server, "daemon_instance", None)
        if daemon is None:
            self._send_error_json(500, "internal_error", "Proxy daemon instance not configured.")
            return

        sandbox_info = daemon.get_sandbox_info()
        start_time = time.monotonic()

        # 1. Read request body
        body = b""
        content_length_str = self.headers.get("Content-Length")
        if content_length_str:
            try:
                length = int(content_length_str)
                if length > MAX_REQUEST_BODY_SIZE:
                    self._send_error_json(413, "payload_too_large", "Request body exceeds 32 MiB ceiling.")
                    return
                if length > 0:
                    body = self.rfile.read(length)
            except ValueError:
                self._send_error_json(400, "bad_request", "Invalid Content-Length header.")
                return

        # 2. Invariant 1: SSRF / Traversal / Control char validation
        is_valid, err_msg, err_status = validate_request_target(self.path)
        if not is_valid:
            self._send_error_json(err_status, "invalid_request_target", err_msg)
            return

        # 3. Path matching and double prefix normalization
        route_info = match_and_normalize_route(self.path)
        if route_info is None:
            self._send_error_json(404, "not_found", f"No provider route matched for path: {self.path}")
            return

        provider = route_info["provider"]
        upstream_path = route_info["upstream_path"]
        target_path_and_query = upstream_path
        if route_info["query"]:
            target_path_and_query += "?" + route_info["query"]

        # 4. Invariant 3: Per-sandbox provider ACL
        if not is_provider_authorized(sandbox_info, route_info["required_secret_key"]):
            daemon.telemetry_mgr.record_call(
                sandbox_name=sandbox_info.name,
                provider=provider,
                endpoint=upstream_path,
                model=route_info.get("requested_model") or "unknown",
                status_code=403,
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=0.0,
            )
            self._send_error_json(
                403,
                "provider_not_authorized",
                f"Provider '{provider}' is not authorized for sandbox '{sandbox_info.name}'. Add {route_info['required_secret_key']} to sandbox secret keys.",
                code="provider_not_authorized",
            )
            return

        # 5. Guardrail Budget Pre-Flight Check
        summary = daemon.telemetry_mgr.get_summary(sandbox_info.name)
        total_tokens = int(summary.get("total_tokens", 0) or 0)
        est_cost = float(summary.get("estimated_cost_usd", 0.0) or 0.0)
        max_tokens = int(getattr(sandbox_info, "max_tokens_budget", 0) or 0)
        max_cost = float(getattr(sandbox_info, "max_cost_usd_budget", 0.0) or 0.0)

        tokens_exceeded = max_tokens > 0 and total_tokens >= max_tokens
        cost_exceeded = max_cost > 0.0 and est_cost >= max_cost

        if tokens_exceeded or cost_exceeded:
            daemon.telemetry_mgr.record_call(
                sandbox_name=sandbox_info.name,
                provider=provider,
                endpoint=upstream_path,
                model=route_info.get("requested_model") or "unknown",
                status_code=429,
                prompt_tokens=0,
                completion_tokens=0,
                latency_ms=0.0,
            )
            reasons = []
            if tokens_exceeded:
                reasons.append(f"tokens: {total_tokens:,}/{max_tokens:,}")
            if cost_exceeded:
                reasons.append(f"spend: ${est_cost:.2f}/${max_cost:.2f} USD")
            msg = (
                f"krunbox guardrail blocked request: sandbox '{sandbox_info.name}' "
                f"reached its budget cap ({', '.join(reasons)}). "
                f"Adjust limits via 'krunbox edit' or the Sandbox Settings dialog."
            )
            self._send_error_json(429, "krunbox_budget_exceeded", msg, code="budget_exceeded")
            return

        # 6. Key Resolution
        secret = daemon.resolve_secret(sandbox_info, route_info["required_secret_key"])
        if not secret:
            self._send_error_json(
                502,
                "secret_not_found",
                f"Secret '{route_info['required_secret_key']}' not found in vault or keyring for sandbox '{sandbox_info.name}'.",
            )
            return

        # 7. Model Extraction & OpenAI Stream Options Injection
        requested_model = route_info.get("requested_model", "")
        content_type = self.headers.get("Content-Type", "")
        if body and "application/json" in content_type.lower():
            try:
                parsed_body = json.loads(body.decode("utf-8"))
                if isinstance(parsed_body, dict):
                    if not requested_model and "model" in parsed_body:
                        requested_model = str(parsed_body["model"])
                    # Inject stream_options.include_usage for OpenAI streaming
                    if provider == "OpenAI" and parsed_body.get("stream") is True:
                        stream_opts = parsed_body.get("stream_options")
                        if not isinstance(stream_opts, dict):
                            stream_opts = {}
                        stream_opts["include_usage"] = True
                        parsed_body["stream_options"] = stream_opts
                        body = json.dumps(parsed_body).encode("utf-8")
            except Exception:
                pass

        # 8. Invariant 2: Sanitize headers and inject secret
        out_headers = sanitize_and_inject_headers(
            incoming_headers=self.headers,
            route_info=route_info,
            secret=secret,
            body_len=len(body),
        )

        # 9. Upstream Dispatch
        upstream_status = 500
        prompt_tokens = 0
        completion_tokens = 0
        recorded_model = requested_model or "unknown"
        upstream_resp: Optional[UpstreamResponse] = None

        try:
            upstream_resp = daemon.dispatch_upstream(
                method=self.command,
                host=route_info["target_host"],
                port=route_info["target_port"],
                path_and_query=target_path_and_query,
                headers=out_headers,
                body=body,
            )
            upstream_status = upstream_resp.status

            self.send_response(upstream_resp.status, upstream_resp.reason)
            resp_content_type = ""
            for h_k, h_v in upstream_resp.headers.items():
                lower_k = h_k.lower()
                if lower_k in HOP_BY_HOP_HEADERS:
                    continue
                if lower_k == "content-type":
                    resp_content_type = h_v
                self.send_header(h_k, h_v)
            self.end_headers()

            is_sse = "text/event-stream" in resp_content_type.lower()
            if is_sse:
                accumulator = SseUsageAccumulator(provider=provider, default_model=requested_model)
                try:
                    for chunk in upstream_resp.iter_chunks():
                        accumulator.feed(chunk)
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    accumulator.finalize()
                    if accumulator.model:
                        recorded_model = accumulator.model
                    prompt_tokens = accumulator.prompt_tokens
                    completion_tokens = accumulator.completion_tokens
            else:
                full_body = bytearray()
                try:
                    for chunk in upstream_resp.iter_chunks():
                        full_body.extend(chunk)
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass

                if "application/json" in resp_content_type.lower() and full_body:
                    try:
                        resp_json = json.loads(full_body.decode("utf-8"))
                        if isinstance(resp_json, dict):
                            p_tok, c_tok, m_name = extract_json_usage(provider, resp_json)
                            prompt_tokens = p_tok
                            completion_tokens = c_tok
                            if m_name:
                                recorded_model = m_name
                    except Exception:
                        pass
        except Exception as exc:
            upstream_status = 502
            self._send_error_json(502, "bad_gateway", f"Upstream connection failed: {exc}")
        finally:
            if upstream_resp is not None:
                upstream_resp.close()

            latency_ms = round((time.monotonic() - start_time) * 1000.0, 2)
            daemon.telemetry_mgr.record_call(
                sandbox_name=sandbox_info.name,
                provider=provider,
                endpoint=upstream_path,
                model=recorded_model,
                status_code=upstream_status,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                latency_ms=latency_ms,
            )


class UnixStreamHttpServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, socket_path: str, request_handler_class, daemon_instance: "HostApiProxyDaemon"):
        self.daemon_instance = daemon_instance
        super().__init__(socket_path, request_handler_class)


class HostApiProxyDaemon:
    """Host-side proxy daemon listening on per-sandbox Unix domain socket."""

    def __init__(
        self,
        sandbox_info: SandboxInfo,
        telemetry_mgr: Optional[TelemetryManager] = None,
        vault_mgr: Optional[SecretVaultManager] = None,
        base_dir: Optional[Path] = None,
        socket_mode: int = 0o666,
        timeout: float = 60.0,
        upstream_dispatcher: Optional[Callable] = None,
        get_sandbox_info: Optional[Callable[[], SandboxInfo]] = None,
    ):
        self.sandbox_info = sandbox_info
        self.get_sandbox_info = get_sandbox_info or (lambda: self.sandbox_info)
        self.telemetry_mgr = telemetry_mgr or TelemetryManager()
        self.vault_mgr = vault_mgr or SecretVaultManager()
        self.base_dir = Path(base_dir) if base_dir else (core_config.DATA_DIR / "proxy")
        self.socket_mode = socket_mode
        self.timeout = timeout
        self.upstream_dispatcher = upstream_dispatcher
        self.server: Optional[UnixStreamHttpServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._is_running = False

    @property
    def sandbox_name(self) -> str:
        return self.get_sandbox_info().name

    @property
    def socket_dir(self) -> Path:
        return self.base_dir / self.sandbox_name

    @property
    def socket_path(self) -> Path:
        return self.socket_dir / "llm.sock"

    def resolve_secret(self, sandbox_info: SandboxInfo, target_key: str) -> Optional[str]:
        keys_to_try = []
        for k in getattr(sandbox_info, "secret_keys", []) or []:
            if k == target_key or k.startswith(target_key + ":"):
                keys_to_try.append(k)
        if target_key not in keys_to_try:
            keys_to_try.append(target_key)
        if target_key == "GEMINI_API_KEY":
            for k in getattr(sandbox_info, "secret_keys", []) or []:
                if k == "GOOGLE_API_KEY" or k.startswith("GOOGLE_API_KEY:"):
                    keys_to_try.append(k)
            keys_to_try.append("GOOGLE_API_KEY")

        for key_name in keys_to_try:
            val = self.vault_mgr.get_secret(sandbox_info.name, key_name)
            if val:
                return val

        for key_name in keys_to_try:
            val = os.environ.get(key_name)
            if val:
                return val

        return None

    def dispatch_upstream(
        self,
        method: str,
        host: str,
        port: int,
        path_and_query: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> UpstreamResponse:
        if self.upstream_dispatcher is not None:
            return self.upstream_dispatcher(method, host, port, path_and_query, headers, body)

        ssl_ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port=port, context=ssl_ctx, timeout=self.timeout)
        conn.request(method, path_and_query, body=body if body else None, headers=headers)
        resp = conn.getresponse()
        resp_headers = {k: v for k, v in resp.getheaders()}
        return UpstreamResponse(
            status=resp.status,
            reason=resp.reason,
            headers=resp_headers,
            body_stream=resp,
            connection=conn,
        )

    def start(self) -> None:
        if self._is_running:
            return

        self.socket_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.socket_dir, 0o700)
        except Exception:
            pass

        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass

        set_dumpable_false()

        self.server = UnixStreamHttpServer(str(self.socket_path), ProxyHttpRequestHandler, daemon_instance=self)
        try:
            os.chmod(self.socket_path, self.socket_mode)
        except Exception:
            pass

        self._is_running = True
        self._server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._server_thread.start()

    def stop(self) -> None:
        self._is_running = False
        if self.server is not None:
            try:
                self.server.shutdown()
            except Exception:
                pass
            try:
                self.server.server_close()
            except Exception:
                pass
            self.server = None

        if self._server_thread is not None:
            self._server_thread.join(timeout=2.0)
            self._server_thread = None

        if self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except Exception:
                pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
