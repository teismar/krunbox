"""
Unit and integration tests for krunbox Zero-Secret Host API Proxy.
"""

import json
import socket
import time
from pathlib import Path
import pytest

from krunbox.core.sandbox import SandboxInfo
from krunbox.core.telemetry import TelemetryManager
from krunbox.core.secrets import SecretVaultManager
from krunbox.core.proxy import (
    HostApiProxyDaemon,
    UpstreamResponse,
    validate_request_target,
    match_and_normalize_route,
    sanitize_and_inject_headers,
    is_provider_authorized,
    SseUsageAccumulator,
)


def _send_unix_http_request(
    socket_path: Path,
    method: str,
    path: str,
    headers: dict = None,
    body: bytes = b"",
) -> tuple[int, dict, bytes]:
    """Helper to dispatch HTTP requests directly over a Unix domain socket."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(str(socket_path))
    s.settimeout(5.0)

    req_headers = dict(headers or {})
    if "Host" not in req_headers:
        req_headers["Host"] = "localhost"
    if body and "Content-Length" not in req_headers:
        req_headers["Content-Length"] = str(len(body))

    head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in req_headers.items()) + "\r\n"
    s.sendall(head.encode("utf-8") + body)

    resp_data = bytearray()
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_data.extend(chunk)
            if b"\r\n\r\n" in resp_data:
                header_part, body_part = resp_data.split(b"\r\n\r\n", 1)
                header_text = header_part.decode("utf-8", errors="replace")
                cl_header = None
                for line in header_text.split("\r\n")[1:]:
                    if ":" in line:
                        k, v = line.split(":", 1)
                        if k.strip().lower() == "content-length":
                            cl_header = int(v.strip())
                            break
                if cl_header is not None and len(body_part) >= cl_header:
                    break
        except socket.timeout:
            break

    s.close()
    if b"\r\n\r\n" not in resp_data:
        return 500, {}, bytes(resp_data)

    header_bytes, body_bytes = resp_data.split(b"\r\n\r\n", 1)
    lines = header_bytes.decode("utf-8", errors="replace").split("\r\n")
    status_code = int(lines[0].split()[1])

    resp_headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()

    return status_code, resp_headers, bytes(body_bytes)


def test_path_parsing_and_double_prefix_normalization():
    # OpenAI normal and double prefix
    r1 = match_and_normalize_route("/openai/v1/chat/completions")
    assert r1["provider"] == "OpenAI"
    assert r1["upstream_path"] == "/v1/chat/completions"

    r2 = match_and_normalize_route("/openai/v1/v1/chat/completions")
    assert r2["provider"] == "OpenAI"
    assert r2["upstream_path"] == "/v1/chat/completions"

    # Anthropic
    r3 = match_and_normalize_route("/anthropic/v1/messages")
    assert r3["provider"] == "Anthropic"
    assert r3["upstream_path"] == "/v1/messages"

    r4 = match_and_normalize_route("/anthropic/v1/v1/messages")
    assert r4["provider"] == "Anthropic"
    assert r4["upstream_path"] == "/v1/messages"

    r5 = match_and_normalize_route("/anthropic/messages")
    assert r5["provider"] == "Anthropic"
    assert r5["upstream_path"] == "/v1/messages"

    # Gemini
    r6 = match_and_normalize_route("/gemini/v1beta/models/gemini-1.5-pro:generateContent")
    assert r6["provider"] == "Google Gemini"
    assert r6["upstream_path"] == "/v1beta/models/gemini-1.5-pro:generateContent"
    assert r6["requested_model"] == "gemini-1.5-pro"

    r7 = match_and_normalize_route("/gemini/v1beta/v1beta/models/gemini-1.5-flash:generateContent")
    assert r7["upstream_path"] == "/v1beta/models/gemini-1.5-flash:generateContent"

    # Mistral
    r8 = match_and_normalize_route("/mistral/v1/v1/chat/completions")
    assert r8["provider"] == "Mistral"
    assert r8["upstream_path"] == "/v1/chat/completions"

    # Unknown
    assert match_and_normalize_route("/unknown/v1/test") is None


def test_anti_ssrf_and_traversal_rejection():
    # Path traversal rejected
    valid, _, code = validate_request_target("/openai/v1/../../billing")
    assert not valid and code == 400

    valid, _, code = validate_request_target("/openai/v1/%2e%2e/billing")
    assert not valid and code == 400

    # Absolute URL rejected
    valid, _, code = validate_request_target("http://169.254.169.254/latest/meta-data")
    assert not valid and code == 400

    valid, _, code = validate_request_target("https://api.openai.com/v1/chat/completions")
    assert not valid and code == 400

    # Control chars / backslashes rejected
    valid, _, code = validate_request_target("/openai/v1/chat\\completions")
    assert not valid and code == 400

    valid, _, code = validate_request_target("/openai/v1/chat\0completions")
    assert not valid and code == 400

    # Valid relative path allowed
    valid, _, code = validate_request_target("/openai/v1/chat/completions")
    assert valid and code == 200


def test_header_stripping_and_gemini_query_key_scrubbing():
    route = match_and_normalize_route("/gemini/v1beta/models/gemini-1.5-pro:generateContent?key=proxy-phantom&alt=sse&pageSize=10")
    assert route["query"] == "alt=sse&pageSize=10"
    assert "key=" not in route["query"]

    incoming = {
        "Authorization": "Bearer phantom",
        "x-api-key": "phantom",
        "x-goog-api-key": "phantom",
        "Cookie": "secret_cookie=123",
        "Host": "attacker.local",
        "X-Forwarded-For": "10.0.0.1",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    sanitized = sanitize_and_inject_headers(incoming, route, secret="real-secret-12345", body_len=10)

    assert sanitized["Host"] == "generativelanguage.googleapis.com"
    assert sanitized["x-goog-api-key"] == "real-secret-12345"
    assert "Authorization" not in sanitized
    assert "x-api-key" not in sanitized
    assert "Cookie" not in sanitized
    assert "X-Forwarded-For" not in sanitized
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Accept"] == "application/json"


def test_provider_acl_authorization_check():
    box_anthropic = SandboxInfo(name="box-1", dir_path="/tmp", hostname="h", container_name="c", ssh_port=2222, secret_keys=["ANTHROPIC_API_KEY"])
    assert is_provider_authorized(box_anthropic, "ANTHROPIC_API_KEY")
    assert not is_provider_authorized(box_anthropic, "OPENAI_API_KEY")

    # Multi-project alias support
    box_alias = SandboxInfo(name="box-2", dir_path="/tmp", hostname="h", container_name="c", ssh_port=2222, secret_keys=["ANTHROPIC_API_KEY:client-acme"])
    assert is_provider_authorized(box_alias, "ANTHROPIC_API_KEY")

    # Gemini with GOOGLE_API_KEY alias
    box_google = SandboxInfo(name="box-3", dir_path="/tmp", hostname="h", container_name="c", ssh_port=2222, secret_keys=["GOOGLE_API_KEY"])
    assert is_provider_authorized(box_google, "GEMINI_API_KEY")


def test_unauthorized_provider_403_forbidden(tmp_path):
    telem = TelemetryManager(telemetry_dir=tmp_path / "telem")
    vault = SecretVaultManager(secrets_dir=tmp_path / "secrets")
    vault.set_secret("box-test", "ANTHROPIC_API_KEY", "real-anthropic-key")

    box = SandboxInfo(name="box-test", dir_path="/tmp", hostname="h", container_name="c", ssh_port=2222, secret_keys=["ANTHROPIC_API_KEY"])

    upstream_called = []
    def mock_dispatcher(*args):
        upstream_called.append(args)
        return UpstreamResponse(200, "OK", {"Content-Type": "application/json"}, b"{}")

    daemon = HostApiProxyDaemon(
        sandbox_info=box,
        telemetry_mgr=telem,
        vault_mgr=vault,
        base_dir=tmp_path / "proxy",
        upstream_dispatcher=mock_dispatcher,
    )

    with daemon:
        status, headers, body = _send_unix_http_request(daemon.socket_path, "POST", "/openai/v1/chat/completions", body=b"{}")
        assert status == 403
        data = json.loads(body.decode("utf-8"))
        assert data["error"]["code"] == "provider_not_authorized"
        assert len(upstream_called) == 0

        # Telemetry should record the 403 rejection
        calls = telem.get_calls("box-test")
        assert len(calls) == 1
        assert calls[0].status_code == 403
        assert calls[0].provider == "OpenAI"


def test_budget_exceeded_429_too_many_requests(tmp_path):
    telem = TelemetryManager(telemetry_dir=tmp_path / "telem")
    vault = SecretVaultManager(secrets_dir=tmp_path / "secrets")
    vault.set_secret("box-test", "OPENAI_API_KEY", "real-openai-key")

    # Seed spend cap: budget is 5.00 USD, record 2,000,000 tokens ($10.00)
    telem.record_call(
        sandbox_name="box-test",
        provider="OpenAI",
        endpoint="/v1/chat/completions",
        model="gpt-4o",
        status_code=200,
        prompt_tokens=1000000,
        completion_tokens=1000000,
    )

    box = SandboxInfo(
        name="box-test",
        dir_path="/tmp",
        hostname="h",
        container_name="c",
        ssh_port=2222,
        secret_keys=["OPENAI_API_KEY"],
        max_cost_usd_budget=5.00,
    )

    upstream_called = []
    def mock_dispatcher(*args):
        upstream_called.append(args)
        return UpstreamResponse(200, "OK", {"Content-Type": "application/json"}, b"{}")

    daemon = HostApiProxyDaemon(
        sandbox_info=box,
        telemetry_mgr=telem,
        vault_mgr=vault,
        base_dir=tmp_path / "proxy",
        upstream_dispatcher=mock_dispatcher,
    )

    with daemon:
        status, headers, body = _send_unix_http_request(daemon.socket_path, "POST", "/openai/v1/chat/completions", body=b"{}")
        assert status == 429
        data = json.loads(body.decode("utf-8"))
        assert data["error"]["code"] == "budget_exceeded"
        assert len(upstream_called) == 0

        # Check telemetry recorded 429 denial
        calls = telem.get_calls("box-test")
        assert calls[0].status_code == 429


def test_json_response_token_accounting(tmp_path):
    telem = TelemetryManager(telemetry_dir=tmp_path / "telem")
    vault = SecretVaultManager(secrets_dir=tmp_path / "secrets")
    vault.set_secret("box-test", "OPENAI_API_KEY", "real-openai-key")

    box = SandboxInfo(name="box-test", dir_path="/tmp", hostname="h", container_name="c", ssh_port=2222, secret_keys=["OPENAI_API_KEY"])

    resp_payload = {
        "id": "chatcmpl-1",
        "model": "gpt-4o",
        "choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 45, "total_tokens": 165},
    }

    def mock_dispatcher(method, host, port, path, headers, body):
        assert headers["Authorization"] == "Bearer real-openai-key"
        return UpstreamResponse(200, "OK", {"Content-Type": "application/json"}, json.dumps(resp_payload).encode("utf-8"))

    daemon = HostApiProxyDaemon(
        sandbox_info=box,
        telemetry_mgr=telem,
        vault_mgr=vault,
        base_dir=tmp_path / "proxy",
        upstream_dispatcher=mock_dispatcher,
    )

    with daemon:
        status, headers, body = _send_unix_http_request(
            daemon.socket_path,
            "POST",
            "/openai/v1/chat/completions",
            body=json.dumps({"model": "gpt-4o", "messages": []}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        data = json.loads(body.decode("utf-8"))
        assert data["choices"][0]["message"]["content"] == "Hello!"

        calls = telem.get_calls("box-test")
        assert len(calls) == 1
        assert calls[0].status_code == 200
        assert calls[0].prompt_tokens == 120
        assert calls[0].completion_tokens == 45
        assert calls[0].total_tokens == 165
        assert calls[0].model == "gpt-4o"


def test_sse_streaming_token_accounting_and_stream_options(tmp_path):
    telem = TelemetryManager(telemetry_dir=tmp_path / "telem")
    vault = SecretVaultManager(secrets_dir=tmp_path / "secrets")
    vault.set_secret("box-test", "OPENAI_API_KEY", "real-openai-key")

    box = SandboxInfo(name="box-test", dir_path="/tmp", hostname="h", container_name="c", ssh_port=2222, secret_keys=["OPENAI_API_KEY"])

    sse_frames = [
        b'data: {"id":"1","model":"gpt-4o","choices":[{"delta":{"content":"Hi"}}]}\n\n',
        b'data: {"id":"1","model":"gpt-4o","choices":[{"delta":{"content":" there"}}],"usage":{"prompt_tokens":35,"completion_tokens":15,"total_tokens":50}}\n\n',
        b'data: [DONE]\n\n',
    ]

    def mock_dispatcher(method, host, port, path, headers, body):
        parsed = json.loads(body.decode("utf-8"))
        # Ensure stream_options.include_usage was automatically injected
        assert parsed.get("stream_options", {}).get("include_usage") is True
        return UpstreamResponse(200, "OK", {"Content-Type": "text/event-stream"}, sse_frames)

    daemon = HostApiProxyDaemon(
        sandbox_info=box,
        telemetry_mgr=telem,
        vault_mgr=vault,
        base_dir=tmp_path / "proxy",
        upstream_dispatcher=mock_dispatcher,
    )

    with daemon:
        status, headers, body = _send_unix_http_request(
            daemon.socket_path,
            "POST",
            "/openai/v1/chat/completions",
            body=json.dumps({"model": "gpt-4o", "stream": True, "messages": []}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        assert status == 200
        assert b"Hi" in body

        calls = telem.get_calls("box-test")
        assert len(calls) == 1
        assert calls[0].prompt_tokens == 35
        assert calls[0].completion_tokens == 15
        assert calls[0].total_tokens == 50
        assert calls[0].model == "gpt-4o"


def test_sse_disconnect_fallback_accounting():
    acc = SseUsageAccumulator(provider="Anthropic", default_model="claude-3-5-sonnet")
    # Simulate content block delta chunks
    acc.feed('event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"abcdefghijklmnopqrstuvwxyz"}}\n\n')
    assert acc.completion_tokens == 0
    assert acc.streamed_completion_chars == 26
    acc.finalize()
    assert acc.completion_tokens == 7  # ceil(26 / 4)
