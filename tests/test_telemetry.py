"""
Unit tests for AI API telemetry and model invocation analytics.
"""

from pathlib import Path
import pytest

from krunbox.core.telemetry import TelemetryManager, identify_provider

def test_identify_provider():
    assert identify_provider("https://api.openai.com/v1/chat/completions") == "OpenAI"
    assert identify_provider("https://api.anthropic.com/v1/messages") == "Anthropic"
    assert identify_provider("https://generativelanguage.googleapis.com/v1beta/models") == "Google Gemini"
    assert identify_provider("https://api.mistral.ai/v1/chat/completions") == "Mistral"
    assert identify_provider("https://huggingface.co/api/models") == "HuggingFace"
    assert identify_provider("http://localhost:11434/api/generate") == "Ollama (Local)"
    assert identify_provider("https://unknown.server.com/api") == "Other"

def test_telemetry_recording_and_summary(tmp_path):
    mgr = TelemetryManager(telemetry_dir=tmp_path)

    # Record some mock AI calls
    mgr.record_call(
        sandbox_name="box-1",
        provider="OpenAI",
        endpoint="/v1/chat/completions",
        model="gpt-4o",
        status_code=200,
        prompt_tokens=150,
        completion_tokens=50,
        latency_ms=850.0
    )

    mgr.record_call(
        sandbox_name="box-1",
        provider="Anthropic",
        endpoint="/v1/messages",
        model="claude-3-5-sonnet-20241022",
        status_code=200,
        prompt_tokens=300,
        completion_tokens=100,
        latency_ms=1200.0
    )

    mgr.record_call(
        sandbox_name="box-2",
        provider="Google Gemini",
        endpoint="models/gemini-1.5-pro:generateContent",
        model="gemini-1.5-pro",
        status_code=429,  # Rate limit error
        prompt_tokens=20,
        completion_tokens=0,
        latency_ms=250.0
    )

    # Test summary for box-1
    summary1 = mgr.get_summary(sandbox_name="box-1")
    assert summary1["total_calls"] == 2
    assert summary1["total_tokens"] == 600
    assert summary1["error_count"] == 0
    assert summary1["by_provider"]["OpenAI"] == 1
    assert summary1["by_provider"]["Anthropic"] == 1

    # Test global summary
    global_summary = mgr.get_summary()
    assert global_summary["total_calls"] == 3
    assert global_summary["total_tokens"] == 620
    assert global_summary["error_count"] == 1
    assert global_summary["success_rate"] == 66.7
    assert global_summary["estimated_cost_usd"] > 0
