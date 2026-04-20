"""
Ollama local LLM client for AI narrative generation.

POST http://localhost:11434/api/generate with model ``llama3`` (overridable via env).
Never raises: failures return an empty string after logging a short diagnostic.
"""

from __future__ import annotations

import json
import os
from typing import Any

from ..scan_logger import logger

OLLAMA_GENERATE_URL = os.environ.get(
    "OLLAMA_GENERATE_URL",
    "http://localhost:11434/api/generate",
).strip()
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3").strip() or "llama3"

try:
    _OLLAMA_TIMEOUT = float(os.environ.get("OLLAMA_TIMEOUT", "60"))
except (TypeError, ValueError):
    _OLLAMA_TIMEOUT = 60.0
OLLAMA_TIMEOUT = max(5.0, min(_OLLAMA_TIMEOUT, 600.0))


def generate_ai_analysis(prompt: str) -> str:
    """
    Send ``prompt`` to Ollama ``/api/generate`` and return the generated text.

    On success: returns stripped ``response`` text from the JSON body.
    On any failure: logs a readable message at INFO/DEBUG and returns ``""``.
    Does **not** raise.
    """
    p = (prompt or "").strip()
    if not p:
        return ""

    try:
        import requests
    except ImportError:
        logger.info(
            "[AI] Ollama client: requests not installed — cannot call local API",
            extra={"kind": "AI_OLLAMA_SKIP", "reason": "requests_missing"},
        )
        return ""

    payload: dict[str, Any] = {
        "model": OLLAMA_MODEL,
        "prompt": p,
        "stream": False,
    }

    try:
        resp = requests.post(
            OLLAMA_GENERATE_URL,
            json=payload,
            timeout=OLLAMA_TIMEOUT,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
    except Exception as exc:
        logger.info(
            "[AI] Ollama request failed: %s: %s",
            type(exc).__name__,
            exc,
            extra={"kind": "AI_OLLAMA_ERROR", "error": str(exc)},
        )
        return ""

    try:
        if resp.status_code != 200:
            body_preview = (resp.text or "")[:500]
            logger.info(
                "[AI] Ollama HTTP %s — %s",
                resp.status_code,
                body_preview or "(empty body)",
                extra={
                    "kind": "AI_OLLAMA_HTTP",
                    "status": resp.status_code,
                },
            )
            return ""
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as exc:
        logger.info(
            "[AI] Ollama invalid JSON response: %s",
            exc,
            extra={"kind": "AI_OLLAMA_BAD_JSON"},
        )
        return ""
    except Exception as exc:
        logger.info(
            "[AI] Ollama response handling error: %s: %s",
            type(exc).__name__,
            exc,
            extra={"kind": "AI_OLLAMA_ERROR", "error": str(exc)},
        )
        return ""

    text = ""
    if isinstance(data, dict):
        text = data.get("response") or ""
    text = str(text).strip()
    if not text:
        logger.info(
            "[AI] Ollama returned empty response",
            extra={"kind": "AI_OLLAMA_EMPTY"},
        )
        return ""

    return text
