"""
Correlation context for scan_id / module across logger and JSONL (contextvars).
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional

_scan_id_ctx: ContextVar[str] = ContextVar("alanscan_scan_id", default="")
_module_ctx: ContextVar[str] = ContextVar("alanscan_module", default="")


def bind_scan_context(scan_id: str) -> tuple[Token, Token]:
    """Set scan_id context; returns tokens for reset."""
    return _scan_id_ctx.set(scan_id or ""), _module_ctx.set("")


def reset_scan_context(scan_tok: Token, mod_tok: Token) -> None:
    _scan_id_ctx.reset(scan_tok)
    _module_ctx.reset(mod_tok)


def set_module_context(module_name: str) -> Token:
    """Set current module name for subsequent log events (returns token to reset)."""
    return _module_ctx.set(module_name or "")


def reset_module_context(token: Token) -> None:
    _module_ctx.reset(token)


def get_scan_id() -> str:
    return _scan_id_ctx.get() or ""


def get_module() -> str:
    return _module_ctx.get() or ""
