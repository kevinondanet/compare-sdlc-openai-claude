"""Harness adapters: render the canonical workflow into host-native formats.

Supported hosts: Claude Code, GitHub Copilot, OpenAI Codex, Cursor, Kiro; plus OpenSpec
change-directory import/export. Canonical artifacts never depend on a harness — adapters
translate (ARCHITECTURE.md §0.7).
"""

from __future__ import annotations

from collections.abc import Callable

from aisdlc.adapters.base import (
    CANONICAL_ARTIFACTS,
    CANONICAL_COMMANDS,
    DEFAULT_HOOK_COMMAND,
    AdapterContext,
    ArtifactDescription,
    CanonicalCommand,
    EmittedFile,
    EmittedFiles,
    HarnessAdapter,
    WorkflowPhase,
    command_by_key,
    default_context,
)
from aisdlc.adapters.claude_code import ClaudeCodeAdapter
from aisdlc.adapters.codex import CodexAdapter
from aisdlc.adapters.copilot import CopilotAdapter
from aisdlc.adapters.cursor import CursorAdapter
from aisdlc.adapters.kiro import KiroAdapter
from aisdlc.adapters.openspec import (
    ExportResult,
    ImportResult,
    OpenSpecError,
    Unmapped,
    export_change,
    import_change,
)

__all__ = [
    "ADAPTERS",
    "CANONICAL_ARTIFACTS",
    "CANONICAL_COMMANDS",
    "DEFAULT_HOOK_COMMAND",
    "AdapterContext",
    "ArtifactDescription",
    "CanonicalCommand",
    "ClaudeCodeAdapter",
    "CodexAdapter",
    "CopilotAdapter",
    "CursorAdapter",
    "EmittedFile",
    "EmittedFiles",
    "ExportResult",
    "HarnessAdapter",
    "ImportResult",
    "KiroAdapter",
    "OpenSpecError",
    "Unmapped",
    "WorkflowPhase",
    "adapter_names",
    "command_by_key",
    "default_context",
    "export_change",
    "get_adapter",
    "import_change",
]

ADAPTERS: dict[str, Callable[[], HarnessAdapter]] = {
    "claude_code": ClaudeCodeAdapter,
    "copilot": CopilotAdapter,
    "codex": CodexAdapter,
    "cursor": CursorAdapter,
    "kiro": KiroAdapter,
}
"""Registered adapters by harness name (aliases with ``-`` are accepted by :func:`get_adapter`)."""


def adapter_names() -> list[str]:
    """Names of the registered harness adapters."""
    return list(ADAPTERS)


def get_adapter(name: str) -> HarnessAdapter:
    """Instantiate the adapter for *name* (``claude_code`` / ``claude-code`` / ``claude``)."""
    key = name.strip().lower().replace("-", "_")
    if key == "claude":
        key = "claude_code"
    try:
        factory = ADAPTERS[key]
    except KeyError as exc:
        raise KeyError(f"unknown harness {name!r}; known: {', '.join(ADAPTERS)}") from exc
    return factory()
