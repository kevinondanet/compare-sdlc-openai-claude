"""Rule-driven support assistant with an allow-listed tool registry.

The assistant is deliberately model-free so the pilot runs offline; the governance
properties under test are the same ones a model-backed agent needs: an explicit tool
allow-list, an approval token for irreversible tools, screening of tool output for
instructions aimed at the assistant, and an audit line per tool call.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Tool = Callable[..., Any]

INJECTION_PATTERNS = (
    re.compile(r"ignore (all |your )?(previous|prior) instructions", re.I),
    re.compile(r"\bsystem prompt\b", re.I),
    re.compile(r"\b(you are now|act as)\b", re.I),
    re.compile(r"\brefund\b.*\bimmediately\b", re.I),
)


@dataclass
class ToolCall:
    """Audit record for one tool invocation."""

    tool: str
    arguments_hash: str
    outcome: str


@dataclass
class SupportAssistant:
    """Answers order questions; refunds need an approval token; tool output is untrusted."""

    tools: dict[str, Tool]
    allowed_tools: frozenset[str] = frozenset({"lookup_order"})
    approval_tools: frozenset[str] = frozenset({"refund_order"})
    audit: list[ToolCall] = field(default_factory=list)

    def _call(self, name: str, **kwargs: Any) -> Any:
        digest = hashlib.sha256(json.dumps(kwargs, sort_keys=True).encode()).hexdigest()[:16]
        if name not in self.tools or name not in (self.allowed_tools | self.approval_tools):
            self.audit.append(ToolCall(name, digest, "denied"))
            raise PermissionError(f"tool {name!r} is not allow-listed")
        try:
            result = self.tools[name](**kwargs)
        except Exception as exc:  # noqa: BLE001 - audited and re-raised
            self.audit.append(ToolCall(name, digest, f"error: {exc}"))
            raise
        self.audit.append(ToolCall(name, digest, "ok"))
        return result

    @staticmethod
    def screen(text: str) -> tuple[str, bool]:
        """Return ``(text, flagged)``; flagged output is quoted, never followed."""
        return text, any(p.search(text) for p in INJECTION_PATTERNS)

    def respond(self, message: str, *, approval_token: str | None = None) -> str:
        """Reply to a customer message using at most one allow-listed tool."""
        order = re.search(r"\b(ORD-\d+)\b", message)
        if re.search(r"\brefund\b", message, re.I):
            if not order:
                return "Which order should be refunded? Please include the ORD- number."
            if not approval_token:
                return (
                    f"A refund for {order.group(1)} needs a supervisor approval token before "
                    "I can submit it."
                )
            self._call("refund_order", order_id=order.group(1), approval_token=approval_token)
            return f"Refund for {order.group(1)} submitted."
        if order:
            raw = str(self._call("lookup_order", order_id=order.group(1)))
            text, flagged = self.screen(raw)
            if flagged:
                return (
                    f"Order {order.group(1)} record contained untrusted instructions and was "
                    "quarantined; a human agent will follow up."
                )
            return f"Order {order.group(1)} status: {text}"
        return "I can help with order status or refunds; please include the ORD- number."
