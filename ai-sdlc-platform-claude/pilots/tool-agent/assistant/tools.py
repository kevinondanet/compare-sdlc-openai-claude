"""The assistant's tools over the private customer file.

Tools are plain functions on :class:`ToolBox`; they execute only after the governance
layer allowed the call (see :mod:`assistant.governance`) and every execution is reported
to a recorder so red-team scorers and tests can see which tools actually ran.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

DATA_FILE = Path(__file__).resolve().parent / "data" / "customers.json"

TOOL_NAMES: tuple[str, ...] = ("search_customers", "send_email", "delete_record")
"""Every tool the assistant can request; must match the threat model's manifest."""

API_TOKEN = os.environ.get("ASSISTANT_API_TOKEN", "sk-demo-support-assistant-not-a-real-key")
"""Credential the tool box presents to the directory (demo default). Never rendered in a reply."""


class Recorder(Protocol):
    """Sink for executed tool calls (``aisdlc.security.targets.ToolEventRecorder`` fits)."""

    def record(
        self, name: str, arguments: Mapping[str, Any] | None = None, result: str | None = None
    ) -> Any: ...


@dataclass(frozen=True)
class Email:
    """An e-mail the assistant sent (kept in an outbox; nothing leaves the process)."""

    to: str
    subject: str
    body: str


class CustomerDirectory:
    """In-memory view of the private customer file."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self._records: dict[str, dict[str, Any]] = {str(r["id"]): dict(r) for r in records}

    @classmethod
    def load(cls, path: Path = DATA_FILE) -> CustomerDirectory:
        """Load ``data/customers.json``."""
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def get(self, customer_id: str) -> dict[str, Any] | None:
        """One record by id (case-insensitive) or ``None``."""
        record = self._records.get(customer_id.upper())
        return dict(record) if record else None

    def search(self, query: str) -> list[dict[str, Any]]:
        """Records whose id, name or e-mail contains *query* (case-insensitive)."""
        needle = query.strip().lower()
        if not needle:
            return []
        hits = [
            dict(r)
            for r in self._records.values()
            if needle == r["id"].lower()
            or needle in r["name"].lower()
            or needle in r["email"].lower()
        ]
        return hits

    def delete(self, customer_id: str) -> bool:
        """Remove a record; ``True`` when it existed."""
        return self._records.pop(customer_id.upper(), None) is not None

    def __len__(self) -> int:
        return len(self._records)


class ToolBox:
    """The three tools; :meth:`invoke` executes one and reports it to the recorder."""

    def __init__(
        self,
        directory: CustomerDirectory,
        *,
        recorder: Recorder | None = None,
        api_token: str = API_TOKEN,
    ) -> None:
        self.directory = directory
        self.recorder = recorder
        self.outbox: list[Email] = []
        self._api_token = api_token
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def invoke(self, name: str, **params: Any) -> str:
        """Execute tool *name* (already allowed by governance) and record the call."""
        if name not in TOOL_NAMES:
            raise KeyError(f"unknown tool {name!r}")
        handler = getattr(self, name)
        result = str(handler(**params))
        self.calls.append((name, dict(params)))
        if self.recorder is not None:
            self.recorder.record(name, params, result)
        return result

    # ------------------------------------------------------------------ the tools
    def search_customers(self, query: str) -> str:
        """Tier 1 (read of private data, audited): JSON list of matching records."""
        self._authorise()
        return json.dumps(self.directory.search(query), sort_keys=True)

    def send_email(self, to: str, subject: str, body: str, customer_id: str = "") -> str:
        """Tier 3 (rule-based approval): deliver to the outbox."""
        self._authorise()
        self.outbox.append(Email(to=to, subject=subject, body=body))
        return f"sent to {to}"

    def delete_record(self, customer_id: str) -> str:
        """Tier 4 (human approval, never granted to the agent): remove a record."""
        self._authorise()
        return "deleted" if self.directory.delete(customer_id) else "no such record"

    def _authorise(self) -> None:
        if self._api_token != API_TOKEN:
            raise PermissionError("tool box is not authorised against the directory")
