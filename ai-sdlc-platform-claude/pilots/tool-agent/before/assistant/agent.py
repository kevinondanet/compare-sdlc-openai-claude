"""Rule-driven support assistant with governed tools (before input screening).

The assistant's instruction-following core sees user messages and tool results verbatim.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from assistant.governance import Governance
from assistant.tools import CustomerDirectory, Recorder, ToolBox

CUSTOMER_ID_RE = re.compile(r"\b(C-\d{3})\b", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
DELETE_RE = re.compile(r"\b(delete|remove|wipe|erase|drop|purge)\b", re.I)
EMAIL_INTENT_RE = re.compile(r"\b(e-?mail|send|forward|mail)\b", re.I)
LOOKUP_RE = re.compile(
    r"\b(look ?up|find|search|show|status|account|summary|balance|plan|who is|customer)\b", re.I
)
INSTRUCTION_RE = re.compile(
    r"\b(?:say|saying|output|respond(?:\s+only)?\s+with(?:\s+the\s+word)?|reply\s+with)"
    r"\s+[\"'“]?([A-Za-z0-9_-]{2,})",
    re.I,
)
_STOPWORDS = frozenset({"the", "a", "an", "your", "my", "that", "this", "it", "only", "so"})

HELP_TEXT = (
    "I can look up a customer by id (for example C-101), e-mail a customer their account "
    "summary at the address we have on file, or pass a deletion request to a human."
)
AUDIT_LOG_ENV = "ASSISTANT_AUDIT_LOG"


class SupportAssistant:
    """Answers support questions with three governed tools over private customer data."""

    def __init__(self, toolbox: ToolBox, governance: Governance) -> None:
        self.toolbox = toolbox
        self.governance = governance
        self.quarantined: list[str] = []

    # ------------------------------------------------------------------ entry point
    def respond(self, message: str) -> str:
        """Reply to one user message (always a string; never raises for policy reasons)."""
        context: list[str] = [message]
        ids = [m.upper() for m in CUSTOMER_ID_RE.findall(message)]
        if DELETE_RE.search(message):
            return self._delete(message, ids)
        if EMAIL_INTENT_RE.search(message) and EMAIL_RE.search(message):
            return self._email(message, ids)
        reply = self._lookup(message, ids, context) if ids or LOOKUP_RE.search(message) else None
        followed = self._follow(context)
        if followed is not None:
            return followed
        return reply or HELP_TEXT

    # ------------------------------------------------------------------ intents
    def _delete(self, message: str, ids: list[str]) -> str:
        target = (
            ids[0]
            if ids
            else (
                "everything" if re.search(r"\b(everything|all)\b", message, re.I) else "unspecified"
            )
        )
        decision = self.governance.check(
            "delete_record", {"customer_id": target}, resource=f"customers.json#{target}"
        )
        if decision.allowed:
            return self.toolbox.invoke("delete_record", customer_id=target)
        return (
            f"Deleting {target} is a tier-{int(decision.tier)} action that needs a human: "
            f"denied by policy ({decision.reason}). The request was logged."
        )

    def _email(self, message: str, ids: list[str]) -> str:
        match = EMAIL_RE.search(message)
        to = match.group(0) if match else ""
        customer_id = ids[0] if ids else ""
        record = self.toolbox.directory.get(customer_id) if customer_id else None
        body = self._summary(record) if record else "No customer was specified."
        params = {
            "to": to,
            "customer_id": customer_id,
            "subject": f"Account summary {customer_id}".strip(),
        }
        decision = self.governance.check("send_email", params, resource=f"mailto:{to}")
        if decision.allowed:
            self.toolbox.invoke("send_email", body=body, **params)
            return f"Sent the account summary of {customer_id} to {to}."
        return f"I can't send that: {decision.reason}. The request was logged."

    def _lookup(self, message: str, ids: list[str], context: list[str]) -> str | None:
        query = ids[0] if ids else ""
        if not query:
            match = EMAIL_RE.search(message)
            if match:
                query = match.group(0)
        if not query:
            named = re.search(r"\bcustomer\s+([A-Za-z][\w'-]+)", message, re.I)
            query = named.group(1) if named else ""
        if not query:
            return None
        decision = self.governance.check(
            "search_customers", {"query": query}, resource="customers.json"
        )
        if not decision.allowed:
            return f"I can't read the customer file right now: {decision.reason}."
        records = json.loads(self.toolbox.invoke("search_customers", query=query))
        if not records:
            return f"No customer matches {query!r}."
        lines = []
        for record in records:
            notes = str(record.get("notes") or "")
            if notes:
                context.append(notes)
            lines.append(f"{self._summary(record)} Notes: {notes or '(none)'}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _summary(record: dict[str, Any]) -> str:
        return (
            f"{record['id']} {record['name']} <{record['email']}>: plan {record['plan']}, "
            f"balance EUR {record['balance_eur']:.2f}."
        )

    @staticmethod
    def _follow(context: list[str]) -> str | None:
        """The model stand-in: obey an imperative 'say X' found anywhere in the context."""
        for text in context:
            for match in INSTRUCTION_RE.finditer(text):
                word = match.group(1)
                if word.lower() not in _STOPWORDS:
                    return word
        return None


def build_assistant(
    *,
    recorder: Recorder | None = None,
    audit_log: str | Path | None = None,
    session_id: str | None = None,
    data_file: Path | None = None,
) -> SupportAssistant:
    """Assemble an assistant over the private customer file.

    The audit log defaults to ``$ASSISTANT_AUDIT_LOG`` (in-memory when unset).
    """
    directory = CustomerDirectory.load(data_file) if data_file else CustomerDirectory.load()
    log = audit_log if audit_log is not None else (os.environ.get(AUDIT_LOG_ENV) or None)
    toolbox = ToolBox(directory, recorder=recorder)
    governance = Governance(directory, audit_log=log, session_id=session_id)
    return SupportAssistant(toolbox, governance)
