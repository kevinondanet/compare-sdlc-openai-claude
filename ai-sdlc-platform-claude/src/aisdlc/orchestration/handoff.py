"""Durable file-based handoffs: ``changes/<id>/handoffs/<seq>-<step>.json``.

Every orchestration step (plan approval, routing, implementation, verification, review,
fix, apply-back, checkpoints, post-merge verification, final review) writes one JSON
handoff. Handoffs are the
only state the executor needs to resume: :meth:`HandoffStore.completed_tasks` tells it
which tasks already finished. Files are written through
:func:`aisdlc.schema.package.write_handoff` so they follow the package conventions.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aisdlc.schema import package as pkgio

__all__ = [
    "HandoffStep",
    "HandoffStatus",
    "Handoff",
    "HandoffStore",
    "inputs_hash",
    "handoff_name",
    "load_handoffs",
    "summarize_handoffs",
]

_NAME_RE = re.compile(r"^(?P<seq>\d{4,})-(?P<step>[a-z][a-z0-9_]*)$")


class HandoffStep(StrEnum):
    """Orchestration steps that produce a handoff."""

    RUN_START = "run_start"
    PLAN_APPROVAL = "plan_approval"
    ROUTE = "route"
    BRIEF = "brief"
    IMPLEMENT = "implement"
    VERIFY = "verify"
    REVIEW = "review"
    FIX = "fix"
    APPLY_BACK = "apply_back"
    TASK_DONE = "task_done"
    TASK_FAILED = "task_failed"
    WAVE = "wave"
    CHECKPOINT = "checkpoint"
    MERGED_VERIFY = "merged_verify"
    FINAL_REVIEW = "final_review"
    RELEASE = "release"
    RUN_END = "run_end"


class HandoffStatus(StrEnum):
    """Outcome recorded in a handoff."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    DENIED = "denied"
    APPROVED = "approved"
    PENDING = "pending"


class Handoff(BaseModel):
    """One durable handoff record."""

    model_config = ConfigDict(extra="forbid")

    seq: int = Field(ge=1)
    step: HandoffStep
    task_id: str | None = None
    status: HandoffStatus = HandoffStatus.SUCCESS
    inputs_hash: str = ""
    outputs: dict[str, Any] = Field(default_factory=dict)
    usage: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    wave: int | None = None
    round: int | None = None
    notes: str = ""

    @property
    def name(self) -> str:
        """File stem ``<seq>-<step>``."""
        return handoff_name(self.seq, self.step)

    def line(self) -> str:
        """One-line human-readable rendering."""
        parts = [f"{self.seq:04d}", f"{self.step.value:<13}", f"{self.status.value:<9}"]
        if self.task_id:
            parts.append(self.task_id)
        if self.round is not None:
            parts.append(f"r{self.round}")
        if self.notes:
            parts.append(self.notes)
        return " ".join(parts)


def handoff_name(seq: int, step: HandoffStep | str) -> str:
    """``<seq>-<step>`` file stem."""
    return f"{seq:04d}-{HandoffStep(step).value}"


def inputs_hash(*parts: Any) -> str:
    """Deterministic SHA-256 over JSON-serialised ``parts``."""
    text = json.dumps(list(parts), sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_handoffs(directory: str | Path) -> list[Handoff]:
    """Read every valid handoff in ``<dir>/handoffs`` in sequence order."""
    out: list[Handoff] = []
    for path in pkgio.list_handoffs(directory):
        if not _NAME_RE.match(path.stem):
            continue
        try:
            data = pkgio.read_json(path)
            out.append(Handoff.model_validate(data))
        except (pkgio.PackageError, ValidationError, ValueError, OSError):
            continue
    out.sort(key=lambda h: h.seq)
    return out


def summarize_handoffs(handoffs: Iterable[Handoff]) -> str:
    """Human-readable multi-line summary."""
    rows = [h.line() for h in handoffs]
    if not rows:
        return "no handoffs"
    return "\n".join(rows)


class HandoffStore:
    """Thread-safe writer/reader over a package's ``handoffs/`` directory."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self._lock = threading.Lock()
        self._seq = max((h.seq for h in load_handoffs(self.directory)), default=0)

    @property
    def next_seq(self) -> int:
        """The sequence number the next write will use."""
        return self._seq + 1

    def write(
        self,
        step: HandoffStep | str,
        *,
        task_id: str | None = None,
        status: HandoffStatus | str = HandoffStatus.SUCCESS,
        inputs: str = "",
        outputs: dict[str, Any] | None = None,
        usage: dict[str, Any] | None = None,
        wave: int | None = None,
        round: int | None = None,
        notes: str = "",
    ) -> Handoff:
        """Append a handoff and return it."""
        with self._lock:
            self._seq += 1
            handoff = Handoff(
                seq=self._seq,
                step=HandoffStep(step),
                task_id=task_id,
                status=HandoffStatus(status),
                inputs_hash=inputs,
                outputs=dict(outputs or {}),
                usage=dict(usage or {}),
                wave=wave,
                round=round,
                notes=notes,
            )
            pkgio.write_handoff(self.directory, handoff.name, handoff)
            return handoff

    def load(self) -> list[Handoff]:
        """All handoffs on disk, in order."""
        return load_handoffs(self.directory)

    def for_task(self, task_id: str) -> list[Handoff]:
        """Handoffs for one task."""
        return [h for h in self.load() if h.task_id == task_id]

    def latest(self, step: HandoffStep | str, task_id: str | None = None) -> Handoff | None:
        """Most recent handoff of ``step`` (optionally for ``task_id``)."""
        wanted = HandoffStep(step)
        for handoff in reversed(self.load()):
            if handoff.step is wanted and (task_id is None or handoff.task_id == task_id):
                return handoff
        return None

    def completed_tasks(self) -> set[str]:
        """Task ids with a successful ``task_done`` handoff."""
        return {
            h.task_id
            for h in self.load()
            if h.step is HandoffStep.TASK_DONE
            and h.status is HandoffStatus.SUCCESS
            and h.task_id is not None
        }

    def failed_tasks(self) -> set[str]:
        """Task ids whose last terminal handoff is ``task_failed``."""
        last: dict[str, HandoffStep] = {}
        for h in self.load():
            if h.task_id and h.step in {HandoffStep.TASK_DONE, HandoffStep.TASK_FAILED}:
                last[h.task_id] = h.step
        return {tid for tid, step in last.items() if step is HandoffStep.TASK_FAILED}

    def plan_approved(self) -> Handoff | None:
        """The approving plan-approval handoff, if any."""
        for h in reversed(self.load()):
            if h.step is HandoffStep.PLAN_APPROVAL and h.status in {
                HandoffStatus.APPROVED,
                HandoffStatus.SUCCESS,
            }:
                return h
        return None

    def summary(self) -> str:
        """Human-readable summary of every handoff."""
        return summarize_handoffs(self.load())
