"""PyRIT target factory: ``aisdlc security campaign run … --target assistant.target:make_target``.

The factory wires a fresh assistant to a :class:`~aisdlc.security.targets.ToolEventRecorder`
so ``tool_call`` objectives can see which tools actually executed, and returns an
:class:`~aisdlc.security.targets.AppUnderTestTarget` the campaign runner drives directly.
"""

from __future__ import annotations

from typing import Any

from assistant.agent import build_assistant


def make_target() -> Any:
    """Build the application-under-test target for the red-team campaign."""
    from aisdlc.security.targets import AppUnderTestTarget, ToolEventRecorder

    recorder = ToolEventRecorder()
    assistant = build_assistant(recorder=recorder, session_id="pyrit-campaign")
    return AppUnderTestTarget(
        respond=assistant.respond, name="support-assistant", recorder=recorder
    )
