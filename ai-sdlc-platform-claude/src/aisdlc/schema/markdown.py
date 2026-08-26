"""Markdown <-> model round trip for the human-editable change package files.

Each file is a YAML front-matter block between ``---`` lines followed by a prose body. The
front-matter carries the structured data; the body is preserved byte-for-byte.
"""

from __future__ import annotations

from typing import Any, TypeVar

import yaml
from pydantic import BaseModel

from aisdlc.schema.models import (
    ArchitectureDecision,
    Assumption,
    Intent,
    Interface,
    OpenQuestion,
    Plan,
    Requirement,
    Scenario,
    Task,
    ThreatModel,
)

__all__ = [
    "FrontMatterError",
    "split_front_matter",
    "join_front_matter",
    "render_model",
    "parse_model",
    "model_to_data",
    "intent_to_markdown",
    "intent_from_markdown",
    "requirements_to_markdown",
    "requirements_from_markdown",
    "assumptions_to_markdown",
    "assumptions_from_markdown",
    "plan_to_markdown",
    "plan_from_markdown",
    "tasks_to_markdown",
    "tasks_from_markdown",
    "threat_model_to_markdown",
    "threat_model_from_markdown",
    "adr_to_markdown",
    "adr_from_markdown",
    "interface_to_markdown",
    "interface_from_markdown",
    "scenarios_to_markdown",
    "scenarios_from_markdown",
]

_DELIM = "---"
_M = TypeVar("_M", bound=BaseModel)


class FrontMatterError(ValueError):
    """Raised when a markdown file has no parseable YAML front-matter."""


def split_front_matter(text: str) -> tuple[dict[str, Any] | None, str]:
    """Split *text* into ``(front_matter, body)``.

    Returns ``(None, text)`` when the text does not start with a ``---`` line. The body is
    everything after the closing ``---`` line, returned verbatim.
    """
    if not text.startswith((_DELIM + "\n", _DELIM + "\r\n")) and text.strip() != _DELIM:
        return None, text
    lines = text.split("\n")
    # lines[0] == "---"
    for index in range(1, len(lines)):
        if lines[index].rstrip("\r") == _DELIM:
            yaml_text = "\n".join(lines[1:index])
            body = "\n".join(lines[index + 1 :])
            try:
                data = yaml.safe_load(yaml_text) if yaml_text.strip() else {}
            except yaml.YAMLError as exc:
                raise FrontMatterError(f"invalid YAML front-matter: {exc}") from exc
            if data is None:
                data = {}
            if not isinstance(data, dict):
                raise FrontMatterError("front-matter must be a YAML mapping")
            return data, body
    raise FrontMatterError("front-matter opened with '---' but never closed")


def join_front_matter(data: dict[str, Any], body: str) -> str:
    """Render *data* as YAML front-matter followed by *body* (verbatim)."""
    dumped = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False)
    if not dumped.endswith("\n"):
        dumped += "\n"
    return f"{_DELIM}\n{dumped}{_DELIM}\n{body}"


def model_to_data(model: BaseModel) -> dict[str, Any]:
    """JSON-mode dump of a model without ``None`` values (defaults stay explicit)."""
    return model.model_dump(mode="json", exclude_none=True)


def render_model(model: BaseModel, body: str = "") -> str:
    """Render a model as front-matter with *body*."""
    return join_front_matter(model_to_data(model), body)


def parse_model(text: str, model_type: type[_M]) -> tuple[_M, str]:
    """Parse front-matter into *model_type*; returns ``(model, body)``."""
    data, body = split_front_matter(text)
    if data is None:
        raise FrontMatterError(f"missing front-matter for {model_type.__name__}")
    return model_type.model_validate(data), body


def _list_data(items: list[BaseModel]) -> list[dict[str, Any]]:
    return [model_to_data(item) for item in items]


def _parse_list(data: dict[str, Any], key: str, model_type: type[_M]) -> list[_M]:
    raw = data.get(key) or []
    if not isinstance(raw, list):
        raise FrontMatterError(f"front-matter key {key!r} must be a list")
    return [model_type.model_validate(item) for item in raw]


# -- intent.md --------------------------------------------------------------------------


def intent_to_markdown(intent: Intent, body: str = "") -> str:
    """Render ``intent.md``."""
    return render_model(intent, body)


def intent_from_markdown(text: str) -> tuple[Intent, str]:
    """Parse ``intent.md``."""
    return parse_model(text, Intent)


# -- requirements.md --------------------------------------------------------------------


def requirements_to_markdown(requirements: list[Requirement], body: str = "") -> str:
    """Render ``requirements.md`` (front-matter key ``requirements``)."""
    return join_front_matter({"requirements": _list_data(list(requirements))}, body)


def requirements_from_markdown(text: str) -> tuple[list[Requirement], str]:
    """Parse ``requirements.md``."""
    data, body = split_front_matter(text)
    if data is None:
        raise FrontMatterError("missing front-matter in requirements.md")
    return _parse_list(data, "requirements", Requirement), body


# -- assumptions.md ---------------------------------------------------------------------


def assumptions_to_markdown(
    assumptions: list[Assumption], open_questions: list[OpenQuestion], body: str = ""
) -> str:
    """Render ``assumptions.md`` (keys ``assumptions`` and ``open_questions``)."""
    return join_front_matter(
        {
            "assumptions": _list_data(list(assumptions)),
            "open_questions": _list_data(list(open_questions)),
        },
        body,
    )


def assumptions_from_markdown(text: str) -> tuple[list[Assumption], list[OpenQuestion], str]:
    """Parse ``assumptions.md``."""
    data, body = split_front_matter(text)
    if data is None:
        raise FrontMatterError("missing front-matter in assumptions.md")
    return (
        _parse_list(data, "assumptions", Assumption),
        _parse_list(data, "open_questions", OpenQuestion),
        body,
    )


# -- plan.md ----------------------------------------------------------------------------


def plan_to_markdown(plan: Plan, body: str = "") -> str:
    """Render ``plan.md``."""
    return render_model(plan, body)


def plan_from_markdown(text: str) -> tuple[Plan, str]:
    """Parse ``plan.md``."""
    return parse_model(text, Plan)


# -- tasks.md ---------------------------------------------------------------------------


def tasks_to_markdown(tasks: list[Task], body: str = "") -> str:
    """Render ``tasks.md`` (key ``tasks``)."""
    return join_front_matter({"tasks": _list_data(list(tasks))}, body)


def tasks_from_markdown(text: str) -> tuple[list[Task], str]:
    """Parse ``tasks.md``."""
    data, body = split_front_matter(text)
    if data is None:
        raise FrontMatterError("missing front-matter in tasks.md")
    return _parse_list(data, "tasks", Task), body


# -- architecture/threat-model.md -------------------------------------------------------


def threat_model_to_markdown(threat_model: ThreatModel, body: str = "") -> str:
    """Render ``architecture/threat-model.md``."""
    return render_model(threat_model, body)


def threat_model_from_markdown(text: str) -> tuple[ThreatModel, str]:
    """Parse ``architecture/threat-model.md``."""
    return parse_model(text, ThreatModel)


# -- architecture/decisions/ADR-nnnn.md -------------------------------------------------


def adr_to_markdown(adr: ArchitectureDecision, body: str = "") -> str:
    """Render an ADR file."""
    return render_model(adr, body)


def adr_from_markdown(text: str) -> tuple[ArchitectureDecision, str]:
    """Parse an ADR file."""
    return parse_model(text, ArchitectureDecision)


# -- architecture/interfaces/IFC-nnn.md -------------------------------------------------


def interface_to_markdown(interface: Interface, body: str = "") -> str:
    """Render an interface file."""
    return render_model(interface, body)


def interface_from_markdown(text: str) -> tuple[Interface, str]:
    """Parse an interface file."""
    return parse_model(text, Interface)


# -- scenarios/REQ-nnn.md ---------------------------------------------------------------


def scenarios_to_markdown(requirement_id: str, scenarios: list[Scenario], body: str = "") -> str:
    """Render an optional per-requirement scenario file."""
    return join_front_matter(
        {"requirement_id": requirement_id, "scenarios": _list_data(list(scenarios))}, body
    )


def scenarios_from_markdown(text: str) -> tuple[str, list[Scenario], str]:
    """Parse a per-requirement scenario file -> ``(requirement_id, scenarios, body)``."""
    data, body = split_front_matter(text)
    if data is None:
        raise FrontMatterError("missing front-matter in scenario file")
    requirement_id = data.get("requirement_id")
    if not isinstance(requirement_id, str):
        raise FrontMatterError("scenario file needs a 'requirement_id'")
    return requirement_id, _parse_list(data, "scenarios", Scenario), body
