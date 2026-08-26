"""Tool/data manifest drift: declared :class:`ToolDataManifest` vs observed behaviour.

The threat model declares which tools an agent may call, which data sources it may read and
which network hosts it may reach.  Observed behaviour comes from the governance audit trail
(``evidence/audit.json`` or the AGT audit formats) or from explicit
:class:`ToolCallRecord` lists.  :func:`compare` produces a :class:`DriftReport`; ``drift`` is
``True`` whenever something undeclared was observed.  Declared-but-unused entries are
reported (over-broad manifests) and only count as drift with ``strict_unused=True``.

Declared entries are matched with :func:`fnmatch.fnmatchcase` (``mcp__github__*``,
``*.github.com``); data-source patterns ending in ``/`` also match by prefix.

Platform-internal actors
========================

The platform records its own governed actions in the same audit trail as the agent's
tool calls: the orchestrator governs every worktree write, verification run, git commit
and package apply-back it performs under the tool name ``aisdlc.orchestration`` (see
``Executor._govern``). Those calls are the platform's behaviour, not the agent's, so they
never belong in the threat model's manifest and are excluded from drift by the explicit
:data:`PLATFORM_TOOLS` allowlist. Matching is **exact** (case-sensitive) — a real tool
named ``aisdlc.orchestration.x`` or ``AISDLC.ORCHESTRATION`` is still reported. Every
call excluded this way is counted in :attr:`ObservedBehaviour.platform_tools` /
:attr:`DriftReport.platform_tools` so the exclusion is visible in the report. Callers
override the allowlist with ``platform_tools=`` (an empty iterable disables it).
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ThreatModel, ToolDataManifest

__all__ = [
    "PLATFORM_TOOLS",
    "DriftReport",
    "ObservedBehaviour",
    "ToolCallRecord",
    "audit_path_candidates",
    "check_drift",
    "compare",
    "drift_for_package",
    "audit_entries_source",
    "load_declared_manifest",
    "host_of",
    "is_platform_tool",
    "load_audit_entries",
    "matches_declared",
    "observe",
    "observe_audit",
    "record_from_audit_entry",
]

PLATFORM_TOOLS: Final[frozenset[str]] = frozenset({"aisdlc.orchestration"})
"""Tool names under which the platform itself records governed actions in the audit trail.

* ``aisdlc.orchestration`` — the executor (:meth:`aisdlc.orchestration.executor.Executor`
  ``_govern`` / ``_govern_verification``): worktree writes, verification and test runs,
  git commits and the tier-3 apply-back of task branches and evidence into the package.

Only names the platform actually writes belong here. The list is matched exactly
(:func:`is_platform_tool`); it is not a prefix or pattern, so it cannot hide an agent tool
that merely resembles a platform name.
"""


def is_platform_tool(tool_name: str, platform_tools: Iterable[str] | None = None) -> bool:
    """``True`` when *tool_name* is exactly one of the platform-internal actor names.

    *platform_tools* replaces :data:`PLATFORM_TOOLS` when given (pass an empty iterable to
    disable the exclusion altogether).
    """
    allowlist = PLATFORM_TOOLS if platform_tools is None else frozenset(platform_tools)
    return tool_name in allowlist


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolCallRecord(_Model):
    """One observed tool invocation (the minimal shape the drift check needs)."""

    tool_name: str
    resource: str | None = None
    egress_host: str | None = None
    data_sources: list[str] = Field(default_factory=list)
    agent_id: str | None = None
    timestamp: str | None = None
    allowed: bool = True


class ObservedBehaviour(_Model):
    """Aggregated observations (agent behaviour; platform-internal calls kept apart)."""

    tools: dict[str, int] = Field(default_factory=dict)
    egress_hosts: dict[str, int] = Field(default_factory=dict)
    data_sources: dict[str, int] = Field(default_factory=dict)
    records: int = Field(default=0, ge=0, description="Agent tool calls aggregated.")
    platform_tools: dict[str, int] = Field(
        default_factory=dict,
        description="Platform-internal calls (see PLATFORM_TOOLS) left out of the counts.",
    )


class DriftReport(_Model):
    """Result of comparing a declared manifest with observed behaviour."""

    undeclared_tools: list[str] = Field(default_factory=list)
    unused_declared: list[str] = Field(
        default_factory=list, description="Declared tools never used."
    )
    undeclared_egress_hosts: list[str] = Field(default_factory=list)
    unused_declared_egress: list[str] = Field(default_factory=list)
    undeclared_data_sources: list[str] = Field(default_factory=list)
    unused_declared_data_sources: list[str] = Field(default_factory=list)
    drift: bool = False
    observed_records: int = Field(default=0, ge=0, description="Agent tool calls compared.")
    platform_tools: dict[str, int] = Field(
        default_factory=dict,
        description="Platform-internal calls excluded from the comparison (name -> count).",
    )
    notes: list[str] = Field(default_factory=list)

    def summary_lines(self) -> list[str]:
        """Human-readable summary."""
        lines = [
            f"manifest drift: {'YES' if self.drift else 'no'} ({self.observed_records} records)"
        ]
        for label, items in (
            ("undeclared tools", self.undeclared_tools),
            ("undeclared egress hosts", self.undeclared_egress_hosts),
            ("undeclared data sources", self.undeclared_data_sources),
            ("declared but unused tools", self.unused_declared),
            ("declared but unused egress", self.unused_declared_egress),
            ("declared but unused data sources", self.unused_declared_data_sources),
        ):
            if items:
                lines.append(f"  {label}: {', '.join(items)}")
        if self.platform_tools:
            excluded = ", ".join(f"{name} ({n})" for name, n in self.platform_tools.items())
            lines.append(f"  platform-internal calls excluded: {excluded}")
        lines.extend(f"  note: {n}" for n in self.notes)
        return lines


# --------------------------------------------------------------------------------------
# Observation
# --------------------------------------------------------------------------------------

_URL_SCHEMES = ("http://", "https://", "ws://", "wss://", "ftp://", "ssh://", "git://")


def host_of(resource: str | None) -> str | None:
    """Host part of a URL-like *resource* (``None`` for paths and other strings)."""
    if not resource:
        return None
    text = resource.strip()
    lowered = text.lower()
    if lowered.startswith(_URL_SCHEMES):
        host = urlsplit(text).hostname
        return host.lower() if host else None
    if lowered.startswith("git@") and ":" in text:
        return text[4:].split(":", 1)[0].lower()
    return None


_TOOL_EVENTS = frozenset(
    {"tool_invocation", "tool_blocked", "tool_call", "tool.call", "pre_tool", "tool_use"}
)
_ALLOWED_OUTCOMES = frozenset({"allowed", "approved", "success", "allow", "ok"})


def record_from_audit_entry(entry: Mapping[str, Any]) -> ToolCallRecord | None:
    """Map an audit entry (platform, AGT Python or AGT Claude Code plugin format) to a record.

    Returns ``None`` for entries that are not tool calls (session events, screening hits,
    approvals) and for entries without a recognisable tool name.
    """
    raw_data = entry.get("data")
    data: Mapping[str, Any] = raw_data if isinstance(raw_data, Mapping) else {}
    event_type = str(entry.get("event_type", "")).lower()
    action = str(entry.get("action", ""))
    tool = data.get("tool_name") or entry.get("tool_name") or entry.get("tool")
    if not tool and action.startswith("tool."):
        tool = action[5:]
    if not tool:
        if event_type in _TOOL_EVENTS:
            tool = action
        else:
            return None
    if event_type and event_type not in _TOOL_EVENTS and not action.startswith("tool."):
        if "tool" not in event_type:
            return None
    outcome = str(entry.get("outcome", entry.get("decision", "allowed"))).lower()
    outcome = outcome.split(":", 1)[-1]  # shadow:allowed -> allowed
    allowed = outcome in _ALLOWED_OUTCOMES or outcome.endswith("allowed") or outcome == "warn"
    resource = entry.get("resource")
    resource_str = str(resource) if resource else None
    egress = data.get("egress_host") or entry.get("egress_host") or host_of(resource_str)
    sources: list[str] = []
    for key in ("data_sources", "data_source"):
        value = data.get(key, entry.get(key))
        if isinstance(value, str) and value:
            sources.append(value)
        elif isinstance(value, list):
            sources.extend(str(v) for v in value if v)
    agent = entry.get("agent_id") or entry.get("agentId") or entry.get("agent_did")
    return ToolCallRecord(
        tool_name=str(tool),
        resource=resource_str,
        egress_host=str(egress).lower() if egress else None,
        data_sources=sources,
        agent_id=str(agent) if agent else None,
        timestamp=str(entry.get("timestamp")) if entry.get("timestamp") else None,
        allowed=allowed,
    )


def load_audit_entries(
    source: str | Path | Mapping[str, Any] | Sequence[Any],
) -> list[dict[str, Any]]:
    """Load audit entries from a file or object.

    Accepts the platform ``evidence/audit.json`` export (``{"entries": [...]}``), a bare
    JSON list (AGT Claude Code plugin ring buffer), an AGT ``export()`` dict, or JSON lines
    (AGT ``FileAuditSink``).
    """
    if isinstance(source, Mapping):
        data: Any = source
    elif isinstance(source, str | Path):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        stripped = text.strip()
        if not stripped:
            return []
        if stripped.startswith("[") or stripped.startswith("{") and "\n{" not in stripped:
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON: {exc}") from exc
        else:
            data = []
            for number, line in enumerate(stripped.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{number}: invalid JSON line: {exc}") from exc
    else:
        data = list(source)
    if isinstance(data, Mapping):
        entries = data.get("entries", data.get("records", data.get("events")))
        if not isinstance(entries, list):
            raise ValueError("audit object has no 'entries' list")
        data = entries
    if not isinstance(data, list):
        raise ValueError("audit source must be a list of entries")
    return [dict(e) for e in data if isinstance(e, Mapping)]


def observe(
    records: Iterable[ToolCallRecord],
    *,
    include_denied: bool = False,
    platform_tools: Iterable[str] | None = None,
) -> ObservedBehaviour:
    """Aggregate *records* into :class:`ObservedBehaviour` (denied calls skipped by default).

    Records whose tool is a platform-internal actor (:data:`PLATFORM_TOOLS`, or the
    *platform_tools* override) are tallied in ``platform_tools`` and otherwise left out —
    their resources are the platform's, not the agent's.
    """
    allowlist = PLATFORM_TOOLS if platform_tools is None else frozenset(platform_tools)
    tools: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    internal: Counter[str] = Counter()
    count = 0
    for record in records:
        if not record.allowed and not include_denied:
            continue
        if is_platform_tool(record.tool_name, allowlist):
            internal[record.tool_name] += 1
            continue
        count += 1
        tools[record.tool_name] += 1
        if record.egress_host:
            hosts[record.egress_host] += 1
        for src in record.data_sources:
            sources[src] += 1
    return ObservedBehaviour(
        tools=dict(sorted(tools.items())),
        egress_hosts=dict(sorted(hosts.items())),
        data_sources=dict(sorted(sources.items())),
        records=count,
        platform_tools=dict(sorted(internal.items())),
    )


def observe_audit(
    source: str | Path | Mapping[str, Any] | Sequence[Any],
    *,
    include_denied: bool = False,
    platform_tools: Iterable[str] | None = None,
) -> ObservedBehaviour:
    """Load audit entries from *source* and aggregate the tool calls they describe."""
    entries = load_audit_entries(source)
    records = [r for r in (record_from_audit_entry(e) for e in entries) if r is not None]
    return observe(records, include_denied=include_denied, platform_tools=platform_tools)


# --------------------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------------------


def matches_declared(declared: Iterable[str], value: str) -> str | None:
    """The first declared pattern matching *value* (``fnmatch``; ``/``-suffixed prefixes)."""
    for pattern in declared:
        if fnmatchcase(value, pattern) or fnmatchcase(value.lower(), pattern.lower()):
            return pattern
        if pattern.endswith("/") and value.startswith(pattern):
            return pattern
    return None


def compare(
    manifest: ToolDataManifest,
    observed: ObservedBehaviour,
    *,
    strict_unused: bool = False,
    platform_tools: Iterable[str] | None = None,
) -> DriftReport:
    """Compare a declared manifest with observed behaviour.

    Platform-internal tools (:data:`PLATFORM_TOOLS` or the *platform_tools* override) still
    present in ``observed.tools`` — an :class:`ObservedBehaviour` built by hand — are moved
    to the report's ``platform_tools`` instead of being reported as undeclared.
    """
    allowlist = PLATFORM_TOOLS if platform_tools is None else frozenset(platform_tools)
    internal: Counter[str] = Counter(observed.platform_tools)
    used_tools: set[str] = set()
    undeclared_tools: list[str] = []
    agent_calls = observed.records
    for tool, calls in observed.tools.items():
        if is_platform_tool(tool, allowlist):
            internal[tool] += calls
            agent_calls = max(0, agent_calls - calls)
            continue
        hit = matches_declared(manifest.tools, tool)
        if hit is None:
            undeclared_tools.append(tool)
        else:
            used_tools.add(hit)
    used_hosts: set[str] = set()
    undeclared_hosts: list[str] = []
    for host in observed.egress_hosts:
        hit = matches_declared(manifest.network_egress, host)
        if hit is None:
            undeclared_hosts.append(host)
        else:
            used_hosts.add(hit)
    used_sources: set[str] = set()
    undeclared_sources: list[str] = []
    for src in observed.data_sources:
        hit = matches_declared(manifest.data_sources, src)
        if hit is None:
            undeclared_sources.append(src)
        else:
            used_sources.add(hit)
    unused_tools = [t for t in manifest.tools if t not in used_tools]
    unused_hosts = [h for h in manifest.network_egress if h not in used_hosts]
    unused_sources = [s for s in manifest.data_sources if s not in used_sources]
    drift = bool(undeclared_tools or undeclared_hosts or undeclared_sources)
    notes: list[str] = []
    if agent_calls == 0:
        excluded = sum(internal.values())
        suffix = f" ({excluded} platform-internal call(s) excluded)" if excluded else ""
        notes.append(f"no tool calls observed{suffix}; unused-declared lists are not meaningful")
    if strict_unused and (unused_tools or unused_hosts or unused_sources):
        drift = True
        notes.append("strict mode: declared-but-unused entries count as drift")
    return DriftReport(
        undeclared_tools=sorted(undeclared_tools),
        unused_declared=unused_tools,
        undeclared_egress_hosts=sorted(undeclared_hosts),
        unused_declared_egress=unused_hosts,
        undeclared_data_sources=sorted(undeclared_sources),
        unused_declared_data_sources=unused_sources,
        drift=drift,
        observed_records=agent_calls,
        platform_tools=dict(sorted(internal.items())),
        notes=notes,
    )


def check_drift(
    declared: ToolDataManifest | ThreatModel,
    audit: str | Path | Mapping[str, Any] | Sequence[Any] | Iterable[ToolCallRecord],
    *,
    include_denied: bool = False,
    strict_unused: bool = False,
    platform_tools: Iterable[str] | None = None,
) -> DriftReport:
    """One-shot: observe *audit* (entries or :class:`ToolCallRecord` list) and compare."""
    manifest = declared.tool_data_manifest if isinstance(declared, ThreatModel) else declared
    if isinstance(audit, str | Path | Mapping):
        observed = observe_audit(
            audit, include_denied=include_denied, platform_tools=platform_tools
        )
    else:
        items: list[Any] = list(audit)
        records = [item for item in items if isinstance(item, ToolCallRecord)]
        if items and len(records) == len(items):
            observed = observe(
                records, include_denied=include_denied, platform_tools=platform_tools
            )
        else:
            observed = observe_audit(
                items, include_denied=include_denied, platform_tools=platform_tools
            )
    return compare(manifest, observed, strict_unused=strict_unused, platform_tools=platform_tools)


def load_declared_manifest(package_dir: str | Path) -> ToolDataManifest:
    """The manifest declared in ``architecture/threat-model.md`` (empty when absent)."""
    from aisdlc.schema.markdown import threat_model_from_markdown

    path = Path(package_dir) / pkgio.THREAT_MODEL_FILE
    if not path.is_file():
        return ToolDataManifest()
    model, _body = threat_model_from_markdown(path.read_text(encoding="utf-8"))
    return model.tool_data_manifest


def drift_for_package(
    package_dir: str | Path,
    *,
    strict_unused: bool = False,
    platform_tools: Iterable[str] | None = None,
) -> DriftReport:
    """Drift for a change package: threat-model manifest vs ``evidence/audit.json``.

    Only the threat model and the audit file are read (never the whole evidence bundle), so
    the check works on packages whose other evidence is still being produced.  A package
    without a threat model yields an empty manifest (every observed tool is undeclared); a
    missing audit file yields zero observations with an explanatory note.
    """
    root = Path(package_dir)
    manifest = load_declared_manifest(root)
    source = audit_entries_source(root)
    if source is None:
        report = compare(
            manifest,
            ObservedBehaviour(),
            strict_unused=strict_unused,
            platform_tools=platform_tools,
        )
        report.notes.append(
            f"audit entries not found ({pkgio.audit_entries_path(root)} or "
            f"{pkgio.evidence_path(root, 'audit')})"
        )
        return report
    return compare(
        manifest,
        observe_audit(source, platform_tools=platform_tools),
        strict_unused=strict_unused,
        platform_tools=platform_tools,
    )


def audit_path_candidates(target: str | Path, package_dir: str | Path) -> list[Path]:
    """Where a path recorded in audit evidence may live, in resolution order.

    An absolute path stands alone. A relative path is the one the producer typed on the
    command line (``aisdlc run change --audit-log .aisdlc/audit.jsonl``,
    ``aisdlc governance audit export .aisdlc/audit.jsonl``), so it resolves against the
    current working directory first and then against the repository root that holds the
    package (the parent of ``changes/``) — never against the evidence directory the
    record happens to sit in.
    """
    path = Path(target)
    if path.is_absolute():
        return [path]
    candidates = [Path.cwd() / path]
    resolved = Path(package_dir).resolve()
    if resolved.parent.name == pkgio.CHANGES_DIR:
        from_root = resolved.parent.parent / path
        if from_root not in candidates:
            candidates.append(from_root)
    return candidates


def audit_entries_source(package_dir: str | Path) -> Path | None:
    """Where a package's per-call audit entries live, or ``None``.

    Prefers ``evidence/audit-entries.json`` (written by
    :func:`aisdlc.governance.audit.record_audit_evidence`); otherwise ``evidence/audit.json``
    when it still carries an entries list (older exports), or the file its canonical
    ``report_uri`` points at (the sidecar or the signed JSON-lines log; relative paths
    resolve per :func:`audit_path_candidates`).
    """
    root = Path(package_dir)
    sidecar = pkgio.audit_entries_path(root)
    if sidecar.is_file():
        return sidecar
    audit_path = pkgio.evidence_path(root, "audit")
    if not audit_path.is_file():
        return None
    try:
        data = json.loads(audit_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return audit_path
    if isinstance(data, Mapping):
        if isinstance(data.get("entries"), list):
            return audit_path
        uri = data.get("report_uri")
        if isinstance(uri, str) and uri and "://" not in uri:
            return next((c for c in audit_path_candidates(uri, root) if c.is_file()), None)
        return None
    return audit_path
