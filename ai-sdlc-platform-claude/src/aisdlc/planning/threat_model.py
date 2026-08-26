"""Threat model artifact: initialisation from the change, validation, G1 input.

:func:`init_threat_model` seeds ``architecture/threat-model.md`` deterministically from
the intent, requirements, project configuration, interfaces and the declared
:class:`~aisdlc.schema.models.ToolDataManifest`:

* **assets** — data classes found in the text (credentials, sessions, payment data,
  PII, secrets), every declared tool/data source/egress host, critical modules and
  interfaces;
* **actors** — end user, maintainer, external attacker; plus implementer/reviewer
  agents, third-party services and untrusted content authors for agentic changes;
* **threat seeds** — STRIDE-style per interface kind, prompt-injection and
  privilege-escalation per declared tool, exfiltration per egress host, disclosure per
  data source, supply chain for code changes, and keyword-driven seeds (credential
  theft, secret leakage, transaction tampering, PII exposure, irreversible data loss).

Seeds are ``open``; tools of tier >= 3 get an *approval* mitigation and every tool gets
a result-screening mitigation, both ``verified=False``. Open high/critical threats are
what :func:`unresolved_high_risk` returns and what blocks G1 — the model fails closed
until a human mitigates or accepts each one.

Tool tiers are estimated from the tool name with :func:`tool_tier` (keyword table
mirroring ``aisdlc.governance.tiers``); unknown names are tier 3 (fail closed). Callers
with better knowledge pass ``tool_tiers``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from pydantic import Field

from aisdlc import ids
from aisdlc.planning import risk as riskmod
from aisdlc.policy.project_config import RISK_ORDER, ProjectConfig
from aisdlc.schema.grammar import IssueSeverity, ValidationIssue
from aisdlc.schema.models import (
    ArtifactModel,
    Intent,
    Interface,
    InterfaceKind,
    Mitigation,
    Requirement,
    RiskClass,
    Severity,
    Threat,
    ThreatCategory,
    ThreatModel,
    ThreatStatus,
    ToolDataManifest,
)

__all__ = [
    "TOOL_TIER_KEYWORDS",
    "UNKNOWN_TOOL_TIER",
    "NETWORK_TOOL_KEYWORDS",
    "ThreatModelReport",
    "tool_tier",
    "is_enumerated_host",
    "tool_asset",
    "threats_for_tool",
    "init_threat_model",
    "validate_threat_model",
    "unresolved_high_risk",
    "check_threat_model",
]

TOOL_TIER_KEYWORDS: Final[dict[int, tuple[str, ...]]] = {
    4: (
        "deploy",
        "secret",
        "secrets",
        "iam",
        "rotate",
        "delete",
        "drop",
        "destroy",
        "terminate",
        "force",
        "prod",
        "production",
        "payment",
        "pay",
        "transfer",
    ),
    3: (
        "push",
        "pr",
        "pull_request",
        "merge",
        "issue",
        "backlog",
        "jira",
        "install",
        "publish",
        "email",
        "mail",
        "send",
        "slack",
        "post",
        "upload",
        "update",
        "shared",
        "db_write",
        "write_db",
        "sql",
    ),
    2: (
        "run",
        "exec",
        "execute",
        "shell",
        "bash",
        "test",
        "tests",
        "build",
        "http",
        "https",
        "fetch",
        "web",
        "browse",
        "browser",
        "curl",
        "request",
        "api",
        "download",
        "query",
    ),
    1: ("write", "edit", "create", "move", "rename", "patch"),
    0: ("read", "search", "grep", "list", "glob", "explain", "get", "view", "lookup", "inspect"),
}
"""Tool-name tokens per tier; the highest matching tier wins."""

UNKNOWN_TOOL_TIER: Final[int] = 3
"""Tier assumed for tools whose name matches no keyword (fail closed: approval)."""

NETWORK_TOOL_KEYWORDS: Final[tuple[str, ...]] = (
    "http",
    "https",
    "fetch",
    "web",
    "browse",
    "browser",
    "curl",
    "request",
    "api",
    "download",
    "upload",
    "email",
    "mail",
    "slack",
    "search",
)
"""Tool-name tokens that imply network egress."""

_HOST_RE = re.compile(
    r"^(?:https?://)?(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,63})"
    r"(?::\d{1,5})?(?:/[^\s]*)?$",
    re.IGNORECASE,
)
_WORD_RE = re.compile(r"[a-z0-9]+")


class ThreatModelReport(ArtifactModel):
    """Outcome of :func:`check_threat_model` (G1 input)."""

    passed: bool
    issues: list[ValidationIssue] = Field(default_factory=list)
    unresolved_high_risk: list[str] = Field(
        default_factory=list, description="Ids of open high/critical threats."
    )

    @property
    def errors(self) -> list[ValidationIssue]:
        """Error-severity issues."""
        return [i for i in self.issues if i.severity is IssueSeverity.ERROR]


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _tokens(name: str) -> list[str]:
    """Lower-case word tokens of a tool name plus adjacent bigrams (``pull_request``)."""
    words = _WORD_RE.findall(name.lower().replace("-", "_"))
    bigrams = [f"{a}_{b}" for a, b in zip(words, words[1:], strict=False)]
    return [*words, *bigrams]


def tool_tier(name: str, overrides: Mapping[str, int] | None = None) -> int:
    """Estimated risk tier (0..4) of a tool from its name; *overrides* win."""
    if overrides is not None and name in overrides:
        return max(0, min(4, int(overrides[name])))
    tokens = set(_tokens(name))
    for tier in (4, 3, 2, 1, 0):
        if any(k in tokens for k in TOOL_TIER_KEYWORDS[tier]):
            return tier
    return UNKNOWN_TOOL_TIER


def is_network_tool(name: str) -> bool:
    """``True`` when the tool name suggests network access."""
    tokens = set(_tokens(name))
    return any(k in tokens for k in NETWORK_TOOL_KEYWORDS)


def is_enumerated_host(entry: str) -> bool:
    """``True`` when *entry* names one concrete host (no wildcards/CIDR/"any")."""
    text = entry.strip()
    lowered = text.lower()
    if not text or "*" in text or lowered in ("any", "all", "0.0.0.0", "::", "internet"):
        return False
    if re.search(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$", lowered):  # CIDR range
        return False
    return _HOST_RE.match(text) is not None


def tool_asset(tool: str) -> str:
    """Asset label used for a declared tool (``tool:<name>``)."""
    return f"tool:{tool}"


def _mentions(threat: Threat, name: str) -> bool:
    label = tool_asset(name)
    if label in threat.assets or name in threat.assets:
        return True
    pattern = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", re.IGNORECASE)
    return bool(pattern.search(threat.title) or pattern.search(threat.description))


def threats_for_tool(model: ThreatModel, tool: str) -> list[Threat]:
    """Threats that reference *tool* (asset label or name in title/description)."""
    return [t for t in model.threats if _mentions(t, tool)]


def unresolved_high_risk(model: ThreatModel | None) -> list[Threat]:
    """Open threats of high/critical severity (drives G1); empty for a missing model."""
    return [] if model is None else model.unresolved_high_risk()


# --------------------------------------------------------------------------------------
# Initialisation
# --------------------------------------------------------------------------------------


class _Seeder:
    """Accumulates threats/mitigations with fresh ids, skipping duplicate titles."""

    def __init__(self, existing: ThreatModel | None) -> None:
        self.threats: list[Threat] = list(existing.threats) if existing else []
        self.mitigations: list[Mitigation] = list(existing.mitigations) if existing else []
        self._titles = {t.title for t in self.threats}
        self._mitigation_texts = {m.description for m in self.mitigations}

    def threat(
        self,
        title: str,
        *,
        category: ThreatCategory,
        severity: Severity,
        description: str,
        assets: Sequence[str] = (),
        mitigation: str | None = None,
    ) -> Threat | None:
        if title in self._titles:
            return None
        threat = Threat(
            id=ids.next_id("THR", [t.id for t in self.threats]),
            title=title,
            description=description,
            category=category,
            severity=severity,
            assets=list(assets),
        )
        self.threats.append(threat)
        self._titles.add(title)
        if mitigation is not None:
            self.mitigate(threat, mitigation)
        return threat

    def mitigate(self, threat: Threat, description: str) -> Mitigation:
        existing = next((m for m in self.mitigations if m.description == description), None)
        if existing is not None:
            if threat.id not in existing.threat_ids:
                existing.threat_ids.append(threat.id)
            if existing.id not in threat.mitigation_ids:
                threat.mitigation_ids.append(existing.id)
            return existing
        number = len(self.mitigations) + 1
        mitigation = Mitigation(
            id=f"MIT-{number:03d}", description=description, threat_ids=[threat.id]
        )
        while any(m.id == mitigation.id for m in self.mitigations):
            number += 1
            mitigation = Mitigation(
                id=f"MIT-{number:03d}", description=description, threat_ids=[threat.id]
            )
        self.mitigations.append(mitigation)
        self._mitigation_texts.add(description)
        threat.mitigation_ids.append(mitigation.id)
        return mitigation


_KEYWORD_SEEDS: Final[
    tuple[tuple[tuple[str, ...], str, ThreatCategory, Severity, str, str], ...]
] = (
    (
        ("auth", "authentication", "login", "log in", "password", "mfa", "sso", "oauth", "session"),
        "Credential theft or session hijack",
        ThreatCategory.SPOOFING,
        Severity.HIGH,
        "An attacker obtains or forges credentials/sessions to act as another user.",
        "credentials",
    ),
    (
        ("secret", "secrets", "credential", "credentials", "private key", "api key", "kms"),
        "Secret leakage",
        ThreatCategory.INFORMATION_DISCLOSURE,
        Severity.CRITICAL,
        "Secrets or keys are exposed through logs, prompts, tool output or source control.",
        "secrets",
    ),
    (
        ("payment", "payments", "billing", "checkout", "credit card"),
        "Transaction tampering",
        ThreatCategory.TAMPERING,
        Severity.CRITICAL,
        "Amounts, recipients or order state are altered in flight or at rest.",
        "payment data",
    ),
    (
        ("pii", "personal data", "personally identifiable", "gdpr", "privacy"),
        "PII exposure",
        ThreatCategory.INFORMATION_DISCLOSURE,
        Severity.HIGH,
        "Personal data is disclosed beyond its purpose or retention limits.",
        "personal data (PII)",
    ),
    (
        ("delete", "drop table", "truncate", "purge", "wipe", "destructive", "irreversible"),
        "Irreversible data loss",
        ThreatCategory.TAMPERING,
        Severity.CRITICAL,
        "A destructive operation removes or corrupts data without recovery.",
        "persistent data",
    ),
)


def _interface_seeds(seeder: _Seeder, interface: Interface, text: str) -> None:
    name = interface.name
    asset = f"interface:{interface.id}"
    auth_sensitive = bool(
        re.search(r"\b(auth|login|session|token|password|admin)\b", f"{text} {name}", re.I)
    )
    if interface.kind is InterfaceKind.API:
        seeder.threat(
            f"Unauthorised access to {name}",
            category=ThreatCategory.SPOOFING,
            severity=Severity.HIGH if auth_sensitive else Severity.MEDIUM,
            description=f"Callers reach {interface.id} without proper authentication.",
            assets=[asset],
        )
        seeder.threat(
            f"Malformed input to {name}",
            category=ThreatCategory.TAMPERING,
            severity=Severity.MEDIUM,
            description=f"Invalid or hostile payloads break {interface.id} invariants.",
            assets=[asset],
        )
        seeder.threat(
            f"Resource exhaustion of {name}",
            category=ThreatCategory.DENIAL_OF_SERVICE,
            severity=Severity.LOW,
            description=f"Unbounded requests starve {interface.id}.",
            assets=[asset],
        )
    elif interface.kind is InterfaceKind.EVENT:
        seeder.threat(
            f"Forged or replayed events on {name}",
            category=ThreatCategory.TAMPERING,
            severity=Severity.MEDIUM,
            description=f"Events on {interface.id} are injected or replayed.",
            assets=[asset],
        )
        seeder.threat(
            f"Unattributable events on {name}",
            category=ThreatCategory.REPUDIATION,
            severity=Severity.LOW,
            description=f"Producers of {interface.id} events cannot be traced.",
            assets=[asset],
        )
    elif interface.kind is InterfaceKind.DATA:
        seeder.threat(
            f"Disclosure of {name} contents",
            category=ThreatCategory.INFORMATION_DISCLOSURE,
            severity=Severity.HIGH if auth_sensitive else Severity.MEDIUM,
            description=f"Data behind {interface.id} is read without authorisation.",
            assets=[asset],
        )
        seeder.threat(
            f"Corruption of {name}",
            category=ThreatCategory.TAMPERING,
            severity=Severity.MEDIUM,
            description=f"Writes to {interface.id} bypass validation.",
            assets=[asset],
        )
    elif interface.kind is InterfaceKind.CLI:
        seeder.threat(
            f"Privilege escalation through {name}",
            category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
            severity=Severity.MEDIUM,
            description=f"Arguments to {interface.id} reach privileged operations.",
            assets=[asset],
        )
    elif interface.kind is InterfaceKind.LIBRARY:
        seeder.threat(
            f"Compromised dependency of {name}",
            category=ThreatCategory.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            description=f"{interface.id} pulls a malicious or vulnerable package.",
            assets=[asset],
        )
    else:  # UI
        seeder.threat(
            f"Content injection in {name}",
            category=ThreatCategory.TAMPERING,
            severity=Severity.MEDIUM,
            description=f"Untrusted content is rendered by {interface.id} without escaping.",
            assets=[asset],
        )


def init_threat_model(
    intent: Intent,
    requirements: Sequence[Requirement],
    project_config: ProjectConfig | None = None,
    *,
    interfaces: Iterable[Interface] = (),
    manifest: ToolDataManifest | None = None,
    existing: ThreatModel | None = None,
    tool_tiers: Mapping[str, int] | None = None,
) -> ThreatModel:
    """Seed a :class:`ThreatModel` (see module docstring); idempotent over *existing*.

    Existing assets, actors, threats and mitigations are kept; seeds whose title already
    exists are skipped. The manifest is the union of *manifest* and the existing one.
    """
    config = project_config if project_config is not None else ProjectConfig()
    base_manifest = existing.tool_data_manifest if existing else ToolDataManifest()
    merged_manifest = ToolDataManifest(
        tools=_union(base_manifest.tools, manifest.tools if manifest else []),
        data_sources=_union(base_manifest.data_sources, manifest.data_sources if manifest else []),
        network_egress=_union(
            base_manifest.network_egress, manifest.network_egress if manifest else []
        ),
    )
    interface_list = list(interfaces)
    text = " ".join(
        [
            intent.title,
            intent.kernel.why,
            *intent.kernel.capabilities,
            *intent.kernel.constraints,
            *intent.labels,
            *(
                " ".join([r.text, r.rationale or "", *r.tags, *(s.text for s in r.scenarios)])
                for r in requirements
            ),
        ]
    )
    signals = riskmod.find_keyword_signals(text, "change")
    signal_classes = {s.risk_class for s in signals}
    agentic = bool(merged_manifest.tools) or RiskClass.AI_AGENT in signal_classes
    docs_only = intent.risk_class is RiskClass.DOCS_ONLY and not agentic
    lowered = text.lower()

    assets: list[str] = list(existing.assets) if existing else []
    actors: list[str] = list(existing.actors) if existing else []

    def add_asset(label: str) -> None:
        if label not in assets:
            assets.append(label)

    def add_actor(label: str) -> None:
        if label not in actors:
            actors.append(label)

    if not docs_only:
        add_asset("source code")
    seeder = _Seeder(existing)
    for keywords, title, category, severity, description, asset in _KEYWORD_SEEDS:
        if any(re.search(r"(?<![\w-])" + re.escape(k) + r"(?![\w-])", lowered) for k in keywords):
            add_asset(asset)
            seeder.threat(
                title, category=category, severity=severity, description=description, assets=[asset]
            )
    for module in config.critical_modules:
        add_asset(f"module:{module}")
    for interface in interface_list:
        add_asset(f"interface:{interface.id}")
    for tool in merged_manifest.tools:
        add_asset(tool_asset(tool))
    for source in merged_manifest.data_sources:
        add_asset(f"data:{source}")
    for host in merged_manifest.network_egress:
        add_asset(f"egress:{host}")

    add_actor("end user")
    add_actor("maintainer")
    add_actor("external attacker")
    if agentic:
        add_actor("implementer agent")
        add_actor("reviewer agent")
        add_actor("untrusted content author")
    if merged_manifest.network_egress:
        add_actor("third-party service")

    if not docs_only:
        seeder.threat(
            "Compromised third-party dependency",
            category=ThreatCategory.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            description="A dependency introduced or upgraded by this change is malicious "
            "or vulnerable.",
            assets=["source code"],
            mitigation="SBOM, provenance attestation and SCA scan in G4.",
        )

    for interface in interface_list:
        _interface_seeds(seeder, interface, text)

    for tool in merged_manifest.tools:
        tier = tool_tier(tool, tool_tiers)
        asset = tool_asset(tool)
        seeder.threat(
            f"Prompt injection via {tool} results",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=Severity.HIGH,
            description=f"Content returned by {tool} carries instructions the agent follows.",
            assets=[asset],
            mitigation=f"Screen {tool} results for injection patterns before they reach the "
            "agent (governance.mcp) and treat them as untrusted input.",
        )
        if tier >= 3:
            seeder.threat(
                f"Unapproved privileged use of {tool} (tier {tier})",
                category=ThreatCategory.ELEVATION_OF_PRIVILEGE,
                severity=Severity.CRITICAL if tier >= 4 else Severity.HIGH,
                description=f"The agent invokes {tool} (tier {tier}) without a human or "
                "rule-based approval.",
                assets=[asset],
                mitigation=f"Require approval before every {tool} call (tool tier {tier}); "
                "deny on timeout; audit each call.",
            )
    for source in merged_manifest.data_sources:
        sensitive = riskmod.is_sensitive_data_source(source)
        seeder.threat(
            f"Disclosure of {source} through agent output",
            category=ThreatCategory.INFORMATION_DISCLOSURE,
            severity=Severity.HIGH if sensitive else Severity.MEDIUM,
            description=f"Data read from {source} leaks into prompts, logs or responses.",
            assets=[f"data:{source}"],
            mitigation=f"Minimise and redact {source} data passed to the model; audit reads.",
        )
    for host in merged_manifest.network_egress:
        seeder.threat(
            f"Data exfiltration to {host}",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=Severity.HIGH if merged_manifest.data_sources else Severity.MEDIUM,
            description=f"Sensitive content is sent to {host} by an injected or faulty agent.",
            assets=[f"egress:{host}"],
            mitigation=f"Allow-list egress to {host} only; block unlisted hosts; audit calls.",
        )

    return ThreatModel(
        assets=assets,
        actors=actors,
        threats=seeder.threats,
        mitigations=seeder.mitigations,
        tool_data_manifest=merged_manifest,
    )


def _union(first: Iterable[str], second: Iterable[str]) -> list[str]:
    out: list[str] = []
    for item in [*first, *second]:
        if item and item not in out:
            out.append(item)
    return out


# --------------------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------------------


def _issue(
    code: str,
    message: str,
    *,
    severity: IssueSeverity = IssueSeverity.ERROR,
    artifact_id: str | None = None,
) -> ValidationIssue:
    return ValidationIssue(code=code, severity=severity, message=message, artifact_id=artifact_id)


def validate_threat_model(
    model: ThreatModel,
    *,
    risk_class: RiskClass | None = None,
    tool_tiers: Mapping[str, int] | None = None,
) -> list[ValidationIssue]:
    """Validate a threat model.

    Errors: ``TM_TOOL_NO_THREAT``, ``TM_TOOL_NO_MITIGATION``, ``TM_TIER3_TOOL_NO_APPROVAL``,
    ``TM_EGRESS_NOT_ENUMERATED``, ``TM_UNKNOWN_MITIGATION``,
    ``TM_MITIGATED_WITHOUT_MITIGATION``, ``TM_NO_THREATS`` (when tools are declared) and
    ``TM_UNRESOLVED_HIGH_RISK`` per open high/critical threat.
    Warnings: ``TM_NO_ASSETS``, ``TM_NO_ACTORS``, ``TM_NO_THREATS``, ``TM_EGRESS_MISSING``,
    ``TM_MITIGATION_UNVERIFIED``, ``TM_MITIGATION_ORPHAN``, ``TM_ACCEPTED_HIGH_RISK``.
    """
    issues: list[ValidationIssue] = []
    manifest = model.tool_data_manifest
    mitigation_ids = {m.id for m in model.mitigations}
    substantive = risk_class is None or RISK_ORDER[risk_class] >= RISK_ORDER[RiskClass.STANDARD]

    if not model.assets:
        issues.append(_issue("TM_NO_ASSETS", "no assets listed", severity=IssueSeverity.WARNING))
    if not model.actors:
        issues.append(_issue("TM_NO_ACTORS", "no actors listed", severity=IssueSeverity.WARNING))
    if not model.threats:
        severity = IssueSeverity.ERROR if manifest.tools else IssueSeverity.WARNING
        if substantive or manifest.tools:
            issues.append(_issue("TM_NO_THREATS", "no threats recorded", severity=severity))

    for threat in model.threats:
        unknown = [m for m in threat.mitigation_ids if m not in mitigation_ids]
        for mid in unknown:
            issues.append(
                _issue(
                    "TM_UNKNOWN_MITIGATION",
                    f"references unknown mitigation {mid}",
                    artifact_id=threat.id,
                )
            )
        linked = [m for m in model.mitigations if m.id in threat.mitigation_ids]
        if threat.status is ThreatStatus.MITIGATED:
            if not linked:
                issues.append(
                    _issue(
                        "TM_MITIGATED_WITHOUT_MITIGATION",
                        "status is mitigated but no mitigation is linked",
                        artifact_id=threat.id,
                    )
                )
            elif threat.severity.rank >= Severity.HIGH.rank and not any(m.verified for m in linked):
                issues.append(
                    _issue(
                        "TM_MITIGATION_UNVERIFIED",
                        "high/critical threat is mitigated by unverified mitigation(s)",
                        severity=IssueSeverity.WARNING,
                        artifact_id=threat.id,
                    )
                )
        if threat.status is ThreatStatus.ACCEPTED and threat.severity.rank >= Severity.HIGH.rank:
            issues.append(
                _issue(
                    "TM_ACCEPTED_HIGH_RISK",
                    "high/critical threat accepted without mitigation; needs sign-off",
                    severity=IssueSeverity.WARNING,
                    artifact_id=threat.id,
                )
            )
        if threat.is_unresolved_high_risk:
            issues.append(
                _issue(
                    "TM_UNRESOLVED_HIGH_RISK",
                    f"open {threat.severity.value} threat: {threat.title}",
                    artifact_id=threat.id,
                )
            )

    for mitigation in model.mitigations:
        if not mitigation.threat_ids and not any(
            mitigation.id in t.mitigation_ids for t in model.threats
        ):
            issues.append(
                _issue(
                    "TM_MITIGATION_ORPHAN",
                    "mitigation addresses no threat",
                    severity=IssueSeverity.WARNING,
                    artifact_id=mitigation.id,
                )
            )

    for tool in manifest.tools:
        threats = threats_for_tool(model, tool)
        if not threats:
            issues.append(
                _issue(
                    "TM_TOOL_NO_THREAT", f"declared tool {tool!r} has no threat", artifact_id=tool
                )
            )
            continue
        mitigations = [
            m
            for m in model.mitigations
            if any(m.id in t.mitigation_ids or t.id in m.threat_ids for t in threats)
        ]
        if not mitigations:
            issues.append(
                _issue(
                    "TM_TOOL_NO_MITIGATION",
                    f"declared tool {tool!r} has threats but no mitigation",
                    artifact_id=tool,
                )
            )
        tier = tool_tier(tool, tool_tiers)
        if tier >= 3 and not any(
            re.search(r"\b(approv|human[- ]in[- ]the[- ]loop|sign[- ]off)", m.description, re.I)
            for m in mitigations
        ):
            issues.append(
                _issue(
                    "TM_TIER3_TOOL_NO_APPROVAL",
                    f"tool {tool!r} is tier {tier} but no mitigation requires approval",
                    artifact_id=tool,
                )
            )

    for entry in manifest.network_egress:
        if not is_enumerated_host(entry):
            issues.append(
                _issue(
                    "TM_EGRESS_NOT_ENUMERATED",
                    f"network egress entry {entry!r} is not a single concrete host",
                    artifact_id=entry,
                )
            )
    if not manifest.network_egress and any(is_network_tool(t) for t in manifest.tools):
        issues.append(
            _issue(
                "TM_EGRESS_MISSING",
                "network-capable tools are declared but no egress host is enumerated",
                severity=IssueSeverity.WARNING,
            )
        )
    return issues


def check_threat_model(
    model: ThreatModel | None,
    *,
    risk_class: RiskClass | None = None,
    tool_tiers: Mapping[str, int] | None = None,
) -> ThreatModelReport:
    """Validate and summarise for G1: passes when there is no error-severity issue.

    A missing model is an error (``TM_MISSING``) for risk classes standard and above.
    """
    if model is None:
        required = risk_class is None or RISK_ORDER[risk_class] >= RISK_ORDER[RiskClass.STANDARD]
        issues = (
            [_issue("TM_MISSING", "architecture/threat-model.md is missing")] if required else []
        )
        return ThreatModelReport(passed=not issues, issues=issues, unresolved_high_risk=[])
    issues = validate_threat_model(model, risk_class=risk_class, tool_tiers=tool_tiers)
    unresolved = [t.id for t in unresolved_high_risk(model)]
    passed = not any(i.severity is IssueSeverity.ERROR for i in issues)
    return ThreatModelReport(passed=passed, issues=issues, unresolved_high_risk=unresolved)
