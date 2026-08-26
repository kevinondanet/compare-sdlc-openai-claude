"""Risk classification and the gate depth profile (ARCHITECTURE.md §3).

Two pure functions:

* :func:`classify` — derive a :class:`~aisdlc.schema.models.RiskClass` for a change from
  the intent, requirements, project configuration, tool/data manifest and (optionally)
  the paths it touches. The result is a :class:`RiskAssessment` that records *why*.
* :func:`gate_depth_profile` — map a risk class (and the org policy) to a
  :class:`GateDepthProfile`: which gates apply at which depth, which checks run, which
  thresholds/trials apply and where the human checkpoints sit. The profile changes the
  depth of a gate, never its meaning. The profile class itself is defined once, in
  :mod:`aisdlc.gates.depth`, and re-exported here.

Heuristics (documented, deterministic, keyword and path based)
==============================================================

Signals are collected from the intent title/labels/kernel (why, capabilities and success
signal only — constraints and non-goals state what must *not* happen), requirement texts/tags/
scenarios, the manifest and the paths. Every signal carries a risk class; the **highest**
class wins (``docs_only < low < standard < high < critical < ai_agent``). With no signal
the project's default class applies.

* ``ai_agent`` — the manifest declares **tools**, or network egress to a model provider
  (an LLM call, :data:`LLM_PROVIDER_HOSTS`); or text mentions LLM/agent/prompt/tool-call
  vocabulary; or a path lives under an agent/LLM directory (``agents/``, ``llm/``,
  ``prompts/``). A declared data source or an ordinary egress host on its own never
  makes a change agentic (ARCHITECTURE.md §3: the class is for changes that call tools
  or models).
* ``critical`` — payments/billing, IAM, secrets/credentials/keys, destructive data
  operations (drop/truncate/purge/wipe), safety- or compliance-critical (PCI, HIPAA).
* ``high`` — authentication/authorization/session, PII/privacy, permissions/RBAC,
  infrastructure/deployment/production, schema migrations, encryption/TLS, or a path
  under ``auth/``/``security/``/``infra/``; also any path matched by a project risk rule
  of that class, any critical module of the project, and a manifest data source that
  names sensitive data (:data:`SENSITIVE_DATA_KEYWORDS`: PII, customers, credentials,
  payments, …).
* ``standard`` — a manifest data source or egress host that is not sensitive/agentic
  (the change reads data or reaches a host, so it is not a docs-only or trivial change).
* ``low`` — the change is labelled/titled as a bug fix, hotfix, typo or chore and nothing
  above matched.
* ``docs_only`` — every touched path is documentation (or no paths are known and the
  change is labelled/titled as documentation) and nothing above matched.

The declared ``intent.risk_class`` is never lowered by heuristics: ``effective`` is the
higher of declared and computed (narrow-only, principle 4).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from fnmatch import fnmatch
from typing import Final

from pydantic import Field

from aisdlc.gates.depth import GateDepthProfile, QualityCheck
from aisdlc.policy.org_policy import OrgPolicy
from aisdlc.policy.project_config import RISK_ORDER, ProjectConfig
from aisdlc.schema.models import (
    ArtifactModel,
    Intent,
    Requirement,
    RiskClass,
    ToolDataManifest,
)

__all__ = [
    "RISK_ORDER",
    "KEYWORDS",
    "PATH_KEYWORDS",
    "DOCS_PATH_PATTERNS",
    "LOW_MARKERS",
    "DOCS_MARKERS",
    "SENSITIVE_DATA_KEYWORDS",
    "LLM_PROVIDER_HOSTS",
    "RiskSignal",
    "RiskAssessment",
    "is_docs_path",
    "is_sensitive_data_source",
    "is_llm_provider_host",
    "find_keyword_signals",
    "classify",
    "max_risk",
    "QualityCheck",
    "GateDepthProfile",
    "gate_depth_profile",
]

# --------------------------------------------------------------------------------------
# Keyword tables
# --------------------------------------------------------------------------------------

KEYWORDS: Final[dict[RiskClass, tuple[str, ...]]] = {
    RiskClass.CRITICAL: (
        "payment",
        "payments",
        "billing",
        "checkout",
        "credit card",
        "card number",
        "iam",
        "identity and access",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "private key",
        "signing key",
        "encryption key",
        "kms",
        "rotate",
        "rotation",
        "drop table",
        "truncate",
        "purge",
        "wipe",
        "delete all",
        "destructive",
        "irreversible",
        "safety-critical",
        "safety critical",
        "pci",
        "hipaa",
    ),
    RiskClass.HIGH: (
        "auth",
        "authentication",
        "authenticate",
        "authorization",
        "authorize",
        "login",
        "log in",
        "logout",
        "password",
        "passcode",
        "mfa",
        "2fa",
        "sso",
        "oauth",
        "saml",
        "session",
        "sessions",
        "access token",
        "refresh token",
        "api key",
        "jwt",
        "pii",
        "personal data",
        "personally identifiable",
        "gdpr",
        "privacy",
        "consent",
        "rbac",
        "permission",
        "permissions",
        "privilege",
        "privileges",
        "admin",
        "infrastructure",
        "terraform",
        "kubernetes",
        "deploy",
        "deployment",
        "production",
        "migration",
        "migrations",
        "schema change",
        "encryption",
        "encrypt",
        "tls",
        "certificate",
        "delete data",
        "delete records",
        "delete users",
        "delete accounts",
    ),
    RiskClass.AI_AGENT: (
        "llm",
        "large language model",
        "language model",
        "ai agent",
        "agentic",
        "agent",
        "agents",
        "prompt injection",
        "system prompt",
        "prompt template",
        "prompt engineering",
        "tool call",
        "tool calls",
        "tool-call",
        "function calling",
        "mcp",
        "chat completion",
        "completions api",
        "openai",
        "anthropic",
        "claude",
        "gpt",
        "gemini",
        "copilot",
        "assistant",
        "chatbot",
        "rag",
        "retrieval-augmented",
        "embedding",
        "embeddings",
        "vector store",
        "model call",
    ),
}
"""Keyword/phrase table per risk class (matched case-insensitively on word boundaries)."""

PATH_KEYWORDS: Final[dict[RiskClass, tuple[str, ...]]] = {
    RiskClass.CRITICAL: ("payment", "payments", "billing", "iam", "secrets", "kms"),
    RiskClass.HIGH: ("auth", "authn", "authz", "security", "infra", "deploy", "migrations"),
    RiskClass.AI_AGENT: ("agent", "agents", "llm", "prompts", "prompt"),
}
"""Path segment names that carry a risk class (any directory or file stem)."""

DOCS_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "docs/*",
    "doc/*",
    "*/docs/*",
    "*.md",
    "*.rst",
    "*.txt",
    "*.adoc",
    "README*",
    "CHANGELOG*",
    "LICENSE*",
    "CONTRIBUTING*",
)
"""``fnmatch`` patterns of documentation-only paths."""

LOW_MARKERS: Final[tuple[str, ...]] = ("bug", "bugfix", "bug fix", "fix", "hotfix", "typo", "chore")
"""Labels/title words that suggest an isolated low-risk change."""

DOCS_MARKERS: Final[tuple[str, ...]] = ("docs", "documentation", "readme", "changelog")
"""Labels/title words that suggest a documentation change."""

SENSITIVE_DATA_KEYWORDS: Final[tuple[str, ...]] = (
    "pii",
    "personal",
    "customer",
    "customers",
    "user",
    "users",
    "account",
    "accounts",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwords",
    "token",
    "tokens",
    "payment",
    "payments",
    "card",
    "cards",
    "financial",
    "health",
    "medical",
    "private",
    "confidential",
)
"""Words that mark a manifest data source as sensitive (matched on whole word tokens)."""

LLM_PROVIDER_HOSTS: Final[tuple[str, ...]] = (
    "api.anthropic.com",
    "*.anthropic.com",
    "api.openai.com",
    "*.openai.com",
    "*.openai.azure.com",
    "*.cognitiveservices.azure.com",
    "*.services.ai.azure.com",
    "generativelanguage.googleapis.com",
    "*.aiplatform.googleapis.com",
    "bedrock*.amazonaws.com",
    "api.mistral.ai",
    "api.cohere.com",
    "api.cohere.ai",
    "openrouter.ai",
    "api.together.xyz",
    "api.groq.com",
    "api-inference.huggingface.co",
    "api.x.ai",
    "api.deepseek.com",
)
"""``fnmatch`` patterns of model-provider hosts: egress to one of them is an LLM call."""

_USER_AGENT = re.compile(r"\buser[- ]agents?\b", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[a-z0-9]+")
_SENSITIVE_TOKENS: Final[frozenset[str]] = frozenset(SENSITIVE_DATA_KEYWORDS)


def is_sensitive_data_source(source: str) -> bool:
    """``True`` when a manifest data source names sensitive data.

    The entry is split into lower-case alphanumeric tokens (``customer_db`` ->
    ``customer``, ``db``) and compared with :data:`SENSITIVE_DATA_KEYWORDS`; substrings
    never match (``dashboard`` is not ``card``).
    """
    return any(token in _SENSITIVE_TOKENS for token in _TOKEN_RE.findall(source.lower()))


def is_llm_provider_host(entry: str) -> bool:
    """``True`` when a manifest egress entry names a model-provider host (an LLM call)."""
    text = entry.strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    host = text.split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    return bool(host) and any(fnmatch(host, pattern) for pattern in LLM_PROVIDER_HOSTS)


def _phrase_pattern(phrase: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])", re.IGNORECASE)


_COMPILED: Final[dict[RiskClass, list[tuple[str, re.Pattern[str]]]]] = {
    risk: [(phrase, _phrase_pattern(phrase)) for phrase in phrases]
    for risk, phrases in KEYWORDS.items()
}


# --------------------------------------------------------------------------------------
# Assessment models
# --------------------------------------------------------------------------------------


class RiskSignal(ArtifactModel):
    """One piece of evidence for a risk class."""

    source: str = Field(description="Where it was found: intent, REQ-001, manifest, path …")
    matched: str = Field(description="The keyword, path or manifest entry that matched.")
    risk_class: RiskClass
    reason: str


class RiskAssessment(ArtifactModel):
    """Outcome of :func:`classify`."""

    computed: RiskClass = Field(description="Highest class supported by the signals.")
    declared: RiskClass | None = Field(default=None, description="``intent.risk_class``.")
    signals: list[RiskSignal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)

    @property
    def effective(self) -> RiskClass:
        """Higher of declared and computed (heuristics never lower a declared class)."""
        if self.declared is None:
            return self.computed
        return max_risk(self.declared, self.computed)

    @property
    def escalated(self) -> bool:
        """``True`` when heuristics found a higher class than declared."""
        return self.declared is not None and RISK_ORDER[self.computed] > RISK_ORDER[self.declared]

    @property
    def below_declared(self) -> bool:
        """``True`` when heuristics found a lower class than declared (never applied)."""
        return self.declared is not None and RISK_ORDER[self.computed] < RISK_ORDER[self.declared]


def max_risk(*classes: RiskClass) -> RiskClass:
    """Highest risk class by :data:`RISK_ORDER`."""
    if not classes:
        raise ValueError("max_risk needs at least one class")
    return max(classes, key=lambda c: RISK_ORDER[c])


# --------------------------------------------------------------------------------------
# Signal extraction
# --------------------------------------------------------------------------------------


def is_docs_path(path: str) -> bool:
    """``True`` when *path* matches :data:`DOCS_PATH_PATTERNS`."""
    normalized = path.replace("\\", "/").lstrip("./")
    name = normalized.rsplit("/", 1)[-1]
    return any(fnmatch(normalized, p) or fnmatch(name, p) for p in DOCS_PATH_PATTERNS)


def find_keyword_signals(text: str, source: str) -> list[RiskSignal]:
    """Keyword signals in *text* (one per matched phrase, highest classes first)."""
    if not text.strip():
        return []
    scrubbed = _USER_AGENT.sub(" ", text)
    signals: list[RiskSignal] = []
    for risk in sorted(_COMPILED, key=lambda c: -RISK_ORDER[c]):
        for phrase, pattern in _COMPILED[risk]:
            if pattern.search(scrubbed):
                signals.append(
                    RiskSignal(
                        source=source,
                        matched=phrase,
                        risk_class=risk,
                        reason=f"{source} mentions {phrase!r} ({risk.value})",
                    )
                )
    return signals


def _path_signals(paths: Sequence[str], config: ProjectConfig) -> list[RiskSignal]:
    signals: list[RiskSignal] = []
    for path in paths:
        normalized = path.replace("\\", "/")
        for rule in config.risk_classification.rules:
            if fnmatch(normalized, rule.pattern):
                signals.append(
                    RiskSignal(
                        source="path",
                        matched=path,
                        risk_class=rule.risk_class,
                        reason=f"path {path} matches project rule {rule.pattern!r} "
                        f"({rule.risk_class.value})",
                    )
                )
                break
        if config.is_critical(normalized):
            signals.append(
                RiskSignal(
                    source="path",
                    matched=path,
                    risk_class=RiskClass.HIGH,
                    reason=f"path {path} is a project critical module (high)",
                )
            )
        segments = [s.lower() for s in re.split(r"[/\\]", normalized) if s]
        stems = [s.rsplit(".", 1)[0] for s in segments]
        for risk in sorted(PATH_KEYWORDS, key=lambda c: -RISK_ORDER[c]):
            hit = next((k for k in PATH_KEYWORDS[risk] if k in segments or k in stems), None)
            if hit is not None:
                signals.append(
                    RiskSignal(
                        source="path",
                        matched=path,
                        risk_class=risk,
                        reason=f"path {path} contains segment {hit!r} ({risk.value})",
                    )
                )
                break
    return signals


def _manifest_signals(manifest: ToolDataManifest | None) -> list[RiskSignal]:
    """Signals from the tool/data manifest (see the module docstring).

    Tools make the change agentic. Data sources are ``high`` when sensitive, otherwise
    ``standard``; egress is ``ai_agent`` for a model-provider host (an LLM call) and
    ``standard`` otherwise. Neither a data source nor an ordinary host implies ``ai_agent``.
    """
    if manifest is None:
        return []
    signals: list[RiskSignal] = []
    for tool in manifest.tools:
        signals.append(
            RiskSignal(
                source="manifest",
                matched=tool,
                risk_class=RiskClass.AI_AGENT,
                reason=f"manifest declares tool {tool!r} (ai_agent)",
            )
        )
    for source in manifest.data_sources:
        if is_sensitive_data_source(source):
            risk, why = RiskClass.HIGH, "sensitive data source"
        else:
            risk, why = RiskClass.STANDARD, "data source"
        signals.append(
            RiskSignal(
                source="manifest",
                matched=source,
                risk_class=risk,
                reason=f"manifest declares {why} {source!r} ({risk.value}); "
                "a data source alone does not make the change agentic",
            )
        )
    for host in manifest.network_egress:
        if is_llm_provider_host(host):
            risk, why = RiskClass.AI_AGENT, "network egress to model provider"
        else:
            risk, why = RiskClass.STANDARD, "network egress"
        signals.append(
            RiskSignal(
                source="manifest",
                matched=host,
                risk_class=risk,
                reason=f"manifest declares {why} {host!r} ({risk.value})",
            )
        )
    return signals


def _marker_hit(markers: Iterable[str], *texts: str) -> str | None:
    for marker in markers:
        pattern = _phrase_pattern(marker)
        for text in texts:
            if pattern.search(text):
                return marker
    return None


def classify(
    intent: Intent,
    requirements: Sequence[Requirement],
    project_config: ProjectConfig | None = None,
    manifest: ToolDataManifest | None = None,
    *,
    paths: Iterable[str] = (),
) -> RiskAssessment:
    """Classify a change; see the module docstring for the heuristics.

    *paths* are the files the change touches (for example the union of ``Task.files``).
    The result never lowers ``intent.risk_class``: use :attr:`RiskAssessment.effective`.
    """
    config = project_config if project_config is not None else ProjectConfig()
    path_list = [p for p in paths if p.strip()]
    signals: list[RiskSignal] = []

    intent_text = " ".join(
        [
            intent.title,
            intent.kernel.why,
            *intent.kernel.capabilities,
            intent.kernel.success_signal,
        ]
    )
    # Constraints and non-goals describe what the change must NOT do ("must not expose
    # credentials"); scanning them for risk keywords produces false escalations, so only
    # the positive statements of intent (why/capabilities/success signal) are scanned.
    signals.extend(find_keyword_signals(intent_text, "intent"))
    signals.extend(find_keyword_signals(" ".join(intent.labels), "labels"))
    for requirement in requirements:
        text = " ".join(
            [
                requirement.text,
                requirement.rationale or "",
                *requirement.tags,
                *(s.text for s in requirement.scenarios),
            ]
        )
        signals.extend(find_keyword_signals(text, requirement.id))
    signals.extend(_manifest_signals(manifest))
    signals.extend(_path_signals(path_list, config))

    strong = [s for s in signals if RISK_ORDER[s.risk_class] >= RISK_ORDER[RiskClass.STANDARD]]
    label_text = " ".join(intent.labels)
    if not strong:
        docs_paths = bool(path_list) and all(is_docs_path(p) for p in path_list)
        docs_marker = _marker_hit(DOCS_MARKERS, intent.title, label_text)
        if docs_paths or (not path_list and docs_marker is not None):
            why = (
                "every touched path is documentation"
                if docs_paths
                else f"labelled/titled as documentation ({docs_marker!r}) and no code paths"
            )
            signals.append(
                RiskSignal(
                    source="path" if docs_paths else "intent",
                    matched=", ".join(path_list) if docs_paths else str(docs_marker),
                    risk_class=RiskClass.DOCS_ONLY,
                    reason=f"{why} (docs_only)",
                )
            )
        else:
            low_marker = _marker_hit(LOW_MARKERS, intent.title, label_text)
            if low_marker is not None:
                signals.append(
                    RiskSignal(
                        source="intent",
                        matched=low_marker,
                        risk_class=RiskClass.LOW,
                        reason=f"labelled/titled as {low_marker!r} with no security surface (low)",
                    )
                )

    if signals:
        computed = max_risk(*(s.risk_class for s in signals))
        reasons = [s.reason for s in signals if s.risk_class is computed]
        others = sorted({s.risk_class.value for s in signals if s.risk_class is not computed})
        if others:
            reasons.append(f"lower signals also present: {', '.join(others)}")
    else:
        computed = config.risk_classification.default
        reasons = [f"no risk signals found; project default {computed.value}"]
    declared = intent.risk_class
    if RISK_ORDER[declared] > RISK_ORDER[computed]:
        reasons.append(
            f"declared risk class {declared.value} is higher than computed {computed.value}; "
            "declared class kept"
        )
    elif RISK_ORDER[declared] < RISK_ORDER[computed]:
        reasons.append(f"declared risk class {declared.value} escalated to {computed.value}")
    return RiskAssessment(computed=computed, declared=declared, signals=signals, reasons=reasons)


# --------------------------------------------------------------------------------------
# Gate depth profile (single definition lives in aisdlc.gates.depth)
# --------------------------------------------------------------------------------------


def gate_depth_profile(risk_class: RiskClass, policy: OrgPolicy | None = None) -> GateDepthProfile:
    """Build the :class:`GateDepthProfile` for *risk_class* under *policy*.

    Thin wrapper over :meth:`aisdlc.gates.depth.GateDepthProfile.from_risk_class` so the
    planning layer and the gates share one profile object: which gates apply at which
    depth, which checks run, the thresholds/trials and where the human checkpoints sit.
    """
    return GateDepthProfile.from_risk_class(risk_class, policy)
