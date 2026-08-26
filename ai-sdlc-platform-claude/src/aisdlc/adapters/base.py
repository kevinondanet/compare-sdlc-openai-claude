"""Harness adapter protocol and the shared canonical workflow context.

Every harness adapter (Claude Code, Copilot, Codex, Cursor, Kiro) renders the *same*
workflow — the canonical ``aisdlc`` command set, the canonical change-package artifacts
and the effective tool tier policy — into the host's native command/skill/rule/hook
format. Nothing here depends on a harness or a model provider (ARCHITECTURE.md §0.7).
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from string import Template
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from aisdlc.policy import EffectivePolicy, ProjectConfig, TierBehaviour, effective_policy
from aisdlc.policy.org_policy import default_org_policy
from aisdlc.policy.project_config import default_project_config
from aisdlc.schema.models import GateId, RiskClass

__all__ = [
    "ADAPTER_TEMPLATES_DIR_NAME",
    "ArtifactDescription",
    "AdapterContext",
    "CANONICAL_ARTIFACTS",
    "CANONICAL_COMMANDS",
    "CanonicalCommand",
    "DEFAULT_HOOK_COMMAND",
    "EmittedFile",
    "EmittedFiles",
    "HarnessAdapter",
    "READ_ONLY_TOOLS",
    "TIER_3_SHELL_PREFIXES",
    "TIER_4_READ_PATTERNS",
    "TIER_4_SHELL_PREFIXES",
    "WorkflowPhase",
    "adapter_templates_dir",
    "command_by_key",
    "default_context",
    "render_template",
    "write_emitted",
]

DEFAULT_HOOK_COMMAND = "aisdlc governance hook"
"""The governance CLI hook (provided by ``aisdlc.cli.cmd_governance``), referenced by name."""

ADAPTER_TEMPLATES_DIR_NAME = "adapters"


class WorkflowPhase(StrEnum):
    """Phases of the canonical workflow, in execution order."""

    INTAKE = "intake"
    SPECIFY = "specify"
    PLAN = "plan"
    IMPLEMENT = "implement"
    REVIEW = "review"
    GATE = "gate"
    SECURITY = "security"
    COST = "cost"


@dataclass(frozen=True)
class CanonicalCommand:
    """One step of the canonical workflow, expressed as an ``aisdlc`` CLI invocation.

    ``slug`` is used for host file names (``aisdlc-<slug>.md``); ``cli`` is the command an
    agent should run; ``brief`` is the narrow instruction rendered into the host command so
    that every harness gives the agent the same fresh-context brief.
    """

    key: str
    slug: str
    title: str
    phase: WorkflowPhase
    cli: str
    description: str
    brief: str
    argument_hint: str = ""
    read_only: bool = True
    produces: tuple[str, ...] = ()


CANONICAL_COMMANDS: tuple[CanonicalCommand, ...] = (
    CanonicalCommand(
        key="change.new",
        slug="change-new",
        title="Create a change package",
        phase=WorkflowPhase.INTAKE,
        cli='aisdlc change new "<title>" --owner <owner> --risk-class <risk-class>',
        description="Create changes/<CHG-id>/ with the skeleton intent, requirements, plan "
        "and tasks files.",
        brief="Create a new change package for the request. Fill the BMAD kernel in "
        "intent.md (why, capabilities, constraints, non-goals, success signal) and set the "
        "accountable owner and risk class. Do not write code.",
        argument_hint="<title> [--owner <owner>] "
        "[--risk-class docs_only|low|standard|high|critical|ai_agent]",
        read_only=False,
        produces=("intent.md", "requirements.md", "assumptions.md", "plan.md", "tasks.md"),
    ),
    CanonicalCommand(
        key="change.validate",
        slug="change-validate",
        title="Validate a change package",
        phase=WorkflowPhase.SPECIFY,
        cli="aisdlc change validate changes/<CHG-id> --strict",
        description="Run grammar (SHALL/MUST, EARS, WHEN/THEN) and cross-artifact "
        "consistency checks; exit 1 on errors.",
        brief="Run the validator and fix every reported issue in the canonical files "
        "(requirements.md, tasks.md, plan.md). Each requirement needs a normative modal and at "
        "least one WHEN/THEN scenario; each task needs an executable verification block.",
        argument_hint="changes/<CHG-id>",
    ),
    CanonicalCommand(
        key="intake.clarify",
        slug="intake-clarify",
        title="Clarify the intent",
        phase=WorkflowPhase.INTAKE,
        cli="aisdlc intake clarify changes/<CHG-id>",
        description="Rank clarification questions and compute the ambiguity score.",
        brief="Ask the ranked clarification questions one at a time, record answers as "
        "resolved open questions in assumptions.md and lower the ambiguity score below the "
        "policy threshold. Never invent answers.",
        argument_hint="changes/<CHG-id>",
    ),
    CanonicalCommand(
        key="intake.checklist",
        slug="intake-checklist",
        title="Requirements quality checklist",
        phase=WorkflowPhase.SPECIFY,
        cli="aisdlc intake checklist changes/<CHG-id>",
        description="Evaluate the requirements-quality checklist (testable, unambiguous, "
        "traceable, complete).",
        brief="Run the checklist and address each failing item by editing requirements.md; "
        "report items you cannot resolve as open questions.",
        argument_hint="changes/<CHG-id>",
    ),
    CanonicalCommand(
        key="intake.analyze",
        slug="intake-analyze",
        title="Cross-artifact analysis",
        phase=WorkflowPhase.SPECIFY,
        cli="aisdlc intake analyze changes/<CHG-id>",
        description="Check intent, requirements, scenarios, assumptions, plan and tasks "
        "against each other for gaps and contradictions.",
        brief="Run the analysis and reconcile inconsistencies between artifacts. Every "
        "requirement must trace to at least one task and every task to a requirement.",
        argument_hint="changes/<CHG-id>",
    ),
    CanonicalCommand(
        key="plan.generate",
        slug="plan-generate",
        title="Generate the plan",
        phase=WorkflowPhase.PLAN,
        cli="aisdlc plan generate changes/<CHG-id>",
        description="Derive tasks with executable verification and dependency waves from "
        "the requirements.",
        brief="Generate tasks.md and plan.md. Each task references requirement ids, "
        "declares its files, and has a verification command with an expected exit code. "
        "Group independent tasks into waves; mark human checkpoints.",
        argument_hint="changes/<CHG-id>",
        read_only=False,
        produces=("plan.md", "tasks.md"),
    ),
    CanonicalCommand(
        key="plan.check",
        slug="plan-check",
        title="Check the plan",
        phase=WorkflowPhase.PLAN,
        cli="aisdlc plan check changes/<CHG-id>",
        description="Goal-backward validation: does completing every task satisfy every "
        "requirement and scenario?",
        brief="Run the plan checker and fix gaps in tasks.md/plan.md until it passes. Do not "
        "start implementation before the plan is approved.",
        argument_hint="changes/<CHG-id>",
    ),
    CanonicalCommand(
        key="run.task",
        slug="run-task",
        title="Implement one task",
        phase=WorkflowPhase.IMPLEMENT,
        cli="aisdlc run task <TASK-id> --change changes/<CHG-id>",
        description="Execute a single task in an isolated worktree with a narrow brief and "
        "run its verification command.",
        brief="Implement exactly the named task: only the files it lists, only the "
        "requirements it references. Run the task's verification command and record the "
        "result. Do not touch other tasks' files; do not push, deploy or install packages "
        "without approval.",
        argument_hint="<TASK-id> --change changes/<CHG-id>",
        read_only=False,
        produces=("evidence/tests.json", "handoffs/"),
    ),
    CanonicalCommand(
        key="review",
        slug="review",
        title="Independent review",
        phase=WorkflowPhase.REVIEW,
        cli="aisdlc run review changes/<CHG-id>",
        description="Review the actual diff with an independent model family; grounded, "
        "blocking findings fail G3.",
        brief="Review the diff against the requirements and scenarios. Report only grounded "
        "findings with file and line; mark a finding blocking only when it violates a "
        "requirement, a scenario, or a security constraint.",
        argument_hint="changes/<CHG-id>",
        produces=("evidence/reviews.json",),
    ),
    CanonicalCommand(
        key="gate.evaluate",
        slug="gate-evaluate",
        title="Evaluate gates",
        phase=WorkflowPhase.GATE,
        cli="aisdlc gate evaluate changes/<CHG-id>",
        description="Evaluate G0..G6 at the depth selected by the risk class from the "
        "evidence bundle; missing or incomplete evidence fails closed.",
        brief="Run the gate evaluation and report each failing gate with its reasons. "
        "Produce the missing evidence with the corresponding command; never edit evidence "
        "files by hand.",
        argument_hint="changes/<CHG-id>",
        produces=("final-verdict.json",),
    ),
    CanonicalCommand(
        key="security.campaign",
        slug="security-campaign",
        title="Adversarial campaign",
        phase=WorkflowPhase.SECURITY,
        cli="aisdlc security campaign run <campaign.yaml> --target <module:callable> "
        "--evidence changes/<CHG-id>/evidence/security.json",
        description="Run a PyRIT red-team campaign against the application under test and "
        "record ASR, undetermined rate and completeness.",
        brief="Run the campaign defined for this change's risk class. A campaign that did "
        "not complete every trial fails closed; do not lower thresholds to pass.",
        argument_hint="<campaign.yaml> --target <module:callable>",
        produces=("evidence/security.json",),
    ),
    CanonicalCommand(
        key="security.safety",
        slug="security-safety",
        title="Safety regression",
        phase=WorkflowPhase.SECURITY,
        cli="aisdlc security safety run <module> "
        "--evidence changes/<CHG-id>/evidence/security.json",
        description="Run the pytest-native safety regression suite (harm categories, "
        "trials, thresholds).",
        brief="Run the safety suite for the agent under test and record the report. "
        "Incomplete runs fail closed.",
        argument_hint="<module>",
        produces=("evidence/security.json",),
    ),
    CanonicalCommand(
        key="cost.report",
        slug="cost-report",
        title="Cost report",
        phase=WorkflowPhase.COST,
        cli="aisdlc cost report --change <CHG-id> --export",
        description="Extract this change's usage from the ledger as CostEvidence and "
        "compare with the budget.",
        brief="Produce the cost extract for the change and report budget variance and "
        "escalations. Do not run additional agents to 'improve' the numbers.",
        argument_hint="--change <CHG-id>",
        produces=("evidence/cost.json",),
    ),
)
"""The canonical command set every adapter renders (same workflow, same briefs)."""


def command_by_key(key: str) -> CanonicalCommand:
    """Look up a canonical command by its dotted key (``"plan.check"``)."""
    for command in CANONICAL_COMMANDS:
        if command.key == key:
            return command
    raise KeyError(key)


@dataclass(frozen=True)
class ArtifactDescription:
    """A canonical change-package artifact and what it holds."""

    path: str
    description: str


CANONICAL_ARTIFACTS: tuple[ArtifactDescription, ...] = (
    ArtifactDescription(
        "intent.md",
        "Intent: title, BMAD kernel (why, capabilities, constraints, non_goals, "
        "success_signal), owner, risk_class.",
    ),
    ArtifactDescription(
        "requirements.md",
        "Requirement[]: REQ-nnn id, normative text (SHALL/MUST or EARS), kind, MoSCoW "
        "priority, WHEN/THEN scenarios (SCN-nnn-nn).",
    ),
    ArtifactDescription("scenarios/", "Optional per-requirement scenario files."),
    ArtifactDescription(
        "assumptions.md", "Assumption[] (ASM-nnn) and OpenQuestion[] (OQ-nnn, blocking flag)."
    ),
    ArtifactDescription(
        "architecture/",
        "context.md, decisions/ADR-nnnn.md, interfaces/IFC-nnn.md, threat-model.md "
        "(assets, actors, threats THR-nnn, mitigations, tool/data manifest).",
    ),
    ArtifactDescription("plan.md", "Plan: waves of task ids with human checkpoints."),
    ArtifactDescription(
        "tasks.md",
        "Task[]: TASK-nnn id, requirement ids, files, executable verification "
        "(command, expected exit code), status, wave.",
    ),
    ArtifactDescription(
        "evidence/",
        "tests.json, reviews.json, security.json, performance.json, cost.json, audit.json — "
        "structured evidence with command, exit code, commit SHA, environment, report URI.",
    ),
    ArtifactDescription("handoffs/", "Durable agent handoffs (JSON)."),
    ArtifactDescription("final-verdict.json", "Gate results G0..G6, overall, signatures."),
)
"""The canonical change-package layout (ARCHITECTURE.md §2.2)."""


READ_ONLY_TOOLS: tuple[str, ...] = ("Read", "Glob", "Grep", "LS")
"""Tier-0 tools (read, search, explain) — automatic in every harness."""

TIER_3_SHELL_PREFIXES: tuple[str, ...] = (
    "git push",
    "gh pr create",
    "gh pr merge",
    "gh issue create",
    "pip install",
    "uv add",
    "npm install",
    "npm publish",
    "poetry add",
)
"""Shared-state actions (tier 3): never auto-allowed; the host must ask."""

TIER_4_SHELL_PREFIXES: tuple[str, ...] = (
    "git push --force",
    "git push -f",
    "git push --force-with-lease",
    "rm -rf /",
    "rm -rf ~",
    "kubectl apply",
    "kubectl delete",
    "helm install",
    "helm upgrade",
    "helm uninstall",
    "terraform apply",
    "terraform destroy",
    "docker push",
    "az containerapp update",
    "az role",
    "az ad",
    "az keyvault",
    "aws iam",
    "aws secretsmanager",
    "gcloud iam",
    "gcloud secrets",
    "vault",
    "gh secret",
    "DROP TABLE",
    "DROP DATABASE",
)
"""Privileged / irreversible actions (tier 4): denied in every emitted host policy."""

TIER_4_READ_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/id_rsa*",
    "**/secrets/**",
)
"""Secret material: reading it is a tier-4 action (``read_secrets``)."""


class EmittedFile(BaseModel):
    """One file written by an adapter."""

    model_config = ConfigDict(extra="forbid")

    path: Path
    description: str
    relative: str = Field(default="", description="Path relative to the output directory.")


class EmittedFiles(BaseModel):
    """Everything an adapter wrote for one harness."""

    model_config = ConfigDict(extra="forbid")

    harness: str
    out_dir: Path
    files: list[EmittedFile] = Field(default_factory=list)

    @property
    def paths(self) -> list[Path]:
        """Absolute paths of the emitted files."""
        return [f.path for f in self.files]

    def relative_paths(self) -> list[str]:
        """Paths relative to ``out_dir`` (POSIX separators)."""
        return [f.relative for f in self.files]


def write_emitted(
    out_dir: Path, relative: str, content: str, description: str, *, files: EmittedFiles
) -> EmittedFile:
    """Write *content* under ``out_dir/relative`` and record it in *files*."""
    path = out_dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    emitted = EmittedFile(path=path, description=description, relative=relative)
    files.files.append(emitted)
    return emitted


@runtime_checkable
class HarnessAdapter(Protocol):
    """Translates the canonical workflow into a host-specific layout."""

    name: str
    description: str

    def emit(
        self, project_config: ProjectConfig, policy: EffectivePolicy, out_dir: Path
    ) -> EmittedFiles:
        """Write the host files under *out_dir* and return what was written."""
        ...


# --------------------------------------------------------------------------------------
# Shared context
# --------------------------------------------------------------------------------------


def _first_token(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()
    return parts[0] if parts else command.strip()


@dataclass
class AdapterContext:
    """The canonical workflow plus the effective policy, ready to render.

    Adapters read from this object only, so every host gets the same commands, the same
    artifact descriptions and the same tool policy derived from the effective policy.
    """

    project: ProjectConfig
    policy: EffectivePolicy
    commands: tuple[CanonicalCommand, ...] = CANONICAL_COMMANDS
    artifacts: tuple[ArtifactDescription, ...] = CANONICAL_ARTIFACTS
    hook_command: str = DEFAULT_HOOK_COMMAND
    role: str = "implementer"
    extra_allowed_shell: tuple[str, ...] = field(default_factory=tuple)

    # -- policy-derived facts --------------------------------------------------------

    def tier_behaviour(self, tier: int) -> TierBehaviour:
        """Behaviour of tool tier *tier* under the effective policy."""
        return self.policy.tier_behaviour(tier)

    def test_commands(self) -> dict[str, str]:
        """Configured test commands (unit, lint, types, …) of the project."""
        return self.project.test_commands.defined()

    def tests_auto_allowed(self) -> bool:
        """Whether tier-2 (run tests/builds) may run without asking."""
        return self.tier_behaviour(2).rank <= TierBehaviour.POLICY_CONTROLLED.rank

    def writes_auto_allowed(self) -> bool:
        """Whether tier-1 (write inside the worktree) may run without asking."""
        return self.tier_behaviour(1).rank <= TierBehaviour.AUTOMATIC_AUDIT.rank

    def allowed_shell_commands(self) -> list[str]:
        """Exact shell commands that may run without prompting."""
        allowed: list[str] = ["aisdlc"]
        if self.tests_auto_allowed():
            allowed.extend(self.test_commands().values())
        allowed.extend(self.extra_allowed_shell)
        return _dedupe(allowed)

    def allowed_shell_prefixes(self) -> list[str]:
        """Command prefixes (first token) that may run without prompting."""
        prefixes = ["aisdlc", "git status", "git diff", "git log", "git show"]
        if self.tests_auto_allowed():
            prefixes.extend(_first_token(cmd) for cmd in self.test_commands().values())
        prefixes.extend(_first_token(cmd) for cmd in self.extra_allowed_shell)
        return _dedupe(prefixes)

    def denied_shell_prefixes(self) -> list[str]:
        """Tier-4 command prefixes that are always denied."""
        return list(TIER_4_SHELL_PREFIXES)

    def approval_shell_prefixes(self) -> list[str]:
        """Tier-3 command prefixes that require approval."""
        return list(TIER_3_SHELL_PREFIXES)

    def denied_read_patterns(self) -> list[str]:
        """Path patterns whose contents must never be read by an agent."""
        return list(TIER_4_READ_PATTERNS)

    def required_gates(self) -> dict[str, list[str]]:
        """Required gates per risk class as plain strings."""
        return {
            risk.value: [g.value for g in self.policy.required_gates_for(risk)]
            for risk in RiskClass
        }

    def commands_in(self, phase: WorkflowPhase) -> list[CanonicalCommand]:
        """Canonical commands belonging to *phase*."""
        return [c for c in self.commands if c.phase == phase]

    # -- markdown fragments shared by every adapter ----------------------------------

    def workflow_markdown(self) -> str:
        """Numbered workflow phases with the command to run in each."""
        lines: list[str] = []
        for index, phase in enumerate(WorkflowPhase, start=1):
            cmds = self.commands_in(phase)
            if not cmds:
                continue
            lines.append(f"{index}. **{phase.value.title()}** — {_PHASE_TEXT[phase]}")
            for cmd in cmds:
                lines.append(f"   - `{cmd.cli}` — {cmd.description}")
        return "\n".join(lines) + "\n"

    def commands_markdown(self) -> str:
        """Table of canonical commands."""
        lines = ["| Command | Phase | Purpose |", "| --- | --- | --- |"]
        for cmd in self.commands:
            lines.append(f"| `{cmd.cli}` | {cmd.phase.value} | {cmd.description} |")
        return "\n".join(lines) + "\n"

    def artifacts_markdown(self) -> str:
        """Bullet list of canonical artifacts."""
        return "".join(f"- `{a.path}` — {a.description}\n" for a in self.artifacts)

    def tool_policy_markdown(self) -> str:
        """Tool risk tiers with their effective behaviour and concrete host patterns."""
        lines = [
            "| Tier | Examples | Behaviour |",
            "| --- | --- | --- |",
            f"| 0 | read, search, explain | {self.tier_behaviour(0).value} |",
            f"| 1 | write inside the isolated worktree | {self.tier_behaviour(1).value} |",
            f"| 2 | run tests/builds, local artifacts | {self.tier_behaviour(2).value} |",
            f"| 3 | git push, create PR, install packages | {self.tier_behaviour(3).value} |",
            f"| 4 | deploy, rotate secrets, change IAM, delete data | "
            f"{self.tier_behaviour(4).value} |",
            "",
            "Allowed without prompting: "
            + ", ".join(f"`{c}`" for c in self.allowed_shell_commands())
            + ".",
            "Requires approval: "
            + ", ".join(f"`{c}`" for c in self.approval_shell_prefixes())
            + ".",
            "Always denied (tier 4): "
            + ", ".join(f"`{c}`" for c in self.denied_shell_prefixes())
            + ".",
            "Never read: " + ", ".join(f"`{p}`" for p in self.denied_read_patterns()) + ".",
            "",
            f"Approval timeout: {self.policy.tool_tiers.approval_timeout_seconds}s; "
            f"deny on timeout: {str(self.policy.tool_tiers.deny_on_timeout).lower()}; "
            f"audited from tier {self.policy.tool_tiers.audit_from_tier}.",
            f"Every tool call is screened by `{self.hook_command}` (AGT policy engine).",
        ]
        return "\n".join(lines) + "\n"

    def policy_summary_markdown(self) -> str:
        """Gates, budgets and quality thresholds from the effective policy."""
        pol = self.policy
        cov = pol.security_baselines.coverage
        lines = [
            f"- Organization policy: `{pol.name}` v{pol.version}; project: `{self.project.name}`"
            f" ({', '.join(self.project.languages) or 'no languages set'}).",
            "- Required gates: "
            + "; ".join(
                f"{risk}: {', '.join(gates)}" for risk, gates in self.required_gates().items()
            )
            + ".",
            f"- Coverage: lines >= {cov.lines:g}% (floor {cov.lines_floor:g}%), "
            f"diff >= {cov.diff_lines:g}%, branches >= {cov.branches:g}%, "
            f"critical modules >= {cov.critical_modules:g}%; "
            f"mutation >= {pol.security_baselines.mutation_score:.2f}.",
            f"- Ambiguity threshold {pol.security_baselines.ambiguity_threshold:.2f}; "
            f"ASR threshold {pol.security_baselines.asr_threshold:.2f}; "
            f"max undetermined {pol.security_baselines.max_undetermined_rate:.2f}.",
            f"- Budgets (USD): change {pol.cost_limits.budgets.per_change_usd:g}, "
            f"task {pol.cost_limits.budgets.per_task_usd:g}, day "
            f"{pol.cost_limits.budgets.per_day_usd:g}; max review rounds "
            f"{pol.cost_limits.max_review_rounds}; max agent turns "
            f"{pol.cost_limits.max_agent_turns}.",
            "- Independent review requires a different model family: "
            f"{str(pol.models.independent_review_requires_different_family).lower()}.",
        ]
        if pol.violations:
            lines.append(
                f"- {len(pol.violations)} project override(s) were rejected for weakening "
                "org policy (org values kept)."
            )
        return "\n".join(lines) + "\n"

    def command_briefs_markdown(self) -> str:
        """One section per canonical command with its narrow brief and CLI invocation."""
        sections: list[str] = []
        for cmd in self.commands:
            produces = ", ".join(f"`{p}`" for p in cmd.produces) or "no new artifacts"
            sections.append(
                f"### {cmd.title} (`{cmd.key}`)\n\n{cmd.brief}\n\n```bash\n{cmd.cli}\n```\n\n"
                f"Produces: {produces}."
            )
        return "\n\n".join(sections) + "\n"

    def test_commands_markdown(self) -> str:
        """Configured test commands as a bullet list."""
        cmds = self.test_commands()
        if not cmds:
            return "- (no test commands configured in project-config.yaml)\n"
        return "".join(f"- {name}: `{cmd}`\n" for name, cmd in cmds.items())

    def substitutions(self) -> dict[str, str]:
        """Placeholder values for :func:`render_template`."""
        return {
            "project_name": self.project.name,
            "org_policy_name": self.policy.name,
            "role": self.role,
            "hook_command": self.hook_command,
            "workflow": self.workflow_markdown().rstrip("\n"),
            "commands": self.commands_markdown().rstrip("\n"),
            "artifacts": self.artifacts_markdown().rstrip("\n"),
            "tool_policy": self.tool_policy_markdown().rstrip("\n"),
            "policy_summary": self.policy_summary_markdown().rstrip("\n"),
            "test_commands": self.test_commands_markdown().rstrip("\n"),
            "command_briefs": self.command_briefs_markdown().rstrip("\n"),
            "gates": ", ".join(g.value for g in GateId),
        }


_PHASE_TEXT: Mapping[WorkflowPhase, str] = {
    WorkflowPhase.INTAKE: "capture the intent and remove ambiguity before anything else.",
    WorkflowPhase.SPECIFY: "requirements are normative, testable and consistent.",
    WorkflowPhase.PLAN: "tasks with executable verification, grouped into waves; human "
    "approval before implementation.",
    WorkflowPhase.IMPLEMENT: "one task per fresh-context agent in an isolated worktree.",
    WorkflowPhase.REVIEW: "independent review of the actual diff by a different model family.",
    WorkflowPhase.GATE: "deterministic gates G0..G6 over the evidence bundle; fail closed.",
    WorkflowPhase.SECURITY: "adversarial and safety evidence for agent/high-risk changes.",
    WorkflowPhase.COST: "usage and budget variance from the control-plane ledger.",
}


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def default_context(
    project: ProjectConfig | None = None,
    policy: EffectivePolicy | None = None,
    **overrides: object,
) -> AdapterContext:
    """Build a context from defaults (or the given project/policy)."""
    proj = project if project is not None else default_project_config()
    pol = policy if policy is not None else effective_policy(default_org_policy(), proj)
    ctx = AdapterContext(project=proj, policy=pol)
    for key, value in overrides.items():
        if not hasattr(ctx, key):
            raise TypeError(f"unknown AdapterContext field {key!r}")
        setattr(ctx, key, value)
    return ctx


# --------------------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------------------


def adapter_templates_dir() -> Path | None:
    """``templates/adapters`` of this repository when running from a checkout, else ``None``."""
    candidate = Path(__file__).resolve().parents[3] / "templates" / ADAPTER_TEMPLATES_DIR_NAME
    return candidate if candidate.is_dir() else None


def render_template(
    harness: str,
    name: str,
    default: str,
    mapping: Mapping[str, str],
    *,
    templates_dir: Path | None = None,
) -> str:
    """Render ``templates/adapters/<harness>/<name>`` (or *default*) with ``$placeholders``.

    Placeholders that are not in *mapping* are left untouched (``safe_substitute``), so host
    syntax such as ``$ARGUMENTS`` survives.
    """
    base = templates_dir if templates_dir is not None else adapter_templates_dir()
    text = default
    if base is not None:
        path = base / harness / name
        if path.is_file():
            text = path.read_text(encoding="utf-8")
    return Template(text).safe_substitute(mapping)


def join_sections(sections: Sequence[str]) -> str:
    """Join markdown sections with a blank line and a trailing newline."""
    return "\n\n".join(s.rstrip("\n") for s in sections if s.strip()) + "\n"
