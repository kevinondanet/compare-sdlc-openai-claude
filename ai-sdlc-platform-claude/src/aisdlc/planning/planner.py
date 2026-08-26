"""Requirements -> tasks with executable verification; dependency waves; checkpoints.

Everything here is a pure function over schema models. The planner never runs agents
and never writes files; :func:`apply_plan` only mutates an in-memory package.

Task derivation
===============

* One **implementation task** per requirement group. A group is a single requirement, or
  (``PlannerConfig.group_by_tag``) every requirement sharing its first tag. Each carries
  an executable :class:`~aisdlc.schema.models.Verification` built from the project's
  unit test command (``pytest …`` gets the task's test file appended, e.g.
  ``pytest -q tests/test_req001_login.py``; other runners are used verbatim).
* One **test task** (``include_test_task``) that runs the full unit/coverage command and
  depends on every implementation task.
* One **docs task** (``include_docs_task``) that updates documentation and verifies the
  change package with ``aisdlc change validate``; tier ``low`` (mechanical work).

Dependencies (``depends_on``) between implementation tasks are inferred from:

1. explicit ordering — ``PlannerConfig.ordering`` (``REQ -> [prerequisite REQs]``),
   tags ``after:REQ-nnn`` / ``depends:REQ-nnn`` and ``REQ-nnn`` ids mentioned in a
   requirement's text/rationale (a requirement that cites another builds on it);
2. interface references — the requirement that *provides* an interface (tag
   ``provides:IFC-nnn`` or ``Interface.provider == REQ-nnn``) precedes every requirement
   that mentions the interface id or is listed in ``Interface.consumers``;
3. ADR references — an ADR whose context/decision cites requirement ids orders them in
   citation order (first cited first) when the ADR is accepted.

Model tier hints: ``high`` for requirements with security/architecture vocabulary,
ADR/interface references or ambiguity markers; ``standard`` otherwise; ``low`` for the
docs task.

Waves are topological levels of the dependency graph (Kahn); a cycle raises
:class:`DependencyCycleError` naming the cycle. Human checkpoints follow the
:class:`~aisdlc.planning.risk.GateDepthProfile`: plan approval (``Plan.approved_by``),
a checkpoint on the wave preceding any wave with privileged (tier >= 3) work, and a
checkpoint on the last wave before release.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from typing import Final

from pydantic import Field

from aisdlc import ids
from aisdlc.planning import risk as riskmod
from aisdlc.policy.org_policy import OrgPolicy
from aisdlc.policy.project_config import RISK_ORDER, ProjectConfig
from aisdlc.schema import grammar
from aisdlc.schema.models import (
    AdrStatus,
    ArchitectureDecision,
    ArtifactModel,
    ChangePackage,
    Interface,
    ModelTier,
    Plan,
    Priority,
    Requirement,
    RiskClass,
    Task,
    Verification,
    Wave,
)
from aisdlc.schema.package import DEFAULT_BODIES, PLAN_FILE

__all__ = [
    "PlanningError",
    "DependencyCycleError",
    "PlannerConfig",
    "PlanResult",
    "ARCHITECTURE_KEYWORDS",
    "PRIVILEGED_KEYWORDS",
    "PLAN_FINGERPRINT_MARKER",
    "requirements_fingerprint",
    "read_plan_fingerprint",
    "stamp_plan_fingerprint",
    "requirement_slug",
    "verification_for",
    "infer_dependencies",
    "model_tier_for",
    "is_privileged_task",
    "derive_tasks",
    "compute_waves",
    "find_cycle",
    "build_plan",
    "generate_plan",
    "apply_plan",
]


class PlanningError(RuntimeError):
    """The plan cannot be derived (unknown references, invalid configuration …)."""


class DependencyCycleError(PlanningError):
    """The task dependency graph contains a cycle."""

    def __init__(self, cycle: Sequence[str]) -> None:
        self.cycle = list(cycle)
        super().__init__("dependency cycle: " + " -> ".join(self.cycle))


class PlannerConfig(ArtifactModel):
    """Knobs for :func:`derive_tasks` / :func:`generate_plan`."""

    include_test_task: bool = True
    include_docs_task: bool = True
    group_by_tag: bool = Field(
        default=False, description="Group requirements sharing their first tag into one task."
    )
    include_wont: bool = Field(default=False, description="Plan ``wont`` requirements too.")
    test_dir: str = "tests"
    unit_command: str | None = Field(
        default=None, description="Overrides ``ProjectConfig.test_commands.unit``."
    )
    docs_command: str | None = Field(
        default=None, description="Overrides the docs task verification command."
    )
    ordering: dict[str, list[str]] = Field(
        default_factory=dict, description="REQ id -> prerequisite REQ ids (explicit ordering)."
    )


class PlanResult(ArtifactModel):
    """Outcome of :func:`generate_plan`."""

    tasks: list[Task]
    plan: Plan
    profile: riskmod.GateDepthProfile
    assessment: riskmod.RiskAssessment
    requirements_fingerprint: str
    notes: list[str] = Field(default_factory=list)


ARCHITECTURE_KEYWORDS: Final[tuple[str, ...]] = (
    "architecture",
    "architectural",
    "migration",
    "schema",
    "protocol",
    "concurrency",
    "concurrent",
    "distributed",
    "consistency",
    "transaction",
    "transactions",
    "interface",
    "contract",
    "cache",
    "caching",
    "idempotent",
    "idempotency",
    "retry",
    "backpressure",
    "scalab",
)
"""Vocabulary that marks a requirement as architecture-sensitive (tier ``high``)."""

PRIVILEGED_KEYWORDS: Final[tuple[str, ...]] = (
    "deploy",
    "deployment",
    "release",
    "publish",
    "rollout",
    "roll out",
    "migrate",
    "migration",
    "rotate",
    "secret",
    "secrets",
    "iam",
    "permission",
    "permissions",
    "delete data",
    "drop table",
    "truncate",
    "push",
    "pull request",
    "merge",
    "backlog",
    "install",
    "registry",
    "production",
    "infra",
    "infrastructure",
)
"""Task vocabulary implying tier >= 3 tool actions (shared state / irreversible)."""

PLAN_FINGERPRINT_MARKER: Final[str] = "aisdlc:requirements-fingerprint"
"""HTML-comment marker stored in ``plan.md``'s body: the requirements the plan was built for."""

_MARKER_RE = re.compile(rf"<!--\s*{re.escape(PLAN_FINGERPRINT_MARKER)}=([0-9a-f]{{64}})\s*-->")
_REQ_RE = re.compile(r"\bREQ-\d{3,}\b")
_IFC_RE = re.compile(r"\bIFC-\d{3,}\b")
_ADR_RE = re.compile(r"\bADR-\d{4,}\b")
_MODAL_RE = re.compile(r"\b(the system|shall|must|should|when|then|if|while|where)\b", re.I)


def _word_pattern(phrase: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w-])" + re.escape(phrase) + r"(?![\w-])", re.IGNORECASE)


_ARCH_PATTERNS = [re.compile(re.escape(k), re.IGNORECASE) for k in ARCHITECTURE_KEYWORDS]
_PRIVILEGED_PATTERNS = [_word_pattern(k) for k in PRIVILEGED_KEYWORDS]


# --------------------------------------------------------------------------------------
# Requirements fingerprint (plan staleness)
# --------------------------------------------------------------------------------------


def requirements_fingerprint(requirements: Sequence[Requirement]) -> str:
    """sha256 over the canonical JSON of *requirements* (order-insensitive by id)."""
    payload = [r.model_dump(mode="json") for r in sorted(requirements, key=lambda r: r.id)]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def read_plan_fingerprint(body: str) -> str | None:
    """The requirements fingerprint stamped in a ``plan.md`` body, if any."""
    match = _MARKER_RE.search(body)
    return match.group(1) if match else None


def stamp_plan_fingerprint(body: str, fingerprint: str) -> str:
    """Return *body* with the marker set to *fingerprint* (replacing an older marker)."""
    marker = f"<!-- {PLAN_FINGERPRINT_MARKER}={fingerprint} -->"
    if _MARKER_RE.search(body):
        return _MARKER_RE.sub(marker, body, count=1)
    if body and not body.endswith("\n"):
        body += "\n"
    return f"{body}{marker}\n"


# --------------------------------------------------------------------------------------
# Per-requirement helpers
# --------------------------------------------------------------------------------------


def requirement_slug(requirement: Requirement, *, max_words: int = 4) -> str:
    """``req001_<first words>`` — a filesystem/identifier-safe slug for a requirement."""
    number = ids.numeric_suffix(requirement.id)
    words = [w for w in re.findall(r"[A-Za-z0-9]+", _MODAL_RE.sub(" ", requirement.text))]
    stem = "_".join(w.lower() for w in words[:max_words])
    return f"req{number:03d}" + (f"_{stem}" if stem else "")


def _group_slug(requirements: Sequence[Requirement], tag: str | None) -> str:
    if tag is not None:
        return ids.slugify(tag, max_length=40).replace("-", "_")
    return requirement_slug(requirements[0])


def verification_for(
    slug: str, project_config: ProjectConfig, config: PlannerConfig | None = None
) -> Verification:
    """Verification for an implementation task named *slug*.

    ``pytest``-style unit commands get ``<test_dir>/test_<slug>.py`` appended; any other
    runner is used verbatim (it is expected to pick up the new test file itself).
    """
    cfg = config or PlannerConfig()
    unit = cfg.unit_command or project_config.test_commands.unit or "pytest -q"
    test_path = f"{cfg.test_dir}/test_{slug}.py"
    try:
        argv = shlex.split(unit)
    except ValueError as exc:
        raise PlanningError(f"unit test command cannot be parsed: {exc}") from exc
    if argv and "pytest" in argv[0]:
        return Verification(command=f"{unit} {test_path}", expect_exit_code=0)
    return Verification(command=unit, expect_exit_code=0)


def _requirement_text(requirement: Requirement) -> str:
    return " ".join(
        [
            requirement.text,
            requirement.rationale or "",
            *requirement.tags,
            *(s.text for s in requirement.scenarios),
        ]
    )


def model_tier_for(
    requirement: Requirement,
    *,
    interfaces: Iterable[Interface] = (),
    decisions: Iterable[ArchitectureDecision] = (),
) -> ModelTier:
    """Routing hint for the implementation task of *requirement* (see module docstring)."""
    text = _requirement_text(requirement)
    if any(
        RISK_ORDER[s.risk_class] >= RISK_ORDER[RiskClass.HIGH]
        for s in riskmod.find_keyword_signals(text, requirement.id)
    ):
        return ModelTier.HIGH
    if _IFC_RE.search(text) or _ADR_RE.search(text):
        return ModelTier.HIGH
    if any(p.search(text) for p in _ARCH_PATTERNS):
        return ModelTier.HIGH
    if grammar.find_ambiguity_markers(text, requirement.id):
        return ModelTier.HIGH
    ifc_ids = {i.id for i in interfaces if i.provider == requirement.id}
    if ifc_ids:
        return ModelTier.HIGH
    for adr in decisions:
        if requirement.id in _REQ_RE.findall(f"{adr.context} {adr.decision}"):
            return ModelTier.HIGH
    return ModelTier.STANDARD


def is_privileged_task(task: Task) -> bool:
    """``True`` when the task's title/description implies tier >= 3 tool actions."""
    text = f"{task.title} {task.description}"
    return any(p.search(text) for p in _PRIVILEGED_PATTERNS)


# --------------------------------------------------------------------------------------
# Dependency inference (requirement level)
# --------------------------------------------------------------------------------------


def infer_dependencies(
    requirements: Sequence[Requirement],
    *,
    interfaces: Iterable[Interface] = (),
    decisions: Iterable[ArchitectureDecision] = (),
    config: PlannerConfig | None = None,
) -> dict[str, list[str]]:
    """``REQ id -> sorted prerequisite REQ ids`` (rules in the module docstring).

    Only known requirement ids are returned; self references are dropped. Unknown ids in
    ``config.ordering`` raise :class:`PlanningError`.
    """
    cfg = config or PlannerConfig()
    known = {r.id for r in requirements}
    deps: dict[str, set[str]] = {r.id: set() for r in requirements}

    def add(req: str, prereq: str) -> None:
        if req in known and prereq in known and req != prereq:
            deps[req].add(prereq)

    for req_id, prereqs in cfg.ordering.items():
        if req_id not in known:
            raise PlanningError(f"ordering references unknown requirement {req_id}")
        for prereq in prereqs:
            if prereq not in known:
                raise PlanningError(f"ordering references unknown requirement {prereq}")
            add(req_id, prereq)

    for requirement in requirements:
        for tag in requirement.tags:
            key, _, value = tag.partition(":")
            if key.lower() in ("after", "depends", "depends_on", "requires"):
                add(requirement.id, value.strip())
        cited = _REQ_RE.findall(f"{requirement.text} {requirement.rationale or ''}")
        for other in cited:
            add(requirement.id, other)

    providers: dict[str, str] = {}
    for requirement in requirements:
        for tag in requirement.tags:
            key, _, value = tag.partition(":")
            if key.lower() == "provides" and ids.is_valid("IFC", value.strip()):
                providers[value.strip()] = requirement.id
    for interface in interfaces:
        if interface.provider and ids.is_valid("REQ", interface.provider):
            providers.setdefault(interface.id, interface.provider)
    for interface in interfaces:
        provider = providers.get(interface.id)
        if provider is None:
            continue
        consumers = {c for c in interface.consumers if ids.is_valid("REQ", c)}
        for requirement in requirements:
            if interface.id in _IFC_RE.findall(_requirement_text(requirement)):
                consumers.add(requirement.id)
        for consumer in consumers:
            add(consumer, provider)

    for adr in decisions:
        if adr.status is not AdrStatus.ACCEPTED:
            continue
        ordered: list[str] = []
        for req_id in _REQ_RE.findall(f"{adr.context} {adr.decision}"):
            if req_id in known and req_id not in ordered:
                ordered.append(req_id)
        for earlier, later in zip(ordered, ordered[1:], strict=False):
            add(later, earlier)

    return {req_id: sorted(prereqs) for req_id, prereqs in deps.items()}


# --------------------------------------------------------------------------------------
# Task derivation
# --------------------------------------------------------------------------------------


def _groups(
    requirements: Sequence[Requirement], config: PlannerConfig
) -> list[tuple[str | None, list[Requirement]]]:
    if not config.group_by_tag:
        return [(None, [r]) for r in requirements]
    ordered: dict[str, list[Requirement]] = {}
    singles: list[tuple[str | None, list[Requirement]]] = []
    for requirement in requirements:
        tag = next((t for t in requirement.tags if ":" not in t), None)
        if tag is None:
            singles.append((None, [requirement]))
        else:
            ordered.setdefault(tag, []).append(requirement)
    return [*((tag, reqs) for tag, reqs in ordered.items()), *singles]


def _truncate(text: str, limit: int = 60) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def derive_tasks(
    requirements: Sequence[Requirement],
    project_config: ProjectConfig | None = None,
    *,
    interfaces: Iterable[Interface] = (),
    decisions: Iterable[ArchitectureDecision] = (),
    config: PlannerConfig | None = None,
    change_dir: str | None = None,
) -> list[Task]:
    """Derive sequential tasks (``TASK-001`` …) from *requirements*.

    *change_dir* is the change package path used in the docs task's verification command
    (defaults to ``changes/<id>`` relative form when unknown, via ``.``).
    """
    cfg = config or PlannerConfig()
    project = project_config if project_config is not None else ProjectConfig()
    interface_list = list(interfaces)
    decision_list = list(decisions)
    planned = [r for r in requirements if cfg.include_wont or r.priority is not Priority.WONT]
    prereqs = infer_dependencies(
        planned, interfaces=interface_list, decisions=decision_list, config=cfg
    )

    tasks: list[Task] = []
    task_of_req: dict[str, str] = {}
    group_specs: list[tuple[str, str | None, list[Requirement]]] = []
    for tag, group in _groups(planned, cfg):
        task_id = ids.next_id("TASK", [t.id for t in tasks] + [g[0] for g in group_specs])
        group_specs.append((task_id, tag, group))
        for requirement in group:
            task_of_req[requirement.id] = task_id

    for task_id, tag, group in group_specs:
        slug = _group_slug(group, tag)
        req_ids = [r.id for r in group]
        depends = sorted(
            {
                task_of_req[p]
                for r in group
                for p in prereqs.get(r.id, [])
                if p in task_of_req and task_of_req[p] != task_id
            }
        )
        tier = ModelTier.STANDARD
        for requirement in group:
            candidate = model_tier_for(
                requirement, interfaces=interface_list, decisions=decision_list
            )
            if candidate.rank > tier.rank:
                tier = candidate
        if tag is not None:
            title = f"Implement {tag}: {', '.join(req_ids)}"
        else:
            title = f"Implement {group[0].id}: {_truncate(group[0].text)}"
        description_lines = [f"{r.id}: {r.text}" for r in group]
        refs = sorted(
            set(_IFC_RE.findall(" ".join(_requirement_text(r) for r in group)))
            | set(_ADR_RE.findall(" ".join(_requirement_text(r) for r in group)))
        )
        if refs:
            description_lines.append("References: " + ", ".join(refs))
        tasks.append(
            Task(
                id=task_id,
                title=title,
                description="\n".join(description_lines),
                requirement_ids=req_ids,
                depends_on=depends,
                verification=verification_for(slug, project, cfg),
                model_tier=tier,
                files=[f"{cfg.test_dir}/test_{slug}.py"],
            )
        )

    implementation_ids = [t.id for t in tasks]
    all_req_ids = [r.id for r in planned]

    if cfg.include_test_task and planned:
        command = (
            project.test_commands.coverage
            or cfg.unit_command
            or project.test_commands.unit
            or "pytest -q"
        )
        tasks.append(
            Task(
                id=ids.next_id("TASK", [t.id for t in tasks]),
                title="Run the full test suite with coverage",
                description=(
                    "Extend and run the whole unit suite so every scenario of "
                    f"{', '.join(all_req_ids)} is exercised."
                ),
                requirement_ids=all_req_ids,
                depends_on=implementation_ids,
                verification=Verification(command=command, expect_exit_code=0),
                model_tier=ModelTier.STANDARD,
            )
        )

    if cfg.include_docs_task and planned:
        target = change_dir or "."
        command = cfg.docs_command or f"aisdlc change validate {shlex.quote(target)}"
        tasks.append(
            Task(
                id=ids.next_id("TASK", [t.id for t in tasks]),
                title="Update documentation and change package",
                description=(
                    "Update user/developer docs and the change package prose for "
                    f"{', '.join(all_req_ids)}; the package must validate cleanly."
                ),
                requirement_ids=all_req_ids,
                depends_on=implementation_ids,
                verification=Verification(command=command, expect_exit_code=0),
                model_tier=ModelTier.LOW,
                files=["docs/"],
            )
        )
    return tasks


# --------------------------------------------------------------------------------------
# Waves
# --------------------------------------------------------------------------------------


def find_cycle(graph: Mapping[str, Iterable[str]]) -> list[str] | None:
    """First dependency cycle in *graph* (``node -> prerequisites``), as ``[a, b, a]``."""
    state: dict[str, int] = {}
    stack: list[str] = []
    found: list[str] | None = None

    def visit(node: str) -> None:
        nonlocal found
        if found is not None:
            return
        state[node] = 1
        stack.append(node)
        for dep in graph.get(node, ()):
            if dep not in graph:
                continue
            if state.get(dep, 0) == 1:
                found = stack[stack.index(dep) :] + [dep]
                return
            if state.get(dep, 0) == 0:
                visit(dep)
                if found is not None:
                    return
        stack.pop()
        state[node] = 2

    for node in graph:
        if state.get(node, 0) == 0:
            visit(node)
        if found is not None:
            break
    return found


def compute_waves(tasks: Sequence[Task]) -> list[list[str]]:
    """Topological levels: wave *n* holds tasks whose prerequisites all sit in waves < n.

    Raises :class:`PlanningError` on unknown dependencies and
    :class:`DependencyCycleError` on cycles. Task ids inside a wave are sorted.
    """
    graph: dict[str, list[str]] = {}
    for task in tasks:
        if task.id in graph:
            raise PlanningError(f"duplicate task id {task.id}")
        graph[task.id] = list(task.depends_on)
    for task_id, deps in graph.items():
        for dep in deps:
            if dep not in graph:
                raise PlanningError(f"{task_id} depends on unknown task {dep}")
    cycle = find_cycle(graph)
    if cycle is not None:
        raise DependencyCycleError(cycle)

    level: dict[str, int] = {}
    remaining = set(graph)
    while remaining:
        ready = sorted(t for t in remaining if all(d in level for d in graph[t]))
        if not ready:  # pragma: no cover - cycles are caught above
            raise DependencyCycleError(sorted(remaining))
        for task_id in ready:
            level[task_id] = max((level[d] + 1 for d in graph[task_id]), default=0)
        remaining.difference_update(ready)
    waves: dict[int, list[str]] = {}
    for task_id, wave in level.items():
        waves.setdefault(wave, []).append(task_id)
    return [sorted(waves[i]) for i in sorted(waves)]


def build_plan(
    tasks: Sequence[Task],
    profile: riskmod.GateDepthProfile,
    *,
    summary: str = "",
) -> tuple[list[Task], Plan]:
    """Assign waves to *tasks* and build a :class:`Plan` with checkpoints for *profile*.

    Returns new task copies (``wave`` set) and the plan. Checkpoint rules:

    * ``checkpoint_before_tier3`` — the wave before any wave containing a privileged task
      gets ``checkpoint=True`` (privileged work in wave 0 is covered by plan approval);
    * ``checkpoint_before_release`` — the last wave gets ``checkpoint=True``.
    """
    wave_ids = compute_waves(tasks)
    by_id = {t.id: t for t in tasks}
    privileged = {t.id for t in tasks if is_privileged_task(t)}
    updated: list[Task] = []
    for index, members in enumerate(wave_ids):
        for task_id in members:
            updated.append(by_id[task_id].model_copy(update={"wave": index}))
    updated.sort(key=lambda t: ids.numeric_suffix(t.id))

    waves: list[Wave] = []
    for index, members in enumerate(wave_ids):
        reasons: list[str] = []
        next_privileged = index + 1 < len(wave_ids) and any(
            t in privileged for t in wave_ids[index + 1]
        )
        if profile.checkpoint_before_tier3 and next_privileged:
            reasons.append("before privileged (tier >= 3) work in the next wave")
        if profile.checkpoint_before_release and index == len(wave_ids) - 1:
            reasons.append("before release")
        description = "; ".join(f"{by_id[t].title}" for t in members)
        if reasons:
            description += " | checkpoint: " + "; ".join(reasons)
        waves.append(
            Wave(index=index, task_ids=members, checkpoint=bool(reasons), description=description)
        )
    return updated, Plan(summary=summary, waves=waves)


# --------------------------------------------------------------------------------------
# Whole package
# --------------------------------------------------------------------------------------


def generate_plan(
    pkg: ChangePackage,
    project_config: ProjectConfig | None = None,
    *,
    config: PlannerConfig | None = None,
    policy: OrgPolicy | None = None,
    profile: riskmod.GateDepthProfile | None = None,
) -> PlanResult:
    """Derive tasks and a wave plan for *pkg* (pure; use :func:`apply_plan` to store it).

    The risk class comes from :func:`aisdlc.planning.risk.classify` (never lower than
    the declared one) unless *profile* is given.
    """
    cfg = config or PlannerConfig()
    project = project_config if project_config is not None else ProjectConfig()
    manifest = pkg.threat_model.tool_data_manifest if pkg.threat_model is not None else None
    paths = [f for t in pkg.tasks for f in t.files]
    assessment = riskmod.classify(pkg.intent, pkg.requirements, project, manifest, paths=paths)
    effective_profile = (
        profile if profile is not None else riskmod.gate_depth_profile(assessment.effective, policy)
    )
    change_dir = str(pkg.root) if pkg.root is not None else f"changes/{pkg.change_id}"
    tasks = derive_tasks(
        pkg.requirements,
        project,
        interfaces=pkg.interfaces,
        decisions=pkg.decisions,
        config=cfg,
        change_dir=change_dir,
    )
    notes: list[str] = list(assessment.reasons)
    if not tasks:
        notes.append("no plannable requirements; empty plan")
    summary = (
        f"{len(tasks)} task(s) for {len(pkg.requirements)} requirement(s); "
        f"risk class {effective_profile.risk_class.value}"
    )
    scheduled, plan = build_plan(tasks, effective_profile, summary=summary)
    if effective_profile.plan_approval_required:
        notes.append("plan approval required before wave 0 (set plan.approved_by)")
    privileged_first = [t.id for t in scheduled if t.wave == 0 and is_privileged_task(t)]
    if privileged_first and effective_profile.checkpoint_before_tier3:
        notes.append(
            "privileged work in wave 0 ("
            + ", ".join(privileged_first)
            + ") relies on plan approval"
        )
    return PlanResult(
        tasks=scheduled,
        plan=plan,
        profile=effective_profile,
        assessment=assessment,
        requirements_fingerprint=requirements_fingerprint(pkg.requirements),
        notes=notes,
    )


def apply_plan(pkg: ChangePackage, result: PlanResult) -> ChangePackage:
    """Store *result* in *pkg* (tasks, plan, fingerprint marker in the plan body)."""
    pkg.tasks = list(result.tasks)
    pkg.plan = result.plan
    body = pkg.bodies.get(PLAN_FILE, DEFAULT_BODIES.get(PLAN_FILE, ""))
    pkg.bodies[PLAN_FILE] = stamp_plan_fingerprint(body, result.requirements_fingerprint)
    return pkg
