"""Change package persistence: directory layout (ARCHITECTURE.md §2.2), load/save,
state derivation, per-kind evidence files, handoffs and the final verdict.

JSON written here is deterministic: sorted keys, two-space indent, trailing newline.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from aisdlc import ids
from aisdlc.schema import fingerprint as fp
from aisdlc.schema import markdown as md
from aisdlc.schema.models import (
    ArchitectureDecision,
    AuditEvidence,
    ChangePackage,
    ChangeState,
    CostEvidence,
    Evidence,
    EvidenceBundle,
    EvidenceKind,
    FinalVerdict,
    Intent,
    Interface,
    PerformanceEvidence,
    Plan,
    Requirement,
    ReviewEvidence,
    ScenarioFile,
    SecurityEvidence,
    TestEvidence,
    ThreatModel,
)

__all__ = [
    "CHANGES_DIR",
    "INTENT_FILE",
    "REQUIREMENTS_FILE",
    "ASSUMPTIONS_FILE",
    "PLAN_FILE",
    "TASKS_FILE",
    "SCENARIOS_DIR",
    "ARCHITECTURE_DIR",
    "CONTEXT_FILE",
    "DECISIONS_DIR",
    "INTERFACES_DIR",
    "THREAT_MODEL_FILE",
    "EVIDENCE_DIR",
    "HANDOFFS_DIR",
    "FINAL_VERDICT_FILE",
    "LIST_EVIDENCE_KINDS",
    "EVIDENCE_TYPES",
    "PackageError",
    "dump_json",
    "write_json",
    "read_json",
    "package_dir",
    "list_packages",
    "create",
    "load",
    "save",
    "adopt",
    "apply_produced_state",
    "save_produced_state",
    "derive_state",
    "evidence_path",
    "read_evidence",
    "write_evidence",
    "append_evidence",
    "load_evidence_bundle",
    "handoffs_dir",
    "list_handoffs",
    "write_handoff",
    "read_handoff",
    "read_final_verdict",
    "write_final_verdict",
    "default_templates_dir",
    "DEFAULT_BODIES",
]

CHANGES_DIR = "changes"
INTENT_FILE = "intent.md"
REQUIREMENTS_FILE = "requirements.md"
ASSUMPTIONS_FILE = "assumptions.md"
PLAN_FILE = "plan.md"
TASKS_FILE = "tasks.md"
SCENARIOS_DIR = "scenarios"
ARCHITECTURE_DIR = "architecture"
CONTEXT_FILE = "architecture/context.md"
DECISIONS_DIR = "architecture/decisions"
INTERFACES_DIR = "architecture/interfaces"
THREAT_MODEL_FILE = "architecture/threat-model.md"
EVIDENCE_DIR = "evidence"
HANDOFFS_DIR = "handoffs"
FINAL_VERDICT_FILE = "final-verdict.json"
AUDIT_ENTRIES_FILE = "audit-entries.json"

LIST_EVIDENCE_KINDS: frozenset[EvidenceKind] = frozenset({EvidenceKind.TESTS, EvidenceKind.REVIEWS})
"""Evidence kinds stored as JSON lists; all others are single objects."""

EVIDENCE_TYPES: dict[EvidenceKind, type[Evidence]] = {
    EvidenceKind.TESTS: TestEvidence,
    EvidenceKind.REVIEWS: ReviewEvidence,
    EvidenceKind.SECURITY: SecurityEvidence,
    EvidenceKind.PERFORMANCE: PerformanceEvidence,
    EvidenceKind.COST: CostEvidence,
    EvidenceKind.AUDIT: AuditEvidence,
}

DEFAULT_BODIES: dict[str, str] = {
    INTENT_FILE: (
        "# Intent\n\n"
        "Describe the change in plain language. The structured kernel lives in the\n"
        "front-matter above: why, capabilities, constraints, non-goals, success signal.\n"
    ),
    REQUIREMENTS_FILE: (
        "# Requirements\n\n"
        "Each requirement in the front-matter uses SHALL/MUST or an EARS form and has at\n"
        "least one WHEN/THEN scenario. Use this body for narrative and rationale.\n"
    ),
    ASSUMPTIONS_FILE: (
        "# Assumptions and open questions\n\n"
        "Assumptions are visible bets; open questions marked `blocking: true` stop G0.\n"
    ),
    PLAN_FILE: (
        "# Plan\n\n"
        "Waves group tasks that can run in parallel. `checkpoint: true` requests a human\n"
        "checkpoint after the wave.\n"
    ),
    TASKS_FILE: (
        "# Tasks\n\nTasks are numbered sequentially and each carries an executable verification.\n"
    ),
    CONTEXT_FILE: (
        "# Architecture context\n\nBounded context, affected components, integration points.\n"
    ),
    THREAT_MODEL_FILE: (
        "# Threat model\n\n"
        "Assets, actors, threats (STRIDE + prompt injection), mitigations and the declared\n"
        "tool/data manifest for agentic changes.\n"
    ),
}

_M = TypeVar("_M", bound=BaseModel)


class PackageError(RuntimeError):
    """A change package is missing required files or contains invalid data."""


# --------------------------------------------------------------------------------------
# JSON helpers
# --------------------------------------------------------------------------------------


def dump_json(data: Any) -> str:
    """Deterministic JSON: sorted keys, indent 2, trailing newline, UTF-8 characters kept."""
    return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def write_json(path: Path, data: Any) -> None:
    """Write *data* as deterministic JSON, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_json(data), encoding="utf-8")


def read_json(path: Path) -> Any:
    """Read a JSON file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PackageError(f"{path}: invalid JSON: {exc}") from exc


def _validate(model_type: type[_M], data: Any, where: Path) -> _M:
    try:
        return model_type.model_validate(data)
    except ValidationError as exc:
        raise PackageError(f"{where}: {exc}") from exc


# --------------------------------------------------------------------------------------
# Locating packages
# --------------------------------------------------------------------------------------


def package_dir(root: str | Path, change_id: str) -> Path:
    """``<root>/changes/<change-id>``."""
    ids.validate_id("CHG", change_id)
    return Path(root) / CHANGES_DIR / change_id


def list_packages(root: str | Path) -> list[Path]:
    """Directories under ``<root>/changes`` that look like change packages."""
    changes = Path(root) / CHANGES_DIR
    if not changes.is_dir():
        return []
    return sorted(p for p in changes.iterdir() if p.is_dir() and (p / INTENT_FILE).is_file())


def default_templates_dir() -> Path | None:
    """``templates/change`` of this repository when running from a checkout, else ``None``."""
    candidate = Path(__file__).resolve().parents[3] / "templates" / "change"
    return candidate if candidate.is_dir() else None


def _template_body(templates_dir: Path | None, relative: str) -> str:
    if templates_dir is not None:
        path = templates_dir / relative
        if path.is_file():
            try:
                _data, body = md.split_front_matter(path.read_text(encoding="utf-8"))
                return body
            except md.FrontMatterError:
                pass
    return DEFAULT_BODIES.get(relative, "")


# --------------------------------------------------------------------------------------
# Create / load / save
# --------------------------------------------------------------------------------------


def create(
    root: str | Path,
    change_id: str,
    intent: Intent,
    *,
    templates_dir: Path | None = None,
    exist_ok: bool = False,
) -> ChangePackage:
    """Create ``<root>/changes/<change_id>/`` with the skeleton layout and return it.

    *intent.id* must equal *change_id*. Prose bodies come from ``templates/change`` when
    available (or *templates_dir*), else from :data:`DEFAULT_BODIES`.
    """
    if intent.id != change_id:
        raise PackageError(f"intent id {intent.id} does not match change id {change_id}")
    directory = package_dir(root, change_id)
    if directory.exists() and not exist_ok:
        raise PackageError(f"change package already exists: {directory}")
    templates = templates_dir if templates_dir is not None else default_templates_dir()
    bodies = {
        rel: _template_body(templates, rel)
        for rel in (
            INTENT_FILE,
            REQUIREMENTS_FILE,
            ASSUMPTIONS_FILE,
            PLAN_FILE,
            TASKS_FILE,
            CONTEXT_FILE,
            THREAT_MODEL_FILE,
        )
    }
    pkg = ChangePackage(
        intent=intent,
        plan=Plan(),
        threat_model=ThreatModel(),
        bodies=bodies,
        root=directory,
    )
    for sub in (SCENARIOS_DIR, DECISIONS_DIR, INTERFACES_DIR, EVIDENCE_DIR, HANDOFFS_DIR):
        (directory / sub).mkdir(parents=True, exist_ok=True)
    save(pkg, directory)
    return pkg


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load(directory: str | Path) -> ChangePackage:
    """Load a change package from its directory.

    Only ``intent.md`` is mandatory; every other artifact is optional. Scenario files
    under ``scenarios/`` are merged into their requirement by scenario id and recorded
    in ``ChangePackage.scenario_files``; for an id listed in both places the scenario
    file wins (it is the more specific artifact, and :func:`save` writes file-owned
    scenarios back to their file only, so the two never diverge after a save).
    """
    root = Path(directory)
    intent_path = root / INTENT_FILE
    if not intent_path.is_file():
        raise PackageError(f"not a change package (missing {INTENT_FILE}): {root}")
    bodies: dict[str, str] = {}

    try:
        intent, bodies[INTENT_FILE] = md.intent_from_markdown(_read_text(intent_path))
    except (md.FrontMatterError, ValidationError) as exc:
        raise PackageError(f"{intent_path}: {exc}") from exc

    requirements: list[Requirement] = []
    if (root / REQUIREMENTS_FILE).is_file():
        try:
            requirements, bodies[REQUIREMENTS_FILE] = md.requirements_from_markdown(
                _read_text(root / REQUIREMENTS_FILE)
            )
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{root / REQUIREMENTS_FILE}: {exc}") from exc

    scenario_files: dict[str, ScenarioFile] = {}
    scenarios_dir = root / SCENARIOS_DIR
    if scenarios_dir.is_dir():
        by_req = {r.id: r for r in requirements}
        owned: dict[str, str] = {}
        for path in sorted(scenarios_dir.glob("*.md")):
            rel = f"{SCENARIOS_DIR}/{path.name}"
            try:
                req_id, scenarios, bodies[rel] = md.scenarios_from_markdown(_read_text(path))
            except (md.FrontMatterError, ValidationError) as exc:
                raise PackageError(f"{path}: {exc}") from exc
            requirement = by_req.get(req_id)
            if requirement is None:
                raise PackageError(f"{path}: scenarios for unknown requirement {req_id}")
            for scenario in scenarios:
                if scenario.id in owned:
                    raise PackageError(
                        f"{path}: scenario {scenario.id} is also defined in {owned[scenario.id]}"
                    )
                owned[scenario.id] = rel
            from_file = {s.id: s for s in scenarios}
            merged = [from_file.pop(s.id, s) for s in requirement.scenarios]
            requirement.scenarios = [*merged, *from_file.values()]
            scenario_files[rel] = ScenarioFile(
                requirement_id=req_id, scenario_ids=[s.id for s in scenarios]
            )

    assumptions: list[Any] = []
    open_questions: list[Any] = []
    if (root / ASSUMPTIONS_FILE).is_file():
        try:
            assumptions, open_questions, bodies[ASSUMPTIONS_FILE] = md.assumptions_from_markdown(
                _read_text(root / ASSUMPTIONS_FILE)
            )
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{root / ASSUMPTIONS_FILE}: {exc}") from exc

    plan: Plan | None = None
    if (root / PLAN_FILE).is_file():
        try:
            plan, bodies[PLAN_FILE] = md.plan_from_markdown(_read_text(root / PLAN_FILE))
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{root / PLAN_FILE}: {exc}") from exc

    tasks: list[Any] = []
    if (root / TASKS_FILE).is_file():
        try:
            tasks, bodies[TASKS_FILE] = md.tasks_from_markdown(_read_text(root / TASKS_FILE))
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{root / TASKS_FILE}: {exc}") from exc

    if (root / CONTEXT_FILE).is_file():
        bodies[CONTEXT_FILE] = _read_text(root / CONTEXT_FILE)

    threat_model: ThreatModel | None = None
    if (root / THREAT_MODEL_FILE).is_file():
        try:
            threat_model, bodies[THREAT_MODEL_FILE] = md.threat_model_from_markdown(
                _read_text(root / THREAT_MODEL_FILE)
            )
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{root / THREAT_MODEL_FILE}: {exc}") from exc

    decisions: list[ArchitectureDecision] = []
    for path in sorted((root / DECISIONS_DIR).glob("ADR-*.md")):
        try:
            adr, bodies[f"{DECISIONS_DIR}/{path.name}"] = md.adr_from_markdown(_read_text(path))
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{path}: {exc}") from exc
        if path.stem != adr.id:
            raise PackageError(f"{path}: file name does not match ADR id {adr.id}")
        decisions.append(adr)

    interfaces: list[Interface] = []
    for path in sorted((root / INTERFACES_DIR).glob("IFC-*.md")):
        try:
            ifc, bodies[f"{INTERFACES_DIR}/{path.name}"] = md.interface_from_markdown(
                _read_text(path)
            )
        except (md.FrontMatterError, ValidationError) as exc:
            raise PackageError(f"{path}: {exc}") from exc
        if path.stem != ifc.id:
            raise PackageError(f"{path}: file name does not match interface id {ifc.id}")
        interfaces.append(ifc)

    evidence = load_evidence_bundle(root)
    final_verdict = read_final_verdict(root)

    try:
        pkg = ChangePackage(
            intent=intent,
            requirements=requirements,
            assumptions=assumptions,
            open_questions=open_questions,
            decisions=decisions,
            interfaces=interfaces,
            threat_model=threat_model,
            plan=plan,
            tasks=tasks,
            evidence=evidence,
            final_verdict=final_verdict,
            bodies=bodies,
            scenario_files=scenario_files,
            root=root,
            base_fingerprint=fp.compute_fingerprint(root),
        )
    except ValidationError as exc:
        raise PackageError(f"{root}: {exc}") from exc
    return pkg


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def save(
    pkg: ChangePackage,
    directory: str | Path | None = None,
    *,
    base_fingerprint: str | None = None,
) -> Path:
    """Write every artifact of *pkg* to *directory* (default: ``pkg.root``).

    When *base_fingerprint* is given the on-disk content must still match it, otherwise
    :class:`~aisdlc.schema.fingerprint.OptimisticConcurrencyError` is raised and nothing
    is written. ``.fingerprint`` is refreshed after every save and ``pkg.base_fingerprint``
    updated.

    Scenarios owned by a scenario file (``pkg.scenario_files``) are written back to that
    file and omitted from ``requirements.md``; a scenario file whose requirement no
    longer exists is removed, and scenario ids that vanished from the requirement are
    dropped from the file's ownership record. Scenarios of requirements without a file
    stay in ``requirements.md``.
    """
    root = Path(directory) if directory is not None else pkg.root
    if root is None:
        raise PackageError("no directory given and package has no root")
    root.mkdir(parents=True, exist_ok=True)

    def body(rel: str) -> str:
        text = pkg.bodies.get(rel, DEFAULT_BODIES.get(rel, ""))
        pkg.bodies[rel] = text  # keep the in-memory package identical to what is on disk
        return text

    def writes() -> None:
        _write_text(root / INTENT_FILE, md.intent_to_markdown(pkg.intent, body(INTENT_FILE)))
        _write_scenario_files(root, pkg, body)
        owned = pkg.file_owned_scenario_ids()
        in_requirements = [
            r.model_copy(update={"scenarios": [s for s in r.scenarios if s.id not in owned]})
            if any(s.id in owned for s in r.scenarios)
            else r
            for r in pkg.requirements
        ]
        _write_text(
            root / REQUIREMENTS_FILE,
            md.requirements_to_markdown(in_requirements, body(REQUIREMENTS_FILE)),
        )
        _write_text(
            root / ASSUMPTIONS_FILE,
            md.assumptions_to_markdown(pkg.assumptions, pkg.open_questions, body(ASSUMPTIONS_FILE)),
        )
        _write_text(root / PLAN_FILE, md.plan_to_markdown(pkg.plan or Plan(), body(PLAN_FILE)))
        _write_text(root / TASKS_FILE, md.tasks_to_markdown(pkg.tasks, body(TASKS_FILE)))
        _write_text(root / CONTEXT_FILE, body(CONTEXT_FILE))
        if pkg.threat_model is not None:
            _write_text(
                root / THREAT_MODEL_FILE,
                md.threat_model_to_markdown(pkg.threat_model, body(THREAT_MODEL_FILE)),
            )
        for adr in pkg.decisions:
            rel = f"{DECISIONS_DIR}/{adr.id}.md"
            _write_text(root / rel, md.adr_to_markdown(adr, body(rel)))
        for ifc in pkg.interfaces:
            rel = f"{INTERFACES_DIR}/{ifc.id}.md"
            _write_text(root / rel, md.interface_to_markdown(ifc, body(rel)))
        for sub in (SCENARIOS_DIR, DECISIONS_DIR, INTERFACES_DIR, EVIDENCE_DIR, HANDOFFS_DIR):
            (root / sub).mkdir(parents=True, exist_ok=True)
        _write_evidence_bundle(root, pkg.evidence)
        if pkg.final_verdict is not None:
            write_final_verdict(root, pkg.final_verdict)

    if base_fingerprint is not None:
        new_fp = fp.check_and_update(root, base_fingerprint, writes)
    else:
        writes()
        new_fp = fp.write_fingerprint(root)
    pkg.root = root
    pkg.base_fingerprint = new_fp
    return root


def _write_scenario_files(root: Path, pkg: ChangePackage, body: Callable[[str], str]) -> None:
    """Write file-owned scenarios back to ``scenarios/*.md`` and prune stale ownership."""
    by_req = {r.id: r for r in pkg.requirements}
    for rel in sorted(pkg.scenario_files):
        ref = pkg.scenario_files[rel]
        path = root / rel
        requirement = by_req.get(ref.requirement_id)
        if requirement is None:
            del pkg.scenario_files[rel]
            pkg.bodies.pop(rel, None)
            if path.is_file():
                path.unlink()
            continue
        current = {s.id: s for s in requirement.scenarios}
        scenarios = [current[sid] for sid in ref.scenario_ids if sid in current]
        ref.scenario_ids = [s.id for s in scenarios]
        _write_text(path, md.scenarios_to_markdown(ref.requirement_id, scenarios, body(rel)))


def adopt(target: ChangePackage, source: ChangePackage) -> ChangePackage:
    """Copy every field of *source* onto *target* in place (keeps *target*'s identity)."""
    for name in ChangePackage.model_fields:
        setattr(target, name, getattr(source, name))
    return target


def apply_produced_state(ours: ChangePackage, theirs: ChangePackage) -> ChangePackage:
    """*theirs* (current on-disk content) with the *produced* state of *ours* applied.

    Used by producers — the orchestrator above all — that never author artifacts but
    record outcomes: task statuses (by task id), plan approval, the evidence bundle and
    the final verdict come from *ours*; intent, requirements, assumptions, architecture,
    prose bodies and any task or plan edits come from *theirs*. Tasks that only exist in
    *ours* are kept (appended) so a run's status is never lost.
    """
    theirs_tasks = {t.id: t for t in theirs.tasks}
    ours_tasks = {t.id: t for t in ours.tasks}
    tasks = [
        t.model_copy(update={"status": ours_tasks[t.id].status}) if t.id in ours_tasks else t
        for t in theirs.tasks
    ]
    tasks.extend(t for tid, t in ours_tasks.items() if tid not in theirs_tasks)
    plan = theirs.plan
    if ours.plan is not None and ours.plan.approved_by:
        plan = (plan or Plan()).model_copy(
            update={"approved_by": ours.plan.approved_by, "approved_at": ours.plan.approved_at}
        )
    merged = theirs.model_copy(
        update={
            "tasks": tasks,
            "plan": plan,
            "evidence": ours.evidence,
            "final_verdict": ours.final_verdict
            if ours.final_verdict is not None
            else theirs.final_verdict,
        }
    )
    merged.root = theirs.root or ours.root
    merged.base_fingerprint = theirs.base_fingerprint
    return merged


def save_produced_state(pkg: ChangePackage) -> Path:
    """Save *pkg* guarded by its base fingerprint; on a concurrent edit, reload and
    reapply only the produced state (:func:`apply_produced_state`) before writing.

    *pkg* is updated in place (:func:`adopt`) so callers keep their reference. Returns
    the package directory.
    """
    if pkg.root is None:
        raise PackageError("package has no root")
    try:
        return save(pkg, base_fingerprint=pkg.base_fingerprint)
    except fp.OptimisticConcurrencyError:
        current = load(pkg.root)
        merged = apply_produced_state(pkg, current)
        save(merged, base_fingerprint=current.base_fingerprint)
        adopt(pkg, merged)
        return merged.root if merged.root is not None else pkg.root


def derive_state(pkg: ChangePackage) -> ChangeState:
    """Workflow state derived from artifacts (see :meth:`ChangePackage.derive_state`)."""
    return pkg.derive_state()


# --------------------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------------------


def evidence_path(directory: str | Path, kind: EvidenceKind | str) -> Path:
    """``<dir>/evidence/<kind>.json``."""
    kind = EvidenceKind(kind)
    return Path(directory) / EVIDENCE_DIR / f"{kind.value}.json"


def audit_entries_path(directory: str | Path) -> Path:
    """``<dir>/evidence/audit-entries.json`` — detailed audit entries beside ``audit.json``.

    ``evidence/audit.json`` holds the canonical :class:`AuditEvidence` summary (counts and
    integrity); the per-call entries the manifest drift check needs live in this sidecar.
    """
    return Path(directory) / EVIDENCE_DIR / AUDIT_ENTRIES_FILE


def read_evidence(directory: str | Path, kind: EvidenceKind | str) -> list[Evidence]:
    """Read evidence of *kind*; always returns a list (empty when the file is absent)."""
    kind = EvidenceKind(kind)
    path = evidence_path(directory, kind)
    if not path.is_file():
        return []
    data = read_json(path)
    model_type = EVIDENCE_TYPES[kind]
    items = data if isinstance(data, list) else [data]
    return [_validate(model_type, item, path) for item in items]


def write_evidence(directory: str | Path, kind: EvidenceKind | str, records: Any) -> Path:
    """Write evidence of *kind*.

    ``tests``/``reviews`` take a list; other kinds take a single record (a one-element list
    is accepted). Records must be of the model type for *kind*.
    """
    kind = EvidenceKind(kind)
    model_type = EVIDENCE_TYPES[kind]
    items: list[Evidence] = list(records) if isinstance(records, list | tuple) else [records]
    for item in items:
        if not isinstance(item, model_type):
            raise PackageError(f"{kind.value} evidence expects {model_type.__name__}")
    path = evidence_path(directory, kind)
    if kind in LIST_EVIDENCE_KINDS:
        write_json(path, [item.model_dump(mode="json") for item in items])
    else:
        if len(items) != 1:
            raise PackageError(f"{kind.value} evidence holds exactly one record")
        write_json(path, items[0].model_dump(mode="json"))
    return path


def append_evidence(directory: str | Path, record: Evidence) -> Path:
    """Append a record to a list kind, or replace the single record of other kinds."""
    kind = EvidenceKind(record.kind)
    if kind in LIST_EVIDENCE_KINDS:
        existing = [e for e in read_evidence(directory, kind) if e.id != record.id]
        return write_evidence(directory, kind, [*existing, record])
    return write_evidence(directory, kind, record)


def load_evidence_bundle(directory: str | Path) -> EvidenceBundle:
    """Read all ``evidence/*.json`` files into an :class:`EvidenceBundle`."""

    def single(kind: EvidenceKind) -> Any:
        items = read_evidence(directory, kind)
        if len(items) > 1:
            raise PackageError(f"{evidence_path(directory, kind)}: expected one record")
        return items[0] if items else None

    return EvidenceBundle(
        tests=[
            e for e in read_evidence(directory, EvidenceKind.TESTS) if isinstance(e, TestEvidence)
        ],
        reviews=[
            e
            for e in read_evidence(directory, EvidenceKind.REVIEWS)
            if isinstance(e, ReviewEvidence)
        ],
        security=single(EvidenceKind.SECURITY),
        performance=single(EvidenceKind.PERFORMANCE),
        cost=single(EvidenceKind.COST),
        audit=single(EvidenceKind.AUDIT),
    )


def _write_evidence_bundle(root: Path, bundle: EvidenceBundle) -> None:
    write_evidence(root, EvidenceKind.TESTS, bundle.tests)
    write_evidence(root, EvidenceKind.REVIEWS, bundle.reviews)
    for kind, record in (
        (EvidenceKind.SECURITY, bundle.security),
        (EvidenceKind.PERFORMANCE, bundle.performance),
        (EvidenceKind.COST, bundle.cost),
        (EvidenceKind.AUDIT, bundle.audit),
    ):
        if record is not None:
            write_evidence(root, kind, record)


# --------------------------------------------------------------------------------------
# Handoffs and final verdict
# --------------------------------------------------------------------------------------


def handoffs_dir(directory: str | Path) -> Path:
    """``<dir>/handoffs`` (created on demand)."""
    path = Path(directory) / HANDOFFS_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


def list_handoffs(directory: str | Path) -> list[Path]:
    """Sorted handoff JSON files."""
    return sorted(handoffs_dir(directory).glob("*.json"))


def write_handoff(directory: str | Path, name: str, data: Any) -> Path:
    """Write ``handoffs/<name>.json`` deterministically; *data* may be a model or dict."""
    if isinstance(data, BaseModel):
        data = data.model_dump(mode="json")
    safe = name[:-5] if name.endswith(".json") else name
    if "/" in safe or safe in {"", ".", ".."}:
        raise PackageError(f"invalid handoff name {name!r}")
    path = handoffs_dir(directory) / f"{safe}.json"
    write_json(path, data)
    return path


def read_handoff(directory: str | Path, name: str) -> Any:
    """Read ``handoffs/<name>.json``."""
    safe = name[:-5] if name.endswith(".json") else name
    return read_json(handoffs_dir(directory) / f"{safe}.json")


def read_final_verdict(directory: str | Path) -> FinalVerdict | None:
    """Read ``final-verdict.json`` if present."""
    path = Path(directory) / FINAL_VERDICT_FILE
    if not path.is_file():
        return None
    return _validate(FinalVerdict, read_json(path), path)


def write_final_verdict(directory: str | Path, verdict: FinalVerdict) -> Path:
    """Write ``final-verdict.json``."""
    path = Path(directory) / FINAL_VERDICT_FILE
    write_json(path, verdict.model_dump(mode="json"))
    return path
