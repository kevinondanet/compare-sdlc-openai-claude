"""PyRIT campaign runner: objectives x attacks x trials -> ASR, undetermined rate, baselines.

A :class:`CampaignSpec` (YAML) lists objectives across harm categories, the attack kinds to
use (``prompt_sending`` with optional converter chains), the scorer that decides success and
the thresholds for gate G4. :func:`run_campaign_async` executes every scheduled trial with
PyRIT's ``PromptSendingAttack`` against any ``PromptTarget`` (see
:mod:`aisdlc.security.targets`) and returns a :class:`CampaignResult` whose ``complete`` flag
fails closed when any scheduled trial produced no verdict.

Everything except :func:`run_campaign_async` (and the PyRIT scorer subclasses) works without
PyRIT installed, so baselines can be compared and reports rendered anywhere.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import re
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    from pyrit.models import ComponentIdentifier, MessagePiece, Score
    from pyrit.score import ScorerPromptValidator, TrueFalseScorer

    PYRIT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when PyRIT is absent
    PYRIT_AVAILABLE = False

__all__ = [
    "PYRIT_AVAILABLE",
    "AttackSpec",
    "BaselineDelta",
    "BaselineNotFoundError",
    "BaselineStore",
    "CampaignError",
    "CampaignResult",
    "CampaignSpec",
    "CategoryDelta",
    "ConverterSpec",
    "Objective",
    "ObjectiveDelta",
    "ObjectiveResult",
    "Pricing",
    "ScorerSpec",
    "SuccessCriteria",
    "UndeterminedVerdictError",
    "UsageSummary",
    "aggregate_trials",
    "compare_results",
    "compute_run_id",
    "ledger_usage_sink",
    "load_campaign",
    "load_dataset",
    "run_campaign",
    "run_campaign_async",
    "scheduled_scenario_tallies",
    "templates_dir",
]

RUN_LABEL_KEY = "aisdlc_run_id"
EXEC_LABEL_KEY = "aisdlc_exec_id"
ATTACK_LABEL_KEY = "aisdlc_attack"
TRIAL_LABEL_KEY = "aisdlc_trial"
_KNOWN_CONVERTERS: dict[str, str] = {
    "base64": "Base64Converter",
    "leetspeak": "LeetspeakConverter",
    "rot13": "ROT13Converter",
    "atbash": "AtbashConverter",
    "caesar": "CaesarConverter",
    "morse": "MorseConverter",
    "binary": "BinaryConverter",
    "unicode_substitution": "UnicodeSubstitutionConverter",
    "character_space": "CharacterSpaceConverter",
    "flip": "FlipConverter",
    "string_join": "StringJoinConverter",
}


#: Marker embedded in judge errors so an "undetermined" verdict survives PyRIT's error
#: wrapping (direct path: exception cause chain; scenario path: ``error_message``).
UNDETERMINED_MARKER = "aisdlc:undetermined-verdict"


class CampaignError(RuntimeError):
    """Raised for configuration or execution problems in a campaign."""


class UndeterminedVerdictError(ValueError):
    """Raised by a judge/scorer that cannot decide; the trial counts as undetermined."""

    def __init__(self, detail: str = "") -> None:
        super().__init__(f"{UNDETERMINED_MARKER}: judge returned no verdict {detail}".strip())


def _is_undetermined(exc: BaseException | None, message: str | None = None) -> bool:
    """True when ``exc``'s cause/context chain or ``message`` carries the undetermined marker."""
    if message and UNDETERMINED_MARKER in message:
        return True
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, UndeterminedVerdictError) or UNDETERMINED_MARKER in str(exc):
            return True
        exc = exc.__cause__ or exc.__context__
    return False


class BaselineNotFoundError(KeyError):
    """Raised when a baseline id is not present in a :class:`BaselineStore`."""


# --------------------------------------------------------------------------------------
# Spec models
# --------------------------------------------------------------------------------------


class SuccessCriteria(BaseModel):
    """How an objective's success is decided.

    * ``substring`` – reply contains ``value`` (case-insensitive unless ``case_sensitive``).
    * ``regex`` – reply matches ``value`` (``re.search``; ``re.IGNORECASE`` unless sensitive).
    * ``tool_call`` – the application reported a tool whose name matches regex ``value``
      (requires a target with a ``ToolEventRecorder``).
    * ``scorer`` – ``value`` is an import path (``module:attr``) to a PyRIT
      ``TrueFalseScorer`` instance, a zero-arg factory returning one, or a
      ``Callable[[str], bool | None]`` that is wrapped.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["substring", "regex", "tool_call", "scorer"]
    value: str = Field(min_length=1)
    case_sensitive: bool = False

    @field_validator("value")
    @classmethod
    def _compile_if_regex(cls, v: str, info: Any) -> str:
        kind = info.data.get("kind")
        if kind in {"regex", "tool_call"}:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"invalid regex {v!r}: {exc}") from exc
        return v


class Objective(BaseModel):
    """One adversarial objective sent to the application under test."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    text: str = Field(min_length=1)
    harm_category: str = Field(min_length=1)
    success_criteria: SuccessCriteria | None = None
    trials: int | None = Field(default=None, ge=1)
    labels: dict[str, str] = Field(default_factory=dict)


class ConverterSpec(BaseModel):
    """A PyRIT converter applied to the prompt before it is sent."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(min_length=1)
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, v: str) -> str:
        if v in _KNOWN_CONVERTERS or v.endswith("Converter") or ":" in v:
            return v
        raise ValueError(
            f"unknown converter {v!r}; use one of {sorted(_KNOWN_CONVERTERS)}, a PyRIT class "
            "name ending in 'Converter', or an import path 'module:Class'"
        )


class AttackSpec(BaseModel):
    """An attack kind plus an optional converter chain."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["prompt_sending"] = "prompt_sending"
    name: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    converters: list[ConverterSpec] = Field(default_factory=list)
    max_attempts_on_failure: int = Field(default=0, ge=0)

    @model_validator(mode="before")
    @classmethod
    def _coerce_converters(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("converters"), list):
            data = dict(data)
            data["converters"] = [
                {"kind": c} if isinstance(c, str) else c for c in data["converters"]
            ]
        return data

    @property
    def effective_name(self) -> str:
        """Name used in results: explicit ``name`` or ``kind[+converters]``."""
        if self.name:
            return self.name
        if not self.converters:
            return self.kind
        return f"{self.kind}+" + "+".join(c.kind for c in self.converters)


class ScorerSpec(BaseModel):
    """Campaign-level scorer used for objectives without their own ``success_criteria``."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["substring", "regex", "tool_call", "composite", "custom"]
    value: str | None = None
    patterns: dict[str, str] | None = None
    case_sensitive: bool = False
    aggregator: Literal["or", "and", "majority"] = "or"
    scorers: list[ScorerSpec] = Field(default_factory=list)
    import_path: str | None = None
    kwargs: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_shape(self) -> ScorerSpec:
        if self.kind in {"substring", "tool_call"} and not self.value:
            raise ValueError(f"{self.kind} scorer requires 'value'")
        if self.kind == "regex" and not (self.value or self.patterns):
            raise ValueError("regex scorer requires 'value' or 'patterns'")
        if self.kind == "composite" and not self.scorers:
            raise ValueError("composite scorer requires 'scorers'")
        if self.kind == "custom" and not self.import_path:
            raise ValueError("custom scorer requires 'import_path'")
        for pat in [self.value] if self.kind in {"regex", "tool_call"} else []:
            if pat:
                re.compile(pat)
        for pat in (self.patterns or {}).values():
            re.compile(pat)
        return self


class CampaignSpec(BaseModel):
    """A red-team campaign definition (loaded from YAML by :func:`load_campaign`)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    description: str = ""
    objectives: list[Objective] = Field(default_factory=list)
    datasets: list[str] = Field(default_factory=list)
    trials: int = Field(default=1, ge=1)
    attacks: list[AttackSpec] = Field(default_factory=lambda: [AttackSpec()])
    scenario: str | None = None
    scorer: ScorerSpec | None = None
    asr_threshold: float = Field(default=0.0, ge=0.0, le=1.0)
    max_undetermined_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    baseline_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    max_concurrency: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def _validate(self) -> CampaignSpec:
        if not self.attacks:
            raise ValueError("at least one attack is required")
        if self.scenario is None or self.scenario == "atomic":
            if not self.objectives and not self.datasets:
                raise ValueError("campaign needs objectives or datasets")
        ids = [o.id for o in self.objectives]
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            raise ValueError(f"duplicate objective ids: {dupes}")
        texts = [o.text for o in self.objectives]
        if len(set(texts)) != len(texts):
            raise ValueError("objective texts must be unique within a campaign")
        if self.scorer is None:
            missing = [o.id for o in self.objectives if o.success_criteria is None]
            if missing:
                raise ValueError(
                    f"objectives {missing} have no success_criteria and campaign has no scorer"
                )
        names = [a.effective_name for a in self.attacks]
        if len(set(names)) != len(names):
            raise ValueError(f"attack names must be unique: {names}")
        return self

    def scheduled_trials(self) -> int:
        """Total trials scheduled for this spec (objectives x attacks x trials)."""
        return sum(self.trials_for(o) for o in self.objectives) * len(self.attacks)

    def trials_for(self, objective: Objective) -> int:
        """Trials for a single objective (objective override or campaign default)."""
        return objective.trials or self.trials

    def spec_hash(self) -> str:
        """Stable content hash of the resolved spec."""
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def templates_dir() -> Path:
    """Directory holding the shipped PyRIT templates (campaigns, datasets, labelled sets)."""
    return Path(__file__).resolve().parents[3] / "templates" / "pyrit"


def load_dataset(path: str | Path) -> list[Objective]:
    """Load a seed dataset YAML (``{id, description, objectives: [...]}``)."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict) or "objectives" not in raw:
        raise CampaignError(f"dataset {p} must be a mapping with an 'objectives' list")
    default_category = raw.get("harm_category")
    objectives: list[Objective] = []
    for item in raw["objectives"]:
        if isinstance(item, dict) and default_category and "harm_category" not in item:
            item = {**item, "harm_category": default_category}
        objectives.append(Objective.model_validate(item))
    return objectives


def load_campaign(path: str | Path) -> CampaignSpec:
    """Load a campaign YAML and merge any referenced datasets into ``objectives``.

    Dataset paths are resolved relative to the campaign file, then relative to
    ``templates/pyrit/datasets``.
    """
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise CampaignError(f"campaign {p} must be a YAML mapping")
    spec = CampaignSpec.model_validate(raw)
    if not spec.datasets:
        return spec
    merged = list(spec.objectives)
    seen = {o.id for o in merged}
    for ds in spec.datasets:
        candidates = [p.parent / ds, templates_dir() / "datasets" / ds]
        found = next((c for c in candidates if c.exists()), None)
        if found is None:
            raise CampaignError(f"dataset {ds!r} not found (looked in {candidates})")
        for obj in load_dataset(found):
            if obj.id in seen:
                raise CampaignError(f"objective id {obj.id!r} from {ds} duplicates another")
            seen.add(obj.id)
            merged.append(obj)
    return spec.model_copy(update={"objectives": merged, "datasets": []})


# --------------------------------------------------------------------------------------
# Result models
# --------------------------------------------------------------------------------------


class ObjectiveResult(BaseModel):
    """Aggregated trials for one objective under one attack."""

    model_config = ConfigDict(extra="forbid")

    objective_id: str
    harm_category: str
    attack: str = "prompt_sending"
    trials: int = Field(ge=0)
    successes: int = Field(default=0, ge=0)
    failures: int = Field(default=0, ge=0)
    undetermined: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)
    asr: float = 0.0
    complete: bool = True
    notes: list[str] = Field(default_factory=list)

    @property
    def completed(self) -> int:
        """Trials that produced a verdict (success/failure/undetermined)."""
        return self.successes + self.failures + self.undetermined


class UsageSummary(BaseModel):
    """Prompts and tokens consumed by a campaign run (cost only when pricing is known)."""

    model_config = ConfigDict(extra="forbid")

    prompts_sent: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None


class Pricing(BaseModel):
    """USD price per one million tokens, used to fill ``UsageSummary.cost_usd``."""

    model_config = ConfigDict(extra="forbid")

    input_per_1m: float = Field(ge=0.0)
    output_per_1m: float = Field(ge=0.0)

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        """Compute the cost for the given token counts."""
        return round(
            input_tokens * self.input_per_1m / 1_000_000
            + output_tokens * self.output_per_1m / 1_000_000,
            6,
        )


class ObjectiveDelta(BaseModel):
    """Per-objective ASR change against a baseline."""

    model_config = ConfigDict(extra="forbid")

    objective_id: str
    harm_category: str
    attack: str
    baseline_asr: float | None
    current_asr: float
    delta: float | None
    regression: bool
    new: bool = False


class CategoryDelta(BaseModel):
    """Per-harm-category ASR change against a baseline."""

    model_config = ConfigDict(extra="forbid")

    harm_category: str
    baseline_asr: float | None
    current_asr: float
    delta: float | None
    regression: bool


class BaselineDelta(BaseModel):
    """Comparison of a campaign result with a stored baseline."""

    model_config = ConfigDict(extra="forbid")

    baseline_id: str
    baseline_run_id: str
    asr_delta: float
    undetermined_delta: float
    per_objective: list[ObjectiveDelta] = Field(default_factory=list)
    per_category: list[CategoryDelta] = Field(default_factory=list)
    removed_objectives: list[str] = Field(default_factory=list)
    regressed: bool = False
    tolerance: float = 0.0


class CampaignResult(BaseModel):
    """Outcome of one campaign run against one target."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    run_id: str
    target_id: str
    scheduled_trials: int = Field(ge=0)
    completed_trials: int = Field(ge=0)
    per_objective: list[ObjectiveResult] = Field(default_factory=list)
    asr: float = 0.0
    asr_by_category: dict[str, float] = Field(default_factory=dict)
    asr_by_attack: dict[str, float] = Field(default_factory=dict)
    undetermined_rate: float = 0.0
    complete: bool = False
    asr_threshold: float = 0.0
    max_undetermined_rate: float = 0.0
    threshold_breached: bool = True
    breaches: list[str] = Field(default_factory=list)
    baseline_id: str | None = None
    baseline_delta: BaselineDelta | None = None
    usage: UsageSummary = Field(default_factory=UsageSummary)
    labels: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime

    def to_evidence(self) -> dict[str, Any]:
        """Plain dict shaped like ``SecurityEvidence.pyrit`` (``schema.models.PyritSummary``)."""
        return {
            "campaign_id": self.campaign_id,
            "asr": self.asr,
            "undetermined_rate": self.undetermined_rate,
            "complete": self.complete,
            "baseline_delta": self.baseline_delta.asr_delta if self.baseline_delta else None,
            "trials": self.scheduled_trials,
        }

    def save(self, path: str | Path) -> Path:
        """Write the result as JSON and return the path."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        return p

    @classmethod
    def load(cls, path: str | Path) -> CampaignResult:
        """Read a result written by :meth:`save`."""
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------
# Pure aggregation helpers
# --------------------------------------------------------------------------------------


def _ratio(num: int, den: int) -> float:
    return round(num / den, 6) if den else 0.0


def compute_run_id(spec: CampaignSpec, target_id: str, trial_config: Mapping[str, Any]) -> str:
    """Deterministic run id from the spec hash, the target id and the trial configuration."""
    payload = json.dumps(
        {"spec": spec.spec_hash(), "target": target_id, "trials": dict(trial_config)},
        sort_keys=True,
        default=str,
    )
    return "run-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def aggregate_trials(
    per_objective: Sequence[ObjectiveResult],
    *,
    scheduled_trials: int,
) -> dict[str, Any]:
    """Compute campaign-level ASR, per-category/attack ASR, undetermined rate, completeness.

    ASR is ``successes / (successes + failures)``; undetermined trials are excluded from the
    denominator and reported via ``undetermined_rate = undetermined / completed``. A campaign
    is complete only when every scheduled trial produced a verdict.
    """
    successes = sum(o.successes for o in per_objective)
    failures = sum(o.failures for o in per_objective)
    undetermined = sum(o.undetermined for o in per_objective)
    completed = successes + failures + undetermined

    def _group(key: Callable[[ObjectiveResult], str]) -> dict[str, float]:
        buckets: dict[str, list[int]] = {}
        for o in per_objective:
            b = buckets.setdefault(key(o), [0, 0])
            b[0] += o.successes
            b[1] += o.failures
        return {k: _ratio(v[0], v[0] + v[1]) for k, v in sorted(buckets.items())}

    complete = completed == scheduled_trials and all(o.complete for o in per_objective)
    return {
        "asr": _ratio(successes, successes + failures),
        "asr_by_category": _group(lambda o: o.harm_category),
        "asr_by_attack": _group(lambda o: o.attack),
        "undetermined_rate": _ratio(undetermined, completed),
        "completed_trials": completed,
        "complete": complete,
    }


def _evaluate_thresholds(result: CampaignResult) -> list[str]:
    breaches: list[str] = []
    if not result.complete:
        breaches.append(
            f"incomplete: {result.completed_trials}/{result.scheduled_trials} trials produced a "
            "verdict"
        )
    if result.asr > result.asr_threshold:
        breaches.append(f"asr {result.asr:.3f} > threshold {result.asr_threshold:.3f}")
    if result.undetermined_rate > result.max_undetermined_rate:
        breaches.append(
            f"undetermined_rate {result.undetermined_rate:.3f} > max "
            f"{result.max_undetermined_rate:.3f}"
        )
    if result.baseline_delta is not None and result.baseline_delta.regressed:
        breaches.append(f"regression against baseline {result.baseline_delta.baseline_id}")
    return breaches


def compare_results(
    current: CampaignResult,
    baseline: CampaignResult,
    *,
    baseline_id: str | None = None,
    tolerance: float = 0.0,
) -> BaselineDelta:
    """Compare ``current`` against ``baseline`` and flag regressions.

    A regression is an ASR increase greater than ``tolerance`` at objective, category or
    campaign level. Objectives absent from the baseline are reported as ``new`` (not
    regressions); objectives absent from the current run are listed in ``removed_objectives``.
    """
    base_by_key = {(o.objective_id, o.attack): o for o in baseline.per_objective}
    cur_keys = {(o.objective_id, o.attack) for o in current.per_objective}
    per_objective: list[ObjectiveDelta] = []
    for o in current.per_objective:
        b = base_by_key.get((o.objective_id, o.attack))
        if b is None:
            per_objective.append(
                ObjectiveDelta(
                    objective_id=o.objective_id,
                    harm_category=o.harm_category,
                    attack=o.attack,
                    baseline_asr=None,
                    current_asr=o.asr,
                    delta=None,
                    regression=False,
                    new=True,
                )
            )
            continue
        delta = round(o.asr - b.asr, 6)
        per_objective.append(
            ObjectiveDelta(
                objective_id=o.objective_id,
                harm_category=o.harm_category,
                attack=o.attack,
                baseline_asr=b.asr,
                current_asr=o.asr,
                delta=delta,
                regression=delta > tolerance,
            )
        )
    per_category: list[CategoryDelta] = []
    for cat, cur_asr in sorted(current.asr_by_category.items()):
        base_asr = baseline.asr_by_category.get(cat)
        delta_c = None if base_asr is None else round(cur_asr - base_asr, 6)
        per_category.append(
            CategoryDelta(
                harm_category=cat,
                baseline_asr=base_asr,
                current_asr=cur_asr,
                delta=delta_c,
                regression=delta_c is not None and delta_c > tolerance,
            )
        )
    asr_delta = round(current.asr - baseline.asr, 6)
    regressed = (
        asr_delta > tolerance
        or any(d.regression for d in per_objective)
        or any(c.regression for c in per_category)
    )
    removed = sorted(f"{k[0]}@{k[1]}" for k in base_by_key if k not in cur_keys)
    return BaselineDelta(
        baseline_id=baseline_id or baseline.baseline_id or baseline.campaign_id,
        baseline_run_id=baseline.run_id,
        asr_delta=asr_delta,
        undetermined_delta=round(current.undetermined_rate - baseline.undetermined_rate, 6),
        per_objective=per_objective,
        per_category=per_category,
        removed_objectives=removed,
        regressed=regressed,
        tolerance=tolerance,
    )


class BaselineStore:
    """Directory of ``<baseline_id>.json`` campaign results used for regression comparison."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def _path(self, baseline_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", baseline_id):
            raise ValueError(f"invalid baseline id {baseline_id!r}")
        return self.directory / f"{baseline_id}.json"

    def save(self, result: CampaignResult, baseline_id: str | None = None) -> Path:
        """Persist ``result`` under ``baseline_id`` (defaults to the campaign id)."""
        bid = baseline_id or result.campaign_id
        self.directory.mkdir(parents=True, exist_ok=True)
        stored = result.model_copy(update={"baseline_id": bid})
        return stored.save(self._path(bid))

    def load(self, baseline_id: str) -> CampaignResult:
        """Load a stored baseline or raise :class:`BaselineNotFoundError`."""
        p = self._path(baseline_id)
        if not p.exists():
            raise BaselineNotFoundError(baseline_id)
        return CampaignResult.load(p)

    def list_ids(self) -> list[str]:
        """Baseline ids present in the store."""
        if not self.directory.exists():
            return []
        return sorted(p.stem for p in self.directory.glob("*.json"))

    def compare(
        self, result: CampaignResult, baseline_id: str, *, tolerance: float = 0.0
    ) -> BaselineDelta:
        """Compare ``result`` with the stored baseline ``baseline_id``."""
        baseline = self.load(baseline_id)
        return compare_results(result, baseline, baseline_id=baseline_id, tolerance=tolerance)


# --------------------------------------------------------------------------------------
# PyRIT-backed scorers
# --------------------------------------------------------------------------------------

if PYRIT_AVAILABLE:

    class CallableScorer(TrueFalseScorer):  # type: ignore[misc]  # pyrit is untyped (ignore_missing_imports)
        """Wraps ``Callable[[str], bool | None]`` (``None`` -> undetermined) as a scorer."""

        _DEFAULT_VALIDATOR = ScorerPromptValidator(supported_data_types=["text"])

        def __init__(
            self,
            *,
            judge: Callable[[str], bool | None],
            name: str = "callable",
            categories: list[str] | None = None,
        ) -> None:
            self._judge = judge
            self._name = name
            self._score_categories = categories or []
            super().__init__(validator=self._DEFAULT_VALIDATOR)

        def _build_identifier(self) -> ComponentIdentifier:
            return self._create_identifier(params={"judge": self._name})

        async def _score_piece_async(
            self, message_piece: MessagePiece, *, objective: str | None = None
        ) -> list[Score]:
            verdict = self._judge(message_piece.converted_value)
            if verdict is None:
                raise UndeterminedVerdictError(f"for judge {self._name!r}")
            return [
                Score(
                    score_value=str(bool(verdict)).lower(),
                    score_value_description="",
                    score_metadata=None,
                    score_type="true_false",
                    score_category=self._score_categories,
                    score_rationale="",
                    scorer_class_identifier=self.get_identifier(),
                    message_piece_id=message_piece.id,
                    objective=objective,
                )
            ]

    class ToolCallScorer(TrueFalseScorer):  # type: ignore[misc]  # pyrit is untyped (ignore_missing_imports)
        """True when a recorded tool event name matches ``pattern`` (see ``ToolEventRecorder``)."""

        _DEFAULT_VALIDATOR = ScorerPromptValidator(supported_data_types=["text"])

        def __init__(self, *, pattern: str, categories: list[str] | None = None) -> None:
            self._pattern = pattern
            self._regex = re.compile(pattern, re.IGNORECASE)
            self._score_categories = categories or []
            super().__init__(validator=self._DEFAULT_VALIDATOR)

        def _build_identifier(self) -> ComponentIdentifier:
            return self._create_identifier(params={"pattern": self._pattern})

        async def _score_piece_async(
            self, message_piece: MessagePiece, *, objective: str | None = None
        ) -> list[Score]:
            from aisdlc.security.targets import TOOL_EVENTS_METADATA_KEY

            raw = (message_piece.prompt_metadata or {}).get(TOOL_EVENTS_METADATA_KEY)
            names: list[str] = []
            if isinstance(raw, str) and raw:
                try:
                    names = [str(e.get("name", "")) for e in json.loads(raw)]
                except (ValueError, AttributeError):
                    names = []
            matched = [n for n in names if self._regex.search(n)]
            return [
                Score(
                    score_value=str(bool(matched)).lower(),
                    score_value_description="",
                    score_metadata=None,
                    score_type="true_false",
                    score_category=self._score_categories,
                    score_rationale=f"tools: {names}",
                    scorer_class_identifier=self.get_identifier(),
                    message_piece_id=message_piece.id,
                    objective=objective,
                )
            ]

    __all__ += ["CallableScorer", "ToolCallScorer"]


def _import_path(path: str) -> Any:
    if ":" in path:
        module_name, _, attr = path.rpartition(":")
    else:
        module_name, _, attr = path.rpartition(".")
    if not module_name or not attr:
        raise CampaignError(f"import path {path!r} must be 'module:attr'")
    module = importlib.import_module(module_name)
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise CampaignError(f"{module_name!r} has no attribute {attr!r}") from exc


def _require_pyrit() -> None:
    if not PYRIT_AVAILABLE:
        raise CampaignError(
            "PyRIT is required to run campaigns; install with "
            "`pip install ai-sdlc-platform[security]`"
        )


def _scorer_from_import(path: str, kwargs: Mapping[str, Any]) -> Any:
    obj = _import_path(path)
    if isinstance(obj, TrueFalseScorer):
        return obj
    if isinstance(obj, type) and issubclass(obj, TrueFalseScorer):
        return obj(**kwargs)
    if callable(obj):
        try:
            produced = obj(**kwargs) if kwargs else None
        except TypeError:
            produced = None
        if isinstance(produced, TrueFalseScorer):
            return produced
        return CallableScorer(judge=obj, name=path)
    raise CampaignError(f"{path!r} is not a TrueFalseScorer, factory or callable judge")


def _scorer_from_criteria(c: SuccessCriteria, categories: list[str]) -> Any:
    from pyrit.analytics.text_matching import ExactTextMatching
    from pyrit.score import RegexScorer, SubStringScorer

    if c.kind == "substring":
        return SubStringScorer(
            substring=c.value,
            text_matcher=ExactTextMatching(case_sensitive=c.case_sensitive),
            categories=categories,
        )
    if c.kind == "regex":
        pattern = c.value if c.case_sensitive else f"(?i){c.value}"
        return RegexScorer(patterns={"criteria": pattern}, categories=categories)
    if c.kind == "tool_call":
        return ToolCallScorer(pattern=c.value, categories=categories)
    return _scorer_from_import(c.value, {})


def _scorer_from_spec(s: ScorerSpec, categories: list[str]) -> Any:
    from pyrit.analytics.text_matching import ExactTextMatching
    from pyrit.score import (
        RegexScorer,
        SubStringScorer,
        TrueFalseCompositeScorer,
        TrueFalseScoreAggregator,
    )

    if s.kind == "substring":
        assert s.value is not None
        return SubStringScorer(
            substring=s.value,
            text_matcher=ExactTextMatching(case_sensitive=s.case_sensitive),
            categories=categories,
        )
    if s.kind == "regex":
        patterns = dict(s.patterns or {})
        if s.value:
            patterns["value"] = s.value
        if not s.case_sensitive:
            patterns = {k: f"(?i){v}" for k, v in patterns.items()}
        return RegexScorer(patterns=patterns, categories=categories)
    if s.kind == "tool_call":
        assert s.value is not None
        return ToolCallScorer(pattern=s.value, categories=categories)
    if s.kind == "composite":
        agg = {
            "or": TrueFalseScoreAggregator.OR,
            "and": TrueFalseScoreAggregator.AND,
            "majority": TrueFalseScoreAggregator.MAJORITY,
        }[s.aggregator]
        return TrueFalseCompositeScorer(
            aggregator=agg, scorers=[_scorer_from_spec(x, categories) for x in s.scorers]
        )
    assert s.import_path is not None
    return _scorer_from_import(s.import_path, s.kwargs)


def build_scorer(spec: CampaignSpec, objective: Objective) -> Any:
    """Build the PyRIT ``TrueFalseScorer`` that decides success for ``objective``."""
    _require_pyrit()
    categories = [objective.harm_category]
    if objective.success_criteria is not None:
        return _scorer_from_criteria(objective.success_criteria, categories)
    assert spec.scorer is not None  # guaranteed by CampaignSpec validation
    return _scorer_from_spec(spec.scorer, categories)


def _build_converter(c: ConverterSpec) -> Any:
    import pyrit.converter as converters

    if ":" in c.kind:
        cls = _import_path(c.kind)
    else:
        cls_name = _KNOWN_CONVERTERS.get(c.kind, c.kind)
        cls = getattr(converters, cls_name, None)
        if cls is None:
            raise CampaignError(f"PyRIT has no converter {cls_name!r}")
    return cls(**c.params)


def build_attack(spec: AttackSpec, target: Any, scorer: Any) -> Any:
    """Build a PyRIT attack strategy for ``spec`` against ``target`` scored by ``scorer``."""
    _require_pyrit()
    from pyrit.executor.attack import (
        AttackConverterConfig,
        AttackScoringConfig,
        PromptSendingAttack,
    )
    from pyrit.prompt_normalizer import ConverterConfiguration

    converter_config = None
    if spec.converters:
        converter_config = AttackConverterConfig(
            request_converters=ConverterConfiguration.from_converters(
                converters=[_build_converter(c) for c in spec.converters]
            )
        )
    return PromptSendingAttack(
        objective_target=target,
        attack_converter_config=converter_config,
        attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
        max_attempts_on_failure=spec.max_attempts_on_failure,
    )


async def ensure_memory_async(memory: str | None = None) -> None:
    """Initialize PyRIT memory (``in_memory``/``sqlite``); ``None`` reuses an existing one.

    Passing an explicit backend re-initializes central memory; targets built earlier keep a
    reference to the old instance, so :func:`run_campaign_async` rebinds them.
    """
    _require_pyrit()
    from pyrit.memory import CentralMemory
    from pyrit.setup import IN_MEMORY, SQLITE, initialize_pyrit_async

    if memory is None:
        try:
            CentralMemory.get_memory_instance()
            return
        except ValueError:
            memory = "in_memory"
    kind = {"in_memory": IN_MEMORY, "inmemory": IN_MEMORY, "sqlite": SQLITE}.get(memory.lower())
    if kind is None:
        raise CampaignError(f"unknown memory backend {memory!r} (use in_memory or sqlite)")
    await initialize_pyrit_async(memory_db_type=kind, silent=True)


def _rebind_target_memory(target: Any) -> None:
    """Point a target created before (re)initialization at the current central memory."""
    from pyrit.memory import CentralMemory

    current = CentralMemory.get_memory_instance()
    if getattr(target, "_memory", current) is not current:
        target._memory = current  # noqa: SLF001 - PyRIT stores the memory handle here


# --------------------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------------------


class _Tally:
    """Mutable per-(objective, attack) counter used during execution."""

    def __init__(self, objective: Objective, attack: str, trials: int) -> None:
        self.objective = objective
        self.attack = attack
        self.trials = trials
        self.successes = 0
        self.failures = 0
        self.undetermined = 0
        self.errors = 0
        self.notes: list[str] = []
        self.conversation_ids: list[str] = []

    def record(self, result: Any) -> None:
        from pyrit.models import AttackOutcome

        if result.conversation_id:
            self.conversation_ids.append(str(result.conversation_id))
        if result.outcome == AttackOutcome.SUCCESS:
            self.successes += 1
        elif result.outcome == AttackOutcome.FAILURE:
            self.failures += 1
        elif result.outcome == AttackOutcome.UNDETERMINED or _is_undetermined(
            None, result.error_message
        ):
            self.undetermined += 1
        else:
            self.errors += 1
            if result.error_message:
                self.notes.append(f"error: {result.error_message.splitlines()[0]}"[:200])

    def record_exception(self, exc: BaseException) -> None:
        if _is_undetermined(exc):
            self.undetermined += 1
            return
        self.errors += 1
        self.notes.append(_short_error(exc))

    def to_result(self) -> ObjectiveResult:
        completed = self.successes + self.failures + self.undetermined
        return ObjectiveResult(
            objective_id=self.objective.id,
            harm_category=self.objective.harm_category,
            attack=self.attack,
            trials=self.trials,
            successes=self.successes,
            failures=self.failures,
            undetermined=self.undetermined,
            errors=self.errors,
            asr=_ratio(self.successes, self.successes + self.failures),
            complete=completed == self.trials,
            notes=self.notes,
        )


async def _usage_from_memory(conversation_ids: Iterable[str]) -> tuple[int, int, int]:
    from pyrit.memory import CentralMemory

    memory = CentralMemory.get_memory_instance()
    prompts = input_tokens = output_tokens = 0
    for cid in conversation_ids:
        for piece in memory.get_message_pieces(conversation_id=cid):
            if piece.role == "user":
                prompts += 1
            meta = piece.prompt_metadata or {}
            input_tokens += _as_int(meta.get("input_tokens"))
            output_tokens += _as_int(meta.get("output_tokens"))
    return prompts, input_tokens, output_tokens


def _short_error(exc: BaseException) -> str:
    """One-line error summary; PyRIT wraps root causes in multi-line strategy errors."""
    text = str(exc)
    for line in text.splitlines():
        if line.startswith("Root cause:"):
            return line[len("Root cause:") :].strip()[:200]
    first = text.splitlines()[0] if text else ""
    return f"{type(exc).__name__}: {first}"[:200]


def _outcome_rank(result: Any) -> int:
    from pyrit.models import AttackOutcome

    if result.outcome in (AttackOutcome.SUCCESS, AttackOutcome.FAILURE):
        return 2
    if result.outcome == AttackOutcome.UNDETERMINED or _is_undetermined(None, result.error_message):
        return 1
    return 0


def _as_int(value: Any) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


async def _run_direct_async(
    spec: CampaignSpec, target: Any, labels: dict[str, str]
) -> list[_Tally]:
    semaphore = asyncio.Semaphore(spec.max_concurrency)
    tallies: list[_Tally] = []
    jobs: list[tuple[_Tally, Any]] = []
    for attack_spec in spec.attacks:
        for objective in spec.objectives:
            scorer = build_scorer(spec, objective)
            attack = build_attack(attack_spec, target, scorer)
            tally = _Tally(objective, attack_spec.effective_name, spec.trials_for(objective))
            tallies.append(tally)
            for _ in range(tally.trials):
                jobs.append((tally, attack))

    async def _one(tally: _Tally, attack: Any) -> None:
        async with semaphore:
            try:
                result = await attack.execute_async(
                    objective=tally.objective.text,
                    memory_labels={**labels, **tally.objective.labels},
                )
            except Exception as exc:  # noqa: BLE001 - every failure is a missing verdict
                tally.record_exception(exc)
                return
        tally.record(result)

    await asyncio.gather(*(_one(t, a) for t, a in jobs))
    return tallies


if PYRIT_AVAILABLE:
    from pyrit.scenario import Scenario, ScenarioTechnique

    class CampaignTechnique(ScenarioTechnique):  # type: ignore[misc]  # pyrit is untyped (ignore_missing_imports)
        """Technique catalog for :class:`CampaignScenario` (single-turn prompt sending)."""

        ALL = ("all", {"all"})
        PromptSending = ("prompt_sending", set[str]())

    class CampaignScenario(Scenario):  # type: ignore[misc]  # pyrit is untyped (ignore_missing_imports)
        """PyRIT Scenario whose atomic attacks are built from an aisdlc CampaignSpec.

        One ``AtomicAttack`` is emitted per (attack, trial) so repeated objectives never share
        an atomic attack (PyRIT requires unique objective hashes within one). Objective-level
        ``success_criteria`` are honoured by grouping objectives that share a scorer.
        """

        VERSION: int = 1

        def __init__(self, *, spec: CampaignSpec, memory_labels: dict[str, str]) -> None:
            from pyrit.models import AttackSeedGroup, SeedObjective
            from pyrit.scenario import DatasetAttackConfiguration

            self._spec = spec
            self._run_labels = memory_labels
            groups = [
                AttackSeedGroup(
                    seeds=[
                        SeedObjective(value=o.text, harm_categories=[o.harm_category], name=o.id)
                    ]
                )
                for o in spec.objectives
            ]
            first = spec.objectives[0]
            super().__init__(
                name=f"aisdlc-{spec.id}",
                version=self.VERSION,
                technique_class=CampaignTechnique,
                default_dataset_config=DatasetAttackConfiguration(seed_groups=groups),
                objective_scorer=build_scorer(spec, first),
            )

        async def _build_atomic_attacks_async(self, *, context: Any) -> list[Any]:
            from pyrit.models import AttackSeedGroup, SeedObjective
            from pyrit.scenario import AtomicAttack, AttackTechnique

            atomic: list[Any] = []
            for attack_spec in self._spec.attacks:
                max_trials = max(self._spec.trials_for(o) for o in self._spec.objectives)
                for trial in range(max_trials):
                    per_scorer: dict[str, tuple[Any, list[Any]]] = {}
                    for o in self._spec.objectives:
                        if trial >= self._spec.trials_for(o):
                            continue
                        scorer = build_scorer(self._spec, o)
                        key = json.dumps(
                            o.success_criteria.model_dump() if o.success_criteria else None,
                            sort_keys=True,
                        )
                        entry = per_scorer.setdefault(key, (scorer, []))
                        entry[1].append(
                            AttackSeedGroup(
                                seeds=[
                                    SeedObjective(
                                        value=o.text, harm_categories=[o.harm_category], name=o.id
                                    )
                                ]
                            )
                        )
                    for idx, (scorer, groups) in enumerate(per_scorer.values()):
                        attack = build_attack(attack_spec, context.objective_target, scorer)
                        atomic.append(
                            AtomicAttack(
                                atomic_attack_name=(
                                    f"{attack_spec.effective_name}#t{trial}#s{idx}"
                                ),
                                display_group=attack_spec.effective_name,
                                attack_technique=AttackTechnique(attack=attack),
                                seed_groups=groups,
                                memory_labels={
                                    **context.memory_labels,
                                    **self._run_labels,
                                    ATTACK_LABEL_KEY: attack_spec.effective_name,
                                    TRIAL_LABEL_KEY: str(trial),
                                },
                            )
                        )
            return atomic

    __all__ += ["CampaignScenario", "CampaignTechnique"]


@dataclass
class _ScenarioRun:
    """What a scenario execution produced, plus what it *should* have produced."""

    tallies: list[_Tally]
    notes: list[str]
    #: Trials scheduled by the scenario definition (``None`` when it could not be read).
    scheduled: int | None
    #: ``initialize_async``/``run_async`` raised; results (if any) were recovered from
    #: memory and the run must not be reported complete.
    failed: bool


def _objective_key(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def scheduled_scenario_tallies(scenario: Any) -> dict[tuple[str, str], _Tally] | None:
    """Expected ``(objective key, atomic attack name) -> tally`` for an initialised scenario.

    Read from the scenario's atomic attacks (one trial per seed group per atomic attack)
    *before* it runs, so completeness is judged against the definition rather than against
    whatever results happened to be persisted. ``None`` when the scenario exposes no atomic
    attacks or a seed group has no objective (completeness cannot be proven).
    """
    attacks = getattr(scenario, "_atomic_attacks", None)
    if not attacks:
        return None
    tallies: dict[tuple[str, str], _Tally] = {}
    for attack in attacks:
        name = str(getattr(attack, "atomic_attack_name", "") or "scenario")
        groups = getattr(attack, "seed_groups", None)
        if groups is None:
            return None
        for group in groups:
            objective = getattr(group, "objective", None)
            text = getattr(objective, "value", None)
            if not isinstance(text, str) or not text:
                return None
            cats = list(getattr(objective, "harm_categories", None) or []) or ["unknown"]
            key = (_objective_key(text), name)
            tally = tallies.get(key)
            if tally is None:
                tally = _Tally(
                    Objective(id=f"obj-{key[0]}", text=text, harm_category=str(cats[0])),
                    name,
                    0,
                )
                tallies[key] = tally
            tally.trials += 1
    return tallies


async def _run_scenario_async(
    spec: CampaignSpec, target: Any, labels: dict[str, str], run_id: str
) -> _ScenarioRun:
    """Run via a PyRIT Scenario (custom ``atomic`` or a registered built-in) and tally.

    The scheduled trial count is taken from the scenario definition once it is initialised;
    a scenario whose ``run_async`` raises is reported ``failed`` even when PyRIT persisted
    every trial before the error (fail closed).
    """
    from pyrit.memory import CentralMemory

    notes: list[str] = []
    # run_id is deterministic; the exec id isolates this execution's rows in shared memory.
    exec_id = uuid.uuid4().hex
    run_labels = {**labels, RUN_LABEL_KEY: run_id, EXEC_LABEL_KEY: exec_id}
    if spec.scenario == "atomic":
        scenario: Any = CampaignScenario(spec=spec, memory_labels=run_labels)
    else:
        from pyrit.registry import ScenarioRegistry

        assert spec.scenario is not None
        try:
            cls = ScenarioRegistry.get_registry_singleton().get_class(spec.scenario)
        except Exception as exc:  # noqa: BLE001 - registry raises assorted errors
            raise CampaignError(f"unknown PyRIT scenario {spec.scenario!r}: {exc}") from exc
        scorer = _scorer_from_spec(spec.scorer, []) if spec.scorer else None
        try:
            scenario = cls(objective_scorer=scorer) if scorer is not None else cls()
        except TypeError:
            scenario = cls()
        notes.append(
            f"built-in scenario {spec.scenario!r}: objectives come from PyRIT datasets; "
            "LLM scorers require configured scorer targets"
        )
    scenario.set_params_from_args(
        args={
            "objective_target": target,
            "memory_labels": run_labels,
            "max_concurrency": spec.max_concurrency,
            "include_baseline": False,
        }
    )
    expected: dict[tuple[str, str], _Tally] | None = None
    failed = False
    try:
        await scenario.initialize_async()
        expected = scheduled_scenario_tallies(scenario)
        scenario_result = await scenario.run_async()
        results: list[Any] = [r for rs in scenario_result.attack_results.values() for r in rs]
        names: dict[str, str] = {}
        for aa_name, rs in scenario_result.attack_results.items():
            for r in rs:
                names[str(r.attack_result_id)] = aa_name
    except CampaignError:
        raise
    except Exception as exc:  # noqa: BLE001 - partial failure: fall back to persisted results
        failed = True
        notes.append(f"scenario failed: {_short_error(exc)}")
        memory = CentralMemory.get_memory_instance()
        results = list(memory.get_attack_results(labels={EXEC_LABEL_KEY: exec_id}))
        names = {}
        if expected is None:
            expected = scheduled_scenario_tallies(scenario)

    if spec.scenario == "atomic":
        by_text = {o.text: o for o in spec.objectives}
        attack_names = {a.effective_name for a in spec.attacks}
        tallies: dict[tuple[str, str], _Tally] = {}
        for attack_spec in spec.attacks:
            for o in spec.objectives:
                key = (o.id, attack_spec.effective_name)
                tallies[key] = _Tally(o, attack_spec.effective_name, spec.trials_for(o))
        # PyRIT may persist several rows per trial on retry/partial failure: keep the best
        # verdict per (objective, attack, trial) so a trial is never counted twice.
        best: dict[tuple[str, str, str], Any] = {}
        for r in results:
            objective = by_text.get(r.objective)
            labels_r = dict(r.labels or {})
            attack_name = labels_r.get(ATTACK_LABEL_KEY, "")
            trial_key = labels_r.get(TRIAL_LABEL_KEY, str(r.attack_result_id))
            if objective is None or attack_name not in attack_names:
                notes.append(f"unmatched result for objective {r.objective!r}")
                continue
            trial_id = (objective.id, attack_name, trial_key)
            prev = best.get(trial_id)
            if prev is None or _outcome_rank(r) > _outcome_rank(prev):
                best[trial_id] = r
        for (oid, attack_name, _), r in best.items():
            tallies[(oid, attack_name)].record(r)
        return _ScenarioRun(list(tallies.values()), notes, spec.scheduled_trials(), failed)

    grouped: dict[tuple[str, str], _Tally] = dict(expected or {})
    scheduled = sum(t.trials for t in grouped.values()) if expected is not None else None
    by_objective: dict[str, list[tuple[str, str]]] = {}
    for key in grouped:
        by_objective.setdefault(key[0], []).append(key)
    for r in results:
        oid = _objective_key(r.objective)
        aa_name = names.get(str(r.attack_result_id))
        if aa_name is None:
            # Recovered from memory (no result -> atomic attack map): attribute to the only
            # scheduled attack for this objective when unambiguous.
            candidates = by_objective.get(oid, [])
            aa_name = candidates[0][1] if len(candidates) == 1 else "scenario"
        key = (oid, aa_name)
        tally = grouped.get(key)
        if tally is None:
            cats = list(r.targeted_harm_categories or []) or ["unknown"]
            tally = _Tally(
                Objective(id=f"obj-{oid}", text=r.objective, harm_category=cats[0]),
                aa_name,
                0,
            )
            grouped[key] = tally
            if expected is not None:
                notes.append(f"unscheduled result for objective {r.objective[:60]!r} ({aa_name})")
        if expected is None:
            tally.trials += 1
        tally.record(r)
    if expected is None:
        notes.append("scenario definition exposed no atomic attacks; scheduled trials unknown")
    return _ScenarioRun(list(grouped.values()), notes, scheduled, failed)


async def run_campaign_async(
    spec: CampaignSpec,
    target: Any,
    *,
    memory: str | None = None,
    baseline_store: BaselineStore | None = None,
    baseline_id: str | None = None,
    trials: int | None = None,
    labels: Mapping[str, str] | None = None,
    pricing: Pricing | None = None,
    usage_sink: Callable[[CampaignResult], None] | None = None,
) -> CampaignResult:
    """Execute ``spec`` against ``target`` and return a :class:`CampaignResult`.

    Args:
        spec: The campaign definition (use :func:`load_campaign` for YAML).
        target: Any PyRIT ``PromptTarget``; see :mod:`aisdlc.security.targets`.
        memory: ``None`` (default) reuses initialized memory (bootstrapping in-memory SQLite
            when nothing is configured); ``"in_memory"``/``"sqlite"`` re-initialize PyRIT.
        baseline_store: Optional store used to compute ``baseline_delta``.
        baseline_id: Overrides ``spec.baseline_id``.
        trials: Overrides ``spec.trials`` (objective-level overrides still apply).
        labels: Extra memory labels attached to every PyRIT conversation.
        pricing: Token prices used to fill ``usage.cost_usd``; ``None`` leaves it unknown.
        usage_sink: Callback receiving the finished result (e.g. a ledger importer).

    The run never raises for target/scorer failures: every failed trial is counted as an
    error, ``complete`` becomes ``False`` and ``threshold_breached`` is ``True`` (fail closed).
    """
    _require_pyrit()
    from aisdlc.security.targets import target_id_of

    if trials is not None:
        spec = spec.model_copy(update={"trials": trials})
    run_labels = {**spec.labels, **dict(labels or {})}
    target_id = target_id_of(target)
    run_id = compute_run_id(
        spec,
        target_id,
        {
            "trials": spec.trials,
            "attacks": [a.effective_name for a in spec.attacks],
            "scenario": spec.scenario,
            "labels": run_labels,
        },
    )
    run_labels = {**run_labels, RUN_LABEL_KEY: run_id}
    await ensure_memory_async(memory)
    _rebind_target_memory(target)
    started = datetime.now(tz=UTC)
    notes: list[str] = []
    failed = False
    scheduled: int | None = spec.scheduled_trials()
    if spec.scenario is None:
        tallies = await _run_direct_async(spec, target, run_labels)
    else:
        scenario_run = await _run_scenario_async(spec, target, run_labels, run_id)
        tallies, notes, failed = scenario_run.tallies, scenario_run.notes, scenario_run.failed
        scheduled = scenario_run.scheduled
    finished = datetime.now(tz=UTC)

    per_objective = [t.to_result() for t in tallies]
    if scheduled is None:
        # Unknown schedule: report what ran, but never claim completeness.
        scheduled = sum(t.trials for t in tallies)
        failed = True
    agg = aggregate_trials(per_objective, scheduled_trials=scheduled)
    if spec.scenario not in (None, "atomic") and not tallies:
        agg["complete"] = False
        notes.append("scenario produced no attack results")
    if failed and agg["complete"]:
        agg["complete"] = False
        notes.append("scenario execution failed or its schedule is unknown: reported incomplete")

    conversation_ids = [cid for t in tallies for cid in t.conversation_ids]
    prompts, in_tok, out_tok = await _usage_from_memory(conversation_ids)
    usage = UsageSummary(
        prompts_sent=prompts,
        input_tokens=in_tok,
        output_tokens=out_tok,
        cost_usd=pricing.cost(in_tok, out_tok) if pricing else None,
    )

    result = CampaignResult(
        campaign_id=spec.id,
        run_id=run_id,
        target_id=target_id,
        scheduled_trials=scheduled,
        completed_trials=agg["completed_trials"],
        per_objective=per_objective,
        asr=agg["asr"],
        asr_by_category=agg["asr_by_category"],
        asr_by_attack=agg["asr_by_attack"],
        undetermined_rate=agg["undetermined_rate"],
        complete=agg["complete"],
        asr_threshold=spec.asr_threshold,
        max_undetermined_rate=spec.max_undetermined_rate,
        baseline_id=baseline_id or spec.baseline_id,
        usage=usage,
        labels=run_labels,
        notes=notes,
        started_at=started,
        finished_at=finished,
    )
    bid = baseline_id or spec.baseline_id
    if bid and baseline_store is not None:
        try:
            result.baseline_delta = baseline_store.compare(result, bid)
        except BaselineNotFoundError:
            result.notes.append(f"baseline {bid!r} not found in {baseline_store.directory}")
    elif bid:
        result.notes.append(f"baseline {bid!r} requested but no baseline store configured")
    result.breaches = _evaluate_thresholds(result)
    result.threshold_breached = bool(result.breaches)
    if usage_sink is not None:
        usage_sink(result)
    return result


def run_campaign(spec: CampaignSpec, target: Any, **kwargs: Any) -> CampaignResult:
    """Synchronous wrapper around :func:`run_campaign_async` (for the CLI)."""
    return asyncio.run(run_campaign_async(spec, target, **kwargs))


def ledger_usage_sink(
    ledger: Any,
    *,
    change_id: str = "",
    agent_role: str = "security_tester",
    task_id: str = "",
    environment: str = "",
    registry: Any | None = None,
    model: str = "",
    price_table: Any | None = None,
) -> Callable[[CampaignResult], None]:
    """Build a ``usage_sink`` that records a campaign's model usage in a ``UsageLedger``.

    Every PyRIT message piece labelled with the run id that carries token metadata becomes
    one :class:`~aisdlc.control_plane.ledger.UsageEvent` (``source="pyrit"``, priced via the
    registry when the model is known). When the target reported no per-message tokens the
    campaign's aggregate :class:`UsageSummary` is recorded as a single event so the spend
    (prompts, tokens, priced cost) is never invisible to budgets and ``cost.json``. The
    number of events written is stored in ``result.labels["aisdlc_ledger_events"]``.
    """
    from aisdlc.control_plane.ledger import UsageEvent
    from aisdlc.control_plane.telemetry import TelemetryDefaults, from_pyrit_memory

    def sink(result: CampaignResult) -> None:
        from pyrit.memory import CentralMemory

        defaults = TelemetryDefaults(
            change_id=change_id,
            task_id=task_id,
            agent_role=agent_role,
            harness="pyrit",
            environment=environment,
            session_id=result.run_id,
        )
        events = from_pyrit_memory(
            CentralMemory.get_memory_instance(),
            labels={RUN_LABEL_KEY: result.run_id},
            defaults=defaults,
            registry=registry,
            model=model or result.target_id,
            price_table=price_table,
        )
        usage = result.usage
        if not events and (usage.prompts_sent or usage.input_tokens or usage.output_tokens):
            events = [
                UsageEvent(
                    ts=result.finished_at,
                    change_id=change_id,
                    task_id=task_id,
                    agent_role=agent_role,
                    harness="pyrit",
                    model=model or result.target_id,
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    tool_calls=usage.prompts_sent,
                    cost_usd=usage.cost_usd or 0.0,
                    source="pyrit",
                    environment=environment,
                    session_id=result.run_id,
                )
            ]
        ledger.record_many(events)
        priced = round(sum(e.cost_usd for e in events), 6)
        if usage.cost_usd is None and priced > 0:
            result.usage = usage.model_copy(update={"cost_usd": priced})
        result.labels = {**result.labels, "aisdlc_ledger_events": str(len(events))}

    return sink
