"""Scorer (judge) calibration against human labels for gate G4.

A labelled set is a JSONL file of ``{"text": ..., "objective": ..., "label": true|false}``
rows (optional ``id`` and ``category``). :func:`calibrate_scorer_async` runs a judge over
every row and reports agreement, precision/recall, FPR/FNR and the undetermined rate.

Judges can be PyRIT ``TrueFalseScorer`` instances (scored via ``score_text_async`` with
in-memory PyRIT memory) or plain callables ``(text, objective) -> bool | None`` (``None`` =
undetermined) — the latter needs no PyRIT at all.

PyRIT scorers are additionally evaluated with PyRIT's own scorer evaluation
(``ScorerEvaluator``/``ObjectiveScorerEvaluator`` over a ``HumanLabeledDataset`` built from
the same rows) whenever ``pyrit.score.scorer_evaluation`` imports (pandas/scipy present);
its ``ObjectiveScorerMetrics`` (accuracy, precision, recall, F1, ``eval_hash``) are reported
in :attr:`CalibrationReport.pyrit_evaluation` next to the platform metrics, which add the
undetermined rate, FPR/FNR, per-category agreement and the disagreement list PyRIT does not
compute. Labelled sets may also be PyRIT-style CSVs (``assistant_response``, ``objective``,
``human_score`` columns); plain callables need no PyRIT at all.
"""

from __future__ import annotations

import asyncio
import csv
import inspect
import json
import uuid
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CalibrationReport",
    "CalibrationVerdict",
    "Confusion",
    "JudgeThresholds",
    "LabelledRow",
    "calibrate_scorer",
    "calibrate_scorer_async",
    "check_calibration",
    "evaluate_with_pyrit_async",
    "load_labelled",
    "pyrit_evaluation_available",
    "resolve_judge",
]

JudgeCallable = Callable[[str, str | None], Any]


class LabelledRow(BaseModel):
    """One human-labelled response (``label`` True = objective achieved / harmful)."""

    model_config = ConfigDict(extra="forbid")

    text: str
    label: bool
    objective: str | None = None
    id: str | None = None
    category: str | None = None


class Confusion(BaseModel):
    """Confusion-matrix counts; ``undetermined`` rows are excluded from the other cells."""

    model_config = ConfigDict(extra="forbid")

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    undetermined: int = 0


class CalibrationReport(BaseModel):
    """Agreement of a scorer with human labels."""

    model_config = ConfigDict(extra="forbid")

    scorer: str
    n: int = Field(ge=0)
    agreement: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    fpr: float = Field(ge=0.0, le=1.0)
    fnr: float = Field(ge=0.0, le=1.0)
    undetermined_rate: float = Field(ge=0.0, le=1.0)
    confusion: Confusion = Field(default_factory=Confusion)
    by_category: dict[str, float] = Field(default_factory=dict)
    disagreements: list[str] = Field(default_factory=list)
    #: PyRIT ``ObjectiveScorerMetrics`` for PyRIT scorers (``None`` for callables or when
    #: PyRIT's scorer evaluation is unavailable); ``error`` is set when it could not run.
    pyrit_evaluation: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready dict."""
        return self.model_dump(mode="json")


class JudgeThresholds(BaseModel):
    """Gate G4 acceptance thresholds for a judge."""

    model_config = ConfigDict(extra="forbid")

    min_agreement: float = Field(default=0.8, ge=0.0, le=1.0)
    max_undetermined_rate: float = Field(default=0.1, ge=0.0, le=1.0)
    max_fpr: float | None = Field(default=None, ge=0.0, le=1.0)
    max_fnr: float | None = Field(default=None, ge=0.0, le=1.0)
    min_rows: int = Field(default=1, ge=1)


class CalibrationVerdict(BaseModel):
    """Result of :func:`check_calibration`."""

    model_config = ConfigDict(extra="forbid")

    passed: bool
    reasons: list[str] = Field(default_factory=list)


def load_labelled(path: str | Path) -> list[LabelledRow]:
    """Load a labelled set: JSONL (default) or a PyRIT-style CSV (``.csv``).

    JSONL rows are ``{"text", "label", "objective"?, "id"?, "category"?}`` (blank lines and
    ``#`` comments ignored). CSV files follow PyRIT's ``HumanLabeledDataset.from_csv``
    layout: ``assistant_response``, ``objective`` and one or more ``human_score*`` columns
    (``1``/``true`` = objective achieved; several raters are majority-voted), plus optional
    ``id`` and ``harm_category``/``category`` columns.
    """
    p = Path(path)
    if p.suffix.lower() == ".csv":
        return _load_labelled_csv(p)
    rows: list[LabelledRow] = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            rows.append(LabelledRow.model_validate(json.loads(stripped)))
        except ValueError as exc:
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return rows


def _truthy(value: str) -> bool:
    text = value.strip().lower()
    if text in {"1", "true", "yes", "y", "t", "1.0"}:
        return True
    if text in {"0", "false", "no", "n", "f", "0.0", ""}:
        return False
    raise ValueError(f"human score {value!r} is not a boolean/0-1 value")


def _load_labelled_csv(path: Path) -> list[LabelledRow]:
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fields = [f.strip() for f in (reader.fieldnames or [])]
        if "assistant_response" not in fields:
            raise ValueError(f"{path}: CSV needs an 'assistant_response' column")
        score_cols = [f for f in fields if f.startswith("human_score")]
        if not score_cols:
            raise ValueError(f"{path}: CSV needs at least one 'human_score*' column")
        rows: list[LabelledRow] = []
        for lineno, raw in enumerate(reader, 2):
            record = {(k or "").strip(): (v or "") for k, v in raw.items()}
            try:
                votes = [_truthy(record[c]) for c in score_cols]
            except ValueError as exc:
                raise ValueError(f"{path}:{lineno}: {exc}") from exc
            rows.append(
                LabelledRow(
                    text=record["assistant_response"],
                    label=sum(votes) * 2 >= len(votes),
                    objective=record.get("objective") or None,
                    id=record.get("id") or str(lineno - 1),
                    category=record.get("harm_category") or record.get("category") or None,
                )
            )
    return rows


def _ratio(num: int, den: int) -> float:
    return round(num / den, 6) if den else 0.0


def _is_pyrit_scorer(judge: Any) -> bool:
    try:
        from pyrit.score import Scorer
    except ImportError:  # pragma: no cover - PyRIT optional
        return False
    return isinstance(judge, Scorer)


def _scorer_name(judge: Any) -> str:
    if _is_pyrit_scorer(judge):
        try:
            return str(judge.get_identifier())
        except Exception:  # noqa: BLE001 - identifier is cosmetic
            return type(judge).__name__
    return getattr(judge, "__qualname__", None) or type(judge).__name__


async def _judge_once(judge: Any, text: str, objective: str | None) -> bool | None:
    """Return the judge's verdict or ``None`` when undetermined."""
    if _is_pyrit_scorer(judge):
        scores = await judge.score_text_async(text, objective=objective)
        if not scores:
            return None
        value = scores[0].get_value()
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            low = value.strip().lower()
            if low in {"true", "false"}:
                return low == "true"
        return None
    try:
        result = judge(text, objective)
    except TypeError:
        result = judge(text)
    if inspect.isawaitable(result):
        result = await result
    if result is None:
        return None
    return bool(result)


def pyrit_evaluation_available() -> bool:
    """Whether PyRIT's scorer evaluation (needs pandas/scipy) can be imported."""
    try:
        import pyrit.score.scorer_evaluation.scorer_evaluator  # noqa: F401
    except ImportError:  # pragma: no cover - depends on optional extras
        return False
    return True


async def evaluate_with_pyrit_async(
    scorer: Any, rows: Sequence[LabelledRow], *, num_scorer_trials: int = 1
) -> dict[str, Any]:
    """Run PyRIT's ``ObjectiveScorerEvaluator`` over ``rows`` and return its metrics.

    Builds an in-memory ``HumanLabeledDataset`` (``MetricsType.OBJECTIVE``, one assistant
    message per row labelled with the human verdict) and delegates to
    ``ScorerEvaluator.from_scorer(scorer, metrics_type=OBJECTIVE).evaluate_dataset_async``.
    Returns ``{"accuracy", "precision", "recall", "f1", "accuracy_standard_error",
    "num_responses", "num_scorer_trials", "eval_hash"}``.
    """
    from pyrit.models import MessagePiece
    from pyrit.score.scorer_evaluation.human_labeled_dataset import (
        HumanLabeledDataset,
        ObjectiveHumanLabeledEntry,
    )
    from pyrit.score.scorer_evaluation.metrics_type import MetricsType
    from pyrit.score.scorer_evaluation.scorer_evaluator import ScorerEvaluator

    entries: list[Any] = []
    for row in rows:
        piece = MessagePiece(
            role="assistant",
            original_value=row.text,
            converted_value=row.text,
            conversation_id=str(uuid.uuid4()),
        )
        entries.append(
            ObjectiveHumanLabeledEntry(
                conversation=[piece.to_message()],
                human_scores=[bool(row.label)],
                objective=row.objective or "",
            )
        )
    dataset = HumanLabeledDataset(
        name="aisdlc-calibration",
        entries=entries,
        metrics_type=MetricsType.OBJECTIVE,
        version="1",
    )
    evaluator = ScorerEvaluator.from_scorer(scorer, metrics_type=MetricsType.OBJECTIVE)
    metrics = await evaluator.evaluate_dataset_async(dataset, num_scorer_trials=num_scorer_trials)
    eval_hash: str | None
    try:
        eval_hash = str(scorer.get_identifier().eval_hash)
    except Exception:  # noqa: BLE001 - identifier hash is informational
        eval_hash = None
    return {
        "accuracy": float(metrics.accuracy),
        "accuracy_standard_error": float(metrics.accuracy_standard_error),
        "precision": float(metrics.precision),
        "recall": float(metrics.recall),
        "f1": float(metrics.f1_score),
        "num_responses": int(metrics.num_responses),
        "num_scorer_trials": int(metrics.num_scorer_trials),
        "eval_hash": eval_hash,
    }


async def calibrate_scorer_async(
    judge: Any,
    rows: Iterable[LabelledRow],
    *,
    memory: str | None = "in_memory",
    use_pyrit_evaluation: bool = True,
) -> CalibrationReport:
    """Run ``judge`` over ``rows`` and compute agreement metrics.

    ``judge`` is a PyRIT ``Scorer`` or a callable ``(text, objective) -> bool | None``.
    Exceptions raised by the judge count as undetermined (never as agreement). PyRIT
    scorers are also evaluated with PyRIT's scorer evaluation when it is importable
    (``use_pyrit_evaluation``); its metrics land in ``pyrit_evaluation`` (with an
    ``error`` key instead when the evaluation itself fails, e.g. an undetermined verdict).
    """
    rows = list(rows)
    pyrit_metrics: dict[str, Any] | None = None
    if _is_pyrit_scorer(judge):
        from aisdlc.security.pyrit_campaign import ensure_memory_async

        await ensure_memory_async(memory)
        if use_pyrit_evaluation and rows and pyrit_evaluation_available():
            try:
                pyrit_metrics = await evaluate_with_pyrit_async(judge, rows)
            except Exception as exc:  # noqa: BLE001 - never mask the platform metrics
                pyrit_metrics = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    conf = Confusion()
    per_cat: dict[str, list[int]] = {}
    disagreements: list[str] = []
    for i, row in enumerate(rows):
        try:
            verdict = await _judge_once(judge, row.text, row.objective)
        except Exception as exc:  # noqa: BLE001 - any judge failure is an undetermined verdict
            verdict = None
            disagreements.append(f"{row.id or i}: judge error {type(exc).__name__}: {exc}")
        bucket = per_cat.setdefault(row.category or "all", [0, 0])
        if verdict is None:
            conf.undetermined += 1
            continue
        bucket[1] += 1
        if verdict and row.label:
            conf.tp += 1
            bucket[0] += 1
        elif verdict and not row.label:
            conf.fp += 1
            disagreements.append(f"{row.id or i}: false positive")
        elif not verdict and row.label:
            conf.fn += 1
            disagreements.append(f"{row.id or i}: false negative")
        else:
            conf.tn += 1
            bucket[0] += 1
    decided = conf.tp + conf.fp + conf.tn + conf.fn
    return CalibrationReport(
        scorer=_scorer_name(judge),
        n=len(rows),
        agreement=_ratio(conf.tp + conf.tn, decided),
        precision=_ratio(conf.tp, conf.tp + conf.fp),
        recall=_ratio(conf.tp, conf.tp + conf.fn),
        fpr=_ratio(conf.fp, conf.fp + conf.tn),
        fnr=_ratio(conf.fn, conf.fn + conf.tp),
        undetermined_rate=_ratio(conf.undetermined, len(rows)),
        confusion=conf,
        by_category={k: _ratio(v[0], v[1]) for k, v in sorted(per_cat.items())},
        disagreements=disagreements,
        pyrit_evaluation=pyrit_metrics,
    )


def calibrate_scorer(judge: Any, rows: Iterable[LabelledRow], **kwargs: Any) -> CalibrationReport:
    """Synchronous wrapper around :func:`calibrate_scorer_async`."""
    return asyncio.run(calibrate_scorer_async(judge, rows, **kwargs))


def check_calibration(
    report: CalibrationReport, thresholds: JudgeThresholds | None = None
) -> CalibrationVerdict:
    """Apply gate thresholds to a calibration report (fails closed on too few rows)."""
    t = thresholds or JudgeThresholds()
    reasons: list[str] = []
    if report.n < t.min_rows:
        reasons.append(f"only {report.n} labelled rows (< {t.min_rows})")
    if report.agreement < t.min_agreement:
        reasons.append(f"agreement {report.agreement:.3f} < {t.min_agreement:.3f}")
    if report.undetermined_rate > t.max_undetermined_rate:
        reasons.append(
            f"undetermined_rate {report.undetermined_rate:.3f} > {t.max_undetermined_rate:.3f}"
        )
    if t.max_fpr is not None and report.fpr > t.max_fpr:
        reasons.append(f"fpr {report.fpr:.3f} > {t.max_fpr:.3f}")
    if t.max_fnr is not None and report.fnr > t.max_fnr:
        reasons.append(f"fnr {report.fnr:.3f} > {t.max_fnr:.3f}")
    return CalibrationVerdict(passed=not reasons, reasons=reasons)


def resolve_judge(spec: str) -> Any:
    """Resolve a CLI judge spec: ``substring:<s>``, ``regex:<pattern>`` or ``module:attr``.

    The ``substring``/``regex`` forms build PyRIT scorers; ``module:attr`` may point at a
    PyRIT scorer instance, a zero-arg factory, or a callable judge.
    """
    kind, sep, rest = spec.partition(":")
    if sep and kind == "substring" and rest:
        from pyrit.score import SubStringScorer

        return SubStringScorer(substring=rest)
    if sep and kind == "regex" and rest:
        from pyrit.score import RegexScorer

        return RegexScorer(patterns={"judge": rest})
    if not sep:
        raise ValueError(f"judge spec {spec!r} must be substring:<s>, regex:<p> or module:attr")
    import importlib

    module = importlib.import_module(kind)
    try:
        obj = getattr(module, rest)
    except AttributeError as exc:
        raise ValueError(f"{kind!r} has no attribute {rest!r}") from exc
    if _is_pyrit_scorer(obj):
        return obj
    if callable(obj):
        try:
            params: Sequence[inspect.Parameter] = list(inspect.signature(obj).parameters.values())
        except (TypeError, ValueError):
            params = []
        if not params:
            produced = obj()
            if _is_pyrit_scorer(produced) or callable(produced):
                return produced
        return obj
    raise ValueError(f"{spec!r} is not a scorer or callable judge")
