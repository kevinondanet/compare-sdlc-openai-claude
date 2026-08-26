# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Strict whole-change cost evidence with exact orchestration reconciliation."""

from __future__ import annotations

import json
from datetime import datetime  # noqa: TC003 -- Pydantic resolves this annotation at runtime
from decimal import Decimal
from enum import StrEnum
from pathlib import Path  # noqa: TC003 -- public loader annotation
from typing import Annotated, Any, Literal, TypeAlias

from pydantic import Field, field_validator, model_validator

from agent_sre.sdlc.canonical import (
    canonical_json_bytes,
    digest_without,
    load_json_file_strict,
    load_json_strict,
)
from agent_sre.sdlc.models import (
    Identifier,
    Money,
    Sha256,
    StrictContractModel,
    _require_utc,
    validate_contract_json,
)
from agent_sre.sdlc.pyrit import Coverage, PyRITSecurityEvidence
from agent_sre.sdlc.rampart import RampartSafetyReport
from agent_sre.sdlc.usage_ledger import UsageRollup, usage_event_set_digest

CHANGE_COST_SCHEMA_VERSION: Literal["agt.change-cost-report/v1"] = "agt.change-cost-report/v1"


class CostComponentKind(StrEnum):
    """Known cross-harness cost partitions."""

    ORCHESTRATION = "orchestration"
    CI = "ci"
    PYRIT = "pyrit"
    RAMPART = "rampart"
    SCANNER = "scanner"
    OTHER = "other"


class CostRollupFacts(StrictContractModel):
    """Cost-completeness projection of one exact event set."""

    event_count: Annotated[int, Field(ge=0)]
    event_set_digest: Sha256
    total_cost_usd: Money | None
    unpriced_events: Annotated[int, Field(ge=0)]
    cost_complete: bool

    @model_validator(mode="after")
    def validate_completeness(self) -> CostRollupFacts:
        if self.unpriced_events > self.event_count:
            raise ValueError("unpriced_events must not exceed event_count")
        complete = self.unpriced_events == 0 and self.total_cost_usd is not None
        if self.cost_complete != complete:
            raise ValueError("cost_complete does not match rollup facts")
        if not complete and self.total_cost_usd is not None:
            raise ValueError("an incomplete rollup must not expose a partial cost as total")
        return self


class LedgerCostComponent(StrictContractModel):
    """One disjoint partition already present in the UsageLedger rollup."""

    component_type: Literal["ledger"] = "ledger"
    component_kind: CostComponentKind
    component_id: Identifier
    source_schema: Identifier
    source_digest: Sha256
    event_ids: tuple[Identifier, ...]
    facts: CostRollupFacts
    partition_digest: Sha256

    @model_validator(mode="after")
    def validate_event_inventory(self) -> LedgerCostComponent:
        if self.event_ids != tuple(sorted(set(self.event_ids))):
            raise ValueError("ledger component event_ids must be sorted and unique")
        if self.facts.event_count != len(self.event_ids):
            raise ValueError("ledger component event_count does not match event_ids")
        if self.facts.event_set_digest != usage_event_set_digest(self.event_ids):
            raise ValueError("ledger component event_set_digest does not match event_ids")
        expected_digest = digest_without(self, "partition_digest")
        if self.partition_digest != expected_digest:
            raise ValueError("ledger component partition_digest does not match its inventory")
        return self


class PyRITExternalUsageComponent(StrictContractModel):
    """Raw PyRIT evidence accounted outside the model-call UsageLedger."""

    component_type: Literal["pyrit_external"] = "pyrit_external"
    component_id: Identifier
    evidence: PyRITSecurityEvidence
    facts: CostRollupFacts

    @model_validator(mode="after")
    def validate_derived_facts(self) -> PyRITExternalUsageComponent:
        usage = self.evidence.usage
        complete = usage.cost_coverage is Coverage.COMPLETE and usage.cost is not None
        expected = CostRollupFacts(
            event_count=usage.observed_response_count,
            event_set_digest=self.evidence.evidence_digest,
            total_cost_usd=(
                usage.cost.decimal_amount if complete and usage.cost is not None else None
            ),
            unpriced_events=(
                0 if complete else usage.observed_response_count - usage.calls_with_cost
            ),
            cost_complete=complete,
        )
        if self.facts != expected:
            raise ValueError("PyRIT external cost facts do not match the raw evidence")
        return self


class RampartExternalUsageComponent(StrictContractModel):
    """Raw RAMPART usage accounted outside the model-call UsageLedger."""

    component_type: Literal["rampart_external"] = "rampart_external"
    component_id: Identifier
    report: RampartSafetyReport
    facts: CostRollupFacts

    @model_validator(mode="after")
    def validate_derived_facts(self) -> RampartExternalUsageComponent:
        usage = self.report.usage
        expected = CostRollupFacts(
            event_count=usage.observed_calls,
            event_set_digest=usage.source_digest,
            total_cost_usd=usage.total_cost_usd if usage.cost_complete else None,
            unpriced_events=(
                0 if usage.cost_complete else usage.observed_calls - usage.calls_with_cost
            ),
            cost_complete=usage.cost_complete,
        )
        if self.facts != expected:
            raise ValueError("RAMPART external cost facts do not match the raw report")
        return self


CostComponent: TypeAlias = Annotated[
    LedgerCostComponent | PyRITExternalUsageComponent | RampartExternalUsageComponent,
    Field(discriminator="component_type"),
]


def _component_kind(component: CostComponent) -> CostComponentKind:
    if isinstance(component, LedgerCostComponent):
        return component.component_kind
    if isinstance(component, PyRITExternalUsageComponent):
        return CostComponentKind.PYRIT
    return CostComponentKind.RAMPART


def _component_id(component: CostComponent) -> str:
    return component.component_id


def _component_facts(component: CostComponent) -> CostRollupFacts:
    return component.facts


def _component_source_digest(component: CostComponent) -> str:
    if isinstance(component, LedgerCostComponent):
        return component.source_digest
    if isinstance(component, PyRITExternalUsageComponent):
        return component.evidence.evidence_digest
    return component.report.report_digest


class ChangeCostReport(StrictContractModel):
    """Complete whole-change cost with a receipt-reconcilable orchestration subset."""

    schema_version: Literal["agt.change-cost-report/v1"] = CHANGE_COST_SCHEMA_VERSION
    change_id: Identifier
    source_revision: Identifier
    change_digest: Sha256
    generated_at: datetime
    ledger_rollup: CostRollupFacts
    orchestration_rollup: CostRollupFacts
    required_component_kinds: Annotated[tuple[CostComponentKind, ...], Field(min_length=1)]
    components: Annotated[tuple[CostComponent, ...], Field(min_length=1)]
    total_event_count: Annotated[int, Field(ge=0)]
    total_cost_usd: Money | None
    total_unpriced_events: Annotated[int, Field(ge=0)]
    cost_complete: bool
    accounting_digest: Sha256

    _utc_generated = field_validator("generated_at")(_require_utc)

    @field_validator("required_component_kinds")
    @classmethod
    def validate_required_component_kinds(
        cls,
        value: tuple[CostComponentKind, ...],
    ) -> tuple[CostComponentKind, ...]:
        expected = tuple(sorted(set(value), key=lambda item: item.value))
        if value != expected:
            raise ValueError("required_component_kinds must be sorted and unique")
        return value

    @model_validator(mode="after")
    def validate_accounting(self) -> ChangeCostReport:
        for component in self.components:
            serialized = canonical_json_bytes(component.model_dump(mode="json"))
            if isinstance(component, LedgerCostComponent):
                LedgerCostComponent.model_validate_json(serialized, strict=True)
            elif isinstance(component, PyRITExternalUsageComponent):
                PyRITExternalUsageComponent.model_validate_json(serialized, strict=True)
            else:
                RampartExternalUsageComponent.model_validate_json(serialized, strict=True)
        order = tuple(
            (component.component_type, _component_kind(component).value, _component_id(component))
            for component in self.components
        )
        if order != tuple(sorted(set(order))):
            raise ValueError("components must be sorted and contain no duplicates")
        observed_kinds = tuple(
            sorted(
                {_component_kind(component) for component in self.components}, key=lambda x: x.value
            )
        )
        if self.required_component_kinds != observed_kinds:
            raise ValueError("components must exactly cover the declared required_component_kinds")

        source_digests = tuple(_component_source_digest(component) for component in self.components)
        if len(source_digests) != len(set(source_digests)):
            raise ValueError("component source digests must be unique")

        ledger_components = tuple(
            component for component in self.components if isinstance(component, LedgerCostComponent)
        )
        ledger_event_ids = tuple(
            event_id for component in ledger_components for event_id in component.event_ids
        )
        if len(ledger_event_ids) != len(set(ledger_event_ids)):
            raise ValueError("ledger component event inventories must be disjoint")
        if self.ledger_rollup.event_count != len(ledger_event_ids):
            raise ValueError("ledger component event inventories do not cover the whole rollup")
        if self.ledger_rollup.event_set_digest != usage_event_set_digest(ledger_event_ids):
            raise ValueError("ledger component event inventories do not match the whole rollup")
        orchestration_components = tuple(
            component
            for component in ledger_components
            if component.component_kind is CostComponentKind.ORCHESTRATION
        )
        if len(orchestration_components) != 1:
            raise ValueError("exactly one ledger orchestration component is required")
        if orchestration_components[0].facts != self.orchestration_rollup:
            raise ValueError("orchestration component must equal orchestration_rollup")

        self._require_sum(
            self.ledger_rollup,
            tuple(component.facts for component in ledger_components),
            label="ledger",
        )
        external_components = tuple(
            component
            for component in self.components
            if not isinstance(component, LedgerCostComponent)
        )
        external_facts = tuple(_component_facts(component) for component in external_components)
        expected_event_count = self.ledger_rollup.event_count + sum(
            (facts.event_count for facts in external_facts), 0
        )
        expected_unpriced = self.ledger_rollup.unpriced_events + sum(
            (facts.unpriced_events for facts in external_facts), 0
        )
        expected_complete = self.ledger_rollup.cost_complete and all(
            facts.cost_complete for facts in external_facts
        )
        expected_cost = (
            None
            if not expected_complete
            else (self.ledger_rollup.total_cost_usd or Decimal("0"))
            + sum(
                (facts.total_cost_usd or Decimal("0") for facts in external_facts),
                Decimal("0"),
            )
        )
        if self.total_event_count != expected_event_count:
            raise ValueError("total_event_count does not match ledger and external components")
        if self.total_unpriced_events != expected_unpriced:
            raise ValueError("total_unpriced_events does not match component coverage")
        if self.cost_complete != expected_complete:
            raise ValueError("cost_complete does not match all cost components")
        if self.total_cost_usd != expected_cost:
            raise ValueError("total_cost_usd does not match complete component costs")

        for component in external_components:
            if isinstance(component, PyRITExternalUsageComponent):
                pyrit_subject = component.evidence.subject
                binding = (
                    pyrit_subject is not None
                    and pyrit_subject.change == self.change_id
                    and pyrit_subject.commit_sha == self.source_revision
                )
            else:
                rampart_subject = component.report.subject
                binding = (
                    rampart_subject.change_id == self.change_id
                    and rampart_subject.source_revision == self.source_revision
                    and rampart_subject.change_digest == self.change_digest
                )
            if not binding:
                raise ValueError("external cost component is not bound to the change subject")

        expected_digest = digest_without(self, "accounting_digest")
        if self.accounting_digest != expected_digest:
            raise ValueError(
                f"accounting_digest mismatch: expected {expected_digest}, "
                f"got {self.accounting_digest}"
            )
        return self

    @staticmethod
    def _require_sum(
        expected: CostRollupFacts,
        components: tuple[CostRollupFacts, ...],
        *,
        label: str,
    ) -> None:
        event_count = sum((item.event_count for item in components), 0)
        unpriced = sum((item.unpriced_events for item in components), 0)
        complete = all(item.cost_complete for item in components)
        cost = (
            None
            if not complete
            else sum(
                (item.total_cost_usd or Decimal("0") for item in components),
                Decimal("0"),
            )
        )
        if (
            expected.event_count != event_count
            or expected.unpriced_events != unpriced
            or expected.cost_complete != complete
            or expected.total_cost_usd != cost
        ):
            raise ValueError(f"{label} components do not partition the rollup")


def cost_rollup_facts(rollup: UsageRollup) -> CostRollupFacts:
    """Project a UsageLedger rollup into fail-closed cost facts."""

    if not isinstance(rollup, UsageRollup):
        raise ValueError("rollup must be a UsageRollup")
    complete = rollup.unpriced_events == 0
    return CostRollupFacts(
        event_count=rollup.event_count,
        event_set_digest=rollup.event_set_digest,
        total_cost_usd=rollup.known_cost_usd if complete else None,
        unpriced_events=rollup.unpriced_events,
        cost_complete=complete,
    )


def ledger_cost_component(
    *,
    kind: CostComponentKind,
    component_id: str,
    source_schema: str,
    source_digest: str,
    event_ids: tuple[str, ...],
    rollup: UsageRollup,
) -> LedgerCostComponent:
    """Create one strictly shaped UsageLedger partition with an exact event proof."""

    payload: dict[str, Any] = {
        "component_kind": kind,
        "component_id": component_id,
        "source_schema": source_schema,
        "source_digest": source_digest,
        "event_ids": tuple(sorted(event_ids)),
        "facts": cost_rollup_facts(rollup),
    }
    provisional = LedgerCostComponent.model_construct(
        **payload,
        partition_digest="0" * 64,
    )
    payload["partition_digest"] = digest_without(provisional, "partition_digest")
    return LedgerCostComponent.model_validate(payload)


def pyrit_external_usage_component(
    evidence: PyRITSecurityEvidence,
) -> PyRITExternalUsageComponent:
    """Derive an external component from raw, self-digested PyRIT evidence."""

    evidence = PyRITSecurityEvidence.model_validate_json(
        canonical_json_bytes(evidence.model_dump(mode="json")),
        strict=True,
    )
    usage = evidence.usage
    complete = usage.cost_coverage is Coverage.COMPLETE and usage.cost is not None
    return PyRITExternalUsageComponent(
        component_id=f"pyrit:{evidence.run.scenario_result_id}",
        evidence=evidence,
        facts=CostRollupFacts(
            event_count=usage.observed_response_count,
            event_set_digest=evidence.evidence_digest,
            total_cost_usd=(
                usage.cost.decimal_amount if complete and usage.cost is not None else None
            ),
            unpriced_events=(
                0 if complete else usage.observed_response_count - usage.calls_with_cost
            ),
            cost_complete=complete,
        ),
    )


def rampart_external_usage_component(
    report: RampartSafetyReport,
) -> RampartExternalUsageComponent:
    """Derive an external component from a raw validated RAMPART report."""

    report = RampartSafetyReport.model_validate_json(
        canonical_json_bytes(report.model_dump(mode="json")),
        strict=True,
    )
    usage = report.usage
    return RampartExternalUsageComponent(
        component_id=f"rampart:{report.run_id}",
        report=report,
        facts=CostRollupFacts(
            event_count=usage.observed_calls,
            event_set_digest=usage.source_digest,
            total_cost_usd=usage.total_cost_usd if usage.cost_complete else None,
            unpriced_events=(
                0 if usage.cost_complete else usage.observed_calls - usage.calls_with_cost
            ),
            cost_complete=usage.cost_complete,
        ),
    )


def change_cost_report_from_usage_rollups(
    whole_change_rollup: UsageRollup,
    *,
    orchestration_rollup: UsageRollup,
    change_id: str,
    source_revision: str,
    change_digest: str,
    generated_at: datetime,
    ledger_components: tuple[LedgerCostComponent, ...],
    external_components: tuple[
        PyRITExternalUsageComponent | RampartExternalUsageComponent, ...
    ] = (),
    required_component_kinds: tuple[CostComponentKind, ...] | None = None,
) -> ChangeCostReport:
    """Build a canonical whole-change report from disjoint, complete partitions."""

    orchestration = orchestration_rollup
    for label, rollup in (
        ("whole_change_rollup", whole_change_rollup),
        ("orchestration_rollup", orchestration),
    ):
        if rollup.group != (("change_id", change_id),):
            raise ValueError(f"{label} must be grouped only by the exact change_id")
    ledger_facts = cost_rollup_facts(whole_change_rollup)
    orchestration_facts = cost_rollup_facts(orchestration)
    if not ledger_components:
        raise ValueError("explicit ledger_components are required")
    components: tuple[CostComponent, ...] = tuple(
        sorted(
            (*ledger_components, *external_components),
            key=lambda item: (
                item.component_type,
                _component_kind(item).value,
                _component_id(item),
            ),
        )
    )
    external_facts = tuple(component.facts for component in external_components)
    observed_kinds = tuple(
        sorted(
            {_component_kind(component) for component in components}, key=lambda item: item.value
        )
    )
    required_kinds = (
        observed_kinds if required_component_kinds is None else required_component_kinds
    )
    complete = ledger_facts.cost_complete and all(item.cost_complete for item in external_facts)
    total_cost = (
        None
        if not complete
        else (ledger_facts.total_cost_usd or Decimal("0"))
        + sum(
            (item.total_cost_usd or Decimal("0") for item in external_facts),
            Decimal("0"),
        )
    )
    payload: dict[str, Any] = {
        "schema_version": CHANGE_COST_SCHEMA_VERSION,
        "change_id": change_id,
        "source_revision": source_revision,
        "change_digest": change_digest,
        "generated_at": generated_at,
        "ledger_rollup": ledger_facts,
        "orchestration_rollup": orchestration_facts,
        "required_component_kinds": required_kinds,
        "components": components,
        "total_event_count": ledger_facts.event_count
        + sum((item.event_count for item in external_facts), 0),
        "total_cost_usd": total_cost,
        "total_unpriced_events": ledger_facts.unpriced_events
        + sum((item.unpriced_events for item in external_facts), 0),
        "cost_complete": complete,
    }
    provisional = ChangeCostReport.model_construct(**payload, accounting_digest="0" * 64)
    payload["accounting_digest"] = digest_without(provisional, "accounting_digest")
    return ChangeCostReport.model_validate(payload)


def parse_change_cost_report(data: str | bytes) -> ChangeCostReport:
    """Strictly parse and integrity-check one whole-change cost report."""

    payload = load_json_strict(data)
    if not isinstance(payload, dict):
        raise ValueError("change cost report must be a JSON object")
    result = validate_contract_json(ChangeCostReport, payload)
    assert isinstance(result, ChangeCostReport)
    return result


def load_change_cost_report(path: str | Path) -> ChangeCostReport:
    """Load a bounded whole-change cost report through defensive JSON parsing."""

    payload = load_json_file_strict(path)
    if not isinstance(payload, dict):
        raise ValueError("change cost report must be a JSON object")
    return parse_change_cost_report(json.dumps(payload, ensure_ascii=False, allow_nan=False))


__all__ = [
    "CHANGE_COST_SCHEMA_VERSION",
    "ChangeCostReport",
    "CostComponent",
    "CostComponentKind",
    "CostRollupFacts",
    "LedgerCostComponent",
    "PyRITExternalUsageComponent",
    "RampartExternalUsageComponent",
    "change_cost_report_from_usage_rollups",
    "cost_rollup_facts",
    "ledger_cost_component",
    "load_change_cost_report",
    "parse_change_cost_report",
    "pyrit_external_usage_component",
    "rampart_external_usage_component",
]
