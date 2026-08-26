"""Pilot 1 — internal CRUD application: ``CHG-add-ticket-priority`` end to end.

Run through ``run.sh`` (or ``python pilot_crud_app.py``). The flow is the documented
standard-risk path: intake and planning gates, a governed dry run of the change in
isolated worktrees with independent review, test evidence for every portfolio layer
(coverage, diff coverage against the pre-change commit, mutation), plane-1 security
artifacts, cost, one human approval and a signed evidence bundle.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

PILOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PILOT_DIR.parent))

import pilotlib  # noqa: E402
from pilotlib import PreChange, Workspace, python, sh  # noqa: E402

CHANGE_ID = "CHG-add-ticket-priority"
PRE_CHANGE = PreChange(overlay_dir="before", absent=("tests/test_priority.py",))
UNIT_MODULES = "tests.test_service tests.test_priority"
LAYERS = ("integration", "contract", "e2e", "architecture")


def run(ws: Workspace) -> str:
    """Drive the whole flow; returns the Markdown summary for the README."""
    py = python()
    ws.section("1. Commit the change on top of the pre-change baseline")
    ws.commit_change(f"{CHANGE_ID}: priority field, validation, sorted listing, CLI flag")

    ws.section("2. Intake and planning gates")
    ws.init_platform()
    ws.run(["change", "validate", CHANGE_ID])
    readiness = ws.run(["intake", "readiness", CHANGE_ID, "--json"]).json()
    ws.run(["intake", "checklist", CHANGE_ID])
    ws.run(["intake", "analyze", CHANGE_ID])
    ws.run(["plan", "check", CHANGE_ID])
    ws.run(["plan", "risk", "classify", CHANGE_ID, "--path", "tickets/service.py"])

    ws.section("3. Governed implementation run (dry runner, worktrees, independent review)")
    ws.run(
        [
            "governance",
            "policy",
            "generate",
            "--out-dir",
            ".aisdlc/policies",
            "--workspace-root",
            ".",
        ]
    )
    report = ws.run(
        [
            "run",
            "change",
            CHANGE_ID,
            "--runner",
            "dry",
            "--yes",
            "--audit-log",
            ".aisdlc/audit-orchestrator.jsonl",
            "--json",
        ]
    ).json()
    ws.run(["run", "status", CHANGE_ID])

    ws.section("4. Test evidence: unit coverage, diff coverage, mutation, portfolio layers")
    unit = ws.run(
        [
            "test",
            "run-evidence",
            CHANGE_ID,
            "--command",
            sh(
                f"{py} -m coverage run --branch --source=tickets -m unittest -q {UNIT_MODULES}"
                f" && {py} -m coverage json -q -o coverage.json"
            ),
            "--coverage-json",
            "coverage.json",
            "--diff-base",
            ws.baseline_sha,
            "--report-uri",
            "coverage.json",
            "--json",
        ],
        note="Unit layer with line/branch coverage and diff coverage against the pre-change commit.",
    ).json()
    mutation = ws.run(
        [
            "test",
            "mutation",
            "--builtin",
            "tickets/service.py",
            "--command",
            f"{py} -m unittest -q {UNIT_MODULES}",
            "--package",
            CHANGE_ID,
            "--max-mutants",
            "20",
            "--cwd",
            ".",
            "--json",
        ],
        note="Built-in mutation runner over the changed module; attached to the unit evidence.",
    ).json()
    layer_ids: dict[str, str] = {}
    for layer in LAYERS:
        record = ws.run(
            [
                "test",
                "run-evidence",
                CHANGE_ID,
                "--command",
                f"{py} -m unittest -q tests.test_{layer}",
                "--report-uri",
                f"tests/test_{layer}.py",
                "--json",
            ]
        ).json()
        layer_ids[layer] = record["id"]
    runs, trace = pilotlib.acceptance_layer_runs(
        ws.package_dir, ws.root / "tests", e2e_evidence_ids=[layer_ids["e2e"]]
    )
    layers_path = ws.reports_dir / "portfolio-layers.json"
    layers_path.write_text(json.dumps(runs, indent=2) + "\n", encoding="utf-8")
    (ws.reports_dir / "traceability.json").write_text(
        json.dumps(trace, indent=2) + "\n", encoding="utf-8"
    )
    ws.note(
        f"scenario traceability: {trace['scenarios_with_tests']}/{trace['scenarios']} scenarios "
        f"referenced by tests; critical journeys in e2e {trace['critical_journeys_e2e']}%"
    )

    ws.section("5. Security evidence (plane 1 artifacts) and manifest check")
    pilotlib.ruff_sarif(ws.root, ["tickets"], ws.root / "ci-artifacts" / "ruff.sarif")
    ws.note("generated ci-artifacts/ruff.sarif with `ruff check --output-format sarif tickets`")
    ws.run(
        [
            "ci",
            "collect-security",
            "ci-artifacts",
            "--package",
            CHANGE_ID,
            "--commit-sha",
            ws.head(),
            "--environment",
            "local",
        ]
    )
    ws.run(["ci", "manifest-drift", CHANGE_ID])
    ws.run(
        ["test", "portfolio", CHANGE_ID, "--layers", str(layers_path.relative_to(ws.root))],
        note="Coverage portfolio over every layer now that security evidence exists.",
    )

    ws.section("6. Cost (control plane ledger)")
    ws.run(["cost", "report", "--change", CHANGE_ID, "--group-by", "agent_role"])

    ws.section("7. Gates, human approval, signed evidence bundle")
    before = ws.run(["gate", "evaluate", CHANGE_ID, "--json"], ok=(0, 1)).json()
    ws.run(
        [
            "gate",
            "approve",
            CHANGE_ID,
            "--role",
            "owner",
            "--approver",
            "tickets-lead",
            "--note",
            "release review after wave 2",
        ]
    )
    verdict = ws.run(["gate", "verdict", CHANGE_ID, "--json"]).json()
    ws.run(["gate", "bundle", CHANGE_ID])
    bundle = ws.run(["gate", "verify-bundle", CHANGE_ID, "--json"]).json()
    ws.run(["change", "status", CHANGE_ID])
    return _summary(ws, readiness, report, unit, mutation, trace, before, verdict, bundle)


def _summary(
    ws: Workspace,
    readiness: dict[str, Any],
    report: dict[str, Any],
    unit: dict[str, Any],
    mutation: dict[str, Any],
    trace: dict[str, Any],
    before: dict[str, Any],
    verdict: dict[str, Any],
    bundle: dict[str, Any],
) -> str:
    cov = unit["coverage"]
    g6_before = next(r for r in before["results"] if r["gate"] == "G6")
    tasks = ", ".join(f"{t['task_id']} {t['status']}" for t in report["tasks"])
    lines = [
        f"Last run: {ws.elapsed():.0f}s, pre-change `{ws.baseline_sha[:12]}` → change "
        f"`{ws.change_sha[:12]}` → merged HEAD `{ws.head()[:12]}`.",
        "",
        f"- G0 readiness: ready={readiness['ready']}, ambiguity score "
        f"{readiness['ambiguity_score']:.2f}",
        f"- Dry run: outcome `{report['outcome']}`; {tasks}; final review "
        f"`{report['final_review_verdict']}`; usage {report['usage']['calls']} calls, "
        f"${report['usage']['cost_usd']:.4f}",
        f"- Unit coverage: lines {cov['lines']}%, branches {cov['branches']}%, diff "
        f"{cov['diff_lines']}% (vs pre-change commit); mutation score "
        f"{mutation['score']:.2f} ({mutation['killed']} killed / {mutation['survived']} "
        f"survived, scope {mutation['scope']})",
        f"- Traceability: {trace['scenarios_with_tests']}/{trace['scenarios']} scenarios "
        f"referenced by tests, critical journeys in e2e {trace['critical_journeys_e2e']}%",
        f"- Before the human approval G6 said: {'; '.join(g6_before['reasons'])}",
        f"- Final verdict overall: **{'PASS' if verdict['overall'] else 'FAIL'}**; bundle "
        f"{'OK' if bundle['ok'] else 'FAILED'} with {bundle['valid_signatures']} valid "
        f"signature(s), {bundle['approvals']} approval(s)",
        "",
        ws.gate_table(),
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(pilotlib.main(run, pilot_dir=PILOT_DIR, change_id=CHANGE_ID, pre_change=PRE_CHANGE))
