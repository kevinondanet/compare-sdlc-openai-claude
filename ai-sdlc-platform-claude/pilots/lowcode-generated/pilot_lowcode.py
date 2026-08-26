"""Pilot 2 — business-user-led generated application: ``CHG-lunch-order-form`` end to end.

The change package does not exist up front: ``aisdlc intake discover`` derives it from
the office manager's plain-language answers (``answers.yaml``). The run shows G0 blocking
on the sparse intent, the clarification loop (ambiguity score before/after), G0 passing,
the architect's artifacts, ``plan generate``, generation of the application from the form,
the governed dry run and the full evidence chain up to a signed bundle.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

PILOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PILOT_DIR.parent))

import pilotlib  # noqa: E402
from pilotlib import PreChange, Workspace, python, sh  # noqa: E402

CHANGE_ID = "CHG-lunch-order-form"
OWNER = "office-manager@example.com"
SUCCESS_SIGNAL = (
    "Lunch-related emails to the office manager drop from 20 to under 5 per week "
    "within two months of launch"
)
PRE_CHANGE = PreChange(
    overlay_dir="before",
    absent=(
        "forms/lunch-order.json",
        "lowcode/generated/lunch_order.py",
        "tests/test_lunch_order.py",
        "tests/test_e2e.py",
        "tests/test_contract.py",
    ),
    generated_package=True,
)
UNIT_MODULES = "tests.test_engine tests.test_lunch_order"
LAYERS = ("integration", "contract", "e2e", "architecture")


def sign_intent(ws: Workspace, owner: str) -> None:
    """Record the accountable owner on the intent (no CLI exposes this yet)."""
    from aisdlc.schema import package as pkgio

    pkg = pkgio.load(ws.package_dir)
    pkg.intent.owner = owner
    pkg.save(base_fingerprint=pkg.base_fingerprint)
    ws.note(f"intent signed: owner set to {owner} through the schema API (aisdlc.schema.package)")


def run(ws: Workspace) -> str:
    """Drive the whole flow; returns the Markdown summary for the README."""
    py = python()
    ws.section("1. Discovery: the office manager answers the plain-language script")
    ws.init_platform()
    discovered = ws.run(
        ["intake", "discover", "--answers", "answers.yaml", "--root", ".", "--json"]
    ).json()
    if discovered["change_id"] != CHANGE_ID:
        raise pilotlib.PilotError(f"discovery produced {discovered['change_id']}")
    brd = ws.reports_dir / "brd.md"
    ws.run(
        [
            "intake",
            "discover",
            "--answers",
            "answers.yaml",
            "--root",
            ".",
            "--dry-run",
            "--markdown",
            str(brd.relative_to(ws.root)),
        ],
        note="The BRD/PRD summary the business user reviews (written to evidence/reports/brd.md).",
    )

    ws.section("2. G0 before clarification (blocked)")
    readiness_before = ws.run(["intake", "readiness", CHANGE_ID, "--json"], ok=(1,)).json()
    g0_before = ws.run(["gate", "evaluate", CHANGE_ID, "--gate", "G0", "--json"], ok=(1,)).json()
    ws.run(["intake", "checklist", CHANGE_ID], ok=(0, 1))

    ws.section("3. Clarification loop")
    questions = ws.run(["intake", "clarify", CHANGE_ID, "--limit", "30", "--json"]).json()
    round1 = ws.run(
        [
            "intake",
            "clarify",
            CHANGE_ID,
            "--limit",
            "30",
            "--answers",
            "clarifications/round-1.yaml",
            "--json",
        ]
    ).json()
    round2 = ws.run(
        [
            "intake",
            "clarify",
            CHANGE_ID,
            "--limit",
            "30",
            "--answers",
            "clarifications/round-2.yaml",
            "--json",
        ]
    ).json()
    ws.run(["intake", "kernel", CHANGE_ID, "--success", SUCCESS_SIGNAL])
    sign_intent(ws, OWNER)

    ws.section("4. G0 after clarification (passes)")
    readiness_after = ws.run(["intake", "readiness", CHANGE_ID, "--json"]).json()
    g0_after = ws.run(["gate", "evaluate", CHANGE_ID, "--gate", "G0", "--json"]).json()
    ws.run(["intake", "checklist", CHANGE_ID], ok=(0, 1))

    ws.section("5. Architecture artifacts (solution architect) and the derived plan")
    overlay = PILOT_DIR / "spec-overlay" / "architecture"
    shutil.copytree(overlay, ws.package_dir / "architecture", dirs_exist_ok=True)
    ws.note("copied spec-overlay/architecture (context, ADR-0001, threat model) into the package")
    ws.run(["plan", "adr", "validate", CHANGE_ID])
    ws.run(["plan", "threat-model", "validate", CHANGE_ID])
    ws.run(["plan", "generate", CHANGE_ID, "--no-docs-task"])
    ws.run(["plan", "check", CHANGE_ID])
    ws.run(["intake", "analyze", CHANGE_ID], ok=(0, 1))
    ws.run(["change", "validate", CHANGE_ID])
    ws.run(["plan", "risk", "classify", CHANGE_ID, "--path", "lowcode/generated/lunch_order.py"])

    ws.section("6. Generate the application from the form and commit it as the change")
    (ws.root / "forms").mkdir(exist_ok=True)
    shutil.copy2(PILOT_DIR / "forms" / "lunch-order.json", ws.root / "forms" / "lunch-order.json")
    ws.note(
        "the office manager adds forms/lunch-order.json (dish, quantity, team, notes; cut-off Friday 10:00)"
    )
    ws.shell(f"{py} -m lowcode.generator forms/lunch-order.json")
    ws.commit_change(
        f"{CHANGE_ID}: generated lunch-order application, tests and the change package"
    )

    ws.section("7. Governed implementation run (dry runner, worktrees, independent review)")
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

    ws.section("8. Test evidence: unit coverage, diff coverage, mutation, portfolio layers")
    unit = ws.run(
        [
            "test",
            "run-evidence",
            CHANGE_ID,
            "--command",
            sh(
                f"{py} -m coverage run --branch --source=lowcode -m unittest -q {UNIT_MODULES}"
                f" && {py} -m coverage json -q -o coverage.json"
            ),
            "--coverage-json",
            "coverage.json",
            "--diff-base",
            ws.baseline_sha,
            "--report-uri",
            "coverage.json",
            "--json",
        ]
    ).json()
    mutation = ws.run(
        [
            "test",
            "mutation",
            "--builtin",
            "lowcode/app.py",
            "lowcode/table.py",
            "--command",
            f"{py} -m unittest -q {UNIT_MODULES}",
            "--package",
            CHANGE_ID,
            "--max-mutants",
            "20",
            "--cwd",
            ".",
            "--json",
        ]
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

    ws.section("9. Security evidence (plane 1 artifacts), manifest check, portfolio")
    pilotlib.ruff_sarif(ws.root, ["lowcode"], ws.root / "ci-artifacts" / "ruff.sarif")
    ws.note("generated ci-artifacts/ruff.sarif with `ruff check --output-format sarif lowcode`")
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
    ws.run(["test", "portfolio", CHANGE_ID, "--layers", str(layers_path.relative_to(ws.root))])

    ws.section("10. Cost, gates, human approval, signed evidence bundle")
    ws.run(["cost", "report", "--change", CHANGE_ID, "--group-by", "agent_role"])
    before = ws.run(["gate", "evaluate", CHANGE_ID, "--json"], ok=(0, 1)).json()
    ws.run(
        [
            "gate",
            "approve",
            CHANGE_ID,
            "--role",
            "owner",
            "--approver",
            OWNER,
            "--note",
            "the form works for the Friday run",
        ]
    )
    verdict = ws.run(["gate", "verdict", CHANGE_ID, "--json"]).json()
    ws.run(["gate", "bundle", CHANGE_ID])
    bundle = ws.run(["gate", "verify-bundle", CHANGE_ID, "--json"]).json()
    ws.run(["change", "status", CHANGE_ID])
    return _summary(
        ws,
        discovered=discovered,
        readiness_before=readiness_before,
        g0_before=g0_before,
        questions=questions,
        round1=round1,
        round2=round2,
        readiness_after=readiness_after,
        g0_after=g0_after,
        report=report,
        unit=unit,
        mutation=mutation,
        trace=trace,
        before=before,
        verdict=verdict,
        bundle=bundle,
    )


def _summary(ws: Workspace, **d: Any) -> str:
    cov = d["unit"]["coverage"]
    g0b = d["g0_before"]["results"][0]
    g0a = d["g0_after"]["results"][0]
    g6_before = next(r for r in d["before"]["results"] if r["gate"] == "G6")
    asked = [f"{q['id']} ({q['category']}): {q['question']}" for q in d["questions"]["questions"]]
    applied = [
        f"{a['question_id']}: {'; '.join(a['changes'])}"
        for a in d["round1"]["applied"] + d["round2"]["applied"]
    ]
    lines = [
        f"Last run: {ws.elapsed():.0f}s, pre-change `{ws.baseline_sha[:12]}` → change "
        f"`{ws.change_sha[:12]}` → merged HEAD `{ws.head()[:12]}`.",
        "",
        f"- Discovery produced `{d['discovered']['change_id']}` with "
        f"{len(d['discovered']['requirements'])} draft requirement(s), "
        f"{len(d['discovered']['open_questions'])} open question(s), risk class "
        f"`{d['discovered']['risk_class']}`",
        f"- G0 before clarification: **{'PASS' if g0b['passed'] else 'FAIL'}** — "
        f"{'; '.join(g0b['reasons'])}",
        f"- Ambiguity score before {d['questions']['ambiguity_score']:.2f} → after round 1 "
        f"{d['round1']['ambiguity_score']:.2f} → after round 2 {d['round2']['ambiguity_score']:.2f}"
        f" (readiness {d['readiness_before']['ambiguity_score']:.2f} → "
        f"{d['readiness_after']['ambiguity_score']:.2f})",
        "- Questions asked (ranked):",
        *[f"  - {q}" for q in asked],
        "- Answers applied:",
        *[f"  - {a}" for a in applied],
        f"- G0 after clarification: **{'PASS' if g0a['passed'] else 'FAIL'}**"
        + (f" — {'; '.join(g0a['reasons'])}" if g0a["reasons"] else ""),
        f"- Dry run: outcome `{d['report']['outcome']}`; "
        + ", ".join(f"{t['task_id']} {t['status']}" for t in d["report"]["tasks"])
        + f"; final review `{d['report']['final_review_verdict']}`",
        f"- Unit coverage: lines {cov['lines']}%, branches {cov['branches']}%, diff "
        f"{cov['diff_lines']}% (vs pre-change commit); mutation score "
        f"{d['mutation']['score']:.2f} ({d['mutation']['killed']} killed / "
        f"{d['mutation']['survived']} survived)",
        f"- Traceability: {d['trace']['scenarios_with_tests']}/{d['trace']['scenarios']} "
        f"scenarios referenced by tests, critical journeys in e2e "
        f"{d['trace']['critical_journeys_e2e']}%",
        f"- Before the human approval G6 said: {'; '.join(g6_before['reasons'])}",
        f"- Final verdict overall: **{'PASS' if d['verdict']['overall'] else 'FAIL'}**; bundle "
        f"{'OK' if d['bundle']['ok'] else 'FAILED'} with {d['bundle']['valid_signatures']} valid "
        f"signature(s), {d['bundle']['approvals']} approval(s)",
        "",
        ws.gate_table(),
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(pilotlib.main(run, pilot_dir=PILOT_DIR, change_id=CHANGE_ID, pre_change=PRE_CHANGE))
