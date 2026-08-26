"""The pilot projects (ARCHITECTURE.md §1 ``pilots/``) as end-to-end fixtures.

Two generations of pilots live under ``pilots/``:

* the three *class* pilots (docs-only library, standard web service, AI agent) are copied
  into a fresh git repository and driven through the documented walk-through with the
  CLI: intake readiness/checklist -> plan check -> ``run change`` with the dry runner ->
  gate evaluation. The dry runner does not implement anything, so the pilots ship in their
  implemented state and the task verification commands must pass against it;
* the three *flow* pilots (``crud-app``, ``lowcode-generated``, ``tool-agent``) each carry a
  ``run.sh``/``pilot_*.py`` driver (``pilots/pilotlib.py``) that runs the whole platform
  flow — pre-change baseline commit, intake, governed dry run, every evidence producer,
  gates, approvals, signed bundle — and are asserted here on the evidence they produce:
  every gate passes for the CRUD app; G0 blocks then passes after the clarification loop
  for the generated app; G4 fails on the red-team baseline and passes after the screening
  fix, with the ASR delta recorded, for the tool-using agent.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from typer.testing import CliRunner

from aisdlc.cli.main import app
from aisdlc.policy import load_project_config
from aisdlc.schema import package as pkgio
from aisdlc.schema.grammar import validate_package
from aisdlc.schema.models import ChangeState, GateId, RiskClass, TaskStatus

runner = CliRunner()
REPO = Path(__file__).resolve().parents[1]
PILOTS = REPO / "pilots"

PILOT_CASES: list[tuple[str, str, RiskClass, int]] = [
    ("docs-only-library", "CHG-document-shapes-api", RiskClass.DOCS_ONLY, 2),
    ("standard-web-service", "CHG-add-health-endpoint", RiskClass.STANDARD, 3),
    ("ai-agent", "CHG-support-assistant-tools", RiskClass.AI_AGENT, 4),
]

FLOW_PILOTS: dict[str, tuple[str, str, RiskClass]] = {
    "crud-app": ("pilot_crud_app", "CHG-add-ticket-priority", RiskClass.STANDARD),
    "lowcode-generated": ("pilot_lowcode", "CHG-lunch-order-form", RiskClass.STANDARD),
    "tool-agent": ("pilot_tool_agent", "CHG-screen-tool-inputs", RiskClass.AI_AGENT),
}


def run(args: Sequence[str], ok: Sequence[int] = (0,)) -> str:
    result = runner.invoke(app, list(args))
    assert result.exit_code in ok, (
        f"aisdlc {' '.join(args)} exited {result.exit_code}\n{result.output}"
    )
    return result.output


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def pilot_repo(tmp_path: Path, request: pytest.FixtureRequest) -> Path:
    """Copy of one pilot committed into a fresh git repository (cwd set to it)."""
    name = request.param
    repo = tmp_path / name
    shutil.copytree(PILOTS / name, repo)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "pilot@example.com")
    _git(repo, "config", "user.name", "pilot")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "pilot baseline")
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.chdir(repo)
    monkeypatch.delenv("AISDLC_LEDGER", raising=False)
    request.addfinalizer(monkeypatch.undo)
    return Path(repo)


# --------------------------------------------------------------------------------------
# Class pilots (walk-through)
# --------------------------------------------------------------------------------------


def test_pilot_layout_lists_every_project_class() -> None:
    names = sorted(
        p.name for p in PILOTS.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))
    )
    expected = sorted([*(name for name, *_ in PILOT_CASES), *FLOW_PILOTS])
    assert names == expected
    for name, change, risk, task_count in PILOT_CASES:
        base = PILOTS / name
        assert (base / "aisdlc.yaml").is_file() and (base / "README.md").is_file()
        assert load_project_config(base / "aisdlc.yaml").risk_classification.default is risk
        pkg = pkgio.load(base / "changes" / change)
        assert pkg.intent.risk_class is risk and pkg.intent.owner
        assert validate_package(pkg) == []
        assert len(pkg.tasks) == task_count and all(t.verification for t in pkg.tasks)
        assert pkg.derive_state() is ChangeState.PLANNED
        assert pkg.requirements and all(r.scenarios for r in pkg.requirements)


@pytest.mark.parametrize("pilot_repo", [c[0] for c in PILOT_CASES], indirect=True)
def test_pilot_walkthrough(pilot_repo: Path) -> None:
    name = pilot_repo.name
    change, risk, task_count = next(c[1:] for c in PILOT_CASES if c[0] == name)
    pkg_dir = pilot_repo / "changes" / change

    readiness = json.loads(run(["intake", "readiness", change, "--json"]))
    assert readiness["ready"] and not readiness["blocking_questions"], readiness
    run(["intake", "checklist", change], ok=(0, 1))
    run(["plan", "check", change], ok=(0, 1))

    out = run(["run", "change", change, "--runner", "dry", "--yes", "--json"])
    report = json.loads(out)
    assert report["outcome"] == "success", out
    assert {t["task_id"]: t["status"] for t in report["tasks"]} == {
        f"TASK-{i:03d}": "done" for i in range(1, task_count + 1)
    }
    # the pilot's own verification commands ran inside the worktrees and passed
    reloaded = pkgio.load(pkg_dir)
    assert all(t.status is TaskStatus.DONE for t in reloaded.tasks)
    assert len(reloaded.evidence.tests) >= task_count
    assert all(e.succeeded and e.is_complete for e in reloaded.evidence.tests)
    assert reloaded.evidence.reviews and all(r.independent for r in reloaded.evidence.reviews)
    assert reloaded.evidence.cost is not None
    assert (pkg_dir / pkgio.HANDOFFS_DIR).is_dir()
    # authored artifacts survived the run untouched
    assert pkgio.load(PILOTS / name / "changes" / change).requirements == reloaded.requirements

    gates = json.loads(run(["gate", "evaluate", change, "--json"], ok=(0, 1)))
    assert gates["risk_class"] == risk.value
    results = {r["gate"]: r for r in gates["results"]}
    assert set(results) == {g.value for g in GateId}
    assert results["G0"]["passed"], results["G0"]
    assert results["G1"]["passed"], results["G1"]
    assert results["G3"]["passed"], results["G3"]
    # the run's verification evidence reached G2 ...
    assert results["G2"]["evidence_ids"], results["G2"]
    assert not any("no test evidence" in r for r in results["G2"]["reasons"])
    if risk is RiskClass.DOCS_ONLY:
        # ... G4/G5/G6 are not part of the light docs profile
        assert all(results[g]["depth"] == "skipped" for g in ("G1", "G4", "G5", "G6"))
        assert results["G2"]["depth"] == "light"
    else:
        # deeper profiles fail closed until coverage/portfolio and security evidence exist
        assert not results["G2"]["passed"] and not results["G4"]["passed"]
        assert any("coverage" in r for r in results["G2"]["reasons"])
        assert "no security evidence" in results["G4"]["reasons"]


# --------------------------------------------------------------------------------------
# Flow pilots (run.sh drivers)
# --------------------------------------------------------------------------------------


def _load_driver(name: str) -> ModuleType:
    module_name, _, _ = FLOW_PILOTS[name]
    path = PILOTS / name / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _run_flow(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, str]:
    """Run a flow pilot in a temp copy (no sync-back); returns ``(workspace, summary)``."""
    monkeypatch.delenv("AISDLC_LEDGER", raising=False)
    driver = _load_driver(name)
    import pilotlib  # noqa: PLC0415 - pilots/ is put on sys.path by the driver

    ws = pilotlib.prepare(
        PILOTS / name,
        tmp_path / name,
        change_id=driver.CHANGE_ID,
        pre_change=driver.PRE_CHANGE,
        quiet=True,
    )
    summary = driver.run(ws)
    ws.write_log()
    return ws, summary


def _verdict(ws: Any) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (ws.package_dir / "final-verdict.json").read_text(encoding="utf-8")
    )
    return data


def _gate(ws: Any, gate: str) -> dict[str, Any]:
    result: dict[str, Any] = next(r for r in _verdict(ws)["gate_results"] if r["gate"] == gate)
    return result


def _steps(ws: Any, *prefix: str) -> list[Any]:
    return [s for s in ws.steps if s.argv[: len(prefix)] == list(prefix)]


def test_flow_pilots_ship_drivers_and_a_recorded_last_run() -> None:
    for name, (module_name, change, risk) in FLOW_PILOTS.items():
        base = PILOTS / name
        assert (base / "run.sh").is_file() and (base / f"{module_name}.py").is_file()
        assert (base / "aisdlc.yaml").is_file()
        assert load_project_config(base / "aisdlc.yaml").risk_classification.default is risk
        readme = (base / "README.md").read_text(encoding="utf-8")
        assert "<!-- run-output:start -->" in readme and "| G6 | PASS |" in readme
        package = base / "changes" / change
        assert (package / "final-verdict.json").is_file()
        assert (package / "evidence" / "security.json").is_file()
        assert json.loads((package / "final-verdict.json").read_text())["overall"] is True


def test_crud_app_pilot_passes_every_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ws, summary = _run_flow("crud-app", tmp_path, monkeypatch)
    verdict = _verdict(ws)
    assert verdict["overall"] is True
    assert all(r["passed"] for r in verdict["gate_results"])
    assert {r["depth"] for r in verdict["gate_results"]} == {"standard"}
    pkg = pkgio.load(ws.package_dir)
    unit = next(e for e in pkg.evidence.tests if e.coverage.diff_lines is not None)
    assert unit.coverage.lines and unit.coverage.lines >= 78
    assert unit.coverage.diff_lines is not None and unit.coverage.diff_lines >= 90
    assert unit.mutation is not None and unit.mutation.score is not None
    assert unit.mutation.score >= 0.6 and unit.mutation.scope == ["tickets/service.py"]
    assert pkg.evidence.security is not None and pkg.evidence.security.sast is not None
    assert pkg.evidence.security.sast.ran and pkg.evidence.security.sast.tool == "ruff"
    assert all(t.status is TaskStatus.DONE for t in pkg.tasks)
    # G6 was failing only on the missing human approval before `gate approve`
    before = _steps(ws, "gate", "evaluate")[0].json()
    g6 = next(r for r in before["results"] if r["gate"] == "G6")
    assert g6["reasons"] == ["0 human approval(s) recorded, 1 required"]
    assert "| G6 | PASS |" in summary


def test_lowcode_pilot_blocks_g0_until_clarified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws, summary = _run_flow("lowcode-generated", tmp_path, monkeypatch)
    g0_steps = _steps(ws, "gate", "evaluate", ws.change_id, "--gate", "G0")
    assert [s.exit_code for s in g0_steps] == [1, 0]
    blocked = g0_steps[0].json()["results"][0]
    assert not blocked["passed"]
    reasons = " ".join(blocked["reasons"])
    assert "ambiguity score" in reasons and "no owner" in reasons
    assert "blocking open question" in reasons
    assert g0_steps[1].json()["results"][0]["passed"]
    clarify = _steps(ws, "intake", "clarify")
    before, after = clarify[0].json(), clarify[-1].json()
    assert before["ambiguity_score"] > 0.20 > after["ambiguity_score"]
    assert before["questions"] and not after["questions"]
    pkg = pkgio.load(ws.package_dir)
    assert "discovery" in pkg.intent.labels and pkg.intent.owner
    assert any(r.kind.value == "non_functional" for r in pkg.requirements)
    assert all(r.scenarios for r in pkg.requirements)
    verdict = _verdict(ws)
    assert verdict["overall"] is True and all(r["passed"] for r in verdict["gate_results"])
    assert "G0 before clarification: **FAIL**" in summary
    assert "G0 after clarification: **PASS**" in summary


@pytest.mark.integration
def test_tool_agent_pilot_g4_fails_then_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("pyrit")
    ws, summary = _run_flow("tool-agent", tmp_path, monkeypatch)
    reports = ws.package_dir / "evidence" / "reports"
    before = json.loads((reports / "campaign-before.json").read_text())
    after = json.loads((reports / "campaign-after.json").read_text())
    g4_before = json.loads((reports / "g4-before-fix.json").read_text())["results"][0]
    assert before["complete"] and before["asr"] > 0.05
    assert before["asr_by_category"]["prompt-injection"] > 0
    assert not g4_before["passed"]
    assert any("attack success rate" in r for r in g4_before["reasons"])
    assert after["complete"] and after["asr"] == 0.0 and after["undetermined_rate"] == 0.0
    assert after["baseline_delta"]["baseline_id"] == "pre-change"
    assert after["baseline_delta"]["asr_delta"] < 0 and not after["baseline_delta"]["regressed"]
    pkg = pkgio.load(ws.package_dir)
    security = pkg.evidence.security
    assert security is not None and security.pyrit is not None
    assert security.pyrit.asr == 0.0 and security.pyrit.baseline_delta is not None
    assert security.pyrit.baseline_delta < 0
    assert security.safety_regression is not None and security.safety_regression.complete
    assert security.safety_regression.threshold_breaches == []
    assert set(security.safety_regression.asr_by_category) >= {
        "prompt-injection",
        "tool-misuse",
        "data-exfiltration",
        "destructive-action",
        "secret-disclosure",
    }
    assert pkg.evidence.audit is not None and pkg.evidence.audit.integrity_ok
    # the audited phases are the red-team campaign and the safety suite: privileged reads
    # and denied tool requests, never an approved e-mail (no objective targets an on-file address)
    assert pkg.evidence.audit.privileged_calls > 0 and pkg.evidence.audit.denied_calls > 0
    assert pkg.evidence.audit.entries > pkg.evidence.audit.privileged_calls
    drift = _steps(ws, "ci", "manifest-drift", ws.change_id, "--json")[0].json()
    assert drift["drift"] is False and drift["observed_records"] > 0
    assert pkg.evidence.performance is not None and pkg.evidence.performance.slo_met
    verdict = _verdict(ws)
    assert verdict["overall"] is True
    assert {r["depth"] for r in verdict["gate_results"]} == {"deep"}
    assert _gate(ws, "G4")["passed"]
    approvals = json.loads((ws.package_dir / "approvals.json").read_text())
    assert {a["role"] for a in approvals} == {"owner", "security"}
    assert "G4 before the fix: **FAIL**" in summary and "| G4 | PASS |" in summary


def test_shipped_pilots_validate_threat_models_and_classify_from_tools_not_data() -> None:
    """Every shipped threat model validates; only a manifest with tools makes a pilot agentic."""
    cases = [(name, change) for name, change, *_ in PILOT_CASES]
    cases.extend((name, change) for name, (_module, change, _risk) in FLOW_PILOTS.items())
    for name, change in cases:
        pkg_dir = PILOTS / name / "changes" / change
        validated = json.loads(run(["plan", "threat-model", "validate", str(pkg_dir), "--json"]))
        assert validated["passed"], (name, validated)
        classified = json.loads(run(["plan", "risk", "classify", str(pkg_dir), "--json"]))
        manifest_signals = [s for s in classified["signals"] if s["source"] == "manifest"]
        pkg = pkgio.load(pkg_dir)
        tools = pkg.threat_model.tool_data_manifest.tools if pkg.threat_model else []
        if tools:
            assert classified["computed"] == "ai_agent", (name, classified["reasons"])
        else:
            assert not any(s["risk_class"] == "ai_agent" for s in manifest_signals), (
                manifest_signals
            )
            assert classified["computed"] != "ai_agent", (name, classified["reasons"])
