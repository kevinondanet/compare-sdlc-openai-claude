# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Fresh-output smoke regression for the documented enterprise AI-SDLC demo."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agent_sre.sdlc.canonical import canonical_json_bytes

REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
DEMO = REPOSITORY_ROOT / "examples/enterprise-ai-sdlc/demo.py"


def test_readme_demo_command_succeeds_in_fresh_output_directory(
    tmp_path: Path,
) -> None:
    """Run the documented entry point and verify its release-critical outputs."""

    output = tmp_path / "fresh-output"
    environment = os.environ.copy()
    source = REPOSITORY_ROOT / "agent-governance-python/agent-sre/src"
    inherited = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = f"{source}{os.pathsep}{inherited}" if inherited else str(source)

    completed = subprocess.run(
        [sys.executable, str(DEMO), "--output", str(output)],
        cwd=REPOSITORY_ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["gate_statuses"] == {f"G{index}": "pass" for index in range(7)}
    assert summary["readiness"] == "ready"
    assert summary["pyrit_release_verdict"] == "pass"
    assert summary["golden_verdict"] == "fail"
    assert summary["tool_call_audits"] == 5
    assert summary["review_rounds"] == 2
    assert summary["remediation_rounds"] == 1
    assert summary["rampart_issuer_verified"] is True
    assert min(summary["rampart_cases_per_dimension"].values()) >= 6

    for relative in (
        "evidence/reports/rampart-native-report.json",
        "evidence/reports/rampart-campaign.json",
        "evidence/reports/rampart-safety-report.json",
    ):
        retained = (output / relative).read_bytes()
        assert retained == canonical_json_bytes(json.loads(retained))
