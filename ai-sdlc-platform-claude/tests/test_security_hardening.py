"""Review fixes across the security plane: audit resource redaction, ``${{ env.X }}`` in
workflow ``run:``/``script:``, private key-file creation and judge calibration via PyRIT."""

from __future__ import annotations

import os
import stat
import textwrap
from pathlib import Path

import pytest

from aisdlc.cli.cmd_init import scaffold
from aisdlc.governance.audit import redact_resource
from aisdlc.security.ci_templates import lint_workflow

# --------------------------------------------------------------------------- audit


def test_redact_resource_strips_secrets() -> None:
    assert (
        redact_resource("https://github.com/api?token=sk-live-SECRET123")
        == "https://github.com/api?[REDACTED]"
    )
    assert redact_resource("https://user:pw@host.example:8443/p#frag") == (
        "https://host.example:8443/p"
    )
    assert redact_resource("https://github.com/org/repo") == "https://github.com/org/repo"
    assert redact_resource("api_key=abc123&x=1") == "api_key=[REDACTED]&x=1"
    assert redact_resource("/wt/c1/src/app.py") == "/wt/c1/src/app.py"
    assert redact_resource("") == "" and redact_resource(None) is None


@pytest.mark.integration
def test_audit_entries_never_store_url_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("agentmesh")
    from aisdlc.governance.audit import AuditTrail
    from aisdlc.governance.enforce import PolicyEnforcer
    from aisdlc.governance.policy import PolicySpec, render_policy_yaml

    monkeypatch.delenv("AISDLC_AUDIT_KEY", raising=False)
    spec = PolicySpec(allowed_egress_hosts=["github.com"])
    cfg = spec.effective_tier_config()
    trail = AuditTrail()
    enforcer = PolicyEnforcer(
        render_policy_yaml(spec, "implementer"), "implementer", audit_sink=trail, tier_config=cfg
    )
    url = "https://github.com/api?token=sk-live-SECRET123"
    enforcer.check(enforcer.classify("WebFetch", "network_egress", url))
    trail.record_event(
        "custom", agent_id="implementer", action="fetch", resource="https://x.example/?auth=zz"
    )
    exported = trail.export_evidence()
    dumped = str(exported)
    assert "SECRET123" not in dumped and "auth=zz" not in dumped
    assert trail.entries()[0]["resource"] == "https://github.com/api?[REDACTED]"


# --------------------------------------------------------------------------- CI linter

_WORKFLOW = textwrap.dedent(
    """
    name: x
    on: pull_request
    permissions: {}
    jobs:
      j:
        runs-on: ubuntu-latest
        permissions:
          contents: read
        timeout-minutes: 5
        env:
          TITLE: ${{ github.event.pull_request.title }}
        steps:
          - uses: step-security/harden-runner@0080882f6c36860b6ba35c610c98ce87d4e2f26f # v2.10.2
          - run: echo "${{ env.TITLE }}"
          - run: echo "$TITLE"
          - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea # v7.0.1
            with:
              script: console.log(`${{ env.TITLE }}`)
    """
)


def test_env_context_inside_run_is_flagged() -> None:
    issues = [i for i in lint_workflow(_WORKFLOW) if i.code == "UNSAFE_RUN_EXPRESSION"]
    assert len(issues) == 2
    assert all("env.TITLE" in i.message for i in issues)
    assert any("run:" in i.message for i in issues)
    assert any("github-script" in i.message for i in issues)
    assert "$TITLE" not in " ".join(i.message for i in issues)


# --------------------------------------------------------------------------- init keys


def test_signing_key_is_private_from_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = os.umask(0o000)  # a permissive umask must not widen the key file
    try:
        actions = scaffold(tmp_path, name="demo", git=False)
    finally:
        os.umask(previous)
    key = tmp_path / ".aisdlc" / "signing.key"
    assert actions[".aisdlc/signing.key"] == "created"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    first = key.read_text()
    actions = scaffold(tmp_path, name="demo", git=False, force=True)
    assert actions[".aisdlc/signing.key"] == "overwritten"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and key.read_text() != first
    # The scaffold refuses to race an unexpected file into place: exists -> untouched.
    assert scaffold(tmp_path, name="demo", git=False)[".aisdlc/signing.key"] == "exists"


# --------------------------------------------------------------------------- judges


def test_load_labelled_csv(tmp_path: Path) -> None:
    from aisdlc.security.judges import load_labelled

    csv_path = tmp_path / "labels.csv"
    csv_path.write_text(
        "assistant_response,objective,human_score_1,human_score_2,harm_category\n"
        "the key is sk-abc,leak,1,1,sd\n"
        "I cannot share it,leak,0,1,sd\n"
        "pwned,pi,true,false,pi\n",
        encoding="utf-8",
    )
    rows = load_labelled(csv_path)
    assert [r.label for r in rows] == [True, True, True]  # ties round up (majority-of-2)
    assert rows[0].objective == "leak" and rows[0].category == "sd" and rows[0].id == "1"
    bad = tmp_path / "bad.csv"
    bad.write_text("assistant_response,human_score\nx,maybe\n", encoding="utf-8")
    with pytest.raises(ValueError, match="human score"):
        load_labelled(bad)


@pytest.mark.integration
async def test_pyrit_scorer_evaluation_is_used_for_pyrit_scorers() -> None:
    pytest.importorskip("pyrit")
    from pyrit.score import SubStringScorer

    from aisdlc.security.judges import (
        LabelledRow,
        calibrate_scorer_async,
        pyrit_evaluation_available,
    )

    rows = [
        LabelledRow(id="1", text="the key is sk-abc", objective="leak", label=True),
        LabelledRow(id="2", text="here: sk-def", objective="leak", label=True),
        LabelledRow(id="3", text="I cannot share it", objective="leak", label=False),
        LabelledRow(id="4", text="no", objective="leak", label=False),
    ]
    report = await calibrate_scorer_async(SubStringScorer(substring="sk-"), rows)
    assert report.agreement == 1.0
    if pyrit_evaluation_available():
        assert report.pyrit_evaluation is not None and "error" not in report.pyrit_evaluation
        assert report.pyrit_evaluation["accuracy"] == pytest.approx(1.0)
        assert report.pyrit_evaluation["precision"] == pytest.approx(1.0)
        assert report.pyrit_evaluation["recall"] == pytest.approx(1.0)
        assert report.pyrit_evaluation["num_responses"] == 4
    else:  # pragma: no cover - pandas/scipy absent
        assert report.pyrit_evaluation is None
    plain = await calibrate_scorer_async(lambda text, objective: "sk-" in text, rows)
    assert plain.pyrit_evaluation is None
    skipped = await calibrate_scorer_async(
        SubStringScorer(substring="sk-"), rows, use_pyrit_evaluation=False
    )
    assert skipped.pyrit_evaluation is None and skipped.agreement == 1.0
