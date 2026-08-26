"""``aisdlc cost import`` — telemetry importers reachable from the CLI (review finding)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aisdlc.cli.cmd_cost import app
from aisdlc.control_plane.ledger import UsageLedger

runner = CliRunner()


def _cc_line(request_id: str, model: str = "claude-sonnet-5", tool: bool = False) -> str:
    content: list[dict[str, object]] = [{"type": "text", "text": "hi"}]
    if tool:
        content.append({"type": "tool_use", "name": "Read", "input": {}})
    return json.dumps(
        {
            "type": "assistant",
            "timestamp": "2026-08-25T12:00:00.000Z",
            "requestId": request_id,
            "sessionId": "sess-1",
            "cwd": "/repo",
            "message": {
                "id": f"msg-{request_id}",
                "model": model,
                "role": "assistant",
                "content": content,
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 100,
                    "cache_read_input_tokens": 5000,
                    "cache_creation_input_tokens": 2000,
                },
            },
        }
    )


def test_import_claude_code_jsonl(tmp_path: Path) -> None:
    transcript = tmp_path / "session.jsonl"
    transcript.write_text(
        "\n".join(
            [
                json.dumps({"type": "user", "message": {"role": "user", "content": "hello"}}),
                _cc_line("req_1"),
                _cc_line("req_1", tool=True),  # streaming duplicate -> deduped
                _cc_line("req_2", model="claude-opus-5"),
            ]
        )
    )
    ledger = tmp_path / "ledger.sqlite"
    result = runner.invoke(
        app,
        [
            "import",
            "claude-code",
            str(transcript),
            "--change",
            "CHG-x",
            "--task",
            "TASK-001",
            "--role",
            "implementer",
            "--team",
            "core",
            "--ledger",
            str(ledger),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["source"] == "claude_code" and summary["events"] == 2
    assert summary["recorded"] == 2 and summary["cost_usd"] > 0
    assert summary["models"] == ["claude-opus-5", "claude-sonnet-5"]
    with UsageLedger(str(ledger)) as led:
        events = led.query({"change_id": "CHG-x"})
        assert len(events) == 2
        assert {e.task_id for e in events} == {"TASK-001"}
        assert {e.agent_role for e in events} == {"implementer"}
        assert {e.harness for e in events} == {"claude_code"} and events[0].team == "core"
        assert max(e.tool_calls for e in events) == 1
        assert all(e.cost_usd > 0 for e in events)
    # the imported spend is visible to the budget/report commands
    report = runner.invoke(app, ["report", "--change", "CHG-x", "--ledger", str(ledger), "--json"])
    assert report.exit_code == 0 and sum(r["calls"] for r in json.loads(report.output)) == 2


def test_import_agt_audit_formats(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.sqlite"
    array = tmp_path / "audit.json"
    array.write_text(
        json.dumps(
            [
                {
                    "entry_id": "e1",
                    "timestamp": "2026-08-25T12:00:00+00:00",
                    "agent_did": "did:agent:implementer",
                    "action": "write_file",
                    "outcome": "success",
                    "data": {"task_id": "TASK-002", "cost_usd": 0.25},
                },
                {
                    "entry_id": "e2",
                    "timestamp": "2026-08-25T12:00:01+00:00",
                    "agent_did": "did:agent:reviewer",
                    "action": "run_tests",
                    "outcome": "denied",
                },
            ]
        )
    )
    result = runner.invoke(
        app,
        ["import", "agt-audit", str(array), "--change", "CHG-q", "--ledger", str(ledger), "--json"],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["event_ids"] == ["e1", "e2"] and summary["recorded"] == 2
    # re-importing the same entries is idempotent (entry ids are the event ids)
    again = runner.invoke(
        app,
        ["import", "agt-audit", str(array), "--change", "CHG-q", "--ledger", str(ledger), "--json"],
    )
    assert json.loads(again.output)["recorded"] == 0
    assert json.loads(again.output)["skipped_existing"] == 2
    # export-dict and JSON-lines shapes are accepted too
    export = tmp_path / "export.json"
    export.write_text(
        json.dumps({"merkle_root": "abc", "entries": [{"entry_id": "e3", "action": "read"}]})
    )
    lines = tmp_path / "audit.jsonl"
    lines.write_text(json.dumps({"entry_id": "e4", "action": "edit"}) + "\n\n")
    for path in (export, lines):
        out = runner.invoke(
            app, ["import", "agt-audit", str(path), "--ledger", str(ledger), "--json"]
        )
        assert out.exit_code == 0, out.output
        assert json.loads(out.output)["recorded"] == 1
    with UsageLedger(str(ledger)) as led:
        events = led.query({"change_id": "CHG-q"})
        assert len(events) == 2 and {e.source for e in events} == {"agt_audit"}
        assert next(e for e in events if e.event_id == "e1").task_id == "TASK-002"
        assert led.count() == 4
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "entries"}')
    assert (
        runner.invoke(app, ["import", "agt-audit", str(bad), "--ledger", str(ledger)]).exit_code
        != 0
    )


def test_import_pyrit_pieces_json(tmp_path: Path) -> None:
    pieces = tmp_path / "pieces.json"
    pieces.write_text(
        json.dumps(
            [
                {"role": "user", "conversation_id": "conv-1", "prompt_metadata": {}},
                {
                    "role": "assistant",
                    "conversation_id": "conv-1",
                    "timestamp": "2026-08-25T12:00:00+00:00",
                    "prompt_metadata": {
                        "token_usage_input_tokens": 1000,
                        "token_usage_output_tokens": 500,
                        "token_usage_cached_tokens": 200,
                    },
                },
                {
                    "role": "assistant",
                    "conversation_id": "conv-2",
                    "prompt_metadata": {
                        "token_usage_input_tokens": 1,
                        "token_usage_output_tokens": 1,
                        "model": "claude-opus-5",
                    },
                },
            ]
        )
    )
    ledger = tmp_path / "ledger.sqlite"
    result = runner.invoke(
        app,
        [
            "import",
            "pyrit",
            str(pieces),
            "--change",
            "CHG-red",
            "--model",
            "claude-sonnet-5",
            "--ledger",
            str(ledger),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["events"] == 2 and summary["models"] == ["claude-opus-5", "claude-sonnet-5"]
    with UsageLedger(str(ledger)) as led:
        events = led.query({"change_id": "CHG-red"})
        assert {e.source for e in events} == {"pyrit"}
        assert {e.agent_role for e in events} == {"security_tester"}
        assert all(e.cost_usd > 0 for e in events)
    only = runner.invoke(
        app,
        [
            "import",
            "pyrit",
            str(pieces),
            "--conversation",
            "conv-2",
            "--ledger",
            str(tmp_path / "other.sqlite"),
            "--json",
        ],
    )
    assert json.loads(only.output)["events"] == 1
    missing = runner.invoke(app, ["import", "pyrit", str(tmp_path / "nope.json")])
    assert missing.exit_code != 0
