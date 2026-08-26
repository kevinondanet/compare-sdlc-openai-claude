"""Tests for aisdlc.security.ci_templates (templates, pins, lint, rendering)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from aisdlc.policy import default_project_config
from aisdlc.policy.project_config import ProjectConfig, TestCommands
from aisdlc.security import ci_templates as ci

EXPECTED_WORKFLOWS = {
    "ai-review",
    "architecture-tests",
    "build-and-test",
    "codeql",
    "cost-benchmark",
    "dependency-review",
    "mutation",
    "pyrit-campaign",
    "safety-regression",
    "sbom-provenance",
    "scorecard",
    "secret-scan",
}


def _on(doc: dict[str, object]) -> dict[str, object]:
    """The workflow trigger block (YAML parses the bare key ``on`` as ``True``)."""
    value = doc.get("on", doc.get(True))
    assert isinstance(value, dict)
    return value


def test_all_expected_workflows_are_bundled() -> None:
    assert set(ci.list_workflows()) == EXPECTED_WORKFLOWS
    assert (ci.CI_DIR / "caller.yml").is_file() and (ci.CI_DIR / "dependabot.yml").is_file()
    with pytest.raises(FileNotFoundError):
        ci.load_workflow("nope")


def test_bundled_templates_are_pinned_and_hardened() -> None:
    assert ci.verify_pins(ci.WORKFLOWS_DIR) == []
    for name in ci.list_workflows():
        text = ci.load_workflow(name)
        issues = ci.lint_workflow(text, name)
        assert issues == [], f"{name}: {[i.message for i in issues]}"
        doc = yaml.safe_load(text)  # raw templates are valid YAML (placeholders are strings)
        assert "workflow_call" in _on(doc)


def test_template_pins_match_catalogue() -> None:
    found = ci.catalogue_from_templates()
    for action, shas in found.items():
        assert action in ci.PINNED_ACTIONS, f"{action} not catalogued"
        assert shas == {ci.PINNED_ACTIONS[action][0]}, f"{action} pinned to a different SHA"
    for action in ci.PINNED_ACTIONS:
        assert ci.SHA_RE.match(ci.PINNED_ACTIONS[action][0])
    assert ci.pin("actions/checkout").startswith("actions/checkout@")
    with pytest.raises(KeyError):
        ci.pin("nobody/nothing")


def test_verify_pins_detects_problems(tmp_path: Path) -> None:
    text = "\n".join(
        [
            "jobs:",
            "  a:",
            "    steps:",
            "      - uses: actions/checkout@v4",
            "      - uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b",
            "      - uses: ./.github/actions/local",
            "      - uses: docker://alpine:3.20",
            "      - uses: docker://alpine@sha256:abc  # 3.20",
            "      - uses: owner/repo/.github/workflows/x.yml@" + "0" * 40 + " # v1",
            "      # - uses: commented/out@main",
            "      - uses: no/ref",
        ]
    )
    issues = ci.verify_pins(text)
    reasons = {(i.uses, i.reason) for i in issues}
    assert ("actions/checkout@v4", "ref is not a 40-hex SHA") in reasons
    assert (
        "actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b",
        "missing version comment",
    ) in reasons
    assert ("docker://alpine:3.20", "image not digest-pinned") in reasons
    assert ("no/ref", "no ref") in reasons
    assert len(issues) == 4
    assert len(ci.verify_pins(text, require_version_comment=False)) == 3
    path = tmp_path / "wf.yml"
    path.write_text(text)
    assert [i.workflow for i in ci.verify_pins(path)][0] == str(path)
    assert ci.verify_pins(tmp_path)[0].line == 4


def test_lint_workflow_rules() -> None:
    checkout = ci.pin("actions/checkout")
    text = f"""
name: bad
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: {checkout}
      - name: echo
        run: echo "${{{{ github.event.pull_request.title }}}}"
      - name: fine
        env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
        run: echo "$TITLE" ${{{{ matrix.version }}}}
"""
    codes = sorted({i.code for i in ci.lint_workflow(text, "bad")})
    assert codes == [
        "NO_HARDEN_RUNNER",
        "NO_JOB_PERMISSIONS",
        "NO_TIMEOUT",
        "NO_TOP_PERMISSIONS",
        "PERSIST_CREDENTIALS",
        "PULL_REQUEST_TARGET",
        "UNSAFE_RUN_EXPRESSION",
    ]
    assert ci.lint_workflow("permissions: write-all\njobs: {}\n")[0].code == "WRITE_ALL"
    assert ci.lint_workflow("[unclosed")[0].code == "INVALID_YAML"
    assert ci.lint_workflow("- just a list")[0].code == "INVALID_YAML"


def test_render_python_defaults() -> None:
    config = default_project_config()
    rendered = ci.render(config)
    assert set(rendered) == {f"{n}.yml" for n in EXPECTED_WORKFLOWS}
    build = rendered["build-and-test.yml"]
    assert re.search(r"\{\{\s*\w+\s*\}\}", build) is None  # only ${{ }} expressions remain
    doc = yaml.safe_load(build)
    steps = doc["jobs"]["test"]["steps"]
    names = [s.get("name") for s in steps]
    assert names[0] == "Harden runner" and names[1] == "Checkout"
    assert "Set up Python" in names and "Lint" in names and "Type check" in names
    assert "Build" not in names  # no build command configured -> step removed
    unit = next(s for s in steps if s.get("name") == "Unit tests with evidence")
    assert "--junitxml=reports/junit.xml" in unit["env"]["UNIT_COMMAND"]
    assert "--cov-report=xml:reports/coverage.xml" in unit["env"]["UNIT_COMMAND"]
    assert _on(doc)["workflow_call"]["inputs"]["versions"]["default"] == '["3.12"]'
    assert ci.verify_pins(build) == []
    codeql = yaml.safe_load(rendered["codeql.yml"])
    assert _on(codeql)["workflow_call"]["inputs"]["languages"]["default"] == '["python"]'
    assert _on(codeql)["workflow_call"]["inputs"]["build-mode"]["default"] == "none"
    mutation = yaml.safe_load(rendered["mutation.yml"])
    run_step = next(s for s in mutation["jobs"]["mutation"]["steps"] if "built-in" in s["name"])
    assert run_step["env"]["SCOPE"] == "src"
    assert "aisdlc test mutation --builtin" in run_step["run"]


def test_render_node_project_with_matrix_and_custom_commands() -> None:
    config = ProjectConfig(
        name="web",
        languages=["TypeScript"],
        test_commands=TestCommands(
            unit='npm test -- --ci "quoted"',
            lint="npm run lint",
            types=None,
            build="npm run build",
            mutation="npx stryker run && cp out/stryker.json reports/mutation.json",
        ),
        critical_modules=["src/auth/", "src/pay/*"],
    )
    options = ci.RenderOptions(matrix={"node": ["20", "22"]}, node_version="22")
    rendered = ci.render(
        config, options=options, workflows=["build-and-test", "mutation", "codeql"]
    )
    build = yaml.safe_load(rendered["build-and-test.yml"])
    steps = build["jobs"]["test"]["steps"]
    names = [s.get("name") for s in steps]
    assert "Set up Python (platform CLI)" in names and "Set up Node.js" in names
    assert "Build" in names and "Type check" not in names
    node_step = next(s for s in steps if s.get("name") == "Set up Node.js")
    assert node_step["with"]["node-version"] == "${{ matrix.version }}"
    unit = next(s for s in steps if s.get("name") == "Unit tests with evidence")
    assert unit["env"]["UNIT_COMMAND"] == 'npm test -- --ci "quoted"'
    assert _on(build)["workflow_call"]["inputs"]["versions"]["default"] == '["20", "22"]'
    mutation = yaml.safe_load(rendered["mutation.yml"])
    custom = next(
        s for s in mutation["jobs"]["mutation"]["steps"] if "project command" in s["name"]
    )
    assert "stryker" in custom["run"]
    codeql = yaml.safe_load(rendered["codeql.yml"])
    assert (
        _on(codeql)["workflow_call"]["inputs"]["languages"]["default"]
        == '["javascript-typescript"]'
    )


def test_render_multi_language_and_unsupported() -> None:
    config = ProjectConfig(name="poly", languages=["python", "go", "java"])
    rendered = ci.render(config, workflows=["architecture-tests"])
    doc = yaml.safe_load(rendered["architecture-tests.yml"])
    names = [s.get("name") for s in doc["jobs"]["architecture"]["steps"]]
    assert "Set up Python" in names and "Set up Go" in names and "Set up Java" in names
    with pytest.raises(ci.RenderError, match="unsupported language"):
        ci.render(ProjectConfig(name="x", languages=["cobol"]), workflows=["codeql"])


def test_render_caller_requires_sha_and_pins_everything() -> None:
    config = default_project_config()
    with pytest.raises(ci.RenderError, match="40-hex"):
        ci.render_caller(config, options=ci.RenderOptions(workflows_ref="main"))
    sha = "a" * 40
    text = ci.render_caller(
        config,
        options=ci.RenderOptions(
            workflows_repo="acme/.github", workflows_ref=sha, workflows_version="v1.2.3"
        ),
    )
    assert ci.verify_pins(text) == []
    assert ci.lint_workflow(text, "caller") == []
    doc = yaml.safe_load(text)
    assert (
        doc["jobs"]["build-and-test"]["uses"]
        == f"acme/.github/.github/workflows/build-and-test.yml@{sha}"
    )
    assert "# v1.2.3" in text
    assert doc["jobs"]["pyrit-campaign"]["with"]["risk-class"] == "standard"


def test_render_rejects_unresolved_placeholder(tmp_path: Path) -> None:
    (tmp_path / "custom.yml").write_text(
        "name: custom\non:\n  workflow_call:\npermissions: {}\njobs:\n  j:\n"
        "    runs-on: x\n    timeout-minutes: 1\n    permissions:\n      contents: read\n"
        "    steps:\n      - uses: "
        + ci.pin("step-security/harden-runner")
        + '\n      - run: "{{ unknown_key }}"\n'
    )
    with pytest.raises(ci.RenderError, match="unresolved placeholders"):
        ci.render(default_project_config(), directory=tmp_path)


def test_render_rejects_weakened_workflow(tmp_path: Path) -> None:
    (tmp_path / "weak.yml").write_text(
        "name: weak\non:\n  workflow_call:\njobs:\n  j:\n    runs-on: x\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    with pytest.raises(ci.RenderError, match="hardening rules"):
        ci.render(default_project_config(), directory=tmp_path)


def test_render_to_writes_files(tmp_path: Path) -> None:
    written = ci.render_to(
        default_project_config(),
        tmp_path / "out",
        options=ci.RenderOptions(workflows_ref="b" * 40),
        workflows=["secret-scan"],
    )
    assert sorted(p.name for p in written) == ["aisdlc-ci.yml", "secret-scan.yml"]
    assert ci.verify_pins(tmp_path / "out") == []


def test_describe_lists_inline_values() -> None:
    info = ci.describe(default_project_config())
    assert info["languages"] == ["python"]
    assert "unit_command" in info["inline"] and "setup_steps" in info["blocks"]
    assert set(info["workflows"]) == EXPECTED_WORKFLOWS
