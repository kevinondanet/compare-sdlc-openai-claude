"""Reusable GitHub workflow templates (plane 1) — rendering, pin verification, linting.

``templates/workflows/*.yml`` are organisation-level ``workflow_call`` workflows following
the hardened patterns: every action pinned to a 40-hex commit SHA with a version comment,
least-privilege ``permissions`` on every job, ``step-security/harden-runner`` (egress audit
by default) as the first step, no ``${{ github.* }}`` / ``${{ inputs.* }}`` expressions
inside ``run:`` (values pass through ``env:``), bounded output sizes, and evidence uploaded
as artifacts for :mod:`aisdlc.security.supply_chain` to parse.

Templates contain two kinds of placeholders that :func:`render` fills from a
:class:`~aisdlc.policy.ProjectConfig`:

* inline ``"{{ name }}"`` inside a double-quoted YAML scalar (JSON-escaped on render);
* a whole list item ``- "{{ name }}"`` replaced by language-specific step blocks (or removed
  when the block is empty, e.g. no lint command configured).

:func:`verify_pins` checks that every ``uses:`` is SHA-pinned; :func:`lint_workflow` applies
the rest of the hardening rules.  Both are run on the rendered output by :func:`render`.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from aisdlc.policy.project_config import ProjectConfig

__all__ = [
    "CI_DIR",
    "PINNED_ACTIONS",
    "SUPPORTED_LANGUAGES",
    "WORKFLOWS_DIR",
    "PinIssue",
    "RenderError",
    "RenderOptions",
    "WorkflowIssue",
    "lint_workflow",
    "list_workflows",
    "load_workflow",
    "pin",
    "render",
    "render_caller",
    "render_to",
    "verify_pins",
]

_TEMPLATES_ROOT = Path(__file__).resolve().parents[3] / "templates"
WORKFLOWS_DIR = _TEMPLATES_ROOT / "workflows"
CI_DIR = _TEMPLATES_ROOT / "ci"
CALLER_TEMPLATE = "caller.yml"

PINNED_ACTIONS: dict[str, tuple[str, str]] = {
    "actions/checkout": ("11bd71901bbe5b1630ceea73d27597364c9af683", "v4.2.2"),
    "actions/setup-python": ("0b93645e9fea7318ecaed2b359559ac225c90a2b", "v5.3.0"),
    "actions/setup-node": ("39370e3970a6d050c480ffad4ff0ed4d3fdee5af", "v4.1.0"),
    "actions/setup-go": ("3041bf56c941b39c61721a86cd11f3bb1338122a", "v5.2.0"),
    "actions/setup-java": ("7a6d8a8234af8eb26422e24e3006232cccaa061b", "v4.6.0"),
    "actions/upload-artifact": ("b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882", "v4.4.3"),
    "actions/download-artifact": ("fa0a91b85d4f404e444e00e005971372dc801d16", "v4.1.8"),
    "actions/github-script": ("60a0d83039c74a4aee543508d2ffcb1c3799cdea", "v7.0.1"),
    "actions/dependency-review-action": ("3b139cfc5fae8b618d3eae3675e383bb1769c019", "v4.5.0"),
    "actions/attest-build-provenance": ("7668571508540a607bdfd90a87a560489fe372eb", "v2.1.0"),
    "step-security/harden-runner": ("0080882f6c36860b6ba35c610c98ce87d4e2f26f", "v2.10.2"),
    "github/codeql-action/init": ("df409f7d9260372bd5f19e5b04e83cb3c43714ae", "v3.27.9"),
    "github/codeql-action/autobuild": ("df409f7d9260372bd5f19e5b04e83cb3c43714ae", "v3.27.9"),
    "github/codeql-action/analyze": ("df409f7d9260372bd5f19e5b04e83cb3c43714ae", "v3.27.9"),
    "github/codeql-action/upload-sarif": ("df409f7d9260372bd5f19e5b04e83cb3c43714ae", "v3.27.9"),
    "gitleaks/gitleaks-action": ("44c470ffc35caa8b1eb3e8012ca53c2f9bea4eb5", "v2.3.7"),
    "anchore/sbom-action": ("df80a981bc6edbc4e220a492d3cbe9f5547a6e75", "v0.17.9"),
    "ossf/scorecard-action": ("62b2cac7ed8198b15735ed49ab1e5cf35480ba46", "v2.4.0"),
}
"""Action → (commit SHA, version tag).  Bump here and in ``templates/workflows`` together."""

SUPPORTED_LANGUAGES: tuple[str, ...] = ("python", "node", "go", "java")
_LANGUAGE_ALIASES: dict[str, str] = {
    "python": "python",
    "py": "python",
    "node": "node",
    "nodejs": "node",
    "javascript": "node",
    "typescript": "node",
    "js": "node",
    "ts": "node",
    "go": "go",
    "golang": "go",
    "java": "java",
    "kotlin": "java",
}
_CODEQL_LANGUAGES: dict[str, str] = {
    "python": "python",
    "node": "javascript-typescript",
    "go": "go",
    "java": "java-kotlin",
}

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"""^\s*(?:-\s+)?uses:\s*(['"]?)([^'"#\s]+)\1\s*(#.*)?$""")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
_BLOCK_LINE_RE = re.compile(r"""^(\s*)-\s+"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}"\s*$""")
#: Expression prefixes that are safe to interpolate into ``run:``/``script:``. ``env.`` is
#: deliberately absent: ``${{ env.X }}`` is expanded by GitHub *before* the shell sees it,
#: so it injects exactly like the untrusted value bound to ``X``; the safe form is the shell
#: variable ``$X``.
_SAFE_RUN_CONTEXTS = (
    "matrix.",
    "runner.",
    "github.workspace",
    "github.sha",
    "github.run_id",
    "github.run_attempt",
    "github.repository",
    "github.server_url",
    "github.api_url",
    "github.token",
    "github.event_name",
)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RenderError(ValueError):
    """Rendering could not produce a hardened, fully-resolved workflow."""


class PinIssue(_Model):
    """An unpinned or badly annotated ``uses:`` reference."""

    workflow: str
    line: int
    uses: str
    reason: str


class WorkflowIssue(_Model):
    """A hardening rule violation."""

    workflow: str
    code: str
    message: str
    line: int | None = None
    job: str | None = None


class RenderOptions(_Model):
    """Knobs for :func:`render` that are not part of the project configuration."""

    python_version: str = "3.12"
    node_version: str = "22"
    go_version: str = "1.23"
    java_version: str = "21"
    java_distribution: str = "temurin"
    matrix: dict[str, list[str]] = Field(
        default_factory=dict, description="language -> toolchain versions for the test matrix"
    )
    aisdlc_spec: str = "ai-sdlc-platform"
    install_command: str | None = Field(
        default=None, description="Override the per-language dependency install command."
    )
    architecture_command: str | None = None
    workflows_repo: str = "ORG/.github"
    workflows_ref: str = Field(
        default="0000000000000000000000000000000000000000",
        description="Commit SHA of the workflows repository the caller pins to.",
    )
    workflows_version: str = "v0.1.0"
    pyrit_spec: str = "templates/pyrit/campaigns/default.yaml"
    pyrit_target: str = ""
    safety_module: str = ""


def pin(action: str) -> str:
    """``<action>@<sha> # <version>`` for a catalogued action."""
    try:
        sha, version = PINNED_ACTIONS[action]
    except KeyError as exc:
        raise KeyError(f"action {action!r} is not in PINNED_ACTIONS") from exc
    return f"{action}@{sha} # {version}"


def list_workflows(directory: Path | None = None) -> list[str]:
    """Names (without extension) of the reusable workflow templates."""
    root = directory or WORKFLOWS_DIR
    return sorted(p.stem for p in root.glob("*.yml"))


def load_workflow(name: str, directory: Path | None = None) -> str:
    """Raw template text for workflow *name* (``build-and-test`` or ``build-and-test.yml``)."""
    root = directory or WORKFLOWS_DIR
    stem = name[:-4] if name.endswith(".yml") else name
    path = root / f"{stem}.yml"
    if not path.is_file():
        raise FileNotFoundError(f"no workflow template {stem!r} in {root}")
    return path.read_text(encoding="utf-8")


# --------------------------------------------------------------------------------------
# Pin verification and linting
# --------------------------------------------------------------------------------------


def _iter_sources(source: str | Path) -> Iterable[tuple[str, str]]:
    if isinstance(source, Path):
        if source.is_dir():
            for path in sorted(source.rglob("*.y*ml")):
                yield str(path), path.read_text(encoding="utf-8")
        else:
            yield str(source), source.read_text(encoding="utf-8")
    elif "\n" not in source and (source.endswith((".yml", ".yaml")) or Path(source).is_dir()):
        yield from _iter_sources(Path(source))
    else:
        yield "<text>", source


def verify_pins(source: str | Path, *, require_version_comment: bool = True) -> list[PinIssue]:
    """Check that every ``uses:`` reference is pinned to a 40-hex commit SHA.

    *source* may be workflow text, a file or a directory (recursively).  Local actions
    (``./…``) are exempt; ``docker://`` images must carry a ``@sha256:`` digest.  A trailing
    ``# vX.Y`` comment is required unless *require_version_comment* is ``False``.
    """
    issues: list[PinIssue] = []
    for name, text in _iter_sources(source):
        for number, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            match = _USES_RE.match(line)
            if not match:
                continue
            uses = match.group(2)
            comment = match.group(3) or ""
            if uses.startswith("./"):
                continue
            if uses.startswith("docker://"):
                if "@sha256:" not in uses:
                    issues.append(
                        PinIssue(
                            workflow=name, line=number, uses=uses, reason="image not digest-pinned"
                        )
                    )
                continue
            if "@" not in uses:
                issues.append(PinIssue(workflow=name, line=number, uses=uses, reason="no ref"))
                continue
            ref = uses.rsplit("@", 1)[1]
            if not SHA_RE.match(ref):
                issues.append(
                    PinIssue(
                        workflow=name, line=number, uses=uses, reason="ref is not a 40-hex SHA"
                    )
                )
                continue
            if require_version_comment and not re.search(r"#\s*v?\d", comment):
                issues.append(
                    PinIssue(
                        workflow=name, line=number, uses=uses, reason="missing version comment"
                    )
                )
    return issues


def _expressions(text: str) -> list[str]:
    return re.findall(r"\$\{\{\s*([^}]*?)\s*\}\}", text)


def _unsafe_run_expressions(run: str) -> list[str]:
    unsafe: list[str] = []
    for expr in _expressions(run):
        if any(expr.startswith(prefix) for prefix in _SAFE_RUN_CONTEXTS):
            continue
        unsafe.append(expr)
    return unsafe


def lint_workflow(text: str, name: str = "<text>") -> list[WorkflowIssue]:
    """Apply the hardening rules to one workflow and return the violations.

    Rules: ``PIN`` (unpinned action), ``NO_TOP_PERMISSIONS``, ``NO_JOB_PERMISSIONS``,
    ``WRITE_ALL``, ``NO_TIMEOUT``, ``NO_HARDEN_RUNNER`` (first step of every step job),
    ``UNSAFE_RUN_EXPRESSION`` (untrusted ``${{ }}`` inside ``run:``),
    ``PULL_REQUEST_TARGET``, ``PERSIST_CREDENTIALS`` (checkout keeps the token),
    ``INVALID_YAML``.
    """
    issues: list[WorkflowIssue] = []
    for pin_issue in verify_pins(text):
        issues.append(
            WorkflowIssue(
                workflow=name,
                code="PIN",
                message=f"{pin_issue.uses}: {pin_issue.reason}",
                line=pin_issue.line,
            )
        )
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        issues.append(WorkflowIssue(workflow=name, code="INVALID_YAML", message=str(exc)))
        return issues
    if not isinstance(doc, Mapping):
        issues.append(WorkflowIssue(workflow=name, code="INVALID_YAML", message="not a mapping"))
        return issues
    triggers = doc.get("on", doc.get(True))
    if isinstance(triggers, Mapping) and "pull_request_target" in triggers:
        issues.append(
            WorkflowIssue(
                workflow=name,
                code="PULL_REQUEST_TARGET",
                message="pull_request_target runs untrusted code with write tokens",
            )
        )
    if "permissions" not in doc:
        issues.append(
            WorkflowIssue(
                workflow=name, code="NO_TOP_PERMISSIONS", message="no top-level permissions"
            )
        )
    elif doc["permissions"] == "write-all":
        issues.append(
            WorkflowIssue(workflow=name, code="WRITE_ALL", message="write-all permissions")
        )
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, Mapping):
        issues.append(
            WorkflowIssue(workflow=name, code="INVALID_YAML", message="jobs is not a mapping")
        )
        return issues
    for job_name, job in jobs.items():
        if not isinstance(job, Mapping):
            continue
        if "permissions" not in job:
            issues.append(
                WorkflowIssue(
                    workflow=name,
                    code="NO_JOB_PERMISSIONS",
                    message="job has no permissions block",
                    job=job_name,
                )
            )
        elif job["permissions"] == "write-all":
            issues.append(
                WorkflowIssue(
                    workflow=name, code="WRITE_ALL", message="write-all permissions", job=job_name
                )
            )
        if "uses" in job:
            continue  # reusable-workflow call: no steps/timeout of its own
        if "timeout-minutes" not in job:
            issues.append(
                WorkflowIssue(
                    workflow=name,
                    code="NO_TIMEOUT",
                    message="job has no timeout-minutes",
                    job=job_name,
                )
            )
        steps = job.get("steps") or []
        if not isinstance(steps, list) or not steps:
            continue
        first = steps[0] if isinstance(steps[0], Mapping) else {}
        if not str(first.get("uses", "")).startswith("step-security/harden-runner@"):
            issues.append(
                WorkflowIssue(
                    workflow=name,
                    code="NO_HARDEN_RUNNER",
                    message="first step must be step-security/harden-runner",
                    job=job_name,
                )
            )
        for step in steps:
            if not isinstance(step, Mapping):
                continue
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout@"):
                with_block = step.get("with") or {}
                if (
                    not isinstance(with_block, Mapping)
                    or with_block.get("persist-credentials") is not False
                ):
                    issues.append(
                        WorkflowIssue(
                            workflow=name,
                            code="PERSIST_CREDENTIALS",
                            message="checkout must set persist-credentials: false",
                            job=job_name,
                        )
                    )
            run = step.get("run")
            if isinstance(run, str):
                for expr in _unsafe_run_expressions(run):
                    issues.append(
                        WorkflowIssue(
                            workflow=name,
                            code="UNSAFE_RUN_EXPRESSION",
                            message=_unsafe_message(
                                expr, "run:", "pass it through env: and use $NAME"
                            ),
                            job=job_name,
                        )
                    )
            with_block = step.get("with")
            if isinstance(with_block, Mapping) and isinstance(with_block.get("script"), str):
                for expr in _unsafe_run_expressions(with_block["script"]):
                    issues.append(
                        WorkflowIssue(
                            workflow=name,
                            code="UNSAFE_RUN_EXPRESSION",
                            message=_unsafe_message(
                                expr, "github-script", "read process.env.NAME / context instead"
                            ),
                            job=job_name,
                        )
                    )
    return issues


def _unsafe_message(expr: str, where: str, advice: str) -> str:
    if expr.startswith("env."):
        return (
            f"${{{{ {expr} }}}} inside {where} — expanded before the shell runs, so it injects "
            f"like the value bound to it; {advice}"
        )
    return f"${{{{ {expr} }}}} inside {where} — {advice}"


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------


def _languages(config: ProjectConfig) -> list[str]:
    seen: list[str] = []
    for raw in config.languages:
        lang = _LANGUAGE_ALIASES.get(raw.lower())
        if lang is None:
            raise RenderError(
                f"unsupported language {raw!r}; supported: {', '.join(SUPPORTED_LANGUAGES)}"
            )
        if lang not in seen:
            seen.append(lang)
    return seen or ["python"]


def _step(
    name: str,
    *,
    uses: str | None = None,
    run: str | None = None,
    env: Mapping[str, str] | None = None,
    with_: Mapping[str, str] | None = None,
) -> str:
    lines = [f"- name: {name}"]
    if uses:
        lines.append(f"  uses: {uses}")
    if with_:
        lines.append("  with:")
        for key, value in with_.items():
            lines.append(f"    {key}: {value}")
    if env:
        lines.append("  env:")
        for key, value in env.items():
            lines.append(f"    {key}: {_yaml_str(value)}")
    if run is not None:
        if "\n" in run:
            lines.append("  run: |")
            lines.extend(f"    {line}" for line in run.splitlines())
        else:
            lines.append(f"  run: {_yaml_str(run)}")
    return "\n".join(lines)


def _yaml_str(value: str) -> str:
    if value.startswith("${{"):
        return value
    return json.dumps(value)


def _setup_steps(languages: Sequence[str], options: RenderOptions, *, matrix: bool) -> list[str]:
    steps: list[str] = []
    primary = languages[0]
    version_of = {
        "python": options.python_version,
        "node": options.node_version,
        "go": options.go_version,
        "java": options.java_version,
    }
    if "python" not in languages:
        steps.append(
            _step(
                "Set up Python (platform CLI)",
                uses=pin("actions/setup-python"),
                with_={"python-version": json.dumps(options.python_version)},
            )
        )
    for lang in languages:
        version = (
            "${{ matrix.version }}" if matrix and lang == primary else json.dumps(version_of[lang])
        )
        if lang == "python":
            steps.append(
                _step(
                    "Set up Python",
                    uses=pin("actions/setup-python"),
                    with_={"python-version": version, "cache": "pip"},
                )
            )
        elif lang == "node":
            steps.append(
                _step(
                    "Set up Node.js",
                    uses=pin("actions/setup-node"),
                    with_={"node-version": version, "cache": "npm"},
                )
            )
        elif lang == "go":
            steps.append(
                _step("Set up Go", uses=pin("actions/setup-go"), with_={"go-version": version})
            )
        elif lang == "java":
            steps.append(
                _step(
                    "Set up Java",
                    uses=pin("actions/setup-java"),
                    with_={
                        "java-version": version,
                        "distribution": json.dumps(options.java_distribution),
                        "cache": "maven",
                    },
                )
            )
    return steps


_EMPTY_MUTATION_JSON = '{"tool":"none","untested":0,"complete":false,"scope":[],"excluded":[]}'

_DEFAULT_INSTALL: dict[str, str] = {
    "python": 'python -m pip install --disable-pip-version-check --quiet -e ".[dev]"',
    "node": "npm ci --no-audit --no-fund",
    "go": "go mod download",
    "java": "mvn --batch-mode --quiet -DskipTests dependency:resolve",
}


def _install_steps(languages: Sequence[str], options: RenderOptions) -> list[str]:
    if options.install_command:
        return [_step("Install dependencies", run=options.install_command)]
    return [_step(f"Install {lang} dependencies", run=_DEFAULT_INSTALL[lang]) for lang in languages]


def _command_step(name: str, command: str | None) -> list[str]:
    if not command or not command.strip():
        return []
    return [_step(name, run=command.strip())]


def _unit_command(config: ProjectConfig, languages: Sequence[str]) -> str:
    command = (config.test_commands.unit or "").strip()
    if not command:
        return 'echo "::error::no unit test command configured in project-config.yaml"; exit 1'
    if "python" in languages and command.split()[0] in ("pytest", "python"):
        if "--junitxml" not in command and "--junit-xml" not in command:
            command += " --junitxml=reports/junit.xml"
        if "--cov" not in command:
            command += " --cov --cov-branch --cov-report=xml:reports/coverage.xml"
    return command


def _architecture_command(languages: Sequence[str], options: RenderOptions) -> str:
    if options.architecture_command:
        return options.architecture_command
    primary = languages[0]
    return {
        "python": "pytest -q -m architecture --junitxml=reports/architecture-junit.xml",
        "node": "npm run --if-present test:architecture",
        "go": "go test ./... -run Architecture",
        "java": "mvn --batch-mode --quiet -Dtest='*ArchitectureTest' test",
    }[primary]


def _mutation_steps(
    config: ProjectConfig, languages: Sequence[str], options: RenderOptions
) -> list[str]:
    custom = (config.test_commands.mutation or "").strip()
    if custom:
        return [
            _step(
                "Mutation testing (project command)",
                run="mkdir -p reports\n" + custom,
            )
        ]
    if "python" not in languages:
        return [
            _step(
                "Mutation testing",
                run="\n".join(
                    [
                        'echo "::warning::no mutation command configured;'
                        ' built-in runner supports Python only"',
                        "mkdir -p reports",
                        "printf '%s' '" + _EMPTY_MUTATION_JSON + "' > reports/mutation.json",
                    ]
                ),
            )
        ]
    scope = [m for m in config.critical_modules if m and not any(ch in m for ch in "*?[")] or [
        "src"
    ]
    return [
        _step(
            "Mutation testing (built-in runner)",
            env={
                "UNIT_COMMAND": _unit_command(config, languages),
                "SCOPE": " ".join(shlex.quote(s) for s in scope),
                "MAX_MUTANTS": "${{ inputs.max-mutants }}",
                "TIMEOUT_SECONDS": "${{ inputs.timeout-seconds }}",
            },
            run="\n".join(
                [
                    "mkdir -p reports",
                    "# shellcheck disable=SC2086",
                    'aisdlc test mutation --builtin --command "$UNIT_COMMAND"'
                    ' --max-mutants "$MAX_MUTANTS" --timeout "$TIMEOUT_SECONDS"'
                    " --out reports/mutation.json $SCOPE",
                ]
            ),
        )
    ]


def _blocks(config: ProjectConfig, options: RenderOptions) -> dict[str, list[str]]:
    languages = _languages(config)
    tc = config.test_commands
    return {
        "setup_steps": _setup_steps(languages, options, matrix=True),
        "setup_steps_fixed": _setup_steps(languages, options, matrix=False),
        "install_steps": _install_steps(languages, options),
        "lint_step": _command_step("Lint", tc.lint),
        "types_step": _command_step("Type check", tc.types),
        "build_step": _command_step("Build", tc.build),
        "integration_step": _command_step("Integration tests", tc.integration),
        "e2e_step": _command_step("End-to-end tests", tc.e2e),
        "architecture_step": [
            _step(
                "Architecture tests",
                run="mkdir -p reports\n" + _architecture_command(languages, options),
            )
        ],
        "mutation_step": _mutation_steps(config, languages, options),
    }


def _inline_values(config: ProjectConfig, options: RenderOptions) -> dict[str, str]:
    languages = _languages(config)
    primary = languages[0]
    default_version = {
        "python": options.python_version,
        "node": options.node_version,
        "go": options.go_version,
        "java": options.java_version,
    }[primary]
    versions = options.matrix.get(primary) or [default_version]
    codeql = [_CODEQL_LANGUAGES[lang] for lang in languages]
    return {
        "project_name": config.name,
        "matrix_versions": json.dumps(versions),
        "codeql_languages": json.dumps(codeql),
        "codeql_build_mode": "none" if primary in ("python", "node") else "autobuild",
        "aisdlc_spec": options.aisdlc_spec,
        "unit_command": _unit_command(config, languages),
        "risk_class": config.risk_classification.default.value,
        "workflows_repo": options.workflows_repo,
        "workflows_ref": options.workflows_ref,
        "workflows_version": options.workflows_version,
        "pyrit_spec": options.pyrit_spec,
        "pyrit_target": options.pyrit_target,
        "safety_module": options.safety_module,
    }


def _render_text(text: str, inline: Mapping[str, str], blocks: Mapping[str, Sequence[str]]) -> str:
    out: list[str] = []
    for line in text.splitlines():
        block_match = _BLOCK_LINE_RE.match(line)
        if block_match and block_match.group(2) in blocks:
            indent = block_match.group(1)
            for chunk in blocks[block_match.group(2)]:
                out.extend(f"{indent}{chunk_line}" for chunk_line in chunk.splitlines())
            continue

        def substitute(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in inline:
                return match.group(0)
            return json.dumps(inline[key])[1:-1]

        out.append(_PLACEHOLDER_RE.sub(substitute, line))
    return "\n".join(out) + "\n"


def _check_rendered(name: str, text: str) -> None:
    leftovers = sorted({m.group(1) for m in _PLACEHOLDER_RE.finditer(text)})
    if leftovers:
        raise RenderError(f"{name}: unresolved placeholders {leftovers}")
    issues = lint_workflow(text, name)
    if issues:
        summary = "; ".join(f"{i.code}: {i.message}" for i in issues[:5])
        raise RenderError(f"{name}: rendered workflow violates hardening rules: {summary}")


def render(
    config: ProjectConfig,
    *,
    options: RenderOptions | None = None,
    workflows: Iterable[str] | None = None,
    directory: Path | None = None,
) -> dict[str, str]:
    """Render the reusable workflows for *config*; returns ``{"<name>.yml": text}``.

    Every rendered workflow is verified (pins, permissions, run-line safety); a violation
    raises :class:`RenderError` rather than emitting a weakened workflow.
    """
    opts = options or RenderOptions()
    inline = _inline_values(config, opts)
    blocks = _blocks(config, opts)
    names = list(workflows) if workflows is not None else list_workflows(directory)
    rendered: dict[str, str] = {}
    for name in names:
        stem = name[:-4] if name.endswith(".yml") else name
        text = _render_text(load_workflow(stem, directory), inline, blocks)
        _check_rendered(f"{stem}.yml", text)
        rendered[f"{stem}.yml"] = text
    return rendered


def render_caller(
    config: ProjectConfig, *, options: RenderOptions | None = None, directory: Path | None = None
) -> str:
    """Render the consumer ("caller") workflow that wires a repository to the org workflows."""
    opts = options or RenderOptions()
    path = (directory or CI_DIR) / CALLER_TEMPLATE
    if not SHA_RE.match(opts.workflows_ref):
        raise RenderError("workflows_ref must be a 40-hex commit SHA of the workflows repository")
    text = _render_text(
        path.read_text(encoding="utf-8"), _inline_values(config, opts), _blocks(config, opts)
    )
    _check_rendered(CALLER_TEMPLATE, text)
    return text


def render_to(
    config: ProjectConfig,
    out_dir: str | Path,
    *,
    options: RenderOptions | None = None,
    workflows: Iterable[str] | None = None,
    include_caller: bool = True,
) -> list[Path]:
    """Render workflows (and the caller) into *out_dir*; returns the written paths."""
    root = Path(out_dir)
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, text in render(config, options=options, workflows=workflows).items():
        path = root / name
        path.write_text(text, encoding="utf-8")
        written.append(path)
    if include_caller:
        path = root / "aisdlc-ci.yml"
        path.write_text(render_caller(config, options=options), encoding="utf-8")
        written.append(path)
    return written


def catalogue_from_templates(directory: Path | None = None) -> dict[str, set[str]]:
    """``{action: {sha, ...}}`` actually referenced by the templates (for consistency checks)."""
    found: dict[str, set[str]] = {}
    root = directory or WORKFLOWS_DIR
    for path in sorted(root.glob("*.yml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = _USES_RE.match(line)
            if match and "@" in match.group(2) and not match.group(2).startswith("./"):
                action, sha = match.group(2).rsplit("@", 1)
                found.setdefault(action, set()).add(sha)
    return found


def describe(config: ProjectConfig, options: RenderOptions | None = None) -> dict[str, Any]:
    """The inline values and block names a render would use (for ``aisdlc ci list``)."""
    opts = options or RenderOptions()
    return {
        "languages": _languages(config),
        "inline": _inline_values(config, opts),
        "blocks": {k: len(v) for k, v in _blocks(config, opts).items()},
        "workflows": list_workflows(),
    }
