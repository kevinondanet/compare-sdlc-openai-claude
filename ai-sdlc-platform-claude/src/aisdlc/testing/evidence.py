"""Capture :class:`~aisdlc.schema.models.TestEvidence` from a test run or CI artifacts.

:func:`capture` runs a command (never through a shell), records exit code and timing, parses
JUnit XML test counts and Cobertura XML / coverage.py JSON coverage, optionally computes diff
coverage from ``git diff`` plus per-line coverage data, and returns a :class:`CaptureResult`
whose ``evidence`` is a :class:`TestEvidence`.  A timeout or an artifact that cannot be
parsed leaves the record ``incomplete`` so the gate fails closed.

:func:`evidence_from_artifacts` is the parse-only entry point for artifacts produced by CI.
:func:`record_test_evidence` appends the record to ``evidence/tests.json`` via the schema
package API.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from aisdlc import __version__, ids
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import Coverage, EvidenceKind, EvidenceStatus, TestEvidence, utcnow

__all__ = [
    "CaptureResult",
    "CoverageData",
    "DiffCoverage",
    "JunitCounts",
    "added_lines_from_diff",
    "capture",
    "capture_test_evidence",
    "diff_coverage",
    "evidence_from_artifacts",
    "git_diff",
    "git_head",
    "next_test_evidence_id",
    "parse_cobertura",
    "parse_coverage_json",
    "parse_junit",
    "record_test_evidence",
]

PRODUCED_BY = f"aisdlc.testing.evidence/{__version__}"
DEFAULT_EVIDENCE_ID = "EVD-tests-001"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class JunitCounts(_Model):
    """Counts extracted from a JUnit XML report."""

    tests: int = Field(default=0, ge=0)
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0, description="Failures (assertion) — see ``errors``.")
    errors: int = Field(default=0, ge=0)
    skipped: int = Field(default=0, ge=0)

    @property
    def failed_total(self) -> int:
        """Failures plus errors — what ``TestEvidence.failed`` records."""
        return self.failed + self.errors


class CoverageData(_Model):
    """Coverage totals plus per-file line data (needed for diff coverage)."""

    lines_percent: float | None = Field(default=None, ge=0, le=100)
    branches_percent: float | None = Field(default=None, ge=0, le=100)
    files: dict[str, dict[int, bool]] = Field(
        default_factory=dict, description="file -> {line number: covered}"
    )
    source: str = ""

    def lookup(self, path: str) -> dict[int, bool] | None:
        """Per-line data for *path*, matching by normalised path or path suffix."""
        wanted = _norm(path)
        if wanted in self.files:
            return self.files[wanted]
        for known, data in self.files.items():
            if known.endswith("/" + wanted) or wanted.endswith("/" + known):
                return data
        return None


class DiffCoverage(_Model):
    """Coverage of lines added by a diff."""

    covered: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)
    files: dict[str, tuple[int, int]] = Field(
        default_factory=dict, description="file -> (covered, measurable added lines)"
    )

    @property
    def percent(self) -> float | None:
        """Percent covered, ``None`` when no added line is measurable."""
        if self.total == 0:
            return None
        return round(100.0 * self.covered / self.total, 2)


class CaptureResult(_Model):
    """Outcome of :func:`capture` / :func:`evidence_from_artifacts`."""

    evidence: TestEvidence
    problems: list[str] = Field(default_factory=list)
    timed_out: bool = False
    stdout_tail: str = ""
    stderr_tail: str = ""
    junit: JunitCounts | None = None
    coverage_data: CoverageData | None = None
    diff: DiffCoverage | None = None

    @property
    def ok(self) -> bool:
        """Complete evidence with a zero exit code and no failures."""
        return self.evidence.succeeded


# --------------------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------------------


def _read_text(source: str | Path | bytes) -> str:
    if isinstance(source, bytes):
        return source.decode("utf-8", errors="replace")
    if isinstance(source, Path) or (
        isinstance(source, str) and not source.lstrip().startswith("<") and "\n" not in source
    ):
        return Path(source).read_text(encoding="utf-8")
    return source


def _parse_xml(source: str | Path | bytes) -> ET.Element:
    """Parse XML from a path, XML text or bytes (expat with default entity limits)."""
    text = _read_text(source)
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML: {exc}") from exc


def parse_junit(source: str | Path | bytes) -> JunitCounts:
    """Parse a JUnit XML report (``<testsuites>`` or ``<testsuite>`` root).

    Test cases are counted individually (``failure`` → failed, ``error`` → errors,
    ``skipped`` → skipped, otherwise passed).  When a file carries only suite attributes
    the ``tests``/``failures``/``errors``/``skipped`` attributes are used instead.
    """
    root = _parse_xml(source)
    tag = root.tag.rsplit("}", 1)[-1]
    if tag not in ("testsuites", "testsuite"):
        raise ValueError(f"not a JUnit report (root element {root.tag!r})")
    cases = [el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "testcase"]
    if cases:
        passed = failed = errors = skipped = 0
        for case in cases:
            kinds = {child.tag.rsplit("}", 1)[-1] for child in case}
            if "failure" in kinds:
                failed += 1
            elif "error" in kinds:
                errors += 1
            elif "skipped" in kinds:
                skipped += 1
            else:
                passed += 1
        return JunitCounts(
            tests=len(cases), passed=passed, failed=failed, errors=errors, skipped=skipped
        )
    if tag == "testsuite":
        suites = [root]
    else:
        suites = [el for el in root.iter() if el.tag.rsplit("}", 1)[-1] == "testsuite"] or [root]

    def attr(el: ET.Element, name: str) -> int:
        raw = el.get(name)
        if raw is None:
            return 0
        try:
            return int(float(raw))
        except ValueError as exc:
            raise ValueError(f"JUnit attribute {name}={raw!r} is not a number") from exc

    tests = sum(attr(s, "tests") for s in suites)
    failed = sum(attr(s, "failures") for s in suites)
    errors = sum(attr(s, "errors") for s in suites)
    skipped = sum(attr(s, "skipped") for s in suites)
    passed = max(0, tests - failed - errors - skipped)
    return JunitCounts(tests=tests, passed=passed, failed=failed, errors=errors, skipped=skipped)


def _norm(path: str) -> str:
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return os.path.normpath(path).replace("\\", "/") if path else path


def parse_cobertura(source: str | Path | bytes) -> CoverageData:
    """Parse a Cobertura XML coverage report (``coverage.py --cov-report=xml``, JaCoCo
    conversions, gcovr, istanbul's cobertura reporter)."""
    root = _parse_xml(source)
    if root.tag.rsplit("}", 1)[-1] != "coverage":
        raise ValueError(f"not a Cobertura report (root element {root.tag!r})")
    files: dict[str, dict[int, bool]] = {}
    for cls in root.iter("class"):
        filename = cls.get("filename")
        if not filename:
            continue
        data = files.setdefault(_norm(filename), {})
        for line in cls.iter("line"):
            number = line.get("number")
            hits = line.get("hits", "0")
            if number is None:
                continue
            try:
                data[int(number)] = int(float(hits)) > 0
            except ValueError as exc:
                raise ValueError(f"bad line entry number={number!r} hits={hits!r}") from exc
    lines_pct = _rate(root.get("line-rate"))
    if lines_pct is None:
        valid = _int_attr(root, "lines-valid")
        covered = _int_attr(root, "lines-covered")
        if valid:
            lines_pct = round(100.0 * covered / valid, 2)
        elif files:
            total = sum(len(d) for d in files.values())
            hit = sum(1 for d in files.values() for v in d.values() if v)
            lines_pct = round(100.0 * hit / total, 2) if total else None
    branches_pct = _rate(root.get("branch-rate"))
    if branches_pct is None:
        valid = _int_attr(root, "branches-valid")
        covered = _int_attr(root, "branches-covered")
        if valid:
            branches_pct = round(100.0 * covered / valid, 2)
    if _int_attr(root, "branches-valid") == 0 and root.get("branches-valid") is not None:
        branches_pct = None
    sources = [s.text.strip() for s in root.iter("source") if s.text and s.text.strip()]
    return CoverageData(
        lines_percent=lines_pct,
        branches_percent=branches_pct,
        files=files,
        source=sources[0] if sources else "",
    )


def _rate(raw: str | None) -> float | None:
    if raw is None:
        return None
    try:
        return round(100.0 * float(raw), 2)
    except ValueError as exc:
        raise ValueError(f"bad coverage rate {raw!r}") from exc


def _int_attr(el: ET.Element, name: str) -> int:
    raw = el.get(name)
    if raw is None:
        return 0
    try:
        return int(float(raw))
    except ValueError as exc:
        raise ValueError(f"bad attribute {name}={raw!r}") from exc


def parse_coverage_json(source: str | Path | bytes | Mapping[str, Any]) -> CoverageData:
    """Parse ``coverage.py`` JSON (``coverage json``) into :class:`CoverageData`."""
    if isinstance(source, Mapping):
        data: Any = dict(source)
    else:
        if isinstance(source, bytes):
            text = source.decode("utf-8", errors="replace")
        elif isinstance(source, Path) or not source.lstrip().startswith("{"):
            text = Path(source).read_text(encoding="utf-8")
        else:
            text = source
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid coverage JSON: {exc}") from exc
    if not isinstance(data, dict) or "totals" not in data or "files" not in data:
        raise ValueError("not a coverage.py JSON report (missing totals/files)")
    totals = data["totals"]
    lines_pct = totals.get("percent_covered")
    lines_percent = round(float(lines_pct), 2) if lines_pct is not None else None
    num_branches = int(totals.get("num_branches", 0) or 0)
    covered_branches = int(totals.get("covered_branches", 0) or 0)
    branches_percent = (
        round(100.0 * covered_branches / num_branches, 2) if num_branches > 0 else None
    )
    files: dict[str, dict[int, bool]] = {}
    for path, entry in data["files"].items():
        per_line: dict[int, bool] = {}
        for n in entry.get("executed_lines", []):
            per_line[int(n)] = True
        for n in entry.get("missing_lines", []):
            per_line[int(n)] = False
        files[_norm(str(path))] = per_line
    return CoverageData(lines_percent=lines_percent, branches_percent=branches_percent, files=files)


# --------------------------------------------------------------------------------------
# Diff coverage
# --------------------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def added_lines_from_diff(diff_text: str) -> dict[str, set[int]]:
    """Return ``{new path: {added line numbers}}`` from a unified diff."""
    added: dict[str, set[int]] = {}
    current: str | None = None
    new_line = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].split("\t", 1)[0].strip()
            if target == "/dev/null":
                current = None
            else:
                if target.startswith("b/"):
                    target = target[2:]
                current = _norm(target)
                added.setdefault(current, set())
            continue
        if raw.startswith("--- ") or raw.startswith("diff ") or raw.startswith("index "):
            continue
        match = _HUNK_RE.match(raw)
        if match:
            new_line = int(match.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+"):
            added[current].add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            continue
        elif raw.startswith("\\"):
            continue
        else:
            new_line += 1
    return added


def diff_coverage(coverage: CoverageData, added: Mapping[str, set[int]]) -> DiffCoverage:
    """Coverage of *added* lines that the coverage data knows about.

    Added lines in files absent from the coverage report (tests, docs, non-code) are not
    measurable and are ignored; lines the report lists as neither executed nor missing
    (blank lines, comments) are ignored as well.
    """
    result = DiffCoverage()
    covered_total = 0
    total = 0
    files: dict[str, tuple[int, int]] = {}
    for path, lines in added.items():
        per_line = coverage.lookup(path)
        if per_line is None:
            continue
        measurable = [n for n in lines if n in per_line]
        if not measurable:
            continue
        hit = sum(1 for n in measurable if per_line[n])
        files[path] = (hit, len(measurable))
        covered_total += hit
        total += len(measurable)
    return result.model_copy(update={"covered": covered_total, "total": total, "files": files})


# --------------------------------------------------------------------------------------
# git helpers (local repository only; never touch the network)
# --------------------------------------------------------------------------------------


def _git(args: Sequence[str], cwd: Path, timeout: float = 30.0) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def git_head(cwd: str | Path) -> str:
    """``HEAD`` commit SHA of the repository at *cwd* (empty string when unavailable)."""
    try:
        return _git(["rev-parse", "HEAD"], Path(cwd)).strip()
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return ""


def git_diff(cwd: str | Path, base: str) -> str:
    """Unified diff (``--unified=0``) of the working tree against *base*."""
    return _git(["diff", "--no-color", "--unified=0", "--no-ext-diff", base, "--"], Path(cwd))


# --------------------------------------------------------------------------------------
# Capture
# --------------------------------------------------------------------------------------


def _as_argv(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        argv = shlex.split(command)
    else:
        argv = [str(part) for part in command]
    if not argv:
        raise ValueError("empty command")
    return argv


def _tail(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[-limit:]


def _assemble(
    *,
    command: str,
    exit_code: int | None,
    commit_sha: str,
    environment: str,
    evidence_id: str,
    produced_by: str,
    report_uri: str | None,
    started_at: datetime,
    finished_at: datetime,
    junit_xml: str | Path | None,
    coverage_xml: str | Path | None,
    coverage_json: str | Path | None,
    diff_text: str | None,
    problems: list[str],
    timed_out: bool,
    stdout_tail: str = "",
    stderr_tail: str = "",
) -> CaptureResult:
    junit: JunitCounts | None = None
    if junit_xml is not None:
        try:
            junit = parse_junit(Path(junit_xml))
        except (OSError, ValueError) as exc:
            problems.append(f"junit: {exc}")
    cov_data: CoverageData | None = None
    for label, source, parser in (
        ("coverage-xml", coverage_xml, parse_cobertura),
        ("coverage-json", coverage_json, parse_coverage_json),
    ):
        if source is None:
            continue
        try:
            parsed = parser(Path(source))
        except (OSError, ValueError) as exc:
            problems.append(f"{label}: {exc}")
            continue
        if cov_data is None:
            cov_data = parsed
        else:
            merged = dict(cov_data.files)
            for path, per_line in parsed.files.items():
                merged.setdefault(path, per_line)
            cov_data = cov_data.model_copy(
                update={
                    "files": merged,
                    "lines_percent": (
                        cov_data.lines_percent
                        if cov_data.lines_percent is not None
                        else parsed.lines_percent
                    ),
                    "branches_percent": (
                        cov_data.branches_percent
                        if cov_data.branches_percent is not None
                        else parsed.branches_percent
                    ),
                }
            )
    diff: DiffCoverage | None = None
    if diff_text is not None:
        if cov_data is None:
            problems.append("diff coverage requested but no coverage data was parsed")
        else:
            diff = diff_coverage(cov_data, added_lines_from_diff(diff_text))
    coverage = Coverage(
        lines=cov_data.lines_percent if cov_data else None,
        branches=cov_data.branches_percent if cov_data else None,
        diff_lines=diff.percent if diff else None,
    )
    complete = exit_code is not None and not timed_out and not problems
    evidence = TestEvidence(
        id=evidence_id,
        kind=EvidenceKind.TESTS,
        commit_sha=commit_sha,
        environment=environment,
        produced_by=produced_by,
        started_at=started_at,
        finished_at=finished_at,
        report_uri=report_uri,
        status=EvidenceStatus.COMPLETE if complete else EvidenceStatus.INCOMPLETE,
        command=command,
        exit_code=exit_code,
        passed=junit.passed if junit else 0,
        failed=junit.failed_total if junit else 0,
        skipped=junit.skipped if junit else 0,
        coverage=coverage,
    )
    return CaptureResult(
        evidence=evidence,
        problems=problems,
        timed_out=timed_out,
        stdout_tail=stdout_tail,
        stderr_tail=stderr_tail,
        junit=junit,
        coverage_data=cov_data,
        diff=diff,
    )


def capture(
    command: str | Sequence[str],
    *,
    cwd: str | Path,
    env: Mapping[str, str] | None = None,
    commit_sha: str | None = None,
    junit_xml: str | Path | None = None,
    coverage_xml: str | Path | None = None,
    coverage_json: str | Path | None = None,
    timeout: float | None = None,
    diff_base: str | None = None,
    diff_text: str | None = None,
    environment: str = "local",
    evidence_id: str = DEFAULT_EVIDENCE_ID,
    produced_by: str = PRODUCED_BY,
    report_uri: str | None = None,
    tail_chars: int = 4000,
) -> CaptureResult:
    """Run *command* in *cwd* and build :class:`TestEvidence` from its outcome.

    * The command runs with ``shell=False`` (a string is ``shlex.split``); *env* entries are
      layered over the current environment.
    * *commit_sha* defaults to ``git rev-parse HEAD`` in *cwd*.
    * *junit_xml*, *coverage_xml* (Cobertura) and *coverage_json* (coverage.py) are parsed
      after the run; relative paths resolve against *cwd*.
    * Diff coverage is computed when *diff_text* (a unified diff) or *diff_base* (a git
      revision; ``git diff --unified=0 <base>`` is run in *cwd*) is given.
    * A timeout, a missing/unparseable artifact or a failed diff leaves the record
      ``incomplete``; a non-zero exit code is recorded but the evidence stays complete.
    """
    root = Path(cwd)
    argv = _as_argv(command)
    problems: list[str] = []
    full_env = {**os.environ, **env} if env is not None else None
    started = utcnow()
    exit_code: int | None = None
    timed_out = False
    stdout = stderr = ""
    try:
        proc = subprocess.run(  # noqa: S603 - argv list, never a shell
            argv,
            cwd=str(root),
            env=full_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        exit_code = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        problems.append(f"timed out after {timeout}s")
        stdout = _decode(exc.stdout)
        stderr = _decode(exc.stderr)
    except OSError as exc:
        problems.append(f"could not start command: {exc}")
    finished = utcnow()
    sha = commit_sha if commit_sha is not None else git_head(root)
    text = diff_text
    if text is None and diff_base:
        try:
            text = git_diff(root, diff_base)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            problems.append(f"diff: {exc}")
    return _assemble(
        command=shlex.join(argv),
        exit_code=exit_code,
        commit_sha=sha,
        environment=environment,
        evidence_id=evidence_id,
        produced_by=produced_by,
        report_uri=report_uri,
        started_at=started,
        finished_at=finished,
        junit_xml=_resolve(root, junit_xml),
        coverage_xml=_resolve(root, coverage_xml),
        coverage_json=_resolve(root, coverage_json),
        diff_text=text,
        problems=problems,
        timed_out=timed_out,
        stdout_tail=_tail(stdout, tail_chars),
        stderr_tail=_tail(stderr, tail_chars),
    )


def _decode(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _resolve(root: Path, path: str | Path | None) -> Path | None:
    if path is None:
        return None
    candidate = Path(path)
    return candidate if candidate.is_absolute() else root / candidate


def capture_test_evidence(
    command: str | Sequence[str],
    *,
    cwd: str | Path,
    env: Mapping[str, str] | None = None,
    commit_sha: str | None = None,
    junit_xml: str | Path | None = None,
    coverage_xml: str | Path | None = None,
    coverage_json: str | Path | None = None,
    timeout: float | None = None,
    diff_base: str | None = None,
    environment: str = "local",
    evidence_id: str = DEFAULT_EVIDENCE_ID,
    report_uri: str | None = None,
) -> TestEvidence:
    """Convenience wrapper around :func:`capture` returning only the :class:`TestEvidence`."""
    return capture(
        command,
        cwd=cwd,
        env=env,
        commit_sha=commit_sha,
        junit_xml=junit_xml,
        coverage_xml=coverage_xml,
        coverage_json=coverage_json,
        timeout=timeout,
        diff_base=diff_base,
        environment=environment,
        evidence_id=evidence_id,
        report_uri=report_uri,
    ).evidence


def evidence_from_artifacts(
    *,
    command: str,
    exit_code: int | None,
    junit_xml: str | Path | None = None,
    coverage_xml: str | Path | None = None,
    coverage_json: str | Path | None = None,
    diff_text: str | None = None,
    diff_file: str | Path | None = None,
    commit_sha: str = "",
    environment: str = "ci",
    evidence_id: str = DEFAULT_EVIDENCE_ID,
    produced_by: str = PRODUCED_BY,
    report_uri: str | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> CaptureResult:
    """Parse-only entry point for artifacts produced elsewhere (CI).

    The command was already run; supply its *exit_code* (``None`` marks an unknown/aborted
    run and yields incomplete evidence) and the artifact paths.
    """
    problems: list[str] = []
    text = diff_text
    if text is None and diff_file is not None:
        try:
            text = Path(diff_file).read_text(encoding="utf-8")
        except OSError as exc:
            problems.append(f"diff: {exc}")
    if exit_code is None:
        problems.append("exit code unknown")
    now = utcnow()
    return _assemble(
        command=command,
        exit_code=exit_code,
        commit_sha=commit_sha,
        environment=environment,
        evidence_id=evidence_id,
        produced_by=produced_by,
        report_uri=report_uri,
        started_at=started_at or now,
        finished_at=finished_at or now,
        junit_xml=junit_xml,
        coverage_xml=coverage_xml,
        coverage_json=coverage_json,
        diff_text=text,
        problems=problems,
        timed_out=False,
    )


# --------------------------------------------------------------------------------------
# Persistence through the schema package API
# --------------------------------------------------------------------------------------


def next_test_evidence_id(package_dir: str | Path) -> str:
    """The next free ``EVD-tests-nnn`` id in ``<package>/evidence/tests.json``."""
    existing = [e.id for e in pkgio.read_evidence(package_dir, EvidenceKind.TESTS)]
    return ids.next_id("EVD", existing, evidence_kind="tests")


def record_test_evidence(package_dir: str | Path, evidence: TestEvidence) -> Path:
    """Append *evidence* to ``evidence/tests.json`` (replacing a record with the same id)."""
    return pkgio.append_evidence(package_dir, evidence)
