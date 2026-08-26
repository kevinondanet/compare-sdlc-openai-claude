"""Shared driver for the pilot projects under ``pilots/``.

A pilot is a small real project plus a change package.  Its ``run.sh`` calls a
``pilot_<name>.py`` script that uses this module to:

1. copy the pilot into a fresh git repository (``prepare``) and commit two states —
   the project *before* the change (files under ``before/`` overlay their targets, files
   listed as ``absent`` are removed) and the project *with* the change — so that diff
   coverage, baselines and "before/after" gate results are measured against a real diff;
2. run the platform CLI in-process (``Workspace.run``) with every step, exit code and
   output recorded in a transcript;
3. sync the produced evidence, verdict and transcript back into the pilot directory and
   refresh the ``<!-- run-output:start -->`` section of its README with the real gate
   table (``sync_back``).

Everything runs offline; the only external tool is ``git``.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterable, Sequence
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aisdlc.cli.main import app

__all__ = [
    "GENERATED_ARTIFACTS",
    "PilotError",
    "PreChange",
    "Step",
    "Workspace",
    "acceptance_layer_runs",
    "critical_module_coverage",
    "main",
    "prepare",
    "python",
    "ruff_sarif",
    "sh",
    "sync_back",
    "update_readme",
]

#: Files/dirs under ``changes/<id>/`` that a run produces (removed before every run).
GENERATED_ARTIFACTS: tuple[str, ...] = (
    "evidence",
    "handoffs",
    "final-verdict.json",
    "evidence-bundle.json",
    "approvals.json",
    ".fingerprint",
    "run-log.md",
)

#: Files/dirs of a pilot that never enter the working copy.
_SKIP_COPY: tuple[str, ...] = ("__pycache__", ".run", ".pytest_cache", "coverage.json")

README_START = "<!-- run-output:start -->"
README_END = "<!-- run-output:end -->"

_SCN_RE = re.compile(r"\bSCN-\d{3}-\d{2}\b")


class PilotError(RuntimeError):
    """A pilot step did not produce the expected exit code."""


@dataclass(frozen=True)
class PreChange:
    """How to derive the *before the change* state from the shipped (final) pilot.

    Attributes:
        overlay_dir: Directory (relative to the pilot) whose files replace the same
            relative paths in the pre-change commit.
        absent: Relative paths that do not exist before the change.
        generated_package: The whole change package is produced by the run (discovery)
            and therefore removed from the pre-change state.
    """

    overlay_dir: str = "before"
    absent: tuple[str, ...] = ()
    generated_package: bool = False


@dataclass
class Step:
    """One recorded command of a pilot run."""

    argv: list[str]
    exit_code: int
    output: str
    seconds: float
    note: str = ""

    @property
    def command(self) -> str:
        """Shell-quoted command line."""
        return "aisdlc " + " ".join(shlex.quote(a) for a in self.argv)

    def json(self) -> Any:
        """Parse the output as JSON (``--json`` steps)."""
        return json.loads(self.output)


def python() -> str:
    """Interpreter used for pilot verification commands (the one running the driver)."""
    return sys.executable


def sh(command: str) -> str:
    """Wrap a shell pipeline for ``aisdlc test run-evidence --command`` (argv-only)."""
    return f"sh -c {shlex.quote(command)}"


@dataclass
class Workspace:
    """A pilot copied into a fresh git repository, driven through the CLI in-process."""

    pilot_dir: Path
    root: Path
    change_id: str
    pre_change: PreChange
    quiet: bool = False
    steps: list[Step] = field(default_factory=list)
    headings: list[tuple[int, str]] = field(default_factory=list)
    baseline_sha: str = ""
    change_sha: str = ""
    started: float = field(default_factory=time.monotonic)

    # ------------------------------------------------------------------ paths
    @property
    def package_dir(self) -> Path:
        """``<root>/changes/<change-id>``."""
        return self.root / "changes" / self.change_id

    @property
    def reports_dir(self) -> Path:
        """Non-canonical reports produced by the run (``evidence/reports``)."""
        path = self.package_dir / "evidence" / "reports"
        path.mkdir(parents=True, exist_ok=True)
        return path

    # ------------------------------------------------------------------ output
    def _echo(self, text: str) -> None:
        if not self.quiet:
            print(text, flush=True)

    def section(self, title: str) -> None:
        """Start a transcript section."""
        self.headings.append((len(self.steps), title))
        self._echo(f"\n== {title} ==")

    def note(self, text: str) -> None:
        """Record a non-CLI action in the transcript."""
        self.steps.append(Step(argv=[], exit_code=0, output="", seconds=0.0, note=text))
        self._echo(f"-- {text}")

    # ------------------------------------------------------------------ commands
    def run(self, args: Sequence[str], *, ok: Iterable[int] = (0,), note: str = "") -> Step:
        """Run ``aisdlc <args>`` in-process from the workspace root.

        Raises :class:`PilotError` unless the exit code is in *ok*.
        """
        from typer.testing import CliRunner

        argv = [str(a) for a in args]
        allowed = tuple(ok)
        started = time.monotonic()
        cwd = Path.cwd()
        os.chdir(self.root)
        try:
            with _PilotEnvironment(self.root):
                result = CliRunner().invoke(app, argv, catch_exceptions=True)
        finally:
            os.chdir(cwd)
        output = result.output
        if result.exception is not None and not isinstance(result.exception, SystemExit):
            output += f"\n[exception] {type(result.exception).__name__}: {result.exception}"
        step = Step(
            argv=argv,
            exit_code=result.exit_code,
            output=output,
            seconds=time.monotonic() - started,
            note=note,
        )
        self.steps.append(step)
        self._echo(f"$ {step.command}   [exit {step.exit_code}, {step.seconds:.1f}s]")
        if not self.quiet and output.strip():
            self._echo(_indent(output.rstrip()))
        if step.exit_code not in allowed:
            raise PilotError(
                f"{step.command} exited {step.exit_code}, expected one of {allowed}:\n{output}"
            )
        return step

    def shell(self, command: str, *, note: str = "") -> str:
        """Run a shell command in the workspace (for the project's own tools)."""
        started = time.monotonic()
        with _PilotEnvironment(self.root):
            proc = subprocess.run(  # noqa: S602 - pilot-authored command line
                command, shell=True, cwd=self.root, capture_output=True, text=True, check=False
            )
        output = proc.stdout + proc.stderr
        self.steps.append(
            Step(
                argv=["#shell", command],
                exit_code=proc.returncode,
                output=output,
                seconds=time.monotonic() - started,
                note=note,
            )
        )
        self._echo(f"$ {command}   [exit {proc.returncode}]")
        if not self.quiet and output.strip():
            self._echo(_indent(output.rstrip()))
        if proc.returncode != 0:
            raise PilotError(f"{command!r} exited {proc.returncode}:\n{output}")
        return output

    def git(self, *args: str) -> str:
        """Run ``git`` in the workspace and return stdout."""
        proc = subprocess.run(
            ["git", "-C", str(self.root), *args], capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            raise PilotError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout

    def head(self) -> str:
        """Current commit sha."""
        return self.git("rev-parse", "HEAD").strip()

    # ------------------------------------------------------------------ change
    def init_platform(self) -> Step:
        """``aisdlc init --no-git`` followed by the commit the user guide prescribes.

        Inside an existing repository ``init`` leaves its scaffold (``aisdlc.yaml``,
        ``org-policy.yaml``, ``changes/.gitkeep``) uncommitted and says so; ``aisdlc run``
        refuses to start while sources outside ``changes/`` are uncommitted because task
        worktrees are created from ``HEAD``. The pilots commit the scaffold right away.
        """
        step = self.run(["init", "--no-git"])
        scaffold = ("aisdlc.yaml", "org-policy.yaml", "changes/.gitkeep")
        if self.git("status", "--porcelain", "--", *scaffold).strip():
            self.git("add", "-A", "--", *scaffold)
            self.git("commit", "-q", "-m", "adopt aisdlc")
            self.note(f"committed the aisdlc scaffold as {self.head()[:12]}")
        return step

    def commit_change(self, message: str) -> str:
        """Restore the shipped (post-change) files and commit them as *the change*."""
        overlay = self.pilot_dir / self.pre_change.overlay_dir
        changed: list[str] = []
        if overlay.is_dir():
            for path in sorted(p for p in overlay.rglob("*") if p.is_file()):
                rel = path.relative_to(overlay).as_posix()
                shutil.copy2(self.pilot_dir / rel, self.root / rel)
                changed.append(rel)
        for rel in self.pre_change.absent:
            source = self.pilot_dir / rel
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            changed.append(rel)
        if self.pre_change.generated_package:
            changed.append(f"changes/{self.change_id}")
        for rel in changed:
            self.git("add", "-A", "--", rel)
        self.git("commit", "-q", "-m", message)
        self.change_sha = self.head()
        self.note(f"committed the change ({', '.join(changed)}) as {self.change_sha[:12]}")
        return self.change_sha

    def purge_modules(self, *prefixes: str) -> None:
        """Drop imported pilot modules so the next import sees the files on disk."""
        for name in list(sys.modules):
            if any(name == p or name.startswith(p + ".") for p in prefixes):
                del sys.modules[name]

    def import_module(self, name: str) -> Any:
        """Import a module of the project under test from the workspace copy."""
        import importlib

        with _PilotEnvironment(self.root):
            return importlib.import_module(name)

    # ------------------------------------------------------------------ transcript
    def elapsed(self) -> float:
        """Seconds since the workspace was created."""
        return time.monotonic() - self.started

    def gate_table(self) -> str:
        """Markdown gate table from the last ``gate verdict``/``gate evaluate`` JSON step."""
        results, risk, depth = self._last_gate_results()
        lines = [
            "| Gate | Result | Depth | Reasons |",
            "| --- | --- | --- | --- |",
        ]
        for item in results:
            status = (
                "SKIP" if item["depth"] == "skipped" else ("PASS" if item["passed"] else "FAIL")
            )
            reasons = "; ".join(item["reasons"]) or "—"
            lines.append(f"| {item['gate']} | {status} | {item['depth']} | {reasons} |")
        header = f"Risk class `{risk}`, depth `{depth}`."
        return header + "\n\n" + "\n".join(lines)

    def _last_gate_results(self) -> tuple[list[dict[str, Any]], str, str]:
        for step in reversed(self.steps):
            gate_step = step.argv[:2] in (["gate", "verdict"], ["gate", "evaluate"])
            if gate_step and "--json" in step.argv:
                data = step.json()
                if "gate_results" in data:
                    profile = self.profile()
                    return data["gate_results"], profile["risk_class"], profile["depth"]
                return data["results"], data["risk_class"], data["depth"]
        raise PilotError("no `gate verdict --json` / `gate evaluate --json` step recorded")

    def profile(self) -> dict[str, str]:
        """Risk class and depth of the last ``gate evaluate --json`` step."""
        for step in reversed(self.steps):
            if step.argv[:2] == ["gate", "evaluate"] and "--json" in step.argv:
                data = step.json()
                return {"risk_class": data["risk_class"], "depth": data["depth"]}
        return {"risk_class": "?", "depth": "?"}

    def transcript(self) -> str:
        """Full Markdown transcript of the run."""
        out = [f"# Run log — {self.change_id}", ""]
        out.append(f"Workspace: `{self.root}`; pre-change `{self.baseline_sha[:12]}`, ")
        out[-1] += f"change `{self.change_sha[:12]}`, final HEAD `{self.head()[:12]}`."
        out.append("")
        headings = dict(self.headings)
        for index, step in enumerate(self.steps):
            if index in headings:
                out.append(f"## {headings[index]}")
                out.append("")
            if not step.argv:
                out.append(f"- {step.note}")
                out.append("")
                continue
            label = step.argv[1] if step.argv[0] == "#shell" else step.command
            out.append(f"### `{label}` → exit {step.exit_code} ({step.seconds:.1f}s)")
            if step.note:
                out.append("")
                out.append(step.note)
            out.append("")
            out.append("```text")
            out.append(step.output.rstrip() or "(no output)")
            out.append("```")
            out.append("")
        out.append(f"Total time: {self.elapsed():.1f}s")
        return "\n".join(out) + "\n"

    def write_log(self) -> Path:
        """Write the transcript into the change package as ``run-log.md``."""
        path = self.package_dir / "run-log.md"
        path.write_text(self.transcript(), encoding="utf-8")
        return path


class _PilotEnvironment:
    """Context: venv ``bin`` first on ``PATH``, workspace importable, no inherited ledger."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._saved: dict[str, str | None] = {}
        self._path_added = False

    def __enter__(self) -> None:
        bin_dir = str(Path(sys.executable).parent)  # the venv bin, not the resolved interpreter
        for key in ("PATH", "AISDLC_LEDGER", "PYTHONPATH"):
            self._saved[key] = os.environ.get(key)
        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
        os.environ.pop("AISDLC_LEDGER", None)
        os.environ["PYTHONPATH"] = str(self.root) + (
            os.pathsep + self._saved["PYTHONPATH"] if self._saved["PYTHONPATH"] else ""
        )
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
            self._path_added = True

    def __exit__(self, *exc: object) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if self._path_added and str(self.root) in sys.path:
            sys.path.remove(str(self.root))


def _indent(text: str, prefix: str = "    ") -> str:
    return "\n".join(prefix + line for line in text.splitlines())


# --------------------------------------------------------------------------------------
# Preparing the working copy
# --------------------------------------------------------------------------------------


def _copy_pilot(pilot_dir: Path, root: Path, pre_change: PreChange) -> None:
    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = {n for n in names if n in _SKIP_COPY or n.endswith(".pyc")}
        if Path(directory) == pilot_dir:
            skipped.add(pre_change.overlay_dir)
        return skipped

    shutil.copytree(pilot_dir, root, ignore=ignore, dirs_exist_ok=True)


def _remove(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def prepare(
    pilot_dir: str | Path,
    root: str | Path,
    *,
    change_id: str,
    pre_change: PreChange,
    quiet: bool = False,
) -> Workspace:
    """Copy *pilot_dir* into *root*, reset generated artifacts, commit the pre-change state.

    The pre-change commit carries the ``before/`` overlay and lacks the ``absent`` files;
    :meth:`Workspace.commit_change` later restores the shipped files as the change commit.
    """
    pilot = Path(pilot_dir).resolve()
    target = Path(root).resolve()
    if target.exists() and any(target.iterdir()):
        raise PilotError(f"workspace {target} is not empty")
    target.mkdir(parents=True, exist_ok=True)
    _copy_pilot(pilot, target, pre_change)
    package = target / "changes" / change_id
    if pre_change.generated_package:
        _remove(package)
    else:
        for name in GENERATED_ARTIFACTS:
            _remove(package / name)
    overlay = pilot / pre_change.overlay_dir
    if overlay.is_dir():
        for path in sorted(p for p in overlay.rglob("*") if p.is_file()):
            rel = path.relative_to(overlay)
            (target / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target / rel)
    for absent in pre_change.absent:
        _remove(target / absent)
    ws = Workspace(
        pilot_dir=pilot, root=target, change_id=change_id, pre_change=pre_change, quiet=quiet
    )
    subprocess.run(["git", "init", "-q", "-b", "main", str(target)], check=True)
    ws.git("config", "user.email", "pilot@example.com")
    ws.git("config", "user.name", "pilot")
    ws.git("config", "commit.gpgsign", "false")
    ws.git("add", "-A")
    ws.git("commit", "-q", "-m", f"{pilot.name}: state before {change_id}")
    ws.baseline_sha = ws.head()
    ws.note(f"pre-change baseline committed as {ws.baseline_sha[:12]} in {target}")
    return ws


# --------------------------------------------------------------------------------------
# Evidence helpers used by several pilots
# --------------------------------------------------------------------------------------


def acceptance_layer_runs(
    package_dir: str | Path,
    tests_dir: str | Path,
    *,
    e2e_evidence_ids: Sequence[str] = (),
    e2e_pattern: str = "test_e2e*.py",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Trace acceptance scenarios to tests and build the extra portfolio layer runs.

    ``acceptance_criteria_with_evidence`` is the share of scenarios (``SCN-…`` ids in the
    package requirements) referenced by at least one test file; ``critical_journeys_e2e``
    is the share of functional *must* requirements (the user journeys) with at least one
    scenario referenced from an end-to-end test file (*e2e_pattern*).  Returns
    ``(layer_runs, traceability)``; ``layer_runs`` is the JSON for
    ``aisdlc test portfolio --layers``.
    """
    from aisdlc.schema import package as pkgio

    pkg = pkgio.load(Path(package_dir))
    tests = Path(tests_dir)
    referenced: dict[str, set[str]] = {}
    for path in sorted(tests.rglob("test_*.py")):
        for scn in _SCN_RE.findall(path.read_text(encoding="utf-8")):
            referenced.setdefault(scn, set()).add(path.name)
    e2e_files = {p.name for p in tests.rglob(e2e_pattern)}
    scenarios = [(r, s) for r in pkg.requirements for s in r.scenarios]
    covered = [s.id for _, s in scenarios if s.id in referenced]
    acceptance = 100.0 * len(covered) / len(scenarios) if scenarios else 100.0
    musts = [
        r for r in pkg.requirements if r.priority.value == "must" and r.kind.value == "functional"
    ]
    journeys = [
        r.id for r in musts if any(referenced.get(s.id, set()) & e2e_files for s in r.scenarios)
    ]
    journey_pct = 100.0 * len(journeys) / len(musts) if musts else 100.0
    missing = sorted(s.id for _, s in scenarios if s.id not in referenced)
    trace = {
        "scenarios": len(scenarios),
        "scenarios_with_tests": len(covered),
        "acceptance_criteria_with_evidence": round(acceptance, 2),
        "critical_journeys": [r.id for r in musts],
        "critical_journeys_with_e2e": journeys,
        "critical_journeys_e2e": round(journey_pct, 2),
        "missing": missing,
        "by_scenario": {k: sorted(v) for k, v in sorted(referenced.items())},
    }
    runs = [
        {
            "layer": "e2e",
            "executed": True,
            "complete": True,
            "metrics": {
                "acceptance_criteria_with_evidence": round(acceptance, 2),
                "critical_journeys_e2e": round(journey_pct, 2),
            },
            "evidence_ids": list(e2e_evidence_ids),
            "notes": [f"{len(covered)}/{len(scenarios)} scenarios traced to tests"],
        }
    ]
    return runs, trace


def critical_module_coverage(coverage_json: str | Path, modules: Sequence[str]) -> dict[str, float]:
    """Per-module line coverage (%) from a coverage.py JSON report."""
    data = json.loads(Path(coverage_json).read_text(encoding="utf-8"))
    files: dict[str, Any] = data.get("files", {})
    out: dict[str, float] = {}
    for module in modules:
        wanted = module.replace("\\", "/")
        for name, info in files.items():
            if name.replace("\\", "/").endswith(wanted):
                out[module] = round(float(info["summary"]["percent_covered"]), 2)
                break
        else:
            out[module] = 0.0
    return out


def ruff_sarif(root: Path, paths: Sequence[str], out: Path) -> Path:
    """Run ``ruff check --output-format sarif`` on *paths* and write the SARIF to *out*."""
    proc = subprocess.run(
        [python(), "-m", "ruff", "check", "--output-format", "sarif", "--exit-zero", *paths],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        raise PilotError(f"ruff SARIF generation failed: {proc.stderr.strip()}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(proc.stdout, encoding="utf-8")
    return out


# --------------------------------------------------------------------------------------
# Sync back + README
# --------------------------------------------------------------------------------------


def sync_back(ws: Workspace, summary: str) -> list[Path]:
    """Copy the run's evidence, verdict and transcript into the pilot and refresh README."""
    source = ws.package_dir
    target = ws.pilot_dir / "changes" / ws.change_id
    copied: list[Path] = []
    if ws.pre_change.generated_package:
        _remove(target)
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("handoffs", ".fingerprint"))
        copied.append(target)
    else:
        for name in ("evidence", "final-verdict.json", "evidence-bundle.json", "approvals.json"):
            _remove(target / name)
            src = source / name
            if src.is_dir():
                shutil.copytree(src, target / name)
            elif src.is_file():
                shutil.copy2(src, target / name)
            else:
                continue
            copied.append(target / name)
    log = target / "run-log.md"
    log.write_text(ws.transcript(), encoding="utf-8")
    copied.append(log)
    update_readme(ws.pilot_dir / "README.md", summary)
    return copied


def update_readme(readme: Path, body: str) -> None:
    """Replace the marked run-output section of *readme* with *body*."""
    text = readme.read_text(encoding="utf-8") if readme.exists() else ""
    block = f"{README_START}\n{body.rstrip()}\n{README_END}"
    if README_START in text and README_END in text:
        start = text.index(README_START)
        end = text.index(README_END) + len(README_END)
        text = text[:start] + block + text[end:]
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    readme.write_text(text, encoding="utf-8")


# --------------------------------------------------------------------------------------
# Entry point shared by the pilot scripts
# --------------------------------------------------------------------------------------


def main(
    run: Callable[[Workspace], str],
    *,
    pilot_dir: Path,
    change_id: str,
    pre_change: PreChange,
    argv: Sequence[str] | None = None,
) -> int:
    """Command-line entry point: ``--workdir``, ``--no-sync-back``, ``--quiet``."""
    parser = argparse.ArgumentParser(description=f"Run the {pilot_dir.name} pilot end to end.")
    parser.add_argument("--workdir", help="Empty directory to run in (default: a temp dir).")
    parser.add_argument(
        "--no-sync-back",
        action="store_true",
        help="Do not copy evidence/verdict back into the pilot or touch its README.",
    )
    parser.add_argument("--quiet", action="store_true", help="Only print the summary.")
    ns = parser.parse_args(list(argv) if argv is not None else None)
    root = Path(ns.workdir) if ns.workdir else Path(tempfile.mkdtemp(prefix=f"{pilot_dir.name}-"))
    ws = prepare(pilot_dir, root, change_id=change_id, pre_change=pre_change, quiet=ns.quiet)
    try:
        summary = run(ws)
    except PilotError as exc:
        print(f"\nPILOT FAILED: {exc}", file=sys.stderr)
        ws.write_log()
        return 1
    ws.write_log()
    if not ns.no_sync_back:
        for path in sync_back(ws, summary):
            print(f"synced {path}")
    print()
    print(summary)
    print(f"\nworkspace: {ws.root}\ntotal: {ws.elapsed():.1f}s")
    return 0


def capture_stdio(fn: Callable[[], Any]) -> tuple[Any, str]:
    """Run *fn* capturing stdout/stderr (for helpers that print)."""
    buffer = io.StringIO()
    with redirect_stdout(buffer), redirect_stderr(buffer):
        value = fn()
    return value, buffer.getvalue()
