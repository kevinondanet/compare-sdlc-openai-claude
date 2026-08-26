"""``aisdlc init`` — scaffold a repository for the platform.

Writes, under ``--root`` (default: the current directory):

* ``aisdlc.yaml`` — the project configuration (:class:`~aisdlc.policy.ProjectConfig`),
  discovered automatically by every command;
* ``org-policy.yaml`` — the organization policy this project is governed by (a copy of
  ``--org-policy`` or the built-in defaults) so the reference is explicit and reviewable;
* ``changes/`` — where change packages live (``aisdlc change new``);
* ``.aisdlc/`` — local state (usage ledger, signing key), git-ignored via
  ``.aisdlc/.gitignore``; with ``--signing-key`` a random HMAC key for
  ``aisdlc gate bundle`` is written to ``.aisdlc/signing.key`` (mode 0600);
* a git repository (``--git``, default) when the root is not already inside one, with an
  initial commit of the **whole working tree** (``.gitignore`` respected) — the
  orchestrator isolates tasks in git worktrees created from ``HEAD`` and evidence records
  commit SHAs, so the project's sources must be committed for agents to see them. Files
  whose name matches a secrets pattern (:data:`SECRET_PATTERNS`: ``.env``, ``*.key``,
  ``*.pem``, ``settings.local.json``, ...) are never committed and are reported. When the
  root is already inside a repository with uncommitted files, the report says how many and
  which command commits them (``aisdlc run change`` refuses to start on a dirty tree).

Existing files are left alone unless ``--force`` is given.
"""

from __future__ import annotations

import fnmatch
import json
import os
import secrets
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import typer

from aisdlc.cli import _common as common
from aisdlc.policy import org_policy as orgmod
from aisdlc.policy import project_config as projmod
from aisdlc.schema import package as pkgio

NAME = "init"
app = typer.Typer(
    help="Scaffold aisdlc.yaml, org-policy.yaml, changes/ and a local signing key.",
    invoke_without_command=True,
)

PROJECT_CONFIG_FILE = "aisdlc.yaml"
ORG_POLICY_FILE = "org-policy.yaml"

#: Basename patterns ``init`` never commits (matched with :func:`fnmatch.fnmatchcase`).
SECRET_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "settings.local.json",
)
#: ``.env.example``-style templates are documentation, not secrets.
_SECRET_EXEMPT_SUFFIXES: tuple[str, ...] = (".example", ".sample", ".template", ".dist")
#: Directory names holding generated artefacts: never committed by ``init`` (even without a
#: ``.gitignore``) and ignored by the uncommitted-sources check of ``aisdlc run``.
GENERATED_DIRS: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".venv",
        "venv",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".hypothesis",
        ".tox",
        ".nox",
    }
)
GENERATED_PATTERNS: tuple[str, ...] = ("*.pyc", "*.pyo")
#: Repository-relative prefixes whose uncommitted files never block a run: the change
#: packages themselves (the platform writes evidence and handoffs there) and local state.
RUN_EXEMPT_PREFIXES: tuple[str, ...] = (f"{pkgio.CHANGES_DIR}/", ".aisdlc/")
SKIPPED_SECRET = "not committed (matches a secrets pattern; add it to .gitignore)"
COMMIT_HINT = "git add -A && git commit -m 'adopt aisdlc'"

__all__ = [
    "NAME",
    "app",
    "PROJECT_CONFIG_FILE",
    "ORG_POLICY_FILE",
    "SECRET_PATTERNS",
    "GENERATED_DIRS",
    "RUN_EXEMPT_PREFIXES",
    "SKIPPED_SECRET",
    "COMMIT_HINT",
    "is_secret_path",
    "is_generated_path",
    "uncommitted_sources",
    "scaffold",
]


def _bundled_org_policy() -> Path | None:
    """``templates/org-policy.yaml`` when running from a checkout, else ``None``."""
    candidate = Path(__file__).resolve().parents[3] / "templates" / ORG_POLICY_FILE
    return candidate if candidate.is_file() else None


def _org_policy_text(source: Path | None) -> str:
    """Validated YAML text of the organization policy to install (comments preserved)."""
    chosen = source if source is not None else _bundled_org_policy()
    if chosen is not None:
        orgmod.load_org_policy(chosen)  # validate before copying
        return chosen.read_text(encoding="utf-8")
    return (
        "# Organization policy (platform defaults). Projects may only tighten these values.\n"
        + orgmod.dump_org_policy(orgmod.default_org_policy())
    )


def _project_config_text(name: str) -> str:
    config = projmod.ProjectConfig(name=name)
    header = (
        "# AI-SDLC project configuration (aisdlc.policy.project_config.ProjectConfig).\n"
        f"# Organization policy: ./{ORG_POLICY_FILE} (discovered automatically; "
        "see aisdlc.policy.ORG_POLICY_CANDIDATES).\n"
        "# `overrides` may only tighten organization values (narrow-only merge).\n"
    )
    return header + projmod.dump_project_config(config)


def _git(root: Path, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        input=input_text,
        check=False,
    )


def is_secret_path(path: str) -> bool:
    """Whether the basename of *path* matches one of :data:`SECRET_PATTERNS`."""
    name = PurePosixPath(path).name
    if name.endswith(_SECRET_EXEMPT_SUFFIXES):
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in SECRET_PATTERNS)


def is_generated_path(path: str) -> bool:
    """Whether *path* lives under one of :data:`GENERATED_DIRS` or is a bytecode file."""
    parts = PurePosixPath(path).parts
    if any(part in GENERATED_DIRS for part in parts[:-1]):
        return True
    return any(fnmatch.fnmatchcase(parts[-1], pattern) for pattern in GENERATED_PATTERNS)


def uncommitted_sources(root: Path) -> list[str]:
    """Modified or untracked files under *root* that task worktrees would not contain.

    Worktrees start from ``HEAD``, so anything uncommitted is invisible to agents and to
    verification commands. Paths under :data:`RUN_EXEMPT_PREFIXES` (``changes/``,
    ``.aisdlc/``) and generated artefacts (:func:`is_generated_path`) are left out. Returns
    ``[]`` when *root* is not inside a repository.
    """
    proc = _git(root, "status", "--porcelain", "--untracked-files=all")
    if proc.returncode != 0:
        return []
    prefix = _git(root, "rev-parse", "--show-prefix").stdout.strip()
    dirty: list[str] = []
    for line in proc.stdout.splitlines():
        if len(line) <= 3:
            continue
        path = line[3:].split(" -> ")[-1].strip().strip('"')
        if prefix and path.startswith(prefix):
            path = path[len(prefix) :]
        if path.startswith(RUN_EXEMPT_PREFIXES) or is_generated_path(path):
            continue
        dirty.append(path)
    return dirty


def _candidate_files(root: Path) -> list[str]:
    """Untracked, non-ignored files under *root* (repository-relative, POSIX)."""
    proc = _git(root, "ls-files", "--others", "--exclude-standard", "-z")
    if proc.returncode != 0:
        return []
    return [item for item in proc.stdout.split("\0") if item]


def _init_git(root: Path, tracked: list[str]) -> tuple[str, list[str]]:
    """Create a repository with an initial commit of the working tree unless *root* is
    already inside one.

    Returns ``(status, skipped)``: *status* is ``created (...)``, ``exists`` (with the
    count of uncommitted sources and the command that commits them when there are any),
    ``skipped`` or a ``failed (...)`` message; *skipped* lists the files left out because
    they match :data:`SECRET_PATTERNS`. Generated artefacts (:func:`is_generated_path`) are
    left out too and only counted.
    """
    if shutil.which("git") is None:
        return "skipped (git not installed)", []
    if _git(root, "rev-parse", "--is-inside-work-tree").returncode == 0:
        pending = len(uncommitted_sources(root))
        if pending:
            return (
                f"exists ({pending} uncommitted file(s); agents run against HEAD, so commit "
                f"them before `aisdlc run`: {COMMIT_HINT})",
                [],
            )
        return "exists", []
    init = _git(root, "init", "-q")
    if init.returncode != 0:
        return f"failed ({(init.stderr or init.stdout).strip()})", []
    candidates = _candidate_files(root)
    skipped = sorted(path for path in candidates if is_secret_path(path))
    generated = sum(1 for path in candidates if is_generated_path(path))
    to_add = [path for path in candidates if not (is_secret_path(path) or is_generated_path(path))]
    if to_add:
        add = _git(
            root,
            "--literal-pathspecs",
            "add",
            "--pathspec-from-file=-",
            "--pathspec-file-nul",
            input_text="\0".join(to_add) + "\0",
        )
        if add.returncode != 0:
            return f"initialised, staging failed ({(add.stderr or add.stdout).strip()})", skipped
    # The scaffold is committed even when a project .gitignore would exclude it.
    _git(root, "add", "-f", "--", *tracked)
    identity: list[str] = []
    if not _git(root, "config", "user.email").stdout.strip():
        identity = ["-c", "user.name=aisdlc", "-c", "user.email=aisdlc@localhost"]
    commit = _git(root, *identity, "commit", "-q", "-m", "chore: aisdlc init")
    if commit.returncode != 0:
        message = (commit.stderr or commit.stdout).strip()
        return f"initialised, initial commit failed ({message})", skipped
    committed = len(_git(root, "ls-files").stdout.splitlines())
    status = f"created ({committed} file(s) committed"
    if generated:
        status += f"; {generated} generated file(s) left out, e.g. __pycache__/, .venv/"
    return status + ")", skipped


def _write(path: Path, text: str, force: bool, mode: int | None = None) -> str:
    """Write *text* to *path* unless it exists (and not *force*); return the action taken.

    With *mode* the file is created through ``os.open`` with that mode from the first
    byte (no umask-dependent window in which a key is world-readable), then re-chmod'ed
    when it already existed.
    """
    existed = path.exists()
    if existed and not force:
        return "exists"
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        path.write_text(text, encoding="utf-8")
        return "overwritten" if existed else "created"
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if existed else os.O_EXCL)
    fd = os.open(str(path), flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(path, mode)
    return "overwritten" if existed else "created"


def scaffold(
    root: Path,
    *,
    name: str | None = None,
    org_policy: Path | None = None,
    signing_key: bool = True,
    git: bool = True,
    force: bool = False,
) -> dict[str, str]:
    """Scaffold *root* and return ``{relative path: created|exists|overwritten|...}``.

    With *git*, ``.git`` maps to the repository status (see :func:`_init_git`) and every
    file skipped because it matches :data:`SECRET_PATTERNS` maps to :data:`SKIPPED_SECRET`.
    """
    root.mkdir(parents=True, exist_ok=True)
    project_name = name or root.resolve().name or "project"
    actions: dict[str, str] = {}
    actions[PROJECT_CONFIG_FILE] = _write(
        root / PROJECT_CONFIG_FILE, _project_config_text(project_name), force
    )
    actions[ORG_POLICY_FILE] = _write(root / ORG_POLICY_FILE, _org_policy_text(org_policy), force)
    changes = root / pkgio.CHANGES_DIR
    changes.mkdir(parents=True, exist_ok=True)
    actions[f"{pkgio.CHANGES_DIR}/.gitkeep"] = _write(changes / ".gitkeep", "", force)
    state = common.hmac_key_file(root).parent
    actions[f"{state.name}/.gitignore"] = _write(state / ".gitignore", "*\n", force)
    if signing_key:
        actions[f"{state.name}/signing.key"] = _write(
            common.hmac_key_file(root), secrets.token_hex(32) + "\n", force, mode=0o600
        )
    if git:
        tracked = [PROJECT_CONFIG_FILE, ORG_POLICY_FILE, f"{pkgio.CHANGES_DIR}/.gitkeep"]
        actions[".git"], skipped = _init_git(root, tracked)
        for path in skipped:
            actions[path] = SKIPPED_SECRET
    return actions


@app.callback(invoke_without_command=True)
def init(
    ctx: typer.Context,
    root: Path = typer.Option(Path("."), "--root", help="Repository root to scaffold."),
    name: str | None = typer.Option(None, "--name", help="Project name (default: dir name)."),
    org_policy: Path | None = typer.Option(
        None,
        "--org-policy",
        help="Organization policy to copy in as org-policy.yaml (default: built-in defaults).",
    ),
    signing_key: bool = typer.Option(
        True,
        "--signing-key/--no-signing-key",
        help="Write a local HMAC key for `aisdlc gate bundle` to .aisdlc/signing.key.",
    ),
    git: bool = typer.Option(
        True,
        "--git/--no-git",
        help="Create a git repository committing the working tree (minus secrets) when not "
        "already inside one.",
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite existing files."),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Scaffold a repository: aisdlc.yaml, org-policy.yaml, changes/, .aisdlc/, git."""
    if ctx.invoked_subcommand is not None:
        return
    try:
        actions = scaffold(
            root,
            name=name,
            org_policy=org_policy,
            signing_key=signing_key,
            git=git,
            force=force,
        )
    except (orgmod.PolicyLoadError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if as_json:
        typer.echo(json.dumps({"root": str(root), "files": actions}, indent=2, sort_keys=True))
        return
    for relative, action in actions.items():
        typer.echo(f"{action:<11} {root / relative}")
    typer.echo(
        "next: aisdlc change new CHG-<slug> --title '<title>' --risk standard; aisdlc policy show"
    )
