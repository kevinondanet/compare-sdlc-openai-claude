"""``aisdlc init``'s initial commit and the uncommitted-sources precondition of ``aisdlc run``.

Task worktrees are created from ``HEAD``, so ``init`` must commit the whole working tree
(minus secrets and generated artefacts) when it creates the repository, report uncommitted
files when the repository already exists, and ``run change`` / ``run task`` must refuse to
start while sources outside ``changes/`` are uncommitted.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aisdlc.cli import cmd_init
from aisdlc.cli.main import app
from tests.orchestration_support import make_package

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
runner = CliRunner()


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout


def _write(root: Path, relative: str, text: str = "x\n") -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _status(root: Path) -> list[str]:
    out = _git(root, "status", "--porcelain", "--untracked-files=all")
    return sorted(line[3:] for line in out.splitlines() if line.strip())


@pytest.mark.parametrize(
    ("path", "secret"),
    [
        (".env", True),
        ("config/.env.production", True),
        ("certs/tls.key", True),
        ("tls.pem", True),
        ("keys/store.p12", True),
        ("store.pfx", True),
        (".claude/settings.local.json", True),
        (".env.example", False),
        (".env.sample", False),
        ("keyring.py", False),
        ("settings.json", False),
        ("src/app.py", False),
    ],
)
def test_is_secret_path(path: str, secret: bool) -> None:
    assert cmd_init.is_secret_path(path) is secret


@pytest.mark.parametrize(
    ("path", "generated"),
    [
        ("src/__pycache__/app.cpython-313.pyc", True),
        ("app.pyc", True),
        (".venv/lib/site.py", True),
        ("node_modules/pkg/index.js", True),
        (".pytest_cache/v/cache/nodeids", True),
        ("src/venv_tools.py", False),
        ("src/app.py", False),
    ],
)
def test_is_generated_path(path: str, generated: bool) -> None:
    assert cmd_init.is_generated_path(path) is generated


def test_init_commits_working_tree_minus_secrets_and_generated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _write(tmp_path, "src/app.py", "print('hi')\n")
    _write(tmp_path, "weird [1].txt", "glob characters are taken literally\n")
    _write(tmp_path, ".gitignore", "*.log\n")
    _write(tmp_path, "debug.log", "ignored by .gitignore\n")
    _write(tmp_path, ".env.example", "TOKEN=\n")
    _write(tmp_path, "src/__pycache__/app.cpython-313.pyc", "bytecode\n")
    secrets = [".env", "certs/tls.key", "certs/tls.pem", "settings.local.json"]
    for relative in secrets:
        _write(tmp_path, relative, "secret\n")

    result = runner.invoke(app, ["init", "--name", "demo", "--json"])
    assert result.exit_code == 0, result.output
    files = json.loads(result.output)["files"]
    assert files[".git"].startswith("created (")
    assert "file(s) committed" in files[".git"] and "1 generated file(s) left out" in files[".git"]
    for relative in secrets:
        assert files[relative] == cmd_init.SKIPPED_SECRET

    tracked = set(_git(tmp_path, "ls-files").splitlines())
    expected = {
        "src/app.py",
        "weird [1].txt",
        ".gitignore",
        ".env.example",
        "aisdlc.yaml",
        "org-policy.yaml",
        "changes/.gitkeep",
    }
    assert expected <= tracked, tracked
    assert not tracked & {*secrets, "debug.log", "src/__pycache__/app.cpython-313.pyc"}
    assert not any(name.startswith(".aisdlc/") for name in tracked)
    assert _git(tmp_path, "log", "-1", "--format=%s").strip() == "chore: aisdlc init"
    # only the secrets and the bytecode are left uncommitted; the bytecode is a generated
    # artefact, so it does not count as an uncommitted source either
    assert _status(tmp_path) == sorted([*secrets, "src/__pycache__/app.cpython-313.pyc"])
    assert cmd_init.uncommitted_sources(tmp_path) == secrets

    # a root nested inside the repository is "exists": nothing is committed on the user's
    # behalf; the new scaffold (2) plus the secrets left above (4) are reported as uncommitted
    nested = runner.invoke(app, ["init", "--root", str(tmp_path / "other"), "--no-signing-key"])
    assert nested.exit_code == 0, nested.output
    assert "exists (6 uncommitted file(s)" in nested.output, nested.output
    assert cmd_init.COMMIT_HINT in nested.output


def test_init_plain_output_lists_skipped_secrets(tmp_path: Path) -> None:
    _write(tmp_path, ".env", "TOKEN=x\n")
    _write(tmp_path, "app.py")
    result = runner.invoke(app, ["init", "--root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert cmd_init.SKIPPED_SECRET in result.output and str(tmp_path / ".env") in result.output
    assert _git(tmp_path, "ls-files").split() == [
        "aisdlc.yaml",
        "app.py",
        "changes/.gitkeep",
        "org-policy.yaml",
    ]


def test_init_in_existing_repo_reports_uncommitted_sources(tmp_repo: Path) -> None:
    _write(tmp_repo, "src/app.py")
    result = runner.invoke(app, ["init", "--root", str(tmp_repo), "--json"])
    assert result.exit_code == 0, result.output
    status = json.loads(result.output)["files"][".git"]
    # src/app.py plus the scaffold init just wrote (changes/.gitkeep is exempt)
    assert status.startswith("exists (3 uncommitted file(s)"), status
    assert cmd_init.COMMIT_HINT in status
    assert cmd_init.uncommitted_sources(tmp_repo) == [
        "aisdlc.yaml",
        "org-policy.yaml",
        "src/app.py",
    ]
    assert _git(tmp_repo, "log", "--oneline").count("\n") == 1  # init never commits here

    _git(tmp_repo, "add", "-A")
    _git(tmp_repo, "commit", "-q", "-m", "adopt aisdlc")
    again = runner.invoke(app, ["init", "--root", str(tmp_repo), "--json"])
    assert json.loads(again.output)["files"][".git"] == "exists"


def test_uncommitted_sources_ignores_packages_state_and_generated(
    tmp_repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    for relative in (
        "changes/CHG-x/intent.md",
        ".aisdlc/ledger.sqlite",
        "src/__pycache__/m.cpython-313.pyc",
        "m.pyc",
        ".venv/lib/site.py",
        "src/m.py",
    ):
        _write(tmp_repo, relative)
    (tmp_repo / "README.md").write_text("# modified\n", encoding="utf-8")
    assert cmd_init.uncommitted_sources(tmp_repo) == ["README.md", "src/m.py"]
    # from a subdirectory (``--root sub``) paths inside it are relative to that root
    assert cmd_init.uncommitted_sources(tmp_repo / "src") == ["README.md", "m.py"]
    assert cmd_init.uncommitted_sources(tmp_path_factory.mktemp("plain")) == []


def test_run_refuses_uncommitted_sources_unless_allowed(tmp_repo: Path) -> None:
    make_package(tmp_repo)
    common = ["--root", str(tmp_repo), "--ledger", str(tmp_repo / ".aisdlc" / "ledger.sqlite")]
    _write(tmp_repo, "src/app.py")

    refused = runner.invoke(app, ["run", "change", "CHG-demo", *common, "--yes"])
    assert refused.exit_code == 2, refused.output
    assert refused.output.startswith("error: 1 uncommitted file(s)")
    assert "src/app.py" in refused.output and "start from HEAD" in refused.output
    assert "git add -A && git commit" in refused.output and "--allow-dirty" in refused.output
    assert not (tmp_repo / "TASK-001.dryrun").exists()  # nothing ran

    task = runner.invoke(app, ["run", "task", "TASK-001", "--change", "CHG-demo", *common, "-y"])
    assert task.exit_code == 2 and "src/app.py" in task.output

    allowed = runner.invoke(
        app, ["run", "change", "CHG-demo", *common, "--yes", "--allow-dirty", "--json"]
    )
    assert allowed.exit_code == 0, allowed.output
    assert json.loads(allowed.output)["outcome"] == "success"

    # a dirty change package and generated artefacts never block a (resumed) run
    _git(tmp_repo, "add", "-A")
    _git(tmp_repo, "commit", "-q", "-m", "baseline")
    _write(tmp_repo, "src/__pycache__/app.cpython-313.pyc")
    _write(tmp_repo, "changes/CHG-demo/notes.md", "work in progress\n")
    clean = runner.invoke(app, ["run", "change", "CHG-demo", *common, "--yes"])
    assert clean.exit_code == 0, clean.output

    # more than five files: the message is truncated, the count is exact
    for index in range(7):
        _write(tmp_repo, f"src/extra{index}.py")
    many = runner.invoke(app, ["run", "change", "CHG-demo", *common, "--yes"])
    assert many.exit_code == 2 and "7 uncommitted file(s)" in many.output
    assert "(+2 more)" in many.output
