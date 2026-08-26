"""Shared pytest fixtures. Tests must never touch the network."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("AISDLC_ENV", "test")


@pytest.fixture
def tmp_repo(tmp_path: Path) -> Path:
    """An empty git repository for tests needing git (worktrees, fingerprints)."""
    import subprocess

    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"], check=True
    )
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "test"], check=True)
    (tmp_path / "README.md").write_text("# test\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    return tmp_path
