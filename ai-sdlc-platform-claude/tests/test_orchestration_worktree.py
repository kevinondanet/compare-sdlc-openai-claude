"""Git worktree isolation: create/list/remove, diffs, apply-back with conflicts."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aisdlc.orchestration.worktree import WorktreeError, WorktreeManager, branch_name


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def test_branch_name() -> None:
    assert branch_name("CHG-x", "TASK-001") == "aisdlc/CHG-x/TASK-001"


def test_manager_requires_git_repo(tmp_path: Path) -> None:
    with pytest.raises(WorktreeError):
        WorktreeManager(tmp_path)


def test_create_list_commit_diff_remove(tmp_repo: Path) -> None:
    manager = WorktreeManager(tmp_repo)
    info = manager.create("CHG-demo", "TASK-001")
    assert info.branch == "aisdlc/CHG-demo/TASK-001"
    assert Path(info.path) == tmp_repo / ".aisdlc" / "worktrees" / "CHG-demo" / "TASK-001"
    assert info.base_sha == _git(tmp_repo, "rev-parse", "HEAD") == info.head_sha
    assert (Path(info.path) / "README.md").is_file()
    # worktrees dir is excluded from the main tree's status
    assert "/.aisdlc/" in (tmp_repo / ".git" / "info" / "exclude").read_text()
    assert _git(tmp_repo, "status", "--porcelain") == ""

    listed = manager.list_worktrees()
    assert [w.task_id for w in listed] == ["TASK-001"] and listed[0].change_id == "CHG-demo"

    # reuse is idempotent
    again = manager.create("CHG-demo", "TASK-001")
    assert again.path == info.path and again.branch == info.branch

    assert manager.commit_all(info, "empty") is None
    (Path(info.path) / "new.txt").write_text("one\ntwo\n")
    (Path(info.path) / "README.md").write_text("# test\nmore\n")
    assert manager.changed_files(info) == ["README.md", "new.txt"]
    sha = manager.commit_all(info, "TASK-001: work")
    assert sha and sha == info.head_sha and manager.changed_files(info) == []

    diff = manager.diff(info)
    assert diff.base == info.base_sha and diff.head == sha
    assert {f.path: f.status for f in diff.files} == {"README.md": "M", "new.txt": "A"}
    assert diff.additions == 3 and diff.deletions == 0 and not diff.empty
    assert "+++ b/new.txt" in diff.patch and "@@ -0,0 +1,2 @@" in diff.patch
    scoped = manager.diff(info, paths=["new.txt"])
    assert scoped.file_paths == ["new.txt"] and scoped.paths == ["new.txt"]

    manager.remove(info)
    assert manager.list_worktrees() == [] and not Path(info.path).exists()
    assert manager.branch_exists(info.branch)
    manager.remove(info, delete_branch=True)  # tolerant of an already removed tree
    assert not manager.branch_exists(info.branch)


def test_apply_back_merge_and_cherry_pick(tmp_repo: Path) -> None:
    manager = WorktreeManager(tmp_repo)
    info = manager.create("CHG-demo", "TASK-001")
    nothing = manager.apply_back(info)
    assert nothing.ok and nothing.message == "nothing to apply" and nothing.applied_commits == 0

    (Path(info.path) / "a.txt").write_text("a\n")
    manager.commit_all(info, "add a")
    result = manager.apply_back(info, strategy="merge")
    assert result.ok and result.applied_commits == 1 and result.target == "main"
    assert (tmp_repo / "a.txt").read_text() == "a\n"
    assert "Merge" in _git(tmp_repo, "log", "-1", "--pretty=%s")

    info2 = manager.create("CHG-demo", "TASK-002")
    (Path(info2.path) / "b.txt").write_text("b\n")
    manager.commit_all(info2, "add b")
    (Path(info2.path) / "c.txt").write_text("c\n")
    manager.commit_all(info2, "add c")
    picked = manager.apply_back(info2, strategy="cherry-pick")
    assert picked.ok and picked.applied_commits == 2
    assert (tmp_repo / "b.txt").is_file() and (tmp_repo / "c.txt").is_file()
    assert _git(tmp_repo, "log", "-1", "--pretty=%s") == "add c"

    with pytest.raises(WorktreeError):
        manager.apply_back(info2, strategy="rebase")


def test_apply_back_reports_conflicts_and_aborts(tmp_repo: Path) -> None:
    manager = WorktreeManager(tmp_repo)
    info = manager.create("CHG-demo", "TASK-001")
    (Path(info.path) / "README.md").write_text("# branch version\n")
    manager.commit_all(info, "branch edit")
    (tmp_repo / "README.md").write_text("# main version\n")
    _git(tmp_repo, "commit", "-qam", "main edit")
    head_before = _git(tmp_repo, "rev-parse", "HEAD")
    for strategy in ("merge", "cherry-pick"):
        result = manager.apply_back(info, strategy=strategy)
        assert not result.ok and result.conflicts == ["README.md"]
        assert _git(tmp_repo, "rev-parse", "HEAD") == head_before
        assert _git(tmp_repo, "status", "--porcelain") == ""  # aborted cleanly
        assert (tmp_repo / "README.md").read_text() == "# main version\n"


def test_cleanup_and_diff_between_in_repo(tmp_repo: Path) -> None:
    manager = WorktreeManager(tmp_repo)
    base = manager.head_sha()
    for tid in ("TASK-001", "TASK-002"):
        info = manager.create("CHG-demo", tid)
        (Path(info.path) / f"{tid}.txt").write_text(tid)
        manager.commit_all(info, tid)
        assert manager.apply_back(info).ok
    other = manager.create("CHG-other", "TASK-001")
    removed = manager.cleanup("CHG-demo", delete_branches=True)
    assert sorted(removed) == ["aisdlc/CHG-demo/TASK-001", "aisdlc/CHG-demo/TASK-002"]
    assert [w.branch for w in manager.list_worktrees()] == [other.branch]
    whole = manager.diff_between(base, "HEAD")
    assert sorted(whole.file_paths) == ["TASK-001.txt", "TASK-002.txt"]
    assert manager.current_branch() == "main"
    assert manager.is_clean()
    with pytest.raises(WorktreeError):
        manager.rev_parse("no-such-ref")


def test_custom_worktrees_dir_outside_repo(tmp_repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "wts"
    manager = WorktreeManager(tmp_repo, worktrees_dir=outside)
    info = manager.create("CHG-demo", "TASK-001")
    assert Path(info.path).is_relative_to(outside)
    manager.remove(info)
