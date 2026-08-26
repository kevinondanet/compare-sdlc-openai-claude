"""Git worktree isolation: one worktree and branch per task (``aisdlc/<change>/<task>``).

The :class:`WorktreeManager` creates, lists and removes worktrees, commits an agent's
work, summarises the diff against the base commit (numstat + unified patch, optionally
scoped to paths) and applies a task branch back onto the repository's current branch by
merge or cherry-pick with conflict reporting (the merge is aborted on conflict, leaving
the repository clean). Everything shells out to ``git``; no network is involved.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "WorktreeError",
    "FileChange",
    "DiffSummary",
    "WorktreeInfo",
    "ApplyResult",
    "branch_name",
    "WorktreeManager",
]

BRANCH_PREFIX = "aisdlc"
DEFAULT_WORKTREES_DIR = Path(".aisdlc") / "worktrees"


class WorktreeError(RuntimeError):
    """A git operation failed."""


class FileChange(BaseModel):
    """One file in a diff."""

    model_config = ConfigDict(extra="forbid")

    path: str
    status: str = Field(default="M", description="A(dded) | M(odified) | D(eleted) | R(enamed)")
    additions: int = 0
    deletions: int = 0


class DiffSummary(BaseModel):
    """Diff of a branch against its base."""

    model_config = ConfigDict(extra="forbid")

    base: str
    head: str
    files: list[FileChange] = Field(default_factory=list)
    patch: str = ""
    paths: list[str] = Field(default_factory=list, description="Scope filter, if any.")

    @property
    def additions(self) -> int:
        """Total added lines."""
        return sum(f.additions for f in self.files)

    @property
    def deletions(self) -> int:
        """Total deleted lines."""
        return sum(f.deletions for f in self.files)

    @property
    def file_paths(self) -> list[str]:
        """Paths touched by the diff."""
        return [f.path for f in self.files]

    @property
    def empty(self) -> bool:
        """True when nothing changed."""
        return not self.files


class WorktreeInfo(BaseModel):
    """A task worktree."""

    model_config = ConfigDict(extra="forbid")

    path: str
    branch: str
    base_sha: str
    change_id: str = ""
    task_id: str = ""
    head_sha: str = ""

    @property
    def directory(self) -> Path:
        """Worktree path."""
        return Path(self.path)


class ApplyResult(BaseModel):
    """Outcome of applying a task branch back onto the target branch."""

    model_config = ConfigDict(extra="forbid")

    ok: bool
    strategy: str
    branch: str
    target: str
    conflicts: list[str] = Field(default_factory=list)
    message: str = ""
    commit: str = ""
    applied_commits: int = 0


def branch_name(change_id: str, task_id: str) -> str:
    """``aisdlc/<change>/<task>``."""
    return f"{BRANCH_PREFIX}/{change_id}/{task_id}"


class WorktreeManager:
    """Create and manage per-task git worktrees under ``<repo>/.aisdlc/worktrees``.

    Operations that mutate repository-level state (worktree add/remove, apply-back) are
    serialised with a re-entrant lock so parallel task workers never race on ``.git``.
    """

    def __init__(
        self,
        repo_root: str | Path,
        *,
        worktrees_dir: str | Path | None = None,
        git: str = "git",
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.worktrees_dir = (
            Path(worktrees_dir).resolve()
            if worktrees_dir is not None
            else self.repo_root / DEFAULT_WORKTREES_DIR
        )
        self.git_executable = git
        self._lock = threading.RLock()
        if not (self.repo_root / ".git").exists():
            raise WorktreeError(f"not a git repository: {self.repo_root}")
        self._ensure_excluded()

    # ------------------------------------------------------------------ git plumbing
    def git(
        self,
        *args: str,
        cwd: str | Path | None = None,
        check: bool = True,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run ``git`` in ``cwd`` (default: the repository root)."""
        proc = subprocess.run(
            [self.git_executable, *args],
            cwd=str(cwd or self.repo_root),
            capture_output=True,
            text=True,
            input=input_text,
            check=False,
        )
        if check and proc.returncode != 0:
            raise WorktreeError(
                f"git {' '.join(args)} failed ({proc.returncode}): "
                f"{(proc.stderr or proc.stdout).strip()}"
            )
        return proc

    def _ensure_excluded(self) -> None:
        """Keep the worktrees directory out of ``git status`` when it lives in the repo."""
        try:
            self.worktrees_dir.relative_to(self.repo_root)
        except ValueError:
            return
        git_dir = self.repo_root / ".git"
        if not git_dir.is_dir():
            return
        exclude = git_dir / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        rel = self.worktrees_dir.relative_to(self.repo_root).as_posix()
        line = f"/{rel.split('/')[0]}/"
        existing = exclude.read_text(encoding="utf-8") if exclude.is_file() else ""
        if line not in existing.splitlines():
            with exclude.open("a", encoding="utf-8") as fh:
                fh.write(("" if existing.endswith("\n") or not existing else "\n") + line + "\n")

    def rev_parse(self, ref: str = "HEAD", cwd: str | Path | None = None) -> str:
        """Resolve ``ref`` to a commit sha."""
        return self.git("rev-parse", "--verify", f"{ref}^{{commit}}", cwd=cwd).stdout.strip()

    def head_sha(self, cwd: str | Path | None = None) -> str:
        """HEAD of ``cwd`` (default repository root)."""
        return self.rev_parse("HEAD", cwd=cwd)

    def current_branch(self, cwd: str | Path | None = None) -> str:
        """Current branch name (or ``HEAD`` when detached)."""
        return self.git("rev-parse", "--abbrev-ref", "HEAD", cwd=cwd).stdout.strip()

    def branch_exists(self, branch: str) -> bool:
        """Whether a local branch exists."""
        proc = self.git("show-ref", "--verify", "--quiet", f"refs/heads/{branch}", check=False)
        return proc.returncode == 0

    def is_clean(self, cwd: str | Path | None = None) -> bool:
        """Whether the working tree has no uncommitted or untracked changes."""
        return not self.git("status", "--porcelain", cwd=cwd).stdout.strip()

    # ------------------------------------------------------------------ worktrees
    def worktree_path(self, change_id: str, task_id: str) -> Path:
        """Deterministic worktree location for a task."""
        return self.worktrees_dir / change_id / task_id

    def create(self, change_id: str, task_id: str, *, base: str | None = None) -> WorktreeInfo:
        """Create (or reuse) the worktree and branch for ``task_id``.

        The branch is created from ``base`` (default: the repository HEAD). An existing
        branch is reused without resetting it, so a resumed run keeps prior commits.
        """
        branch = branch_name(change_id, task_id)
        path = self.worktree_path(change_id, task_id)
        with self._lock:
            base_sha = self.rev_parse(base or "HEAD")
            existing = self._find(path=path)
            if existing is not None:
                return existing.model_copy(
                    update={
                        "change_id": change_id,
                        "task_id": task_id,
                        "base_sha": self._merge_base(branch, base_sha) or base_sha,
                        "head_sha": self.head_sha(path),
                    }
                )
            path.parent.mkdir(parents=True, exist_ok=True)
            if self.branch_exists(branch):
                self.git("worktree", "add", str(path), branch)
                base_sha = self._merge_base(branch, base_sha) or base_sha
            else:
                self.git("worktree", "add", "-b", branch, str(path), base_sha)
            return WorktreeInfo(
                path=str(path),
                branch=branch,
                base_sha=base_sha,
                change_id=change_id,
                task_id=task_id,
                head_sha=self.head_sha(path),
            )

    def _merge_base(self, branch: str, other: str) -> str | None:
        proc = self.git("merge-base", branch, other, check=False)
        return proc.stdout.strip() or None if proc.returncode == 0 else None

    def _find(self, *, path: Path | None = None, branch: str | None = None) -> WorktreeInfo | None:
        for info in self.list_worktrees():
            if path is not None and Path(info.path) == path.resolve():
                return info
            if branch is not None and info.branch == branch:
                return info
        return None

    def list_worktrees(self) -> list[WorktreeInfo]:
        """Worktrees registered on the repository (excluding the main worktree)."""
        out = self.git("worktree", "list", "--porcelain").stdout
        infos: list[WorktreeInfo] = []
        current: dict[str, str] = {}
        blocks = [b for b in out.strip().split("\n\n") if b.strip()]
        for block in blocks:
            current = {}
            for line in block.splitlines():
                key, _, value = line.partition(" ")
                current[key] = value
            path = Path(current.get("worktree", "")).resolve()
            if not current.get("worktree") or path == self.repo_root:
                continue
            branch = current.get("branch", "").removeprefix("refs/heads/")
            change_id, task_id = "", ""
            parts = branch.split("/")
            if len(parts) == 3 and parts[0] == BRANCH_PREFIX:
                change_id, task_id = parts[1], parts[2]
            infos.append(
                WorktreeInfo(
                    path=str(path),
                    branch=branch or "HEAD",
                    base_sha=current.get("HEAD", ""),
                    head_sha=current.get("HEAD", ""),
                    change_id=change_id,
                    task_id=task_id,
                )
            )
        return infos

    def remove(
        self, target: WorktreeInfo | str | Path, *, delete_branch: bool = False, force: bool = True
    ) -> None:
        """Remove a worktree (and optionally its branch); tolerant of already-removed trees."""
        path = Path(target.path) if isinstance(target, WorktreeInfo) else Path(target)
        branch = target.branch if isinstance(target, WorktreeInfo) else None
        args = ["worktree", "remove"]
        if force:
            args.append("--force")
        with self._lock:
            proc = self.git(*args, str(path), check=False)
            if proc.returncode != 0 and path.exists():
                raise WorktreeError(f"could not remove worktree {path}: {proc.stderr.strip()}")
            self.git("worktree", "prune", check=False)
            if delete_branch and branch and self.branch_exists(branch):
                self.git("branch", "-D", branch)

    def cleanup(self, change_id: str, *, delete_branches: bool = False) -> list[str]:
        """Remove every worktree of ``change_id``; returns the removed branch names."""
        removed: list[str] = []
        for info in self.list_worktrees():
            if info.change_id == change_id:
                self.remove(info, delete_branch=delete_branches)
                removed.append(info.branch)
        return removed

    # ------------------------------------------------------------------ changes
    def commit_all(self, info: WorktreeInfo, message: str) -> str | None:
        """Stage and commit everything in the worktree; returns the sha or ``None`` if clean."""
        self.git("add", "-A", cwd=info.path)
        staged = self.git("diff", "--cached", "--quiet", cwd=info.path, check=False)
        if staged.returncode == 0:
            return None
        self.git(
            "-c",
            "user.email=aisdlc@localhost",
            "-c",
            "user.name=aisdlc",
            "commit",
            "-q",
            "-m",
            message,
            cwd=info.path,
        )
        sha = self.head_sha(info.path)
        info.head_sha = sha
        return sha

    def changed_files(self, info: WorktreeInfo) -> list[str]:
        """Uncommitted (tracked or untracked) files in the worktree."""
        out = self.git("status", "--porcelain", "--untracked-files=all", cwd=info.path).stdout
        files: list[str] = []
        for line in out.splitlines():
            if len(line) > 3:
                files.append(line[3:].split(" -> ")[-1].strip())
        return files

    def diff(
        self,
        info: WorktreeInfo,
        *,
        base: str | None = None,
        head: str | None = None,
        paths: list[str] | None = None,
    ) -> DiffSummary:
        """Diff summary between ``base`` (default the worktree base) and ``head`` (HEAD)."""
        return self.diff_between(base or info.base_sha, head or "HEAD", cwd=info.path, paths=paths)

    def diff_between(
        self,
        base: str,
        head: str = "HEAD",
        *,
        cwd: str | Path | None = None,
        paths: list[str] | None = None,
    ) -> DiffSummary:
        """Diff summary between two commits in ``cwd`` (default repository root)."""
        base_sha = self.rev_parse(base, cwd=cwd)
        head_sha = self.rev_parse(head, cwd=cwd)
        scope = ["--", *paths] if paths else []
        numstat = self.git("diff", "--numstat", base_sha, head_sha, *scope, cwd=cwd).stdout
        status = self.git("diff", "--name-status", base_sha, head_sha, *scope, cwd=cwd).stdout
        patch = self.git("diff", "--no-color", base_sha, head_sha, *scope, cwd=cwd).stdout
        statuses: dict[str, str] = {}
        for line in status.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                statuses[parts[-1]] = parts[0][:1]
        files: list[FileChange] = []
        for line in numstat.splitlines():
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            add, dele, path = parts
            files.append(
                FileChange(
                    path=path,
                    status=statuses.get(path, "M"),
                    additions=int(add) if add.isdigit() else 0,
                    deletions=int(dele) if dele.isdigit() else 0,
                )
            )
        return DiffSummary(
            base=base_sha, head=head_sha, files=files, patch=patch, paths=list(paths or [])
        )

    # ------------------------------------------------------------------ apply back
    def apply_back(
        self,
        info: WorktreeInfo,
        *,
        strategy: str = "merge",
        target: str | None = None,
        message: str | None = None,
    ) -> ApplyResult:
        """Apply the task branch onto ``target`` (default: the current branch) in the repo.

        ``strategy`` is ``merge`` (``--no-ff``) or ``cherry-pick`` (each commit since the
        base). On conflict the operation is aborted, the repository is left as it was, and
        the conflicting paths are reported.
        """
        if strategy not in {"merge", "cherry-pick"}:
            raise WorktreeError(f"unknown apply strategy {strategy!r}")
        with self._lock:
            return self._apply_back_locked(info, strategy=strategy, target=target, message=message)

    def _apply_back_locked(
        self,
        info: WorktreeInfo,
        *,
        strategy: str,
        target: str | None,
        message: str | None,
    ) -> ApplyResult:
        current = self.current_branch()
        target_branch = target or current
        if target_branch != current:
            self.git("checkout", "-q", target_branch)
        head = self.head_sha(info.path)
        base = self._merge_base(info.branch, target_branch) or info.base_sha
        commits = [
            c for c in self.git("rev-list", "--reverse", f"{base}..{head}").stdout.split() if c
        ]
        if not commits:
            return ApplyResult(
                ok=True,
                strategy=strategy,
                branch=info.branch,
                target=target_branch,
                message="nothing to apply",
                commit=self.head_sha(),
            )
        identity = ["-c", "user.email=aisdlc@localhost", "-c", "user.name=aisdlc"]
        if strategy == "merge":
            msg = message or f"Merge {info.branch} ({info.task_id or 'task'})"
            proc = self.git(*identity, "merge", "--no-ff", "-m", msg, head, check=False)
            if proc.returncode != 0:
                conflicts = self._conflicts()
                self.git("merge", "--abort", check=False)
                return ApplyResult(
                    ok=False,
                    strategy=strategy,
                    branch=info.branch,
                    target=target_branch,
                    conflicts=conflicts,
                    message=(proc.stderr or proc.stdout).strip(),
                )
        else:
            proc = self.git(*identity, "cherry-pick", *commits, check=False)
            if proc.returncode != 0:
                conflicts = self._conflicts()
                self.git("cherry-pick", "--abort", check=False)
                return ApplyResult(
                    ok=False,
                    strategy=strategy,
                    branch=info.branch,
                    target=target_branch,
                    conflicts=conflicts,
                    message=(proc.stderr or proc.stdout).strip(),
                )
        return ApplyResult(
            ok=True,
            strategy=strategy,
            branch=info.branch,
            target=target_branch,
            message=f"applied {len(commits)} commit(s)",
            commit=self.head_sha(),
            applied_commits=len(commits),
        )

    def _conflicts(self) -> list[str]:
        out = self.git("diff", "--name-only", "--diff-filter=U", check=False).stdout
        return [line.strip() for line in out.splitlines() if line.strip()]
