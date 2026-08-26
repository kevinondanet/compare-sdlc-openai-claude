"""Helpers shared by the ``aisdlc`` CLI modules.

Not a subcommand module (no ``NAME``/``app``), so :mod:`aisdlc.cli.main` never mounts it.

Every command that takes a change package accepts either a directory (holding
``intent.md``) or a bare ``CHG-<slug>`` id; ids are looked up under ``changes/`` in the
current directory and then in each parent directory, so ``aisdlc gate evaluate
CHG-demo`` works from anywhere inside the repository.
"""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from aisdlc import ids
from aisdlc.policy import merge as policy_merge
from aisdlc.policy import org_policy as orgmod
from aisdlc.policy import project_config as projmod
from aisdlc.schema import package as pkgio
from aisdlc.schema.models import ChangePackage

__all__ = [
    "EXIT_LOAD_ERROR",
    "resolve_package_dir",
    "package_arg",
    "optional_package_arg",
    "repo_root_for",
    "load_package",
    "load_effective_policy",
    "hmac_key_file",
    "read_hmac_key_file",
    "concise_validation_error",
]

EXIT_LOAD_ERROR = 2
SIGNING_KEY_FILE = Path(".aisdlc") / "signing.key"


def _is_package(directory: Path) -> bool:
    return (directory / pkgio.INTENT_FILE).is_file()


def resolve_package_dir(ref: str | Path, root: Path | None = None) -> Path:
    """Resolve *ref* (directory or ``CHG-<slug>`` id) to a change package directory.

    Resolution order: *ref* as a directory; ``<root>/changes/<ref>`` when *root* is given;
    otherwise ``changes/<ref>`` under the current directory and then under each parent.
    When nothing exists the most likely path is returned so that the caller's error
    message names it (``changes/<id>`` for a valid id, *ref* itself otherwise).
    """
    candidate = Path(ref)
    if _is_package(candidate):
        return candidate
    name = str(ref)
    bare_id = candidate.parent == Path(".") and ids.is_valid("CHG", name)
    if not bare_id:
        return candidate
    if root is not None:
        return root / pkgio.CHANGES_DIR / name
    cwd = Path.cwd()
    local = Path(pkgio.CHANGES_DIR) / name
    if _is_package(cwd / local):
        return local
    for base in cwd.parents:
        hit = base / pkgio.CHANGES_DIR / name
        if _is_package(hit):
            return hit
    return local


def package_arg(value: Path) -> Path:
    """Typer argument callback: resolve a package reference (see :func:`resolve_package_dir`)."""
    return resolve_package_dir(value)


def optional_package_arg(value: Path | None) -> Path | None:
    """Typer callback for optional package arguments/options."""
    return None if value is None else resolve_package_dir(value)


def repo_root_for(package_dir: Path) -> Path:
    """Repository root that holds ``changes/<id>``; the current directory otherwise."""
    resolved = package_dir.resolve()
    if resolved.parent.name == pkgio.CHANGES_DIR:
        return resolved.parent.parent
    return Path(".")


def load_package(ref: str | Path, root: Path | None = None) -> ChangePackage:
    """Load the package behind *ref*; exit 2 with a message when it is not one."""
    directory = resolve_package_dir(ref, root)
    try:
        return pkgio.load(directory)
    except pkgio.PackageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc


def load_effective_policy(
    root: Path, org: Path | None = None, project: Path | None = None
) -> policy_merge.EffectivePolicy:
    """Effective (narrow-merged) policy from explicit paths or files discovered under *root*."""
    org_path = org if org is not None else orgmod.find_org_policy(root)
    project_path = project if project is not None else projmod.find_project_config(root)
    try:
        org_policy = orgmod.load_org_policy(org_path) if org_path else orgmod.default_org_policy()
        project_config = (
            projmod.load_project_config(project_path)
            if project_path
            else projmod.default_project_config()
        )
    except orgmod.PolicyLoadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=EXIT_LOAD_ERROR) from exc
    return policy_merge.effective_policy(org_policy, project_config)


def hmac_key_file(root: Path) -> Path:
    """Location of the local HMAC signing key written by ``aisdlc init``."""
    return root / SIGNING_KEY_FILE


def read_hmac_key_file(root: Path) -> bytes | None:
    """Bytes of the local signing key when present (hex is decoded), else ``None``."""
    path = hmac_key_file(root)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return text.encode("utf-8")


def concise_validation_error(exc: ValidationError, limit: int = 3) -> str:
    """One line ``field.path: message`` for the first *limit* errors of a pydantic failure.

    Commands that load user files print this after ``error: <path>: `` instead of pydantic's
    multi-line report (which reads like a traceback on a terminal).
    """
    parts: list[str] = []
    for err in exc.errors()[:limit]:
        loc = ".".join(str(item) for item in err.get("loc", ()))
        parts.append(f"{loc}: {err['msg']}" if loc else str(err["msg"]))
    extra = exc.error_count() - len(parts)
    return "; ".join(parts) + (f" (+{extra} more)" if extra > 0 else "")
