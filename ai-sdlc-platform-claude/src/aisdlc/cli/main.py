"""Typer application root.

Subcommands are auto-discovered: every module ``aisdlc.cli.cmd_<name>`` that exposes a
module-level ``app: typer.Typer`` and ``NAME: str`` is mounted as ``aisdlc <NAME>``.
Implementers add a new ``cmd_*.py`` file and never edit this module.
"""

from __future__ import annotations

import importlib
import pkgutil

import typer

from aisdlc import __version__

app = typer.Typer(
    name="aisdlc",
    help="AI-SDLC platform: canonical change artifacts, governed orchestration, gates, control plane.",
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"aisdlc {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True, help="Show version."
    ),
) -> None:
    """AI-SDLC platform CLI."""


def _discover() -> None:
    import aisdlc.cli as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        if not mod.name.startswith("cmd_"):
            continue
        module = importlib.import_module(f"aisdlc.cli.{mod.name}")
        sub = getattr(module, "app", None)
        name = getattr(module, "NAME", None)
        if isinstance(sub, typer.Typer) and isinstance(name, str):
            app.add_typer(sub, name=name)


_discover()


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
