"""The runtime of a generated application: submissions, the table and a generic CLI."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lowcode.schema import FormSpec, ValidationError
from lowcode.table import Table


class SubmissionsClosed(ValueError):
    """The cut-off has passed for the current period."""


class FormApp:
    """Submissions against a :class:`FormSpec`, stored in a :class:`Table`."""

    def __init__(
        self,
        spec: FormSpec,
        *,
        rows: Sequence[dict[str, Any]] = (),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.spec = spec
        self.table = Table(spec.columns, rows)
        self._clock = clock or (lambda: datetime.now(tz=UTC))

    def is_open(self, now: datetime | None = None) -> bool:
        """Whether submissions are currently accepted."""
        moment = now or self._clock()
        return self.spec.cutoff is None or self.spec.cutoff.is_open(moment)

    def submit(self, values: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        """Validate and store one submission; returns the stored row.

        Raises :class:`SubmissionsClosed` after the cut-off and :class:`ValidationError`
        for invalid values (nothing is stored in either case).
        """
        moment = now or self._clock()
        cutoff = self.spec.cutoff
        if cutoff is not None and not cutoff.is_open(moment):
            raise SubmissionsClosed(
                f"submissions closed at {cutoff.describe()}; try again tomorrow"
            )
        cleaned = self.spec.validate(values)
        return self.table.add(cleaned, submitted_at=moment)

    def rows(self) -> list[dict[str, Any]]:
        """Every stored submission."""
        return self.table.rows()

    def export_csv(self) -> str:
        """The table as CSV."""
        return self.table.export_csv()


# --------------------------------------------------------------------------------------
# Generic command line (persisted through a JSON store so it works across processes)
# --------------------------------------------------------------------------------------


def build_parser(spec: FormSpec) -> argparse.ArgumentParser:
    """An argparse parser derived from the form: ``submit --<field> …``, ``list``, ``export``."""
    parser = argparse.ArgumentParser(prog=spec.slug, description=spec.title)
    parser.add_argument("--store", default=f"{spec.slug}.json", help="JSON file with the table.")
    parser.add_argument("--now", help="ISO timestamp used as the submission time (tests).")
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit", help="Submit the form.")
    for item in spec.fields:
        submit.add_argument(f"--{item.name}", required=False, help=f"{item.type} field")
    sub.add_parser("list", help="Print every submission as JSON.")
    sub.add_parser("export", help="Print the table as CSV.")
    return parser


def load_app(spec: FormSpec, store: Path) -> FormApp:
    """Rebuild the application from its JSON store (empty when the file is missing)."""
    rows = json.loads(store.read_text(encoding="utf-8")) if store.exists() else []
    return FormApp(spec, rows=rows)


def save_app(app: FormApp, store: Path) -> None:
    """Persist the application's table."""
    store.write_text(json.dumps(app.rows(), indent=2) + "\n", encoding="utf-8")


def main(spec: FormSpec, argv: Sequence[str] | None = None) -> int:
    """Run the generic CLI for *spec*; exit 0 ok, 2 invalid input or closed submissions."""
    parser = build_parser(spec)
    args = parser.parse_args(argv)
    store = Path(args.store)
    app = load_app(spec, store)
    now = datetime.fromisoformat(args.now) if args.now else None
    try:
        if args.command == "submit":
            values = {f.name: getattr(args, f.name) for f in spec.fields}
            row = app.submit(values, now=now)
            save_app(app, store)
            print(json.dumps(row))
        elif args.command == "list":
            print(json.dumps(app.rows()))
        elif args.command == "export":
            sys.stdout.write(app.export_csv())
    except (ValidationError, SubmissionsClosed) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
