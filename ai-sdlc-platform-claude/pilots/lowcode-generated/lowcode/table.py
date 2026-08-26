"""The table behind a form: rows with ids and timestamps, CSV export."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable
from datetime import datetime
from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection: prefix dangerous leading characters."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


class Table:
    """An append-only table with ``id`` and ``submitted_at`` system columns."""

    SYSTEM_COLUMNS: tuple[str, ...] = ("id", "submitted_at")

    def __init__(self, columns: Iterable[str], rows: Iterable[dict[str, Any]] = ()) -> None:
        self.columns = tuple(columns)
        self._rows: list[dict[str, Any]] = []
        for row in rows:
            self._rows.append(dict(row))

    @property
    def header(self) -> tuple[str, ...]:
        """System columns followed by the form columns."""
        return (*self.SYSTEM_COLUMNS, *self.columns)

    def add(self, values: dict[str, Any], *, submitted_at: datetime) -> dict[str, Any]:
        """Append a validated row and return the stored record."""
        record = {
            "id": len(self._rows) + 1,
            "submitted_at": submitted_at.isoformat(timespec="seconds"),
            **{name: values.get(name) for name in self.columns},
        }
        self._rows.append(record)
        return dict(record)

    def rows(self) -> list[dict[str, Any]]:
        """All rows in submission order."""
        return [dict(r) for r in self._rows]

    def __len__(self) -> int:
        return len(self._rows)

    def export_csv(self) -> str:
        """CSV text with a header row; cell values are formula-injection safe."""
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(self.header)
        for row in self._rows:
            writer.writerow([csv_safe(row.get(name, "")) for name in self.header])
        return buffer.getvalue()
