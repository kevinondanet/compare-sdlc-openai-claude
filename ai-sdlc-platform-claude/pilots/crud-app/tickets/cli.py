"""Command-line interface over :class:`tickets.service.TicketService` with a JSON store.

Exit codes: 0 ok, 1 not found, 2 invalid input (argparse convention).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from tickets.service import DEFAULT_PRIORITY, PRIORITIES, STATUSES, TicketService


def _load(store: Path) -> TicketService:
    if not store.exists():
        return TicketService()
    return TicketService.from_rows(json.loads(store.read_text(encoding="utf-8")))


def _save(store: Path, service: TicketService) -> None:
    store.write_text(json.dumps(service.to_rows(), indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """The ``tickets`` argument parser (IFC-001)."""
    parser = argparse.ArgumentParser(prog="tickets", description="Manage support tickets.")
    parser.add_argument("--store", default="tickets.json", help="JSON file holding the tickets.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="Create a ticket.")
    create.add_argument("title")
    create.add_argument(
        "--priority",
        default=DEFAULT_PRIORITY,
        help=f"One of {', '.join(PRIORITIES)} (default {DEFAULT_PRIORITY}).",
    )

    listing = sub.add_parser("list", help="List tickets.")
    listing.add_argument("--status", choices=STATUSES)
    listing.add_argument("--sort", choices=("created", "priority"), default="created")

    get = sub.add_parser("get", help="Show one ticket.")
    get.add_argument("id", type=int)

    update = sub.add_parser("update", help="Update a ticket.")
    update.add_argument("id", type=int)
    update.add_argument("--title")
    update.add_argument("--status", choices=STATUSES)
    update.add_argument("--priority")

    delete = sub.add_parser("delete", help="Delete a ticket.")
    delete.add_argument("id", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; returns the exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    store = Path(args.store)
    service = _load(store)
    try:
        if args.command == "create":
            ticket = service.create(args.title, priority=args.priority)
            _save(store, service)
            print(json.dumps(ticket.to_dict()))
        elif args.command == "list":
            rows = [t.to_dict() for t in service.list(status=args.status, sort=args.sort)]
            print(json.dumps(rows))
        elif args.command == "get":
            print(json.dumps(service.get(args.id).to_dict()))
        elif args.command == "update":
            ticket = service.update(
                args.id, title=args.title, status=args.status, priority=args.priority
            )
            _save(store, service)
            print(json.dumps(ticket.to_dict()))
        elif args.command == "delete":
            service.delete(args.id)
            _save(store, service)
            print(json.dumps({"deleted": args.id}))
    except KeyError as exc:
        print(f"error: {exc.args[0]}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through ``python -m tickets``
    sys.exit(main())
