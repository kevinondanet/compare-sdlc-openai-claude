"""``python -m assistant "<message>"`` — one governed turn, reply on stdout."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from assistant.agent import build_assistant


def main(argv: Sequence[str] | None = None) -> int:
    """Answer one message; exit 0."""
    parser = argparse.ArgumentParser(prog="assistant")
    parser.add_argument("message")
    parser.add_argument("--audit-log", help="Signed JSON-lines audit log (default: in memory).")
    args = parser.parse_args(argv)
    assistant = build_assistant(audit_log=args.audit_log, session_id="cli")
    try:
        print(assistant.respond(args.message))
    finally:
        assistant.governance.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
