"""Health endpoint: dependency checks with a hard timeout, JSON body, 200/503."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

CHECK_TIMEOUT_SECONDS = 2.0

Check = Callable[[], bool]


def run_checks(
    checks: dict[str, Check], *, timeout: float = CHECK_TIMEOUT_SECONDS
) -> dict[str, str]:
    """Run every check with a timeout; a slow or failing check reports ``"fail"``."""
    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, len(checks))) as pool:
        futures = {name: pool.submit(check) for name, check in checks.items()}
        for name, future in futures.items():
            try:
                results[name] = "ok" if future.result(timeout=timeout) else "fail"
            except (FutureTimeout, Exception):  # noqa: BLE001 - a failing check is a result
                results[name] = "fail"
    return results


def health_status(checks: dict[str, Check]) -> tuple[int, dict[str, Any]]:
    """``(http_status, body)`` for ``GET /health``."""
    results = run_checks(checks)
    failing = sorted(name for name, state in results.items() if state != "ok")
    status = 503 if failing else 200
    return status, {"status": "fail" if failing else "ok", "checks": results, "failing": failing}


def make_app(
    checks: dict[str, Check],
) -> Callable[[dict[str, Any], Callable[..., Any]], Iterable[bytes]]:
    """Minimal WSGI application serving ``/health``."""

    def application(environ: dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        if environ.get("PATH_INFO") != "/health" or environ.get("REQUEST_METHOD") != "GET":
            start_response("404 Not Found", [("Content-Type", "application/json")])
            return [b'{"error": "not found"}']
        code, body = health_status(checks)
        reason = {200: "OK", 503: "Service Unavailable"}[code]
        payload = json.dumps(body, sort_keys=True).encode()
        start_response(f"{code} {reason}", [("Content-Type", "application/json")])
        return [payload]

    return application
