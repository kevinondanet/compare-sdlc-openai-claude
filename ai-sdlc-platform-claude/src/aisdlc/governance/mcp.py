"""MCP gateway configuration and tool-result injection screening.

Tool results, repository files, web content and issue text are untrusted input
(ARCHITECTURE.md §4). :func:`screen_tool_result` detects prompt-injection patterns in
such text before it reaches an agent and produces a sanitised copy; :func:`screened`
wraps any tool callable so its results are screened automatically.

Detected pattern families (see :data:`INJECTION_PATTERNS`):

* instruction overrides ("ignore previous instructions", "disregard the above",
  "new instructions:")
* role impersonation (``system:`` / ``assistant:`` prefixes carrying directives,
  chat-template tokens) and instructions addressed to the agent ("AI assistant: stop ...")
* system-prompt extraction and concealment ("do not tell the user")
* hidden HTML / Markdown comments and invisible Unicode carrying instructions
* base64 / hex blobs that decode to instruction-like text
* exfiltration URLs (secrets in query strings, image beacons, collaborator hosts)
* remote-bootstrap commands (``curl ... | sh``), destructive ``rm -rf`` on system roots
  and credential reads

Text is NFKC-normalised, stripped of zero-width/bidi characters and folded for
Latin-lookalike Cyrillic/Greek letters before matching. Patterns are scoped to
instruction-directed language so ordinary repository content (Markdown headings,
Dockerfiles, YAML keys, chat transcripts) does not trip them; ``severity`` lets callers
block on ``critical`` only.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aisdlc.governance.tiers import Scope


class MCPServerConfig(BaseModel):
    """One MCP server behind the gateway."""

    model_config = ConfigDict(extra="forbid")

    name: str
    command: list[str] = Field(default_factory=list)
    url: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    tool_allowlist: list[str] = Field(default_factory=list)
    scopes: list[Scope] = Field(default_factory=lambda: [Scope.READ])
    timeout_seconds: float = 30.0
    egress_hosts: list[str] = Field(default_factory=list)
    screen_results: bool = True

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
            raise ValueError("server name must be alphanumeric/underscore/dash")
        return value

    def tool_allowed(self, tool: str) -> bool:
        """Whether ``tool`` is on this server's allow-list (empty list = nothing allowed)."""
        return any(_glob_match(pattern, tool) for pattern in self.tool_allowlist)


class MCPGatewayConfig(BaseModel):
    """Gateway configuration: servers, per-server allow-lists, scopes, timeouts, egress."""

    model_config = ConfigDict(extra="forbid")

    servers: list[MCPServerConfig] = Field(default_factory=list)
    default_timeout_seconds: float = 30.0
    max_result_chars: int = 200_000
    screen_results: bool = True
    allowed_egress_hosts: list[str] = Field(default_factory=list)

    def server(self, name: str) -> MCPServerConfig | None:
        """Look up a server by name."""
        return next((s for s in self.servers if s.name == name), None)

    def is_tool_allowed(self, server: str, tool: str) -> bool:
        """Whether ``tool`` on ``server`` may be called through the gateway."""
        cfg = self.server(server)
        return cfg is not None and cfg.tool_allowed(tool)

    def allowed_claude_tools(self) -> list[str]:
        """Claude Code tool names (``mcp__<server>__<tool>``) for exact allow-list entries."""
        names: list[str] = []
        for server in self.servers:
            for tool in server.tool_allowlist:
                if "*" not in tool and "?" not in tool:
                    names.append(f"mcp__{server.name}__{tool}")
        return names

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict form (JSON-serialisable)."""
        return self.model_dump(mode="json")

    def to_json(self, indent: int = 2) -> str:
        """Render the gateway configuration as JSON."""
        return json.dumps(self.to_dict(), indent=indent) + "\n"

    def to_claude_mcp_json(self) -> dict[str, Any]:
        """Render a ``.mcp.json``-style ``mcpServers`` mapping for Claude Code."""
        servers: dict[str, Any] = {}
        for server in self.servers:
            entry: dict[str, Any] = {}
            if server.command:
                entry["command"] = server.command[0]
                entry["args"] = list(server.command[1:])
            if server.url:
                entry["url"] = server.url
            if server.env:
                entry["env"] = dict(server.env)
            servers[server.name] = entry
        return {"mcpServers": servers}

    @classmethod
    def from_json(cls, text: str) -> MCPGatewayConfig:
        """Parse a configuration rendered by :meth:`to_json`."""
        return cls.model_validate(json.loads(text))


def _glob_match(pattern: str, value: str) -> bool:
    regex = "^" + re.escape(pattern).replace("\\*", ".*").replace("\\?", ".") + "$"
    return re.match(regex, value) is not None


# --------------------------------------------------------------------------------------
# Injection screening
# --------------------------------------------------------------------------------------


class Finding(BaseModel):
    """One matched injection pattern."""

    model_config = ConfigDict(extra="forbid")

    pattern: str
    severity: str
    excerpt: str


class ScreeningResult(BaseModel):
    """Result of screening untrusted text."""

    model_config = ConfigDict(extra="forbid")

    suspicious: bool
    patterns: list[str] = Field(default_factory=list)
    severity: str | None = None
    sanitized_text: str
    findings: list[Finding] = Field(default_factory=list)
    truncated: bool = False


_KEYWORDS = (
    r"ignore|disregard|instruction|instructions|system prompt|assistant|you are now|"
    r"execute|run |curl|wget|password|secret|token|api[_ -]?key|credential|exfil|"
    r"send .{0,40}to http|rm -rf|\.ssh|\.env\b|printenv"
)

#: Instruction-directed language that turns a hidden HTML/Markdown comment into a finding
#: (a comment merely mentioning "token" or "password" is documentation, not injection).
_HIDDEN_KEYWORDS = (
    r"\b(?:ignore|disregard|forget|override|bypass|you are now|you must|you should|"
    r"from now on|new instructions?|system prompt|assistant\s*:|system\s*:|execute|run\b|"
    r"curl|wget|exfiltrat\w*|send\b[^\n]{0,40}\bto\s+https?://|rm -rf|\.ssh|\.env\b|reveal|"
    r"print (?:the )?(?:secrets?|tokens?|api[_ -]?keys?|passwords?|env))\b"
)

_OVERRIDE_VERBS = r"(?:ignore|disregard|forget|override|bypass|skip|abandon|drop)"
_QUALIFIER_WORDS = (
    r"previous|prior|above|preceding|earlier|original|initial|system|developer|safety|"
    r"existing|former|old|default"
)
_OVERRIDE_QUALIFIERS = r"(?:" + _QUALIFIER_WORDS + r")"
_OVERRIDE_FILLERS = (
    r"(?:all|any|every|each|of|the|your|these|those|my|our|please|now|completely|entirely|"
    r"totally|" + _QUALIFIER_WORDS + r")"
)
_OVERRIDE_NOUNS = (
    r"(?:instructions?|directions?|directives?|prompts?|rules?|guidelines?|guidance|"
    r"guardrails?|constraints?|context|orders?|messages?|policy|policies|programming|"
    r"training|restrictions?|limitations?|filters?|safeguards?)"
)

#: (id, severity, compiled regex). Order matters for sanitisation (first match wins).
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "instruction_override",
        "critical",
        re.compile(
            r"\b"
            + _OVERRIDE_VERBS
            + r"\b(?:\s+"
            + _OVERRIDE_FILLERS
            + r")*?\s+"
            + _OVERRIDE_QUALIFIERS
            + r"\s+(?:\w+\s+){0,2}?"
            + _OVERRIDE_NOUNS
            + r"\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "critical",
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:all\s+(?:of\s+)?)?"
            r"(?:everything|anything|what(?:ever)?\s+(?:is|was|you)(?:\s+\w+){0,2}|the|that|"
            r"all)?\s*(?:written\s+|said\s+|stated\s+|mentioned\s+)?"
            r"(?:above|before(?:\s+this)?|prior\s+to\s+this|earlier|previously|so\s+far|"
            r"until\s+now|up\s+to\s+now|previous\s+(?:message|text|content|section|turns?))"
            r"(?=[\s,.;:!?)]|$)",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "critical",
        re.compile(
            r"\b(?:ignore|disregard|forget)\s+(?:everything|all|anything|whatever)\s+"
            r"(?:that\s+)?(?:you|i|we)\s+(?:were|have been|know|learned|learnt|read|said|"
            r"wrote|told|was)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "critical",
        re.compile(
            r"(?:^|\n|\s)(?:new|updated|real|actual|true|secret|hidden|revised|override)"
            r"\s+instructions?\s*:|"
            r"(?:^|\n|\s)(?:real|actual|true|secret|hidden)\s+(?:task|objective|goal|mission)\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "high",
        re.compile(
            r"\bfrom now on\b,?\s+(?:you|ignore|disregard|respond|reply|answer|act|behave|"
            r"always|never|only|do not|don't|refuse|pretend)\b",
            re.IGNORECASE,
        ),
    ),
    (
        # ``system:``/``developer:`` lines carrying any directive; a bare YAML key or a
        # transcript line without instruction language is not a finding.
        "role_impersonation",
        "critical",
        re.compile(
            r"(?:^|\n)\s*\[?(?:system|developer|tool|admin|root|sudo)\]?\s*:\s*"
            r"(?=[^\n]*\b(?:ignore|disregard|you are|you must|you should|you will|you now|"
            r"must|never|always|reveal|do not|don't|instructions?|from now on|override|"
            r"execute|run|delete|send|new task|jailbreak|unrestricted|pretend|act as|obey|"
            r"comply|follow|respond|answer|say|write|stop|print|output)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        # ``assistant:`` is a normal transcript line; only strong override language counts.
        "role_impersonation",
        "critical",
        re.compile(
            r"(?:^|\n)\s*\[?assistant\]?\s*:\s*"
            r"(?=[^\n]*\b(?:ignore|disregard|you are now|you must|you will now|reveal|"
            r"from now on|override|new task|jailbreak|unrestricted|pretend|act as|obey|"
            r"do not tell|don't tell)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "role_impersonation",
        "high",
        re.compile(
            r"<\|im_start\|>\s*(?:system|assistant)|<<SYS>>|\[INST\]|\[/INST\]|"
            r"<\s*/?\s*system\s*>|###\s*system\s*(?:prompt|message)\b|"
            r"<\|(?:system|assistant|user)\|>|<\|start_header_id\|>",
            re.IGNORECASE,
        ),
    ),
    (
        "role_impersonation",
        "high",
        re.compile(
            r"\byou are (?:now|no longer)\b[^.\n]{0,80}|"
            r"\bact as (?:an? )?(?:unrestricted|jailbroken|unfiltered|DAN|developer mode)\b|"
            r"\bpretend (?:you are|to be) (?:an? )?(?:unrestricted|"
            r"jailbroken|different)\b|\bthis is (?:your|the) (?:system|developer)\b|"
            r"\benter (?:developer|debug|god|admin) mode\b|\bjailbreak\b",
            re.IGNORECASE,
        ),
    ),
    (
        "addressed_instruction",
        "critical",
        re.compile(
            r"(?:^|\n|[.!?]\s+|[\"'(\[])\s*(?:AI(?:\s+(?:assistant|agent|model|system))?|"
            r"LLM|language model|chatbot|Claude|Copilot|ChatGPT|GPT(?:-\d)?|Gemini|"
            r"(?:hey|dear|attention)\s+(?:assistant|agent|AI|model|bot))\s*[,:]\s*"
            r"(?:stop|halt|delete|remove|erase|wipe|ignore|disregard|push|run|execute|send|"
            r"email|upload|reveal|print|leak|you must|you should|you are|please|now|do not|"
            r"don't|never|always|install|download|open|visit|go to)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "addressed_instruction",
        "critical",
        re.compile(
            r"(?:^|\n|[.!?]\s+|[\"'(\[])\s*(?:assistant|agent|model|bot)\s*[,:]\s*"
            r"(?:stop|halt|delete|remove|erase|wipe|ignore|disregard|reveal|leak|exfiltrate|"
            r"email|upload|you must|do not|don't|never|always)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_extraction",
        "critical",
        re.compile(
            r"\b(?:reveal|print|show|output|display|repeat|recite|leak|dump|disclose|share|"
            r"echo|return|paste|expose)\b(?:\s+\w+){0,3}?\s+(?:the\s+|your\s+|its\s+|this\s+)?"
            r"(?:system|developer|hidden|secret|initial|original|internal|confidential)\s+"
            r"(?:prompt|instructions?|message|configuration|rules)s?\b|"
            r"\b(?:system|developer)\s+prompt\b[^.\n]{0,40}\bverbatim\b|"
            r"\bwhat (?:is|are|were) your (?:system|developer|initial|original|hidden) "
            r"(?:prompt|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "concealment",
        "critical",
        re.compile(
            r"\b(?:do not|don't|never|without|avoid|must not|should not|shouldn't)\s+"
            r"(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|alert(?:ing)?|notify(?:ing)?|"
            r"show(?:ing)?|reveal(?:ing)?|let(?:ting)?|disclos(?:e|ing)|report(?:ing)?|"
            r"warn(?:ing)?)\s+(?:this\s+to\s+|it\s+to\s+|about\s+this\s+to\s+)?(?:the\s+)?"
            r"(?:user|human|operator|owner|developers?|admins?|anyone|anybody)\b|"
            r"\bkeep\s+(?:this|it|these)\s+(?:a\s+)?(?:secret|hidden|confidential|private)"
            r"\s+from\s+(?:the\s+)?(?:user|human|operator|owner)\b|"
            r"\b(?:secretly|silently|quietly|covertly|discreetly)\s+(?:run|execute|delete|"
            r"send|push|install|modify|exfiltrate|upload|commit|change|open)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "hidden_comment",
        "high",
        re.compile(r"<!--[\s\S]*?-->|(?:^|\n)\[[^\]]*\]:\s*#\s*\([^)]*\)", re.IGNORECASE),
    ),
    (
        "exfil_url",
        "critical",
        re.compile(
            r"https?://[^\s<>\"')]+[?&#][^\s<>\"')]*(?:token|secret|password|passwd|api[_-]?key|"
            r"apikey|auth|credential|cookie|session|private[_-]?key)=[^\s<>\"')&]*",
            re.IGNORECASE,
        ),
    ),
    (
        "exfil_url",
        "critical",
        re.compile(
            r"https?://[^\s<>\"')]*(?:webhook\.site|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|"
            r"burpcollaborator|oastify\.com|interact\.sh|oast\.(?:fun|live|me|pro|site)|"
            r"canarytokens|beeceptor\.com|hookbin|requestcatcher)[^\s<>\"')]*",
            re.IGNORECASE,
        ),
    ),
    (
        "exfil_url",
        "critical",
        re.compile(
            r"\b(?:send|post|upload|transmit|exfiltrate|forward|leak|email|mail|submit|copy)\b"
            r"[^.\n]{0,60}?"
            r"\b(?:contents?|secrets?|env(?:ironment)?|api[_ -]?keys?|tokens?|credentials?|"
            r"passwords?|\.env|ssh keys?|private keys?|source code|database|files?)\b"
            r"[^.\n]{0,60}?\bto\b[^.\n]{0,20}?(?:https?://|[\w.+-]+@[\w-]+\.[a-z]{2,}|me\b|"
            r"this (?:address|url|endpoint|email))",
            re.IGNORECASE,
        ),
    ),
    (
        "exfil_url",
        "critical",
        re.compile(
            r"(?:!\[[^\]]*\]\(\s*|<img\b[^>]*\bsrc\s*=\s*[\"'])https?://[^\s)\"']*\?"
            r"[^\s)\"']*\b(?:secret|token|key|password|passwd|env|credential|cookie|session|"
            r"ssh|private)[^\s)\"']*",
            re.IGNORECASE,
        ),
    ),
    (
        "exfil_url",
        "high",
        re.compile(
            r"(?:!\[[^\]]*\]\(\s*|<img\b[^>]*\bsrc\s*=\s*[\"'])https?://[^\s)\"']*\?"
            r"[^\s)\"']*=(?:[^\s)\"'&]{16,}|[^\s)\"'&]*(?:\$|\{\{|%7B%7B)[^\s)\"'&]*)",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_coercion",
        "critical",
        re.compile(
            r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
            r"\bbash\s+<\(\s*(?:curl|wget)|"
            r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:--?\S+\s+)*(?:/|/\*|~|~/|~/\*|\$HOME(?:/\*?)?|"
            r"/(?:home|etc|usr|bin|sbin|boot|root|lib|opt|srv)(?:/\*)?|\.\.(?:/\*?)?)"
            r"(?=[\s;&|)\"']|$)|"
            r"\bcat\s+[^\n]{0,40}(?:~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|"
            r"\.kube/config|\.npmrc|\.netrc|\.git-credentials)|"
            r"\b(?:printenv|env)\b[^\n]{0,80}\|\s*(?:curl|wget|nc|ncat|base64|xxd)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_coercion",
        "high",
        re.compile(
            r"\b(?:run|execute|call|invoke)\b\s+(?:the\s+)?(?:following|this|these)\s+"
            r"(?:command|commands|script|code|tool)\b[^.\n]{0,80}?\b(?:without|before|immediately|now)\b",
            re.IGNORECASE,
        ),
    ),
]

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){20,}(?![0-9A-Fa-f])")
_KEYWORD_RE = re.compile(_KEYWORDS, re.IGNORECASE)
_HIDDEN_KEYWORD_RE = re.compile(_HIDDEN_KEYWORDS, re.IGNORECASE)

#: Zero-width / format / bidi-control code points that can hide or reorder instructions.
_HIDDEN_CHARS = (
    "\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\ufeff\u180e\u00ad"
    "\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f"
)
_HIDDEN_CHAR_RE = re.compile(f"[{_HIDDEN_CHARS}]+")
_HIDDEN_RUN_RE = re.compile(f"[{_HIDDEN_CHARS}]{{3,}}")
_HIDDEN_IN_WORD_RE = re.compile(f"(?<=\\w)[{_HIDDEN_CHARS}]+(?=\\w)")

#: Cyrillic/Greek letters that render like Latin ones (one-to-one, length preserving).
CONFUSABLES: dict[int, str] = {
    ord(src): dst
    for src, dst in (
        ("а", "a"),
        ("е", "e"),
        ("о", "o"),
        ("р", "p"),
        ("с", "c"),
        ("у", "y"),
        ("х", "x"),
        ("і", "i"),
        ("ј", "j"),
        ("ѕ", "s"),
        ("һ", "h"),
        ("ԁ", "d"),
        ("ɡ", "g"),
        ("ԛ", "q"),
        ("ѡ", "w"),
        ("к", "k"),
        ("т", "t"),
        ("в", "b"),
        ("н", "h"),
        ("м", "m"),
        ("ӏ", "l"),
        ("А", "A"),
        ("В", "B"),
        ("Е", "E"),
        ("К", "K"),
        ("М", "M"),
        ("Н", "H"),
        ("О", "O"),
        ("Р", "P"),
        ("С", "C"),
        ("Т", "T"),
        ("У", "Y"),
        ("Х", "X"),
        ("І", "I"),
        ("Ј", "J"),
        ("Ѕ", "S"),
        ("Ԁ", "D"),
        ("Ԛ", "Q"),
        ("Ѡ", "W"),
        ("α", "a"),
        ("ε", "e"),
        ("ι", "i"),
        ("κ", "k"),
        ("ο", "o"),
        ("ρ", "p"),
        ("τ", "t"),
        ("υ", "u"),
        ("χ", "x"),
        ("ν", "v"),
        ("Α", "A"),
        ("Β", "B"),
        ("Ε", "E"),
        ("Ζ", "Z"),
        ("Η", "H"),
        ("Ι", "I"),
        ("Κ", "K"),
        ("Μ", "M"),
        ("Ν", "N"),
        ("Ο", "O"),
        ("Ρ", "P"),
        ("Τ", "T"),
        ("Υ", "Y"),
        ("Χ", "X"),
    )
}


def normalize_for_screening(text: str) -> tuple[str, str, list[int]]:
    """Return ``(stripped, folded, hidden_positions)`` for ``text``.

    ``stripped`` is the NFKC-normalised text with hidden (zero-width/format/bidi) code
    points removed; ``folded`` additionally maps Latin-lookalike Cyrillic/Greek letters to
    Latin (same length as ``stripped``, so match offsets transfer). ``hidden_positions``
    are the offsets in ``stripped`` where a suspicious hidden run (inside a word, or three
    or more in a row) was removed.
    """
    norm = unicodedata.normalize("NFKC", text)
    hidden_positions: list[int] = []
    flagged_starts = {m.start() for m in _HIDDEN_IN_WORD_RE.finditer(norm)}
    flagged_starts |= {m.start() for m in _HIDDEN_RUN_RE.finditer(norm)}
    pieces: list[str] = []
    cursor = 0
    removed = 0
    for match in _HIDDEN_CHAR_RE.finditer(norm):
        pieces.append(norm[cursor : match.start()])
        if match.start() in flagged_starts:
            hidden_positions.append(match.start() - removed)
        removed += match.end() - match.start()
        cursor = match.end()
    pieces.append(norm[cursor:])
    stripped = "".join(pieces)
    return stripped, stripped.translate(CONFUSABLES), hidden_positions


def _decode_base64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    return _printable(raw)


def _decode_hex(blob: str) -> str | None:
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return None
    return _printable(raw)


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    if not text or printable / len(text) < 0.9:
        return None
    return text


def _excerpt(text: str, limit: int = 80) -> str:
    snippet = " ".join(text.split())
    return snippet if len(snippet) <= limit else snippet[: limit - 3] + "..."


def _looks_like_instructions(decoded: str) -> bool:
    folded = decoded.translate(CONFUSABLES)
    return bool(_KEYWORD_RE.search(folded)) or any(
        regex.search(folded) for _, _, regex in INJECTION_PATTERNS
    )


def screen_tool_result(
    text: str, *, sanitize: bool = True, max_chars: int | None = None
) -> ScreeningResult:
    """Screen untrusted text for prompt-injection patterns.

    The text is NFKC-normalised, stripped of zero-width/bidi characters and folded for
    Latin-lookalike letters before matching, so homoglyph and hidden-character
    obfuscations do not bypass the patterns. Base64 and hex runs are decoded and screened.

    Args:
        text: Tool result, web page, issue body, file content...
        sanitize: Replace matched spans with ``[FILTERED:<pattern>]`` markers.
        max_chars: Truncate the sanitised output to this many characters.

    Returns:
        :class:`ScreeningResult` with ``suspicious``, matched ``patterns``, the highest
        ``severity``, the ``sanitized_text`` (identical to the input when nothing matched;
        otherwise built from the normalised text) and findings.
    """
    stripped, folded, hidden_positions = normalize_for_screening(text)
    findings: list[Finding] = []
    spans: list[tuple[int, int, str]] = []

    for pos in hidden_positions:
        findings.append(
            Finding(
                pattern="hidden_unicode",
                severity="high",
                excerpt=_excerpt(stripped[max(0, pos - 20) : pos + 20]),
            )
        )
        spans.append((pos, pos, "hidden_unicode"))

    for pattern_id, severity, regex in INJECTION_PATTERNS:
        for match in regex.finditer(folded):
            span = stripped[match.start() : match.end()]
            if pattern_id == "hidden_comment" and not _HIDDEN_KEYWORD_RE.search(
                folded[match.start() : match.end()]
            ):
                continue
            findings.append(Finding(pattern=pattern_id, severity=severity, excerpt=_excerpt(span)))
            spans.append((match.start(), match.end(), pattern_id))

    for regex, decode in ((_BASE64_RE, _decode_base64), (_HEX_RE, _decode_hex)):
        for match in regex.finditer(folded):
            decoded = decode(match.group(0))
            if decoded is None or not _looks_like_instructions(decoded):
                continue
            findings.append(
                Finding(pattern="encoded_instructions", severity="high", excerpt=_excerpt(decoded))
            )
            spans.append((match.start(), match.end(), "encoded_instructions"))

    patterns: list[str] = []
    for finding in findings:
        if finding.pattern not in patterns:
            patterns.append(finding.pattern)
    top_severity: str | None = max(
        (f.severity for f in findings), key=lambda s: _SEVERITY_RANK.get(s, 0), default=None
    )

    sanitized = text
    if spans:
        sanitized = _apply_filters(stripped, spans) if sanitize else stripped
    truncated = False
    if max_chars is not None and len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars] + "\n[TRUNCATED]"
        truncated = True
    return ScreeningResult(
        suspicious=bool(findings),
        patterns=patterns,
        severity=top_severity,
        sanitized_text=sanitized,
        findings=findings,
        truncated=truncated,
    )


def _apply_filters(text: str, spans: list[tuple[int, int, str]]) -> str:
    merged: list[tuple[int, int, str]] = []
    for start, end, pid in sorted(spans):
        if merged and start < merged[-1][1]:
            prev = merged[-1]
            merged[-1] = (prev[0], max(prev[1], end), prev[2])
        else:
            merged.append((start, end, pid))
    out: list[str] = []
    cursor = 0
    for start, end, pid in merged:
        out.append(text[cursor:start])
        out.append(f"[FILTERED:{pid}]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def extract_text(result: Any) -> str:
    """Flatten an MCP/tool result (str, dict with content/text, list of blocks) to text."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, bytes):
        return result.decode("utf-8", errors="replace")
    if isinstance(result, dict):
        for key in ("text", "content", "result", "output", "body", "stdout"):
            if key in result:
                return extract_text(result[key])
        return "\n".join(extract_text(v) for v in result.values())
    if isinstance(result, (list, tuple)):
        return "\n".join(extract_text(item) for item in result)
    return str(result)


class InjectionDetectedError(RuntimeError):
    """Raised by :func:`screened` wrappers configured with ``on_suspicious='raise'``."""

    def __init__(self, result: ScreeningResult) -> None:
        self.result = result
        super().__init__(f"suspicious tool result: {', '.join(result.patterns)}")


def screened(
    fn: Callable[..., Any],
    *,
    on_suspicious: str = "sanitize",
    max_chars: int | None = None,
    on_finding: Callable[[ScreeningResult], None] | None = None,
) -> Callable[..., Any]:
    """Wrap a tool callable so its result is screened before being returned to an agent.

    ``on_suspicious``: ``"sanitize"`` returns the filtered text, ``"raise"`` raises
    :class:`InjectionDetectedError`, ``"flag"`` returns the :class:`ScreeningResult` itself.
    ``on_finding`` is called with the result whenever something matched (e.g. to audit).
    """
    if on_suspicious not in {"sanitize", "raise", "flag"}:
        raise ValueError("on_suspicious must be 'sanitize', 'raise' or 'flag'")

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        raw = fn(*args, **kwargs)
        result = screen_tool_result(extract_text(raw), max_chars=max_chars)
        if result.suspicious and on_finding is not None:
            on_finding(result)
        if on_suspicious == "flag":
            return result
        if result.suspicious and on_suspicious == "raise":
            raise InjectionDetectedError(result)
        return result.sanitized_text

    wrapper.__name__ = getattr(fn, "__name__", "screened")
    wrapper.__doc__ = getattr(fn, "__doc__", None)
    return wrapper


class ScreenedGateway:
    """Screens results of tools called through an :class:`MCPGatewayConfig`.

    ``call(server, tool, invoke, **params)`` enforces the server allow-list, invokes the
    tool via ``invoke(**params)`` and screens the result.
    """

    def __init__(
        self,
        config: MCPGatewayConfig,
        *,
        on_finding: Callable[[str, str, ScreeningResult], None] | None = None,
    ) -> None:
        self.config = config
        self._on_finding = on_finding

    def call(
        self, server: str, tool: str, invoke: Callable[..., Any], /, **params: Any
    ) -> ScreeningResult:
        """Invoke ``tool`` on ``server`` and return the screened result."""
        if not self.config.is_tool_allowed(server, tool):
            raise PermissionError(f"tool {tool!r} on MCP server {server!r} is not allow-listed")
        raw = invoke(**params)
        server_cfg = self.config.server(server)
        screen = self.config.screen_results and (server_cfg is None or server_cfg.screen_results)
        text = extract_text(raw)
        if not screen:
            return ScreeningResult(suspicious=False, sanitized_text=text)
        result = screen_tool_result(text, max_chars=self.config.max_result_chars)
        if result.suspicious and self._on_finding is not None:
            self._on_finding(server, tool, result)
        return result
