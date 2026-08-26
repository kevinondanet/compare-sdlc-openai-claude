"""Customer-support assistant with governed tools over a private customer file (pilot 3).

The assistant is rule-driven so the pilot runs offline; its rule core stands in for a
model in one specific way: it follows imperative instructions found in its context (the
user message and tool results), which is exactly the behaviour prompt injection exploits.
Tool calls go through the platform's tier policy (search audited, e-mail rule-approved,
deletion denied) and every request lands in an HMAC-signed audit log.
"""

from assistant.agent import SupportAssistant, build_assistant

__all__ = ["SupportAssistant", "build_assistant"]
