"""Secret detection patterns and scanner.

Two tiers of rules to minimize false positives:
  - **Anchored** third-party tokens (Stripe/AWS/Google/etc.) — high confidence,
    each has a unique prefix and length.
  - **Context-gated** Bubble tokens — 64-hex strings only reported when a
    nearby keyword (Bearer, api_token, bubble, authorization, …) is present.
    Without the gate, every SHA-256 path in Bubble bundles would produce a
    false positive.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SecretMatch:
    rule: str
    category: str
    severity: str
    value: str
    context: str
    offset: int
    source: str = ""


@dataclass
class SecretRule:
    name: str
    category: str
    severity: str
    pattern: re.Pattern[str]
    context_pattern: Optional[re.Pattern[str]] = None
    context_window: int = 100
    group: int = 0  # capture group holding the secret value


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


RULES: list[SecretRule] = [
    # ── Stripe ────────────────────────────────────────────────────────────
    SecretRule("stripe-sk-live", "Stripe", "critical",
        re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    SecretRule("stripe-rk-live", "Stripe", "critical",
        re.compile(r"\brk_live_[A-Za-z0-9]{20,}\b")),
    SecretRule("stripe-whsec", "Stripe", "high",
        re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b")),
    SecretRule("stripe-sk-test", "Stripe", "medium",
        re.compile(r"\bsk_test_[A-Za-z0-9]{20,}\b")),
    SecretRule("stripe-pk-live", "Stripe", "info",
        re.compile(r"\bpk_live_[A-Za-z0-9]{20,}\b")),

    # ── OpenAI / Anthropic ────────────────────────────────────────────────
    SecretRule("openai-proj", "OpenAI", "high",
        re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{40,}\b")),
    SecretRule("openai-sk", "OpenAI", "high",
        re.compile(r"\bsk-[A-Za-z0-9]{40,}\b"),
        re.compile(r"openai|gpt|chatgpt|completion|embedding", re.I)),
    SecretRule("anthropic-sk", "Anthropic", "high",
        re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{40,}\b")),

    # ── Google ────────────────────────────────────────────────────────────
    SecretRule("google-api-key", "Google", "medium",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),

    # ── AWS ───────────────────────────────────────────────────────────────
    SecretRule("aws-access-key", "AWS", "critical",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),

    # ── GitHub ────────────────────────────────────────────────────────────
    SecretRule("github-pat", "GitHub", "critical",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),

    # ── Slack ─────────────────────────────────────────────────────────────
    SecretRule("slack-token", "Slack", "critical",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),

    # ── SendGrid / Mailgun ────────────────────────────────────────────────
    SecretRule("sendgrid", "SendGrid", "critical",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    SecretRule("mailgun", "Mailgun", "high",
        re.compile(r"\bkey-[0-9a-f]{32}\b"),
        re.compile(r"mailgun", re.I)),

    # ── Twilio ────────────────────────────────────────────────────────────
    SecretRule("twilio-sid", "Twilio", "medium",
        re.compile(r"\b(?:AC|SK)[0-9a-f]{32}\b"),
        re.compile(r"twilio", re.I)),

    # ── JWT ───────────────────────────────────────────────────────────────
    SecretRule("jwt", "JWT", "medium",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),

    # ── Private keys (PEM) ────────────────────────────────────────────────
    SecretRule("rsa-private-key", "RSA Private Key", "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),

    # ── Bubble — 64-hex API token (context-gated) ─────────────────────────
    SecretRule("bubble-api-token", "Bubble API Token", "high",
        re.compile(r"\b([a-f0-9]{64})\b"),
        re.compile(
            r"bearer|authori[sz]ation|api[_-]?token|api[_-]?key|bubble[_-]?api|"
            r"x[_-]?api[_-]?key",
            re.I,
        ),
        context_window=140,
        group=1),
    SecretRule("bubble-user-token", "Bubble User Session", "medium",
        re.compile(r"\b1[0-9]{12}x[0-9]{15,20}\b"),
        re.compile(r"token|session|bubble_uid|current_user|user_id", re.I),
        context_window=80),

    # ── URL-embedded secrets ──────────────────────────────────────────────
    SecretRule("url-auth-param", "URL secret", "high",
        re.compile(
            r"[?&](?:api[_-]?key|api[_-]?token|access[_-]?token|"
            r"auth[_-]?token|bearer|token|secret)=([A-Za-z0-9._\-]{16,})"
        ),
        group=1),

    # ── Basic auth in URL ─────────────────────────────────────────────────
    SecretRule("basic-auth-url", "Basic auth in URL", "high",
        re.compile(r"https?://[A-Za-z0-9._\-]+:([^@\s'\"]{6,})@")),

    # ── Generic apiconnector2 "Private: false" hardcoded value ────────────
    SecretRule("bubble-apiconnector-private", "API Connector private value", "medium",
        re.compile(
            r'"(?:value|private_value|header_value)"\s*:\s*"([A-Za-z0-9._\-]{20,})"'
        ),
        re.compile(r'api[_-]?connector|shared[_-]?headers?', re.I),
        context_window=200,
        group=1),

    # ── Tier 6.4 — API Connector response schema cache ────────────────────
    # When Bubble devs use "Detect request data" the test-call response is
    # baked into `static.js`. Look for standard OAuth/JWT-ish fields nested
    # in an object literal — these are almost always real tokens pulled from
    # the test call.
    SecretRule("api-cache-access-token", "API cache", "high",
        re.compile(r'"access[_-]?token"\s*:\s*"([A-Za-z0-9._\-]{20,})"'),
        group=1),
    SecretRule("api-cache-refresh-token", "API cache", "high",
        re.compile(r'"refresh[_-]?token"\s*:\s*"([A-Za-z0-9._\-]{20,})"'),
        group=1),
    SecretRule("api-cache-id-token", "API cache", "high",
        re.compile(r'"id[_-]?token"\s*:\s*"([A-Za-z0-9._\-]{20,})"'),
        group=1),
    SecretRule("api-cache-bearer", "API cache", "high",
        re.compile(r'"bearer[_-]?token"\s*:\s*"([A-Za-z0-9._\-]{20,})"'),
        group=1),
    SecretRule("api-cache-session-id", "API cache", "medium",
        re.compile(r'"session[_-]?id"\s*:\s*"([A-Za-z0-9._\-]{16,})"'),
        group=1),
    SecretRule("api-cache-client-secret", "API cache", "critical",
        re.compile(r'"client[_-]?secret"\s*:\s*"([A-Za-z0-9._\-]{16,})"'),
        group=1),

    # ── Tier 6.1 — option-set attribute values (context-gated) ────────────
    # Option sets are shipped plaintext to every visitor. Flag any string
    # attribute value that contains a token-ish fragment, but only when
    # OptionSet/option_set context is nearby.
    SecretRule("option-set-jwt", "Option Set", "high",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        re.compile(r"option[_-]?set|OptionSet|OptionAttribute", re.I),
        context_window=500),
    SecretRule("option-set-aws", "Option Set", "critical",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        re.compile(r"option[_-]?set|OptionSet|OptionAttribute", re.I),
        context_window=500),
    SecretRule("option-set-google", "Option Set", "medium",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        re.compile(r"option[_-]?set|OptionSet|OptionAttribute", re.I),
        context_window=500),
]


def scan(content: str, source: str = "") -> list[SecretMatch]:
    """Return deduped `SecretMatch` list for the given content."""
    seen: set[tuple[str, str]] = set()
    out: list[SecretMatch] = []
    for rule in RULES:
        for m in rule.pattern.finditer(content):
            value = m.group(rule.group) if rule.group else m.group(0)
            if rule.context_pattern is not None:
                start = max(0, m.start() - rule.context_window)
                end = min(len(content), m.end() + rule.context_window)
                ctx = content[start:end]
                if not rule.context_pattern.search(ctx):
                    continue
            key = (rule.name, value)
            if key in seen:
                continue
            seen.add(key)
            ctx_start = max(0, m.start() - 30)
            ctx_end = min(len(content), m.end() + 30)
            ctx_snippet = content[ctx_start:ctx_end].replace("\n", " ").replace("\r", " ")
            out.append(SecretMatch(
                rule=rule.name,
                category=rule.category,
                severity=rule.severity,
                value=value,
                context=ctx_snippet,
                offset=m.start(),
                source=source,
            ))
    out.sort(key=lambda s: (-_SEV_ORDER.get(s.severity, 0), s.category, s.rule))
    return out
