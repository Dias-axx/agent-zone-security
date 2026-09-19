"""Heuristic scanner for tool output. This is NOT a prompt-injection filter
and does not reverse this project's stated non-goal (the threat model assumes
injection succeeds and focuses on containment, not prevention — see
docs/threat-model.md and the README's Non-goals section).

What this module actually does: flag tool output containing known
injection-marker patterns (instruction-override phrasing, role-play/jailbreak
framing, zero-width/invisible Unicode used to hide text from a human reviewer
but not a model, and non-http(s) URL schemes in tool output that could be used
for exfiltration or further injection) as an additional detection signal,
feeding the same detection/rules/*.yaml pipeline as Hubble flows and egress
logs. It is best-effort: it will miss novel phrasing (a false negative) and
will sometimes flag legitimate content that happens to match a pattern (a
false positive). Treat AGT-INJECT-001 the way every other rule in this repo
is treated — as a signal to investigate, not as proof, and never as a reason
to skip the containment controls (policy engine, egress allowlist, zone
enforcement) that do not depend on content inspection at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Deliberately conservative and documented, not exhaustive. Each pattern names
# what it targets so a false positive is easy to diagnose and narrow.
_MARKER_PATTERNS: dict[str, re.Pattern[str]] = {
    "instruction_override": re.compile(
        r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier)\b[^.\n]{0,40}\b"
        r"(instructions?|prompt|rules?|system message)\b",
        re.IGNORECASE,
    ),
    "role_override": re.compile(
        r"\byou are now\b|\bnew system prompt\b|\bact as (?:if you (?:are|were)|a)\b|\bDAN mode\b",
        re.IGNORECASE,
    ),
    "credential_or_secret_request": re.compile(
        r"\b(reveal|print|output|dump)\b[^.\n]{0,40}\b(api key|secret|password|credential|token)s?\b",
        re.IGNORECASE,
    ),
    "zero_width_or_invisible_unicode": re.compile(
        r"[​‌‍⁠﻿]"
    ),
    "non_http_url_scheme": re.compile(
        r"\b(?!https?://)[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE
    ),
}


@dataclass(frozen=True)
class ScanFinding:
    marker: str
    span: tuple[int, int]
    matched_text: str


def scan_tool_output(text: str) -> list[ScanFinding]:
    """Returns every heuristic marker found in `text`. An empty list means no
    known marker matched — it does not mean the output is safe."""
    findings: list[ScanFinding] = []
    for marker, pattern in _MARKER_PATTERNS.items():
        for match in pattern.finditer(text):
            findings.append(ScanFinding(marker=marker, span=match.span(), matched_text=match.group(0)))
    return findings
