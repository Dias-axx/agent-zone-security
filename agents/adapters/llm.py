"""Optional adapter for a real model API (Claude). Import-guarded so the rest of
the repository runs, and all PoCs and tests pass, with no API key and no network
access. This module is never imported by control/, detection/ or the mock agents.
"""

from __future__ import annotations

from typing import Any

try:
    import anthropic  # type: ignore[import-not-found]

    HAS_ANTHROPIC = True
except ImportError:
    anthropic = None
    HAS_ANTHROPIC = False


def is_available() -> bool:
    return HAS_ANTHROPIC


def complete(prompt: str, model: str = "claude-sonnet-5") -> str:
    if not HAS_ANTHROPIC:
        raise RuntimeError("anthropic package is not installed; this adapter is optional")
    client: Any = anthropic.Anthropic()
    response = client.messages.create(
        model=model,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    block = response.content[0]
    return block.text if hasattr(block, "text") else str(block)
