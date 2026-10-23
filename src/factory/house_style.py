"""factory/house_style.py — strip the machine-writing tells out of generated prose.

A commodity model writes correct prose that still *reads* as machine-written: em dashes everywhere,
decorative emojis, the occasional doubled space left by a deletion. Those are quality defects a human would
otherwise hand-fix before shipping. The governing principle of this codebase is "build only what encodes your
standards"; this module is exactly that, our house style, applied to provider output so the operator does not
have to edit it.

Boundary and gotchas:
  - PROSE ONLY. Never run this over code: it would rewrite punctuation that code depends on. Fenced code
    blocks (```...```) and inline `code` spans are protected here and pass through untouched, so a research
    report that embeds a snippet (or a mermaid diagram, which is a ```mermaid fence) is safe.
  - It is deliberately conservative. It fixes the MECHANICAL tells (dashes, emojis, whitespace litter). It does
    NOT touch the rhetorical tells (the antithesis cadence, the rule of three, buzzwords): those need a
    sentence rewrite, not a substitution, so they belong to a model pass or a human, not a regex.
  - Idempotent: running it twice yields the same text as running it once.
"""
from __future__ import annotations

import re

# A spaced em/en dash is the usual honest joint; a comma is its plain-prose replacement.
_SPACED_DASH = re.compile(r"\s+[–—]\s+")
# A numeric range "1–5" reads as "1 to 5"; do this before the glued-dash rule so it wins on digits.
_RANGE = re.compile(r"(?<=\d)\s*[–—]\s*(?=\d)")
# An em/en dash glued between two word characters becomes a comma-joint too.
_GLUED_DASH = re.compile(r"(?<=\w)[–—](?=\w)")
# A bare em/en dash left over (start of line, around non-word chars) collapses to a comma.
_BARE_DASH = re.compile(r"[–—]")

# Decorative emoji and pictographs. We strip the common Unicode emoji blocks (symbols, pictographs, transport,
# flags, dingbats, variation selectors, the keycap combiner). Plain typographic punctuation is untouched.
_EMOJI = re.compile(
    "[\U0001F300-\U0001FAFF"   # symbols, pictographs, emoji extensions
    "\U00002600-\U000027BF"    # misc symbols + dingbats
    "\U0001F000-\U0001F0FF"    # mahjong/dominoes/cards
    "\U00002190-\U000021FF"    # arrows (decorative ➜-style; mermaid arrows live in protected fences)
    "\U0000FE00-\U0000FE0F"    # variation selectors (the emoji-style modifier)
    "\U00002B00-\U00002BFF"    # misc symbols and arrows (stars, etc.)
    "\U0000200D"               # zero-width joiner that stitches multi-part emoji
    "\U000020E3]"              # combining enclosing keycap
)

# Protect fenced code (```lang ... ```) and inline `code` so we never rewrite what is not prose.
_FENCE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]*`")


def normalize_prose(text: str) -> str:
    """Return `text` with the mechanical AI tells removed, code spans preserved. The single entry point a
    prose vertical pipes its model output through before storing or exporting it."""
    if not text:
        return text
    # Emojis are decorative content, NEVER structural code syntax a renderer or compiler depends on (unlike a
    # dash, which can be a mermaid arrow or a code operator). So strip them EVERYWHERE first, including inside
    # code fences, which the dash/whitespace rules below still protect. This catches an emoji in a fenced
    # example (a UI mockup in a PRD, say) that the fence would otherwise shield.
    text = _EMOJI.sub("", text)
    # Stash protected segments (fences first, then inline code) behind sentinels, transform the prose around
    # them, then restore. A list-backed sentinel avoids any chance of a collision with real content.
    stash: list[str] = []

    def _hide(match: re.Match[str]) -> str:
        stash.append(match.group(0))
        return f"\x00{len(stash) - 1}\x00"

    work = _FENCE.sub(_hide, text)
    work = _INLINE_CODE.sub(_hide, work)
    work = _transform(work)
    # Restore in reverse is unnecessary (sentinels are unique by index); restore by index.
    return re.sub(r"\x00(\d+)\x00", lambda m: stash[int(m.group(1))], work)


def _transform(prose: str) -> str:
    """Apply the prose-only substitutions. Order matters: ranges before the glued/bare dash rules."""
    prose = _RANGE.sub(" to ", prose)        # 1–5  -> 1 to 5
    prose = _SPACED_DASH.sub(", ", prose)    # a — b -> a, b
    prose = _GLUED_DASH.sub(", ", prose)     # word—word -> word, word
    prose = _BARE_DASH.sub(", ", prose)      # any straggler em/en dash -> comma
    # (emoji are stripped globally in normalize_prose, before fences are protected, so not repeated here)
    prose = re.sub(r"[ \t]{2,}", " ", prose)  # collapse the doubled spaces a deletion leaves
    prose = re.sub(r" +([,.;:!?])", r"\1", prose)  # no space before the punctuation a strip can orphan
    prose = re.sub(r",\s*,", ",", prose)     # collapse a doubled comma a substitution can create
    prose = re.sub(r"[ \t]+$", "", prose, flags=re.MULTILINE)  # trim the trailing space a stripped emoji leaves
    return prose
