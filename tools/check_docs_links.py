#!/usr/bin/env python3
"""Check internal links between this repository's Markdown documents.

Azazel-Nexus was a documentation-only repository until the Knowledge Lite
consumer landed (Nexus#15); its unit tests now run in their own CI job, and
this check remains what holds the documents themselves together. It verifies
that
every relative link in a Markdown file points at a file that exists, and that a
`#fragment` on a Markdown target names a heading that exists in it. External
links (http, https, mailto, ...) are not fetched: this check must pass offline
and must not depend on anything outside the repository.

Adapted from the same check in Azazel-Boot (`tools/check_docs_links.py`); the
behavior is deliberately identical so that the two repositories' documentation
is held to one standard.

Standard library only. Exit status 0 when every internal link resolves.

Usage:
    python3 tools/check_docs_links.py [ROOT]
"""

from __future__ import annotations

import os
import re
import sys
import unicodedata

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}

# [text](target "optional title") -- target may not contain spaces or parens.
INLINE_LINK = re.compile(r"\[(?:[^\]]*)\]\(\s*<?([^()<>\s]+)>?(?:\s+\"[^\"]*\")?\s*\)")
# [label]: target  (link reference definition, at the start of a line)
REF_DEFINITION = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?([^\s<>]+)>?")
ATX_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE = re.compile(r"^\s*(```+|~~~+)")
# An external scheme, or a protocol-relative URL.
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")


def markdown_files(root: str) -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.lower().endswith(".md"):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


def strip_code_fences(lines: list[str]) -> list[tuple[int, str]]:
    """Return (1-based line number, text) for lines outside fenced code blocks."""
    out: list[tuple[int, str]] = []
    fence: str | None = None
    for number, line in enumerate(lines, start=1):
        match = FENCE.match(line)
        if fence is None:
            if match:
                fence = match.group(1)[0] * 3
                continue
            out.append((number, line))
        else:
            if match and match.group(1)[0] * 3 == fence:
                fence = None
    return out


def slugify(heading: str) -> str:
    """Approximate GitHub's heading anchor generation."""
    text = heading
    # Inline code, links, emphasis: keep the visible text only.
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[*_]{1,3}([^*_]+)[*_]{1,3}", r"\1", text)
    text = unicodedata.normalize("NFKC", text).strip().lower()
    text = text.replace(" ", "-")
    # GitHub keeps word characters and hyphens; other punctuation is dropped.
    text = "".join(ch for ch in text if ch.isalnum() or ch in "-_")
    return text


def anchors_of(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except (OSError, UnicodeDecodeError):
        return set()
    seen: dict[str, int] = {}
    anchors: set[str] = set()
    for _, line in strip_code_fences(lines):
        match = ATX_HEADING.match(line)
        if not match:
            continue
        base = slugify(match.group(2))
        if not base:
            continue
        count = seen.get(base, 0)
        seen[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def links_in(path: str) -> list[tuple[int, str]]:
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    found: list[tuple[int, str]] = []
    for number, line in strip_code_fences(lines):
        definition = REF_DEFINITION.match(line)
        if definition:
            found.append((number, definition.group(1)))
            continue
        for target in INLINE_LINK.findall(line):
            found.append((number, target))
    return found


def check(root: str) -> list[str]:
    problems: list[str] = []
    files = markdown_files(root)
    if not files:
        return [f"{root}: no Markdown files found; nothing to check"]

    anchor_cache: dict[str, set[str]] = {}
    for path in files:
        rel_file = os.path.relpath(path, root)
        for number, raw_target in links_in(path):
            target = raw_target.strip()
            if not target or EXTERNAL.match(target) or target.startswith("#!"):
                continue

            location, _, fragment = target.partition("#")
            if location:
                resolved = os.path.normpath(
                    os.path.join(os.path.dirname(path), location)
                )
            else:
                resolved = path

            if not os.path.exists(resolved):
                problems.append(
                    f"{rel_file}:{number}: missing target {location!r}"
                )
                continue

            inside = os.path.relpath(resolved, root)
            if inside.startswith(".."):
                problems.append(
                    f"{rel_file}:{number}: target {location!r} escapes the repository"
                )
                continue

            if not fragment or not resolved.lower().endswith(".md"):
                continue
            if resolved not in anchor_cache:
                anchor_cache[resolved] = anchors_of(resolved)
            if slugify(fragment) not in anchor_cache[resolved]:
                problems.append(
                    f"{rel_file}:{number}: no heading {'#' + fragment!r} in "
                    f"{os.path.relpath(resolved, root)}"
                )

    return problems


def main(argv: list[str]) -> int:
    root = os.path.abspath(argv[1]) if len(argv) > 1 else os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    )
    problems = check(root)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            f"\n{len(problems)} broken internal link(s).", file=sys.stderr
        )
        return 1
    print(
        f"internal links OK ({len(markdown_files(root))} Markdown files checked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
