"""Offline, stdlib-only structural check for reasoning-playbook/1 layers.

This deliberately independent checker is temporary integration scaffolding:
integration should replace validation with the library's authoritative reader.
It checks data only and does not admit, install, compose, or execute a layer.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SCHEMA = "azazel-nexus/reasoning-playbook/1"
MAX_BYTES = 2 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
ENTRY_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,63}\Z")
TECHNIQUE = re.compile(r"T\d{4}(?:\.\d{3})?\Z", re.ASCII)
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
CATEGORIES = frozenset({
    "authentication", "network", "endpoint", "web_application", "email", "cloud",
    "vulnerability", "data_exfiltration", "insider", "availability", "deception",
    "supply_chain", "edge_network",
})
REFERENCE_IDS = {
    "mitre-attack": r"(?:T\d{4}(?:\.\d{3})?|TA\d{4})",
    "mitre-d3fend": r"D3-[A-Z0-9]{2,12}",
    "owasp-top10-2021": r"A(?:0[1-9]|10)",
    "owasp-asvs": r"V\d{1,2}(?:\.\d{1,2}){0,2}",
    "owasp-cheatsheet": r"[a-z0-9-]{3,64}",
    "nist-sp800-61r3": r"(?:govern|identify|protect|detect|respond|recover)",
    "cisa-kev": r"CVE-\d{4}-\d{4,7}",
}
GUIDANCE = frozenset({"interpretation", "checks", "first_response", "benign", "missing"})
# A semicolon introducing a Latin command token is refused, while ordinary
# Japanese punctuation is prose. The other forbidden sequences are literal.
UNSAFE = re.compile(
    r"://|www\.|`|\$\(|&&|\||;\s*[A-Za-z_./]|rm -|sudo\s|chmod\s|curl\s|"
    r"wget\s|powershell -|iptables\s|nft\s|enforcement|block_all",
    re.IGNORECASE,
)


class InvalidPlaybook(ValueError):
    """Fixed reasons only, without echoing potentially hostile content."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise InvalidPlaybook(reason)


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate key")
        result[key] = value
    return result


def _fields(value: object, fields: set | frozenset) -> None:
    _require(type(value) is dict and value.keys() == fields, "invalid fields")


def _text(value: object, *, maximum: int | None = None) -> None:
    _require(type(value) is str and bool(value.strip()), "invalid text")
    _require(maximum is None or len(value) <= maximum, "text too long")
    _require(UNSAFE.search(value) is None, "unsafe text")


def _list(value: object, minimum: int, maximum: int | None = None) -> None:
    _require(type(value) is list, "invalid list")
    _require(len(value) >= minimum and (maximum is None or len(value) <= maximum),
             "invalid list length")


def _pattern(value: object, pattern: re.Pattern) -> None:
    _text(value)
    _require(pattern.fullmatch(value) is not None, "invalid identifier")


def _bilingual(value: object, *, items: bool, maximum: int | None = None,
               count: int = 5) -> None:
    _fields(value, {"ja", "en"})
    for language in ("ja", "en"):
        if items:
            _list(value[language], 1, count)
            for item in value[language]:
                _text(item, maximum=maximum)
        else:
            _text(value[language], maximum=maximum)


def _entry(entry: object, layer: str) -> None:
    _fields(entry, {"id", "status", "category", "title", "references", "match", "guidance"})
    _pattern(entry["id"], ENTRY_ID)
    _require(type(entry["status"]) is str and entry["status"] in {"template", "reviewed"},
             "invalid status")
    _require(layer != "baseline" or entry["status"] == "template", "baseline must be template")
    _require(type(entry["category"]) is str and entry["category"] in CATEGORIES,
             "invalid category")
    _bilingual(entry["title"], items=False)
    _list(entry["references"], 1, 8)
    for reference in entry["references"]:
        _fields(reference, {"source", "id"})
        _text(reference["source"])
        _require(reference["source"] in REFERENCE_IDS, "invalid reference source")
        _pattern(reference["id"], re.compile(REFERENCE_IDS[reference["source"]], re.ASCII))
    match = entry["match"]
    _fields(match, {"keywords", "attack_techniques", "context_kinds", "min_score"})
    _bilingual(match["keywords"], items=True, maximum=48, count=24)
    _list(match["attack_techniques"], 0)
    for technique in match["attack_techniques"]:
        _pattern(technique, TECHNIQUE)
    _list(match["context_kinds"], 0)
    for kind in match["context_kinds"]:
        _text(kind)
    _require(type(match["min_score"]) is int and match["min_score"] >= 1, "invalid min_score")
    _fields(entry["guidance"], GUIDANCE)
    for section in GUIDANCE:
        _bilingual(entry["guidance"][section], items=True, maximum=160)


def validate(raw: bytes) -> dict:
    """Return a validated layer or raise InvalidPlaybook with a fixed reason."""
    _require(type(raw) is bytes and len(raw) <= MAX_BYTES, "invalid byte length")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, InvalidPlaybook):
            raise
        raise InvalidPlaybook("invalid JSON") from None
    _fields(document, {"schema", "library_id", "layer", "version", "disable", "entries"})
    _require(document["schema"] == SCHEMA, "invalid schema")
    _pattern(document["library_id"], NAME)
    _require(type(document["layer"]) is str and document["layer"] in {"baseline", "site"},
             "invalid layer")
    _pattern(document["version"], VERSION)
    _list(document["disable"], 0)
    for disabled in document["disable"]:
        _pattern(disabled, ENTRY_ID)
    _require(document["layer"] != "baseline" or not document["disable"],
             "baseline cannot disable")
    _list(document["entries"], 0, 512)
    ids = set()
    for entry in document["entries"]:
        _entry(entry, document["layer"])
        _require(entry["id"] not in ids, "duplicate entry id")
        ids.add(entry["id"])
    return document


def check_path(path: Path) -> dict:
    """Bound the read before parsing; this is an offline check, not admission."""
    with path.open("rb") as stream:
        return validate(stream.read(MAX_BYTES + 1))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path,
                        default=[Path(__file__).resolve().parents[1]
                                 / "playbooks/baseline/azazel-baseline.json"])
    args = parser.parse_args(argv)
    for path in args.paths:
        try:
            document = check_path(path)
        except (OSError, InvalidPlaybook) as exc:
            reason = str(exc) if isinstance(exc, InvalidPlaybook) else "unreadable file"
            print(f"playbooks: invalid: {reason}")
            return 1
        print(f"playbooks: valid: {document['library_id']} ({len(document['entries'])} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
