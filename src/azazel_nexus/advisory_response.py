"""What a remote provider is allowed to have said (#98).

A response is **untrusted content**. It arrives from a system this node does
not run, over a link this node does not control, and it is the one input in
this product that an adversary can author freely and at length.

So the boundary is not "sanitise the response". It is: the only things that
can be built from a response are a bounded piece of advisory text and a
bounded set of advisory fields. There is no constructor here that produces a
command, a tool call, a URL, an Edge action, a lease or an enforcement
instruction -- so a response cannot become one by being cleverly worded.

## Absent vocabulary, not a filter

The refusals below scan for the *shapes* an instruction takes, because a
scan can be widened as new shapes appear. But the guarantee does not rest on
the scan: it rests on there being **no type here that an executor consumes**.
`AdvisoryText` is a string with a length bound. `AdvisoryData` is a mapping
whose values are strings, numbers and booleans. Neither is accepted anywhere
that acts.

A filter that removed `<tool_call>` would be a filter someone has to keep
ahead of the attacker. A vocabulary with no executable member is not.

## It is advice, and advice is never authority

`docs/architecture.md`: the deterministic arbiter from Azazel-Edge holds the
final authority to decide and to enforce. A remote provider's answer is
context and a recommendation. A node that lost every provider decides
exactly what it decided before.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

__all__ = [
    "AdvisoryData",
    "AdvisoryRefusal",
    "AdvisoryRefused",
    "AdvisoryText",
    "MAX_ADVISORY_BYTES",
    "MAX_FIELDS",
    "MAX_FIELD_BYTES",
    "read_advisory",
]

#: The largest response this node will read, before it is decoded. A ceiling
#: enforced after reading everything is a ceiling on nothing; the transport
#: stops at the byte that exceeds it and this refuses what still arrives.
MAX_ADVISORY_BYTES = 64 * 1024

#: The most structured fields an advisory may carry.
MAX_FIELDS = 32

#: The largest single field value.
MAX_FIELD_BYTES = 4096

#: Shapes an instruction takes. Not the guarantee -- the guarantee is that
#: nothing here is executable -- but a loud refusal is better than a quiet
#: acceptance, and a provider whose answers look like commands is a provider
#: an operator should hear about.
_INSTRUCTION_SHAPES = (
    (re.compile(r"</?\s*(tool_call|function_call|invoke|antml:)", re.I), "a tool call"),
    (re.compile(r"\b(?:https?|ftp|file|data|javascript)\s*:\s*/?/?", re.I), "a URL or scheme"),
    (re.compile(r"(?m)^\s*(?:\$|#|>)\s*\S+\s"), "a shell prompt"),
    (re.compile(r"\b(?:rm|curl|wget|chmod|chown|systemctl|iptables|nft)\s+-", re.I), "a command"),
    (re.compile(r"\b(?:enforce|quarantine|block|drop|isolate)\s+(?:host|ip|interface|peer)\b", re.I), "an enforcement instruction"),
    (re.compile(r"\b(?:grant|extend|renew|revoke)\s+(?:lease|activation|authority)\b", re.I), "a lease or activation instruction"),
    (re.compile(r"\bunmask\b|\bsystemctl\b", re.I), "a unit instruction"),
)

#: Unicode categories that have no place in advisory text: control
#: characters, format characters (which include the bidirectional overrides
#: used to make text read differently from how it parses), surrogates and
#: unassigned code points.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Cn", "Co"})


class AdvisoryRefusal(str, Enum):
    """Why a response was not read as advice. One value per condition."""

    LOCAL_SCHEMA = "local_schema"
    UNGROUNDED_FACTS = "ungrounded_facts"
    LANGUAGE_MISMATCH = "language_mismatch"
    TOO_LARGE = "too_large"
    NOT_TEXT = "not_text"
    CONTROL_CHARACTERS = "control_characters"
    LOOKS_LIKE_AN_INSTRUCTION = "looks_like_an_instruction"
    TOO_MANY_FIELDS = "too_many_fields"
    FIELD_TOO_LARGE = "field_too_large"
    UNSUPPORTED_VALUE = "unsupported_value"
    EMPTY = "empty"


class AdvisoryRefused(Exception):
    """A response that is not advice. Refused, never repaired.

    The message names the **shape** that was refused and never quotes the
    response. A reason that quoted it would be a reason that carried
    attacker-authored text into the journal.
    """

    def __init__(self, refusal: AdvisoryRefusal, reason: str) -> None:
        super().__init__(f"{refusal.value}: {reason}")
        self.refusal = refusal
        self.reason = reason


@dataclass(frozen=True)
class AdvisoryText:
    """Bounded text. A string, and nothing consumes it but a display."""

    text: str


@dataclass(frozen=True)
class AdvisoryData:
    """Bounded fields. Strings, numbers and booleans, and nothing else.

    No nested object and no list: a structure that can nest is a structure
    that can carry a payload past a check written for the top level.
    """

    fields: Mapping[str, object]


@dataclass(frozen=True)
class Advisory:
    """What a provider said, as much as this node will represent of it."""

    text: Optional[AdvisoryText]
    data: Optional[AdvisoryData]
    #: Over the raw bytes, so an audit entry can identify a response without
    #: storing it.
    digest: str

    def as_event(self, *, local: bool = False) -> dict:
        """Audit metadata: a digest and counts. Never the response."""

        return {
            "event_type": "mio.local.advisory.read" if local else "mio.remote.advisory.read",
            "digest": self.digest,
            "text_characters": len(self.text.text) if self.text else 0,
            "field_count": len(self.data.fields) if self.data else 0,
        }


def _refuse(refusal: AdvisoryRefusal, reason: str):
    raise AdvisoryRefused(refusal, reason)


def _check_text(value: str, *, where: str) -> None:
    if not value.strip():
        _refuse(AdvisoryRefusal.EMPTY, f"{where} is empty")
    for character in value:
        if character in "\n\t":
            continue
        if unicodedata.category(character) in _FORBIDDEN_CATEGORIES:
            _refuse(
                AdvisoryRefusal.CONTROL_CHARACTERS,
                f"{where} contains a control or format character "
                f"(U+{ord(character):04X}). A bidirectional override makes text "
                "read differently from how it parses, which is how a reviewer "
                "approves something other than what they saw",
            )
    for pattern, shape in _INSTRUCTION_SHAPES:
        if pattern.search(value):
            _refuse(
                AdvisoryRefusal.LOOKS_LIKE_AN_INSTRUCTION,
                f"{where} contains what reads as {shape}. A provider returns "
                "advice; nothing here executes one, and one that tries is an "
                "operator's business to know about",
            )


def read_advisory(
    raw: bytes, *, max_bytes: int = MAX_ADVISORY_BYTES
) -> Advisory:
    """Read a provider's response as advice, or refuse it entirely.

    There is no partial success. A response that fails any check produces
    nothing rather than the part of it that passed: a half-read answer from
    an untrusted system is an answer whose missing half nobody chose.
    """

    import hashlib
    import json

    if len(raw) > max_bytes:
        _refuse(
            AdvisoryRefusal.TOO_LARGE,
            f"{len(raw)} bytes is larger than {max_bytes}",
        )
    if not raw:
        _refuse(AdvisoryRefusal.EMPTY, "the response is empty")

    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _refuse(AdvisoryRefusal.NOT_TEXT, f"the response is not UTF-8: {exc.reason}")

    try:
        document = json.loads(decoded)
    except ValueError as exc:
        _refuse(AdvisoryRefusal.NOT_TEXT, f"the response is not JSON: {exc}")
    if not isinstance(document, dict):
        _refuse(AdvisoryRefusal.NOT_TEXT, "the response is JSON that is not an object")

    unknown = sorted(set(document) - {"advice", "fields"})
    if unknown:
        # Refused rather than ignored. A key this reader does not understand
        # is a key the provider expected something to act on.
        _refuse(
            AdvisoryRefusal.UNSUPPORTED_VALUE,
            f"the response carries {unknown}, which nothing here reads. A key "
            "nobody consumes is a key the sender expected somebody to",
        )

    text = None
    if "advice" in document:
        value = document["advice"]
        if not isinstance(value, str):
            _refuse(AdvisoryRefusal.NOT_TEXT, "advice is text")
        if len(value.encode("utf-8")) > MAX_FIELD_BYTES * 4:
            _refuse(AdvisoryRefusal.TOO_LARGE, "advice is longer than this node reads")
        _check_text(value, where="advice")
        text = AdvisoryText(value)

    data = None
    if "fields" in document:
        value = document["fields"]
        if not isinstance(value, dict):
            _refuse(AdvisoryRefusal.UNSUPPORTED_VALUE, "fields is an object")
        if len(value) > MAX_FIELDS:
            _refuse(
                AdvisoryRefusal.TOO_MANY_FIELDS,
                f"{len(value)} fields is more than {MAX_FIELDS}",
            )
        checked: dict = {}
        for name, item in value.items():
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]{1,64}", name):
                _refuse(
                    AdvisoryRefusal.UNSUPPORTED_VALUE,
                    "a field name is a bounded lower-case identifier",
                )
            if isinstance(item, bool) or isinstance(item, (int, float)):
                checked[name] = item
                continue
            if not isinstance(item, str):
                _refuse(
                    AdvisoryRefusal.UNSUPPORTED_VALUE,
                    f"field {name!r} is not a string, number or boolean. A "
                    "structure that can nest is a structure that can carry a "
                    "payload past a check written for the top level",
                )
            if len(item.encode("utf-8")) > MAX_FIELD_BYTES:
                _refuse(
                    AdvisoryRefusal.FIELD_TOO_LARGE,
                    f"field {name!r} is longer than {MAX_FIELD_BYTES} bytes",
                )
            _check_text(item, where=f"field {name!r}")
            checked[name] = item
        data = AdvisoryData(checked)

    if text is None and data is None:
        _refuse(
            AdvisoryRefusal.EMPTY,
            "the response carries neither advice nor fields, so nothing was "
            "said. A provider that answers with nothing has not answered",
        )
    return Advisory(text=text, data=data, digest=digest)
