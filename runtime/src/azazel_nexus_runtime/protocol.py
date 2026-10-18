"""What a caller may ask for, and the shapes that are the whole vocabulary.

The rule from issue #36, made structural rather than remembered:

    No verb takes an arbitrary command, unit name, path, or argument.

So there is no argument kind here that carries free text. A caller sends a
verb from a fixed allowlist and arguments that are ordinals, flags, values
from an enumeration the verb declares, or digests — and a digest is a fixed
grammar (`sha256:` and sixty-four hex digits) that is **compared and never
dereferenced**. It names nothing on the filesystem and reaches nothing.

Two refusals are worth stating because they are easy to get backwards:

*An undeclared key is refused, not ignored.* Ignoring it means a caller and a
daemon disagree about what was asked, and only one of them finds out.

*A verb with no admitted principal cannot be constructed.* Default deny is a
property of the type, not a branch someone could forget to write.

And one about what the refusals record. A rejected frame is attacker-supplied
by definition, so nothing from it is written to the ledger verbatim. An
unknown verb is recorded as a bounded fingerprint: enough to see that the same
unknown verb arrived four hundred times, and not a channel for writing text
into the audit chain.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

from .principal import Principal, PrincipalClass

__all__ = [
    "Argument",
    "ArgumentKind",
    "RequestRefused",
    "Refusal",
    "Verb",
    "VerbRegistry",
    "fingerprint",
]

#: A digest as this protocol accepts one. Compared, never dereferenced.
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

#: An RFC3339 instant in UTC. A fixed grammar, not a date parser.
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")

#: A name: an operator, a service account, a host-local identity.
#:
#: The one kind that carries text a caller chose, and it is bounded on both
#: axes -- 64 characters, and an alphabet with no whitespace, no control
#: characters and no shell metacharacters. An actor has to be recordable for
#: an audit entry to mean anything; the bound and the alphabet are what keep
#: the field from being a channel into the ledger.
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._@:+-]{1,64}$")

#: Keys a caller might use to assert who they are.
#:
#: Refused with their own reason rather than as generic undeclared keys, so
#: that an attempt to supply a principal is visible in the ledger as that and
#: not as a typo. No verb may declare an argument with one of these names, and
#: the registry refuses one that tries.
RESERVED_PRINCIPAL_KEYS = frozenset(
    {
        "principal",
        "role",
        "roles",
        "uid",
        "gid",
        "user",
        "username",
        "group",
        "as",
        "as_user",
        "sudo",
        "privileged",
        "authority",
    }
)


class Refusal(str, Enum):
    """Why a request was not served. One reason per cause, never merged."""

    FRAME_TOO_LARGE = "frame_too_large"
    MALFORMED_FRAME = "malformed_frame"
    TRUNCATED_FRAME = "truncated_frame"
    TRAILING_BYTES = "trailing_bytes"
    NOT_AN_OBJECT = "not_an_object"
    UNKNOWN_VERB = "unknown_verb"
    CLIENT_ASSERTED_PRINCIPAL = "client_asserted_principal"
    UNDECLARED_ARGUMENT = "undeclared_argument"
    MISSING_ARGUMENT = "missing_argument"
    ARGUMENT_TYPE = "argument_type"
    ARGUMENT_RANGE = "argument_range"
    PRINCIPAL_DENIED = "principal_denied"
    READ_DEADLINE = "read_deadline"
    #: A declared verb whose implementation this build does not provide yet.
    #: A fixed refusal rather than an exception, so the daemon keeps serving.
    VERB_UNAVAILABLE = "verb_unavailable"


class RequestRefused(Exception):
    """Carries the reason, and only bounded facts about what was refused."""

    def __init__(self, refusal: Refusal, detail: str = "") -> None:
        super().__init__(f"{refusal.value}: {detail}" if detail else refusal.value)
        self.refusal = refusal
        self.detail = detail


class ArgumentKind(str, Enum):
    """The whole type system. There is no free-text kind, on purpose."""

    #: A non-negative integer, bounded by the argument's `maximum`.
    ORDINAL = "ordinal"
    #: A boolean.
    FLAG = "flag"
    #: One of the values the argument enumerates.
    ENUM = "enum"
    #: `sha256:` plus sixty-four hex digits. Compared, never dereferenced.
    DIGEST = "digest"
    #: An RFC3339 UTC instant, by grammar.
    TIMESTAMP = "timestamp"
    #: A bounded name: 64 characters from a fixed alphabet. See `_IDENTIFIER`.
    IDENTIFIER = "identifier"


@dataclass(frozen=True)
class Argument:
    name: str
    kind: ArgumentKind
    #: For `ENUM`. The complete set of values this argument may take.
    choices: tuple[str, ...] = ()
    #: For `ORDINAL`. The largest value accepted, inclusive.
    maximum: Optional[int] = None

    def __post_init__(self) -> None:
        if self.name in RESERVED_PRINCIPAL_KEYS:
            raise ValueError(
                f"{self.name!r} is a name a caller would use to assert who they "
                "are. The principal is derived from the socket, and an argument "
                "by this name would make it look negotiable"
            )
        if self.kind is ArgumentKind.ENUM and not self.choices:
            raise ValueError(
                f"{self.name!r} enumerates nothing, so every value would be "
                "out of range or every value would be in it"
            )
        if self.kind is ArgumentKind.ORDINAL and self.maximum is None:
            raise ValueError(
                f"{self.name!r} is an unbounded ordinal; an index with no "
                "ceiling is a number the caller chooses the size of"
            )

    def coerce(self, value: Any) -> Any:
        """Check and return, or refuse. Never adapts a value into range."""

        if self.kind is ArgumentKind.FLAG:
            if not isinstance(value, bool):
                raise RequestRefused(Refusal.ARGUMENT_TYPE, self.name)
            return value
        if self.kind is ArgumentKind.ORDINAL:
            # `bool` is an `int` in Python, and accepting `True` as ordinal 1
            # would let a flag address an interface.
            if isinstance(value, bool) or not isinstance(value, int):
                raise RequestRefused(Refusal.ARGUMENT_TYPE, self.name)
            if value < 0 or (self.maximum is not None and value > self.maximum):
                raise RequestRefused(Refusal.ARGUMENT_RANGE, self.name)
            return value
        if self.kind is ArgumentKind.ENUM:
            if not isinstance(value, str):
                raise RequestRefused(Refusal.ARGUMENT_TYPE, self.name)
            if value not in self.choices:
                raise RequestRefused(Refusal.ARGUMENT_RANGE, self.name)
            return value
        if not isinstance(value, str):
            raise RequestRefused(Refusal.ARGUMENT_TYPE, self.name)
        grammar = {
            ArgumentKind.DIGEST: _DIGEST,
            ArgumentKind.TIMESTAMP: _TIMESTAMP,
            ArgumentKind.IDENTIFIER: _IDENTIFIER,
        }[self.kind]
        if not grammar.match(value):
            raise RequestRefused(Refusal.ARGUMENT_RANGE, self.name)
        return value


@dataclass(frozen=True)
class Verb:
    """One thing a caller may ask for, and who may ask."""

    name: str
    arguments: tuple[Argument, ...] = ()
    admits: frozenset[PrincipalClass] = frozenset()
    #: Whether this verb carries a second, separately validated object.
    #:
    #: A payload sent to a verb that does not declare one is refused: an
    #: object nothing validates is an object that reaches the daemon
    #: unchecked.
    #:
    #: Two verbs declare one, and the count is a fact a reviewer sees rather
    #: than a sentence that went stale. Until Nexus#98 it was one; the second
    #: is `remote.infer`, whose payload is a sealed sanitizer envelope and
    #: the frame it authorises. Both are validated before the handler acts on
    #: them, and `payload_contract` is what says by what.
    accepts_payload: bool = False
    #: **What** validates this verb's payload, named. Required whenever
    #: `accepts_payload` is set, and forbidden otherwise.
    #:
    #: A boolean alone would let a third payload verb appear with nothing
    #: checking its object, and "the payload is validated" would still read
    #: as true of the type. A name has to be filled in by whoever adds one,
    #: and `tests/unit/test_runtime_protocol.py` checks that each named
    #: contract exists.
    payload_contract: str = ""

    def __post_init__(self) -> None:
        if not self.admits:
            raise ValueError(
                f"{self.name!r} admits no principal class. Default deny is a "
                "property of this type rather than a branch somebody writes, "
                "so a verb nobody may call cannot be registered as one anybody can"
            )
        names = [argument.name for argument in self.arguments]
        if len(set(names)) != len(names):
            raise ValueError(f"{self.name!r} declares an argument twice: {names}")
        if self.accepts_payload and not self.payload_contract.strip():
            raise ValueError(
                f"{self.name!r} accepts a payload and names nothing that "
                "validates it. An object nothing validates is an object that "
                "reaches the daemon unchecked, and a verb that could declare "
                "one without saying what checks it is how a third one appears"
            )
        if self.payload_contract.strip() and not self.accepts_payload:
            raise ValueError(
                f"{self.name!r} names a payload contract and accepts no "
                "payload; the contract would describe something that never "
                "arrives"
            )

    def bind(self, raw: Mapping[str, Any]) -> dict:
        """Validate one request's arguments against this verb's declaration."""

        asserted = sorted(set(raw) & RESERVED_PRINCIPAL_KEYS)
        if asserted:
            raise RequestRefused(Refusal.CLIENT_ASSERTED_PRINCIPAL, asserted[0])

        declared = {argument.name: argument for argument in self.arguments}
        undeclared = sorted(set(raw) - set(declared))
        if undeclared:
            # Refused rather than dropped: a caller and a daemon that disagree
            # about what was asked should both find out, not one of them.
            raise RequestRefused(Refusal.UNDECLARED_ARGUMENT, undeclared[0])
        missing = sorted(set(declared) - set(raw))
        if missing:
            raise RequestRefused(Refusal.MISSING_ARGUMENT, missing[0])
        return {name: declared[name].coerce(raw[name]) for name in declared}


class VerbRegistry:
    """The allowlist. A verb that is not in it does not exist."""

    def __init__(self, verbs: Sequence[Verb]) -> None:
        names = [verb.name for verb in verbs]
        if len(set(names)) != len(names):
            raise ValueError(f"a verb is registered twice: {sorted(names)}")
        self._verbs = {verb.name: verb for verb in verbs}

    def __contains__(self, name: object) -> bool:
        return name in self._verbs

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._verbs))

    def resolve(self, name: Any, principal: Principal) -> Verb:
        """Find the verb and check the caller may use it, in that order.

        The principal check comes second so that an unknown verb is reported
        as unknown rather than as a denial -- and an unknown verb's name never
        reaches the ledger, while a denial's does, because a denial names a
        verb this daemon declared.
        """

        if not isinstance(name, str) or name not in self._verbs:
            raise RequestRefused(Refusal.UNKNOWN_VERB, "")
        verb = self._verbs[name]
        if not principal.admits(verb.admits):
            raise RequestRefused(Refusal.PRINCIPAL_DENIED, verb.name)
        return verb


def fingerprint(raw: bytes, *, length: int = 16) -> str:
    """A bounded, fixed-width stand-in for text that must not be stored.

    A rejected frame is attacker-supplied. Writing its contents to the audit
    chain would make the ledger a place anyone who can reach the socket may
    write into. A fingerprint is bounded, is the same for the same input, and
    lets an operator see that one unknown verb arrived four hundred times
    without the ledger carrying four hundred copies of whatever it said.
    """

    return hashlib.sha256(raw).hexdigest()[:length]
