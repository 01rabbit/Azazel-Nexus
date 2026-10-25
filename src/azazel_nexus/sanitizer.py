"""The deterministic sanitizer, which is the one-way egress boundary (#5, E2).

`docs/mio-runtime.md` §6 and `docs/IMPLEMENTATION_SPEC.md` §6.3. This is
implementable now, and separately from the remote path, because the spec says
so: *"Privacy classes, sanitizer policy, and alias key material are
Nexus-local."* Fabric `mio_contracts` owns the frame's canonical **wire
shape**, not what may be in it — so the boundary can exist before the wire
does, and **no egress exists here either way**.

## Deny is the default, not the fallback

    ambiguous classification, invalid structure, or unavailable policy
    resolves to deny remote egress -- deny-on-ambiguity is not a fallback, it
    is the default.

That rule is applied to the *policy* as well as to the frame. A class marked
`remote: allow` with no field allowlist is ambiguous -- it could mean every
field or no field -- so loading it is refused rather than resolved. The
example policy in `IMPLEMENTATION_SPEC.md` §11 writes `P0-public: {remote:
allow}` with no `fields`, and this loader refuses it; that discrepancy is
recorded in `docs/mio-sanitizer.md` rather than settled by guessing which
reading was meant.

## Removed, never transformed

A redacted field does not appear in the output with a mask, a hash or a
placeholder. It is absent. A masked value still says the field was present
and how long it was, and a placeholder invites a reader to ask what it stood
for. `tests/unit/test_sanitizer.py` asserts absence, not masking.

## Aliases are scoped to a mission, and that is the point

    identities are replaced by aliases that are deterministic **only within a
    declared mission or request scope**; the same subject in a different
    mission maps differently, and cross-mission correlation is prohibited.

An alias that were stable across missions would let a remote party join two
missions on a shared subject -- which is the disclosure the aliasing exists to
prevent. So the mission scope is part of the derivation, and a test asserts
that the same subject in two missions produces two aliases.

## Byte-identical, or it cannot be audited

The same frame, policy version and alias key produce the same bytes. A
sanitizer that is not reproducible cannot be audited, so non-determinism is a
defect rather than a tolerance. Nothing here reads a clock, a random source,
an environment variable, or a dictionary's insertion order.

## A budget is not a truncation

    Exceeding a budget is a local fallback, never a truncation that is passed
    off as a complete answer.

A frame over `max_bytes` is denied whole. There is no path that shortens one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Mapping, Optional, Sequence

__all__ = [
    "PrivacyClass",
    "Redaction",
    "SanitizerDecision",
    "SanitizerPolicy",
    "SanitizerRefused",
    "count_bucket",
    "sanitize",
    "time_bucket",
]


class PrivacyClass(str, Enum):
    """`docs/IMPLEMENTATION_SPEC.md` §6.3. Eligibility, never authority."""

    P0_PUBLIC = "P0-public"
    P1_SANITIZED = "P1-sanitized"
    P2_MISSION = "P2-mission"
    P3_RESTRICTED = "P3-restricted"


class SanitizerRefused(Exception):
    """The policy cannot be loaded. It is never resolved by guessing."""


#: Classes that may never leave, whatever a policy says. `P3-restricted` is
#: "never remote" in the contract, and `P2-mission` is "local only unless an
#: explicit policy transformation exists" -- and no such transformation exists
#: in this build, so it is local only here.
NEVER_REMOTE = frozenset({PrivacyClass.P2_MISSION, PrivacyClass.P3_RESTRICTED})


@dataclass(frozen=True)
class SanitizerPolicy:
    """The loaded policy. Every class it does not allow, it denies."""

    version: str
    #: Class -> the exact set of field names that class may carry.
    allowed: Mapping[PrivacyClass, frozenset[str]]
    #: Field names removed outright, whatever class they appear under.
    redactions: frozenset[str]
    #: Field names whose value is replaced by a mission-scoped alias.
    aliases: frozenset[str]
    #: Field names whose value is replaced by a coarse time bucket.
    time_buckets: frozenset[str]
    #: Field names whose value is replaced by a coarse count bucket.
    count_buckets: frozenset[str]
    max_bytes: int

    @classmethod
    def from_mapping(cls, raw: Mapping) -> "SanitizerPolicy":
        """Load a policy, refusing anything ambiguous.

        Takes an already-parsed mapping rather than a path. The contract's
        example is YAML and this package carries no YAML parser -- adding one
        would put a dependency on the CORE path, which `pyproject.toml`
        forbids and says why. Where the policy lives and in what syntax is a
        packaging decision recorded in `docs/mio-sanitizer.md`, not one this
        module makes by reaching for a parser.
        """

        version = raw.get("version")
        if not isinstance(version, str) or not version.strip():
            raise SanitizerRefused(
                "a sanitizer policy names its version; an unversioned policy "
                "cannot be part of a reproducible decision"
            )
        if raw.get("remote_default") != "deny":
            raise SanitizerRefused(
                f"remote_default must be 'deny'; got {raw.get('remote_default')!r}. "
                "Deny-on-ambiguity is the default, not a fallback, and a policy "
                "that starts from allow cannot express it"
            )

        classes = raw.get("classes")
        if not isinstance(classes, Mapping):
            raise SanitizerRefused("a sanitizer policy maps privacy classes to rules")

        allowed: dict[PrivacyClass, frozenset[str]] = {}
        for name, rule in classes.items():
            try:
                privacy_class = PrivacyClass(name)
            except ValueError as exc:
                raise SanitizerRefused(
                    f"{name!r} is not a privacy class this product defines"
                ) from exc
            if not isinstance(rule, Mapping):
                raise SanitizerRefused(f"the rule for {name} is a mapping")
            remote = rule.get("remote")
            if remote == "deny":
                continue
            if remote != "allow":
                raise SanitizerRefused(
                    f"the rule for {name} says remote={remote!r}; a rule that is "
                    "neither allow nor deny is ambiguous, and ambiguity denies"
                )
            if privacy_class in NEVER_REMOTE:
                raise SanitizerRefused(
                    f"{name} is never remote in this build; a policy that allows "
                    "it contradicts the contract rather than configuring it"
                )
            fields = rule.get("fields")
            if not isinstance(fields, list) or not fields:
                raise SanitizerRefused(
                    f"{name} is allowed remote with no field allowlist, which could "
                    "mean every field or no field; an ambiguous class denies rather "
                    "than resolving. See docs/mio-sanitizer.md"
                )
            if any(not isinstance(field, str) or not field.strip() for field in fields):
                raise SanitizerRefused(f"the field allowlist for {name} names strings")
            allowed[privacy_class] = frozenset(fields)

        limits = raw.get("limits")
        if not isinstance(limits, Mapping) or not isinstance(limits.get("max_bytes"), int):
            raise SanitizerRefused("a sanitizer policy declares limits.max_bytes")
        if limits["max_bytes"] < 1:
            raise SanitizerRefused("max_bytes is a positive number of bytes")

        return cls(
            version=version,
            allowed=allowed,
            redactions=_names(raw, "redactions"),
            aliases=_names(raw, "aliases"),
            time_buckets=_names(raw, "time_buckets"),
            count_buckets=_names(raw, "count_buckets"),
            max_bytes=limits["max_bytes"],
        )


def _names(raw: Mapping, key: str) -> frozenset[str]:
    values = raw.get(key, [])
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not value.strip() for value in values
    ):
        raise SanitizerRefused(f"{key} is a list of field names")
    return frozenset(values)


@dataclass(frozen=True)
class Redaction:
    """The local record. Only its *reference* ever travels."""

    record_id: str
    policy_version: str
    mission: str
    removed: tuple[str, ...]
    aliased: tuple[str, ...]
    bucketed: tuple[str, ...]

    def as_event(self) -> dict:
        return {
            "event_type": "mio.sanitizer.redaction",
            "redaction_record_id": self.record_id,
            "sanitizer_policy_version": self.policy_version,
            "mission": self.mission,
            "removed": list(self.removed),
            "aliased": list(self.aliased),
            "bucketed": list(self.bucketed),
        }


@dataclass(frozen=True)
class SanitizerDecision:
    """Allowed with a frame, or denied with nothing.

    When `allowed` is `False`, `frame` is `None` -- not an empty mapping, not a
    partial one. Restricted frames and sanitizer failures produce **zero**
    remote egress, and a caller that had a frame object to reach for would be
    one refactor away from sending it.
    """

    allowed: bool
    reason: str
    frame: Optional[bytes] = None
    redaction: Optional[Redaction] = None
    request_fingerprint: Optional[str] = None

    def as_event(self) -> dict:
        return {
            "event_type": "mio.sanitizer.decision",
            "allowed": self.allowed,
            "reason": self.reason,
            "request_fingerprint": self.request_fingerprint,
            "redaction_record_id": self.redaction.record_id if self.redaction else None,
            "frame_bytes": len(self.frame) if self.frame else 0,
        }


_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})\Z")

#: Coarse count buckets, low to high. The boundaries are inclusive floors.
_COUNT_BUCKETS = ((0, "0"), (1, "1"), (2, "2-5"), (6, "6-20"), (21, "21-100"), (101, ">100"))


def time_bucket(instant: str) -> str:
    """Round an instant down to its UTC hour. Coarse, and never a clock read."""

    if not _INSTANT.fullmatch(instant):
        raise SanitizerRefused(f"{instant!r} is not an instant this can coarsen")
    text = instant[:-1] + "+00:00" if instant.endswith("Z") else instant
    parsed = datetime.fromisoformat(text).astimezone(timezone.utc)
    return parsed.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


def count_bucket(count: int) -> str:
    """Replace an exact count with the range it falls in."""

    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise SanitizerRefused(f"{count!r} is not a count this can coarsen")
    label = "0"
    for floor, name in _COUNT_BUCKETS:
        if count >= floor:
            label = name
    return label


def sanitize(
    frame: Mapping,
    *,
    privacy_class: PrivacyClass,
    policy: SanitizerPolicy,
    mission: str,
    alias_key: bytes,
) -> SanitizerDecision:
    """Build a remote frame, or deny. Never raises for the caller."""

    if not mission.strip():
        return _deny(
            "no mission scope was declared; aliases are deterministic only within "
            "a declared scope, and an undeclared one cannot be that"
        )
    if not alias_key:
        return _deny("no alias key was supplied; identities cannot be aliased without one")
    if privacy_class in NEVER_REMOTE:
        return _deny(
            f"{privacy_class.value} is not remote-eligible; no egress occurs at all"
        )
    allowlist = policy.allowed.get(privacy_class)
    if allowlist is None:
        return _deny(
            f"{privacy_class.value} is not allowed remote by policy "
            f"{policy.version}; anything unlisted is denied"
        )

    removed: list[str] = []
    aliased: list[str] = []
    bucketed: list[str] = []
    body: dict[str, object] = {}

    for name in sorted(frame):
        value = frame[name]
        # Redaction comes first: a field named here is removed whatever the
        # allowlist says, because "remove the secret" and "deny the frame
        # containing a secret" would otherwise be the same rule, and every
        # real frame would be denied.
        if name in policy.redactions:
            removed.append(name)
            continue
        if name not in allowlist:
            return _deny(
                f"field {name!r} is not in the allowlist for {privacy_class.value} "
                f"under policy {policy.version}; anything unlisted is denied"
            )
        try:
            if name in policy.aliases:
                body[name] = _alias(alias_key, mission, value)
                aliased.append(name)
            elif name in policy.time_buckets:
                body[name] = time_bucket(str(value))
                bucketed.append(name)
            elif name in policy.count_buckets:
                body[name] = count_bucket(value)
                bucketed.append(name)
            else:
                body[name] = value
        except SanitizerRefused as exc:
            return _deny(f"field {name!r} could not be coarsened: {exc}")

    # Both canonicalisations are guarded together. A value that does not
    # serialize must deny, and computing the record id first -- outside the
    # guard -- would let it raise out of `sanitize`, which is the one thing
    # this function must not do to a caller.
    try:
        record_id = _digest(
            _canonical(
                {
                    "policy_version": policy.version,
                    "mission": mission,
                    "removed": tuple(removed),
                    "aliased": tuple(aliased),
                    "bucketed": tuple(bucketed),
                    "body": body,
                }
            )
        )
        payload = _canonical(
            {
                "sanitizer_policy_version": policy.version,
                "remote_privacy_class": privacy_class.value,
                "redaction_record_id": record_id,
                "body": body,
            }
        )
    except (TypeError, ValueError) as exc:
        return _deny(f"the frame does not serialize, which is invalid structure: {exc}")

    record = Redaction(
        record_id=record_id,
        policy_version=policy.version,
        mission=mission,
        removed=tuple(removed),
        aliased=tuple(aliased),
        bucketed=tuple(bucketed),
    )

    if len(payload) > policy.max_bytes:
        return _deny(
            f"the sanitized frame is {len(payload)} bytes against a {policy.max_bytes} "
            "byte budget; a budget is a local fallback and never a truncation passed "
            "off as a complete answer"
        )

    return SanitizerDecision(
        allowed=True,
        reason=(
            f"{len(body)} field(s) admitted for {privacy_class.value} under policy "
            f"{policy.version}; {len(removed)} removed, {len(aliased)} aliased, "
            f"{len(bucketed)} bucketed"
        ),
        frame=payload,
        redaction=record,
        request_fingerprint=_digest(payload),
    )


def _deny(reason: str) -> SanitizerDecision:
    return SanitizerDecision(allowed=False, reason=reason, frame=None)


def _alias(alias_key: bytes, mission: str, value: object) -> str:
    """A mission-scoped alias. The mission is *in* the derivation, not beside it.

    The scope and the value are length-prefixed rather than joined by a
    separator, so that two different (mission, value) pairs cannot produce the
    same input bytes -- which would give one subject two missions' alias, the
    exact correlation the scoping forbids.
    """

    scope = mission.encode("utf-8")
    subject = str(value).encode("utf-8")
    message = (
        len(scope).to_bytes(4, "big") + scope + len(subject).to_bytes(4, "big") + subject
    )
    return "alias:" + hmac.new(alias_key, message, hashlib.sha256).hexdigest()[:16]


def _canonical(payload: Mapping) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_no_default
    ).encode("utf-8")


def _no_default(value: object) -> object:
    if isinstance(value, (tuple, list)):
        return list(value)
    raise TypeError(f"{type(value).__name__} has no canonical form in a remote frame")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()
