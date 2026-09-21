"""The embedded Tactical Decoy Runtime, before it is allowed to exist (#54, E3).

This module is the lifecycle and the refusals around Deception Lite. It does
not start anything, bind anything, or change anything outside this process,
and `tests/unit/test_decoy.py` scans for the absence of every verb that
could.

## Initially disabled, and that is a state rather than a setting

A decoy begins `DISABLED`. It becomes `ELIGIBLE` only when **all** of an
operator commissioning record, a verified generation digest, and a passing
isolation check are present -- and `EXPOSED` only when an operator then
exposes an eligible decoy. "It is in the configuration" is not a reason to be
listening.

## Nothing arbitrary

    No API exposes shell command execution, arbitrary policy upload,
    arbitrary container start, packet capture retrieval, or a general
    network-control primitive.
    -- docs/IMPLEMENTATION_SPEC.md §7

The catalogue is data bound to a verified generation; the runtime accepts only
what the catalogue names, exactly. An image, a command, an address or a port
that is not in it is refused -- not sanitised, not defaulted.

Four addresses are refused whatever a catalogue says, because a catalogue that
could name them would be a general-network primitive wearing a decoy's
clothes: the unspecified addresses `0.0.0.0` and `::`, loopback, and anything
outside the decoy bridge prefix the commissioning declared. Privileged ports
are refused for the same reason -- binding one needs a capability this runtime
must not have.

## Redirect is a different question, and the answer here is always no

`docs/IMPLEMENTATION_SPEC.md` §9 has `redirect_to_lite` as a policy action the
**arbiter** issues. Nothing in this stage grants it: `redirect_eligible` is
derived, is `False` in every state this module can produce, and the reason
says so. An exposed decoy is an observation surface, not an enforcement one.

## A failure stops the decoy, not the node

Quarantine stops and isolates one decoy. It never touches the deterministic
path, and it **preserves telemetry** (§7's degradation row) -- the record of
what happened is the reason the failure is worth anything.

## The audit keeps provenance, never secret material

A decoy's whole purpose is to be reached by someone hostile. What they send is
not this node's to keep: the audit records that a decoy was reached, which one,
under which generation, and why something was refused. It does not record
credentials, and a static scan refuses a field that would hold one.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional, Sequence

from .content_store import parse_digest

__all__ = [
    "DECOY_BRIDGE",
    "DecoyCatalogue",
    "DecoyEntry",
    "DecoyRefused",
    "DecoyState",
    "DecoyStatus",
    "MAX_DECOYS",
    "MIN_PORT",
    "Commissioning",
    "IsolationCheck",
    "evaluate",
]

#: The only bridge a Lite decoy lives on (`IMPLEMENTATION_SPEC.md` §9).
DECOY_BRIDGE = "az-decoy0"

#: `IMPLEMENTATION_SPEC.md` §2.1: `lite` and `standard` each permit "up to
#: three Lite decoys". Three is the ceiling in every envelope, not a default.
MAX_DECOYS = 3

#: Below this a bind needs a capability this runtime must not hold.
MIN_PORT = 1024


class DecoyRefused(Exception):
    """The catalogue, the entry, or the transition is not admissible."""


class DecoyState(str, Enum):
    """Where one decoy is. `DISABLED` is where every decoy starts."""

    #: Nothing is listening and nothing has been approved.
    DISABLED = "disabled"
    #: Commissioned, generation verified, isolation passing. Not listening.
    ELIGIBLE = "eligible"
    #: Listening on exactly the address and port the catalogue names.
    EXPOSED = "exposed"
    #: It was running and is not trusted. Stopped and isolated.
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class DecoyEntry:
    """One approved decoy. Every field is named, none is inferred."""

    name: str
    #: The container or process image, by digest. Never a tag, never a name:
    #: a tag is a pointer somebody else can move.
    image_digest: str
    listen_address: str
    port: int

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise DecoyRefused("a decoy entry is named")
        parse_digest(self.image_digest)
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise DecoyRefused(f"a port is a whole number; got {self.port!r}")
        if self.port < MIN_PORT or self.port > 65535:
            raise DecoyRefused(
                f"port {self.port} is outside {MIN_PORT}-65535; a privileged port "
                "needs a capability this runtime must not hold"
            )
        try:
            address = ipaddress.ip_address(self.listen_address)
        except ValueError as exc:
            raise DecoyRefused(f"{self.listen_address!r} is not an address: {exc}") from exc
        if address.is_unspecified:
            raise DecoyRefused(
                f"{self.listen_address} is the unspecified address; binding it "
                "listens on every interface, which is a general-network primitive "
                "and not a decoy"
            )
        if address.is_loopback:
            raise DecoyRefused(
                f"{self.listen_address} is loopback; a decoy nobody can reach is "
                "not a decoy, and a decoy on loopback is reachable by this host "
                "alone"
            )

    def as_event(self) -> dict:
        """Provenance. Never what anyone sent to it.

        The field is `decoy_name` rather than `decoy` because the bare word is
        a **retired role word** in this repository -- it was an interface role
        in Azazel-Boot's old commissioning list -- and
        `tests/unit/test_commissioning.py` refuses it as a string value
        anywhere in the package. The noun is still current product vocabulary
        (`IMPLEMENTATION_SPEC.md` §2.1 counts "Lite decoys"); what was retired
        is its use as a role, and the exact-match rule is how this repository
        already keeps `capture_spool` while refusing `capture`.
        """

        return {
            "decoy_name": self.name,
            "image_digest": self.image_digest,
            "listen_address": self.listen_address,
            "port": self.port,
        }


@dataclass(frozen=True)
class Commissioning:
    """What the operator confirmed, and the generation it was confirmed under."""

    record_digest: str
    generation_digest: str
    #: The prefix the decoy bridge was commissioned with. An entry outside it
    #: is refused; there is no default prefix, because a default would be a
    #: network this product chose on an operator's behalf.
    bridge_prefix: str
    actor: str

    def __post_init__(self) -> None:
        parse_digest(self.record_digest)
        parse_digest(self.generation_digest)
        if not self.actor.strip():
            raise DecoyRefused("a commissioning records who performed it")
        try:
            ipaddress.ip_network(self.bridge_prefix, strict=True)
        except ValueError as exc:
            raise DecoyRefused(
                f"{self.bridge_prefix!r} is not a network prefix: {exc}"
            ) from exc

    def contains(self, address: str) -> bool:
        return ipaddress.ip_address(address) in ipaddress.ip_network(self.bridge_prefix)


@dataclass(frozen=True)
class IsolationCheck:
    """The result of actively testing the denied paths (§9).

    `passed` is `Optional` on purpose. `None` is "nobody ran it", which is not
    a pass and is not a failure -- and the three read differently to an
    operator. `docs/hardware-gates.md` `HG-06` tracks running it for real:
    nothing in CI can establish that a kernel refused to forward a packet.
    """

    passed: Optional[bool]
    checked_at: Optional[str] = None
    #: Which denied paths were tested. An empty tuple with `passed=True` is
    #: refused: a check that tested nothing did not pass.
    denied_paths: tuple[str, ...] = ()
    detail: str = ""

    def refusal(self) -> Optional[str]:
        if self.passed is None:
            return (
                "no isolation check has been run; a decoy is not exposed because "
                "nobody looked, and absence of a check is not a pass"
            )
        if not self.passed:
            return f"the isolation check failed: {self.detail or 'no detail recorded'}"
        if not self.denied_paths:
            return (
                "the isolation check reports passing having tested no denied path; "
                "a check that tested nothing did not pass"
            )
        if not (self.checked_at or "").strip():
            return "a passing isolation check records when it ran"
        return None


@dataclass(frozen=True)
class DecoyCatalogue:
    """The fixed allowlist. Nothing outside it can be named."""

    entries: tuple[DecoyEntry, ...]

    @classmethod
    def of(cls, entries: Sequence[DecoyEntry]) -> "DecoyCatalogue":
        if len(entries) > MAX_DECOYS:
            raise DecoyRefused(
                f"{len(entries)} decoys were named and the ceiling is {MAX_DECOYS} "
                "in every envelope; a larger set is refused rather than truncated"
            )
        if not entries:
            raise DecoyRefused(
                "an empty catalogue approves nothing; that is the correct state "
                "for a node with no decoys and is expressed by having no "
                "catalogue, not by having an empty one"
            )
        names = [entry.name for entry in entries]
        if len(set(names)) != len(names):
            raise DecoyRefused(f"two decoys share a name: {sorted(names)}")
        bindings = [(entry.listen_address, entry.port) for entry in entries]
        if len(set(bindings)) != len(bindings):
            raise DecoyRefused(
                f"two decoys claim one address and port: {sorted(map(str, bindings))}"
            )
        return cls(tuple(entries))

    def entry(self, name: str) -> DecoyEntry:
        for entry in self.entries:
            if entry.name == name:
                return entry
        raise DecoyRefused(
            f"{name!r} is not in the catalogue; the runtime starts what the "
            "catalogue names and nothing else"
        )


@dataclass(frozen=True)
class DecoyStatus:
    """What one decoy is, and why it is not more than that."""

    decoy: str
    state: DecoyState
    reason: str
    generation_digest: Optional[str] = None

    def blocks_deterministic_path(self) -> bool:
        """Always False. A decoy failing is a decoy failing."""

        return False

    @property
    def redirect_eligible(self) -> bool:
        """Always False in this build, derived rather than stored.

        Redirect is the arbiter's to issue (`IMPLEMENTATION_SPEC.md` §9) and
        nothing in this stage grants it. Derived so that a future change has
        to be written deliberately rather than by setting a field.
        """

        return False

    @property
    def exposed(self) -> bool:
        return self.state is DecoyState.EXPOSED

    def as_event(self) -> dict:
        return {
            "event_type": "deception.lite.state",
            "decoy_name": self.decoy,
            "state": self.state.value,
            "reason": self.reason,
            "generation_digest": self.generation_digest,
            "redirect_eligible": self.redirect_eligible,
        }


def evaluate(
    name: str,
    *,
    catalogue: Optional[DecoyCatalogue],
    commissioning: Optional[Commissioning],
    isolation: IsolationCheck,
    operator_exposed: bool = False,
    quarantine_reason: Optional[str] = None,
) -> DecoyStatus:
    """What one decoy may be right now. Never raises for the node.

    Checked in the order a refusal is most specific: a quarantined decoy is
    quarantined whatever else is true, and everything else descends from
    "nothing is approved" to "an operator has not exposed it yet".
    """

    if quarantine_reason is not None:
        return DecoyStatus(
            decoy=name,
            state=DecoyState.QUARANTINED,
            reason=(
                f"stopped and isolated: {quarantine_reason}. Telemetry is kept; "
                "the deterministic path is untouched"
            ),
            generation_digest=commissioning.generation_digest if commissioning else None,
        )

    if catalogue is None:
        return _disabled(name, "no decoy catalogue is present; nothing is approved")
    try:
        entry = catalogue.entry(name)
    except DecoyRefused as exc:
        return _disabled(name, str(exc))

    if commissioning is None:
        return _disabled(
            name,
            "no operator commissioning is present; being in a catalogue is not "
            "being approved to listen",
        )
    if not commissioning.contains(entry.listen_address):
        return _disabled(
            name,
            f"{entry.listen_address} is outside the commissioned bridge prefix "
            f"{commissioning.bridge_prefix}; a decoy lives on {DECOY_BRIDGE} and "
            "nowhere else",
        )

    refusal = isolation.refusal()
    if refusal is not None:
        return DecoyStatus(
            decoy=name,
            state=DecoyState.DISABLED,
            reason=refusal,
            generation_digest=commissioning.generation_digest,
        )

    if not operator_exposed:
        return DecoyStatus(
            decoy=name,
            state=DecoyState.ELIGIBLE,
            reason=(
                "commissioned, generation verified and isolation passing; an "
                "operator has not exposed it, and eligibility is not exposure"
            ),
            generation_digest=commissioning.generation_digest,
        )

    return DecoyStatus(
        decoy=name,
        state=DecoyState.EXPOSED,
        reason=(
            f"listening on {entry.listen_address}:{entry.port} under generation "
            f"{commissioning.generation_digest}; an observation surface, not an "
            "enforcement one"
        ),
        generation_digest=commissioning.generation_digest,
    )


def _disabled(name: str, reason: str) -> DecoyStatus:
    return DecoyStatus(decoy=name, state=DecoyState.DISABLED, reason=reason)
