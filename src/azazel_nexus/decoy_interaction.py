"""A reach of a Deception Lite decoy, as Nexus evidence (#196 P2).

Design: `docs/deception-redirect-prerequisites.md` §6 (P2), §7 Q8 and §11.

Each time something reaches a decoy, the decoy reports one Fabric
`EnvironmentEvent` (`schema_version: environment-event/v0.1`,
`event_type: "interaction"`) to the intake, which stores it as a **Nexus
observation**: it is not an Edge finding, it never opens or updates an Edge
incident, and nothing about it flows back to Edge.

## No field the sender may fill freely

A decoy is the one Nexus component an attacker talks to, so its account is
the likeliest to be taken. What it reports is therefore held to values the
intake already knows, not merely to a format; a format check alone let an
address through as a decimal or hex number, or a host name (review of #269).

* `event_id` -- checked for its form (`evt-` and 32 lower-case hex digits),
  then **replaced by the intake** with its own random id. What the decoy sent
  is not stored.
* `environment_id` -- exactly one of the decoy names in `DECOY_NAMES` (fixed
  in code until the catalogue reaches the intake).
* `package_id` -- exactly `PACKAGE_ID`. A Lite decoy is an in-code responder,
  not an AZ-06 package; the catalogue generation is bound in a later phase.
* `node_id` -- exactly the intake's own node id (`LOCAL_NODE_ID` until the
  commissioned node identity reaches the intake).
* `observed_at` -- whole seconds, UTC, and within `MAX_SKEW_S` of the intake's
  clock when it arrives.
* `metadata` -- exactly `bytes_received` (0 to `MAX_BYTES_RECEIVED`, the
  decoy's read ceiling), `truncated` (only at that ceiling) and `responder`
  (one of `RESPONDER_NAMES`).

What remains for a sender to choose is a name and a responder among four
each, a byte count, a flag and a second within a ten-minute window: about
thirty bits per event, at the intake's rate limit. That is a bounded side channel,
not room for a payload, a credential or an address (§7 Q8). An address-like
spelling is also refused as `DECOY_ADDRESS` as a second check, but the
guarantee is the exact match, not that check.

Fabric is not imported: the shape is a strict subset of the rc5 model, and a
reference test validates it against Fabric when the pinned Fabric is present.
This module grants no authority and opens nothing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

__all__ = [
    "DECOY_NAMES",
    "DECOY_REFUSAL_CODES",
    "EVENT_TYPE",
    "LOCAL_NODE_ID",
    "MAX_BYTES_RECEIVED",
    "MAX_INTERACTION_LINE",
    "MAX_SKEW_S",
    "PACKAGE_ID",
    "RECORD_KIND",
    "RESPONDER_NAMES",
    "SCHEMA_VERSION",
    "DecoyEventRefused",
    "DecoyInteraction",
    "DecoyInteractionRecord",
    "build_interaction",
    "incidents_near",
    "new_event_id",
    "parse_interaction",
]

#: Fabric's `EnvironmentEvent` schema version (Azazel-Fabric v0.10.0).
SCHEMA_VERSION = "environment-event/v0.1"
#: The only event type a decoy reports.
EVENT_TYPE = "interaction"
#: The decoy's read ceiling (`decoy_loopback.MAX_READ_BYTES`; a test keeps
#: them equal). A decoy that read more kept more than it may.
MAX_BYTES_RECEIVED = 4096
#: The in-code responders (`decoy_loopback.RESPONDERS`; a test keeps them
#: equal). A name, never a banner.
RESPONDER_NAMES = frozenset({"ssh-banner", "smtp-banner", "http-banner", "telnet-banner"})
#: The decoy names an interaction may carry. Fixed in code: the catalogue
#: does not reach the intake in this build, and a name the sender could
#: choose freely would be a field for anything.
DECOY_NAMES = frozenset({"ssh-decoy", "smtp-decoy", "http-decoy", "telnet-decoy"})
#: `package_id` for every Lite interaction: in-code responders, no package.
PACKAGE_ID = "azazel-nexus/deception-lite"
#: `node_id` until the commissioned node identity reaches the intake: the
#: record lives on, and was written by, the node that stores it.
LOCAL_NODE_ID = "local"
#: How far `observed_at` may be from the intake's clock on arrival.
MAX_SKEW_S = 300
#: One interaction line, newline excluded. The closed shape is far smaller.
MAX_INTERACTION_LINE = 1024
#: The label of a stored record. An Edge evidence record has no `kind`.
RECORD_KIND = "nexus.deception-lite.interaction"
#: How far around an incident's first and last sighting an interaction is
#: considered near it, by default.
DEFAULT_WINDOW_S = 300

DECOY_REFUSAL_CODES = frozenset({
    "DECOY_TOO_LARGE",
    "DECOY_JSON",
    "DECOY_SHAPE",
    "DECOY_TYPE",
    "DECOY_RANGE",
    "DECOY_ADDRESS",
    "DECOY_CLOCK",
})

_TOP_KEYS = frozenset({
    "schema_version", "event_id", "environment_id", "package_id", "node_id",
    "event_type", "observed_at", "evidence_refs", "metadata",
})
_METADATA_KEYS = frozenset({"bytes_received", "truncated", "responder"})

_EVENT_ID = re.compile(r"evt-[0-9a-f]{32}", re.ASCII)
_OBSERVED_AT = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", re.ASCII)

#: What an address looks like inside a string: dotted or dashed IPv4,
#: anything with two or more colons between hex groups, a MAC address.
_ADDRESS_LIKE = (
    re.compile(r"(?<![0-9])[0-9]{1,3}(?:[._-][0-9]{1,3}){3}(?![0-9])", re.ASCII),
    re.compile(r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}", re.ASCII),
    re.compile(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}", re.ASCII),
)


class DecoyEventRefused(ValueError):
    """Only a fixed code leaves this boundary, never the input."""

    def __init__(self, code: str):
        self.code = code if code in DECOY_REFUSAL_CODES else "DECOY_SHAPE"
        super().__init__(self.code)


def _require(ok, code="DECOY_SHAPE"):
    if not ok:
        raise DecoyEventRefused(code)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def new_event_id() -> str:
    """A fresh event id: random, so it says nothing about the peer."""

    return "evt-" + secrets.token_hex(16)


def _looks_like_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        pass
    return any(pattern.search(value) for pattern in _ADDRESS_LIKE)


def _string(value, *, limit=128):
    _require(type(value) is str, "DECOY_TYPE")
    _require(len(value) <= limit, "DECOY_RANGE")
    # The second check: an address is named as one. The exact matches below
    # are what make it impossible to carry one in any spelling.
    _require(not _looks_like_address(value), "DECOY_ADDRESS")


def _one_of(value, allowed):
    _string(value)
    _require(value in allowed, "DECOY_RANGE")


def _validate(value, *, decoy_names, node_id, now) -> dict:
    _require(type(value) is dict)
    _require(set(value) == _TOP_KEYS)
    _require(value["schema_version"] == SCHEMA_VERSION, "DECOY_RANGE")
    _require(value["event_type"] == EVENT_TYPE, "DECOY_RANGE")
    _string(value["event_id"])
    _require(_EVENT_ID.fullmatch(value["event_id"]) is not None, "DECOY_RANGE")
    _one_of(value["environment_id"], decoy_names)
    _one_of(value["package_id"], {PACKAGE_ID})
    _one_of(value["node_id"], {node_id})
    observed = value["observed_at"]
    _require(type(observed) is str, "DECOY_TYPE")
    _require(len(observed) == 20 and _OBSERVED_AT.fullmatch(observed) is not None,
             "DECOY_RANGE")
    try:
        instant = datetime.strptime(observed, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise DecoyEventRefused("DECOY_RANGE") from None
    if now is not None:
        _require(abs(instant.timestamp() - now) <= MAX_SKEW_S, "DECOY_CLOCK")
    _require(type(value["evidence_refs"]) is list, "DECOY_TYPE")
    _require(value["evidence_refs"] == [], "DECOY_RANGE")
    metadata = value["metadata"]
    _require(type(metadata) is dict, "DECOY_TYPE")
    _require(set(metadata) == _METADATA_KEYS)
    received, truncated = metadata["bytes_received"], metadata["truncated"]
    _require(type(received) is int, "DECOY_TYPE")
    _require(0 <= received <= MAX_BYTES_RECEIVED, "DECOY_RANGE")
    _require(type(truncated) is bool, "DECOY_TYPE")
    # The decoy stops reading at its ceiling and only then calls it truncated.
    _require(not truncated or received == MAX_BYTES_RECEIVED, "DECOY_RANGE")
    _one_of(metadata["responder"], RESPONDER_NAMES)
    return value


@dataclass(frozen=True)
class DecoyInteraction:
    """One validated interaction, held as its canonical bytes."""

    encoded: bytes

    def as_dict(self) -> dict:
        return json.loads(self.encoded)

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.encoded).hexdigest()

    @property
    def line(self) -> bytes:
        """What a decoy sends to the intake: one line, one connection."""
        return self.encoded + b"\n"


def build_interaction(
    *,
    decoy_name: str,
    observed_at: str,
    bytes_received: int,
    truncated: bool,
    responder: str,
    event_id: str | None = None,
    node_id: str = LOCAL_NODE_ID,
    decoy_names: frozenset = DECOY_NAMES,
) -> DecoyInteraction:
    """The event a decoy reports for one reach; refused unless it is closed.

    The decoy's observation has no payload and no peer field, so neither can
    be passed here. Every identifier is fixed or one of a fixed set.
    """

    event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id if event_id is not None else new_event_id(),
        "environment_id": decoy_name,
        "package_id": PACKAGE_ID,
        "node_id": node_id,
        "event_type": EVENT_TYPE,
        "observed_at": observed_at,
        "evidence_refs": [],
        "metadata": {
            "bytes_received": bytes_received,
            "truncated": truncated,
            "responder": responder,
        },
    }
    return DecoyInteraction(_canonical(
        _validate(event, decoy_names=decoy_names, node_id=node_id, now=None)))


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "DECOY_JSON")
        result[key] = value
    return result


def _constant(_):
    raise DecoyEventRefused("DECOY_JSON")


def parse_interaction(
    raw: bytes,
    *,
    now: float | None = None,
    decoy_names: frozenset = DECOY_NAMES,
    node_id: str = LOCAL_NODE_ID,
    event_id: Callable[[], str] | None = None,
) -> DecoyInteraction:
    """One line from the decoy socket, newline removed; refused as a whole.

    The intake passes its clock (`now`) and an id source (`event_id`): the
    stored event carries the intake's id, never the one the sender chose.
    """

    _require(type(raw) is bytes, "DECOY_TYPE")
    _require(len(raw) <= MAX_INTERACTION_LINE, "DECOY_TOO_LARGE")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, DecoyEventRefused):
            raise
        raise DecoyEventRefused("DECOY_JSON") from None
    value = _validate(value, decoy_names=decoy_names, node_id=node_id, now=now)
    if event_id is not None:
        value["event_id"] = event_id()
        _require(_EVENT_ID.fullmatch(value["event_id"]) is not None, "DECOY_RANGE")
    return DecoyInteraction(_canonical(value))


@dataclass(frozen=True)
class DecoyInteractionRecord:
    """What the intake stores: the event, its digest, when it arrived.

    Labelled so that no reader can take it for Edge's: `kind` names it a
    Nexus Deception Lite observation and `edge_observation` is `false`. An
    Edge evidence record (`edge_intake.EvidenceRecord`) has neither field.
    """

    interaction: DecoyInteraction
    received_at: float

    @classmethod
    def receive(cls, interaction: DecoyInteraction, clock: Callable[[], float]):
        return cls(interaction, clock())

    @property
    def digest(self) -> str:
        return self.interaction.digest

    def as_dict(self) -> dict:
        return {
            "kind": RECORD_KIND,
            "observer": "azazel-nexus",
            "edge_observation": False,
            "environment_event": self.interaction.as_dict(),
            "digest": self.digest,
            "received_at": self.received_at,
        }


def incidents_near(
    record: Mapping,
    incidents: Iterable[Mapping],
    *,
    decoy_ports: Mapping[str, int],
    window_s: float = DEFAULT_WINDOW_S,
) -> list[str]:
    """Edge incidents an interaction may belong to, by decoy and time only.

    `record` is a stored interaction (`DecoyInteractionRecord.as_dict()`);
    `incidents` are incident transitions as the intake's ledger records them
    (`incident_id`, `target_port`, `first_seen`, `last_seen`, all on the
    intake's clock, as `received_at` is). An incident is near when its target
    port is the decoy's catalogued port and the interaction arrived within
    `window_s` of its first-to-last sighting. No address is compared: the
    interaction carries none (§7 Q8). The answer is a correlation for a
    reader, never an input to Edge and never a change to the incident.
    """

    if (not isinstance(record, Mapping) or record.get("kind") != RECORD_KIND
            or record.get("edge_observation") is not False):
        return []
    port = decoy_ports.get(record["environment_event"]["environment_id"])
    at = record["received_at"]
    if (type(port) is not int or type(at) not in (int, float) or not math.isfinite(at)
            or not math.isfinite(window_s) or window_s < 0):
        return []
    near = set()
    for incident in incidents:
        try:
            if (incident["target_port"] == port
                    and incident["first_seen"] - window_s <= at <= incident["last_seen"] + window_s):
                near.add(incident["incident_id"])
        except (KeyError, TypeError):
            continue
    return sorted(near)
