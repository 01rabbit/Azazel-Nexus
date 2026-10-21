"""A reach of a Deception Lite decoy, as Nexus evidence (#196 P2).

Design: `docs/deception-redirect-prerequisites.md` §6 (P2) and §7 Q8.

Each time something reaches a decoy, the decoy reports one Fabric
`EnvironmentEvent` (`schema_version: environment-event/v0.1`,
`event_type: "interaction"`) to the intake, which stores it as a **Nexus
observation**: it is not an Edge finding, it never opens or updates an Edge
incident, and nothing about it flows back to Edge.

## A closed shape, narrower than Fabric's

Fabric's `EnvironmentEvent.metadata` is an open mapping of scalars. Here it is
exactly three keys:

* `bytes_received` -- how many bytes the decoy read (at most
  `MAX_BYTES_RECEIVED`, the decoy's read ceiling);
* `truncated` -- whether the peer sent more than the decoy would read;
* `responder` -- which in-code responder answered (`RESPONDER_NAMES`).

No payload, no credential and **no peer address** (§7 Q8): an interaction is
correlated with an Edge incident by decoy and time window only
(`incidents_near`). Every other field is fixed or pattern-bound, and
`evidence_refs` is always empty. An extra field, a missing one, a value of the
wrong type, an identifier that looks like an address and a string that could
carry what was sent are each refused as a whole, with a fixed code.

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
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

__all__ = [
    "DECOY_REFUSAL_CODES",
    "EVENT_TYPE",
    "MAX_BYTES_RECEIVED",
    "MAX_INTERACTION_LINE",
    "RECORD_KIND",
    "RESPONDER_NAMES",
    "SCHEMA_VERSION",
    "DecoyEventRefused",
    "DecoyInteraction",
    "DecoyInteractionRecord",
    "build_interaction",
    "incidents_near",
    "parse_interaction",
]

#: Fabric's `EnvironmentEvent` schema version (Azazel-Fabric v0.9.0rc5).
SCHEMA_VERSION = "environment-event/v0.1"
#: The only event type a decoy reports.
EVENT_TYPE = "interaction"
#: The decoy's read ceiling (`decoy_loopback.MAX_READ_BYTES`; a test keeps
#: them equal). A decoy that read more kept more than it may.
MAX_BYTES_RECEIVED = 4096
#: The in-code responders (`decoy_loopback.RESPONDERS`; a test keeps them
#: equal). A name, never a banner.
RESPONDER_NAMES = frozenset({"ssh-banner", "smtp-banner", "http-banner", "telnet-banner"})
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
})

_TOP_KEYS = frozenset({
    "schema_version", "event_id", "environment_id", "package_id", "node_id",
    "event_type", "observed_at", "evidence_refs", "metadata",
})
_METADATA_KEYS = frozenset({"bytes_received", "truncated", "responder"})

_EVENT_ID = re.compile(r"evt-[0-9a-f]{32}", re.ASCII)
#: The decoy's catalogue name (the loopback rule): no dot, no colon.
_DECOY_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,30}", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", re.ASCII)
_OBSERVED_AT = re.compile(
    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z", re.ASCII)

#: What an address looks like inside an identifier: dotted or dashed IPv4,
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


def _looks_like_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        pass
    return any(pattern.search(value) for pattern in _ADDRESS_LIKE)


def _identifier(value, pattern, *, limit=128):
    _require(type(value) is str, "DECOY_TYPE")
    _require(len(value) <= limit, "DECOY_RANGE")
    # An address is refused as an address, before the narrower pattern would
    # refuse it as merely malformed: Q8 is the reason the shape is closed.
    _require(not _looks_like_address(value), "DECOY_ADDRESS")
    _require(pattern.fullmatch(value) is not None, "DECOY_RANGE")


def _validate(value) -> dict:
    _require(type(value) is dict)
    _require(set(value) == _TOP_KEYS)
    _require(value["schema_version"] == SCHEMA_VERSION, "DECOY_RANGE")
    _require(value["event_type"] == EVENT_TYPE, "DECOY_RANGE")
    _identifier(value["event_id"], _EVENT_ID)
    _identifier(value["environment_id"], _DECOY_NAME)
    _identifier(value["package_id"], _DIGEST)
    _identifier(value["node_id"], _NODE_ID)
    observed = value["observed_at"]
    _require(type(observed) is str, "DECOY_TYPE")
    _require(len(observed) <= 32 and _OBSERVED_AT.fullmatch(observed) is not None,
             "DECOY_RANGE")
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
    responder = metadata["responder"]
    _require(type(responder) is str, "DECOY_TYPE")
    _require(len(responder) <= 32, "DECOY_RANGE")
    _require(not _looks_like_address(responder), "DECOY_ADDRESS")
    _require(responder in RESPONDER_NAMES, "DECOY_RANGE")
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
    event_id: str,
    decoy_name: str,
    generation_digest: str,
    node_id: str,
    observed_at: str,
    bytes_received: int,
    truncated: bool,
    responder: str,
) -> DecoyInteraction:
    """The event a decoy reports for one reach; refused unless it is closed.

    The decoy's observation has no payload and no peer field, so neither can
    be passed here. `generation_digest` (the verified catalogue generation)
    is the event's `package_id`; the decoy's name is its `environment_id`.
    """

    event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "environment_id": decoy_name,
        "package_id": generation_digest,
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
    return DecoyInteraction(_canonical(_validate(event)))


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "DECOY_JSON")
        result[key] = value
    return result


def _constant(_):
    raise DecoyEventRefused("DECOY_JSON")


def parse_interaction(raw: bytes) -> DecoyInteraction:
    """One line from the decoy socket, newline removed; refused as a whole."""

    _require(type(raw) is bytes, "DECOY_TYPE")
    _require(len(raw) <= MAX_INTERACTION_LINE, "DECOY_TOO_LARGE")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                           parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, DecoyEventRefused):
            raise
        raise DecoyEventRefused("DECOY_JSON") from None
    return DecoyInteraction(_canonical(_validate(value)))


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
