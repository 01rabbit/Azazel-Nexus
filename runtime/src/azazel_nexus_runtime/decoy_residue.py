"""What a definition-less stop of the exposure units leaves (#196 G6, item (a)).

`docs/deception-exposure-grant.md` §6.3, "For G6" (a). After a mask and a
`daemon-reload` the three exposure units' definitions are `/dev/null`: their
`Requires=` and `After=` are gone, the trip unit's `Conflicts=` is what stops
them, and with no `ExecStop=` or `ExecStopPost=` nothing cleans up (the
second and third G4 rehearsals, grant §11). This module judges, from values
already read, whether the pass should refuse the grant because of that state:

* `exposure_unit_masked_running`: an exposure unit is masked (its
  `LoadState` or `UnitFileState` says so) and is not stopped (its
  `ActiveState` is neither `inactive` nor `failed`);
* `exposure_leftovers_present`: the namespace `azazel-decoy`, the host's
  links `az-decoy-host0` or `az-decoy0`, or the table `inet azazel_decoy` is
  present while no exposure unit is running (every `ActiveState` is
  `inactive` or `failed`): what a stop without its clean-up leaves;
* `exposure_state_unreadable`: a value absent or not in its closed form.

**Implemented, not wired (#196 G6 preparation A).** Nothing calls
`exposure_residue_departures`: `ActivationController._withholding_reason`
still withholds the tier as `isolation_evidence_absent` unconditionally, and
wiring this in is G6 (grant §9). It reads nothing itself (the caller passes
what it read from the service manager's bus, `ip` and `nft`), stops nothing,
removes nothing and adds no unit operation: the operator stops such a unit
and clears what is left (operations). It says reason codes only, each a
fixed word with a fixed phrase, never a name, an address or a value.

A leaf apart from `decoy_addresses` (the fixed names) and
`decoy_reachability.parse_json_list` (the one `ip -j` parser): no socket,
no process, no environment, no file.
"""

from __future__ import annotations

import json
from typing import Mapping, Optional

from .decoy_addresses import BRIDGE, HOST_VETH, NAMESPACE, NFT_TABLE
from .decoy_reachability import parse_json_list

__all__ = [
    "EXPOSURE_LEFTOVERS_PRESENT",
    "EXPOSURE_STATE_UNREADABLE",
    "EXPOSURE_UNIT_MASKED_RUNNING",
    "EXPOSURE_UNITS",
    "RESIDUE_CODES",
    "RESIDUE_PHRASES",
    "UNIT_PROPERTIES",
    "exposure_residue_departures",
    "residue_refusal",
]

#: The three exposure units (`azazel_nexus.activation.DECEPTION_EXPOSURE_UNITS`;
#: a test keeps them equal). Named here so that this leaf loads no library.
EXPOSURE_UNITS: tuple[str, ...] = (
    "azazel-decoy-nsd.service",
    "azazel-decoy-netd.service",
    "azazel-decoyd.service",
)

#: The `org.freedesktop.systemd1.Unit` properties read for each unit.
UNIT_PROPERTIES: tuple[str, ...] = ("LoadState", "UnitFileState", "ActiveState")

EXPOSURE_UNIT_MASKED_RUNNING = "exposure_unit_masked_running"
EXPOSURE_LEFTOVERS_PRESENT = "exposure_leftovers_present"
EXPOSURE_STATE_UNREADABLE = "exposure_state_unreadable"
#: In the order they are reported.
RESIDUE_CODES: tuple[str, ...] = (
    EXPOSURE_UNIT_MASKED_RUNNING,
    EXPOSURE_LEFTOVERS_PRESENT,
    EXPOSURE_STATE_UNREADABLE,
)

RESIDUE_PHRASES: dict[str, str] = {
    EXPOSURE_UNIT_MASKED_RUNNING: ("a Deception Lite exposure unit is masked and "
                                   "still running; the operator stops it"),
    EXPOSURE_LEFTOVERS_PRESENT: ("the decoy namespace, its links or its table are "
                                 "present while no exposure unit runs; the "
                                 "operator removes them"),
    EXPOSURE_STATE_UNREADABLE: ("the exposure units' state or the decoy network's "
                                "objects could not be read"),
}

#: systemd 257's values (`systemctl --state=help`). Anything else is unreadable.
_LOAD_STATES = frozenset({"stub", "loaded", "not-found", "bad-setting", "error",
                          "merged", "masked"})
_ACTIVE_STATES = frozenset({"active", "reloading", "inactive", "failed", "activating",
                            "deactivating", "maintenance", "refreshing"})
#: `UnitFileState` is empty for a unit with no file (`not-found`).
_UNIT_FILE_STATES = frozenset({"enabled", "enabled-runtime", "linked", "linked-runtime",
                               "alias", "masked", "masked-runtime", "static", "indirect",
                               "disabled", "generated", "transient", "bad", ""})
_MASKED_FILE_STATES = frozenset({"masked", "masked-runtime"})
#: A unit in one of these runs nothing (`ExecStop=`'s clean-up aside).
_STOPPED = frozenset({"inactive", "failed"})


def _unit_states(units: object) -> Optional[dict[str, tuple[str, str, str]]]:
    """`unit -> (LoadState, UnitFileState, ActiveState)`, or None when not closed."""

    if not isinstance(units, Mapping) or set(units) != set(EXPOSURE_UNITS):
        return None
    states = {}
    for unit in EXPOSURE_UNITS:
        properties = units[unit]
        if not isinstance(properties, Mapping):
            return None
        values = tuple(properties.get(name) for name in UNIT_PROPERTIES)
        load, file_state, active = values
        if (not all(type(value) is str for value in values) or load not in _LOAD_STATES
                or file_state not in _UNIT_FILE_STATES or active not in _ACTIVE_STATES):
            return None
        states[unit] = (load, file_state, active)
    return states


def _named(read: object, key: str, wanted: frozenset[str], *,
           empty_allowed: bool = False) -> Optional[bool]:
    """Whether an `ip -j` list names one of `wanted` under `key`; None unreadable."""

    if type(read) is not tuple or len(read) != 2:
        return None
    status, output = read
    if status != 0 or type(output) is not bytes:
        return None
    # `ip -j netns list` prints nothing at all when there is no namespace
    # (iproute2 6.15, container-checked).
    if empty_allowed and not output.strip():
        return False
    listed = parse_json_list(output)
    if listed is None or not all(type(item.get(key)) is str for item in listed):
        return None
    return any(item[key] in wanted for item in listed)


def _table_present(read: object) -> Optional[bool]:
    """Whether `nft -j list tables` lists `inet azazel_decoy`; None unreadable."""

    if type(read) is not tuple or len(read) != 2:
        return None
    status, output = read
    if status != 0 or type(output) is not bytes:
        return None
    try:
        document = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(document) is not dict or type(document.get("nftables")) is not list:
        return None
    present = False
    for item in document["nftables"]:
        if type(item) is not dict:
            return None
        table = item.get("table")
        if table is None:
            continue
        if (type(table) is not dict or type(table.get("family")) is not str
                or type(table.get("name")) is not str):
            return None
        present = present or (table["family"], table["name"]) == ("inet", NFT_TABLE)
    return present


def exposure_residue_departures(units: Mapping[str, Mapping[str, str]],
                                netns: tuple[int, bytes], links: tuple[int, bytes],
                                tables: tuple[int, bytes]) -> tuple[str, ...]:
    """The reason codes of G6 item (a) that hold, in the order of `RESIDUE_CODES`.

    Pure. `units` maps each of `EXPOSURE_UNITS` to its `LoadState`,
    `UnitFileState` and `ActiveState` as the service manager's bus gave them
    (strings); `netns`, `links` and `tables` are `(status, output)` of
    `ip -j netns list`, `ip -j link show` (host namespace) and
    `nft -j list tables`. Empty when neither state holds. A unit state that
    cannot be read leaves both judgements unmade (`exposure_state_unreadable`
    alone); an unreadable object read leaves the leftovers unjudged.
    """

    states = _unit_states(units)
    if states is None:
        return (EXPOSURE_STATE_UNREADABLE,)
    found: set[str] = set()
    for load, file_state, active in states.values():
        if ((load == "masked" or file_state in _MASKED_FILE_STATES)
                and active not in _STOPPED):
            found.add(EXPOSURE_UNIT_MASKED_RUNNING)
    present = (_named(netns, "name", frozenset({NAMESPACE}), empty_allowed=True),
               _named(links, "ifname", frozenset({HOST_VETH, BRIDGE})),
               _table_present(tables))
    if any(value is None for value in present):
        found.add(EXPOSURE_STATE_UNREADABLE)
    elif any(present) and all(active in _STOPPED for _, _, active in states.values()):
        found.add(EXPOSURE_LEFTOVERS_PRESENT)
    return tuple(code for code in RESIDUE_CODES if code in found)


def residue_refusal(codes: tuple[str, ...]) -> Optional[str]:
    """`"<code>: <phrase>"` for the first of `codes`, or None when there is none."""

    if not codes:
        return None
    return f"{codes[0]}: {RESIDUE_PHRASES[codes[0]]}"
