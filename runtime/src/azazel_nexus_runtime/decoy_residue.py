"""What a definition-less stop of the exposure units leaves (#196 G6, item (a)).

`docs/deception-exposure-grant.md` §6.3, "For G6" (a). After a mask and a
`daemon-reload` the three exposure units' definitions are `/dev/null`: their
`Requires=` and `After=` are gone, the trip unit's `Conflicts=` is what stops
them, and with no `ExecStop=` or `ExecStopPost=` nothing cleans up (the
second and third G4 rehearsals, grant §11). This module judges, from values
already read, whether the pass should refuse the grant because of that state:

* `exposure_unit_masked_running`: an exposure unit has no definition (its
  `LoadState` is `masked` or `not-found`, or its `UnitFileState` is
  `masked` or `masked-runtime`) and is not stopped (its `ActiveState` is
  neither `inactive` nor `failed`);
* `exposure_leftovers_present`, judged per owner: an object is present
  while the unit that creates and removes it is stopped. The namespace
  unit owns the namespace `azazel-decoy` and the host's veth end
  `az-decoy-host0` (its `ExecStart=` and `ExecStopPost=`); the helper owns
  the bridge `az-decoy0` (its steps and `ExecStop=`). So the decoy running
  alone with the namespace unit and the helper stopped and their objects
  present is a leftover, and so is the helper stopped with the bridge
  present while the namespace unit runs. The helper's table
  `inet azazel_decoy` is not judged here (`docs/deception-exposure-wiring.md`
  §4.4, A1): the controller cannot list nftables without `CAP_NET_ADMIN`,
  and a leftover table alone is the helper's to refuse (`HELPER_ABSENT`
  fails its start closed);
* `exposure_state_unreadable`: a value absent or not in its closed form.

**Wired by G6** (`docs/deception-exposure-wiring.md` §4.3, stage P5): the
pass calls `exposure_residue_departures` with the bus reads of §4.5
(`systemd_bus.SystemdUnitCalls.exposure_unit_states`), `read_netns()` and
the names of `netlink.read_links()`. The judgement reads nothing itself (the caller passes what it
read from the service manager's bus, `/run/netns` through `read_netns`,
and the host's link names from `netlink.read_links`), stops nothing,
removes nothing and adds no unit operation: the operator stops such a unit
and clears what is left (operations). It says reason codes only, each a
fixed word with a fixed phrase, never a name, an address or a value.

**The namespace is read from `/run/netns`, not from `ip netns list`**
(#196 cross review L2, H1(c)). iproute2 prints nothing and exits 0 when it
cannot open `/run/netns`, so "unreadable" passed as "no namespace"; and the
pass that will call this in G6 runs in the controller, which starts no
process (only the network helper may spawn one, `test_runtime_boundary`).
`read_netns` opens `/run/netns` itself (`O_DIRECTORY|O_NOFOLLOW`) and looks
the one name `azazel-decoy` up in it without following a link. The host's
links are the names of the existing route-netlink dump (`netlink.read_links`,
no capability; wiring §4.4 (c)); no `ip -j` output is parsed here.

A leaf apart from `decoy_addresses` (the fixed names): no socket, no
process, no environment; the one file read is `read_netns`'s, read-only
and with no link followed.
"""

from __future__ import annotations

import errno
import os
import stat
from typing import Mapping, Optional

from .decoy_addresses import BRIDGE, HOST_VETH, NAMESPACE

__all__ = [
    "EXPOSURE_LEFTOVERS_PRESENT",
    "EXPOSURE_STATE_UNREADABLE",
    "EXPOSURE_UNIT_MASKED_RUNNING",
    "EXPOSURE_UNITS",
    "RESIDUE_CODES",
    "RESIDUE_PHRASES",
    "UNIT_PROPERTIES",
    "exposure_residue_departures",
    "read_netns",
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
    EXPOSURE_LEFTOVERS_PRESENT: ("the decoy namespace or its links are "
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
#: A `LoadState` with no definition behind it: masked, or the file removed
#: (`not-found`) while the unit still runs.
_DEFINITIONLESS = frozenset({"masked", "not-found"})
#: A unit in one of these runs nothing (`ExecStop=`'s clean-up aside).
_STOPPED = frozenset({"inactive", "failed"})
#: What a unit with no unit object is read as: a load state with no
#: definition behind it that is not `masked` or `not-found` (those mean a
#: definition was replaced or removed while an object exists).
_NO_OBJECT_LOAD = "stub"

#: Private test seam: where the named network namespaces are. Production is
#: exactly this (`hardening.NETNS_DIRECTORY`, a test keeps them equal).
_NETNS = "/run/netns"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _unit_states(units: object) -> Optional[dict[str, tuple[str, str, str]]]:
    """`unit -> (LoadState, UnitFileState, ActiveState)`, or None when not closed.

    `LoadState` and `ActiveState` both None mean systemd holds no unit
    object for the unit (`GetUnit` answered `NoSuchUnit`, wiring §4.5): it
    has no definition loaded and nothing of it runs, so it is read as
    `stub` and `inactive`. One of the two None without the other is not
    that, and is not closed.
    """

    if not isinstance(units, Mapping) or set(units) != set(EXPOSURE_UNITS):
        return None
    states = {}
    for unit in EXPOSURE_UNITS:
        properties = units[unit]
        if not isinstance(properties, Mapping) or set(properties) != set(UNIT_PROPERTIES):
            return None
        values = tuple(properties.get(name) for name in UNIT_PROPERTIES)
        if values[0] is None and values[2] is None:
            values = (_NO_OBJECT_LOAD, values[1], "inactive")
        load, file_state, active = values
        if (not all(type(value) is str for value in values) or load not in _LOAD_STATES
                or file_state not in _UNIT_FILE_STATES or active not in _ACTIVE_STATES):
            return None
        states[unit] = (load, file_state, active)
    return states


def read_netns() -> tuple[int, Optional[int]]:
    """`(error, mode)`: what `/run/netns` holds under `azazel-decoy`, read now.

    `error` is 0 when `/run/netns` was opened (`O_DIRECTORY|O_NOFOLLOW`, so
    a link in its place is an error) and the name looked up in it, or the
    `errno` of the first of the two that failed; `mode` is the entry's
    `st_mode` as `lstat` gives it (a link is not followed), None when there
    is no such entry or on an error. Read-only, one directory and one name;
    nothing here is judged (`exposure_residue_departures`).
    """

    try:
        directory = os.open(_NETNS, _DIR_FLAGS)
    except OSError as error:
        return error.errno or errno.EIO, None
    try:
        entry = os.stat(NAMESPACE, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return 0, None
    except OSError as error:
        return error.errno or errno.EIO, None
    finally:
        os.close(directory)
    return 0, entry.st_mode


def _namespace_present(read: object) -> Optional[bool]:
    """Whether `read_netns` found the namespace; None unreadable.

    No `/run/netns` at all (`ENOENT` opening it) is no namespace; any other
    error is unreadable (iproute2's `ip netns list` printed nothing for both).
    The entry is the empty regular file `ip netns add` binds the namespace's
    nsfs file onto; a link, a directory or anything else under that name is
    not that, and is unreadable.
    """

    if type(read) is not tuple or len(read) != 2:
        return None
    error, mode = read
    if type(error) is not int or (mode is not None and type(mode) is not int):
        return None
    if error == errno.ENOENT and mode is None:
        return False
    if error != 0:
        return None
    if mode is None:
        return False
    return True if stat.S_ISREG(mode) else None


def _link_names(links: object) -> Optional[frozenset[str]]:
    """The host's link names; None unreadable.

    `links` is the names of `netlink.read_links()`'s records, in its order,
    or None when the dump failed. A record without a name (`LinkRecord.name`
    None) could be any link, so the list is unreadable rather than
    shortened (wiring §4.4, "What B1's parser must hold"). An empty dump is
    unreadable too: every host namespace has `lo`, so no link at all is not
    a reading of it.
    """

    if (type(links) is not tuple or not links
            or not all(type(name) is str for name in links)):
        return None
    return frozenset(links)


def exposure_residue_departures(units: Mapping[str, Mapping[str, str]],
                                netns: tuple[int, Optional[int]],
                                links: Optional[tuple[Optional[str], ...]],
                                ) -> tuple[str, ...]:
    """The reason codes of G6 item (a) that hold, in the order of `RESIDUE_CODES`.

    Pure. `units` maps each of `EXPOSURE_UNITS` to its `LoadState`,
    `UnitFileState` and `ActiveState` as the service manager's bus gave them
    (strings); `netns` is `read_netns()`'s `(error, mode)` (no `/run/netns`
    is no namespace, any other error unreadable, the entry a regular file or
    unreadable); `links` is the host namespace's link names as
    `netlink.read_links()` yields them (`tuple(r.name for r in records)`),
    None when the dump failed; a None name anywhere, or no link at all (a
    host always has `lo`), is unreadable. No table listing is taken (wiring
    §4.4, A1). Empty when neither state holds. Any argument of another
    shape is `exposure_state_unreadable`, never an exception. A unit state
    that cannot be read leaves both judgements unmade
    (`exposure_state_unreadable` alone); an unreadable object read leaves
    the leftovers unjudged.
    """

    states = _unit_states(units)
    if states is None:
        return (EXPOSURE_STATE_UNREADABLE,)
    found: set[str] = set()
    for load, file_state, active in states.values():
        if ((load in _DEFINITIONLESS or file_state in _MASKED_FILE_STATES)
                and active not in _STOPPED):
            found.add(EXPOSURE_UNIT_MASKED_RUNNING)
    namespace = _namespace_present(netns)
    link_names = _link_names(links)
    if namespace is None or link_names is None:
        found.add(EXPOSURE_STATE_UNREADABLE)
    else:
        namespace_unit, helper, _ = EXPOSURE_UNITS
        owned = (
            (namespace_unit, namespace or HOST_VETH in link_names),
            (helper, BRIDGE in link_names),
        )
        if any(present and states[owner][2] in _STOPPED for owner, present in owned):
            found.add(EXPOSURE_LEFTOVERS_PRESENT)
    return tuple(code for code in RESIDUE_CODES if code in found)


def residue_refusal(codes: tuple[str, ...]) -> Optional[str]:
    """`"<code>: <phrase>"` for the first of `codes`, or None when there is none."""

    if not codes:
        return None
    return f"{codes[0]}: {RESIDUE_PHRASES[codes[0]]}"
