"""Withholding reasons of the exposure tier that no pass reaches yet (#196 G6 prep).

`docs/deception-exposure-grant.md` §5 (C1, conditions 5 and 6) and §6.2.
Two of the node-level conditions the pass is to require before it may grant
`DECEPTION_EXPOSURE`, as pure judgements of values a caller has read, and one
bounded reader:

* **coexistence** (§6.2, §10 Q12): `host_firewall_refusal` withholds while
  any of `nftables.service`, `firewalld.service` or
  `netfilter-persistent.service` (`hardening.HOST_FIREWALL_UNITS`) is not
  provably off: `disabled` or masked **and** `inactive`. Its input is each
  unit's unit-file state and active state **as read through the bus the
  pass already uses** (`GetUnitFileState`, the Unit interface's
  `ActiveState`); this module reads no bus and adds no bus call;
* **`net.core.fb_tunnels_only_for_init_net`** (§5 item 6, §13 of the
  prerequisites document): `fb_tunnels_refusal` withholds unless the value
  is exactly `2`; `read_fb_tunnels` reads it from `/proc/sys`.

The LSM condition (§5 item 4) is `decoy_apparmor.exposure_lsm_withholding`
and the governed-set exclusion of an enforcing Edge (§6.2) is the library's
`azazel_nexus.exposure_exclusivity`.

**Implemented, not wired.** Nothing calls this module: the pass, the
controller and the library do not import it, and
`ActivationController._withholding_reason` still withholds the tier as
`isolation_evidence_absent` unconditionally (`tests/unit/test_exposure_g6_parts.py`
pins both). Wiring these in, in an order, is G6. Nothing here grants,
enables, masks or starts anything, takes an argument that loosens a
judgement, or reads the environment.
"""

from __future__ import annotations

import errno
import os

__all__ = [
    "FB_TUNNELS_NOT_INIT_NET_ONLY",
    "FB_TUNNELS_REASON_CODES",
    "HOST_FIREWALL_ACTIVE",
    "HOST_FIREWALL_ENABLED",
    "HOST_FIREWALL_REASON_CODES",
    "HOST_FIREWALL_UNITS",
    "HOST_FIREWALL_UNREADABLE",
    "UNREADABLE",
    "fb_tunnels_refusal",
    "host_firewall_refusal",
    "read_fb_tunnels",
]

#: The host firewall loaders that can flush the ruleset when they load
#: (§6.2); restated from `hardening.HOST_FIREWALL_UNITS` so that this module
#: imports nothing of the product (a test keeps the two equal).
HOST_FIREWALL_UNITS: tuple[str, ...] = (
    "nftables.service", "firewalld.service", "netfilter-persistent.service")

HOST_FIREWALL_ENABLED = "host_firewall_enabled"
HOST_FIREWALL_ACTIVE = "host_firewall_active"
HOST_FIREWALL_UNREADABLE = "host_firewall_unreadable"
HOST_FIREWALL_REASON_CODES: tuple[str, ...] = (
    HOST_FIREWALL_UNREADABLE, HOST_FIREWALL_ENABLED, HOST_FIREWALL_ACTIVE)

FB_TUNNELS_NOT_INIT_NET_ONLY = "fb_tunnels_not_init_net_only"
FB_TUNNELS_REASON_CODES: tuple[str, ...] = (FB_TUNNELS_NOT_INIT_NET_ONLY,)

#: The unit-file states that are **off** at boot: no `[Install]` link pulls
#: the unit in. Off at boot is not off: a `disabled` unit still starts when
#: another unit wants it, by hand or by D-Bus activation, so
#: `host_firewall_refusal` also requires `ActiveState` `inactive`.
_OFF_STATES = frozenset({"disabled", "masked", "masked-runtime"})
#: Every `ActiveState` systemd 257 names. Only `inactive` passes.
_ACTIVE_STATES = frozenset({
    "active", "reloading", "inactive", "failed", "activating", "deactivating",
    "maintenance", "refreshing",
})
#: Every other state systemd 257 names (`systemd_bus._UNIT_FILE_STATES`):
#: enabled, linked, alias, static, indirect, generated, transient, invalid or
#: bad.
#: None of them is provably off: `static` and `indirect` units start when
#: another unit pulls them in, `generated` and `transient` ones are made
#: outside the unit files. Each withholds as enabled.
_ON_STATES = frozenset({
    "enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "static",
    "indirect", "generated", "transient", "invalid", "bad",
})


class _Unreadable:
    """A value that exists but could not be read."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNREADABLE"


#: A file present and not readable (EACCES, EIO, a link, out of bounds).
UNREADABLE = _Unreadable()

_FB_TUNNELS = "/proc/sys/net/core/fb_tunnels_only_for_init_net"
_FB_TUNNELS_LIMIT = 16
_ABSENT = frozenset({errno.ENOENT, errno.ENOTDIR})


def host_firewall_refusal(states) -> str | None:
    """Why a host firewall loader withholds the tier (§6.2), or None.

    `states` maps exactly the three `HOST_FIREWALL_UNITS` to what the bus
    gave for each: None when systemd has neither a unit file nor a unit
    object for it, or `{"UnitFileState": str, "ActiveState": str}` (either
    value may be `UNREADABLE`). Pure. In order:

    * `host_firewall_unreadable`: a mapping that is not exactly the three, a
      value of another shape, a value not read, or a state systemd does not
      name;
    * `host_firewall_enabled`: a unit-file state other than `disabled`,
      `masked` or `masked-runtime`;
    * `host_firewall_active`: an `ActiveState` other than `inactive`.

    **Why both (review of #294 F1).** A `disabled` unit still starts when
    another unit's `Wants=` or `Requires=` pulls it in, by hand, or by D-Bus
    activation, and a unit masked while it ran keeps running; the file state
    alone says nothing about now. `inactive` is required, not merely "not
    active": `failed`, `activating`, `deactivating`, `reloading`,
    `maintenance` and `refreshing` withhold too.

    **Still open until G6.** The pair is a snapshot at the pass: a disabled
    unit started later in the boot (a `Wants=` from another unit, a manual
    start) is not seen here; the watch (§6.1) is what notices its flush. The
    None case rests on the G6 reader: it maps to None only the specific
    errors that mean "no such unit file" and "no such unit object" and
    refuses every other error; that mapping and its tests are G6's.

    The judgement does not read `/etc/nftables.conf` (§6.2 rejects that:
    includes and other loaders make it unreliable).
    """

    if type(states) is not dict or set(states) != set(HOST_FIREWALL_UNITS):
        return (f"{HOST_FIREWALL_UNREADABLE}: the unit states read are not "
                "exactly the host firewall loaders")
    enabled = active = 0
    for unit in HOST_FIREWALL_UNITS:
        value = states[unit]
        if value is None:
            continue
        if type(value) is not dict or set(value) != {"UnitFileState", "ActiveState"}:
            return (f"{HOST_FIREWALL_UNREADABLE}: a host firewall loader's unit "
                    "state is not in the form read from the bus")
        file_state, active_state = value["UnitFileState"], value["ActiveState"]
        if (type(file_state) is not str or file_state not in _OFF_STATES | _ON_STATES
                or type(active_state) is not str or active_state not in _ACTIVE_STATES):
            return (f"{HOST_FIREWALL_UNREADABLE}: a host firewall loader's unit "
                    "state could not be read")
        if file_state not in _OFF_STATES:
            enabled += 1
        elif active_state != "inactive":
            active += 1
    if enabled:
        return (f"{HOST_FIREWALL_ENABLED}: {enabled} of the {len(HOST_FIREWALL_UNITS)} "
                "host firewall loaders, each of which can flush the decoy's "
                "table, is not disabled or masked")
    if active:
        return (f"{HOST_FIREWALL_ACTIVE}: {active} of the {len(HOST_FIREWALL_UNITS)} "
                "host firewall loaders is disabled or masked but not inactive")
    return None


def fb_tunnels_refusal(value) -> str | None:
    """Why `net.core.fb_tunnels_only_for_init_net` withholds the tier, or None.

    `value` is the content of the sysctl file: bytes, None when it does not
    exist, or `UNREADABLE`. Pure. Only exactly `b"2\\n"` passes (fallback
    tunnel devices in no namespace but the initial one, so the decoy's
    namespace holds only `lo` and its own link); anything else is
    `fb_tunnels_not_init_net_only`.
    """

    if value == b"2\n" and type(value) is bytes:
        return None
    if value is None:
        detail = "the sysctl does not exist on this kernel"
    elif type(value) is not bytes:
        detail = "the sysctl could not be read"
    else:
        detail = "it is not 2"
    return (f"{FB_TUNNELS_NOT_INIT_NET_ONLY}: net.core.fb_tunnels_only_for_init_net "
            f"must be 2 before the decoy's namespace is made; {detail}")


def read_fb_tunnels():
    """The sysctl file's bytes, None when absent, `UNREADABLE` otherwise.

    Read-only, bounded (one byte past the bound is `UNREADABLE`), no link
    followed.
    """

    try:
        fd = os.open(_FB_TUNNELS, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as error:
        return None if error.errno in _ABSENT else UNREADABLE
    try:
        data = os.read(fd, _FB_TUNNELS_LIMIT + 1)
        return UNREADABLE if len(data) > _FB_TUNNELS_LIMIT else data
    except OSError:
        return UNREADABLE
    finally:
        os.close(fd)
