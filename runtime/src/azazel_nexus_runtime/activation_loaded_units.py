"""What the running manager loaded for marker-guarded units (#251 H-1, M-3).

`docs/activation-observe-baseline.md` §8.2. `activation_unit_files` checks
the files systemd would read; a manager that loaded a unit earlier in the
boot (an enabled unit with a queued start job, before any daemon-reload)
runs **its loaded definition**, not the file measured now, and the
preflight mask does not reload it. READY would release such a job for any
marker-guarded unit, whether or not this pass's policy names it. So, before
any grant, the pass checks every marker-guarded unit's start guard
(the grantable units, which include the Knowledge Context broker since A1),
refusing unless:

* each one's vendor file, if present, passes the content check and has no
  override or drop-in (`require_grantable_unit_files`);
* the manager is a reviewed systemd profile: `Version` and `UnitPath`
  through `observe_bootstrap_systemd_profile`, the same gate as the
  bootstrap path (so the twelve search-path directories the override check
  walks are the ones this manager uses);
* each one is either not loaded (`GetUnit` answers `NoSuchUnit`, so no job
  can be queued and a later load reads the checked file), loaded as
  `masked`, or `loaded` with `Id` the unit, `FragmentPath` the vendor file in
  `/usr/lib/systemd/system`, no `DropInPaths`, `Conditions` and `Asserts`
  equal to the rendered unit's (the grant-marker `ConditionPathExists=`
  among them), and `azazel-activated.service` among its `Requires` and
  `After`.

Read-only: no reload, no start, no mask. A refusal is a fixed label; the
pass treats it as a failed producer, so nothing is granted.
"""

from __future__ import annotations

from .activation_unit_files import (
    CONTROLLER_UNIT,
    UNIT_DIRECTORY,
    _directives,
    rendered_unit,
    require_grantable_unit_files,
)
from .units import CONTEXTD_UNIT

__all__ = [
    "LoadedUnitRefused",
    "expected_loaded_guards",
    "verify_grantable_units",
    "verify_loaded_units",
]


class LoadedUnitRefused(Exception):
    """The manager's profile or a loaded unit is not what the pass measured."""


def _guard(key: str, value: str) -> tuple[str, bool, bool, str]:
    trigger = value.startswith("|")
    value = value[1:] if trigger else value
    negate = value.startswith("!")
    return (key, trigger, negate, value[1:] if negate else value)


def expected_loaded_guards(unit: str) -> tuple[list, list]:
    """The rendered unit's `(Conditions, Asserts)` as systemd reports them.

    Each entry is `(type, trigger, negate, parameter)`, sorted; the state
    field systemd adds is not part of the definition.
    """
    conditions, asserts = [], []
    for section, key, value, _ in _directives(rendered_unit(unit)):
        if section != "Unit":
            continue
        if key.startswith("Condition"):
            conditions.append(_guard(key, value))
        elif key.startswith("Assert"):
            asserts.append(_guard(key, value))
    return sorted(conditions), sorted(asserts)


def _observed(entries) -> list:
    return sorted(tuple(entry[:4]) for entry in entries)


def _check_loaded(unit: str, loaded) -> None:
    if loaded is None:
        return  # Not loaded: nothing queued; a later load reads the checked file.
    if type(loaded) is not dict or loaded.get("Id") != unit:
        raise LoadedUnitRefused("loaded unit identity refused")
    state = loaded.get("LoadState")
    if state == "masked":
        return  # Masked in the manager: it cannot start.
    if state != "loaded":
        raise LoadedUnitRefused("loaded unit state refused")
    if loaded.get("FragmentPath") != f"{UNIT_DIRECTORY}/{unit}":
        raise LoadedUnitRefused("loaded unit fragment is not the vendor file")
    if loaded.get("DropInPaths") != []:
        raise LoadedUnitRefused("loaded unit has a drop-in")
    if any(type(loaded.get(name)) is not list
           for name in ("Conditions", "Asserts", "Requires", "After")):
        raise LoadedUnitRefused("loaded unit definition refused")
    conditions, asserts = expected_loaded_guards(unit)
    if (_observed(loaded["Conditions"]) != conditions
            or _observed(loaded["Asserts"]) != asserts):
        raise LoadedUnitRefused("loaded unit start guards differ from the declaration")
    if unit == CONTEXTD_UNIT:
        _check_loaded_egress(unit, loaded)
    # Implicit dependencies (slices, targets) are added by systemd, so the
    # lists are not compared whole: the controller must be among them.
    if CONTROLLER_UNIT not in loaded["Requires"] or CONTROLLER_UNIT not in loaded["After"]:
        raise LoadedUnitRefused("loaded unit does not wait for the controller")


#: systemd reports `IPAddressDeny=any` as both all-zero prefixes.
_DENY_ANY = [(2, bytes(4), 0), (10, bytes(16), 0)]


def file_allow(unit: str) -> list:
    """The `IPAddressAllow` entries of the measured unit file, as the manager reports them.

    Read from the bytes the pass measures (and the generation hashes), not from
    the derivation: loaded must equal the file exactly.
    """
    import ipaddress

    from .activation_unit_files import UNIT_DIRECTORY, _directives, _read, _open

    fd = _open(UNIT_DIRECTORY, required=True)
    try:
        data = _read(fd, unit)
    finally:
        import os
        os.close(fd)
    result = []
    for section, key, value, _ in _directives(data.decode("ascii")):
        if key == "IPAddressAllow" and section == "Service":
            net = ipaddress.ip_network(value, strict=True)
            result.append((2 if net.version == 4 else 10, net.network_address.packed,
                           net.prefixlen))
    return sorted(result)


def _check_loaded_egress(unit: str, loaded) -> None:
    """The broker's loaded cgroup IP filter equals its measured file.

    Deny is any; Allow equals the file's `IPAddressAllow` exactly (empty when
    the file has none). Every slice in the broker's chain must have an empty
    Allow, because the manager merges a parent slice's Allow and evaluates
    Allow before Deny. Missing or malformed values are refused. (The loaded
    representation of Deny is unverified until the real-systemd run.)
    """
    allow, deny = loaded.get("IPAddressAllow"), loaded.get("IPAddressDeny")
    chain = loaded.get("SliceChainAllow")
    if type(allow) is not list or type(deny) is not list or type(chain) is not dict:
        raise LoadedUnitRefused("loaded unit egress filter unreadable")
    if deny != _DENY_ANY:
        raise LoadedUnitRefused("loaded unit does not deny all addresses")
    if not chain or any(entries != [] for entries in chain.values()):
        raise LoadedUnitRefused("loaded slice chain allows addresses")
    try:
        expected = file_allow(unit)
    except Exception:  # noqa: BLE001 - an unreadable file is not "no Allow"
        raise LoadedUnitRefused("unit file egress allowance unreadable") from None
    if allow != expected:
        raise LoadedUnitRefused("loaded unit egress allowance differs from its file")


def _check_slice_chain(reader) -> None:
    """Parent slices carry no Allow, whether or not the broker is loaded.

    systemd merges a slice's `IPAddressAllow` into its members and evaluates
    Allow before Deny. The pass withdraws and masks the broker, after which its
    loaded read is None; this read does not depend on that.
    """
    read = getattr(reader, "slice_chain_allow", None)
    if not callable(read):
        raise LoadedUnitRefused("slice chain reader required")
    try:
        chain = read()
    except Exception:  # noqa: BLE001 - unreadable is refused
        raise LoadedUnitRefused("slice chain unreadable") from None
    if (type(chain) is not dict or set(chain) != {"system.slice", "-.slice"}
            or any(entries != [] for entries in chain.values())):
        raise LoadedUnitRefused("loaded slice chain allows addresses")


def verify_loaded_units(reader, units) -> None:
    """Refuse unless the manager is reviewed and each unit is loaded as declared.

    `reader` is the controller's `SystemdBusSession` (`bootstrap_profile()`
    and `loaded_unit(unit)`); anything else is refused.
    """
    profile = getattr(reader, "bootstrap_profile", None)
    loaded_unit = getattr(reader, "loaded_unit", None)
    if not callable(profile) or not callable(loaded_unit):
        raise LoadedUnitRefused("systemd manager reader required")
    names = tuple(units)
    if not names or any(type(name) is not str for name in names):
        raise LoadedUnitRefused("unit scope refused")
    try:
        before = profile()
    except Exception:  # noqa: BLE001 - redacted: an unreviewed manager is refused
        raise LoadedUnitRefused("systemd manager profile refused") from None
    if CONTEXTD_UNIT in names:
        _check_slice_chain(reader)
    for unit in names:
        try:
            loaded = loaded_unit(unit)
        except Exception:  # noqa: BLE001 - unreadable is refused, never "as declared"
            raise LoadedUnitRefused("loaded unit unreadable") from None
        _check_loaded(unit, loaded)
    # Read again after the units: a manager re-executed (daemon-reexec, an
    # upgrade) while they were read may be another version or search path,
    # and the definitions above would then describe a manager that is gone.
    try:
        after = profile()
    except Exception:  # noqa: BLE001 - the manager changed under the reads
        raise LoadedUnitRefused("systemd manager profile refused") from None
    if after != before:
        raise LoadedUnitRefused("systemd manager profile changed during the reads")


def verify_grantable_units(reader, units) -> None:
    """The pass's `systemd_loaded_units` producer over its guarded-unit scope.

    The files first (content, overrides; an absent vendor file outside the
    policy is accepted), then the manager's profile and loaded definitions.
    The scope may include marker-guarded services that are not grantable
    (none today); this does not widen the set the pass may grant.
    """
    try:
        require_grantable_unit_files(units)
    except Exception:  # noqa: BLE001 - redacted: labels only
        raise LoadedUnitRefused("grantable unit files refused") from None
    verify_loaded_units(reader, units)
