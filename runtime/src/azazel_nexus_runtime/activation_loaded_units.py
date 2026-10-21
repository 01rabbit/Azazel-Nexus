"""What the running manager has loaded for the scoped units (#251 H-1, M-3).

`docs/activation-observe-baseline.md` §8.2. `activation_unit_files` checks
the files systemd would read; a manager that loaded a unit earlier in the
boot (an enabled unit with a queued start job, before any daemon-reload)
runs **its loaded definition**, not the file measured now. So, before any
grant, the pass reads the manager over the fixed D-Bus session and refuses
unless:

* the manager is a reviewed systemd profile: `Version` and `UnitPath`
  through `observe_bootstrap_systemd_profile`, the same gate as the
  bootstrap path (so the twelve search-path directories the override check
  walks are the ones this manager uses);
* each scoped unit is either not loaded (`GetUnit` answers `NoSuchUnit`, so
  no job can be queued and a later load reads the measured file), loaded as
  `masked`, or `loaded` with `Id` the unit, `FragmentPath` the vendor file in
  `/usr/lib/systemd/system`, no `DropInPaths`, and `Conditions` and
  `Asserts` equal to the rendered unit's (the grant-marker
  `ConditionPathExists=` among them).

Read-only: no reload, no start, no mask. A refusal is a fixed label; the
pass treats it as a failed producer, so nothing is granted.
"""

from __future__ import annotations

from .activation_unit_files import UNIT_DIRECTORY, rendered_unit, _directives

__all__ = ["LoadedUnitRefused", "expected_loaded_guards", "verify_loaded_units"]


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
        return  # Not loaded: nothing queued; a later load reads the measured file.
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
    if type(loaded.get("Conditions")) is not list or type(loaded.get("Asserts")) is not list:
        raise LoadedUnitRefused("loaded unit start guards refused")
    conditions, asserts = expected_loaded_guards(unit)
    if (_observed(loaded["Conditions"]) != conditions
            or _observed(loaded["Asserts"]) != asserts):
        raise LoadedUnitRefused("loaded unit start guards differ from the declaration")


def verify_loaded_units(reader, units) -> None:
    """Refuse unless the manager is reviewed and each scoped unit loaded as declared.

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
        profile()
    except Exception:  # noqa: BLE001 - redacted: an unreviewed manager is refused
        raise LoadedUnitRefused("systemd manager profile refused") from None
    for unit in names:
        try:
            loaded = loaded_unit(unit)
        except Exception:  # noqa: BLE001 - unreadable is refused, never "as declared"
            raise LoadedUnitRefused("loaded unit unreadable") from None
        _check_loaded(unit, loaded)
    try:
        profile()
    except Exception:  # noqa: BLE001 - the manager changed under the reads
        raise LoadedUnitRefused("systemd manager profile refused") from None
