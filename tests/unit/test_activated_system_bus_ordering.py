"""The controller is stopped before the system bus it closes through (#324).

A READY supporting-only bootstrap controller closes its grant and overlay
journal when it is stopped: the start fence's Reload, mask, StopUnit, the
inactivity and mask observations and the withdrawal are all calls over the
system bus. The unit has `DefaultDependencies=no`, so nothing ordered it
against `dbus.service`, and an ordinary reboot stopped the bus in parallel
with the close. Stop order is the reverse of start order, so `After=` on the
bus units is what keeps the bus up until the controller has stopped.

Ordering only: a `Wants=`/`Requires=`/`BindsTo=` on the bus would let the
bus's failure stop the controller, or pull the bus into the controller's
start transaction, which the bootstrap closure inspection does not admit.

These are declaration checks on the packaged unit file. That systemd stops
the units in this order at shutdown was seen in the 2026-10-26 VM rehearsal,
which is not hardware evidence.
"""

from __future__ import annotations

from pathlib import Path

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT
from azazel_nexus_runtime import systemd_socket
from azazel_nexus_runtime.hardening import PROFILES, SYSTEM_BUS_UNITS, render_unit

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO_ROOT / "packaging" / "systemd"
STRONG = ("Requires", "Wants", "BindsTo", "Requisite", "Upholds", "PartOf",
          "PropagatesStopTo", "StopPropagatedFrom")


def _settings(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, separator, value = line.partition("=")
        if separator:
            found.setdefault(key, []).append(value)
    return found


def _controller() -> dict[str, list[str]]:
    return _settings((UNIT_DIR / ACTIVATION_CONTROLLER_UNIT).read_text(encoding="utf-8"))


def test_the_bus_units_are_the_ones_serving_the_socket_the_controller_uses():
    # dbus.socket listens on this path; dbus.service is the daemon behind it.
    assert systemd_socket.SYSTEM_BUS_SOCKET == "/run/dbus/system_bus_socket"
    assert SYSTEM_BUS_UNITS == ("dbus.socket", "dbus.service")


def test_controller_is_ordered_after_the_system_bus_once():
    settings = _controller()
    assert settings["DefaultDependencies"] == ["no"]
    for unit in SYSTEM_BUS_UNITS:
        assert settings["After"].count(unit) == 1, unit
        assert unit not in settings.get("Before", [])


def test_the_bus_ordering_is_ordering_only():
    settings = _controller()
    for key in STRONG:
        for value in settings.get(key, []):
            assert "dbus" not in value, f"{key}={value}"


def test_the_shutdown_conflict_is_kept():
    settings = _controller()
    assert settings["Conflicts"] == ["shutdown.target"]
    assert "shutdown.target" in settings["Before"]


def test_only_the_controller_gains_the_bus_ordering():
    # The bootstrap pair is ordered after the controller, so it is already
    # stopped before the controller's close; this change adds nothing to it.
    for profile in PROFILES:
        rendered = _settings(render_unit(profile))
        after = rendered.get("After", [])
        if profile.unit == ACTIVATION_CONTROLLER_UNIT:
            assert all(unit in after for unit in SYSTEM_BUS_UNITS)
        elif profile.unit in {"azazel-auditd.service", "azazel-commissiond.service"}:
            assert not any(unit in after for unit in SYSTEM_BUS_UNITS), profile.unit
