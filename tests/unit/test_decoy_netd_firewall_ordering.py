"""The decoy network helper is ordered after the host firewall, never bound to it (#276 F1).

docs/deception-redirect-prerequisites.md §10 ("Before any grant"): Debian's
`nftables.service` loads `/etc/nftables.conf`, whose default first line is
`flush ruleset`, and is only `WantedBy=sysinit.target`, so nothing ordered the
helper after it. The helper gains `After=nftables.service` so that the boot's
firewall load cannot remove the decoy table after the helper loaded and
checked it. Only `After=`: a `Requires=`, `Wants=`, `BindsTo=` or `PartOf=`
would let a host without the unit, or with it failed, stop the helper or pull
the firewall in. No `Before=`: the helper has to come later.

This covers the boot order only. A later reload, stop, restart or start of
the firewall still removes the table and nothing notices; that, Edge's
enforce and every other flush stay before-grant items in §10.

These are declaration checks on the packaged unit file. They do not show that
systemd orders the boot this way.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from azazel_nexus.activation import (
    ACTIVATION_CONTROLLER_UNIT,
    DECOY_NAMESPACE_UNIT,
    DECOY_NETWORK_HELPER_UNIT,
    DECOY_UNIT,
)
from azazel_nexus_runtime.activation_unit_files import (
    require_governed_unit_content,
)
from azazel_nexus_runtime.hardening import (
    ALL_PROFILES,
    HOST_FIREWALL_UNIT,
    PROFILES,
    render_unit,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO_ROOT / "packaging" / "systemd"
FIREWALL = "nftables.service"
STRONG = ("Requires", "Wants", "BindsTo", "Requisite", "Upholds", "PartOf",
          "PropagatesReloadTo", "ReloadPropagatedFrom", "PropagatesStopTo",
          "StopPropagatedFrom", "OnSuccess", "OnFailure")


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


def _helper_text() -> str:
    return (UNIT_DIR / DECOY_NETWORK_HELPER_UNIT).read_text(encoding="ascii")


def _profile(unit: str):
    return next(p for p in PROFILES if p.unit == unit)


def test_the_firewall_unit_is_debians_nftables_service():
    assert HOST_FIREWALL_UNIT == FIREWALL


def test_helper_is_ordered_after_the_firewall_once():
    after = _settings(_helper_text())["After"]
    assert after == [ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT, FIREWALL]


def test_helper_has_no_strong_dependency_and_no_before_on_the_firewall():
    settings = _settings(_helper_text())
    for key in STRONG + ("Before", "Conflicts"):
        for value in settings.get(key, []):
            assert FIREWALL not in value, f"{key}={value}"
    assert "Wants" not in settings
    assert "Before" not in settings
    assert settings["Requires"] == [ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT]


def test_no_unit_requires_wants_or_precedes_the_firewall():
    for profile in ALL_PROFILES:
        settings = _settings(render_unit(profile))
        for key in STRONG + ("Before", "Conflicts"):
            for value in settings.get(key, []):
                assert FIREWALL not in value, f"{profile.unit} has {key}={value}"


def test_only_the_helper_names_the_firewall_and_the_decoy_follows_it():
    for profile in ALL_PROFILES:
        if profile.unit == DECOY_NETWORK_HELPER_UNIT:
            continue
        assert FIREWALL not in profile.after, profile.unit
    # The decoy is ordered after the helper, so after the firewall as well.
    assert DECOY_NETWORK_HELPER_UNIT in _profile(DECOY_UNIT).after


def test_the_helper_file_still_passes_the_content_check():
    # #253: the extra `After=` changes no grant-marker line and no guard.
    require_governed_unit_content(DECOY_NETWORK_HELPER_UNIT,
                                  _helper_text().encode("ascii"))
    assert _helper_text() == render_unit(_profile(DECOY_NETWORK_HELPER_UNIT))


def test_the_loaded_check_accepts_the_firewall_among_after():
    # #253's loaded-unit check requires the controller among `Requires` and
    # `After`, so a manager reporting the firewall there as well is accepted.
    from azazel_nexus_runtime.activation_loaded_units import _check_loaded

    unit = DECOY_NETWORK_HELPER_UNIT
    _check_loaded(unit, {
        "Id": unit, "LoadState": "loaded",
        "FragmentPath": f"/usr/lib/systemd/system/{unit}", "DropInPaths": [],
        "Conditions": [("ConditionPathExists", False, False,
                        f"/run/azazel-activation/granted/{unit}", 0)],
        "Asserts": [("AssertSecurity", False, False, "apparmor", 0)],
        "Requires": [ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT,
                     "system.slice", "sysinit.target"],
        "After": [ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT, FIREWALL,
                  "basic.target", "system.slice", "sysinit.target"],
    })


@pytest.mark.parametrize("change", [
    {"after": (ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT)},
    {"after": (ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT, FIREWALL,
               "firewalld.service")},
    {"requires": (ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT, FIREWALL)},
    {"requires": (ACTIVATION_CONTROLLER_UNIT,)},
    {"binds_to": (FIREWALL,)},
    {"before": (FIREWALL,)},
    {"conflicts": (FIREWALL,)},
    {"default_dependencies": False},
], ids=lambda change: next(iter(change)))
def test_the_helper_wiring_is_pinned(change):
    with pytest.raises(ValueError, match="requires only the first two"):
        replace(_profile(DECOY_NETWORK_HELPER_UNIT), **change)
