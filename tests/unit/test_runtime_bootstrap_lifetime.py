"""Declaration checks for the partial bootstrap lifetime binding.

These assertions compare the packaged unit files' values. They do not prove
that systemd enforces the relationship or that a persistent mask survives
failure or reboot.
"""

from __future__ import annotations

from pathlib import Path

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT
from azazel_nexus_runtime.hardening import PROFILES

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO_ROOT / "packaging" / "systemd"
BOOTSTRAP_PAIR = {
    "azazel-auditd.service",
    "azazel-commissiond.service",
}


def _settings(unit: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in (UNIT_DIR / unit).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, separator, value = line.partition("=")
        if separator:
            found.setdefault(key, []).append(value)
    return found


def test_controller_requires_explicit_readiness_and_kills_its_control_group():
    settings = _settings(ACTIVATION_CONTROLLER_UNIT)

    assert settings["Type"] == ["notify"]
    assert settings["NotifyAccess"] == ["main"]
    assert settings["Restart"] == ["no"]
    assert settings["KillMode"] == ["control-group"]
    assert "RemainAfterExit" not in settings
    # The volatile overlay directory is provisioned by tmpfiles before the
    # controller. No dependency on a helper may create a startup cycle.
    assert settings["After"] == [
        "systemd-tmpfiles-setup.service",
        "sysinit.target",
        "basic.target",
        # Ordering only on the commissioning storage (#242): never a
        # requirement, so locked or absent storage cannot stop the controller.
        "etc-azazel-commissioning.mount",
        "var-lib-azazel-secrets.mount",
        # The same ordering-only rule for the mission storage (#251 M-7) and
        # the passive time-sync target (#251 M-1), which waits for
        # synchronization only when a wait-sync service holds it.
        "data.mount",
        "time-sync.target",
        # The system bus its close at shutdown speaks through (#324): stop
        # order is the reverse of start order, so the bus outlives the close.
        "dbus.socket",
        "dbus.service",
    ]
    assert not any(
        key in settings for key in ("Requires", "BindsTo", "Wants")
    )


def test_exact_bootstrap_pair_binds_to_controller_and_commission_waits_for_audit():
    assert BOOTSTRAP_PAIR <= {profile.unit for profile in PROFILES}

    for unit in BOOTSTRAP_PAIR:
        settings = _settings(unit)
        dependencies = [ACTIVATION_CONTROLLER_UNIT]
        if unit == "azazel-commissiond.service":
            dependencies.append("azazel-auditd.service")
        assert settings["After"] == [
            *dependencies, "sysinit.target", "basic.target",
        ]
        assert settings["Requires"] == dependencies
        assert settings["BindsTo"] == dependencies
        assert "Wants" not in settings
        assert settings["Type"] == ["notify"]
        assert settings["Restart"] == ["no"]
        assert settings["KillMode"] == ["control-group"]
        assert settings["NotifyAccess"] == ["main"]


def test_lifetime_binding_adds_no_dependencies_or_lifecycle_changes_elsewhere():
    for profile in PROFILES:
        if profile.unit == ACTIVATION_CONTROLLER_UNIT or profile.unit in BOOTSTRAP_PAIR:
            continue

        settings = _settings(profile.unit)
        assert "BindsTo" not in settings
        assert "Restart" not in settings
        if profile.unit != "azazel-knowledge-contextd.service":
            # The broker alone carries the stop profile (KillMode=control-group,
            # TimeoutStopSec, KillSignal, FinalKillSignal, SendSIGKILL) that
            # its withdrawal depends on (activation stop contract).
            assert "KillMode" not in settings
        else:
            assert settings["KillMode"] == ["control-group"]
        assert "NotifyAccess" not in settings
