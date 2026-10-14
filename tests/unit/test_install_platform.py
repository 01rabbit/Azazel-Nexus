from pathlib import Path

import pytest

from azazel_nexus.install_platform import (
    CURRENT_INSTALL_PLATFORM_PROFILES,
    InstallPlatformProfile,
    build_install_plan,
    parse_os_release,
    parse_preset_declarations,
    select_install_profile,
)
from azazel_nexus.layout import LAYOUT
from azazel_nexus_runtime.hardening import PROFILES, SYSTEM_ACCOUNTS


ROOT = Path(__file__).resolve().parents[2]
PRESET_TEXT = (ROOT / "packaging/azazel-nexus.preset").read_text(encoding="utf-8")


def test_selects_only_the_declared_debian_13_profile():
    values = parse_os_release('ID=debian\nVERSION_ID="13"\nNAME="Debian GNU/Linux"\n')

    selected = select_install_profile(values)

    assert selected == CURRENT_INSTALL_PLATFORM_PROFILES[0]
    assert selected.profile_id == "debian-13-systemd-installer-v1"


@pytest.mark.parametrize(
    "contents",
    [
        "ID=ubuntu\nVERSION_ID=13\n",
        "ID=debian\nVERSION_ID=12\n",
        "ID=debian\n",
        "ID=debian\nVERSION_ID=\n",
        "ID=debian\nID=debian\nVERSION_ID=13\n",
        "ID=debian\nVERSION_ID=$(id)\n",
        'ID=debian\nVERSION_ID="13\n',
    ],
)
def test_rejects_unknown_or_malformed_os_release(contents):
    with pytest.raises(ValueError):
        select_install_profile(parse_os_release(contents))


def test_synthetic_registry_injection_does_not_mutate_current_registry():
    synthetic = InstallPlatformProfile(
        profile_id="synthetic-os-v1",
        os_id="synthetic",
        version_id="1",
        unit_directory="/opt/synthetic/systemd",
        preset_directory="/opt/synthetic/preset",
        libexec_directory="/opt/synthetic/libexec",
        service_manager="synthetic-manager",
        required_tools=("synthetic-installer",),
    )

    assert select_install_profile(
        {"ID": "synthetic", "VERSION_ID": "1"}, registry=(synthetic,)
    ) is synthetic
    assert len(CURRENT_INSTALL_PLATFORM_PROFILES) == 1
    with pytest.raises(ValueError):
        select_install_profile(
            {"ID": "synthetic", "VERSION_ID": "1"}, registry=()
        )


def test_profiles_and_plans_reject_mutable_collections():
    with pytest.raises(ValueError, match="immutable tuple"):
        InstallPlatformProfile(
            profile_id="synthetic-v1",
            os_id="synthetic",
            version_id="1",
            unit_directory="/opt/synthetic/systemd",
            preset_directory="/opt/synthetic/preset",
            libexec_directory="/opt/synthetic/libexec",
            service_manager="synthetic-manager",
            required_tools=["synthetic-installer"],
        )


def test_install_plan_uses_absolute_destinations_and_existing_declarations():
    selected = select_install_profile({"ID": "debian", "VERSION_ID": "13"})
    plan = build_install_plan(
        selected, preset_declarations=parse_preset_declarations(PRESET_TEXT)
    )

    assert plan.accounts == SYSTEM_ACCOUNTS
    assert plan.groups == tuple(sorted(set(SYSTEM_ACCOUNTS) | {
        name
        for spec in LAYOUT
        for name in (spec.owner, spec.group)
        if name != "root"
    }))
    assert {item.path for item in plan.directories if item.path in {s.path for s in LAYOUT}} == {
        spec.path for spec in LAYOUT
    }
    assert all(Path(item.destination).is_absolute() for item in plan.files)
    assert all(Path(item.path).is_absolute() for item in plan.directories)
    assert {item.source for item in plan.files if item.source.startswith("packaging/systemd/")} == {
        f"packaging/systemd/{service.unit}" for service in PROFILES
    }
    assert plan.service_manager.mask_units == tuple(
        unit for action, unit in parse_preset_declarations(PRESET_TEXT) if action == "disable"
    )
    assert plan.service_manager.enable_units == ("azazel-activated.service",)
    assert plan.service_manager.start_units == ()
    assert plan.architecture_evaluated is False
    assert plan.hardware_compatibility_established is False


@pytest.mark.parametrize("path", ["relative/path", "/a/../b", "/a//b"])
def test_profile_rejects_nonabsolute_or_noncanonical_destinations(path):
    with pytest.raises(ValueError):
        InstallPlatformProfile(
            profile_id="test-v1",
            os_id="test",
            version_id="1",
            unit_directory=path,
            preset_directory="/etc/systemd/system-preset",
            libexec_directory="/usr/libexec/azazel",
            service_manager="systemd",
            required_tools=("systemctl",),
        )


@pytest.mark.parametrize(
    "text",
    [
        "enable *.service\n",
        "enable azazel-activated.service\nenable azazel-activated.service\n",
        "run azazel-activated.service\n",
    ],
)
def test_preset_parser_rejects_globs_duplicates_and_unknown_actions(text):
    with pytest.raises(ValueError):
        parse_preset_declarations(text)


def test_install_plan_rejects_unreviewed_manager_enablement():
    selected = CURRENT_INSTALL_PLATFORM_PROFILES[0]
    with pytest.raises(ValueError):
        build_install_plan(
            selected,
            preset_declarations=(("enable", "azazel-commissiond.service"),),
        )
