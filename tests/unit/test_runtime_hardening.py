"""The hardening is checked as values, not as the presence of words (#42).

Issue #36's seventh boundary says not to finish at "the setting appears in the
file". So every check here reads what the setting is *set to*, and compares it
against a declaration that something else also uses -- the layout, the unit
definitions, the address families the code is statically proven not to reach.

What this establishes: **the distribution does not contradict itself.** The
units say what the table says, the installer creates what the layout declares,
and each daemon's account is the one its unit runs as.

What it does not establish: anything about what the operating system enforces.
`HG-01` and `HG-02` stay open, and no test in this file starts a service.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT, CORE_UNITS
from azazel_nexus.layout import LAYOUT
from azazel_nexus_runtime.hardening import (
    PROFILES,
    SHARED_HARDENING,
    SYSTEM_ACCOUNTS,
    ServiceProfile,
    render_unit,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
UNIT_DIR = REPO_ROOT / "packaging" / "systemd"
INSTALLER = (REPO_ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")


def _unit(name: str) -> str:
    return (UNIT_DIR / name).read_text(encoding="utf-8")


def _settings(name: str) -> dict[str, list[str]]:
    """Every `Key=Value` in a unit file, comments excluded."""

    found: dict[str, list[str]] = {}
    for line in _unit(name).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key, []).append(value)
    return found


# -- the files are what the declaration renders --------------------------


def test_every_committed_unit_is_exactly_what_the_table_renders():
    """A hand edit is a difference, and a difference is a failure.

    Generating without comparing would drift silently, which is worse than
    editing by hand -- so the comparison is the point rather than the
    generation.
    """

    for profile in PROFILES:
        assert _unit(profile.unit) == render_unit(profile), (
            f"{profile.unit} differs from what the hardening table renders. "
            "Run tools/render_units.py"
        )


def test_the_table_covers_every_unit_the_packaging_installs():
    packaged = {path.name for path in UNIT_DIR.glob("*.service")}
    declared = {profile.unit for profile in PROFILES}
    assert packaged == declared


def test_the_table_covers_every_unit_the_controller_governs():
    governed = {definition.name for definition in CORE_UNITS}
    declared = {profile.unit for profile in PROFILES}
    assert governed | {ACTIVATION_CONTROLLER_UNIT} == declared


# -- accounts -------------------------------------------------------------


def test_each_daemon_has_its_own_account():
    accounts = [profile.account for profile in PROFILES]
    assert len(set(accounts)) == len(accounts), (
        "two daemons share an account, so a fault in one runs with the "
        "other's access"
    )


def test_only_the_activation_controller_is_root():
    """The reason the other three are not.

    Unmasking a unit means writing under /etc/systemd/system. Isolating that
    in one daemon is what leaves the rest unprivileged; spreading it makes
    least privilege a comment.
    """

    roots = [p.unit for p in PROFILES if p.account == "root"]
    assert roots == [ACTIVATION_CONTROLLER_UNIT]


def test_the_unit_account_is_the_one_the_library_declares():
    by_unit = {profile.unit: profile.account for profile in PROFILES}
    for definition in CORE_UNITS:
        assert by_unit[definition.name] == definition.account


def test_the_installer_creates_every_non_root_account():
    """The accounts it loops over are exactly the declared ones, and it
    actually calls `useradd`.

    The first version grepped for each name anywhere in the script, which the
    loop header satisfies -- so deleting the `useradd` call left it green. A
    mention is not a creation.
    """

    loop = re.search(r"for account in ([^;]+); do", INSTALLER)
    assert loop, "the installer has no account-creation loop"
    assert sorted(loop.group(1).split()) == sorted(SYSTEM_ACCOUNTS)
    assert re.search(r'\buseradd\b[^\n]*"\$account"', INSTALLER), (
        "the loop names the accounts and never creates one"
    )
    assert "root" not in SYSTEM_ACCOUNTS, "root is not an account to create"


def test_every_created_account_is_non_login():
    assert "--shell /usr/sbin/nologin" in INSTALLER
    assert "--no-create-home" in INSTALLER
    assert "--system" in INSTALLER


def test_every_group_the_layout_names_is_created_or_is_a_daemon_account():
    created = set(SYSTEM_ACCOUNTS)
    for spec in LAYOUT:
        if spec.group == "root":
            continue
        assert spec.group in created or re.search(
            rf"groupadd --system {re.escape(spec.group)}\b", INSTALLER
        ), f"{spec.path} is grouped to {spec.group}, which nothing creates"


# -- address families -----------------------------------------------------


def test_a_directory_grouped_to_an_account_must_grant_that_group_something():
    """Otherwise the group is documentation.

    `/etc/azazel/commissioning` is grouped to `azcommission` so that daemon
    can write the record. A spec that named the group and left the group bits
    clear would look like least privilege and be no privilege.
    """

    from azazel_nexus.layout import PathSpec

    with pytest.raises(ValueError):
        PathSpec("/var/lib/azazel/run", 0o700, "sockets", group="azazel-operator")
    # And the declared ones all pass it.
    for spec in LAYOUT:
        if spec.group != "root":
            assert spec.mode & 0o070


def test_no_unit_is_allowed_an_internet_address_family():
    for profile in PROFILES:
        families = _settings(profile.unit)["RestrictAddressFamilies"]
        assert len(families) == 1
        allowed = set(families[0].split())
        assert allowed & {"AF_INET", "AF_INET6", "AF_PACKET"} == set()


def test_only_the_commissioning_daemon_is_allowed_netlink():
    """It reads `IFLA_PERM_ADDRESS`. Nothing else has a reason to.

    A second daemon with netlink would be a second place a link write could
    be sent from, whatever its code happens to do today.
    """

    with_netlink = [
        profile.unit
        for profile in PROFILES
        if "AF_NETLINK" in _settings(profile.unit)["RestrictAddressFamilies"][0]
    ]
    assert with_netlink == ["azazel-commissiond.service"]


def test_a_profile_asking_for_an_internet_family_cannot_be_built():
    with pytest.raises(ValueError):
        ServiceProfile(
            unit="azazel-bad.service",
            executable="/usr/libexec/azazel/az-bad",
            account="azbad",
            description="d",
            documentation="u",
            address_families=("AF_UNIX", "AF_INET"),
            read_write_paths=(),
        )


def test_every_unit_denies_ip_addresses():
    for profile in PROFILES:
        assert _settings(profile.unit)["IPAddressDeny"] == ["any"]


# -- capabilities ---------------------------------------------------------


def test_every_unit_has_an_empty_capability_bounding_set():
    """Not "a small set". Empty.

    A bounding set is what a daemon may ever acquire, and none of these needs
    anything: the one that talks to the kernel does it over a route netlink
    socket, which is a read.
    """

    for profile in PROFILES:
        settings = _settings(profile.unit)
        assert settings["CapabilityBoundingSet"] == [""]
        assert settings["AmbientCapabilities"] == [""]


def test_every_unit_refuses_new_privileges():
    for profile in PROFILES:
        assert _settings(profile.unit)["NoNewPrivileges"] == ["yes"]


# -- writable paths and the runtime directory -----------------------------


def test_every_writable_path_is_one_the_layout_declares():
    """A writable path nobody declared is one nobody set the owner of."""

    declared = {spec.path for spec in LAYOUT} | {"/etc/systemd/system"}
    for profile in PROFILES:
        for path in _settings(profile.unit).get("ReadWritePaths", []):
            assert path in declared, f"{profile.unit} writes to undeclared {path}"


def test_only_the_activation_controller_may_write_unit_files():
    writers = [
        profile.unit
        for profile in PROFILES
        if "/etc/systemd/system" in _settings(profile.unit).get("ReadWritePaths", [])
    ]
    assert writers == [ACTIVATION_CONTROLLER_UNIT]


def test_a_profile_writing_outside_the_layout_cannot_be_built():
    with pytest.raises(ValueError):
        ServiceProfile(
            unit="azazel-bad.service",
            executable="/usr/libexec/azazel/az-bad",
            account="azbad",
            description="d",
            documentation="u",
            address_families=("AF_UNIX",),
            read_write_paths=("/etc/shadow",),
        )


def test_the_runtime_directory_mode_matches_the_layouts_socket_directory():
    """`/var/lib/azazel/run` is `0750` and so is what systemd creates.

    Socket ACLs are the first authorization boundary (§4); two declarations
    of that boundary disagreeing means one of them is not the boundary.
    """

    run = next(spec for spec in LAYOUT if spec.path.endswith("/run"))
    for profile in PROFILES:
        mode = _settings(profile.unit)["RuntimeDirectoryMode"][0]
        assert int(mode, 8) == run.mode


# -- the installer agrees with all of it ----------------------------------


def test_the_installer_installs_every_declared_unit():
    for profile in PROFILES:
        assert f"systemd/{profile.unit}" in INSTALLER


def test_the_installer_checks_for_every_declared_executable():
    for profile in PROFILES:
        binary = Path(profile.executable).name
        assert binary in INSTALLER, (
            f"{profile.unit} execs {binary} and the preflight does not check "
            "for it, so the refusal would miss exactly this unit"
        )


def test_the_shared_hardening_is_applied_to_every_unit_without_exception():
    for profile in PROFILES:
        settings = _settings(profile.unit)
        for key, value in SHARED_HARDENING:
            assert settings.get(key) == [value], (
                f"{profile.unit} sets {key} to {settings.get(key)} and the "
                f"shared declaration says {value!r}"
            )


def test_the_generator_is_deterministic():
    """Two runs produce the same bytes, so the comparison above is meaningful."""

    for profile in PROFILES:
        assert render_unit(profile) == render_unit(profile)


def test_the_units_say_they_are_generated():
    for profile in PROFILES:
        assert _unit(profile.unit).startswith("# Generated from")
