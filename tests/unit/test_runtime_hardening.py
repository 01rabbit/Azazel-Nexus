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
    ALL_PROFILES,
    EDGE_PROBE_PREFLIGHT_UNIT,
    PROFILES,
    SHARED_HARDENING,
    UNGOVERNED_PROFILES,
    SYSTEM_ACCOUNTS,
    ServiceProfile,
    render_unit,
)
from azazel_nexus_runtime.launch_environment import BOOTSTRAP_UNSET_ENVIRONMENT

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

    for profile in ALL_PROFILES:
        assert _unit(profile.unit) == render_unit(profile), (
            f"{profile.unit} differs from what the hardening table renders. "
            "Run tools/render_units.py"
        )


def test_the_table_covers_every_unit_the_packaging_installs():
    packaged = {path.name for path in UNIT_DIR.glob("*.service")}
    declared = {profile.unit for profile in ALL_PROFILES}
    assert packaged == declared


def test_the_table_covers_every_unit_the_controller_governs():
    governed = {definition.name for definition in CORE_UNITS}
    declared = {profile.unit for profile in PROFILES}
    assert governed | {ACTIVATION_CONTROLLER_UNIT} == declared


# -- accounts -------------------------------------------------------------


def test_each_daemon_has_its_own_account():
    # root is the controller's and the decoy network helper's (#196 P1); every
    # other daemon has an account of its own.
    accounts = [profile.account for profile in PROFILES if profile.account != "root"]
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
    # The named exceptions (#196 P1, #196 (a)): the one-shot decoy namespace
    # unit and network helper, root only so that each one's single
    # bounding-set capability reaches it without an ambient grant.
    assert roots == [ACTIVATION_CONTROLLER_UNIT, "azazel-decoy-nsd.service",
                     "azazel-decoy-netd.service"]


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


def test_no_unit_but_the_artifact_fetcher_is_allowed_an_internet_family():
    """Two exemptions, each declared on its own profile, `AF_PACKET` for nobody.

    The history of this assertion is the history of the boundary:

    | when | what it said |
    | --- | --- |
    | before Nexus#105 | no unit at all may take an internet family |
    | Nexus#105 | one may: the artifact fetcher, by a field it must set |
    | Nexus#98 | two may, and the second is a **different field** |

    The second is the remote inference transport. It is `is_inference_transport`
    rather than a second unit setting `is_artifact_fetcher`, because the two
    are not the same permission: one pulls public bytes in against a digest
    declared beforehand, the other pushes what this node observed out. Sharing
    the flag would have shared the account, and a node where one credential
    did both is a node where one compromise is two.

    Naming each loosening here is the point: a hardening guarantee that
    quietly weakened and left no trace is one nobody can audit.
    """

    for profile in PROFILES:
        families = _settings(profile.unit)["RestrictAddressFamilies"]
        assert len(families) == 1
        allowed = set(families[0].split())
        assert "AF_PACKET" not in allowed
        if not (profile.is_artifact_fetcher or profile.is_inference_transport
                or profile.is_decoy_listener):
            assert allowed & {"AF_INET", "AF_INET6"} == set(), profile.unit


def test_exactly_one_profile_holds_each_network_role():
    """A third would be a diff a reviewer sees, not a set that grew.

    Each role is counted separately, so a second fetcher cannot hide behind
    the transport's exemption and the reverse.
    """

    fetchers = [p.unit for p in PROFILES if p.is_artifact_fetcher]
    transports = [p.unit for p in PROFILES if p.is_inference_transport]
    hosts = [p.unit for p in PROFILES if p.is_model_host]
    listeners = [p.unit for p in PROFILES if p.is_decoy_listener]
    assert fetchers == ["azazel-model-fetchd.service"]
    assert transports == ["azazel-mio-remoted.service"]
    assert hosts == ["azazel-mio-locald.service"]
    assert listeners == ["azazel-decoyd.service"]
    assert len(set(fetchers + transports + hosts + listeners)) == 4, (
        "one unit holds two roles; the four acts are kept in four units"
    )


def test_the_artifact_fetcher_still_denies_every_address():
    """The exemption opens an address *family*, not an address.

    `IPAddressDeny=any` stays, so the unit as shipped reaches nothing. What
    it may reach arrives as a commissioning drop-in built from the signed
    Source Registry -- which means adding a real endpoint is reviewed,
    signed, commissioned data rather than an edit to this file.
    """

    fetcher = next(profile for profile in PROFILES if profile.is_artifact_fetcher)
    settings = _settings(fetcher.unit)
    assert settings["IPAddressDeny"] == ["any"]
    assert "IPAddressAllow" not in settings
    assert fetcher.account != "root"
    # It writes its staging area and its own socket leaf. Nothing else.
    assert set(fetcher.read_write_paths) == {
        "/var/lib/azazel/fetch",
        "/var/lib/azazel/run/fetch",
    }
    assert "/etc/systemd/system" not in fetcher.read_write_paths


def test_the_artifact_fetcher_bounds_its_journal():
    """A transfer that fails repeatedly must not fill the journal with one
    refusal. A journal nobody can read is a journal nobody reads."""

    settings = _settings("azazel-model-fetchd.service")
    assert settings["LogRateLimitIntervalSec"] == ["30"]
    assert int(settings["LogRateLimitBurst"][0]) > 0


def test_a_profile_that_is_not_the_fetcher_cannot_take_an_internet_family():
    with pytest.raises(ValueError):
        ServiceProfile(
            unit="azazel-sneaky.service",
            executable="/usr/libexec/azazel/az-sneaky",
            account="azsneaky",
            description="d",
            documentation="u",
            address_families=("AF_UNIX", "AF_INET"),
            read_write_paths=(),
        )


def test_a_fetcher_that_would_use_no_internet_family_cannot_be_built():
    """An exemption nothing uses is a hole held open for nothing."""

    with pytest.raises(ValueError):
        ServiceProfile(
            unit="azazel-idle-fetcher.service",
            executable="/usr/libexec/azazel/az-idle",
            account="azfetch",
            description="d",
            documentation="u",
            address_families=("AF_UNIX",),
            read_write_paths=(),
            is_artifact_fetcher=True,
        )


def test_only_commissioning_and_activation_readers_are_allowed_netlink():
    """Both collect IFLA_PERM_ADDRESS; neither can administer networking.

    Activation's full-evidence loader requires current hardware, not a cached
    commissioning result. Keep this explicit expansion bounded to two units.
    """

    with_netlink = [
        profile.unit
        for profile in PROFILES
        if "AF_NETLINK" in _settings(profile.unit)["RestrictAddressFamilies"][0]
    ]
    # Plus the decoy network helper (#196 P1), which configures links and
    # rules over netlink with CAP_NET_ADMIN and nothing else, and the decoy
    # namespace unit (#196 (a)), whose `ip` uses route netlink. The family
    # admits every netlink protocol to both, nftables included.
    assert with_netlink == ["azazel-activated.service", "azazel-commissiond.service",
                            "azazel-decoy-nsd.service", "azazel-decoy-netd.service"]
    for unit in with_netlink:
        settings = _settings(unit)
        assert settings["RestrictAddressFamilies"] == (
            ["AF_NETLINK"] if unit in ("azazel-decoy-netd.service",
                                       "azazel-decoy-nsd.service")
            else ["AF_UNIX AF_NETLINK"])
        assert settings["CapabilityBoundingSet"] == {
            "azazel-activated.service": ["CAP_DAC_READ_SEARCH"],
            "azazel-decoy-netd.service": ["CAP_NET_ADMIN"],
            "azazel-decoy-nsd.service": ["CAP_SYS_ADMIN CAP_NET_ADMIN"],
        }.get(unit, [""])
        assert settings["AmbientCapabilities"] == [""]
        assert settings["IPAddressDeny"] == ["any"]


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


def test_every_unit_but_the_controller_has_an_empty_capability_bounding_set():
    """Not "a small set". Empty.

    A bounding set is what a daemon may ever acquire, and none of these needs
    anything: the one that talks to the kernel does it over a route netlink
    socket, which is a read.
    """

    for profile in PROFILES:
        if profile.unit == "azazel-activated.service":
            continue
        settings = _settings(profile.unit)
        assert settings["CapabilityBoundingSet"] == {
            "azazel-decoy-netd.service": ["CAP_NET_ADMIN"],
            "azazel-decoy-nsd.service": ["CAP_SYS_ADMIN CAP_NET_ADMIN"],
        }.get(profile.unit, [""])
        assert settings["AmbientCapabilities"] == [""]
        if profile.unit == "azazel-commissiond.service":
            assert settings["SupplementaryGroups"] == ["azknowledge"]
        elif profile.unit == "azazel-mio-entryd.service":
            assert settings["SupplementaryGroups"] == ["azazel-operator"]
        elif profile.unit == "azazel-mio-locald.service":
            assert settings["SupplementaryGroups"] == ["azknowledge-read azmission-read"]
        elif profile.unit == "azazel-incident-explaind.service":
            assert settings["SupplementaryGroups"] == [
                "azincident-read azknowledge-read azaudit-submit azmio-advise"]
        else:
            assert "SupplementaryGroups" not in settings


def test_capabilities_and_supplementary_groups_have_an_exact_allowlist():
    """Owner-approved: root controller gets exactly CAP_DAC_READ_SEARCH and
    SupplementaryGroups=azazel-operator; commissiond gets the read-only
    trust consumer group to preserve its GID on published files. Entryd
    needs the operator group to connect to provider sockets."""

    widened = {
        profile.unit
        for profile in PROFILES
        if profile.capability_bounding_set or profile.supplementary_groups
    }
    assert widened == {
        "azazel-activated.service", "azazel-commissiond.service",
        "azazel-mio-entryd.service", "azazel-mio-locald.service",
        "azazel-incident-explaind.service", "azazel-decoy-netd.service",
        "azazel-decoy-nsd.service",
    }
    settings = _settings("azazel-activated.service")
    assert settings["User"] == ["root"]
    assert settings["CapabilityBoundingSet"] == ["CAP_DAC_READ_SEARCH"]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["SupplementaryGroups"] == ["azazel-operator"]
    assert settings["NoNewPrivileges"] == ["yes"]


@pytest.mark.parametrize("bounding,groups", [
    (("CAP_DAC_READ_SEARCH", "CAP_DAC_OVERRIDE"), ("azazel-operator",)),
    (("CAP_DAC_OVERRIDE",), ("azazel-operator",)),
    (("CAP_DAC_READ_SEARCH",), ("azazel-operator", "wheel")),
    (("CAP_DAC_READ_SEARCH",), ()),
    ((), ("azazel-operator",)),
])
def test_a_wider_or_different_controller_declaration_does_not_render_the_unit(
    bounding, groups,
):
    from dataclasses import replace

    controller = next(p for p in PROFILES if p.unit == "azazel-activated.service")
    changed = replace(
        controller, capability_bounding_set=bounding, supplementary_groups=groups,
    )
    assert render_unit(changed) != _unit("azazel-activated.service")


def test_every_unit_refuses_new_privileges():
    for profile in PROFILES:
        assert _settings(profile.unit)["NoNewPrivileges"] == ["yes"]


# -- writable paths and the runtime directory -----------------------------


def test_every_writable_path_is_one_the_layout_declares():
    """A writable path nobody declared is one nobody set the owner of."""

    declared = {spec.path for spec in LAYOUT} | {
        "/etc/systemd/system", "/run/systemd/system.control",
        "/run/azazel-nexus-bootstrap", "/run/azazel-activation",
        "/run/netns",
    }
    for profile in PROFILES:
        for path in _settings(profile.unit).get("ReadWritePaths", []):
            # "-" marks an optional path; it is still one the layout declares.
            assert path.removeprefix("-") in declared, f"{profile.unit} writes to undeclared {path}"


def test_only_the_activation_controller_may_write_unit_files():
    writers = [
        profile.unit
        for profile in PROFILES
        if "/etc/systemd/system" in _settings(profile.unit).get("ReadWritePaths", [])
    ]
    assert writers == [ACTIVATION_CONTROLLER_UNIT]


def test_overlay_write_scope_and_boot_provisioning_order_are_controller_only():
    writers = [profile.unit for profile in PROFILES
               if "/run/systemd/system.control" in profile.read_write_paths]
    assert writers == [ACTIVATION_CONTROLLER_UNIT]
    controller = next(profile for profile in PROFILES if profile.unit == ACTIVATION_CONTROLLER_UNIT)
    assert "systemd-tmpfiles-setup.service" in controller.after
    assert not {"/run", "/run/systemd", "/run/netns"} & set(controller.read_write_paths)
    claim_writers = [profile.unit for profile in PROFILES
                     if "/run/azazel-nexus-bootstrap" in profile.read_write_paths]
    assert claim_writers == [ACTIVATION_CONTROLLER_UNIT]
    assert controller.conditions == (
        ("ConditionPathExists", "!/run/azazel-nexus-bootstrap/controller-used"),
    )
    # Besides the controller's once-claim, only the per-boot grant markers
    # (#206 §5), and only on the governed loop units.
    assert all(
        profile.conditions == (
            ("ConditionPathExists", f"/run/azazel-activation/granted/{profile.unit}"),
        ) if profile.unit in GRANT_LOOP_UNITS else
        not any(key == "ConditionPathExists" for key, _ in profile.conditions)
        for profile in PROFILES
        if profile.unit != ACTIVATION_CONTROLLER_UNIT
    )
    from dataclasses import replace
    with pytest.raises(ValueError, match="only by the activation controller"):
        replace(controller, unit="azazel-other.service")


#: Every governed unit except the bootstrap pair: the six loop units (§2 of
#: docs/activation-observe-baseline.md) and the four other controller
#: dependents (watchdog, fetch, local and remote model hosts).
GRANT_LOOP_UNITS = frozenset({
    "azazel-decoy-netd.service",
    "azazel-decoy-nsd.service",
    "azazel-decoyd.service",
    "azazel-edge-core.service",
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
    "azazel-mio-locald.service",
    "azazel-mio-remoted.service",
    "azazel-model-fetchd.service",
    "azazel-watchdog.service",
})


def test_condition_path_exists_is_present_exactly_on_the_marker_units():
    """Each governed unit but the bootstrap pair starts only with this boot's marker.

    The controller's READY releases queued starts of every unit that
    Requires= it; with the condition, none of them starts without a marker
    this boot's pass wrote. auditd and commissiond are started by the
    supporting-only bootstrap, which writes no marker, so they must not carry
    the condition (residual: masked on the ordinary path and BindsTo= the
    controller).
    """
    from azazel_nexus.activation import CORE_UNITS
    from azazel_nexus_runtime.activation_markers import GRANTABLE_UNITS

    assert GRANT_LOOP_UNITS == {d.name for d in CORE_UNITS} - {
        "azazel-auditd.service", "azazel-commissiond.service"}
    assert GRANTABLE_UNITS < GRANT_LOOP_UNITS
    for profile in ALL_PROFILES:
        if ACTIVATION_CONTROLLER_UNIT in profile.requires and profile.unit not in (
                "azazel-auditd.service", "azazel-commissiond.service"):
            assert profile.unit in GRANT_LOOP_UNITS, profile.unit
    from azazel_nexus_runtime.activation_markers import GRANT_MARKER_DIRECTORY
    from azazel_nexus_runtime.hardening import GRANT_MARKER_UNITS

    assert set(GRANT_MARKER_UNITS) == GRANT_LOOP_UNITS
    for profile in ALL_PROFILES:
        markers = [value for value in _settings(profile.unit).get("ConditionPathExists", [])
                   if "azazel-activation" in value]
        if profile.unit in GRANT_LOOP_UNITS:
            assert markers == [f"{GRANT_MARKER_DIRECTORY}/{profile.unit}"], profile.unit
        else:
            assert markers == [], profile.unit
    for unit in ("azazel-auditd.service", "azazel-commissiond.service"):
        assert "ConditionPathExists" not in _settings(unit)


def test_only_the_controller_may_write_grant_markers_and_it_stays_optional():
    writers = [profile.unit for profile in ALL_PROFILES
               if any(path.removeprefix("-") == "/run/azazel-activation"
                      for path in _settings(profile.unit).get("ReadWritePaths", []))]
    assert writers == [ACTIVATION_CONTROLLER_UNIT]
    # Optional so a node without the tmpfiles directory still narrows; then no
    # marker can be written and nothing granted can start.
    assert "-/run/azazel-activation" in _settings(ACTIVATION_CONTROLLER_UNIT)["ReadWritePaths"]
    # A separate root-owned directory, never under any unit's RuntimeDirectory:
    # systemd chowns a runtime directory to the unit's account and removes it
    # when that unit stops, which would hand over or delete the markers.
    from pathlib import PurePosixPath
    from azazel_nexus_runtime.activation_markers import GRANT_MARKER_DIRECTORY
    marker = PurePosixPath(GRANT_MARKER_DIRECTORY)
    for profile in ALL_PROFILES:
        declared = [value for value in _settings(profile.unit).get("RuntimeDirectory", [])]
        for name in declared + ([profile.runtime_directory] if profile.runtime_directory else []):
            for item in name.split():
                runtime = PurePosixPath("/run") / item
                assert runtime != marker and runtime not in marker.parents, (profile.unit, item)
    from dataclasses import replace
    entry = next(profile for profile in ALL_PROFILES if profile.unit == "azazel-mio-entryd.service")
    with pytest.raises(ValueError, match="grant markers are writable only"):
        replace(entry, optional_read_write_paths=("/run/azazel-activation",))


def test_only_the_three_lifetime_units_override_default_shutdown_dependencies():
    restricted = {
        "azazel-activated.service",
        "azazel-auditd.service",
        "azazel-commissiond.service",
    }
    assert {profile.unit for profile in PROFILES if not profile.default_dependencies} == restricted
    for profile in PROFILES:
        if profile.unit in restricted:
            assert profile.default_dependencies is False
            assert profile.before == ("shutdown.target",)
            assert profile.conflicts == ("shutdown.target",)
            settings = _settings(profile.unit)
            assert settings["DefaultDependencies"] == ["no"]
            assert settings["Before"] == ["shutdown.target"]
            assert settings["Conflicts"] == ["shutdown.target"]
        else:
            assert profile.default_dependencies is True
            assert profile.before == ()
            assert profile.conflicts == ()


def test_only_bootstrap_lifetime_units_clear_launcher_environment():
    expected_units = {
        "azazel-activated.service",
        "azazel-auditd.service",
        "azazel-commissiond.service",
    }
    actual_units = {
        profile.unit for profile in PROFILES
        if {key for key, _ in profile.extra}
        & {"SetLoginEnvironment", "UnsetEnvironment"}
    }
    assert actual_units == expected_units

    expected_unset = " ".join(BOOTSTRAP_UNSET_ENVIRONMENT)
    for profile in PROFILES:
        extras = dict(profile.extra)
        if profile.unit in expected_units:
            assert extras["SetLoginEnvironment"] == "no"
            assert extras["UnsetEnvironment"] == expected_unset
            assert profile.default_dependencies is False
            assert profile.before == ("shutdown.target",)
            assert profile.conflicts == ("shutdown.target",)
        else:
            assert "SetLoginEnvironment" not in extras
            assert "UnsetEnvironment" not in extras
        assert not {"EnvironmentFile", "DefaultDependencies"} & extras.keys()
        if profile.unit != "azazel-edge-core.service":
            assert "Environment" not in extras

    authority = {
        profile.unit: (profile.account, profile.address_families)
        for profile in PROFILES if profile.unit in expected_units
    }
    assert authority == {
        "azazel-activated.service": ("root", ("AF_UNIX", "AF_NETLINK")),
        "azazel-auditd.service": ("azaudit", ("AF_UNIX",)),
        "azazel-commissiond.service": ("azcommission", ("AF_UNIX", "AF_NETLINK")),
    }


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


def test_systemd_runtime_directory_is_separate_from_persistent_socket_tree():
    """systemd's `/run/azazel` is distinct from `/var/lib/azazel/run`."""

    for profile in PROFILES:
        settings = _settings(profile.unit)
        if not profile.runtime_directory:
            assert "RuntimeDirectory" not in settings
            continue
        mode = settings["RuntimeDirectoryMode"][0]
        if profile.unit == "azazel-decoy-netd.service":
            # The one exception (#196 §14): the decoy reads the helper's
            # isolation record under its own account. Root-owned, 0755,
            # holding one root 0644 record of fixed results.
            assert (profile.runtime_directory, mode) == ("azazel-decoy-isolation", "0755")
            continue
        assert int(mode, 8) == 0o750


# -- the installer agrees with all of it ----------------------------------


def test_the_installer_installs_every_declared_unit():
    for profile in PROFILES:
        assert f"systemd/{profile.unit}" in INSTALLER


def test_the_installer_checks_for_every_declared_executable():
    for profile in PROFILES:
        if profile.unit == "azazel-decoy-nsd.service":
            # #196 G4 follow-up: the system's iproute2 ip, which Nexus does
            # not stage; a missing ip fails the unit's start (fail closed).
            assert profile.executable == "/usr/bin/ip"
            assert "az-decoy-nsd" not in INSTALLER
            continue
        binary = Path(profile.executable).name
        assert binary in INSTALLER, (
            f"{profile.unit} execs {binary} and the preflight does not check "
            "for it, so the refusal would miss exactly this unit"
        )


def test_the_shared_hardening_is_applied_to_every_unit_without_exception():
    from azazel_nexus_runtime.hardening import DECOY_NAMESPACE_SHARED_OMISSIONS

    for profile in PROFILES:
        settings = _settings(profile.unit)
        for key, value in SHARED_HARDENING:
            if (key == "CapabilityBoundingSet"
                    and profile.unit == "azazel-activated.service"):
                value = "CAP_DAC_READ_SEARCH"
            if (key == "CapabilityBoundingSet"
                    and profile.unit == "azazel-decoy-netd.service"):
                value = "CAP_NET_ADMIN"
            if profile.unit == "azazel-decoy-nsd.service":
                # #196 (a): the one unit with shared overrides and omissions,
                # pinned by test_decoy_namespace_unit.py.
                if key == "CapabilityBoundingSet":
                    value = "CAP_SYS_ADMIN CAP_NET_ADMIN"
                elif key in ("RestrictNamespaces", "SystemCallFilter"):
                    continue
                elif key in DECOY_NAMESPACE_SHARED_OMISSIONS:
                    assert key not in settings, key
                    continue
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


@pytest.mark.parametrize(
    ("unit", "account", "paths", "read_only"),
    [
        (
            "azazel-mio-entryd.service", "azmioentry",
            ["/var/lib/azazel/state/mio", "/var/lib/azazel/run/mio-entry",
             "/var/lib/azazel/run/mio-advise"],
            None,
        ),
        (
            "azazel-knowledge-lited.service", "azknowledge",
            ["/var/lib/azazel/knowledge", "/var/lib/azazel/run/knowledge",
             "/var/lib/azazel/run/knowledge-read",
             "/var/lib/azazel/state/knowledge"],
            ["/var/lib/azazel/lite-trust"],
        ),
    ],
)
def test_entry_and_knowledge_profiles_have_exact_least_privilege_scope(
    unit, account, paths, read_only
):
    settings = _settings(unit)
    assert settings["User"] == [account]
    assert settings["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert settings["ReadWritePaths"] == paths
    assert settings.get("ReadOnlyPaths") == read_only
    assert settings["CapabilityBoundingSet"] == [""]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["Requires"] == [ACTIVATION_CONTROLLER_UNIT]


@pytest.mark.parametrize(
    ("unit", "paths"),
    [
        ("azazel-mio-locald.service", ["/var/lib/azazel/mio", "/var/lib/azazel/run/mio"]),
        ("azazel-mio-remoted.service",
         ["/var/lib/azazel/remote", "/var/lib/azazel/run/remote"]),
    ],
)
def test_provider_hosts_write_only_their_own_socket_leaf(unit, paths):
    """Never the whole run tree: not other daemons' leaves and not the legacy
    unattested `/var/lib/azazel/run/core-reserve.json`."""

    written = _settings(unit)["ReadWritePaths"]
    assert written == paths
    assert "/var/lib/azazel/run" not in written
    assert not any("/var/lib/azazel/run/core-reserve.json".startswith(path + "/")
                   for path in written)


@pytest.mark.parametrize(
    ("unit", "sockets", "paths"),
    [
        ("azazel-model-fetchd.service", ("fetch",),
         ["/var/lib/azazel/fetch", "/var/lib/azazel/run/fetch"]),
        ("azazel-auditd.service", ("audit", "audit-submit"),
         ["/var/lib/azazel/run/audit", "/var/lib/azazel/run/audit-submit",
          "/var/lib/azazel/state/audit", "/var/lib/azazel/state/auditd",
          "-/var/lib/azazel/run/audit-status"]),
        ("azazel-watchdog.service", ("watchdog",),
         ["/var/lib/azazel/run/watchdog", "/var/lib/azazel/state/watchdog"]),
    ],
)
def test_socket_daemons_write_only_their_own_run_leaf(unit, sockets, paths):
    """Each of these creates only its sockets under the run tree, each in its
    installer-owned leaf, so those leaves are the whole of its run-tree grant.
    auditd has two: the operator socket and the explainer's append-only one,
    plus its capacity snapshot leaf (#211), which holds no socket."""

    from azazel_nexus_runtime.runtime_paths import audit_status_path, socket_path

    written = _settings(unit)["ReadWritePaths"]
    assert written == paths
    run_grants = [p for p in written if p.lstrip("-") == "/var/lib/azazel/run"
                  or p.lstrip("-").startswith("/var/lib/azazel/run/")]
    # Optional ("-"): a missing snapshot leaf must not stop auditd's start.
    snapshot = (["-/var/lib/azazel/run/" + audit_status_path().parent.name]
                if unit == "azazel-auditd.service" else [])
    assert run_grants == ["/var/lib/azazel/run/" + socket_path(name).parent.name
                          for name in sockets] + snapshot


def test_no_unprivileged_unit_holds_the_run_root():
    """Every unprivileged unit writes only its own run leaf. The root
    controller's grant is `/var/lib/azazel` as a whole and is not this test's
    subject."""

    holders = {
        profile.unit for profile in PROFILES
        if "/var/lib/azazel/run" in profile.read_write_paths
    }
    assert holders == set()


def test_the_edge_probe_writes_only_its_result_leaf():
    """The Edge probe writes its result by temp file and rename, which needs
    the directory writable -- so the directory is a leaf of its own, owned by
    the probe's account and group-readable by operators (who run `status`)."""

    from azazel_nexus.edge_package import PROBE_STATE_PATH
    from azazel_nexus.layout import spec_for

    leaf = "/var/lib/azazel/run/edge-probe"
    assert str(PROBE_STATE_PATH.parent) == leaf
    assert _settings("azazel-edge-probed.service")["ReadWritePaths"] == [leaf]
    spec = spec_for(leaf)
    assert (spec.owner, spec.group, spec.mode) == ("azprobe", "azazel-operator", 0o2750)
    assert spec.mode & 0o007 == 0
    run = spec_for("/var/lib/azazel/run")
    assert (run.owner, run.mode) == ("root", 0o711)


def test_entry_can_traverse_and_connect_to_provider_socket_leaves():
    # Provider leaves are operator-group 2710 and their sockets are 0660.
    assert _settings("azazel-mio-entryd.service")["SupplementaryGroups"] == [
        "azazel-operator",
    ]


def test_locald_optional_selection_reads_have_no_write_grant():
    settings = _settings("azazel-mio-locald.service")
    assert settings["SupplementaryGroups"] == ["azknowledge-read azmission-read"]
    assert settings["ReadOnlyPaths"] == ["-/etc/azazel/model-admission", "-/etc/azazel/operator-trust",
                                         "-/var/lib/azazel/models", "-/etc/azazel/mission-pack.json",
                                         "-/data/azazel/mission-packs"]
    assert settings["ProtectSystem"] == ["strict"]
    assert settings["CapabilityBoundingSet"] == [""]


def test_locald_aggregate_safety_ceiling_allows_packaged_server_exec():
    settings = _settings("azazel-mio-locald.service")
    assert settings["MemoryMax"] == ["4G"]
    assert settings["MemorySwapMax"] == ["0"]
    assert settings["CPUQuota"] == ["40%"]
    assert settings["PrivateNetwork"] == ["yes"]
    assert settings["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert "NoExecPaths" not in settings
    assert "ExecPaths" not in settings


def test_entry_gets_private_commissioning_snapshot_without_a_protection_key():
    settings = _settings("azazel-mio-entryd.service")
    assert settings["User"] == ["azmioentry"]
    assert settings["LoadCredential"] == [
        "mio-profile_commissioning-proposal.expected.json:"
        "/etc/azazel/commissioning/commissioning-proposal.expected.json",
        "mio-profile_commissioning-proposal.json:"
        "/etc/azazel/commissioning/commissioning-proposal.json",
        "mio-profile_commissioning-proposal.sig:/etc/azazel/mio-profile/commissioning-proposal.sig",
        "mio-trust:/etc/azazel/operator-trust/operators.json",
        "mio-node:/etc/azazel/node.yaml",
    ]
    # Every source has a non-empty fallback, so a locked commissioning volume
    # (missing source files) starts the unit with CORE instead of failing it.
    assert settings["SetCredential"] == [
        source.split(":", 1)[0] + ":absent" for source in settings["LoadCredential"]
    ]
    sources = [source.split(":", 1)[1] for source in settings["LoadCredential"]]
    # Never a directory source on the commissioning volume (drafts, records):
    # only the two fixed proposal files, read in place and never copied (#244).
    assert [s for s in sources if s.startswith("/etc/azazel/commissioning")] == [
        "/etc/azazel/commissioning/commissioning-proposal.expected.json",
        "/etc/azazel/commissioning/commissioning-proposal.json",
    ]
    # The unencrypted profile directory supplies only the reviewed signature.
    assert [s for s in sources if s.startswith("/etc/azazel/mio-profile")] == [
        "/etc/azazel/mio-profile/commissioning-proposal.sig",
    ]
    assert not any("secrets" in s or s.endswith(".key") for s in sources)
    assert settings["CapabilityBoundingSet"] == [""]


def test_no_packaged_unit_has_an_empty_set_credential():
    """systemd drops `SetCredential=ID:` with an empty value as invalid syntax.

    The fallback then silently does not exist, and a missing LoadCredential
    source fails the unit start (243/CREDENTIALS) instead of using it. Found on
    the Debian 13 test VM with `systemd-analyze verify`.
    """
    units = sorted((Path(__file__).resolve().parents[2] / "packaging/systemd").glob("*.service"))
    assert units
    for unit in units:
        for line in unit.read_text().splitlines():
            if line.startswith("SetCredential="):
                ident, _, value = line.partition("=")[2].partition(":")
                assert ident and value.strip(), f"{unit.name}: {line!r}"


def test_edge_core_posture_matches_the_packaged_health_contract():
    """Health and daemon startup must describe the same observe-only posture."""
    import json

    from azazel_nexus.edge_package import EDGE_PACKAGE_ROOT, EDGE_UNIT, HEALTH_ARGV
    from azazel_nexus.activation import UnitTier
    from azazel_nexus_runtime.units import UnitKey, UNIT_NAMES

    settings = _settings(EDGE_UNIT)
    environment = dict(value.split("=", 1) for value in settings["Environment"])
    schema = json.loads(
        (REPO_ROOT / "contract/azazel-edge-core/manifest-schema.json").read_text()
    )
    prefix = "startup.observe_only_env."
    posture_keys = {key.removeprefix(prefix) for key in schema["keys"]
                    if key.startswith(prefix)}
    posture = {
        "AZAZEL_DEFENSE_ENFORCE": "false",
        "AZAZEL_DEFENSE_DRY_RUN": "true",
        "AZAZEL_DEFENSE_ENFORCE_LEVEL": "advisory",
        "AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO": "false",
    }
    assert posture_keys == posture.keys()
    assert {key: value for key, value in environment.items()
            if key.startswith("AZAZEL_DEFENSE_") and key != "AZAZEL_DEFENSE_RELEASE_LEDGER"} == posture
    assert settings["ExecStart"] == [str(EDGE_PACKAGE_ROOT / HEALTH_ARGV[0])]
    assert settings["ExecStart"] == ["/opt/azazel/edge-core/bin/azazel-edge-core"]
    assert environment["AZAZEL_FORWARD_AI"] == "true"
    assert environment["AZAZEL_AI_SOCKET"] == "/var/lib/azazel/run/edge-intake/edge-intake.sock"
    # Edge's own JSONL copy is unbounded; the intake keeps the bounded record.
    assert environment["AZAZEL_FORWARD_LOG"] == "false"
    assert "AZAZEL_NORMALIZED_EVENT_LOG" not in environment
    assert environment["AZAZEL_DEFENSE_RELEASE_LEDGER"] == "/var/lib/azazel/edge-core/release-ledger.json"
    assert environment["AZAZEL_REDIRECT_POLICY_PATH"] == str(EDGE_PACKAGE_ROOT / "config/redirect_policy.yaml")
    assert environment["AZAZEL_EVE_PATH"] == "/var/log/suricata/eve.json"
    # Optional, so a host without Suricata yet still starts the unit.
    assert settings["ReadOnlyPaths"] == ["-/var/log/suricata"]
    # It owns nothing under /run: a RuntimeDirectory would chown and, on
    # stop, remove the /run/azazel the intake socket lives in.
    assert "RuntimeDirectory" not in settings
    assert settings["PrivateNetwork"] == ["yes"]
    # Edge's detection is weighted ahead of every other unit under load.
    assert settings["CPUWeight"] == ["400"]
    assert settings["ReadWritePaths"] == ["/var/lib/azazel/edge-core"]
    assert settings["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert settings["CapabilityBoundingSet"] == [""]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["IPAddressDeny"] == ["any"]
    assert settings["User"] == ["azedge"]
    assert "SupplementaryGroups" not in settings
    assert "AZAZEL_DEFENSE_ENFORCE=true" not in _unit(EDGE_UNIT)
    assert "EnvironmentFile" not in settings
    spec = next(spec for spec in LAYOUT if spec.path == "/var/lib/azazel/edge-core")
    assert (spec.owner, spec.mode) == ("azedge", 0o700)
    definition = next(definition for definition in CORE_UNITS if definition.name == EDGE_UNIT)
    assert definition.tier is UnitTier.EDGE_BASELINE
    assert UNIT_NAMES[UnitKey.EDGE_CORE] == EDGE_UNIT


# -- the Edge probe boot preflight (#206 P5, design E1) ---------------------


def _preflight():
    return next(p for p in UNGOVERNED_PROFILES if p.unit == EDGE_PROBE_PREFLIGHT_UNIT)


def _probed():
    return next(p for p in PROFILES if p.unit == "azazel-edge-probed.service")


def test_the_only_ungoverned_unit_is_the_probe_preflight():
    from azazel_nexus_runtime.hardening import DECOY_WATCH_PROFILES

    assert [p.unit for p in UNGOVERNED_PROFILES] == [EDGE_PROBE_PREFLIGHT_UNIT]
    # The Deception Lite verify unit (#196 G2) is not governed either, but it
    # is not enabled beside the controller: the decoy pulls it in.
    assert [p.unit for p in DECOY_WATCH_PROFILES] == ["azazel-decoy-verify.service"]
    assert ALL_PROFILES == PROFILES + UNGOVERNED_PROFILES + DECOY_WATCH_PROFILES


def test_the_probe_preflight_is_not_governed_anywhere():
    """Not in the controller's lists, so a pass never masks or unmasks it."""

    from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT as controller
    from azazel_nexus_runtime.hardening import governed_units
    from azazel_nexus_runtime.units import UNIT_NAMES

    assert EDGE_PROBE_PREFLIGHT_UNIT not in {d.name for d in CORE_UNITS}
    assert EDGE_PROBE_PREFLIGHT_UNIT not in governed_units()
    assert EDGE_PROBE_PREFLIGHT_UNIT not in UNIT_NAMES.values()
    assert EDGE_PROBE_PREFLIGHT_UNIT not in {p.unit for p in PROFILES}
    assert EDGE_PROBE_PREFLIGHT_UNIT != controller


def test_the_probe_preflight_runs_only_the_fixed_probe_binary_as_azprobe():
    settings = _settings(EDGE_PROBE_PREFLIGHT_UNIT)
    assert settings["ExecStart"] == ["/usr/libexec/azazel/az-edge-probed"]
    assert settings["ExecStart"] == _settings("azazel-edge-probed.service")["ExecStart"]
    assert settings["User"] == ["azprobe"]
    assert settings["Type"] == ["oneshot"]
    for key in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
                "ExecReload", "ExecCondition", "Group", "SupplementaryGroups",
                "Environment", "EnvironmentFile", "LoadCredential",
                "SetCredential", "RuntimeDirectory"):
        assert key not in settings, f"the preflight unexpectedly sets {key}"


def test_the_probe_preflight_is_read_only_with_the_probe_sandbox():
    """Same sandbox as the governed probe: AF_UNIX only, no addresses, one leaf."""

    preflight, probed = _preflight(), _probed()
    for field in ("executable", "account", "address_families", "read_write_paths",
                  "optional_read_write_paths", "supplementary_groups",
                  "capability_bounding_set", "unit_type", 
                  "is_artifact_fetcher", "is_model_host", "is_inference_transport",
                  "default_dependencies"):
        assert getattr(preflight, field) == getattr(probed, field), field
    # The governed probe waits for its grant marker; the ungoverned preflight
    # runs before the pass, when no marker can exist, so it has no condition.
    assert preflight.conditions == ()
    settings = _settings(EDGE_PROBE_PREFLIGHT_UNIT)
    assert settings["RestrictAddressFamilies"] == ["AF_UNIX"]
    assert settings["IPAddressDeny"] == ["any"]
    assert "IPAddressAllow" not in settings
    assert settings["ReadWritePaths"] == ["/var/lib/azazel/run/edge-probe"]
    for key, value in SHARED_HARDENING:
        assert settings.get(key) == [value], key
    probed_settings = _settings("azazel-edge-probed.service")
    for key in [key for key, _ in SHARED_HARDENING] + ["RestrictAddressFamilies",
                                                        "ReadWritePaths", "User"]:
        assert settings[key] == probed_settings[key], key


def test_the_probe_preflight_runs_before_the_controller_and_needs_nothing_of_it():
    settings = _settings(EDGE_PROBE_PREFLIGHT_UNIT)
    assert settings["Before"] == [ACTIVATION_CONTROLLER_UNIT]
    for key in ("After", "Requires", "BindsTo", "Wants", "Requisite", "PartOf",
                "Conflicts"):
        assert key not in settings, f"the preflight sets {key}"
    assert settings["WantedBy"] == ["multi-user.target"]
    assert settings["TimeoutStartSec"] == ["60s"]
    # Ordered before the controller, so its result is from this boot when the
    # pass reads it; nothing it does is a precondition of the pass.
    assert "azazel-edge-probe-preflight" not in _unit(ACTIVATION_CONTROLLER_UNIT)


# -- Deception Lite exposure units (#196 P1, design D1) ---------------------


HELPER = "azazel-decoy-netd.service"
DECOY = "azazel-decoyd.service"


def _profile(unit):
    return next(p for p in PROFILES if p.unit == unit)


def test_cap_net_admin_is_held_by_the_three_one_shot_decoy_units_alone():
    """The helper (host side), the namespace unit (the inside; #196 body, §13)
    and the verify unit, which lists the table (#196 G2, grant §10 Q7)."""

    holders = [p.unit for p in ALL_PROFILES if "CAP_NET_ADMIN" in p.capability_bounding_set]
    assert holders == ["azazel-decoy-nsd.service", HELPER, "azazel-decoy-verify.service"]
    for path in UNIT_DIR.glob("*.service"):
        if path.name not in holders:
            settings = _settings(path.name)
            for key in ("CapabilityBoundingSet", "AmbientCapabilities"):
                assert not any("CAP_NET_ADMIN" in value
                               for value in settings.get(key, [])), path.name


def test_the_decoy_network_helper_runs_once_with_exactly_cap_net_admin():
    settings = _settings(HELPER)
    assert settings["Type"] == ["oneshot"]
    assert settings["RemainAfterExit"] == ["yes"]
    assert settings["User"] == ["root"]
    assert settings["ExecStart"] == ["/usr/libexec/azazel/az-decoy-netd"]
    assert settings["ExecStop"] == ["/usr/libexec/azazel/az-decoy-netd stop"]
    assert settings["CapabilityBoundingSet"] == ["CAP_NET_ADMIN"]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["NoNewPrivileges"] == ["yes"]
    # Root, so no AF_UNIX: it cannot reach the service manager over D-Bus.
    assert settings["RestrictAddressFamilies"] == ["AF_NETLINK"]
    assert settings["IPAddressDeny"] == ["any"]
    # Its one writable place is its own runtime directory, for this boot's
    # isolation record (#196 §14); no declared writable path, no namespace of
    # its own (it would configure the host's links).
    assert settings["RuntimeDirectory"] == ["azazel-decoy-isolation"]
    assert settings["RuntimeDirectoryMode"] == ["0755"]
    # Its one input (#196 G1b, grant §4.3 H3): the scope file, as exactly one
    # credential, with no fallback, so that a missing file fails the start.
    assert settings["LoadCredential"] == [
        "decoy-scope:/run/azazel-activation/decoy-scope.json"]
    for key in ("ReadWritePaths", "NetworkNamespacePath",
                "PrivateNetwork", "SupplementaryGroups", "SetCredential",
                "LoadCredentialEncrypted", "ImportCredential", "SetCredentialEncrypted",
                "Environment", "EnvironmentFile", "ExecStartPre", "IPAddressAllow",
                "RuntimeDirectoryPreserve", "StateDirectory", "BindPaths"):
        assert key not in settings, key
    # m2 of the review of #268 (#196 body): the further sandbox.
    for key in ("ProtectClock", "ProtectHostname", "ProtectKernelLogs",
                "RestrictRealtime"):
        assert settings[key] == ["yes"], key
    assert settings["InaccessiblePaths"] == ["-/run/dbus/system_bus_socket",
                                             "-/run/systemd/private"]
    for key in ("ProtectSystem", "PrivateTmp", "PrivateDevices", "RestrictNamespaces"):
        assert settings[key] == [dict(SHARED_HARDENING)[key]], key


@pytest.mark.parametrize("path", [
    "/run", "/run/", "-/run", "/run/azazel-decoy-isolation", "-/run/azazel-decoy-isolation/",
    "/run/azazel-decoy-isolation/isolation.json",
])
@pytest.mark.parametrize("field", ["read_write_paths", "optional_read_write_paths"])
@pytest.mark.parametrize("unit", ["azazel-decoyd.service", "azazel-mio-entryd.service",
                                  "azazel-activated.service"])
def test_no_unit_may_declare_run_or_the_isolation_record_writable(unit, field, path):
    """Review of #274: only the helper's runtime directory reaches the record."""

    from dataclasses import replace

    profile = next(p for p in ALL_PROFILES if p.unit == unit)
    with pytest.raises(ValueError, match="not a declared writable path"):
        replace(profile, **{field: getattr(profile, field) + (path,)})


@pytest.mark.parametrize("change", [
    (),
    (("RemainAfterExit", "yes"), ("TimeoutStartSec", "30s")),
    "drop-last",
    "add-environment",
    "other-stop",
    "no-scope",
    "other-scope-source",
    "scope-fallback",
    "second-credential",
])
def test_the_helper_extra_is_pinned_whole(change):
    from dataclasses import replace

    from azazel_nexus_runtime.hardening import DECOY_HELPER_SANDBOX

    def swap(changed, new_value):
        return tuple((key, new_value) if key == changed else (key, value)
                     for key, value in DECOY_HELPER_SANDBOX)

    extra = {
        "drop-last": DECOY_HELPER_SANDBOX[:-1],
        "add-environment": DECOY_HELPER_SANDBOX + (("Environment", "X=1"),),
        "other-stop": swap("ExecStop", "/usr/sbin/nft flush ruleset"),
        "no-scope": tuple(item for item in DECOY_HELPER_SANDBOX
                          if item[0] != "LoadCredential"),
        "other-scope-source": swap("LoadCredential",
                                   "decoy-scope:/etc/azazel/decoy-scope.json"),
        # A fallback would turn a missing scope into a start (#196 G1b).
        "scope-fallback": DECOY_HELPER_SANDBOX + (("SetCredential", "decoy-scope:{}"),),
        "second-credential": DECOY_HELPER_SANDBOX + (
            ("LoadCredential", "node:/etc/azazel/node.yaml"),),
    }.get(change, change)
    with pytest.raises(ValueError, match="in extra"):
        replace(_profile(HELPER), extra=extra)


def test_the_scope_credential_is_the_one_the_helper_reads():
    """The unit's credential name and source, and the reader's fixed path (G1b)."""

    from azazel_nexus.decoy_scope import SCOPE_CREDENTIAL_PATH
    from azazel_nexus_runtime.hardening import DECOY_HELPER_SANDBOX, DECOY_SCOPE_CREDENTIAL

    name, _, source = DECOY_SCOPE_CREDENTIAL.partition(":")
    assert (name, source) == ("decoy-scope", "/run/azazel-activation/decoy-scope.json")
    assert SCOPE_CREDENTIAL_PATH == f"/run/credentials/{HELPER}/{name}"
    assert [value for key, value in DECOY_HELPER_SANDBOX
            if key == "LoadCredential"] == [DECOY_SCOPE_CREDENTIAL]
    assert not [key for key, _ in DECOY_HELPER_SANDBOX
                if key != "LoadCredential" and "Credential" in key]


@pytest.mark.parametrize("unit", ["azazel-decoyd.service", "azazel-mio-entryd.service",
                                  "azazel-knowledge-lited.service"])
@pytest.mark.parametrize("credential", [
    ("LoadCredential", "decoy-scope:/run/azazel-activation/decoy-scope.json"),
    ("LoadCredential", "x:/run/azazel-activation/decoy-scope.json"),
    ("LoadCredential", "grants:/run/azazel-activation/granted"),
    ("ImportCredential", "decoy-scope"),
])
def test_no_other_unit_may_load_the_scope(unit, credential):
    from dataclasses import replace

    profile = next(p for p in ALL_PROFILES if p.unit == unit)
    with pytest.raises(ValueError, match="credential alone"):
        replace(profile, extra=profile.extra + (credential,))


def test_the_decoy_has_no_capability_and_listens_only_in_its_namespace():
    from azazel_nexus_runtime.hardening import DECOY_NAMESPACE_PATH

    settings = _settings(DECOY)
    assert settings["User"] == ["azdecoy"]
    assert settings["ExecStart"] == ["/usr/libexec/azazel/az-decoyd"]
    assert settings["CapabilityBoundingSet"] == [""]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["NetworkNamespacePath"] == [DECOY_NAMESPACE_PATH]
    assert DECOY_NAMESPACE_PATH == "/run/netns/azazel-decoy"
    assert settings["PrivateUsers"] == ["yes"]
    # #276 F10: it binds the IPv4 wildcard only, so no AF_INET6.
    assert settings["RestrictAddressFamilies"] == ["AF_UNIX AF_INET"]
    assert settings["IPAddressDeny"] == ["any"]
    # The fixed decoy subnet and nothing else (#196 body, §13): without it
    # the cgroup filter drops what the decoy receives as well.
    assert settings["IPAddressAllow"] == ["10.255.196.0/30"]
    from azazel_nexus_runtime.decoy_addresses import DECOY_SUBNET
    assert settings["IPAddressAllow"] == [DECOY_SUBNET]
    assert "PrivateNetwork" not in settings
    # #276 F10: it writes no file, so no writable path; the manager's private
    # sockets are inaccessible to it, as to the helper.
    assert settings["InaccessiblePaths"] == ["-/run/dbus/system_bus_socket",
                                             "-/run/systemd/private"]
    for key in ("SupplementaryGroups", "RuntimeDirectory", "LoadCredential",
                "Environment", "EnvironmentFile", "ExecStartPre", "ReadWritePaths",
                "StateDirectory", "BindPaths"):
        assert key not in settings, key
    # After and Requires the helper as well as the controller: stopping the
    # helper stops the decoy first. And the watch (#196 G2): after a verify
    # that passed, requiring it and its timer.
    assert settings["Requires"] == [ACTIVATION_CONTROLLER_UNIT, HELPER,
                                    "azazel-decoy-verify.service",
                                    "azazel-decoy-verify.timer"]
    assert settings["After"] == [ACTIVATION_CONTROLLER_UNIT, HELPER,
                                 "azazel-decoy-verify.service"]
    from azazel_nexus.layout import spec_for
    spec = spec_for("/var/lib/azazel/decoy")
    assert (spec.owner, spec.group, spec.mode) == ("azdecoy", "root", 0o700)


def test_the_decoy_and_the_helper_share_one_manager_socket_list():
    from azazel_nexus_runtime.hardening import (
        DECOY_HELPER_SANDBOX,
        DECOY_MANAGER_SOCKETS_INACCESSIBLE,
    )

    assert DECOY_MANAGER_SOCKETS_INACCESSIBLE == (
        ("InaccessiblePaths", "-/run/dbus/system_bus_socket"),
        ("InaccessiblePaths", "-/run/systemd/private"))
    assert DECOY_HELPER_SANDBOX[-2:] == DECOY_MANAGER_SOCKETS_INACCESSIBLE
    assert _profile(DECOY).extra[-2:] == DECOY_MANAGER_SOCKETS_INACCESSIBLE


@pytest.mark.parametrize("families", [
    ("AF_UNIX", "AF_INET", "AF_INET6"), ("AF_UNIX", "AF_INET6"), ("AF_INET",),
    ("AF_UNIX", "AF_INET", "AF_NETLINK"), ("AF_INET", "AF_UNIX"),
])
def test_the_decoy_gets_exactly_unix_and_ipv4(families):
    """#276 F10: no AF_INET6 (it binds IPv4 only) and nothing else."""

    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(_profile(DECOY), address_families=families)


@pytest.mark.parametrize("field,path", [
    ("read_write_paths", "/var/lib/azazel/decoy"),
    ("optional_read_write_paths", "/var/lib/azazel/decoy"),
])
def test_the_decoy_declares_no_writable_path(field, path):
    from dataclasses import replace

    with pytest.raises(ValueError, match="writes no file"):
        replace(_profile(DECOY), **{field: (path,)})


@pytest.mark.parametrize("change", ["drop-one", "drop-both", "add-other", "reorder"])
def test_the_decoy_keeps_exactly_the_manager_sockets_inaccessible(change):
    from dataclasses import replace

    profile = _profile(DECOY)
    rest = tuple(item for item in profile.extra if item[0] != "InaccessiblePaths")
    paths = tuple(item for item in profile.extra if item[0] == "InaccessiblePaths")
    extra = {
        "drop-one": rest + paths[:1],
        "drop-both": rest,
        "add-other": profile.extra + (("InaccessiblePaths", "-/run/other"),),
        "reorder": rest + paths[::-1],
    }[change]
    with pytest.raises(ValueError, match="InaccessiblePaths"):
        replace(profile, extra=extra)


@pytest.mark.parametrize("key", ["BindPaths", "ReadWritePaths", "ExecStop"])
def test_the_decoy_may_state_no_other_reserved_key(key):
    from dataclasses import replace

    profile = _profile(DECOY)
    with pytest.raises(ValueError, match="in extra"):
        replace(profile, extra=profile.extra + ((key, "/run/other"),))


def test_both_exposure_units_carry_the_three_marker_lines_and_pass_the_content_check():
    """#253: the file check and the marker condition apply to them as to any grantable unit."""

    from azazel_nexus_runtime.activation_unit_files import (
        require_governed_unit_content,
        required_unit_lines,
    )

    for unit in (HELPER, DECOY):
        text = _unit(unit)
        unit_section = text.split("[Unit]", 1)[1].split("[Service]", 1)[0].splitlines()
        assert set(required_unit_lines(unit)) <= set(unit_section)
        require_governed_unit_content(unit, text.encode("ascii"))


@pytest.mark.parametrize("change", [
    {"capability_bounding_set": ("CAP_NET_ADMIN", "CAP_SYS_ADMIN")},
    {"capability_bounding_set": ("CAP_SYS_ADMIN",)},
    {"capability_bounding_set": ()},
])
def test_the_helper_cannot_be_declared_wider_or_different(change):
    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(_profile(HELPER), **change)


@pytest.mark.parametrize("unit", ["azazel-mio-entryd.service", "azazel-decoyd.service"])
def test_no_other_unit_can_take_cap_net_admin(unit):
    from dataclasses import replace

    with pytest.raises(ValueError, match="CAP_NET_ADMIN"):
        replace(_profile(unit), capability_bounding_set=("CAP_NET_ADMIN",))


@pytest.mark.parametrize("change", [
    {"capability_bounding_set": ("CAP_NET_BIND_SERVICE",)},
    {"account": "root"},
    {"supplementary_groups": ("azazel-operator",)},
    {"extra": (("PrivateUsers", "yes"),)},
    {"extra": (("NetworkNamespacePath", "/run/netns/other"), ("PrivateUsers", "yes"))},
    {"extra": (("NetworkNamespacePath", "/run/netns/azazel-decoy"),)},
    {"extra": (("NetworkNamespacePath", "/run/netns/azazel-decoy"), ("PrivateUsers", "yes"),
               ("IPAddressAllow", "192.0.2.0/24"))},
    {"extra": (("NetworkNamespacePath", "/run/netns/azazel-decoy"), ("PrivateUsers", "yes"),
               ("PrivateNetwork", "yes"))},
    {"unit": "azazel-other.service"},
])
def test_the_decoy_listener_role_refuses_anything_wider(change):
    """A changed or extra address allowance is refused as well (below)."""

    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(_profile(DECOY), **change)


@pytest.mark.parametrize("allowance", [
    None, ["any"], ["localhost"], ["10.255.196.0/29"], ["10.255.196.0/30", "localhost"],
    ["10.255.196.0/30", "10.255.196.0/30"],
])
def test_the_decoy_allows_exactly_the_fixed_subnet(allowance):
    from dataclasses import replace

    profile = _profile(DECOY)
    extra = tuple(item for item in profile.extra if item[0] != "IPAddressAllow")
    extra += tuple(("IPAddressAllow", value) for value in (allowance or ()))
    with pytest.raises(ValueError, match="IPAddressAllow"):
        replace(profile, extra=extra)


def test_the_decoy_sees_only_its_own_processes_in_proc():
    """#289 F1: its AppArmor rule for /proc/<pid>/net/dev has no `owner`
    (G4), so `ProtectProc=invisible` keeps other users' pids out of sight.
    Not `ProcSubset=pid`: the decoy reads /proc/sys/kernel/random/boot_id."""

    settings = _settings(DECOY)
    assert settings["ProtectProc"] == ["invisible"]
    assert "ProcSubset" not in settings


@pytest.mark.parametrize("change", [
    lambda extra: tuple(item for item in extra if item[0] != "ProtectProc"),
    lambda extra: tuple(("ProtectProc", "noaccess") if item[0] == "ProtectProc" else item
                        for item in extra),
    lambda extra: extra + (("ProtectProc", "invisible"),),
    lambda extra: extra + (("ProcSubset", "pid"),),
    lambda extra: extra + (("ProcSubset", "all"),),
])
def test_the_decoy_states_protect_proc_invisible_and_no_proc_subset(change):
    from dataclasses import replace

    profile = _profile(DECOY)
    with pytest.raises(ValueError, match="ProtectProc"):
        replace(profile, extra=change(profile.extra))


def test_a_decoy_listener_without_an_internet_family_cannot_be_built():
    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(_profile(DECOY), address_families=("AF_UNIX",))


def test_the_installer_masks_and_never_enables_the_exposure_units():
    for unit in (HELPER, DECOY):
        assert f'install -m 0644 "$HERE"/systemd/{unit} "$UNIT_DIR"' in INSTALLER
        assert f"systemctl mask {unit}" in INSTALLER
        assert f"systemctl enable {unit}" not in INSTALLER
        assert f"systemctl start {unit}" not in INSTALLER
    assert "make_owned_dir 0700 azdecoy root /var/lib/azazel/decoy" in INSTALLER


@pytest.mark.parametrize("families", [("AF_UNIX", "AF_NETLINK"), ("AF_UNIX",),
                                      ("AF_NETLINK", "AF_UNIX")])
def test_the_root_helper_cannot_be_given_a_unix_socket(families):
    from dataclasses import replace

    with pytest.raises(ValueError, match="netlink only"):
        replace(_profile(HELPER), address_families=families)


@pytest.mark.parametrize("unit", ["azazel-mio-entryd.service", "azazel-decoyd.service",
                                  "azazel-edge-core.service"])
def test_only_the_controller_and_the_helper_may_run_as_root(unit):
    from dataclasses import replace

    with pytest.raises(ValueError, match="would run as root"):
        replace(_profile(unit), account="root", is_decoy_listener=False,
                address_families=("AF_UNIX",))
