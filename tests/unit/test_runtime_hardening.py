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
        if not (profile.is_artifact_fetcher or profile.is_inference_transport):
            assert allowed & {"AF_INET", "AF_INET6"} == set(), profile.unit


def test_exactly_one_profile_holds_each_network_role():
    """A third would be a diff a reviewer sees, not a set that grew.

    Each role is counted separately, so a second fetcher cannot hide behind
    the transport's exemption and the reverse.
    """

    fetchers = [p.unit for p in PROFILES if p.is_artifact_fetcher]
    transports = [p.unit for p in PROFILES if p.is_inference_transport]
    hosts = [p.unit for p in PROFILES if p.is_model_host]
    assert fetchers == ["azazel-model-fetchd.service"]
    assert transports == ["azazel-mio-remoted.service"]
    assert hosts == ["azazel-mio-locald.service"]
    assert len(set(fetchers + transports + hosts)) == 3, (
        "one unit holds two roles; the three acts are kept in three units"
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
    assert with_netlink == ["azazel-activated.service", "azazel-commissiond.service"]
    for unit in with_netlink:
        settings = _settings(unit)
        assert settings["RestrictAddressFamilies"] == ["AF_UNIX AF_NETLINK"]
        assert settings["CapabilityBoundingSet"] == (
            ["CAP_DAC_READ_SEARCH"]
            if unit == "azazel-activated.service" else [""]
        )
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
        assert settings["CapabilityBoundingSet"] == [""]
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
        "azazel-incident-explaind.service",
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
        "/run/azazel-nexus-bootstrap",
    }
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


def test_overlay_write_scope_and_boot_provisioning_order_are_controller_only():
    writers = [profile.unit for profile in PROFILES
               if "/run/systemd/system.control" in profile.read_write_paths]
    assert writers == [ACTIVATION_CONTROLLER_UNIT]
    controller = next(profile for profile in PROFILES if profile.unit == ACTIVATION_CONTROLLER_UNIT)
    assert "systemd-tmpfiles-setup.service" in controller.after
    assert not {"/run", "/run/systemd"} & set(controller.read_write_paths)
    claim_writers = [profile.unit for profile in PROFILES
                     if "/run/azazel-nexus-bootstrap" in profile.read_write_paths]
    assert claim_writers == [ACTIVATION_CONTROLLER_UNIT]
    assert controller.conditions == (
        ("ConditionPathExists", "!/run/azazel-nexus-bootstrap/controller-used"),
    )
    assert all(
        not any(key == "ConditionPathExists" for key, _ in profile.conditions)
        for profile in PROFILES
        if profile.unit != ACTIVATION_CONTROLLER_UNIT
    )
    from dataclasses import replace
    with pytest.raises(ValueError, match="only by the activation controller"):
        replace(controller, unit="azazel-other.service")


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
        assert int(mode, 8) == 0o750


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
            if (key == "CapabilityBoundingSet"
                    and profile.unit == "azazel-activated.service"):
                value = "CAP_DAC_READ_SEARCH"
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
          "/var/lib/azazel/run/audit-status",
          "/var/lib/azazel/state/audit", "/var/lib/azazel/state/auditd"]),
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
    run_grants = [p for p in written if p == "/var/lib/azazel/run"
                  or p.startswith("/var/lib/azazel/run/")]
    snapshot = (["/var/lib/azazel/run/" + audit_status_path().parent.name]
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
        "mio-profile:/etc/azazel/mio-profile",
        "mio-trust:/etc/azazel/operator-trust/operators.json",
        "mio-node:/etc/azazel/node.yaml",
    ]
    assert settings["SetCredential"] == ["mio-trust:absent", "mio-node:absent"]
    assert all(source.split(":", 1)[1] != "/etc/azazel/commissioning"
               for source in settings["LoadCredential"])
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
