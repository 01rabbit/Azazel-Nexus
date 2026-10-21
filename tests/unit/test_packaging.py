"""The installer, the preset, and the unit files (#28).

`IMPLEMENTATION_SPEC.md` §2.3 opens with a sentence the whole slice is built
around: *installation MUST NOT start an operational network service*. These
tests read what the installer would do rather than what it says it does.

They read text. None of them runs the installer, masks a unit, or speaks to
systemd -- that half is `HG-01` in `docs/hardware-gates.md`, and it stays
open. What a text scan can establish is that the files agree with each other
and with the declarations in `azazel_nexus`, which is the drift these tests
exist to catch.
"""

from __future__ import annotations

import re
import stat
from pathlib import Path

import pytest

from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT, CORE_UNITS
from azazel_nexus.layout import LAYOUT, create_layout

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGING = REPO_ROOT / "packaging"
INSTALLER = PACKAGING / "install.sh"
PRESET = PACKAGING / "azazel-nexus.preset"
UNIT_DIR = PACKAGING / "systemd"
BOOTSTRAP_TMPFILES = PACKAGING / "tmpfiles.d" / "azazel-nexus-bootstrap.conf"
EXPECTED_BOOTSTRAP_TMPFILES = (
    b"d /run/systemd/system.control :0755 :root :root - -\n"
    b"d /run/azazel-nexus-bootstrap :0700 :root :root - -\n"
    b"d /run/azazel-mio-identity 0750 root azmio - -\n"
    b"d /etc/azazel/mio-profile 0700 root root - -\n"
    b"d /run/azazel-activation 0755 root root - -\n"
)

GOVERNED = tuple(d.name for d in CORE_UNITS)
#: Installed and enabled beside the controller, and governed by nothing:
#: the read-only Edge probe preflight (#206 P5).
PROBE_PREFLIGHT = "azazel-edge-probe-preflight.service"
ALL_UNITS = GOVERNED + (ACTIVATION_CONTROLLER_UNIT, PROBE_PREFLIGHT)


def _installer() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def _preset_directives() -> list[tuple[str, str]]:
    directives = []
    for line in PRESET.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        verb, _, unit = line.partition(" ")
        directives.append((verb, unit.strip()))
    return directives


def _systemctl_calls(verb: str) -> list[str]:
    """Every `systemctl <verb> <unit>` the installer would run.

    Comments are stripped first: this file explains itself at length, and a
    scan that counted the word `start` inside a comment would report a
    violation that does not exist -- or, worse, be loosened until it stopped.
    """

    calls = []
    for line in _installer().splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        match = re.match(rf"systemctl\s+{verb}\s+(?:--\S+\s+)*(\S+)$", line)
        if match:
            calls.append(match.group(1))
    return calls


# -- unit files ---------------------------------------------------------


def test_every_unit_the_controller_governs_has_a_unit_file():
    missing = [name for name in ALL_UNITS if not (UNIT_DIR / name).is_file()]
    assert missing == [], f"{missing} are governed or installed but have no unit file"


def test_no_unit_file_exists_for_a_component_this_slice_does_not_install():
    """The packaging tree describes what exists, not what is planned.

    The enforcement, M.I.O., Knowledge Lite, Deception Lite and module-manager
    units belong to slices that are not built. A unit file shipped ahead of
    its daemon is a unit that fails at boot and a claim that the component is
    present.
    """

    present = sorted(path.name for path in UNIT_DIR.glob("*.service"))
    assert present == sorted(ALL_UNITS), (
        f"the packaged units are {present}; the controller governs "
        f"{sorted(GOVERNED)} plus {ACTIVATION_CONTROLLER_UNIT} and "
        f"{PROBE_PREFLIGHT}"
    )


def test_bootstrap_tmpfiles_creates_only_exact_persistent_runtime_directories():
    raw = BOOTSTRAP_TMPFILES.read_bytes()
    directives = [line for line in raw.splitlines(keepends=True)
                  if line.strip() and not line.lstrip().startswith(b"#")]
    assert directives == EXPECTED_BOOTSTRAP_TMPFILES.splitlines(keepends=True)
    assert all(line.split()[-2:] == [b"-", b"-"] for line in directives)


def test_each_unit_file_declares_the_account_its_definition_names():
    for definition in CORE_UNITS:
        text = (UNIT_DIR / definition.name).read_text(encoding="utf-8")
        assert f"User={definition.account}" in text, (
            f"{definition.name} does not run as {definition.account}; a unit "
            "whose identity is unstated runs as whatever the file last said"
        )


def test_no_governed_unit_runs_as_root():
    """The activation controller is root. The three it governs are not.

    A design where all four are root is one where least privilege is a
    comment -- and the only thing between a bug in the netlink parser and the
    whole host is that the parser has no bug.
    """

    # One named exception (#196 P1): the one-shot decoy network helper runs
    # as root so that its CAP_NET_ADMIN bounding set reaches it without an
    # ambient grant. It writes nothing and the pass never grants it.
    assert [d.name for d in CORE_UNITS if d.account == "root"] == [
        "azazel-decoy-netd.service"]
    assert len({d.account for d in CORE_UNITS}) == len(CORE_UNITS), (
        "two governed daemons share an account, so a fault in one runs with "
        "the other's access"
    )


def test_each_unit_file_refuses_privilege_escalation():
    """`NoNewPrivileges=yes` on every unit, including the controller.

    The controller is root already; the setting is there so that what it
    execs cannot become more than root gave it.
    """

    for name in ALL_UNITS:
        text = (UNIT_DIR / name).read_text(encoding="utf-8")
        assert "NoNewPrivileges=yes" in text, f"{name} permits privilege gain"


def test_no_governed_unit_is_ordered_before_the_activation_controller():
    """A governed unit that started first would start while masked or not at all.

    Either way the controller's verdict would not be what decided it.
    """

    for name in GOVERNED:
        text = (UNIT_DIR / name).read_text(encoding="utf-8")
        assert f"After={ACTIVATION_CONTROLLER_UNIT}" in text or (
            "After=azazel-auditd.service" in text
        ), f"{name} does not order itself after the activation controller"
        assert f"Requires={ACTIVATION_CONTROLLER_UNIT}" in text, (
            f"{name} does not require the controller; a governed unit that can "
            "run without the component that validated it is not governed"
        )


# -- the preset ---------------------------------------------------------


def test_the_preset_disables_every_governed_unit():
    directives = {unit: verb for verb, unit in _preset_directives()}
    for name in GOVERNED:
        assert directives.get(name) == "disable", (
            f"{name} is not preset-disabled; a distribution running "
            "`systemctl preset-all` would enable it because it carries an "
            "[Install] section"
        )


def test_the_preset_enables_only_the_controller_and_the_probe_preflight():
    enabled = [unit for verb, unit in _preset_directives() if verb == "enable"]
    assert enabled == [ACTIVATION_CONTROLLER_UNIT, PROBE_PREFLIGHT]
    assert PROBE_PREFLIGHT not in GOVERNED


def test_the_preset_uses_no_glob():
    """`enable azazel-*` would re-enable the operational units on preset-all.

    That is precisely the failure the preset is there to prevent, so the
    directives name units exactly.
    """

    globbed = [unit for _, unit in _preset_directives() if "*" in unit or "?" in unit]
    assert globbed == []


# -- the installer ------------------------------------------------------


def test_the_installer_starts_nothing():
    """IMPLEMENTATION_SPEC 2.3, checked rather than quoted."""

    assert _systemctl_calls("start") == []
    assert _systemctl_calls("restart") == []


def test_the_installer_masks_every_governed_unit():
    """Masked, not merely disabled.

    A disabled unit is one `systemctl start` away from running. A masked one
    refuses until the controller unmasks it against a revalidated generation.
    """

    installer_masks = _systemctl_calls("mask")
    preset_masks = [unit for verb, unit in _preset_directives() if verb == "disable"]
    assert sorted(installer_masks) == sorted(GOVERNED)
    assert sorted(installer_masks) == sorted(preset_masks), (
        "installer mask actions and declarative preset intent must stay aligned"
    )


def test_the_installer_enables_only_the_controller_and_the_probe_preflight():
    assert _systemctl_calls("enable") == [ACTIVATION_CONTROLLER_UNIT, PROBE_PREFLIGHT]


def test_the_installer_installs_and_never_masks_the_probe_preflight():
    """Masking it would stop the boot-time Edge evidence it exists to give."""

    assert f'"$HERE"/systemd/{PROBE_PREFLIGHT} "$UNIT_DIR"' in _installer()
    assert PROBE_PREFLIGHT not in _systemctl_calls("mask")
    assert PROBE_PREFLIGHT not in _systemctl_calls("unmask")


def test_the_installer_refuses_while_the_daemons_it_names_are_absent():
    """This slice ships unit files and no executables.

    An installer that enabled a unit whose ExecStart does not exist would
    "succeed" into a boot failure. The refusal is what makes the missing half
    visible at install time instead of on a rugged PC.
    """

    text = _installer()
    assert "refusing to install" in text
    assert "install_profile_fields.py" in text
    assert 'LIBEXEC=$(profile_field libexec_directory)' in text
    assert '--platform-profile "$INSTALL_PROFILE_ID"' in text


def test_installer_resolves_a_reviewed_os_profile_before_writing():
    text = _installer()
    profile_resolution = text.index('INSTALL_PROFILE_ID=$(profile_field profile_id)')
    first_account_write = text.index('useradd --system')
    first_directory_write = text.index('make_dir 0755 root /etc/azazel')
    assert profile_resolution < first_account_write
    assert profile_resolution < first_directory_write
    assert "no reviewed install profile" in text


def test_every_nexus_unit_names_an_executable_the_installer_checks_for():
    # `az-[a-z]+` stopped at the first dash and read `az-edge-probed` as
    # `az-edge`, so the unit that most needed checking was the one the
    # assertion could not see.
    checked = set(re.findall(r"\baz-[a-z]+(?:-[a-z]+)*\b", _installer()))
    for name in ALL_UNITS:
        text = (UNIT_DIR / name).read_text(encoding="utf-8")
        exec_start = re.search(r"^ExecStart=(\S+)", text, re.M)
        assert exec_start, f"{name} has no ExecStart"
        if name == "azazel-edge-core.service":
            # Edge is installed separately and verified before baseline admission.
            assert exec_start.group(1) == "/opt/azazel/edge-core/bin/azazel-edge-core"
            continue
        binary = Path(exec_start.group(1)).name
        assert binary in checked, (
            f"{name} execs {binary}, which the installer's preflight does not "
            "check for; the refusal would miss exactly this unit"
        )


# -- the layout ---------------------------------------------------------


def test_the_installer_creates_exactly_the_declared_layout():
    """`layout.py` and `install.sh` are one declaration in two places.

    §3 calls these permissions mandatory defaults. A default that lives in a
    document is a default until the first installer that disagrees, and
    nothing notices.
    """

    installer = _installer()
    found = {
        path: (int(mode, 8), "root", group)
        for mode, group, path in re.findall(
            r"^make_dir (\d{4}) (\S+) (/\S+)$", installer, re.M
        )
    }
    found.update({
        path: (int(mode, 8), owner, group)
        for mode, owner, group, path in re.findall(
            r"^make_owned_dir (\d{4}) (\S+) (\S+) (/\S+)$", installer, re.M
        )
    })
    declared = {
        spec.path: (spec.mode, spec.owner, spec.group)
        for spec in LAYOUT
    }
    assert found == declared, (
        "the installer and the layout disagree about a directory's mode or "
        "group. A writable path nobody declared is a path nobody set the "
        "owner of"
    )
    assert all(
        spec.owner == "root" or spec.path in found
        for spec in LAYOUT
    ), "non-root-owned layout paths must use the explicit make_owned_dir adapter"
    assert '-o root -g "$2"' in _installer(), (
        "`make_dir` no longer applies the declared ownership"
    )
    assert '-o "$2" -g "$3"' in _installer(), (
        "`make_owned_dir` no longer applies declared service ownership"
    )


def test_the_declared_modes_survive_creation(tmp_path):
    create_layout(tmp_path)
    for spec in LAYOUT:
        target = tmp_path / spec.path.lstrip("/")
        assert target.is_dir(), f"{spec.path} was not created"
        observed_mode = stat.S_IMODE(target.stat().st_mode)
        assert observed_mode == spec.mode, (
            f"{spec.path} was created with the process umask rather than the "
            f"declared {spec.mode:04o}"
        )


def test_service_socket_directories_are_setgid_for_operator_group_inheritance():
    socket_dirs = {
        spec.path: spec
        for spec in LAYOUT
        if spec.path.startswith("/var/lib/azazel/run/")
    }
    assert set(socket_dirs) == {
        "/var/lib/azazel/run/audit",
        "/var/lib/azazel/run/audit-submit",
        "/var/lib/azazel/run/audit-status",
        "/var/lib/azazel/run/commission",
        "/var/lib/azazel/run/watchdog",
        "/var/lib/azazel/run/edge-probe",
        "/var/lib/azazel/run/edge-intake",
        "/var/lib/azazel/run/edge-intake-status",
        "/var/lib/azazel/run/incident-explain-status",
        "/var/lib/azazel/run/fetch",
        "/var/lib/azazel/run/mio-entry",
        "/var/lib/azazel/run/mio-advise",
        "/var/lib/azazel/run/mio",
        "/var/lib/azazel/run/remote",
        "/var/lib/azazel/run/knowledge",
        "/var/lib/azazel/run/knowledge-read",
    }
    dedicated = {"knowledge-read": "azknowledge-read", "edge-intake": "azedge",
                 "audit-submit": "azaudit-submit", "mio-advise": "azmio-advise"}
    for spec in socket_dirs.values():
        assert stat.S_ISGID & spec.mode
        assert spec.group == dedicated.get(spec.path.rsplit("/", 1)[1], "azazel-operator")
        assert spec.mode & 0o007 == 0


def test_dedicated_socket_groups_match_the_runtime_and_the_installer():
    """The client verifies the socket GID the leaf hands it, so the runtime's
    group for each leaf must be the group the layout and installer give it."""

    from azazel_nexus_runtime import runtime_paths

    specs = {spec.path: spec for spec in LAYOUT}
    for name, leaf in runtime_paths._SOCKET_LEAVES.items():
        spec = specs[f"/var/lib/azazel/run/{leaf}"]
        assert runtime_paths.socket_group(name) == spec.group, name
        assert (f"make_owned_dir {spec.mode:o} {spec.owner} {spec.group} "
                f"/var/lib/azazel/run/{leaf}\n") in _installer(), leaf


def test_every_declared_daemon_socket_has_an_installed_daemon_owned_leaf():
    """A socket name the runtime binds must have its leaf in the layout.

    `runtime_paths.socket_path` deliberately never creates a missing parent,
    so a leaf absent from the layout is a daemon that fails to bind at start
    (found by the container M.I.O. rehearsal: locald and remoted had none).
    """

    from azazel_nexus_runtime import runtime_paths

    expected_owner = {
        "audit": "azaudit", "audit-submit": "azaudit", "commission": "azcommission", "watchdog": "azwatch",
        "fetch": "azfetch", "mio-entry": "azmioentry", "mio-advise": "azmioentry", "mio": "azmio",
        "remote": "azremote", "knowledge": "azknowledge", "knowledge-read": "azknowledge", "edge-intake": "azintake",
    }
    owners = {spec.path: spec.owner for spec in LAYOUT}
    assert set(runtime_paths._SOCKET_LEAVES) == set(expected_owner)
    for name, leaf in runtime_paths._SOCKET_LEAVES.items():
        parent = f"/var/lib/azazel/run/{leaf}"
        assert parent in owners, f"socket {name!r} has no installed leaf {parent}"
        assert owners[parent] == expected_owner[name], parent


def test_service_accounts_are_not_added_to_the_operator_socket_group():
    installer = _installer()
    assert 'usermod --append --groups azazel-operator' not in installer
    assert "usermod --append --groups azaudit azwatch" not in installer


def test_service_state_writers_have_private_installer_owned_leaves():
    expected = {
        "/var/lib/azazel/state/audit": ("azaudit", "root"),
        "/var/lib/azazel/state/auditd": ("azaudit", "root"),
        "/var/lib/azazel/state/commission": ("azcommission", "root"),
        "/var/lib/azazel/state/watchdog": ("azwatch", "root"),
        "/var/lib/azazel/state/mio": ("azmioentry", "root"),
        "/var/lib/azazel/state/knowledge": ("azknowledge", "root"),
    }
    for path, (owner, group) in expected.items():
        spec = next(item for item in LAYOUT if item.path == path)
        assert (spec.mode, spec.owner, spec.group) == (0o700, owner, group)
        assert f"make_owned_dir 0700 {owner} {group} {path}" in _installer()


def test_a_child_does_not_inherit_a_parent_created_on_the_way(tmp_path):
    """`/var/lib/azazel/run` stays traversal-only under a default-mode parent.

    `mkdir(parents=True)` would have created the parent at whatever umask the
    shell had, which is a boundary set by the environment. The traversal-only
    mode deliberately grants no listing/read permission to ordinary users.
    """

    create_layout(tmp_path)
    parent = tmp_path / "var/lib/azazel"
    assert stat.S_IMODE(parent.stat().st_mode) == 0o711


def test_the_socket_directory_is_not_world_readable():
    """Socket ACLs are the first authorization boundary (§4)."""

    spec = next(s for s in LAYOUT if s.path.endswith("/run"))
    assert not spec.mode & 0o006


def test_the_secret_directory_is_root_only():
    spec = next(s for s in LAYOUT if s.path.endswith("/secrets"))
    assert spec.mode == 0o700


def test_bootstrap_persistence_directory_is_root_private_and_installed():
    spec = next(s for s in LAYOUT if s.path == "/var/lib/azazel/state/bootstrap")
    assert spec.mode == 0o700 and spec.group == "root"
    assert "make_dir 0700 root /var/lib/azazel/state/bootstrap" in _installer()


def test_administrator_bootstrap_configuration_directory_is_root_private():
    spec = next(s for s in LAYOUT if s.path == "/etc/azazel/bootstrap")
    assert spec.mode == 0o700 and spec.group == "root"
    assert "make_dir 0700 root /etc/azazel/bootstrap" in _installer()


def test_activation_approval_directory_is_root_private_and_installed():
    # Read by activation_store/activation_policy and written by az-activation install.
    spec = next(s for s in LAYOUT if s.path == "/etc/azazel/activation")
    assert spec.mode == 0o700 and spec.group == "root"
    assert "make_dir 0700 root /etc/azazel/activation" in _installer()


def test_bootstrap_overlay_journal_has_an_isolated_root_private_directory():
    spec = next(s for s in LAYOUT if s.path == "/var/lib/azazel/state/bootstrap-overlay")
    assert spec.mode == 0o700 and spec.group == "root"
    assert "make_dir 0700 root /var/lib/azazel/state/bootstrap-overlay" in _installer()


def test_a_layout_entry_must_be_absolute_and_explained():
    from azazel_nexus.layout import PathSpec

    with pytest.raises(ValueError):
        PathSpec("var/lib/azazel", 0o750, "relative")
    with pytest.raises(ValueError):
        PathSpec("/var/lib/azazel", 0o750, "   ")


# -- the register of what is still owed ---------------------------------


def test_every_hardware_gate_says_what_would_settle_it():
    """A gate with no closing condition is a caveat, not a gate.

    The register exists so that a simulated result is never read as a measured
    one. A gate that does not say what measurement would close it cannot be
    closed, and quietly becomes permanent.
    """

    text = (REPO_ROOT / "docs" / "hardware-gates.md").read_text(encoding="utf-8")
    gates = re.findall(r"^## (`HG-\d+`)", text, re.M)
    assert gates, "the register lists no gates"
    for gate in gates:
        section = text.split(f"## {gate}", 1)[1].split("\n## ", 1)[0]
        assert "**What would settle it.**" in section, (
            f"{gate} names no measurement that would close it"
        )
        assert "hardware-unverified" in text


def test_knowledge_store_is_service_owned_and_operator_readable():
    spec = next(s for s in LAYOUT if s.path == "/var/lib/azazel/knowledge")
    assert (spec.mode, spec.owner, spec.group) == (
        0o2750, "azknowledge", "azazel-operator"
    )


def test_entry_and_knowledge_console_scripts_point_to_lane_modules():
    import tomllib

    runtime = tomllib.loads((REPO_ROOT / "runtime/pyproject.toml").read_text())
    scripts = runtime["project"]["scripts"]
    assert scripts["az-mio-entryd"] == "azazel_nexus_runtime.mio_entryd:main"
    assert scripts["az-knowledge-lited"] == "azazel_nexus_runtime.knowledge_lited:main"


def test_mission_reader_provisioning_is_part_of_installer():
    text = _installer()
    for group in ('azknowledge-read', 'azmission-read'):
        assert f'getent group {group}' in text
        assert f'groupadd --system {group}' in text
    assert 'python_stager -IS "$REPO_ROOT/tools/provision_mission_read.py" "$@"' in text
    assert 'usermod' not in text


def test_minimal_profile_directory_is_always_installed_root_private():
    spec = next(s for s in LAYOUT if s.path == "/etc/azazel/mio-profile")
    assert spec.mode == 0o700
    assert spec.owner == "root" and spec.group == "root"
    assert "make_dir 0700 root /etc/azazel/mio-profile" in _installer()


def test_every_account_gets_its_own_group_explicitly():
    """Sockets and leaves rely on an account's same-named group (azedge,
    azknowledge); it must not depend on the distribution's USERGROUPS_ENAB."""
    text = (REPO_ROOT / "packaging/install.sh").read_text()
    useradds = [line.strip() for line in text.splitlines()
                if line.strip().startswith("useradd ")]
    assert useradds
    assert all("--user-group" in line or "--gid" in line for line in useradds)
