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

GOVERNED = tuple(d.name for d in CORE_UNITS)
ALL_UNITS = GOVERNED + (ACTIVATION_CONTROLLER_UNIT,)


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
        f"{sorted(GOVERNED)} plus {ACTIVATION_CONTROLLER_UNIT}"
    )


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

    assert [d.account for d in CORE_UNITS].count("root") == 0
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


def test_the_preset_enables_exactly_one_unit_and_it_is_the_controller():
    enabled = [unit for verb, unit in _preset_directives() if verb == "enable"]
    assert enabled == [ACTIVATION_CONTROLLER_UNIT]


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

    assert sorted(_systemctl_calls("mask")) == sorted(GOVERNED)


def test_the_installer_enables_only_the_activation_controller():
    assert _systemctl_calls("enable") == [ACTIVATION_CONTROLLER_UNIT]


def test_the_installer_refuses_while_the_daemons_it_names_are_absent():
    """This slice ships unit files and no executables.

    An installer that enabled a unit whose ExecStart does not exist would
    "succeed" into a boot failure. The refusal is what makes the missing half
    visible at install time instead of on a rugged PC.
    """

    text = _installer()
    assert "refusing to install" in text
    assert "/usr/libexec/azazel" in text


def test_every_unit_names_an_executable_the_installer_checks_for():
    checked = set(re.findall(r"\baz-[a-z]+\b", _installer()))
    for name in ALL_UNITS:
        text = (UNIT_DIR / name).read_text(encoding="utf-8")
        exec_start = re.search(r"^ExecStart=(\S+)", text, re.M)
        assert exec_start, f"{name} has no ExecStart"
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

    found = {
        path: (int(mode, 8), owner, group)
        for mode, owner, group, path in re.findall(
            r"^install -d -m (\d{4}) -o (\S+) -g (\S+) (/\S+)$", _installer(), re.M
        )
    }
    declared = {spec.path: (spec.mode, spec.owner, spec.group) for spec in LAYOUT}
    assert found == declared, (
        "the installer and the layout disagree about a directory's mode, "
        "owner or group. A writable path nobody declared is a path nobody set "
        "the owner of"
    )


def test_the_declared_modes_survive_creation(tmp_path):
    create_layout(tmp_path)
    for spec in LAYOUT:
        target = tmp_path / spec.path.lstrip("/")
        assert target.is_dir(), f"{spec.path} was not created"
        assert stat.S_IMODE(target.stat().st_mode) == spec.mode, (
            f"{spec.path} was created with the process umask rather than the "
            f"declared {spec.mode:04o}"
        )


def test_a_child_does_not_inherit_a_parent_created_on_the_way(tmp_path):
    """`/var/lib/azazel/run` at 0750 under a parent nobody set the mode of.

    `mkdir(parents=True)` would have created the parent at whatever umask the
    shell had, which is a boundary set by the environment.
    """

    create_layout(tmp_path)
    parent = tmp_path / "var/lib/azazel"
    assert stat.S_IMODE(parent.stat().st_mode) == 0o750


def test_the_socket_directory_is_not_world_readable():
    """Socket ACLs are the first authorization boundary (§4)."""

    spec = next(s for s in LAYOUT if s.path.endswith("/run"))
    assert not spec.mode & 0o007


def test_the_secret_directory_is_root_only():
    spec = next(s for s in LAYOUT if s.path.endswith("/secrets"))
    assert spec.mode == 0o700


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
