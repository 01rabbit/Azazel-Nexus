"""The Deception Lite AppArmor profiles and their enforce-mode check (#196 G3).

`docs/deception-exposure-grant.md` §7 (L1), decided as §10 Q8: AppArmor,
`AppArmorProfile=` without `-`, the pass checking enforce mode, Landlock
later. These tests pin:

* the three packaged profiles (`packaging/apparmor/`): every claim of the
  gate written as an explicit `deny` in every profile block, the namespace
  unit's child profile included; what each may do kept to its unit's
  capabilities, address families, programs and (for the namespace unit's
  `ip` only) mounts;
* the units: each of the three names exactly its own profile, without `-`,
  rendered from `ServiceProfile` and nowhere else; no other unit names one;
* the installer: the profiles placed in `/etc/apparmor.d/`, compiled but
  never loaded, and `apparmor_parser` (package `apparmor`) required only
  with the service manager;
* `decoy_apparmor.exposure_lsm_refusal`: enforce, absent, complain and
  AppArmor disabled, on the kernel's listing format;
* that its reasons are **not reached**: nothing on the activation path
  imports it, and the tier is still withheld as `isolation_evidence_absent`.

No test loads a profile or reads the host's securityfs. None of this is VM
or hardware evidence; the rules marked INFERRED in the profiles are VM work
(G4, §11 item 4).
"""

from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from azazel_nexus_runtime import decoy_apparmor
from azazel_nexus_runtime.decoy_apparmor import (
    DECOY_APPARMOR_PROFILES,
    LSM_APPARMOR_DISABLED,
    LSM_PROFILES_ABSENT,
    LSM_PROFILES_NOT_ENFORCED,
    LSM_PROFILES_UNREADABLE,
    LSM_REASON_CODES,
    REQUIRED_ENFORCED_PROFILES,
    apparmor_profile_for,
    exposure_lsm_refusal,
    read_exposure_lsm,
)
from azazel_nexus_runtime.hardening import ALL_PROFILES, PROFILES, render_unit
from azazel_nexus_runtime.install_platform import (
    APPARMOR_DIRECTORY,
    CURRENT_INSTALL_PLATFORM_PROFILES,
    build_install_plan,
    parse_preset_declarations,
)

from azazel_nexus.activation import (
    DECEPTION_EXPOSURE_UNITS,
    DECOY_NAMESPACE_UNIT,
    DECOY_NETWORK_HELPER_UNIT,
    DECOY_UNIT,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "packaging" / "apparmor"
UNIT_DIR = ROOT / "packaging" / "systemd"
INSTALLER = (ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
PRESET = (ROOT / "packaging" / "azazel-nexus.preset").read_text(encoding="utf-8")
NAMES = dict(DECOY_APPARMOR_PROFILES)

#: The gate's claims (§7 "What each profile must deny"), as rule lines. Each
#: must appear, exactly, in every profile block: a child profile inherits
#: nothing from its parent.
GATE_DENIES = (
    # Writes to the activation state, the grant markers, the unit files and
    # the ledgers. /lib/systemd is Debian's unit directory for this package
    # (install_platform), /run/systemd/system{,.control} and transient the
    # runtime unit paths; both go beyond the letter of §7 on purpose.
    "deny /run/azazel-activation{,/**} wlk,",
    "deny /etc/systemd{,/**} wlk,",
    "deny /usr/lib/systemd{,/**} wlk,",
    "deny /lib/systemd{,/**} wlk,",
    "deny /run/systemd/{system,system.control,transient}{,/**} wlk,",
    "deny /etc/azazel{,/**} wlk,",
    "deny /var/lib/azazel{,/**} wlk,",
    # The service manager's sockets.
    "deny /run/dbus/system_bus_socket rw,",
    "deny /run/systemd/private rw,",
    "deny dbus,",
    "deny ptrace,",
    "deny capability mac_admin,",
    "deny capability mac_override,",
    "deny /sys/kernel/security{,/**} wlk,",
    "deny change_profile,",
)


def _rules(name: str) -> list[str]:
    """The profile file's lines, comments and blank lines removed."""

    lines = []
    for line in (PROFILE_DIR / name).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def _blocks(name: str) -> dict[str, list[str]]:
    """`profile -> its own rules`, a child's rules not counted in its parent."""

    blocks: dict[str, list[str]] = {}
    stack: list[str] = []
    for line in _rules(name):
        opened = re.fullmatch(r"profile ([A-Za-z0-9_.-]+) \{", line)
        if opened:
            child = opened.group(1)
            full = f"{stack[-1]}//{child}" if stack else child
            assert full not in blocks, full
            blocks[full] = []
            stack.append(full)
            continue
        if line == "}":
            stack.pop()
            continue
        if stack:
            blocks[stack[-1]].append(line)
    assert not stack, f"{name}: unbalanced braces"
    return blocks


def _all_blocks() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for _, name in DECOY_APPARMOR_PROFILES:
        found.update(_blocks(name))
    return found


def _allows(rules: list[str]) -> list[str]:
    return [rule for rule in rules if not rule.startswith("deny ")]


def _settings(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key, []).append(value)
    return found


# -- the profiles ---------------------------------------------------------------


def test_one_profile_file_per_exposure_unit_and_nothing_else():
    assert tuple(unit for unit, _ in DECOY_APPARMOR_PROFILES) == DECEPTION_EXPOSURE_UNITS
    assert NAMES == {
        DECOY_NAMESPACE_UNIT: "azazel-decoy-nsd",
        DECOY_NETWORK_HELPER_UNIT: "azazel-decoy-netd",
        DECOY_UNIT: "azazel-decoyd",
    }
    assert sorted(path.name for path in PROFILE_DIR.iterdir()) == sorted(NAMES.values())


def test_every_profile_block_is_the_one_the_listing_check_requires():
    """The kernel lists a child as `parent//child`; the check requires each."""

    assert sorted(_all_blocks()) == sorted(REQUIRED_ENFORCED_PROFILES)
    assert REQUIRED_ENFORCED_PROFILES == (
        "azazel-decoy-nsd", "azazel-decoy-netd", "azazel-decoyd", "azazel-decoy-nsd//ip")
    for _, name in DECOY_APPARMOR_PROFILES:
        rules = _rules(name)
        # The profile is named, never attached by path: only the unit's
        # AppArmorProfile= puts a process in it.
        assert f"profile {name} {{" in rules
        assert rules[:2] == ["abi <abi/4.0>,", "include <tunables/global>"]


@pytest.mark.parametrize("block", REQUIRED_ENFORCED_PROFILES)
def test_every_profile_block_states_every_claim_of_the_gate_as_a_deny(block):
    rules = _all_blocks()[block]
    missing = [rule for rule in GATE_DENIES if rule not in rules]
    assert missing == []
    # Each once, so a later edit cannot leave a weaker copy behind.
    assert all(rules.count(rule) == 1 for rule in GATE_DENIES)


@pytest.mark.parametrize("block", REQUIRED_ENFORCED_PROFILES)
def test_no_profile_block_allows_what_the_gate_denies(block):
    allows = _allows(_all_blocks()[block])
    for rule in allows:
        assert not rule.startswith(("change_profile", "ptrace", "dbus", "pivot_root",
                                    "userns", "io_uring", "unix")), rule
        assert "mac_admin" not in rule and "mac_override" not in rule, rule
        for denied in ("/run/azazel-activation", "/etc/systemd", "/usr/lib/systemd",
                       "/lib/systemd", "/run/systemd", "/etc/azazel", "/var/lib/azazel",
                       "/run/dbus", "/sys/kernel/security"):
            assert denied not in rule, rule
    # No profile runs in complain mode or unconfined by flag.
    text = "\n".join(_all_blocks()[block])
    assert "flags=" not in text and "complain" not in text


def test_no_profile_file_sets_a_mode_flag():
    for _, name in DECOY_APPARMOR_PROFILES:
        for rule in _rules(name):
            assert "flags=" not in rule, rule


@pytest.mark.parametrize(("block", "expected"), [
    ("azazel-decoy-nsd", {"capability sys_admin,", "capability net_admin,"}),
    ("azazel-decoy-nsd//ip", {"capability sys_admin,", "capability net_admin,"}),
    ("azazel-decoy-netd", {"capability net_admin,"}),
    ("azazel-decoyd", set()),
])
def test_each_profile_allows_exactly_its_units_capabilities(block, expected):
    allows = _allows(_all_blocks()[block])
    assert {rule for rule in allows if rule.startswith("capability")} == expected
    parent = block.split("//")[0]
    unit = next(unit for unit, name in DECOY_APPARMOR_PROFILES if name == parent)
    profile = next(p for p in PROFILES if p.unit == unit)
    assert expected == {f"capability {cap.removeprefix('CAP_').lower()},"
                        for cap in profile.capability_bounding_set}


def test_the_decoy_profile_denies_every_capability():
    assert "deny capability," in _all_blocks()["azazel-decoyd"]


@pytest.mark.parametrize(("block", "expected"), [
    ("azazel-decoy-nsd", {"network netlink raw,"}),
    ("azazel-decoy-nsd//ip", {"network netlink raw,"}),
    ("azazel-decoy-netd", {"network netlink raw,"}),
    ("azazel-decoyd", {"network inet stream,", "network unix stream,"}),
])
def test_each_profile_allows_only_its_units_address_families(block, expected):
    allows = _allows(_all_blocks()[block])
    assert {rule for rule in allows if rule.startswith("network")} == expected
    parent = block.split("//")[0]
    unit = next(unit for unit, name in DECOY_APPARMOR_PROFILES if name == parent)
    families = next(p for p in PROFILES if p.unit == unit).address_families
    assert {f"AF_{rule.split()[1].upper()}" for rule in expected} == set(families)


def _file_rules(rules: list[str]) -> list[tuple[str, str]]:
    """`(rule, permissions)` of every allowed file rule."""

    found = []
    for rule in _allows(rules):
        if not rule.startswith(("/", "@{", "owner ")):
            continue
        words = rule.rstrip(",").split(" -> ")[0].split()
        found.append((rule, words[-1]))
    return found


def _executes(rules: list[str]) -> set[str]:
    return {rule for rule, permissions in _file_rules(rules) if "x" in permissions}


def _writes(rules: list[str]) -> set[str]:
    return {rule for rule, permissions in _file_rules(rules)
            if set(permissions) & set("wal")}


@pytest.mark.parametrize(("block", "expected"), [
    # The Python body runs only ip, and only into the child profile.
    ("azazel-decoy-nsd", {"/usr/bin/python3* mrix,", "/usr/bin/ip Cx -> ip,"}),
    # The child runs nothing.
    ("azazel-decoy-nsd//ip", set()),
    ("azazel-decoy-netd", {"/usr/bin/python3* mrix,", "/usr/bin/ip mrix,",
                           "/usr/sbin/nft mrix,"}),
    ("azazel-decoyd", {"/usr/bin/python3* mrix,"}),
])
def test_each_profile_runs_only_its_fixed_programs(block, expected):
    assert _executes(_all_blocks()[block]) == expected


#: The only mounts any profile allows: those `ip netns add`, `ip netns
#: delete` and `ip -n` make (prerequisites §13), in the namespace unit's `ip`
#: child. The exact rules are VM work (G4); this pins what is claimed.
IP_MOUNTS = {
    "mount options=(rw, rshared) -> /run/netns/,",
    "mount options=(rw, bind) /run/netns/ -> /run/netns/,",
    "mount options=(rw, bind) @{PROC}/@{pid}/{,task/@{tid}/}ns/net -> /run/netns/azazel-decoy,",
    "umount /run/netns/azazel-decoy,",
    "mount options=(rw, rslave) -> /,",
    "umount /sys/,",
    "mount fstype=sysfs -> /sys/,",
}


@pytest.mark.parametrize("block", REQUIRED_ENFORCED_PROFILES)
def test_only_the_namespace_units_ip_mounts_and_only_what_ip_needs(block):
    mounts = {rule for rule in _allows(_all_blocks()[block])
              if rule.startswith(("mount", "umount", "remount", "pivot_root"))}
    assert mounts == (IP_MOUNTS if block == "azazel-decoy-nsd//ip" else set())
    # /etc/netns/azazel-decoy is never bound over /etc.
    assert not any("/etc/netns" in rule for rule in mounts)


def test_the_helper_writes_only_its_runtime_directory():
    assert _writes(_all_blocks()["azazel-decoy-netd"]) == {
        "/run/azazel-decoy-isolation/* rw,"}


@pytest.mark.parametrize("block", ["azazel-decoy-nsd", "azazel-decoyd"])
def test_the_namespace_unit_and_the_decoy_bodies_write_nothing(block):
    assert _writes(_all_blocks()[block]) == set()


def test_the_namespace_units_ip_writes_only_the_namespace_handle():
    assert _writes(_all_blocks()["azazel-decoy-nsd//ip"]) == {
        "/run/netns/ rw,", "/run/netns/azazel-decoy rw,"}


def test_inferred_rules_are_marked_in_every_profile():
    for _, name in DECOY_APPARMOR_PROFILES:
        text = (PROFILE_DIR / name).read_text(encoding="utf-8")
        assert "INFERRED" in text
        assert "not hardware evidence" in text


@pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                    reason="apparmor_parser (Debian package apparmor) is not installed")
@pytest.mark.parametrize("name", sorted(dict(DECOY_APPARMOR_PROFILES).values()))
def test_the_profile_compiles_when_the_parser_is_present(name):
    """Compiled only (`--skip-kernel-load`); nothing is loaded into a kernel."""

    result = subprocess.run(
        ["apparmor_parser", "--skip-kernel-load", "--skip-cache", "--quiet",
         str(PROFILE_DIR / name)],
        capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr


# -- the units ------------------------------------------------------------------


@pytest.mark.parametrize("unit", DECEPTION_EXPOSURE_UNITS)
def test_each_exposure_unit_names_its_own_profile_without_a_dash(unit):
    profile = next(p for p in PROFILES if p.unit == unit)
    assert profile.apparmor_profile == NAMES[unit] == apparmor_profile_for(unit)
    for text in (render_unit(profile),
                 (UNIT_DIR / unit).read_text(encoding="utf-8")):
        settings = _settings(text)
        # Exactly once, exactly the name: no `-`, so a start without the
        # profile loaded fails instead of running unconfined.
        assert settings["AppArmorProfile"] == [NAMES[unit]]
        assert not settings["AppArmorProfile"][0].startswith("-")
        assert (PROFILE_DIR / settings["AppArmorProfile"][0]).is_file()


def test_no_other_unit_names_a_profile():
    for profile in ALL_PROFILES:
        if profile.unit in DECEPTION_EXPOSURE_UNITS:
            continue
        assert profile.apparmor_profile == ""
        assert "AppArmorProfile" not in render_unit(profile)
    for path in UNIT_DIR.glob("*.service"):
        if path.name not in DECEPTION_EXPOSURE_UNITS:
            assert "AppArmorProfile" not in path.read_text(encoding="utf-8"), path.name
    assert apparmor_profile_for("azazel-activated.service") == ""


@pytest.mark.parametrize("unit", DECEPTION_EXPOSURE_UNITS)
@pytest.mark.parametrize("value", ["", "-{name}", "{name}-other", "unconfined",
                                   "azazel-decoyd-x"])
def test_an_exposure_unit_refuses_any_other_profile(unit, value):
    profile = next(p for p in PROFILES if p.unit == unit)
    with pytest.raises(ValueError, match="AppArmorProfile"):
        replace(profile, apparmor_profile=value.format(name=NAMES[unit]))


@pytest.mark.parametrize("value", ["azazel-decoyd", "azazel-decoy-nsd", "-azazel-decoyd"])
@pytest.mark.parametrize("unit", ["azazel-activated.service", "azazel-edge-core.service",
                                  "azazel-mio-entryd.service"])
def test_no_other_unit_may_name_a_profile(unit, value):
    profile = next(p for p in ALL_PROFILES if p.unit == unit)
    with pytest.raises(ValueError, match="AppArmorProfile"):
        replace(profile, apparmor_profile=value)


@pytest.mark.parametrize("unit", ["azazel-decoyd.service", "azazel-mio-entryd.service"])
def test_no_unit_may_name_a_profile_through_extra(unit):
    profile = next(p for p in ALL_PROFILES if p.unit == unit)
    with pytest.raises(ValueError, match="in extra"):
        replace(profile, extra=profile.extra + (("AppArmorProfile", "-azazel-decoyd"),))


# -- the installer --------------------------------------------------------------


def test_the_installer_places_each_profile_and_loads_none():
    for _, name in DECOY_APPARMOR_PROFILES:
        line = (f'install -m 0644 "$HERE"/apparmor/{name} '
                f'"${{DESTDIR:-}}/etc/apparmor.d/{name}"')
        assert INSTALLER.count(line) == 1, name
    assert 'install -d -m 0755 "${DESTDIR:-}/etc/apparmor.d"' in INSTALLER
    # Compiled, never loaded, replaced or removed here; the package's
    # apparmor.service loads /etc/apparmor.d at boot.
    calls = [line.strip() for line in INSTALLER.splitlines()
             if "apparmor_parser" in line and not line.strip().startswith("#")]
    assert calls == [('if ! apparmor_parser --skip-kernel-load --skip-cache --quiet '
                      '"$HERE/apparmor/$profile"; then')]
    for forbidden in ("aa-enforce", "aa-complain", "aa-disable", "apparmor-utils",
                      "--replace", "apparmor_parser -r", "apparmor_parser -a",
                      "apparmor_parser -R", "systemctl reload apparmor"):
        assert forbidden not in INSTALLER, forbidden
    assert ("for profile in azazel-decoy-nsd azazel-decoy-netd azazel-decoyd; do"
            in INSTALLER)


def test_the_installer_compiles_the_profiles_before_writing_anything():
    compile_at = INSTALLER.index("apparmor_parser --skip-kernel-load")
    for first_write in ("useradd", "make_dir 0755 root /etc/azazel",
                        'install -d -m 0755 "$UNIT_DIR"'):
        assert compile_at < INSTALLER.index(first_write), first_write
    block = INSTALLER[INSTALLER.rindex("\n", 0, compile_at - 200):compile_at]
    assert 'if [ "$WITH_SERVICE_MANAGER" = yes ]; then' in block


def test_the_install_plan_places_the_profiles_and_requires_the_package_with_systemd():
    profile = CURRENT_INSTALL_PLATFORM_PROFILES[0]
    assert APPARMOR_DIRECTORY == "/etc/apparmor.d"
    # Debian package `apparmor` provides apparmor_parser; `apparmor-utils`
    # is never required.
    assert "apparmor_parser" in profile.service_manager_tools
    assert not any("aa-" in tool or "utils" in tool
                   for tool in profile.required_tools + profile.service_manager_tools
                   + profile.account_tools)
    for with_service_manager in (True, False):
        plan = build_install_plan(
            profile, preset_declarations=parse_preset_declarations(PRESET),
            with_service_manager=with_service_manager)
        placed = {(item.source, item.destination, item.mode) for item in plan.files
                  if item.source.startswith("packaging/apparmor/")}
        assert placed == {(f"packaging/apparmor/{name}", f"/etc/apparmor.d/{name}", 0o644)
                          for _, name in DECOY_APPARMOR_PROFILES}
        assert ("apparmor_parser" in plan.required_tools) is with_service_manager


# -- the enforce-mode check -----------------------------------------------------

LSM = b"lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm"
ENFORCED = (
    b"/usr/bin/man (enforce)\n"
    b"azazel-decoyd (enforce)\n"
    b"azazel-decoy-nsd//ip (enforce)\n"
    b"azazel-decoy-nsd (enforce)\n"
    b"azazel-decoy-netd (enforce)\n"
    b"unrelated-tool (complain)\n"
    b"lsb_release (enforce)\n"
)


def _without(name: bytes) -> bytes:
    return b"".join(line + b"\n" for line in ENFORCED.splitlines()
                    if line.rpartition(b" (")[0] != name)


def test_all_profiles_in_enforce_mode_is_no_refusal():
    assert exposure_lsm_refusal(LSM, ENFORCED) is None
    assert exposure_lsm_refusal(LSM + b"\n", ENFORCED) is None
    # The kernel's order is not the check's.
    reordered = b"\n".join(reversed(ENFORCED.splitlines())) + b"\n"
    assert exposure_lsm_refusal(b"apparmor", reordered) is None


@pytest.mark.parametrize("name", [n.encode() for n in REQUIRED_ENFORCED_PROFILES])
def test_a_profile_missing_from_the_listing_withholds(name):
    reason = exposure_lsm_refusal(LSM, _without(name))
    assert reason is not None and reason.startswith(LSM_PROFILES_ABSENT + ":")
    # The reason holds a count, never a profile name or a path.
    assert name.decode() not in reason


def test_an_empty_listing_withholds_as_absent():
    reason = exposure_lsm_refusal(LSM, b"")
    assert reason is not None and reason.startswith(LSM_PROFILES_ABSENT + ":")
    assert "4 of the 4" in reason


@pytest.mark.parametrize("mode", [b"complain", b"kill", b"unconfined", b"prompt", b"user"])
@pytest.mark.parametrize("name", [n.encode() for n in REQUIRED_ENFORCED_PROFILES])
def test_a_profile_in_any_other_mode_withholds(name, mode):
    listing = ENFORCED.replace(name + b" (enforce)", name + b" (" + mode + b")")
    assert listing != ENFORCED
    reason = exposure_lsm_refusal(LSM, listing)
    assert reason is not None and reason.startswith(LSM_PROFILES_NOT_ENFORCED + ":")


def test_a_profile_listed_twice_withholds_unless_both_are_enforce():
    twice = ENFORCED + b"azazel-decoyd (complain)\n"
    assert exposure_lsm_refusal(LSM, twice).startswith(LSM_PROFILES_NOT_ENFORCED)
    assert exposure_lsm_refusal(LSM, ENFORCED + b"azazel-decoyd (enforce)\n") is None


def test_a_profile_in_another_policy_namespace_does_not_count():
    listing = _without(b"azazel-decoyd") + b":other:azazel-decoyd (enforce)\n"
    assert exposure_lsm_refusal(LSM, listing).startswith(LSM_PROFILES_ABSENT)


@pytest.mark.parametrize(("lsm", "profiles"), [
    (None, ENFORCED),
    (LSM, None),
    (None, None),
    (b"lockdown,capability,landlock,yama,bpf", ENFORCED),
    (b"", ENFORCED),
    (b"capability,selinux", ENFORCED),
    (b"apparmor-not,capability", ENFORCED),
    (b"\xff\xfe", ENFORCED),
    (b"apparmor," * 1000, ENFORCED),
])
def test_apparmor_disabled_withholds(lsm, profiles):
    reason = exposure_lsm_refusal(lsm, profiles)
    assert reason is not None and reason.startswith(LSM_APPARMOR_DISABLED + ":")


@pytest.mark.parametrize("profiles", [
    b"azazel-decoyd enforce\n",
    b"azazel-decoyd (enforce\n",
    b"(enforce)\n",
    b" azazel-decoyd (enforce)\n",
    b"azazel-decoyd ()\n",
    b"azazel-decoyd (en force)\n",
    b"azazel-decoyd (enforce)\r\n",
    ENFORCED + b"\xff (enforce)\n",
    b"x (enforce)\n" * 100_000,
])
def test_a_listing_not_in_the_kernels_form_withholds(profiles):
    reason = exposure_lsm_refusal(LSM, profiles)
    assert reason is not None and reason.startswith(LSM_PROFILES_UNREADABLE + ":")


def test_the_reason_codes_are_distinct_and_fixed():
    assert LSM_REASON_CODES == ("lsm_apparmor_disabled", "lsm_profiles_unreadable",
                                "lsm_profiles_absent", "lsm_profiles_not_enforced")
    assert len(set(LSM_REASON_CODES)) == 4


def test_the_reader_reads_both_files_bounded(tmp_path, monkeypatch):
    lsm, profiles = tmp_path / "lsm", tmp_path / "profiles"
    lsm.write_bytes(LSM)
    profiles.write_bytes(ENFORCED)
    monkeypatch.setattr(decoy_apparmor, "_LSM", str(lsm))
    monkeypatch.setattr(decoy_apparmor, "_PROFILES", str(profiles))
    assert read_exposure_lsm() == (LSM, ENFORCED)
    assert exposure_lsm_refusal(*read_exposure_lsm()) is None
    # One byte past the bound is read, so an oversized listing is judged
    # oversized rather than cut to fit.
    profiles.write_bytes(b"x (enforce)\n" * 100_000)
    assert len(read_exposure_lsm()[1]) == decoy_apparmor._PROFILES_LIMIT + 1
    assert exposure_lsm_refusal(*read_exposure_lsm()).startswith(LSM_PROFILES_UNREADABLE)


def test_the_reader_gives_none_for_an_absent_or_linked_file(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.write_bytes(ENFORCED)
    link = tmp_path / "link"
    os.symlink(real, link)
    monkeypatch.setattr(decoy_apparmor, "_LSM", str(tmp_path / "absent"))
    monkeypatch.setattr(decoy_apparmor, "_PROFILES", str(link))
    assert read_exposure_lsm() == (None, None)
    assert exposure_lsm_refusal(*read_exposure_lsm()).startswith(LSM_APPARMOR_DISABLED)


def test_the_production_paths_are_securityfs():
    assert decoy_apparmor._LSM == "/sys/kernel/security/lsm"
    assert decoy_apparmor._PROFILES == "/sys/kernel/security/apparmor/profiles"


# -- not reached in this build --------------------------------------------------


def _python_modules():
    for base in (ROOT / "src", ROOT / "runtime" / "src"):
        yield from sorted(base.rglob("*.py"))


def _imports_decoy_apparmor(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.endswith("decoy_apparmor"):
                return True
            if any(alias.name == "decoy_apparmor" for alias in node.names):
                return True
        elif isinstance(node, ast.Import):
            if any(alias.name.endswith("decoy_apparmor") for alias in node.names):
                return True
    return False


def test_only_the_unit_renderer_and_the_install_plan_import_the_module():
    """The pass, the controller and the library never call the check (G6 does)."""

    importers = {path.relative_to(ROOT).as_posix() for path in _python_modules()
                 if _imports_decoy_apparmor(path)}
    assert importers == {
        "runtime/src/azazel_nexus_runtime/hardening.py",
        "runtime/src/azazel_nexus_runtime/install_platform.py",
    }


def test_the_reason_codes_appear_nowhere_else_in_the_product():
    for path in _python_modules():
        if path.name == "decoy_apparmor.py":
            continue
        text = path.read_text(encoding="utf-8")
        for code in LSM_REASON_CODES:
            assert code not in text, (path, code)
        assert "exposure_lsm_refusal" not in text, path
        assert "read_exposure_lsm" not in text, path


def test_the_tier_is_still_withheld_unconditionally():
    """`_withholding_reason` still returns `isolation_evidence_absent` for the
    tier with nothing before it that reads the LSM (the controller-level
    run is `test_activation.py`)."""

    from azazel_nexus import activation

    source = Path(activation.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    method = next(node for node in ast.walk(tree)
                  if isinstance(node, ast.FunctionDef) and node.name == "_withholding_reason")
    body = ast.get_source_segment(source, method)
    branch = body[body.index("if definition.tier is UnitTier.DECEPTION_EXPOSURE:"):
                  body.index("if definition.tier is UnitTier.EDGE_BASELINE:")]
    returns = re.findall(r'return \(\s*"([a-z_]+):', branch)
    assert returns == ["exposure_tier_partial", "isolation_evidence_absent"]
    assert "lsm" not in branch.lower() and "apparmor" not in branch.lower()
