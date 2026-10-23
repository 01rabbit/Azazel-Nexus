"""The Deception Lite AppArmor profiles and their enforce-mode check (#196 G3).

`docs/deception-exposure-grant.md` §7 (L1), decided as §10 Q8: AppArmor,
`AppArmorProfile=` without `-`, the pass checking enforce mode, Landlock
later. These tests pin:

* the four packaged profiles (`packaging/apparmor/`): every claim of the
  gate written as an explicit `deny` in every profile; what each may do kept
  to its unit's capabilities, address families, programs and (for the
  namespace unit, which runs only `ip`) mounts; no child profile (G4
  follow-up: under `NoNewPrivileges=yes` the kernel refused the namespace
  unit's `Cx` transition); `attach_disconnected` on every profile, with
  `attach_disconnected.path=/.azazel-nsfs/` on the namespace unit's
  alone (G4), and no other flag;
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
    PROFILE_INTERPRETER,
    PROFILE_PYTHON_ROOTS,
    REQUIRED_ENFORCED_PROFILES,
    UNREADABLE,
    apparmor_profile_for,
    exposure_lsm_refusal,
    read_exposure_lsm,
    wrapper_profile_refusal,
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
#: The verify unit of grant §6.1 (#196 G2): the helper's executable, its own
#: profile, and the one unit outside the tier that names a profile.
VERIFY = "azazel-decoy-verify.service"
#: Every unit that names a profile, in the order they start.
PROFILED_UNITS = (DECOY_NAMESPACE_UNIT, DECOY_NETWORK_HELPER_UNIT, VERIFY, DECOY_UNIT)

#: The one flag of every profile, and the namespace unit's prefix for
#: disconnected paths (G4: its nsfs bind source; grant §7).
DISCONNECTED = "/.azazel-nsfs/"
FLAGS = {
    "azazel-decoy-nsd": f"flags=(attach_disconnected, attach_disconnected.path={DISCONNECTED})",
    "azazel-decoy-netd": "flags=(attach_disconnected)",
    "azazel-decoy-verify": "flags=(attach_disconnected)",
    "azazel-decoyd": "flags=(attach_disconnected)",
}

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
        opened = re.fullmatch(r"profile ([A-Za-z0-9_.-]+)(?: (flags=\([^)]*\)))? \{", line)
        if opened:
            child = opened.group(1)
            assert opened.group(2) == FLAGS[child], line
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
    assert tuple(unit for unit, _ in DECOY_APPARMOR_PROFILES) == PROFILED_UNITS
    assert set(DECEPTION_EXPOSURE_UNITS) == set(PROFILED_UNITS) - {VERIFY}
    assert NAMES == {
        DECOY_NAMESPACE_UNIT: "azazel-decoy-nsd",
        DECOY_NETWORK_HELPER_UNIT: "azazel-decoy-netd",
        VERIFY: "azazel-decoy-verify",
        DECOY_UNIT: "azazel-decoyd",
    }
    assert sorted(path.name for path in PROFILE_DIR.iterdir()) == sorted(NAMES.values())


def test_every_profile_block_is_the_one_the_listing_check_requires():
    """One block per profile, no child (G4 follow-up), and the check requires each."""

    assert sorted(_all_blocks()) == sorted(REQUIRED_ENFORCED_PROFILES)
    assert REQUIRED_ENFORCED_PROFILES == (
        "azazel-decoy-nsd", "azazel-decoy-netd", "azazel-decoy-verify", "azazel-decoyd")
    assert not any("//" in name for name in _all_blocks())
    for _, name in DECOY_APPARMOR_PROFILES:
        rules = _rules(name)
        # The profile is named, never attached by path: only the unit's
        # AppArmorProfile= puts a process in it.
        assert f"profile {name} {FLAGS[name]} {{" in rules
        assert [rule for rule in rules if rule.startswith("profile ")] == [
            f"profile {name} {FLAGS[name]} {{"]
        assert rules[:2] == ["abi <abi/4.0>,", "include <tunables/global>"]


#: The decoy's one exception to `GATE_DENIES` (finding 1 of the review of
#: #285): its report to the intake is a connect to a path socket under
#: /var/lib/azazel, which AppArmor mediates as a write to the socket file, so
#: a deny there would drop every report. Its writes under /var/lib/azazel are
#: refused by the profile's default instead, and its one allow there is pinned.
VAR_LIB_DENY = "deny /var/lib/azazel{,/**} wlk,"
INTAKE_SOCKET = "/var/lib/azazel/run/decoy-intake/decoy-intake.sock"


def _gate_denies(block: str) -> tuple[str, ...]:
    if block == "azazel-decoyd":
        return tuple(rule for rule in GATE_DENIES if rule != VAR_LIB_DENY)
    return GATE_DENIES


@pytest.mark.parametrize("block", REQUIRED_ENFORCED_PROFILES)
def test_every_profile_block_states_every_claim_of_the_gate_as_a_deny(block):
    rules = _all_blocks()[block]
    missing = [rule for rule in _gate_denies(block) if rule not in rules]
    assert missing == []
    # Each once, so a later edit cannot leave a weaker copy behind.
    assert all(rules.count(rule) == 1 for rule in _gate_denies(block))


def test_the_decoy_denies_nothing_under_var_lib_azazel_and_allows_only_the_intake_socket():
    from azazel_nexus_runtime.decoy_sender import DECOY_INTAKE_SOCKET

    rules = _all_blocks()["azazel-decoyd"]
    assert not any(rule.startswith("deny") and "/var/lib/azazel" in rule for rule in rules)
    assert [rule for rule in _allows(rules) if "/var/lib/azazel" in rule] == [
        f"{INTAKE_SOCKET} rw,"]
    # The socket the decoy connects to.
    assert INTAKE_SOCKET == DECOY_INTAKE_SOCKET


def test_the_decoy_is_an_af_unix_stream_client_only():
    unix = [rule for rule in _allows(_all_blocks()["azazel-decoyd"])
            if rule.startswith("unix")]
    assert unix == [("unix (create, connect, send, receive, getattr, getopt, setopt, "
                     "shutdown) type=stream,")]
    for word in ("bind", "listen", "accept"):
        assert word not in unix[0]


@pytest.mark.parametrize("block", REQUIRED_ENFORCED_PROFILES)
def test_no_profile_block_allows_what_the_gate_denies(block):
    allows = _allows(_all_blocks()[block])
    for rule in allows:
        assert not rule.startswith(("change_profile", "ptrace", "dbus", "pivot_root",
                                    "userns", "io_uring")), rule
        if block != "azazel-decoyd":
            assert not rule.startswith("unix"), rule
        assert "mac_admin" not in rule and "mac_override" not in rule, rule
        for denied in ("/run/azazel-activation", "/etc/systemd", "/usr/lib/systemd",
                       "/lib/systemd", "/run/systemd", "/etc/azazel", "/run/dbus",
                       "/sys/kernel/security"):
            assert denied not in rule, rule
        if "/var/lib/azazel" in rule:
            assert (block, rule) == ("azazel-decoyd", f"{INTAKE_SOCKET} rw,")
    # No profile runs in complain mode or unconfined by flag.
    text = "\n".join(_all_blocks()[block])
    assert "flags=" not in text and "complain" not in text


def test_no_profile_file_sets_a_mode_flag():
    """`attach_disconnected` is the one flag (G4: the verify unit's `/dev/null`
    was refused as a disconnected path under systemd's sandbox), and the
    namespace unit's alone names a prefix for disconnected paths (G4: its nsfs
    bind source was named `/`). No mode flag (complain, kill, unconfined,
    prompt), no other path flag."""

    for _, name in DECOY_APPARMOR_PROFILES:
        flagged = [rule for rule in _rules(name) if "flags=" in rule]
        assert flagged == [f"profile {name} {FLAGS[name]} {{"], name
        text = (PROFILE_DIR / name).read_text(encoding="utf-8")
        # (`kill` is not checked as a word: `signal set=(kill)` is a rule.)
        words = ["complain", "flags=(kill", "unconfined)", "prompt", "mediate_deleted",
                 "chroot_relative"]
        if name != "azazel-decoy-nsd":
            words.append("attach_disconnected.path")
        for word in words:
            assert word not in "\n".join(_rules(name)), (name, word)
        # The flag is explained where it is set: it names a path, and every
        # rule, the denies included, still applies to that name.
        assert "attach_disconnected" in text.split("abi <abi/4.0>")[0]
        assert "denies included" in text


def _unit_of(block: str):
    parent = block.split("//")[0]
    unit = next(unit for unit, name in DECOY_APPARMOR_PROFILES if name == parent)
    return next(p for p in ALL_PROFILES if p.unit == unit)


@pytest.mark.parametrize(("block", "expected"), [
    # The namespace unit runs only ip (G4 follow-up), so only ip holds them.
    ("azazel-decoy-nsd", {"capability sys_admin,", "capability net_admin,"}),
    ("azazel-decoy-netd", {"capability net_admin,"}),
    ("azazel-decoy-verify", {"capability net_admin,"}),
    ("azazel-decoyd", set()),
])
def test_each_profile_allows_exactly_its_units_capabilities(block, expected):
    allows = _allows(_all_blocks()[block])
    assert {rule for rule in allows if rule.startswith("capability")} == expected
    assert expected == {f"capability {cap.removeprefix('CAP_').lower()},"
                        for cap in _unit_of(block).capability_bounding_set}


def test_the_namespace_unit_runs_no_python_and_only_ip():
    """G4 follow-up: the Python body and its `Cx` child are gone; systemd runs
    `ip` directly under the one profile, so the capabilities are ip's alone."""

    from azazel_nexus_runtime import decoy_network

    profile = next(p for p in ALL_PROFILES if p.unit == DECOY_NAMESPACE_UNIT)
    assert profile.executable == "/usr/bin/ip"
    assert not (Path(decoy_network.__file__).parent / "decoy_nsd.py").exists()
    rules = _all_blocks()["azazel-decoy-nsd"]
    assert not any("python" in rule or "/opt/azazel-nexus" in rule
                   or "/usr/libexec/azazel" in rule for rule in rules)
    assert not any(" Cx" in rule or " Px" in rule or " ix" in rule for rule in rules)
    assert "/usr/bin/ip mr," in rules
    # The helper's body still never enters a namespace or mounts.
    tree = ast.parse(Path(decoy_network.__file__).read_text(encoding="utf-8"))
    called = {node.func.attr if isinstance(node.func, ast.Attribute) else
              getattr(node.func, "id", "") for node in ast.walk(tree)
              if isinstance(node, ast.Call)}
    assert not called & {"setns", "unshare", "mount", "umount", "socket"}


def test_the_decoy_profile_denies_every_capability():
    assert "deny capability," in _all_blocks()["azazel-decoyd"]


@pytest.mark.parametrize(("block", "expected"), [
    ("azazel-decoy-nsd", {"network netlink raw,"}),
    ("azazel-decoy-netd", {"network netlink raw,"}),
    ("azazel-decoy-verify", {"network netlink raw,"}),
    ("azazel-decoyd", {"network inet stream,"}),
])
def test_each_profile_allows_only_its_units_address_families(block, expected):
    rules = _allows(_all_blocks()[block])
    found = {rule for rule in rules if rule.startswith("network")}
    assert found == expected
    families = {f"AF_{rule.split()[1].upper()}" for rule in found}
    if any(rule.startswith("unix") for rule in rules):
        families.add("AF_UNIX")
    assert families == set(_unit_of(block).address_families)


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


PYTHON = f"{PROFILE_INTERPRETER} mrix,"


@pytest.mark.parametrize(("block", "expected"), [
    # systemd starts ip under the profile; ip runs nothing (G4 follow-up).
    ("azazel-decoy-nsd", set()),
    ("azazel-decoy-netd", {PYTHON, "/usr/bin/ip mrix,", "/usr/sbin/nft mrix,"}),
    ("azazel-decoy-verify", {PYTHON, "/usr/bin/ip mrix,", "/usr/sbin/nft mrix,"}),
    ("azazel-decoyd", {PYTHON}),
])
def test_each_profile_runs_only_its_fixed_programs(block, expected):
    assert _executes(_all_blocks()[block]) == expected


def test_the_profiles_python_is_the_one_the_installer_checks():
    """Findings 4 and 7 of #285: one interpreter, two code roots, in both places."""

    from azazel_nexus_runtime.python_profile import BASE_INTERPRETER

    assert PROFILE_INTERPRETER == "/" + BASE_INTERPRETER == "/usr/bin/python3.13"
    assert PROFILE_PYTHON_ROOTS == ("/usr/lib/python3.13", "/opt/azazel-nexus/venv")
    # The namespace unit runs no Python (G4 follow-up).
    for block in ("azazel-decoy-netd", "azazel-decoy-verify", "azazel-decoyd"):
        reads = {rule for rule, _ in _file_rules(_all_blocks()[block])}
        assert {f"{root}/** mr," for root in PROFILE_PYTHON_ROOTS} <= reads
        assert not any("python3*" in rule or "python3{" in rule
                       or "/usr/local" in rule for rule in reads), block


#: The only mounts any profile allows: those `ip netns add`, `ip netns
#: delete` and `ip -n` make (prerequisites §13), in the namespace unit's
#: profile, under which only `ip` runs (G4 follow-up). The exact rules are VM work (G4); this pins what is claimed. The
#: first bind of /run/netns onto itself is allowed as rbind (iproute2's
#: MS_BIND|MS_REC) and as bind until the VM shows which.
IP_MOUNTS = {
    "mount options=(rw, rshared) -> /run/netns/,",
    "mount options=(rw, rbind) /run/netns/ -> /run/netns/,",
    "mount options=(rw, bind) /run/netns/ -> /run/netns/,",
    "mount options=(rw, bind) @{PROC}/@{pid}/{,task/@{tid}/}ns/net -> /run/netns/azazel-decoy,",
    # G4: the nsfs source as the kernel names it (the prefix of the flags).
    f"mount options=(rw, bind) {DISCONNECTED} -> /run/netns/azazel-decoy,",
    "umount /run/netns/azazel-decoy,",
    "mount options=(rw, rslave) -> /,",
    "umount /sys/,",
    "mount fstype=sysfs -> /sys/,",
}


@pytest.mark.parametrize("block", REQUIRED_ENFORCED_PROFILES)
def test_only_the_namespace_units_ip_mounts_and_only_what_ip_needs(block):
    mounts = {rule for rule in _allows(_all_blocks()[block])
              if rule.startswith(("mount", "umount", "remount", "pivot_root"))}
    assert mounts == (IP_MOUNTS if block == "azazel-decoy-nsd" else set())
    # /etc/netns/azazel-decoy is never bound over /etc.
    assert not any("/etc/netns" in rule for rule in mounts)


def test_the_namespace_units_ip_maps_its_libraries():
    assert "/usr/lib/@{multiarch}/** mr," in _all_blocks()["azazel-decoy-nsd"]


def test_the_helper_writes_only_its_runtime_directory():
    assert _writes(_all_blocks()["azazel-decoy-netd"]) == {
        "/run/azazel-decoy-isolation/* rw,"}


def test_the_helper_reads_its_scope_credential_and_only_there():
    """#196 G1b: the credential path the reader opens, read only, in no other profile."""

    from azazel_nexus.decoy_scope import SCOPE_CREDENTIAL_PATH

    directory = SCOPE_CREDENTIAL_PATH.rpartition("/")[0] + "/"
    blocks = _all_blocks()
    credential = {rule for rule in blocks["azazel-decoy-netd"] if "/run/credentials" in rule}
    assert credential == {f"{directory} r,", f"{SCOPE_CREDENTIAL_PATH} r,"}
    for name, rules in blocks.items():
        if name not in ("azazel-decoy-netd", "azazel-decoy-verify", "azazel-decoyd"):
            assert not any("/run/credentials" in rule or "decoy-scope" in rule
                           for rule in rules), name


def test_the_decoy_reads_only_its_scope_digest_credential():
    """#196 G6 (wiring §6, D2): the decoy's one credential is the pass's scope
    digest, read only at its own path; never the scope file itself."""

    from azazel_nexus.decoy_isolation import SCOPE_DIGEST_CREDENTIAL_PATH

    directory = SCOPE_DIGEST_CREDENTIAL_PATH.rpartition("/")[0] + "/"
    rules = _all_blocks()["azazel-decoyd"]
    credential = {rule for rule in rules if "/run/credentials" in rule or "decoy-scope" in rule}
    assert credential == {f"{directory} r,", f"{SCOPE_DIGEST_CREDENTIAL_PATH} r,"}
    assert SCOPE_DIGEST_CREDENTIAL_PATH == (
        "/run/credentials/azazel-decoyd.service/decoy-scope-digest")


def test_the_verify_unit_reads_its_own_scope_credential_and_only_there():
    """#196 G2: the same source file, at the verify unit's own credential path."""

    from azazel_nexus.decoy_scope import VERIFY_SCOPE_CREDENTIAL_PATH

    directory = VERIFY_SCOPE_CREDENTIAL_PATH.rpartition("/")[0] + "/"
    rules = _all_blocks()["azazel-decoy-verify"]
    credential = {rule for rule in rules if "/run/credentials" in rule}
    assert credential == {f"{directory} r,", f"{VERIFY_SCOPE_CREDENTIAL_PATH} r,"}


def test_the_verify_unit_writes_nothing_and_reads_only_forwarding_under_proc_sys():
    """#196 G2: the helper's profile without its one writable place (grant §7)."""

    rules = _all_blocks()["azazel-decoy-verify"]
    assert _writes(rules) == set()
    assert "deny /run/azazel-decoy-isolation{,/**} wlk," in rules
    assert "deny @{PROC}/sys/** wlk," in rules
    assert not any("/run/azazel-decoy-isolation" in rule for rule in _allows(rules))
    sysctl = {rule for rule in _allows(rules) if "/sys/net" in rule}
    assert sysctl == {
        "@{PROC}/sys/net/ipv4/conf/ r,", "@{PROC}/sys/net/ipv4/conf/*/ r,",
        "@{PROC}/sys/net/ipv4/conf/*/forwarding r,",
        "@{PROC}/sys/net/ipv4/conf/*/proxy_arp r,",
        "@{PROC}/sys/net/ipv6/ r,", "@{PROC}/sys/net/ipv6/conf/ r,",
        "@{PROC}/sys/net/ipv6/conf/*/ r,", "@{PROC}/sys/net/ipv6/conf/*/forwarding r,",
    }
    # Its allows are the helper's but for the record and the boot id (which
    # only the record needs), its credential and the forwarding reads.
    helper = set(_allows(_all_blocks()["azazel-decoy-netd"]))
    verify = set(_allows(rules))
    assert helper - verify == {
        "/run/azazel-decoy-isolation/ r,", "/run/azazel-decoy-isolation/* rw,",
        "@{PROC}/sys/kernel/random/boot_id r,",
        "/run/credentials/azazel-decoy-netd.service/ r,",
        "/run/credentials/azazel-decoy-netd.service/decoy-scope r,",
        "signal (send) set=(kill) peer=azazel-decoy-netd,",
        "signal (receive) peer=azazel-decoy-netd,",
    }


def test_the_decoy_writes_only_to_connect_to_the_intake_socket():
    assert _writes(_all_blocks()["azazel-decoyd"]) == {f"{INTAKE_SOCKET} rw,"}


def test_the_namespace_units_ip_writes_only_the_namespace_handle():
    # `k` on the directory only: ip netns add flocks /run/netns/ (G4).
    assert _writes(_all_blocks()["azazel-decoy-nsd"]) == {
        "/run/netns/ rwk,", "/run/netns/azazel-decoy rw,"}
    assert not any("k" in permissions for rule, permissions
                   in _file_rules(_all_blocks()["azazel-decoy-nsd"])
                   if rule != "/run/netns/ rwk,")


def test_the_namespace_unit_names_only_the_disconnected_prefix_never_the_real_root():
    """G4: the nsfs file is a disconnected path. Named under the prefix, it is
    kept apart from the host's real `/`; a rule over `/` would let `/` be bound
    onto the handle and every denied path reached again under it."""

    rules = _all_blocks()["azazel-decoy-nsd"]
    assert [rule for rule in rules if DISCONNECTED in rule] == [
        f"{DISCONNECTED} r,",
        f"mount options=(rw, bind) {DISCONNECTED} -> /run/netns/azazel-decoy,",
    ]
    # The prefix alone: nothing under it.
    assert not any(f"{DISCONNECTED}*" in rule or f"{DISCONNECTED}{{" in rule for rule in rules)
    for block, block_rules in _all_blocks().items():
        for rule in block_rules:
            assert not rule.startswith("/ "), (block, rule)
            assert " / -> " not in rule, (block, rule)
            # `/` as a target only in ip -n's slave remount (no source).
            assert (not rule.endswith(" /,")
                    or rule == "mount options=(rw, rslave) -> /,"), (block, rule)
        if block != "azazel-decoy-nsd":
            assert not any(DISCONNECTED in rule for rule in block_rules), block


def test_the_decoy_reads_its_net_dev_without_owner():
    """G4: /proc/<pid>/net is owned by root, not by the decoy's account, so an
    `owner` rule refused it (fsuid=979 ouid=0)."""

    rules = _all_blocks()["azazel-decoyd"]
    assert "@{PROC}/@{pid}/net/dev r," in rules
    assert "owner @{PROC}/@{pid}/net/dev r," not in rules
    assert "owner @{PROC}/@{pid}/ns/net r," in rules
    # Without `owner` it matches every pid, so the unit hides other users'
    # processes (review of #289 F1); not ProcSubset=pid, which would hide the
    # boot id the decoy reads under /proc/sys.
    settings = _settings((UNIT_DIR / DECOY_UNIT).read_text(encoding="utf-8"))
    assert settings["ProtectProc"] == ["invisible"]
    assert "ProcSubset" not in settings
    assert "@{PROC}/sys/kernel/random/boot_id r," in rules


def test_the_service_manager_sockets_are_hidden_by_the_sandbox_not_only_the_profile():
    """G4: on Debian 13's kernel a path connect to the D-Bus socket succeeded
    under all three profiles that could make one (aa-exec, outside the units);
    the profiles' denies are defence in depth. By design the address families
    (namespace unit) or `InaccessiblePaths=` (the others) keep it from the
    manager; a connect under the units was not run in G4."""

    for unit, name in DECOY_APPARMOR_PROFILES:
        # The two denies stay, exactly and once, for a kernel that mediates
        # path unix.
        rules = _all_blocks()[name]
        for deny in ("deny /run/dbus/system_bus_socket rw,", "deny /run/systemd/private rw,"):
            assert rules.count(deny) == 1, (name, deny)
        assert not any("system_bus_socket" in rule or "/run/systemd/private" in rule
                       for rule in _allows(rules)), name
        settings = _settings((UNIT_DIR / unit).read_text(encoding="utf-8"))
        if unit == DECOY_NAMESPACE_UNIT:
            assert settings["RestrictAddressFamilies"] == ["AF_NETLINK"]
        else:
            hidden = set(settings["InaccessiblePaths"])
            assert {"-/run/dbus/system_bus_socket", "-/run/systemd/private"} <= hidden, unit


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
        # Finding 2 of #285: with AppArmor disabled systemd ignores
        # AppArmorProfile=; the assertion fails the start instead.
        assert settings["AssertSecurity"] == ["apparmor"]
        unit_section = text.split("[Service]")[0]
        assert "\nAssertSecurity=apparmor\n" in unit_section


def test_no_other_unit_asserts_apparmor():
    for profile in ALL_PROFILES:
        if profile.unit not in PROFILED_UNITS:
            assert "AssertSecurity" not in render_unit(profile)


def test_the_verify_unit_names_its_own_profile_without_a_dash():
    """#196 G2: like the three, `AppArmorProfile=` without `-` and the assertion."""

    profile = next(p for p in ALL_PROFILES if p.unit == VERIFY)
    assert profile.apparmor_profile == NAMES[VERIFY] == apparmor_profile_for(VERIFY)
    for text in (render_unit(profile), (UNIT_DIR / VERIFY).read_text(encoding="utf-8")):
        settings = _settings(text)
        assert settings["AppArmorProfile"] == ["azazel-decoy-verify"]
        assert settings["AssertSecurity"] == ["apparmor"]
        assert "\nAssertSecurity=apparmor\n" in text.split("[Service]")[0]
    with pytest.raises(ValueError, match="AppArmorProfile"):
        replace(profile, apparmor_profile="azazel-decoy-netd")


def _content(unit: str, text: str) -> None:
    from azazel_nexus_runtime.activation_unit_files import require_governed_unit_content

    require_governed_unit_content(unit, text.encode("ascii"))


@pytest.mark.parametrize("unit", DECEPTION_EXPOSURE_UNITS)
def test_the_unit_content_check_accepts_the_rendered_exposure_unit(unit):
    _content(unit, (UNIT_DIR / unit).read_text(encoding="utf-8"))


@pytest.mark.parametrize("change", [
    "remove-profile", "dash-profile", "other-profile", "double-profile",
    "profile-in-unit-section", "remove-assert", "double-assert", "reset-profile",
])
@pytest.mark.parametrize("unit", DECEPTION_EXPOSURE_UNITS)
def test_the_unit_content_check_refuses_a_changed_lsm_line(unit, change):
    """Finding 3 of #285: the profile line and the assertion, exactly, once."""

    from azazel_nexus_runtime.activation_unit_files import UnitContentRefused

    text = (UNIT_DIR / unit).read_text(encoding="utf-8")
    line = f"AppArmorProfile={NAMES[unit]}\n"
    changed = {
        "remove-profile": text.replace(line, ""),
        "dash-profile": text.replace(line, f"AppArmorProfile=-{NAMES[unit]}\n"),
        "other-profile": text.replace(line, "AppArmorProfile=unconfined\n"),
        "double-profile": text.replace(line, line + line),
        "profile-in-unit-section": text.replace(line, "").replace(
            "\n[Service]", f"\n{line}[Service]"),
        "remove-assert": text.replace("AssertSecurity=apparmor\n", ""),
        "double-assert": text.replace("AssertSecurity=apparmor\n",
                                      "AssertSecurity=apparmor\nAssertSecurity=apparmor\n"),
        "reset-profile": text.replace(line, line + "AppArmorProfile=\n"),
    }[change]
    assert changed != text
    with pytest.raises(UnitContentRefused):
        _content(unit, changed)


def _loaded(unit: str, asserts: list) -> dict:
    return {
        "Id": unit, "LoadState": "loaded",
        "FragmentPath": f"/usr/lib/systemd/system/{unit}", "DropInPaths": [],
        "Conditions": [("ConditionPathExists", False, False,
                        f"/run/azazel-activation/granted/{unit}", 0)],
        "Asserts": asserts,
        "Requires": ["azazel-activated.service"], "After": ["azazel-activated.service"],
    }


@pytest.mark.parametrize("unit", DECEPTION_EXPOSURE_UNITS)
def test_the_loaded_unit_check_requires_the_apparmor_assertion(unit):
    """Finding 3 of #285: a manager that loaded the unit without it is refused.

    The loaded `AppArmorProfile=` (a property of the Service interface, which
    the pass does not read yet) is G6's (grant design §7).
    """

    from azazel_nexus_runtime.activation_loaded_units import (
        LoadedUnitRefused,
        _check_loaded,
    )

    _check_loaded(unit, _loaded(unit, [("AssertSecurity", False, False, "apparmor", 0)]))
    for asserts in ([], [("AssertSecurity", False, True, "apparmor", 0)],
                    [("AssertSecurity", False, False, "selinux", 0)]):
        with pytest.raises(LoadedUnitRefused):
            _check_loaded(unit, _loaded(unit, asserts))


@pytest.mark.parametrize("unit", ["azazel-edge-core.service", "azazel-mio-entryd.service"])
def test_the_unit_content_check_refuses_a_profile_on_another_unit(unit):
    from azazel_nexus_runtime.activation_unit_files import UnitContentRefused

    text = (UNIT_DIR / unit).read_text(encoding="utf-8")
    _content(unit, text)
    with pytest.raises(UnitContentRefused):
        _content(unit, text.replace("[Service]\n", "[Service]\nAppArmorProfile=azazel-decoyd\n"))


def test_no_other_unit_names_a_profile():
    for profile in ALL_PROFILES:
        if profile.unit in PROFILED_UNITS:
            continue
        assert profile.apparmor_profile == ""
        assert "AppArmorProfile" not in render_unit(profile)
    for path in UNIT_DIR.iterdir():
        if path.name not in PROFILED_UNITS:
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
    assert ("for profile in azazel-decoy-nsd azazel-decoy-netd azazel-decoy-verify "
            "azazel-decoyd; do" in INSTALLER)


def test_the_installer_compiles_the_profiles_before_writing_anything():
    compile_at = INSTALLER.index("apparmor_parser --skip-kernel-load")
    for first_write in ("useradd", "make_dir 0755 root /etc/azazel",
                        'install -d -m 0755 "$UNIT_DIR"'):
        assert compile_at < INSTALLER.index(first_write), first_write
    # Inside the service-manager block (which since the review of #288 also
    # checks /usr/bin/ip first), with no `fi` between its start and here.
    opened = INSTALLER.rindex('if [ "$WITH_SERVICE_MANAGER" = yes ]; then', 0, compile_at)
    block = INSTALLER[opened:compile_at]
    assert "\nfi\n" not in block and compile_at - opened < 1200


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


def test_the_installer_warns_when_apparmor_is_disabled():
    """Finding 2 of #285: a warning, not a refusal; the units' assertion is the wall."""

    block = INSTALLER[INSTALLER.index("lsm=\n"):INSTALLER.index("Non-login accounts")]
    assert "read -r lsm < /sys/kernel/security/lsm" in block
    assert "*,apparmor,*) ;;" in block
    assert "WARNING: AppArmor is not enabled in this kernel." in block
    assert "exit" not in block.split("WARNING: AppArmor")[1].split("esac")[0]


def _stale_child_check() -> str:
    start = INSTALLER.index("    # A child profile or hat of a decoy profile still loaded")
    end = INSTALLER.index("    # end of the stale child check")
    return INSTALLER[start:end]


@pytest.mark.parametrize(("listing", "said"), [
    (b"azazel-decoy-nsd (enforce)\nazazel-decoy-nsd//ip (complain)\n", True),
    (b"azazel-decoyd//hat (enforce)\n", True),
    (b"azazel-decoy-verify//x (enforce)\n", True),
    (b"azazel-decoy-netd//null-/usr/sbin/nft (complain)\n", True),
    (b"azazel-decoy-nsd (enforce)\nazazel-decoyd (enforce)\n", False),
    (b":ns:azazel-decoy-nsd//ip (complain)\n", False),
    (b"azazel-decoy-nsdx//ip (complain)\nother//azazel-decoy-nsd//ip (enforce)\n", False),
    (b"", False),
    (None, False),
])
def test_the_installer_says_a_stale_child_must_go_and_changes_nothing(tmp_path, listing,
                                                                      said):
    """Finding 4 of the review of #303: a stale child is detected and the
    operator told to reboot or remove and reload the parent; the installer
    loads, replaces and removes nothing, and does not refuse."""

    block = _stale_child_check()
    # Inside the service-manager block, after the AppArmor-disabled warning.
    assert INSTALLER.index("WARNING: AppArmor is not enabled") < INSTALLER.index(block)
    opened = INSTALLER.rindex('if [ "$WITH_SERVICE_MANAGER" = yes ]; then', 0,
                              INSTALLER.index(block))
    assert "\nfi\n" not in INSTALLER[opened:INSTALLER.index(block)]
    for forbidden in ("apparmor_parser", "aa-", "exit", ">&2"):
        assert forbidden not in block, forbidden
    path = tmp_path / "profiles"
    if listing is not None:
        path.write_bytes(listing)
    script = block.replace("/sys/kernel/security/apparmor/profiles", str(path))
    assert script != block
    run = subprocess.run(["bash", "-c", script], capture_output=True, check=True)
    assert run.stderr == b""
    if said:
        out = run.stdout.decode()
        assert "NOTICE: a child profile of a Deception Lite AppArmor profile" in out
        assert "reboot, or, with the decoy units stopped, remove the parent" in out
        assert "Nothing was loaded or removed." in out
    else:
        assert run.stdout == b""


def test_the_installer_checks_the_decoy_wrappers_against_the_profiles():
    """Finding 4 of #285: refused with the service manager, a warning without."""

    tool = '"$REPO_ROOT/tools/check_decoy_apparmor_wrappers.py"'
    assert (f'python_fixed -IS {tool} "$LIBEXEC" || exit 1') in INSTALLER
    assert (f'python_fixed -IS {tool} --warn-only "$LIBEXEC"') in INSTALLER
    check = INSTALLER.index(f"python_fixed -IS {tool} \"$LIBEXEC\"")
    assert INSTALLER.rindex('if [ "$WITH_SERVICE_MANAGER" = yes ]; then', 0, check) > \
        INSTALLER.index("for binary in az-activated")
    # After the wrappers are staged, before any account or directory.
    assert INSTALLER.index("stage_runtime_entrypoints") < check < INSTALLER.index("useradd")


# -- the staged wrappers --------------------------------------------------------

STDLIB = "/usr/lib/python3.13"
SITE = "/opt/azazel-nexus/venv/lib/python3.13/site-packages"


@pytest.mark.parametrize("paths", [
    (STDLIB, f"{STDLIB}/lib-dynload", SITE),
    (SITE,),
    ("/opt/azazel-nexus/venv",),
])
def test_a_wrapper_inside_the_profiles_is_accepted(paths):
    assert wrapper_profile_refusal(PROFILE_INTERPRETER, paths) is None


@pytest.mark.parametrize(("interpreter", "paths"), [
    ("/usr/bin/python3", (STDLIB, SITE)),
    ("/usr/local/bin/python3.13", (STDLIB, SITE)),
    ("/opt/azazel-nexus/venv/bin/python3.13", (STDLIB, SITE)),
    (PROFILE_INTERPRETER, (STDLIB, "/usr/local/lib/python3.13/dist-packages")),
    (PROFILE_INTERPRETER, (STDLIB, "/usr/lib/python3/dist-packages")),
    (PROFILE_INTERPRETER, (STDLIB, "/opt/venv/lib/python3.13/site-packages")),
    (PROFILE_INTERPRETER, (STDLIB, "/opt/azazel-nexus/venv-other/lib")),
    (PROFILE_INTERPRETER, (STDLIB, "/usr/lib/python3.130")),
    (PROFILE_INTERPRETER, ()),
])
def test_a_wrapper_outside_the_profiles_is_refused(interpreter, paths):
    assert wrapper_profile_refusal(interpreter, paths) is not None


def _tool():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_decoy_apparmor_wrappers", ROOT / "tools" / "check_decoy_apparmor_wrappers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stage(libexec: Path, interpreter: str, paths: tuple[str, ...]) -> None:
    from azazel_nexus_runtime.startup_wrapper import render_wrapper

    tool = _tool()
    libexec.mkdir(exist_ok=True)
    for name, target in tool._targets().items():
        (libexec / name).write_bytes(render_wrapper(interpreter, target, import_paths=paths))


def test_the_wrapper_check_accepts_wrappers_inside_the_profiles(tmp_path, monkeypatch):
    tool = _tool()
    # Resolution is the kernel's; here the paths do not exist, so they are
    # their own resolution (the real resolution is tested below).
    monkeypatch.setattr(tool.os.path, "realpath", lambda path, **_: path)
    _stage(tmp_path / "libexec", PROFILE_INTERPRETER, (STDLIB, SITE))
    assert tool.findings(tmp_path / "libexec") == []
    assert tool.main([str(tmp_path / "libexec")]) == 0


def test_the_wrapper_check_resolves_links_before_judging(tmp_path):
    tool = _tool()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = tmp_path / "venv-link"
    os.symlink(elsewhere, link)
    _stage(tmp_path / "libexec", PROFILE_INTERPRETER, (str(link),))
    found = tool.findings(tmp_path / "libexec")
    assert len(found) == 2
    assert all("import paths resolve outside" in line for line in found)


def test_the_wrapper_check_refuses_and_warn_only_reports(tmp_path, capsys):
    tool = _tool()
    _stage(tmp_path / "libexec", "/nonexistent/bin/python3.13", (STDLIB,))
    assert tool.main([str(tmp_path / "libexec")]) == 1
    assert capsys.readouterr().err.count("refusing to install: az-decoy") == 2
    assert tool.main(["--warn-only", str(tmp_path / "libexec")]) == 0
    assert capsys.readouterr().err.count("WARNING: az-decoy") == 2


def test_the_wrapper_check_refuses_a_missing_or_foreign_wrapper(tmp_path):
    tool = _tool()
    libexec = tmp_path / "libexec"
    libexec.mkdir()
    (libexec / "az-decoyd").write_bytes(b"#!/bin/sh\nexec python3 -m x\n")
    found = tool.findings(libexec)
    assert len(found) == 2
    assert all("not a readable canonical wrapper" in line for line in found)


def test_the_wrapper_check_names_exactly_the_two_decoy_wrappers():
    import tomllib

    tool = _tool()
    # The namespace unit has no wrapper: it runs /usr/bin/ip (G4 follow-up).
    assert tool.WRAPPERS == ("az-decoy-netd", "az-decoyd")
    with (ROOT / "runtime" / "pyproject.toml").open("rb") as stream:
        scripts = tomllib.load(stream)["project"]["scripts"]
    assert tool.TARGETS == {name: scripts[name] for name in tool.WRAPPERS}
    assert {f"/usr/libexec/azazel/{name}" for name in tool.WRAPPERS} == {
        p.executable for p in PROFILES
        if p.unit in DECEPTION_EXPOSURE_UNITS and p.unit != DECOY_NAMESPACE_UNIT}
    assert "az-decoy-nsd" not in scripts


# -- the enforce-mode check -----------------------------------------------------

LSM = b"lockdown,capability,landlock,yama,apparmor,tomoyo,bpf,ipe,ima,evm"
ENFORCED = (
    b"/usr/bin/man (enforce)\n"
    b"azazel-decoyd (enforce)\n"
    b"azazel-decoy-nsd (enforce)\n"
    b"azazel-decoy-netd (enforce)\n"
    b"azazel-decoy-verify (enforce)\n"
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
    # One fixed phrase per code: no count (review of #196 G6 preparation, M1).
    assert reason == exposure_lsm_refusal(LSM, _without(b"azazel-decoyd"))
    assert not any(c.isdigit() for c in reason)


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
])
def test_apparmor_disabled_withholds(lsm, profiles):
    reason = exposure_lsm_refusal(lsm, profiles)
    assert reason is not None and reason.startswith(LSM_APPARMOR_DISABLED + ":")


@pytest.mark.parametrize("line", [
    b"azazel-decoyd enforce",
    b"azazel-decoyd",
    b"azazel-decoyd (enforce",
    b" azazel-decoyd (enforce)",
    b"azazel-decoyd ()",
    b"azazel-decoyd (en force)",
    b"azazel-decoyd (Enforce)",
    b"azazel-decoyd (enforce)\r",
    b"azazel-decoy-nsd (enforce) ",
])
def test_a_required_profiles_line_not_in_the_kernels_form_withholds(line):
    """Finding 8 of #285: the required names' lines are read strictly."""

    reason = exposure_lsm_refusal(LSM, ENFORCED + line + b"\n")
    assert reason is not None and reason.startswith(LSM_PROFILES_UNREADABLE + ":")


@pytest.mark.parametrize("line", [
    # The former child of the G4 follow-up: replacing its parent leaves it
    # in the kernel (observed on the VM, Debian 13, AppArmor 4.1).
    b"azazel-decoy-nsd//ip (complain)",
    b"azazel-decoy-nsd//ip (enforce)",
    b"azazel-decoyd//hat (enforce)",
    b"azazel-decoy-netd//null-/usr/sbin/nft (complain)",
    b" azazel-decoy-verify//x (kill)",
    b"azazel-decoyd//",
])
def test_a_child_profile_or_hat_of_a_required_profile_withholds(line):
    """Review of #196 G6 preparation (L5) and of #303 (finding 5): a child or a
    hat of a required profile, in any mode, has its own code, after the G3
    codes, and is not "unreadable"."""

    from azazel_nexus_runtime.decoy_apparmor import LSM_PROFILE_CHILD_PRESENT

    assert exposure_lsm_refusal(LSM, ENFORCED + line + b"\n").startswith(
        LSM_PROFILE_CHILD_PRESENT + ":")
    # The G3 codes come first: an absent or lax profile is said before it.
    assert exposure_lsm_refusal(LSM, _without(b"azazel-decoyd") + line + b"\n"
                                ).startswith(LSM_PROFILES_ABSENT + ":")


@pytest.mark.parametrize("line", [
    b"(enforce)",
    b"\xff (enforce)",
    b"some profile with spaces (complain)",
    b"other-tool enforce",
    b"azazel-decoyd-lookalike (complain)",
    b":ns:azazel-decoyd (complain)",
    b"garbage without a mode",
    # Another namespace's child, and a look-alike's: not ours.
    b":ns:azazel-decoy-nsd//ip (complain)",
    b"azazel-decoy-nsdx//ip (complain)",
])
def test_other_lines_in_any_form_do_not_matter(line):
    """Finding 8 of #285: only the required names' lines are judged."""

    assert exposure_lsm_refusal(LSM, ENFORCED + line + b"\n") is None


@pytest.mark.parametrize(("lsm", "profiles"), [
    (UNREADABLE, ENFORCED),
    (LSM, UNREADABLE),
    (UNREADABLE, UNREADABLE),
    (b"apparmor," * 1000, ENFORCED),
    (LSM, b"x (enforce)\n" * 100_000),
])
def test_a_file_present_and_unreadable_or_oversized_withholds_as_unreadable(lsm, profiles):
    """Finding 8 of #285: EACCES or EIO is not "AppArmor disabled"."""

    reason = exposure_lsm_refusal(lsm, profiles)
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


def test_the_reader_tells_an_absent_file_from_an_unreadable_one(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.write_bytes(ENFORCED)
    link = tmp_path / "link"
    os.symlink(real, link)
    lsm = tmp_path / "lsm"
    lsm.write_bytes(LSM)
    # Absent: AppArmor is not there.
    monkeypatch.setattr(decoy_apparmor, "_LSM", str(tmp_path / "absent"))
    monkeypatch.setattr(decoy_apparmor, "_PROFILES", str(tmp_path / "absent-too"))
    assert read_exposure_lsm() == (None, None)
    assert exposure_lsm_refusal(*read_exposure_lsm()).startswith(LSM_APPARMOR_DISABLED)
    # A link is never followed: present and unreadable.
    monkeypatch.setattr(decoy_apparmor, "_LSM", str(lsm))
    monkeypatch.setattr(decoy_apparmor, "_PROFILES", str(link))
    assert read_exposure_lsm() == (LSM, UNREADABLE)
    assert exposure_lsm_refusal(*read_exposure_lsm()).startswith(LSM_PROFILES_UNREADABLE)


@pytest.mark.parametrize("errno_value", [13, 5, 40])
def test_a_read_error_is_unreadable_not_absent(tmp_path, monkeypatch, errno_value):
    """EACCES, EIO and ELOOP give UNREADABLE; only ENOENT/ENOTDIR give None."""

    def failing_open(*_args, **_kwargs):
        raise OSError(errno_value, "refused")

    monkeypatch.setattr(decoy_apparmor.os, "open", failing_open)
    assert read_exposure_lsm() == (UNREADABLE, UNREADABLE)
    assert exposure_lsm_refusal(*read_exposure_lsm()).startswith(LSM_PROFILES_UNREADABLE)


def test_a_failing_read_after_open_is_unreadable(tmp_path, monkeypatch):
    path = tmp_path / "profiles"
    path.write_bytes(ENFORCED)
    monkeypatch.setattr(decoy_apparmor, "_PROFILES", str(path))

    def failing_read(*_args):
        raise OSError(5, "EIO")

    monkeypatch.setattr(decoy_apparmor.os, "read", failing_read)
    assert read_exposure_lsm()[1] is UNREADABLE


def test_the_production_paths_are_securityfs():
    assert decoy_apparmor._LSM == "/sys/kernel/security/lsm"
    assert decoy_apparmor._PROFILES == "/sys/kernel/security/apparmor/profiles"


# -- not reached in this build --------------------------------------------------
#
# Which files import the module (the unit renderer, the install plan, the
# wrapper check and `exposure_generation`), that its LSM names and reason codes
# appear nowhere else, and that the tier is still withheld unconditionally, are
# `test_g6_unwired.py` (#196 L1), with every other G6 part. G6 edits that
# table when it wires the check in.
