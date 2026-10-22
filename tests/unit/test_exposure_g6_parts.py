"""#196 G6 preparation C: the parts of the grant condition, built and not wired.

`docs/deception-exposure-grant.md` §4.4 item 5, §5 C1 conditions 2, 4, 5 and
6, §6.2, §6.3 and §7 "Left to G6":

* the generation's exposure section (`exposure_generation`, with
  `activation_unit_files.measure_exposure_unit_files` and the bytes
  `require_watch_unit_files` now returns);
* coexistence and `fb_tunnels_only_for_init_net` (`exposure_withholding`);
* the LSM condition with the loaded-unit and kernel-hash comparisons
  (`decoy_apparmor.exposure_lsm_withholding`);
* the governed-set exclusion of the tier and an enforcing unit
  (`azazel_nexus.exposure_exclusivity`).

And that none of them is reached: no product module imports or names them,
the tier is still withheld as `isolation_evidence_absent`, and the schema,
allowlist and grantable set are unchanged.
"""

from __future__ import annotations

import ast
from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path
import re

import pytest

from azazel_nexus.activation import (
    CORE_UNITS,
    DECEPTION_EXPOSURE_UNITS,
    UnitDefinition,
    UnitTier,
)
from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
from azazel_nexus.decoy_scope import parse_scope_file
from azazel_nexus.exposure_exclusivity import (
    EXPOSURE_ENFORCEMENT_EXCLUSIVE,
    exposure_enforcement_conflict,
)
from azazel_nexus.generation import GenerationRefused
from azazel_nexus.observe_baseline import OBSERVE_BASELINE_SCHEMA
from azazel_nexus_runtime import activation_unit_files as unit_files
from azazel_nexus_runtime import decoy_apparmor, exposure_withholding
from azazel_nexus_runtime.activation_markers import EXPOSURE_UNITS, GRANTABLE_UNITS
from azazel_nexus_runtime.decoy_apparmor import (
    DECOY_APPARMOR_PROFILES,
    LSM_APPARMOR_DISABLED,
    LSM_LOADED_REASON_CODES,
    LSM_POLICY_DIFFERS,
    LSM_POLICY_UNVERIFIABLE,
    LSM_REASON_CODES,
    LSM_UNIT_PROFILE_DIFFERS,
    REQUIRED_ENFORCED_PROFILES,
    UNREADABLE,
    exposure_lsm_withholding,
    loaded_unit_profile_refusal,
    policy_hash_refusal,
    read_policy_hashes,
)
from azazel_nexus_runtime.exposure_generation import (
    APPARMOR_DIRECTORY,
    EXPOSURE_SECTION_KEYS,
    ExposureFilesRefused,
    build_exposure_section,
    measure_exposure_section_inputs,
    verify_exposure_section,
)
from azazel_nexus_runtime.exposure_withholding import (
    FB_TUNNELS_NOT_INIT_NET_ONLY,
    FB_TUNNELS_REASON_CODES,
    HOST_FIREWALL_ACTIVE,
    HOST_FIREWALL_ENABLED,
    HOST_FIREWALL_REASON_CODES,
    HOST_FIREWALL_UNITS,
    HOST_FIREWALL_UNREADABLE,
    fb_tunnels_refusal,
    host_firewall_refusal,
    read_fb_tunnels,
)
from azazel_nexus_runtime.hardening import packaged_unit_files

ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "packaging" / "apparmor"
WATCH = unit_files.WATCH_UNITS
SCOPE = (b'{"approved_v4":["10.20.0.0/24","172.16.8.0/22","192.168.10.0/24"],'
         b'"contract":"azazel-nexus/decoy-scope/v1","ingress":["enp3s0"]}\n')
VENDOR = "usr/lib/systemd/system"


def _sha(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


# -- the generation's exposure section ------------------------------------------


@pytest.fixture
def root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    vendor = root / VENDOR
    vendor.mkdir(parents=True)
    rendered = dict(packaged_unit_files())
    for unit in (*sorted(EXPOSURE_UNITS), *WATCH):
        (vendor / unit).write_text(rendered[unit])
        (vendor / unit).chmod(0o644)
    profiles = root / "etc" / "apparmor.d"
    profiles.mkdir(parents=True)
    for name in REQUIRED_ENFORCED_PROFILES:
        (profiles / name).write_bytes((PROFILE_DIR / name).read_bytes())
        (profiles / name).chmod(0o644)
    for path in [root, *root.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)
    monkeypatch.setattr(unit_files, "_ROOT", root)
    monkeypatch.setattr(unit_files, "_OWNER", os.getuid())
    return root


def _measured():
    return dict(zip(("unit_files", "watch_unit_files", "apparmor_profiles"),
                    measure_exposure_section_inputs()))


def test_the_section_digests_exactly_what_is_placed(root):
    measured = _measured()
    rendered = dict(packaged_unit_files())
    assert measured["unit_files"] == {u: rendered[u].encode() for u in EXPOSURE_UNITS}
    assert measured["watch_unit_files"] == {u: rendered[u].encode() for u in WATCH}
    assert measured["apparmor_profiles"] == {
        n: (PROFILE_DIR / n).read_bytes() for n in REQUIRED_ENFORCED_PROFILES}
    section = build_exposure_section(**measured, scope_file=SCOPE)
    assert tuple(sorted(section)) == EXPOSURE_SECTION_KEYS
    assert section["unit_files"] == {u: _sha(rendered[u].encode())
                                     for u in sorted(EXPOSURE_UNITS)}
    assert section["watch_unit_files"] == {u: _sha(rendered[u].encode()) for u in WATCH}
    assert section["apparmor_profiles"] == {
        n: _sha((PROFILE_DIR / n).read_bytes()) for n in REQUIRED_ENFORCED_PROFILES}
    assert section["scope_digest"] == parse_scope_file(SCOPE).scope_digest == _sha(SCOPE)
    verify_exposure_section(section, **measured, scope_file=SCOPE)


def test_the_watch_check_returns_the_bytes_it_compared(root):
    rendered = dict(packaged_unit_files())
    assert unit_files.require_watch_unit_files() == {u: rendered[u].encode() for u in WATCH}


@pytest.mark.parametrize("key, name, label", [
    ("unit_files", "azazel-decoyd.service", "exposure unit file digest differs"),
    ("watch_unit_files", "azazel-decoy-trip.target", "watch unit file digest differs"),
    ("apparmor_profiles", "azazel-decoy-nsd", "AppArmor profile file digest differs"),
])
def test_each_changed_file_is_refused_with_its_label(root, key, name, label):
    measured = _measured()
    section = build_exposure_section(**measured, scope_file=SCOPE)
    changed = {k: dict(v) for k, v in measured.items()}
    changed[key][name] = changed[key][name] + b"#\n"
    with pytest.raises(GenerationRefused, match=label):
        verify_exposure_section(section, **changed, scope_file=SCOPE)


def test_another_scope_is_refused(root):
    measured = _measured()
    section = build_exposure_section(**measured, scope_file=SCOPE)
    other = SCOPE.replace(b"enp3s0", b"enp4s0")
    with pytest.raises(GenerationRefused, match="exposure scope digest differs"):
        verify_exposure_section(section, **measured, scope_file=other)


@pytest.mark.parametrize("scope", [b"", b"{}\n", SCOPE.rstrip(b"\n"), SCOPE + b" ", "x"])
def test_a_refused_scope_file_builds_no_section(root, scope):
    with pytest.raises(GenerationRefused, match="scope file refused"):
        build_exposure_section(**_measured(), scope_file=scope)


@pytest.mark.parametrize("key", ["unit_files", "watch_unit_files", "apparmor_profiles"])
@pytest.mark.parametrize("change", ["missing", "extra", "empty", "text"])
def test_the_supplied_sets_must_be_exact(root, key, change):
    measured = _measured()
    files = dict(measured[key])
    first = sorted(files)[0]
    if change == "missing":
        del files[first]
    elif change == "extra":
        files["azazel-edge-core.service"] = b"x"
    elif change == "empty":
        files[first] = b""
    else:
        files[first] = files[first].decode()
    measured[key] = files
    with pytest.raises(GenerationRefused, match="must match their set exactly"):
        build_exposure_section(**measured, scope_file=SCOPE)


@pytest.mark.parametrize("mutate", [
    lambda s: s.pop("scope_digest"),
    lambda s: s.update(extra={}),
    lambda s: s.update(scope_digest="sha256:" + "A" * 64),
    lambda s: s["unit_files"].pop("azazel-decoyd.service"),
    lambda s: s["watch_unit_files"].update({"azazel-decoy-trip.target": "md5:x"}),
    lambda s: s["apparmor_profiles"].update({"x": "sha256:" + "0" * 64}),
])
def test_a_malformed_recorded_section_is_refused(root, mutate):
    measured = _measured()
    section = build_exposure_section(**measured, scope_file=SCOPE)
    mutate(section)
    with pytest.raises(GenerationRefused, match="exposure section"):
        verify_exposure_section(section, **measured, scope_file=SCOPE)


def test_an_exposure_unit_file_without_its_profile_line_is_refused(root):
    path = root / VENDOR / "azazel-decoyd.service"
    text = path.read_text()
    assert "AppArmorProfile=azazel-decoyd\n" in text
    path.write_text(text.replace("AppArmorProfile=azazel-decoyd\n", ""))
    with pytest.raises(unit_files.UnitContentRefused):
        measure_exposure_section_inputs()


def test_a_drop_in_on_an_exposure_unit_is_refused(root):
    directory = root / "etc/systemd/system/azazel-decoy-netd.service.d"
    directory.mkdir(parents=True)
    for path in (directory, directory.parent, directory.parent.parent):
        path.chmod(0o755)
    (directory / "x.conf").write_text("[Service]\n")
    with pytest.raises(unit_files.UnitOverrideRefused):
        unit_files.measure_exposure_unit_files()


def test_a_masked_watch_unit_is_refused_by_the_measurement(root):
    etc = root / "etc/systemd/system"
    etc.mkdir(parents=True)
    for path in (etc, etc.parent):
        path.chmod(0o755)
    os.symlink("/dev/null", etc / "azazel-decoy-trip.target")
    with pytest.raises(unit_files.UnitOverrideRefused):
        measure_exposure_section_inputs()


@pytest.mark.parametrize("change", ["missing", "group_writable", "link", "empty"])
def test_an_unprotected_profile_file_is_refused(root, change):
    path = root / "etc/apparmor.d/azazel-decoy-verify"
    if change == "missing":
        path.unlink()
    elif change == "group_writable":
        path.chmod(0o664)
    elif change == "link":
        target = root / "etc/apparmor.d/elsewhere"
        target.write_bytes(path.read_bytes())
        path.unlink()
        os.symlink(target, path)
    else:
        path.write_bytes(b"")
    with pytest.raises(ExposureFilesRefused, match="AppArmor profile files unavailable"):
        measure_exposure_section_inputs()


def test_the_profile_directory_is_the_installers():
    from azazel_nexus_runtime.install_platform import APPARMOR_DIRECTORY as installed

    assert APPARMOR_DIRECTORY == installed == "/etc/apparmor.d"


def test_the_current_generation_allowlist_and_grantable_set_are_unchanged():
    """The section is in no generation of this build (the schema that carries
    it is introduced in G6)."""

    assert OBSERVE_BASELINE_SCHEMA == "azazel-nexus/observe-baseline-generation/v1"
    assert not set(ACTIVATION_UNIT_ALLOWLIST) & (EXPOSURE_UNITS | set(WATCH))
    assert GRANTABLE_UNITS == frozenset({
        "azazel-decoy-netd.service", "azazel-decoy-nsd.service", "azazel-decoyd.service",
        "azazel-edge-core.service", "azazel-edge-intaked.service",
        "azazel-edge-probed.service", "azazel-incident-explaind.service",
        "azazel-knowledge-lited.service", "azazel-mio-entryd.service",
    })
    assert not GRANTABLE_UNITS & set(WATCH)
    from azazel_nexus_runtime.activation_pass import POLICY_UNIT_SCOPE

    assert not POLICY_UNIT_SCOPE & EXPOSURE_UNITS


# -- coexistence (§6.2) -----------------------------------------------------------


def test_the_firewall_units_are_the_helpers_ordering_units():
    from azazel_nexus_runtime.hardening import HOST_FIREWALL_UNITS as ordered

    assert HOST_FIREWALL_UNITS == ordered


def _unit(file_state="disabled", active_state="inactive"):
    return {"UnitFileState": file_state, "ActiveState": active_state}


@pytest.mark.parametrize("value", [None, _unit("disabled"), _unit("masked"),
                                   _unit("masked-runtime")])
def test_a_firewall_loader_off_and_inactive_or_absent_does_not_withhold(value):
    assert host_firewall_refusal({u: value for u in HOST_FIREWALL_UNITS}) is None


@pytest.mark.parametrize("unit", HOST_FIREWALL_UNITS)
@pytest.mark.parametrize("state", ["enabled", "enabled-runtime", "linked", "linked-runtime",
                                   "alias", "static", "indirect", "generated", "transient",
                                   "invalid", "bad"])
def test_any_firewall_loader_not_provably_off_withholds(unit, state):
    states = {u: _unit() for u in HOST_FIREWALL_UNITS}
    states[unit] = _unit(state)
    reason = host_firewall_refusal(states)
    assert reason is not None and reason.startswith(HOST_FIREWALL_ENABLED + ":")


@pytest.mark.parametrize("unit", HOST_FIREWALL_UNITS)
@pytest.mark.parametrize("file_state", ["disabled", "masked", "masked-runtime"])
@pytest.mark.parametrize("active_state", ["active", "reloading", "failed", "activating",
                                          "deactivating", "maintenance", "refreshing"])
def test_a_disabled_or_masked_loader_that_is_not_inactive_withholds(unit, file_state,
                                                                    active_state):
    """Review of #294 F1: a disabled unit still starts through another unit's
    `Wants=`, by hand or by D-Bus activation; a masked one may still run."""

    states = {u: _unit() for u in HOST_FIREWALL_UNITS}
    states[unit] = _unit(file_state, active_state)
    reason = host_firewall_refusal(states)
    assert reason is not None and reason.startswith(HOST_FIREWALL_ACTIVE + ":")


def test_every_state_the_bus_accepts_is_judged():
    from azazel_nexus_runtime.systemd_bus import _ACTIVE_STATES, _UNIT_FILE_STATES

    for state in _UNIT_FILE_STATES:
        reason = host_firewall_refusal({u: _unit(state) for u in HOST_FIREWALL_UNITS})
        if state in {"disabled", "masked", "masked-runtime"}:
            assert reason is None
        else:
            assert reason.startswith(HOST_FIREWALL_ENABLED + ":"), state
    for state in _ACTIVE_STATES:
        reason = host_firewall_refusal({u: _unit("disabled", state)
                                        for u in HOST_FIREWALL_UNITS})
        if state == "inactive":
            assert reason is None
        else:
            assert reason.startswith(HOST_FIREWALL_ACTIVE + ":"), state


def test_enabled_is_reported_before_active():
    states = {u: _unit() for u in HOST_FIREWALL_UNITS}
    states["nftables.service"] = _unit("enabled", "active")
    states["firewalld.service"] = _unit("disabled", "active")
    assert host_firewall_refusal(states).startswith(HOST_FIREWALL_ENABLED + ":")


_NONE = {u: None for u in HOST_FIREWALL_UNITS}


@pytest.mark.parametrize("states", [
    None, [], {}, {"nftables.service": None},
    {**_NONE, "iptables.service": None},
    {**_NONE, "firewalld.service": UNREADABLE},
    {**_NONE, "firewalld.service": exposure_withholding.UNREADABLE},
    {**_NONE, "nftables.service": "disabled"},
    {**_NONE, "nftables.service": ("disabled", "inactive")},
    {**_NONE, "nftables.service": {"UnitFileState": "disabled"}},
    {**_NONE, "nftables.service": {**_unit(), "SubState": "dead"}},
    {**_NONE, "nftables.service": _unit("Enabled")},
    {**_NONE, "nftables.service": _unit(b"enabled")},
    {**_NONE, "nftables.service": _unit(exposure_withholding.UNREADABLE)},
    {**_NONE, "nftables.service": _unit("disabled", exposure_withholding.UNREADABLE)},
    {**_NONE, "nftables.service": _unit("disabled", None)},
    {**_NONE, "nftables.service": _unit("disabled", "Inactive")},
    {**_NONE, "nftables.service": _unit(None, "inactive")},
])
def test_an_unread_or_malformed_state_withholds_as_unreadable(states):
    reason = host_firewall_refusal(states)
    assert reason is not None and reason.startswith(HOST_FIREWALL_UNREADABLE + ":")




# -- fb_tunnels_only_for_init_net (§5 item 6) -----------------------------------


def test_only_two_passes():
    assert fb_tunnels_refusal(b"2\n") is None


@pytest.mark.parametrize("value", [b"0\n", b"1\n", b"2", b"2\n\n", b" 2\n", b"02\n",
                                   None, exposure_withholding.UNREADABLE, "2\n", 2])
def test_anything_but_two_withholds(value):
    reason = fb_tunnels_refusal(value)
    assert reason is not None and reason.startswith(FB_TUNNELS_NOT_INIT_NET_ONLY + ":")


def test_the_reader_is_bounded_and_follows_no_link(tmp_path, monkeypatch):
    path = tmp_path / "fb"
    monkeypatch.setattr(exposure_withholding, "_FB_TUNNELS", str(path))
    assert read_fb_tunnels() is None
    path.write_bytes(b"2\n")
    assert read_fb_tunnels() == b"2\n"
    path.write_bytes(b"2" * 17)
    assert read_fb_tunnels() is exposure_withholding.UNREADABLE
    link = tmp_path / "link"
    path.write_bytes(b"2\n")
    os.symlink(path, link)
    monkeypatch.setattr(exposure_withholding, "_FB_TUNNELS", str(link))
    assert read_fb_tunnels() is exposure_withholding.UNREADABLE


def test_the_production_path_is_procfs():
    assert exposure_withholding._FB_TUNNELS == "/proc/sys/net/core/fb_tunnels_only_for_init_net"


# -- the LSM: loaded units and the kernel's policy (§7 "Left to G6") ---------------


def _loaded(**changes):
    loaded = {unit: {"LoadState": "loaded", "AppArmorProfile": (False, profile)}
              for unit, profile in DECOY_APPARMOR_PROFILES}
    loaded.update(changes)
    return loaded


def test_units_loaded_with_their_profiles_or_not_loaded_pass():
    assert loaded_unit_profile_refusal(_loaded()) is None
    assert loaded_unit_profile_refusal({u: None for u, _ in DECOY_APPARMOR_PROFILES}) is None
    masked = {"LoadState": "masked", "AppArmorProfile": (False, "")}
    assert loaded_unit_profile_refusal(_loaded(**{
        "azazel-decoy-nsd.service": masked, "azazel-decoy-netd.service": masked,
        "azazel-decoyd.service": masked})) is None


@pytest.mark.parametrize("unit, value", [
    ("azazel-decoyd.service", {"LoadState": "loaded", "AppArmorProfile": (False, "")}),
    ("azazel-decoyd.service", {"LoadState": "loaded", "AppArmorProfile": (True, "azazel-decoyd")}),
    ("azazel-decoyd.service", {"LoadState": "loaded", "AppArmorProfile": (False, "azazel-decoy-netd")}),
    ("azazel-decoyd.service", {"LoadState": "loaded", "AppArmorProfile": [False, "azazel-decoyd"]}),
    ("azazel-decoyd.service", {"LoadState": "loaded", "AppArmorProfile": (0, "azazel-decoyd")}),
    ("azazel-decoyd.service", {"LoadState": "not-found", "AppArmorProfile": (False, "azazel-decoyd")}),
    ("azazel-decoyd.service", {"LoadState": "loaded"}),
    ("azazel-decoyd.service", "loaded"),
    ("azazel-decoy-verify.service", {"LoadState": "masked", "AppArmorProfile": (False, "")}),
])
def test_a_unit_loaded_otherwise_withholds(unit, value):
    reason = loaded_unit_profile_refusal(_loaded(**{unit: value}))
    assert reason is not None and reason.startswith(LSM_UNIT_PROFILE_DIFFERS + ":")


@pytest.mark.parametrize("loaded", [None, {}, {u: None for u in DECEPTION_EXPOSURE_UNITS}])
def test_not_exactly_the_four_units_withholds(loaded):
    assert loaded_unit_profile_refusal(loaded).startswith(LSM_UNIT_PROFILE_DIFFERS + ":")


HASHES = {name: sha256(name.encode()).hexdigest() for name in REQUIRED_ENFORCED_PROFILES}


def _entries(**changes):
    entries = {name: (HASHES[name] + "\n").encode() for name in REQUIRED_ENFORCED_PROFILES}
    entries.update(changes)
    listed = [(name.encode() + b"\n", value) for name, value in entries.items()]
    return tuple(listed + [(b"other-profile\n", b"")])


def test_the_kernel_hashes_equal_to_the_expected_pass():
    assert policy_hash_refusal(_entries(), HASHES) is None


def test_this_build_has_no_expected_hash_and_withholds():
    """Fail closed: how the kernel's hash relates to the placed file is G6's."""

    reason = policy_hash_refusal(_entries(), None)
    assert reason.startswith(LSM_POLICY_UNVERIFIABLE + ":")


@pytest.mark.parametrize("entries", [
    None, UNREADABLE, [], "x",
    _entries(**{"azazel-decoyd": b""}),
    _entries(**{"azazel-decoyd": None}),
    _entries(**{"azazel-decoyd": UNREADABLE}),
    _entries(**{"azazel-decoyd": HASHES["azazel-decoyd"].encode()}),
    _entries(**{"azazel-decoyd": (HASHES["azazel-decoyd"].upper() + "\n").encode()}),
    tuple(e for e in _entries() if e[0] != b"azazel-decoy-verify\n"),
    _entries() + ((b"azazel-decoyd\n", (HASHES["azazel-decoyd"] + "\n").encode()),),
    _entries() + ((UNREADABLE, UNREADABLE),),
    _entries() + ((None, None),),
])
def test_an_unverifiable_kernel_policy_withholds(entries):
    reason = policy_hash_refusal(entries, HASHES)
    assert reason is not None and reason.startswith(LSM_POLICY_UNVERIFIABLE + ":")


@pytest.mark.parametrize("expected", [
    {}, {**HASHES, "azazel-decoyd": "0" * 63},
    {k: v for k, v in HASHES.items() if k != "azazel-decoyd"},
])
def test_malformed_expected_hashes_withhold(expected):
    assert policy_hash_refusal(_entries(), expected).startswith(LSM_POLICY_UNVERIFIABLE + ":")


def test_a_different_loaded_policy_withholds():
    other = ("0" * 64 + "\n").encode()
    reason = policy_hash_refusal(_entries(**{"azazel-decoy-nsd": other}), HASHES)
    assert reason.startswith(LSM_POLICY_DIFFERS + ": 1 of the 4")


def test_the_policy_reader(tmp_path, monkeypatch):
    base = tmp_path / "profiles"
    monkeypatch.setattr(decoy_apparmor, "_POLICY_PROFILES", str(base))
    assert read_policy_hashes() is None
    base.mkdir()
    for index, name in enumerate(REQUIRED_ENFORCED_PROFILES):
        entry = base / f"{name}.{index}"
        entry.mkdir()
        (entry / "name").write_bytes(name.encode() + b"\n")
        (entry / "sha256").write_bytes((HASHES[name] + "\n").encode())
    nohash = base / "other.9"
    nohash.mkdir()
    (nohash / "name").write_bytes(b"other\n")
    os.symlink(base / "other.9", base / "link.10")
    entries = read_policy_hashes()
    assert (b"other\n", None) in entries
    assert (UNREADABLE, UNREADABLE) in entries
    # A link among the entries is unreadable, which an expected hash cannot pass
    # only if it is a required name; here it is not, so the four still compare.
    assert policy_hash_refusal(tuple(e for e in entries if e[0] is not UNREADABLE),
                               HASHES) is None
    assert policy_hash_refusal(entries, HASHES).startswith(LSM_POLICY_UNVERIFIABLE)


def test_the_policy_path_is_securityfs():
    assert decoy_apparmor._POLICY_PROFILES == "/sys/kernel/security/apparmor/policy/profiles"


ENFORCED = b"".join(name.encode() + b" (enforce)\n" for name in REQUIRED_ENFORCED_PROFILES)


def test_the_lsm_judgements_in_order():
    assert exposure_lsm_withholding(b"lockdown,capability\n", ENFORCED, None, None, None
                                    ).startswith(LSM_APPARMOR_DISABLED + ":")
    lsm = b"lockdown,capability,apparmor\n"
    assert exposure_lsm_withholding(lsm, ENFORCED, {}, _entries(), HASHES
                                    ).startswith(LSM_UNIT_PROFILE_DIFFERS + ":")
    assert exposure_lsm_withholding(lsm, ENFORCED, _loaded(), _entries(), None
                                    ).startswith(LSM_POLICY_UNVERIFIABLE + ":")
    assert exposure_lsm_withholding(lsm, ENFORCED, _loaded(), _entries(), HASHES) is None


def test_the_new_lsm_reason_codes_are_distinct_from_the_g3_ones():
    assert LSM_LOADED_REASON_CODES == ("lsm_unit_profile_differs", "lsm_policy_unverifiable",
                                       "lsm_policy_differs")
    assert not set(LSM_LOADED_REASON_CODES) & set(LSM_REASON_CODES)


# -- the governed set: exposure and enforcement (§6.2) --------------------------


ENFORCING = UnitDefinition("azazel-edge-enforced.service", UnitTier.ENFORCEMENT, "azedge",
                           "a hypothetical enforcing Edge unit")


def test_this_builds_governed_set_does_not_conflict():
    assert exposure_enforcement_conflict(CORE_UNITS) is None
    assert not any(d.tier is UnitTier.ENFORCEMENT for d in CORE_UNITS)


def test_the_exposure_tier_and_an_enforcement_unit_conflict():
    reason = exposure_enforcement_conflict((*CORE_UNITS, ENFORCING))
    assert reason.startswith(EXPOSURE_ENFORCEMENT_EXCLUSIVE + ":")


def test_an_exposure_unit_counted_by_name_also_conflicts():
    renamed = [replace(d, tier=UnitTier.SUPPORTING) if d.name == DECEPTION_EXPOSURE_UNITS[0]
               else d for d in CORE_UNITS if d.tier is UnitTier.DECEPTION_EXPOSURE]
    assert exposure_enforcement_conflict([renamed[0], ENFORCING]).startswith(
        EXPOSURE_ENFORCEMENT_EXCLUSIVE + ":")


def test_enforcement_without_the_exposure_tier_does_not_conflict():
    without = [d for d in CORE_UNITS if d.tier is not UnitTier.DECEPTION_EXPOSURE]
    assert exposure_enforcement_conflict((*without, ENFORCING)) is None


@pytest.mark.parametrize("definitions", [None, 3, ["azazel-decoyd.service"], (object(),)])
def test_anything_but_definitions_is_refused(definitions):
    assert exposure_enforcement_conflict(definitions).startswith(
        EXPOSURE_ENFORCEMENT_EXCLUSIVE + ":")


# -- not wired -------------------------------------------------------------------
#
# Two layers, on purpose (review of #294 F5). The static layer (the tests on
# imports, names and reason codes below, and `_withholding_reason`'s branch)
# says no product module can reach a part. The dynamic layer (a pass with
# every part replaced by one that fails when called) says a real pass does
# not, whatever path the static scan might miss (a `getattr`, an import made
# at run time). Either alone could pass while the other fails.
#
# When G6 wires the parts in, these tests are replaced, not loosened, and the
# importer lists that this PR widened go back to naming only real callers:
# `test_decoy_apparmor.py` (`exposure_generation.py` added) and
# `test_decoy_scope.py` (`exposure_generation.py` added).


NEW_MODULES = ("exposure_withholding", "exposure_generation", "exposure_exclusivity")
#: The only files that may name a part: where each is defined, and the new
#: modules' cross-references. The pass, the controller and the library are
#: not among them.
PART_FILES = {"activation_unit_files.py", "decoy_apparmor.py", "exposure_withholding.py",
              "exposure_generation.py", "exposure_exclusivity.py"}
NEW_NAMES = (
    "measure_exposure_unit_files", "exposure_lsm_withholding",
    "loaded_unit_profile_refusal", "policy_hash_refusal", "read_policy_hashes",
    "read_exposure_lsm_policy", "host_firewall_refusal", "fb_tunnels_refusal",
    "read_fb_tunnels", "exposure_enforcement_conflict", "build_exposure_section",
    "verify_exposure_section", "measure_exposure_section_inputs",
    "measure_apparmor_profile_files",
)


def _product_modules():
    for base in (ROOT / "src", ROOT / "runtime" / "src"):
        yield from sorted(base.rglob("*.py"))


def _imported(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            names.add((node.module or "").rsplit(".", 1)[-1])
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name.rsplit(".", 1)[-1] for alias in node.names)
    return names


def test_no_product_module_imports_the_new_parts():
    for path in _product_modules():
        assert not _imported(path) & set(NEW_MODULES), path


def test_the_new_names_appear_only_where_they_are_defined():
    for path in _product_modules():
        text = path.read_text(encoding="utf-8")
        for name in NEW_NAMES:
            if re.search(rf"\b{name}\b", text):
                assert path.name in PART_FILES, (path, name)


def test_the_new_reason_codes_appear_only_where_they_are_defined():
    codes = (LSM_LOADED_REASON_CODES + HOST_FIREWALL_REASON_CODES
             + FB_TUNNELS_REASON_CODES + (EXPOSURE_ENFORCEMENT_EXCLUSIVE,))
    for path in _product_modules():
        text = path.read_text(encoding="utf-8")
        for code in codes:
            if code in text:
                assert path.name in PART_FILES, (path, code)


def test_the_tier_is_still_withheld_unconditionally():
    from azazel_nexus import activation

    source = Path(activation.__file__).read_text(encoding="utf-8")
    method = next(node for node in ast.walk(ast.parse(source))
                  if isinstance(node, ast.FunctionDef) and node.name == "_withholding_reason")
    body = ast.get_source_segment(source, method)
    branch = body[body.index("if definition.tier is UnitTier.DECEPTION_EXPOSURE:"):
                  body.index("if definition.tier is UnitTier.EDGE_BASELINE:")]
    assert re.findall(r'return \(\s*"([a-z_]+):', branch) == [
        "exposure_tier_partial", "isolation_evidence_absent"]


def test_a_pass_with_every_part_poisoned_still_withholds_the_tier(tmp_path, monkeypatch):
    """None of the parts is called; the tier is `isolation_evidence_absent`."""

    import test_activation as ta
    from azazel_nexus import exposure_exclusivity
    from azazel_nexus.activation import (
        ARTIFACT_TRANSPORT,
        LOCAL_MODEL_PROVIDER,
        REMOTE_INFERENCE_TRANSPORT,
        EdgeBaselineState,
    )
    from azazel_nexus_runtime import exposure_generation

    calls = []

    def poisoned(name):
        def call(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"{name} was called")
        return call

    for module, names in (
        (decoy_apparmor, ("exposure_lsm_withholding", "loaded_unit_profile_refusal",
                          "policy_hash_refusal", "read_policy_hashes",
                          "read_exposure_lsm_policy", "exposure_lsm_refusal",
                          "read_exposure_lsm")),
        (exposure_withholding, ("host_firewall_refusal", "fb_tunnels_refusal",
                                "read_fb_tunnels")),
        (exposure_generation, ("build_exposure_section", "verify_exposure_section",
                               "measure_exposure_section_inputs",
                               "measure_apparmor_profile_files")),
        (unit_files, ("measure_exposure_unit_files", "require_watch_unit_files")),
        (exposure_exclusivity, ("exposure_enforcement_conflict",)),
    ):
        for name in names:
            monkeypatch.setattr(module, name, poisoned(name))

    controller, units, _, _ = ta._controller(tmp_path)
    outcome = controller.activate(
        now=ta.NOW, actor=ta.ACTOR, lease=ta._lease(),
        edge=EdgeBaselineState(True, True, True, True, True), healthy=True,
        record=ta._record(roles=(ta._confirmed_role(),)),
        wired=(ARTIFACT_TRANSPORT, LOCAL_MODEL_PROVIDER, REMOTE_INFERENCE_TRANSPORT),
    )
    assert calls == []
    for unit in DECEPTION_EXPOSURE_UNITS:
        verdict = next(v for v in outcome.verdicts if v.unit == unit)
        assert not verdict.granted
        assert verdict.reason.startswith("isolation_evidence_absent")
        assert ("unmask_and_enable", unit) not in units.calls
    assert "azazel-edge-core.service" in outcome.granted
