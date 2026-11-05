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

And that the schema, allowlist and grantable set are unchanged. That none of
them is reached (no product file imports or names them, the tier is still
withheld as `isolation_evidence_absent`) is `test_g6_unwired.py`.
"""

from __future__ import annotations

from dataclasses import replace
import errno
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
    EXPOSURE_ENFORCEMENT_UNREADABLE,
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
    EXPOSURE_SECTION_DIFFERS,
    EXPOSURE_SECTION_KEYS,
    EXPOSURE_SECTION_PHRASES,
    EXPOSURE_SECTION_UNVERIFIABLE,
    ExposureFilesRefused,
    build_exposure_section,
    expected_policy_hashes,
    measure_exposure_section_inputs,
    verify_exposure_section,
)
from azazel_nexus_runtime.exposure_withholding import (
    FB_TUNNELS_NOT_INIT_NET_ONLY,
    FB_TUNNELS_UNREADABLE,
    HOST_FIREWALL_ACTIVE,
    HOST_FIREWALL_ENABLED,
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
#: The policy hashes an installer would record (G6: the SHA-256 of its
#: `apparmor_parser -Q -o` output); here, any 64 lowercase hex digits.
RECORDED = {name: sha256(b"compiled " + name.encode()).hexdigest()
            for name in REQUIRED_ENFORCED_PROFILES}
UNVERIFIABLE = re.escape(
    f"{EXPOSURE_SECTION_UNVERIFIABLE}: "
    f"{EXPOSURE_SECTION_PHRASES[EXPOSURE_SECTION_UNVERIFIABLE]}") + r"\Z"
DIFFERS = re.escape(
    f"{EXPOSURE_SECTION_DIFFERS}: {EXPOSURE_SECTION_PHRASES[EXPOSURE_SECTION_DIFFERS]}") + r"\Z"


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
    section = build_exposure_section(**measured, apparmor_policy_hashes=RECORDED,
                                     scope_file=SCOPE)
    assert tuple(sorted(section)) == EXPOSURE_SECTION_KEYS
    assert section["unit_files"] == {u: _sha(rendered[u].encode())
                                     for u in sorted(EXPOSURE_UNITS)}
    assert section["watch_unit_files"] == {u: _sha(rendered[u].encode()) for u in WATCH}
    assert section["apparmor_profiles"] == {
        n: _sha((PROFILE_DIR / n).read_bytes()) for n in REQUIRED_ENFORCED_PROFILES}
    assert section["scope_digest"] == parse_scope_file(SCOPE).scope_digest == _sha(SCOPE)
    assert section["apparmor_policy_hashes"] == RECORDED
    verify_exposure_section(section, **measured, scope_file=SCOPE)


def test_the_watch_check_returns_the_bytes_it_compared(root):
    rendered = dict(packaged_unit_files())
    assert unit_files.require_watch_unit_files() == {u: rendered[u].encode() for u in WATCH}


@pytest.mark.parametrize("key, name", [
    ("unit_files", "azazel-decoyd.service"),
    ("watch_unit_files", "azazel-decoy-trip.target"),
    ("apparmor_profiles", "azazel-decoy-nsd"),
])
def test_each_changed_file_is_refused_as_differs(root, key, name):
    measured = _measured()
    section = build_exposure_section(**measured, apparmor_policy_hashes=RECORDED,
                                     scope_file=SCOPE)
    changed = {k: dict(v) for k, v in measured.items()}
    changed[key][name] = changed[key][name] + b"#\n"
    with pytest.raises(GenerationRefused, match=DIFFERS):
        verify_exposure_section(section, **changed, scope_file=SCOPE)


def test_another_scope_is_refused(root):
    measured = _measured()
    section = build_exposure_section(**measured, apparmor_policy_hashes=RECORDED,
                                     scope_file=SCOPE)
    other = SCOPE.replace(b"enp3s0", b"enp4s0")
    with pytest.raises(GenerationRefused, match=DIFFERS):
        verify_exposure_section(section, **measured, scope_file=other)


@pytest.mark.parametrize("scope", [b"", b"{}\n", SCOPE.rstrip(b"\n"), SCOPE + b" ", "x"])
def test_a_refused_scope_file_builds_no_section(root, scope):
    with pytest.raises(GenerationRefused, match=UNVERIFIABLE):
        build_exposure_section(**_measured(), apparmor_policy_hashes=RECORDED,
                               scope_file=scope)


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
    with pytest.raises(GenerationRefused, match=UNVERIFIABLE):
        build_exposure_section(**measured, apparmor_policy_hashes=RECORDED, scope_file=SCOPE)


@pytest.mark.parametrize("mutate", [
    lambda s: s.pop("scope_digest"),
    lambda s: s.update(extra={}),
    lambda s: s.update(scope_digest="sha256:" + "A" * 64),
    lambda s: s["unit_files"].pop("azazel-decoyd.service"),
    lambda s: s["watch_unit_files"].update({"azazel-decoy-trip.target": "md5:x"}),
    lambda s: s["apparmor_profiles"].update({"x": "sha256:" + "0" * 64}),
    lambda s: s.pop("apparmor_policy_hashes"),
    lambda s: s["apparmor_policy_hashes"].pop("azazel-decoyd"),
    lambda s: s["apparmor_policy_hashes"].update({"x": "0" * 64}),
    lambda s: s["apparmor_policy_hashes"].update({"azazel-decoyd": "0" * 63}),
    lambda s: s["apparmor_policy_hashes"].update({"azazel-decoyd": "A" * 64}),
    lambda s: s["apparmor_policy_hashes"].update({"azazel-decoyd": "sha256:" + "0" * 64}),
    lambda s: s["apparmor_policy_hashes"].update({"azazel-decoyd": "0" * 64 + "\n"}),
    lambda s: s.update(apparmor_policy_hashes=list(RECORDED.items())),
])
def test_a_malformed_recorded_section_is_refused(root, mutate):
    measured = _measured()
    section = build_exposure_section(**measured, apparmor_policy_hashes=RECORDED,
                                     scope_file=SCOPE)
    mutate(section)
    with pytest.raises(GenerationRefused, match=UNVERIFIABLE):
        verify_exposure_section(section, **measured, scope_file=SCOPE)
    with pytest.raises(GenerationRefused, match=UNVERIFIABLE):
        expected_policy_hashes(section)


def test_an_exposure_unit_file_without_its_profile_line_is_refused(root):
    path = root / VENDOR / "azazel-decoyd.service"
    text = path.read_text()
    assert "AppArmorProfile=azazel-decoyd\n" in text
    path.write_text(text.replace("AppArmorProfile=azazel-decoyd\n", ""))
    with pytest.raises(unit_files.UnitContentRefused, match=UNVERIFIABLE) as caught:
        measure_exposure_section_inputs()
    # The reader's own label stays on the chained cause.
    assert type(caught.value.__cause__) is unit_files.UnitContentRefused


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
    with pytest.raises(unit_files.UnitOverrideRefused, match=UNVERIFIABLE):
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
    with pytest.raises(ExposureFilesRefused, match=UNVERIFIABLE):
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
        "azazel-auditd-loop.service",
        "azazel-decoy-netd.service", "azazel-decoy-nsd.service", "azazel-decoyd.service",
        "azazel-edge-core.service", "azazel-edge-intaked.service",
        "azazel-edge-probed.service", "azazel-incident-explaind.service",
        # The optional Knowledge egress is grantable only through the same
        # explicit, signed activation policy; its installer preset stays off.
        "azazel-knowledge-contextd.service",
        "azazel-knowledge-lited.service", "azazel-mio-entryd.service",
        "azazel-mio-referenced.service",
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


@pytest.mark.parametrize("value", [b"0\n", b"1\n", b"2", b"2\n\n", b" 2\n", b"02\n", b""])
def test_anything_but_two_withholds(value):
    reason = fb_tunnels_refusal(value)
    assert reason is not None and reason.startswith(FB_TUNNELS_NOT_INIT_NET_ONLY + ":")


@pytest.mark.parametrize("value", [None, exposure_withholding.UNREADABLE, "2\n", 2])
def test_a_sysctl_absent_or_not_read_withholds_as_unreadable(value):
    """Review of #196 G6 preparation (M1): not read is its own code, not
    "not 2"."""

    assert fb_tunnels_refusal(value).startswith(FB_TUNNELS_UNREADABLE + ":")


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
    assert reason.startswith(LSM_POLICY_DIFFERS + ":")
    assert not re.search(r"\d", reason.split(":", 1)[1])


NO_HASH = LSM_POLICY_UNVERIFIABLE + ":"


def _linked_policy(tmp_path, monkeypatch, target=None, hashes=HASHES, raw_sha256=True):
    """The VM's layout: `raw_sha256 -> ../../raw_data/<n>/sha256` in each entry.

    `target(n)` replaces the link's text; `hashes` None places no raw data;
    `raw_sha256` False places no `raw_sha256` at all. `name` and `sha256` are
    regular files, `sha256` holding another value, as on the VM.
    """

    policy = tmp_path / "policy"
    base, raw_data = policy / "profiles", policy / "raw_data"
    monkeypatch.setattr(decoy_apparmor, "_POLICY_PROFILES", str(base))
    monkeypatch.setattr(decoy_apparmor, "_POLICY_RAW_DATA", str(raw_data))
    base.mkdir(parents=True)
    raw_data.mkdir()
    for index, name in enumerate(REQUIRED_ENFORCED_PROFILES):
        number = 120 + index
        entry = base / f"{name}.{number}"
        entry.mkdir()
        (entry / "name").write_bytes(name.encode() + b"\n")
        (entry / "sha256").write_bytes(b"f" * 64 + b"\n")
        if hashes is not None:
            (raw_data / str(number)).mkdir()
            (raw_data / str(number) / "sha256").write_bytes((hashes[name] + "\n").encode())
        if raw_sha256:
            link = target(number) if target else f"../../raw_data/{number}/sha256"
            os.symlink(link, entry / "raw_sha256")
    return base, raw_data


def _hashes():
    return [hash for _, hash in read_policy_hashes()]


def test_the_policy_reader(tmp_path, monkeypatch):
    monkeypatch.setattr(decoy_apparmor, "_POLICY_PROFILES", str(tmp_path / "none"))
    assert read_policy_hashes() is None
    base, _ = _linked_policy(tmp_path, monkeypatch)
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


def test_a_raw_sha256_link_of_the_kernels_form_is_read_through_raw_data(tmp_path,
                                                                        monkeypatch):
    _linked_policy(tmp_path, monkeypatch)
    entries = read_policy_hashes()
    assert sorted(hash for _, hash in entries) == sorted(
        (value + "\n").encode() for value in HASHES.values())
    assert policy_hash_refusal(entries, HASHES) is None


def test_the_reader_compares_raw_sha256_not_sha256(tmp_path, monkeypatch):
    # The VM's entry holds both; `raw_sha256` is the compiled policy's digest,
    # `sha256` another value. Only `raw_sha256` is read: a `sha256` equal to
    # the expected hash does not pass a `raw_sha256` that differs.
    base, _ = _linked_policy(tmp_path, monkeypatch, hashes={
        name: "0" * 64 for name in REQUIRED_ENFORCED_PROFILES})
    for index, name in enumerate(REQUIRED_ENFORCED_PROFILES):
        (base / f"{name}.{120 + index}" / "sha256").write_bytes(
            (HASHES[name] + "\n").encode())
    assert policy_hash_refusal(read_policy_hashes(), HASHES).startswith(
        LSM_POLICY_DIFFERS + ":")


def test_sha256_without_raw_sha256_withholds(tmp_path, monkeypatch):
    base, _ = _linked_policy(tmp_path, monkeypatch, raw_sha256=False)
    for index, name in enumerate(REQUIRED_ENFORCED_PROFILES):
        (base / f"{name}.{120 + index}" / "sha256").write_bytes(
            (HASHES[name] + "\n").encode())
    entries = read_policy_hashes()
    assert all(hash is None for _, hash in entries)
    assert policy_hash_refusal(entries, HASHES).startswith(NO_HASH)


#: Targets that, followed, reach the very file the kernel's form names
#: (`raw_data/<n>/sha256`, which holds the expected hash): only the check of
#: the form refuses them.
_REACHING = [
    lambda tmp, n: str(tmp / "policy" / "raw_data" / str(n) / "sha256"),
    lambda tmp, n: f"../../raw_data/./{n}/sha256",
    lambda tmp, n: f"../../raw_data/{n}/../{n}/sha256",
    lambda tmp, n: f"../../../policy/raw_data/{n}/sha256",
    lambda tmp, n: f"../../raw_data//{n}/sha256",
    lambda tmp, n: f"../.././raw_data/{n}/sha256",
]


@pytest.mark.parametrize("target", _REACHING)
def test_a_link_reaching_the_right_hash_by_another_form_withholds(tmp_path, monkeypatch,
                                                                  target):
    base, _ = _linked_policy(tmp_path, monkeypatch, lambda n: target(tmp_path, n))
    # Followed, each link would give the expected hash ...
    for index, name in enumerate(REQUIRED_ENFORCED_PROFILES):
        assert (base / f"{name}.{120 + index}" / "raw_sha256").read_bytes() == (
            HASHES[name] + "\n").encode()
    # ... and the reader refuses every one for its form.
    entries = read_policy_hashes()
    assert all(hash is UNREADABLE for _, hash in entries)
    assert policy_hash_refusal(entries, HASHES).startswith(NO_HASH)


@pytest.mark.parametrize("target", [
    lambda n: "../../../etc/x",
    lambda n: "../../raw_data/x/sha256",
    lambda n: "../../raw_data//sha256",
    lambda n: f"../../raw_data/0{n}/sha256",
    lambda n: f"../../raw_data/{n}/sha256/",
    lambda n: f"../../raw_data/{n}/raw_data",
    lambda n: f"../raw_data/{n}/sha256",
    lambda n: f"../../raw_data/-{n}/sha256",
    lambda n: "../../raw_data/" + "1" * 21 + "/sha256",
])
def test_a_raw_sha256_link_of_any_other_form_withholds(tmp_path, monkeypatch, target):
    # Forms that do not reach the hash at all: refused for the form, before
    # anything is opened.
    _linked_policy(tmp_path, monkeypatch, target)
    entries = read_policy_hashes()
    assert all(hash is UNREADABLE for _, hash in entries)
    assert policy_hash_refusal(entries, HASHES).startswith(NO_HASH)


def test_a_raw_sha256_link_whose_target_is_absent_withholds(tmp_path, monkeypatch):
    _linked_policy(tmp_path, monkeypatch, hashes=None)
    entries = read_policy_hashes()
    assert all(hash is None for _, hash in entries)
    assert policy_hash_refusal(entries, HASHES).startswith(NO_HASH)


def test_a_raw_sha256_regular_file_withholds(tmp_path, monkeypatch):
    # Only the observed form, a link, is accepted.
    base, _ = _linked_policy(tmp_path, monkeypatch, raw_sha256=False)
    for index, name in enumerate(REQUIRED_ENFORCED_PROFILES):
        (base / f"{name}.{120 + index}" / "raw_sha256").write_bytes(
            (HASHES[name] + "\n").encode())
    assert _hashes() == [UNREADABLE] * 4
    assert policy_hash_refusal(read_policy_hashes(), HASHES).startswith(NO_HASH)


def test_a_raw_data_directory_that_is_a_link_withholds(tmp_path, monkeypatch):
    _, raw_data = _linked_policy(tmp_path, monkeypatch)
    moved = tmp_path / "moved"
    os.rename(raw_data, moved)
    os.symlink(moved, raw_data)
    assert _hashes() == [UNREADABLE] * 4


def test_a_raw_data_entry_that_is_a_link_or_a_file_withholds(tmp_path, monkeypatch):
    _, raw_data = _linked_policy(tmp_path, monkeypatch)
    moved = tmp_path / "elsewhere"
    os.rename(raw_data / "120", moved)
    os.symlink(moved, raw_data / "120")
    (raw_data / "121" / "sha256").unlink()
    os.symlink(moved / "sha256", raw_data / "121" / "sha256")
    (raw_data / "122" / "sha256").unlink()
    (raw_data / "122").rmdir()
    (raw_data / "122").write_bytes((HASHES[REQUIRED_ENFORCED_PROFILES[2]] + "\n").encode())
    assert _hashes().count(UNREADABLE) == 3


@pytest.mark.parametrize("content", [
    b"", b"\n", b"A" * 64 + b"\n", b"0" * 63 + b"\n", b"0" * 64, b"0" * 64 + b"\n\n",
    b"0" * 300,
])
def test_a_malformed_or_oversized_target_hash_withholds(tmp_path, monkeypatch, content):
    _, raw_data = _linked_policy(tmp_path, monkeypatch)
    (raw_data / "120" / "sha256").write_bytes(content)
    assert policy_hash_refusal(read_policy_hashes(), HASHES).startswith(NO_HASH)
    if len(content) > decoy_apparmor._POLICY_HASH_LIMIT:
        assert UNREADABLE in _hashes()


@pytest.mark.parametrize("code", [errno.EACCES, errno.EPERM, errno.EIO, errno.ELOOP])
def test_a_readlink_error_other_than_einval_withholds(tmp_path, monkeypatch, code, private_os):
    private_os(decoy_apparmor)
    _linked_policy(tmp_path, monkeypatch)

    def refuse(*args, **kwargs):
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(decoy_apparmor.os, "readlink", refuse)
    assert _hashes() == [UNREADABLE] * 4
    assert policy_hash_refusal(read_policy_hashes(), HASHES).startswith(NO_HASH)


def test_the_policy_path_is_securityfs():
    assert decoy_apparmor._POLICY_PROFILES == "/sys/kernel/security/apparmor/policy/profiles"
    # The directory the kernel's `../../raw_data` names from a profile's entry.
    assert decoy_apparmor._POLICY_RAW_DATA == os.path.normpath(
        decoy_apparmor._POLICY_PROFILES + "/x/../../raw_data")


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


def _section_recording(hashes):
    files = {
        "unit_files": {u: b"[Unit]\n" + u.encode() for u in EXPOSURE_UNITS},
        "watch_unit_files": {u: b"[Unit]\n" + u.encode() for u in WATCH},
        "apparmor_profiles": {n: b"profile " + n.encode() for n in REQUIRED_ENFORCED_PROFILES},
    }
    return files, build_exposure_section(**files, apparmor_policy_hashes=hashes,
                                         scope_file=SCOPE)


def test_the_section_records_the_expected_policy_hashes_for_the_lsm_judgement():
    """Review of #196 G6 preparation (M2): the kernel's expected hashes are a
    field of the exposure section, in the form `exposure_lsm_withholding`
    takes as `expected`. Nothing derives or records one in this build."""

    files, section = _section_recording(HASHES)
    assert section["apparmor_policy_hashes"] == HASHES
    assert list(section["apparmor_policy_hashes"]) == sorted(REQUIRED_ENFORCED_PROFILES)
    expected = expected_policy_hashes(section)
    assert expected == HASHES and type(expected) is dict
    expected["azazel-decoyd"] = "f" * 64
    assert section["apparmor_policy_hashes"] == HASHES  # a copy
    lsm = b"lockdown,capability,apparmor\n"
    assert exposure_lsm_withholding(lsm, ENFORCED, _loaded(), _entries(),
                                    expected_policy_hashes(section)) is None
    other = ("0" * 64 + "\n").encode()
    assert exposure_lsm_withholding(
        lsm, ENFORCED, _loaded(), _entries(**{"azazel-decoyd": other}),
        expected_policy_hashes(section)).startswith(LSM_POLICY_DIFFERS + ":")
    # The record is not a measurement of the files: verify checks its form
    # only, so another record of the same files verifies. **Today only the
    # form is checked; G6 changes this** (finding 3 of the review of #303):
    # the record is trusted because the generation digest, and through it
    # the signed approval, covers the whole section.
    _, recorded_other = _section_recording(RECORDED)
    verify_exposure_section(recorded_other, **files, scope_file=SCOPE)
    # Each accepted hash is one `policy_hash_refusal` accepts, and no other.
    from azazel_nexus_runtime import exposure_generation

    assert ([bool(exposure_generation._POLICY_HASH.match(p)) for p in _HASH_PROBES]
            == [decoy_apparmor._hex_digest(p) for p in _HASH_PROBES]
            == [True, True] + [False] * 6)


_HASH_PROBES = ["0" * 64, "a" * 64, "A" * 64, "0" * 63, "0" * 65, "g" * 64,
                "0" * 64 + "\n", " " + "0" * 63]


@pytest.mark.parametrize("hashes", [
    None, {}, list(HASHES.items()),
    {k: v for k, v in HASHES.items() if k != "azazel-decoyd"},
    {**HASHES, "other": "0" * 64},
    {**HASHES, "azazel-decoyd": "0" * 63},
    {**HASHES, "azazel-decoyd": "A" * 64},
    {**HASHES, "azazel-decoyd": "sha256:" + "0" * 64},
    {**HASHES, "azazel-decoyd": ("0" * 64).encode()},
])
def test_a_policy_hash_record_of_another_form_builds_no_section(hashes):
    with pytest.raises(GenerationRefused, match=UNVERIFIABLE):
        _section_recording(hashes)


def test_the_new_lsm_reason_codes_are_distinct_from_the_g3_ones():
    assert LSM_LOADED_REASON_CODES == ("lsm_profile_child_present",
                                       "lsm_unit_profile_differs", "lsm_policy_unverifiable",
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
def test_anything_but_definitions_is_refused_as_unreadable(definitions):
    assert exposure_enforcement_conflict(definitions).startswith(
        EXPOSURE_ENFORCEMENT_UNREADABLE + ":")


# -- not wired -------------------------------------------------------------------
#
# That no product file imports or names the parts, the reason codes included,
# that `_withholding_reason` still withholds the tier as
# `isolation_evidence_absent`, and that a pass with every part replaced by one
# that fails when called reaches none of them, are `test_g6_unwired.py`
# (#196 L1): one table for every G6 part, one scan of every tracked file. G6
# edits that table; the importer list of `test_decoy_scope.py`
# (`exposure_generation.py` added by preparation C) goes back to naming only
# real callers then.
