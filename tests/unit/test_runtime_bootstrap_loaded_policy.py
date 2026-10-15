"""Protected loaded-unit policy decoding and stable input reads."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_prestart_policy import BootstrapPrestartPolicy
from azazel_nexus.bootstrap_prestart_policy import encode_prestart_policy
from azazel_nexus import bootstrap_prestart_store, bootstrap_store
from azazel_nexus.activation_store import _read_file_at
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_loaded_policy as loaded
from azazel_nexus_runtime.bootstrap_loaded import _DEPENDENCIES
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey
from test_bootstrap_generation import _context

PROFILE_DIGEST = "sha256:" + "a" * 64
LOADED_DIGEST = "sha256:" + "b" * 64
SETTINGS = {
    "TimeoutStartUSec": 1,
    "TimeoutStopUSec": 2,
    "RuntimeMaxUSec": 3,
    "WatchdogUSec": 4,
    "SetLoginEnvironment": False,
}


def _prestart(*, loaded_digest=LOADED_DIGEST, profile_digest=PROFILE_DIGEST):
    return BootstrapPrestartPolicy(
        package_digest="sha256:" + "c" * 64,
        unit_closure_digest="sha256:" + "d" * 64,
        systemd_profile_digest=profile_digest,
        min_usable_memory_mib=4096,
        min_online_logical_cpus=4,
        min_mission_available_mib=2048,
        bootstrap_bytes=1000,
        bootstrap_inodes=100,
        audit_bytes=2000,
        audit_inodes=200,
        audit_sequence=1,
        audit_head="e" * 64,
        max_audit_bytes=10_000,
        max_audit_segments=10,
        max_anchor_lifetime_ns=60_000_000_000,
        max_uncertainty_ns=2_000_000_000,
        drift_ppb=100,
        loaded_policy_digest=loaded_digest,
    )


def _document():
    controller = "azazel-activated.service"
    audit = UNIT_NAMES[UnitKey.AUDITD]
    commission = UNIT_NAMES[UnitKey.COMMISSIOND]
    edges = {
        UnitKey.AUDITD: {
            "After": [controller], "Before": [commission],
            "Requires": [controller], "RequiredBy": [commission],
            "BindsTo": [controller], "BoundBy": [commission],
        },
        UnitKey.COMMISSIOND: {
            "After": sorted([controller, audit]),
            "Requires": sorted([controller, audit]),
            "BindsTo": sorted([controller, audit]),
        },
    }
    units = {}
    for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
        dependencies = {key: edges[unit].get(key, []) for key in _DEPENDENCIES}
        units[UNIT_NAMES[unit]] = {
            "dependencies": dependencies,
            "service_settings": dict(SETTINGS),
        }
    return {
        "schema": "azazel-nexus/loaded-bootstrap-units/v1",
        "systemd_profile_digest": PROFILE_DIGEST,
        "units": units,
    }


def _raw(document=None):
    return json.dumps(
        _document() if document is None else document,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _pinned(raw, *, profile_digest=PROFILE_DIGEST):
    return replace(
        _prestart(loaded_digest="sha256:" + sha256(raw).hexdigest()),
        systemd_profile_digest=profile_digest,
    )


def test_decode_returns_immutable_tuple_storage_and_fresh_public_mappings():
    raw = _raw()
    result = loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))

    assert result.digest == "sha256:" + sha256(raw).hexdigest()
    assert set(result.units) == {UnitKey.AUDITD, UnitKey.COMMISSIOND}
    unit = result.units[UnitKey.COMMISSIOND]
    assert isinstance(unit._dependencies, tuple)
    dependencies = unit.dependencies
    dependencies["After"] = frozenset()
    assert UNIT_NAMES[UnitKey.AUDITD] in unit.dependencies["After"]
    settings = unit.service_settings
    settings.clear()
    assert unit.service_settings == SETTINGS


def test_explicit_os_mount_profile_pin_and_timer_policy_is_accepted():
    document = _document()
    document["systemd_profile_digest"] = "sha256:" + "9" * 64
    for record in document["units"].values():
        for key in ("After", "Requires", "Wants"):
            record["dependencies"][key] = sorted(
                record["dependencies"][key] + ["var.mount"]
            )
    raw = _raw(document)
    result = loaded.decode_loaded_bootstrap_policy(
        raw, prestart_policy=_pinned(raw, profile_digest=document["systemd_profile_digest"])
    )

    # These are explicit expectations, not proof of mount topology/hardening.
    assert result.systemd_profile_digest == document["systemd_profile_digest"]
    assert all(entry.service_settings == SETTINGS for entry in result.units.values())
    for entry in result.units.values():
        assert "var.mount" in entry.dependencies["After"]
        assert "var.mount" in entry.dependencies["Requires"]
        assert "var.mount" in entry.dependencies["Wants"]


@pytest.mark.parametrize("edge", ["Requires", "Wants"])
def test_positive_dependency_without_after_ordering_is_rejected(edge):
    document = _document()
    dependencies = document["units"][UNIT_NAMES[UnitKey.AUDITD]]["dependencies"]
    dependencies[edge] = sorted(set(dependencies[edge]) | {"basic.target"})
    raw = _raw(document)

    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


def test_ordered_external_positive_dependencies_and_conflicts_are_accepted():
    document = _document()
    dependencies = document["units"][UNIT_NAMES[UnitKey.AUDITD]]["dependencies"]
    dependencies["After"] = sorted(set(dependencies["After"]) | {"basic.target"})
    dependencies["Requires"] = sorted(set(dependencies["Requires"]) | {"basic.target"})
    dependencies["Wants"] = ["local-fs.target"]
    dependencies["After"] = sorted(set(dependencies["After"]) | {"local-fs.target"})
    dependencies["Conflicts"] = ["maintenance.target"]
    raw = _raw(document)

    result = loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))

    expected = result.units[UnitKey.AUDITD].dependencies
    assert "basic.target" in expected["After"] & expected["Requires"]
    assert "local-fs.target" in expected["After"] & expected["Wants"]
    assert expected["Conflicts"] == frozenset({"maintenance.target"})


@pytest.mark.parametrize("mutation", ["digest", "profile"])
def test_digest_and_systemd_profile_pins_must_match(mutation):
    raw = _raw()
    if mutation == "digest":
        pin = _prestart(loaded_digest="sha256:" + "0" * 64)
    else:
        pin = _prestart(
            loaded_digest="sha256:" + sha256(raw).hexdigest(),
            profile_digest="sha256:" + "f" * 64,
        )
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=pin)


@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
@pytest.mark.parametrize("field,ceiling", [
    ("TimeoutStartUSec", 30_000_000), ("TimeoutStopUSec", 10_000_000),
])
@pytest.mark.parametrize("invalid", [0, 2**64 - 1, "above-ceiling", True])
def test_pinning_does_not_admit_unbounded_start_stop(unit, field, ceiling, invalid):
    document = _document()
    document["units"][UNIT_NAMES[unit]]["service_settings"][field] = (
        ceiling + 1 if invalid == "above-ceiling" else invalid
    )
    raw = _raw(document)
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


def test_start_stop_ceiling_is_accepted_with_independent_pin():
    document = _document()
    for record in document["units"].values():
        record["service_settings"].update(
            TimeoutStartUSec=30_000_000, TimeoutStopUSec=10_000_000,
        )
    raw = _raw(document)
    result = loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))
    assert all(item.service_settings["TimeoutStopUSec"] == 10_000_000
               for item in result.units.values())


def test_v3_prestart_policy_without_loaded_digest_is_refused():
    raw = _raw()
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(
            raw, prestart_policy=_prestart(loaded_digest=None)
        )


@pytest.mark.parametrize("mutation", ["extra_unit", "missing_inverse", "extra_service_keys"])
def test_policy_rejects_widened_or_incomplete_expectations(mutation):
    document = _document()
    if mutation == "extra_unit":
        document["units"]["azazel-other.service"] = next(iter(document["units"].values()))
    elif mutation == "missing_inverse":
        audit = document["units"][UNIT_NAMES[UnitKey.AUDITD]]["dependencies"]
        audit["BoundBy"] = []
    else:
        service = document["units"][UNIT_NAMES[UnitKey.AUDITD]]["service_settings"]
        service.update({
            "ProtectSystem": "strict", "RootDirectory": "/", "MountAPIVFS": True,
            "TimeoutSomethingElseUSec": 7,
        })
    raw = _raw(document)
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


@pytest.mark.parametrize("document", [None, [], {"schema": "wrong"}])
def test_malformed_and_noncanonical_policy_refuses(document):
    raw = b"{" + b" " * loaded._LIMIT
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_prestart())
    if document is not None:
        raw = json.dumps(document).encode()
        with pytest.raises(ApprovalRefused):
            loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


def test_missing_nexus_inverse_is_refused():
    document = _document()
    commission = document["units"][UNIT_NAMES[UnitKey.COMMISSIOND]]["dependencies"]
    commission["Requires"] = ["azazel-activated.service"]
    raw = _raw(document)
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


@pytest.mark.parametrize("bad_names", [
    ["azazel-activated.service", "azazel-activated.service"],
    ["azazel-commissiond.service", "azazel-activated.service"],
])
def test_duplicate_or_unsorted_dependency_names_refuse(bad_names):
    document = _document()
    audit = document["units"][UNIT_NAMES[UnitKey.AUDITD]]["dependencies"]
    audit["After"] = bad_names
    raw = _raw(document)

    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


@pytest.mark.parametrize("key", [
    "Upholds", "UpheldBy", "OnFailure", "OnSuccess", "OnFailureOf",
    "OnSuccessOf", "Triggers", "TriggeredBy",
])
@pytest.mark.parametrize("unit", [UnitKey.AUDITD, UnitKey.COMMISSIOND])
def test_independently_pinned_activation_channel_is_not_authorized(key, unit):
    document = _document()
    document["units"][UNIT_NAMES[unit]]["dependencies"][key] = ["external.service"]
    raw = _raw(document)
    # A matching protected outer pin does not legitimize this semantic effect.
    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


def test_extra_nexus_dependency_edge_refuses():
    document = _document()
    audit = document["units"][UNIT_NAMES[UnitKey.AUDITD]]["dependencies"]
    audit["Wants"] = ["azazel-unreviewed.service"]
    audit["After"] = sorted([*audit["After"], "azazel-unreviewed.service"])
    raw = _raw(document)

    with pytest.raises(ApprovalRefused):
        loaded.decode_loaded_bootstrap_policy(raw, prestart_policy=_pinned(raw))


@pytest.mark.parametrize("change", ["file", "directory", "prestart"])
def test_protected_loader_rechecks_file_identity_bytes_and_prestart(change, monkeypatch):
    raw = _raw()
    prestart = _pinned(raw)
    calls = {"directory": 0, "read": 0, "policy": 0}

    @contextmanager
    def directory():
        calls["directory"] += 1
        yield calls["directory"]

    def fstat(fd):
        inode = 1 if change != "directory" or fd == 1 else 2
        return SimpleNamespace(st_dev=10, st_ino=inode)

    def read_at(_fd, name, *, owner, limit):
        assert name == "loaded-units.json" and owner == 0 and limit == loaded._LIMIT
        calls["read"] += 1
        return raw if change != "file" or calls["read"] == 1 else raw + b" "

    def read_prestart(*, expected):
        calls["policy"] += 1
        return prestart if change != "prestart" or calls["policy"] == 1 else replace(
            prestart, audit_sequence=2
        )

    monkeypatch.setattr(bootstrap_store, "_bootstrap_directory", directory)
    monkeypatch.setattr(bootstrap_store, "_read_file_at", read_at)
    monkeypatch.setattr(bootstrap_store.os, "fstat", fstat)
    monkeypatch.setattr(loaded, "load_bootstrap_prestart_policy", read_prestart)
    with pytest.raises(ApprovalRefused):
        loaded.load_loaded_bootstrap_policy(expected=object())
    assert calls["directory"] == 2
    assert calls["read"] == (1 if change == "directory" else 2)
    assert calls["policy"] == (2 if change == "prestart" else 1)


def test_protected_loader_succeeds_with_real_file_reader_and_prestart_store(
    tmp_path, monkeypatch
):
    raw_loaded = _raw()
    context = _context()
    prestart = BootstrapPrestartPolicy(
        package_digest=context.package_digest,
        unit_closure_digest=context.unit_closure_digest,
        systemd_profile_digest=PROFILE_DIGEST,
        min_usable_memory_mib=4096,
        min_online_logical_cpus=4,
        min_mission_available_mib=2048,
        bootstrap_bytes=1000,
        bootstrap_inodes=100,
        audit_bytes=2000,
        audit_inodes=200,
        audit_sequence=1,
        audit_head="e" * 64,
        max_audit_bytes=10_000,
        max_audit_segments=10,
        max_anchor_lifetime_ns=60_000_000_000,
        max_uncertainty_ns=2_000_000_000,
        drift_ppb=100,
        loaded_policy_digest="sha256:" + sha256(raw_loaded).hexdigest(),
    )
    raw_prestart = encode_prestart_policy(prestart)
    expected = replace(context, policy_digest="sha256:" + sha256(raw_prestart).hexdigest())
    tmp_path.chmod(0o700)
    for name, raw in (("admission.json", raw_prestart), ("loaded-units.json", raw_loaded)):
        path = tmp_path / name
        path.write_bytes(raw)
        path.chmod(0o600)

    @contextmanager
    def directory():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(bootstrap_store, "_bootstrap_directory", directory)
    monkeypatch.setattr(bootstrap_prestart_store, "_bootstrap_directory", directory)

    def user_owned_read(fd, name, *, owner, limit):
        return _read_file_at(fd, name, owner=os.getuid(), limit=limit)

    def user_owned_prestart_read(fd, *, owner):
        return _read_file_at(fd, "admission.json", owner=os.getuid(), limit=8192)

    monkeypatch.setattr(bootstrap_store, "_read_file_at", user_owned_read)
    monkeypatch.setattr(bootstrap_prestart_store, "_read_at", user_owned_prestart_read)

    result = loaded.load_loaded_bootstrap_policy(expected=expected)

    assert result.digest == prestart.loaded_policy_digest
    assert set(result.units) == {UnitKey.AUDITD, UnitKey.COMMISSIOND}
