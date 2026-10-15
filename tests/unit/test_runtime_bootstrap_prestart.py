"""Policy reader and real capacity algorithms with ordinary/synthetic inputs."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import os
from types import SimpleNamespace

import pytest

from azazel_nexus import bootstrap_prestart_store as store
from azazel_nexus.bootstrap_prestart_policy import BootstrapPrestartPolicy, encode_prestart_policy
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_prestart as prestart
from azazel_nexus_runtime import bootstrap_resources as resources
from azazel_nexus_runtime import bootstrap_state_capacity as capacity
from test_bootstrap_generation import _context


@pytest.fixture(params=[None, "sha256:" + "b" * 64], ids=["v3", "v4"])
def configured(tmp_path, monkeypatch, request):
    context = _context()
    policy = BootstrapPrestartPolicy(
        package_digest=context.package_digest,
        unit_closure_digest=context.unit_closure_digest,
        systemd_profile_digest="sha256:" + "a" * 64,
        min_usable_memory_mib=1024,
        min_online_logical_cpus=2,
        min_mission_available_mib=512,
        bootstrap_bytes=100,
        bootstrap_inodes=10,
        audit_bytes=200,
        audit_inodes=20,
        audit_sequence=1,
        audit_head="a" * 64,
        max_audit_bytes=10000,
        max_audit_segments=10,
        max_anchor_lifetime_ns=60_000_000_000,
        max_uncertainty_ns=2_000_000_000,
        drift_ppb=1000,
        loaded_policy_digest=request.param,
    )
    raw = encode_prestart_policy(policy)
    context = replace(context, policy_digest="sha256:" + sha256(raw).hexdigest())
    tmp_path.chmod(0o700)
    path = tmp_path / "admission.json"
    path.write_bytes(raw)
    path.chmod(0o600)

    @contextmanager
    def directory():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    reader = store._read_at
    monkeypatch.setattr(store, "_read_at", lambda fd, *, owner: reader(fd, owner=os.getuid()))
    observation = dict(schema="azazel-nexus/resource-observation/v1", admission="not-evaluated",
                       unavailable=[], measurements=dict(usable_memory_mib=1024,
                       online_logical_cpus=2, mission_available_mib=512))
    monkeypatch.setattr(resources, "assess_resources", lambda: observation)
    monkeypatch.setattr(capacity.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=1234))
    monkeypatch.setattr(capacity, "_sample", lambda *args: (1, 300, 30))
    return context, path, observation


def test_policy_pinned_capacity_uses_real_reader_and_both_checks(configured):
    context, path, _ = configured
    loaded = store.load_bootstrap_prestart_policy(expected=context)
    assert encode_prestart_policy(loaded) == path.read_bytes()
    assert prestart.check_bootstrap_capacity(expected=context) is None


@pytest.mark.parametrize("case", ["hash", "absent", "permissions", "capacity", "state"])
def test_any_prerequisite_refuses(configured, monkeypatch, case):
    context, path, observation = configured
    if case == "hash":
        context = replace(context, policy_digest="sha256:" + "0" * 64)
    elif case == "absent":
        path.unlink()
    elif case == "permissions":
        path.chmod(0o666)
    elif case == "capacity":
        observation["measurements"]["usable_memory_mib"] = 1023
    else:
        monkeypatch.setattr(capacity, "_sample", lambda *args: (1, 299, 30))
    with pytest.raises(ApprovalRefused):
        prestart.check_bootstrap_capacity(expected=context)


def test_policy_mutation_during_measurements_refuses(configured, monkeypatch):
    context, path, observation = configured

    def mutate():
        path.write_bytes(path.read_bytes() + b"\n")
        return observation

    monkeypatch.setattr(resources, "assess_resources", mutate)
    with pytest.raises(ApprovalRefused):
        prestart.check_bootstrap_capacity(expected=context)


@pytest.mark.parametrize("change_policy", [False, True])
def test_audit_continuation_uses_previous_head_and_pinned_limits(configured, monkeypatch, change_policy):
    context, path, _ = configured
    previous = prestart.AuditObservation(2, "b" * 64, 1, 100)
    successor = prestart.AuditObservation(3, "c" * 64, 1, 200)

    def inspect(**kwargs):
        assert kwargs == dict(expected_head=(2, "b" * 64), max_total_bytes=10000, max_segments=10)
        if change_policy:
            path.write_bytes(path.read_bytes() + b"\n")
        return successor

    monkeypatch.setattr(prestart, "inspect_audit_extension", inspect)
    if change_policy:
        with pytest.raises(ApprovalRefused):
            prestart.check_bootstrap_audit_extension(expected=context, previous=previous)
    else:
        assert prestart.check_bootstrap_audit_extension(expected=context, previous=previous) is successor
