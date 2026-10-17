"""Protected clock source reads use ordinary private temporary files only."""

from contextlib import contextmanager
from dataclasses import replace
import json
import os

import pytest

from azazel_nexus import bootstrap_clock_store as store
from azazel_nexus.bootstrap_clock import (
    AdministratorTimeAnchor,
    decode_administrator_anchor,
    encode_administrator_anchor,
)
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_generation import _context
from test_bootstrap_prestart_policy import policy as make_policy

NS = 1_000_000_000
START = 5 * NS


@pytest.fixture
def source(tmp_path, monkeypatch):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    path = root / "time.json"
    context = _context()
    anchor = AdministratorTimeAnchor(
        node_digest=context.node_digest,
        policy_digest=context.policy_digest,
        boot_id=context.boot_id,
        earliest_utc="2026-10-13T12:00:00Z",
        latest_utc="2026-10-13T12:00:10Z",
        boottime_ns=START,
        expires_boottime_ns=20 * NS,
    )
    raw = encode_administrator_anchor(anchor)
    path.write_bytes(raw)
    path.chmod(0o600)
    clock_policy = make_policy(max_anchor_lifetime_ns=20 * NS,
                               max_uncertainty_ns=20 * NS, drift_ppb=0)

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    read_at = store._read_at
    monkeypatch.setattr(store, "_read_at", lambda fd, *, owner: read_at(fd, owner=os.getuid()))
    monkeypatch.setattr(store, "load_bootstrap_prestart_policy", lambda *, expected: clock_policy)
    monkeypatch.setattr(store, "read_boot_id", lambda: context.boot_id)
    monkeypatch.setattr(store, "read_boottime_ns", lambda: START + NS)
    return context, anchor, raw, clock_policy, root, path


def test_anchor_encoding_is_exact_canonical_schema_and_roundtrips(source):
    _context_value, anchor, raw, _policy, _root, _path = source

    assert raw == json.dumps({
        "schema": "azazel-nexus/administrator-clock-anchor/v1",
        "source": "administrator-confirmed",
        "node_digest": anchor.node_digest,
        "policy_digest": anchor.policy_digest,
        "boot_id": anchor.boot_id,
        "earliest_utc": anchor.earliest_utc,
        "latest_utc": anchor.latest_utc,
        "boottime_ns": anchor.boottime_ns,
        "expires_boottime_ns": anchor.expires_boottime_ns,
    }, sort_keys=True, separators=(",", ":")).encode()
    assert decode_administrator_anchor(raw) == anchor
    assert encode_administrator_anchor(decode_administrator_anchor(raw)) == raw


def test_load_returns_window_from_pinned_anchor_and_explicit_policy(source, monkeypatch):
    context, anchor, _raw, clock_policy, _root, _path = source
    calls = []
    original = store.load_bootstrap_prestart_policy

    def load_policy(*, expected):
        calls.append(expected)
        return original(expected=expected)

    monkeypatch.setattr(store, "load_bootstrap_prestart_policy", load_policy)
    result = store.load_administrator_time_window(expected=context)

    assert result.node_digest == anchor.node_digest
    assert result.policy_digest == anchor.policy_digest
    assert result.boot_id == anchor.boot_id
    assert result.observed_boottime_ns == START + NS
    assert result.observed_boottime_ns < result.valid_until_boottime_ns
    assert result.valid_until_boottime_ns <= anchor.expires_boottime_ns
    assert len(calls) == 2
    assert clock_policy.clock_limits().drift_ppb == 0


@pytest.mark.parametrize("case", ["absent", "unsafe-mode", "malformed", "wrong-source"])
def test_missing_unsafe_or_malformed_clock_record_refuses_without_fallback(source, case):
    context, _anchor, _raw, _policy, _root, path = source
    if case == "absent":
        path.unlink()
    elif case == "unsafe-mode":
        path.chmod(0o640)
    elif case == "malformed":
        path.write_bytes(b"{")
    else:
        document = json.loads(path.read_bytes())
        document["source"] = "system-clock"
        path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
        path.chmod(0o600)

    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)


def test_initial_wrong_boot_and_boot_change_during_projection_refuse(source, monkeypatch):
    context, _anchor, _raw, _policy, _root, _path = source
    monkeypatch.setattr(store, "read_boot_id", lambda: "33333333-3333-4333-8333-333333333333")
    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)

    boots = iter((context.boot_id, "33333333-3333-4333-8333-333333333333"))
    monkeypatch.setattr(store, "read_boot_id", lambda: next(boots))
    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)


@pytest.mark.parametrize("final_offset", [0, -1])
def test_expired_or_backward_final_boottime_refuses(source, monkeypatch, final_offset):
    context, anchor, _raw, _policy, _root, _path = source
    observed = anchor.expires_boottime_ns - 1 if final_offset == 0 else START + NS
    final = anchor.expires_boottime_ns if final_offset == 0 else observed - 1
    ticks = iter((observed, final))
    monkeypatch.setattr(store, "read_boottime_ns", lambda: next(ticks))

    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)


def test_record_change_during_projection_refuses(source, monkeypatch):
    context, _anchor, raw, _policy, _root, path = source
    projector = store.project_administrator_window

    def mutate_record(*args, **kwargs):
        result = projector(*args, **kwargs)
        path.write_bytes(raw + b"\n")
        path.chmod(0o600)
        return result

    monkeypatch.setattr(store, "project_administrator_window", mutate_record)

    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)


def test_policy_change_during_projection_refuses(source, monkeypatch):
    context, _anchor, _raw, clock_policy, _root, _path = source
    calls = []

    def changed_policy(*, expected):
        calls.append(expected)
        if len(calls) == 1:
            return clock_policy
        return replace(clock_policy, max_uncertainty_ns=clock_policy.max_uncertainty_ns + 1)

    monkeypatch.setattr(store, "load_bootstrap_prestart_policy", changed_policy)

    with pytest.raises(ApprovalRefused):
        store.load_administrator_time_window(expected=context)
    assert len(calls) == 2
