"""Protected activation policy reader (#206 P2): temporary regular files only."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os

import pytest

from azazel_nexus import activation_store
from azazel_nexus import activation_policy
from azazel_nexus.activation_policy import (
    ACTIVATION_UNIT_ALLOWLIST,
    MAX_LEASE_SECONDS_CAP,
    ActivationPolicy,
    decode_activation_policy,
    encode_activation_policy,
    load_activation_policy,
)
from azazel_nexus.operator_trust import ApprovalRefused

SUPPORTING = [
    "azazel-edge-intaked.service", "azazel-edge-probed.service",
    "azazel-incident-explaind.service", "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
]


def _document(**changes) -> dict:
    document = {
        "schema": "azazel-nexus/activation-policy/v1",
        "operators": ["operator-a", "operator-b"],
        "max_lease_seconds": 86400,
        "units": SUPPORTING,
        "state_floors": {"audit_bytes": 1 << 20, "audit_inodes": 64,
                         "bootstrap_bytes": 1 << 20, "bootstrap_inodes": 64},
        "resource_floors": {"min_mission_available_mib": 256, "min_online_logical_cpus": 2,
                            "min_usable_memory_mib": 1024},
        "max_clock_skew_seconds": 120,
    }
    document.update(changes)
    return document


def _raw(document=None) -> bytes:
    return json.dumps(document or _document(), sort_keys=True, separators=(",", ":")).encode()


def test_canonical_policy_decodes_with_digest_over_exact_bytes():
    raw = _raw()
    policy = decode_activation_policy(raw)
    assert policy.operators == ("operator-a", "operator-b")
    assert policy.units == tuple(SUPPORTING)
    assert policy.max_lease_seconds == 86400
    assert policy.max_clock_skew_seconds == 120
    assert policy.state_floor_values()["audit_inodes"] == 64
    assert policy.resource_floor_values()["min_online_logical_cpus"] == 2
    assert policy.policy_digest == "sha256:" + sha256(raw).hexdigest()
    assert encode_activation_policy(policy) == raw


def test_allowlist_is_code_fixed_to_the_loop_units():
    # The model-free reference service (proposed 2026-10-28, §6.2) is the one
    # addition: it runs no model, so it is none of the excluded hosts.
    # The loop's audit writer (2026-10-30, ADR 0007) is the second; the
    # bootstrap helper pair stays outside.
    assert ACTIVATION_UNIT_ALLOWLIST == tuple(sorted(
        SUPPORTING + ["azazel-edge-core.service", "azazel-mio-referenced.service",
                      "azazel-auditd-loop.service"]))
    assert "azazel-mio-locald.service" not in ACTIVATION_UNIT_ALLOWLIST
    assert not {"azazel-auditd.service", "azazel-commissiond.service"} & set(
        ACTIVATION_UNIT_ALLOWLIST)
    # #196 P1: the Deception Lite exposure units are grantable for the #253
    # checks but no policy may name them, so no lease ever holds one.
    from azazel_nexus.activation import DECEPTION_EXPOSURE_UNITS
    assert not set(DECEPTION_EXPOSURE_UNITS) & set(ACTIVATION_UNIT_ALLOWLIST)
    for unit in DECEPTION_EXPOSURE_UNITS:
        with pytest.raises(ApprovalRefused):
            decode_activation_policy(_raw(_document(units=sorted(SUPPORTING + [unit]))))
    full = decode_activation_policy(_raw(_document(units=list(ACTIVATION_UNIT_ALLOWLIST))))
    assert full.units == ACTIVATION_UNIT_ALLOWLIST


def test_lease_cap_is_72_hours_in_code():
    assert MAX_LEASE_SECONDS_CAP == 259200
    assert decode_activation_policy(_raw(_document(max_lease_seconds=259200))).max_lease_seconds == 259200
    with pytest.raises(ApprovalRefused):
        decode_activation_policy(_raw(_document(max_lease_seconds=259201)))


@pytest.mark.parametrize("unit", [
    "azazel-auditd.service", "azazel-commissiond.service", "azazel-watchdog.service",
    "azazel-model-fetchd.service", "azazel-mio-locald.service", "azazel-mio-remoted.service",
    "azazel-activated.service", "azazel-edge-intaked", "sshd.service",
])
def test_unit_outside_allowlist_refuses_the_whole_policy(unit):
    with pytest.raises(ApprovalRefused) as error:
        decode_activation_policy(_raw(_document(units=sorted(SUPPORTING + [unit]))))
    assert str(error.value) == "activation policy refused"


@pytest.mark.parametrize("changes", [
    {"schema": "azazel-nexus/activation-policy/v2"},
    {"extra": True},
    {"operators": []},
    {"operators": ["operator-b", "operator-a"]},
    {"operators": ["operator-a", "operator-a"]},
    {"operators": ["Operator-A"]},
    {"operators": "operator-a"},
    {"units": []},
    {"units": list(reversed(SUPPORTING))},
    {"units": SUPPORTING + [SUPPORTING[0]]},
    {"max_lease_seconds": 0},
    {"max_lease_seconds": -1},
    {"max_lease_seconds": True},
    {"max_lease_seconds": "3600"},
    {"max_lease_seconds": 3600.0},
    {"max_clock_skew_seconds": -1},
    {"max_clock_skew_seconds": 301},
    {"max_clock_skew_seconds": False},
    {"state_floors": {"audit_bytes": 1, "audit_inodes": 1, "bootstrap_bytes": 1}},
    {"state_floors": {"audit_bytes": 1, "audit_inodes": 1, "bootstrap_bytes": 1,
                      "bootstrap_inodes": 0}},
    {"state_floors": {"audit_bytes": 1, "audit_inodes": 1, "bootstrap_bytes": 1,
                      "bootstrap_inodes": 1, "extra": 1}},
    {"resource_floors": {"min_mission_available_mib": 1, "min_online_logical_cpus": True,
                         "min_usable_memory_mib": 1}},
    {"resource_floors": None},
])
def test_closed_shape_refusals(changes):
    with pytest.raises(ApprovalRefused):
        decode_activation_policy(_raw(_document(**changes)))


@pytest.mark.parametrize("field", sorted(_document()))
def test_every_field_is_required(field):
    document = _document()
    document.pop(field)
    with pytest.raises(ApprovalRefused):
        decode_activation_policy(_raw(document))


@pytest.mark.parametrize("raw", [
    json.dumps(_document(), sort_keys=True, indent=2).encode(),
    json.dumps(_document(), separators=(",", ":")).encode(),
    _raw() + b"\n",
    _raw().replace(b'"max_clock_skew_seconds":120', b'"max_clock_skew_seconds":120,"max_clock_skew_seconds":120'),
    b"",
    b"\xff",
    b"[]",
    b" " * 9000,
])
def test_noncanonical_duplicate_or_malformed_bytes_refused(raw):
    with pytest.raises(ApprovalRefused):
        decode_activation_policy(raw)


# -- require_clock_synchronized (#251 M-1) ------------------------------------

#: A policy as written before the field existed, byte for byte.
_PRE_FIELD = (
    b'{"max_clock_skew_seconds":120,"max_lease_seconds":86400,'
    b'"operators":["operator-a","operator-b"],"resource_floors":'
    b'{"min_mission_available_mib":256,"min_online_logical_cpus":2,'
    b'"min_usable_memory_mib":1024},"schema":"azazel-nexus/activation-policy/v1",'
    b'"state_floors":{"audit_bytes":1048576,"audit_inodes":64,'
    b'"bootstrap_bytes":1048576,"bootstrap_inodes":64},"units":['
    + b",".join(b'"' + unit.encode() + b'"' for unit in SUPPORTING) + b"]}"
)


def test_a_policy_without_the_field_keeps_its_bytes_and_digest():
    assert _raw() == _PRE_FIELD
    policy = decode_activation_policy(_PRE_FIELD)
    assert policy.require_clock_synchronized is None
    assert policy.clock_synchronization_required is False
    assert encode_activation_policy(policy) == _PRE_FIELD
    assert policy.policy_digest == "sha256:" + sha256(_PRE_FIELD).hexdigest()
    assert b"require_clock_synchronized" not in encode_activation_policy(policy)


@pytest.mark.parametrize("value", [True, False])
def test_explicit_field_round_trips_canonically(value):
    raw = _raw(_document(require_clock_synchronized=value))
    expected = b'"require_clock_synchronized":' + (b"true" if value else b"false")
    assert expected in raw
    # Sorted keys: after "operators", before "resource_floors".
    assert raw.index(b'"operators"') < raw.index(expected) < raw.index(b'"resource_floors"')
    policy = decode_activation_policy(raw)
    assert policy.require_clock_synchronized is value
    assert policy.clock_synchronization_required is value
    assert encode_activation_policy(policy) == raw
    assert policy.policy_digest == "sha256:" + sha256(raw).hexdigest()


def test_the_three_forms_are_three_different_policies():
    digests = {decode_activation_policy(raw).policy_digest for raw in (
        _raw(), _raw(_document(require_clock_synchronized=False)),
        _raw(_document(require_clock_synchronized=True)))}
    assert len(digests) == 3


@pytest.mark.parametrize("value", [None, 1, 0, "true", "false", [], {}])
def test_non_boolean_field_refused(value):
    with pytest.raises(ApprovalRefused):
        decode_activation_policy(_raw(_document(require_clock_synchronized=value)))


@pytest.mark.parametrize("raw", [
    _raw()[:-1] + b',"require_clock_synchronized":true}',  # unsorted
    _raw(_document(require_clock_synchronized=True)).replace(
        b'"require_clock_synchronized":true',
        b'"require_clock_synchronized":true,"require_clock_synchronized":true'),
    _raw(_document(require_clock_synchronized=True)).replace(
        b'"require_clock_synchronized":true', b'"require_clock_synchronized": true'),
    _raw(_document(require_clock_synchronized=True)).replace(
        b'"require_clock_synchronized"', b'"require_clock_synchronised"'),
])
def test_noncanonical_duplicate_or_misspelled_field_refused(raw):
    with pytest.raises(ApprovalRefused):
        decode_activation_policy(raw)


def test_directly_constructed_policy_refuses_a_non_boolean_field():
    policy = decode_activation_policy(_raw(_document(require_clock_synchronized=True)))
    with pytest.raises(ApprovalRefused):
        ActivationPolicy(**{**policy.__dict__, "require_clock_synchronized": 1})
    # Dropping the field changes the bytes, so the carried digest no longer matches.
    with pytest.raises(ApprovalRefused):
        ActivationPolicy(**{**policy.__dict__, "require_clock_synchronized": None})


def test_directly_constructed_policy_must_carry_its_own_digest():
    policy = decode_activation_policy(_raw())
    with pytest.raises(ApprovalRefused):
        ActivationPolicy(**{**policy.__dict__, "policy_digest": "sha256:" + "0" * 64})


# -- protected reader --------------------------------------------------------


@pytest.fixture
def store(tmp_path, monkeypatch):
    directory = tmp_path / "activation"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    policy = directory / "policy.json"
    policy.write_bytes(_raw())
    policy.chmod(0o600)
    opened = []

    @contextmanager
    def directory_reader():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        opened.append(os.fstat(fd).st_ino)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(activation_policy, "_approval_directory", directory_reader)
    read_at = activation_policy._read_at
    monkeypatch.setattr(
        activation_policy, "_read_at",
        lambda fd, *, owner: read_at(fd, owner=os.getuid() if owner == 0 else owner),
    )
    return directory, policy, opened


def test_public_reader_returns_the_decoded_policy(store):
    _, _, opened = store
    policy = load_activation_policy()
    assert policy == decode_activation_policy(_raw())
    assert len(opened) == 2


def _read(directory, owner=None):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return activation_policy._read_at(fd, owner=os.getuid() if owner is None else owner)
    finally:
        os.close(fd)


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o604, 0o660, 0o400 | 0o020])
def test_permissions_wider_than_owner_only_refused(store, mode):
    directory, policy, _ = store
    policy.chmod(mode)
    with pytest.raises(ApprovalRefused):
        _read(directory)
    with pytest.raises(ApprovalRefused) as error:
        load_activation_policy()
    assert str(error.value) == "protected activation policy refused"


def test_directory_open_to_others_refused(store):
    directory, _, _ = store
    directory.chmod(0o750)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_wrong_owner_refused(store):
    directory, _, _ = store
    with pytest.raises(ApprovalRefused):
        _read(directory, owner=os.getuid() + 1)


def test_symlinked_policy_refused(store, tmp_path):
    directory, policy, _ = store
    target = tmp_path / "elsewhere.json"
    target.write_bytes(_raw())
    target.chmod(0o600)
    policy.unlink()
    policy.symlink_to(target)
    with pytest.raises(OSError):
        _read(directory)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_hard_linked_policy_refused(store, tmp_path):
    directory, policy, _ = store
    os.link(policy, tmp_path / "second-name")
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


@pytest.mark.parametrize("content", [b"", b"x" * 8193])
def test_empty_or_oversized_policy_refused(store, content):
    _, policy, _ = store
    policy.write_bytes(content)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_missing_policy_or_directory_entry_of_wrong_type_refused(store):
    _, policy, _ = store
    policy.unlink()
    with pytest.raises(ApprovalRefused):
        load_activation_policy()
    policy.mkdir(mode=0o700)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_policy_rewritten_during_a_read_refused(store, monkeypatch, private_os):
    private_os(activation_store)
    _, policy, _ = store
    original = os.read

    def rewriting(fd, size):
        data = original(fd, size)
        if data:
            with open(policy, "ab") as stream:
                stream.write(b" ")
        return data

    monkeypatch.setattr(activation_store.os, "read", rewriting)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_policy_replaced_between_the_two_reads_refused(store, monkeypatch):
    _, policy, _ = store
    original = activation_policy._read_at
    calls = 0

    def replacing(fd, *, owner):
        nonlocal calls
        result = original(fd, owner=owner)
        calls += 1
        if calls == 1:
            replacement = policy.with_name("replacement")
            replacement.write_bytes(_raw(_document(max_lease_seconds=3600)))
            replacement.chmod(0o600)
            os.replace(replacement, policy)
        return result

    monkeypatch.setattr(activation_policy, "_read_at", replacing)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_directory_swapped_between_the_two_reads_refused(store, tmp_path, monkeypatch):
    directory, _, _ = store
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    (other / "policy.json").write_bytes(_raw())
    (other / "policy.json").chmod(0o600)
    sequence = iter([directory, other])

    @contextmanager
    def swapping():
        fd = os.open(next(sequence), os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(activation_policy, "_approval_directory", swapping)
    with pytest.raises(ApprovalRefused):
        load_activation_policy()


def test_reader_has_no_path_or_owner_override():
    import inspect

    assert list(inspect.signature(load_activation_policy).parameters) == []
