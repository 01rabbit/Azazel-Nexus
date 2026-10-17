from dataclasses import FrozenInstanceError

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from azazel_nexus_runtime.bootstrap_audit_live import (
    BootstrapLiveAuditHead,
    WriterHead,
)


def _observation(sequence=4, digest="a" * 64):
    return AuditObservation(sequence, digest, 1, 128)


class _Reader:
    def __init__(self, *values):
        self.values = iter(values)

    def observe_head(self):
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return value


def test_writer_head_is_immutable_and_distinct_from_disk_observation():
    head = WriterHead(4, "a" * 64)
    assert type(head) is not AuditObservation
    with pytest.raises(FrozenInstanceError):
        head.sequence = 5


@pytest.mark.parametrize("value", [
    (True, "a" * 64),
    (0, "a" * 64),
    (4, "A" * 64),
    (4, "a" * 63),
    [4, "a" * 64],
    (4, "a" * 64, "extra"),
])
def test_malformed_live_heads_are_redacted(value):
    adapter = BootstrapLiveAuditHead(_observation(), _Reader(value))
    with pytest.raises(ApprovalRefused) as error:
        adapter.verify_startup()
    assert str(error.value) == "bootstrap audit live head unavailable"
    assert "a" * 64 not in str(error.value)


@pytest.mark.parametrize("value", [
    (3, "a" * 64),
    (4, "b" * 64),
    (5, "a" * 64),
])
def test_startup_head_must_exactly_match_stopped_writer_observation(value):
    adapter = BootstrapLiveAuditHead(_observation(), _Reader(value))
    with pytest.raises(ApprovalRefused, match="startup head differs"):
        adapter.verify_startup()


def test_startup_match_then_monotonic_advance_is_accepted():
    adapter = BootstrapLiveAuditHead(
        _observation(), _Reader((4, "a" * 64), (4, "a" * 64), (7, "c" * 64))
    )
    assert adapter.verify_startup() == WriterHead(4, "a" * 64)
    assert adapter.observe() == WriterHead(4, "a" * 64)
    assert adapter.observe() == WriterHead(7, "c" * 64)


@pytest.mark.parametrize("later", [
    (3, "a" * 64),
    (4, "b" * 64),
])
def test_stale_or_same_sequence_inconsistent_later_head_is_refused(later):
    adapter = BootstrapLiveAuditHead(
        _observation(), _Reader((4, "a" * 64), later)
    )
    adapter.verify_startup()
    with pytest.raises(ApprovalRefused) as error:
        adapter.observe()
    assert str(error.value) == "bootstrap audit live head is stale or inconsistent"
    assert "a" * 64 not in str(error.value)


def test_live_read_before_startup_is_refused_without_calling_reader():
    adapter = BootstrapLiveAuditHead(_observation(), _Reader())
    with pytest.raises(ApprovalRefused, match="startup head not verified"):
        adapter.observe()


def test_startup_can_only_be_verified_once():
    adapter = BootstrapLiveAuditHead(
        _observation(), _Reader((4, "a" * 64), (4, "a" * 64))
    )
    adapter.verify_startup()
    with pytest.raises(ApprovalRefused, match="startup head already observed"):
        adapter.verify_startup()


def test_reader_failure_is_redacted():
    adapter = BootstrapLiveAuditHead(
        _observation(), _Reader(RuntimeError("sensitive socket detail"))
    )
    with pytest.raises(ApprovalRefused) as error:
        adapter.verify_startup()
    assert str(error.value) == "bootstrap audit live head unavailable"
    assert "sensitive" not in str(error.value)


def test_invalid_stopped_observation_type_is_refused():
    with pytest.raises(ApprovalRefused):
        BootstrapLiveAuditHead(object(), _Reader())
