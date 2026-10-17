"""Kernel guard orchestration uses a fake backend, never a timer or signal."""

from dataclasses import replace
import gc
from importlib.machinery import SourceFileLoader
from types import ModuleType

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_kernel_deadline as module
from azazel_nexus_runtime.bootstrap_lifetime import BootstrapProcessLifetime
from test_runtime_bootstrap import evidence as original_evidence


@pytest.fixture
def evidence(request):
    return original_evidence.__wrapped__(request)


class Backend:
    def __init__(self):
        self.calls = []
        self.handle = object()
        self.check_error = None

    def arm(self, ns):
        self.calls.append(("arm", ns))
        return self.handle

    def check(self, handle):
        assert handle is self.handle
        self.calls.append(("check",))
        if self.check_error:
            raise self.check_error

    def release(self, handle):
        assert handle is self.handle
        self.calls.append(("release",))


@pytest.fixture
def backend(monkeypatch):
    value = Backend()
    monkeypatch.setattr(module, "_load_backend", lambda: value)
    return value


def test_binds_retained_absolute_deadline_once_and_checks_each_refresh(evidence, backend):
    deadline, _generation = evidence
    guard = module.BootstrapKernelDeadline()
    assert guard(deadline) is None
    assert guard(replace(deadline, last_boottime_ns=deadline.last_boottime_ns + 1)) is None
    assert backend.calls == [("arm", deadline.deadline_boottime_ns), ("check",), ("check",)]
    assert guard.release_after_stop() is None
    assert guard.release_after_stop() is None
    assert backend.calls[-1] == ("release",)
    assert backend.calls.count(("release",)) == 1
    with pytest.raises(ApprovalRefused):
        guard(deadline)


def test_changed_deadline_refuses_without_rearming(evidence, backend):
    deadline, _generation = evidence
    guard = module.BootstrapKernelDeadline()
    guard(deadline)
    with pytest.raises(ApprovalRefused):
        guard(replace(deadline, deadline_boottime_ns=deadline.deadline_boottime_ns + 1))
    assert [call[0] for call in backend.calls] == ["arm", "check"]
    # Only the supervisor's confirmed-stop path may now release it.
    guard.release_after_stop()
    assert backend.calls[-1] == ("release",)


def test_failed_native_check_never_retries_or_cancels_implicitly(evidence, backend):
    deadline, _generation = evidence
    guard = module.BootstrapKernelDeadline()
    guard(deadline)
    backend.check_error = OSError("private native detail")
    with pytest.raises(ApprovalRefused) as error:
        guard(deadline)
    assert "private" not in str(error.value)
    before = list(backend.calls)
    with pytest.raises(ApprovalRefused):
        guard(deadline)
    assert backend.calls == before
    assert ("release",) not in backend.calls


def test_missing_native_backend_fails_closed_and_release_is_unconfirmed(evidence, monkeypatch):
    deadline, _generation = evidence
    calls = []

    def missing():
        calls.append(True)
        raise ImportError("private interpreter layout")

    monkeypatch.setattr(module, "_load_backend", missing)
    guard = module.BootstrapKernelDeadline()
    for _ in range(2):
        with pytest.raises(ApprovalRefused, match="bootstrap kernel deadline refused"):
            guard(deadline)
    assert calls == [True]
    with pytest.raises(ApprovalRefused, match="release refused"):
        guard.release_after_stop()


def test_default_loader_rejects_a_python_backend_stub(monkeypatch):
    import azazel_nexus_runtime

    stub = ModuleType("azazel_nexus_runtime._bootstrap_deadline")
    stub.__loader__ = SourceFileLoader(stub.__name__, "synthetic.py")
    monkeypatch.setattr(azazel_nexus_runtime, "_bootstrap_deadline", stub, raising=False)
    with pytest.raises(ImportError, match="compiled Linux deadline backend required"):
        module._load_backend()


def test_gc_does_not_disarm_an_active_guard(evidence, backend):
    deadline, _generation = evidence
    guard = module.BootstrapKernelDeadline()
    guard(deadline)
    del guard
    gc.collect()
    assert ("release",) not in backend.calls


def test_process_lifetime_context_exit_does_not_disarm(evidence, backend):
    deadline, _generation = evidence
    with BootstrapProcessLifetime() as lifetime:
        lifetime.deadline_guard(deadline)
    assert ("release",) not in backend.calls


def test_changed_process_cannot_check_or_release(evidence, backend, monkeypatch):
    deadline, _generation = evidence
    guard = module.BootstrapKernelDeadline()
    guard(deadline)
    before = list(backend.calls)
    monkeypatch.setattr(module.os, "getpid", lambda: guard._owner + 1)
    with pytest.raises(ApprovalRefused):
        guard(deadline)
    with pytest.raises(ApprovalRefused):
        guard.release_after_stop()
    assert backend.calls == before


@pytest.mark.parametrize("ns", [True, 0, -1, 1 << 63])
def test_invalid_native_integer_bound_refuses_before_arm(evidence, backend, ns):
    deadline, _generation = evidence
    guard = module.BootstrapKernelDeadline()
    with pytest.raises(ApprovalRefused):
        guard(replace(deadline, deadline_boottime_ns=ns))
    assert backend.calls == []
