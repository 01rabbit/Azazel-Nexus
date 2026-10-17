"""Synthetic tests for fixed bootstrap process-lifetime signal handling."""

from __future__ import annotations

import signal
import threading

import pytest
from azazel_nexus_runtime.bootstrap_lifetime import BootstrapProcessLifetime

_SIGNALS = (signal.SIGTERM, signal.SIGINT)


def _installed_handler(signum: signal.Signals):
    return signal.getsignal(signum)


def test_context_installs_fixed_handlers_and_restores_original_handlers():
    previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}
    lifetime = BootstrapProcessLifetime()
    try:
        with lifetime:
            handlers = {signum: _installed_handler(signum) for signum in _SIGNALS}
            assert all(callable(handler) for handler in handlers.values())
            assert handlers[signal.SIGTERM] == handlers[signal.SIGINT]
            assert lifetime.stopped() is False
        assert {signum: signal.getsignal(signum) for signum in _SIGNALS} == previous
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def test_context_restores_handlers_when_body_raises():
    previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}

    def fail_inside_context():
        with BootstrapProcessLifetime():
            raise RuntimeError("synthetic failure")

    try:
        with pytest.raises(RuntimeError, match="synthetic failure") as raised:
            fail_inside_context()
        assert str(raised.value) == "synthetic failure"
        assert {signum: signal.getsignal(signum) for signum in _SIGNALS} == previous
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@pytest.mark.parametrize("signum", _SIGNALS)
def test_captured_fixed_handler_sets_exact_bool_and_wait_wakes(signum):
    previous = {item: signal.getsignal(item) for item in _SIGNALS}
    lifetime = BootstrapProcessLifetime()
    try:
        with lifetime:
            handler = _installed_handler(signum)
            assert callable(handler)
            waiter_started = threading.Event()

            def wait_for_stop():
                waiter_started.set()
                lifetime.wait(30.0)

            worker = threading.Thread(target=wait_for_stop)
            worker.start()
            try:
                assert waiter_started.wait(1.0)
                handler(signum, None)
                worker.join(1.0)
                assert not worker.is_alive()
                assert lifetime.stopped() is True
                assert type(lifetime.stopped()) is bool
            finally:
                if worker.is_alive():
                    handler(signum, None)
                    worker.join(1.0)
    finally:
        for item, handler in previous.items():
            signal.signal(item, handler)


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1.0, True, "1"])
def test_wait_rejects_nonfinite_negative_or_non_numeric_timeout(timeout):
    previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}
    try:
        with BootstrapProcessLifetime() as lifetime, pytest.raises(ValueError):
            lifetime.wait(timeout)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def test_wait_caps_large_timeout_to_finite_bound(monkeypatch):
    previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}
    observed = []
    lifetime = BootstrapProcessLifetime()
    try:
        with lifetime:
            monkeypatch.setattr(lifetime._stopping, "wait", lambda timeout: observed.append(timeout))
            lifetime.wait(10**100)
        assert observed == [60.0]
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def test_context_rejects_non_main_thread_and_always_restores_handlers():
    previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}
    outcome = []

    def install_from_worker():
        try:
            with BootstrapProcessLifetime():
                pass
        except RuntimeError as exc:
            outcome.append(str(exc))

    worker = threading.Thread(target=install_from_worker)
    worker.start()
    worker.join(1.0)
    try:
        assert not worker.is_alive()
        assert outcome == ["signal handlers may only be managed on the main thread"]
        assert {signum: signal.getsignal(signum) for signum in _SIGNALS} == previous
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def test_callbacks_require_active_context():
    lifetime = BootstrapProcessLifetime()
    with pytest.raises(RuntimeError, match="not installed"):
        lifetime.stopped()
    with pytest.raises(RuntimeError, match="not installed"):
        lifetime.wait(0.0)


def test_lifetime_object_cannot_be_reused_with_a_stale_stop_event():
    previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}
    lifetime = BootstrapProcessLifetime()
    try:
        with lifetime:
            _installed_handler(signal.SIGTERM)(signal.SIGTERM, None)
            assert lifetime.stopped() is True
        with pytest.raises(RuntimeError, match="single-use"), lifetime:
            pass
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
