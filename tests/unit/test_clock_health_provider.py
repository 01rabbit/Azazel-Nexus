"""How the library learns clock health without importing the runtime (ADR-0011)."""
import socket
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from azazel_nexus import technique_knowledge as tk


@pytest.fixture(autouse=True)
def clean_provider(monkeypatch):
    """Global state must not leak between tests: start unregistered, restore after."""
    monkeypatch.setattr(tk, "_clock_health_provider", None)


def test_registration_is_once_and_callable_only():
    first = lambda contract: None  # noqa: E731
    with pytest.raises(TypeError):
        tk.set_clock_health_provider("not callable")
    assert tk._clock_health_provider is None
    tk.set_clock_health_provider(first)
    tk.set_clock_health_provider(first)
    with pytest.raises(ValueError):
        tk.set_clock_health_provider(lambda contract: None)
    assert tk._clock_health_provider is first


def _v2():
    pytest.importorskip("azazel_fabric.knowledge_context_clocklab")
    from test_handoff_clock_validity import record
    value = record()
    validity = value["validity"]
    expiry = datetime.fromisoformat(validity["effective_expires_at"].replace("Z", "+00:00"))
    # After adoption (1 s before the signed expiry), before the effective expiry.
    return value, expiry - timedelta(milliseconds=1)


def test_without_a_provider_a_v2_record_is_not_usable():
    value, inside = _v2()
    shown = tk.display_projection(value, inside.timestamp())["server_validity"]
    assert shown["usable"] is False and shown["reason"] == "clock_health_unavailable"


def test_a_registered_provider_makes_the_window_usable_and_closes_at_expiry():
    value, inside = _v2()
    tk.set_clock_health_provider(lambda contract: SimpleNamespace(check=lambda **kw: True))
    assert tk.display_projection(value, inside.timestamp())["server_validity"]["usable"] is True
    effective = datetime.fromisoformat(value["validity"]["effective_expires_at"].replace("Z", "+00:00"))
    assert tk.display_projection(value, effective.timestamp())["server_validity"] == {
        "usable": False, "reason": "expired", "as_of": effective.timestamp()}


@pytest.mark.parametrize("error", [RuntimeError, KeyError, AttributeError, OSError])
def test_an_unexpected_provider_failure_closes(error):
    value, inside = _v2()

    def provider(contract):
        raise error("boom")

    tk.set_clock_health_provider(provider)
    shown = tk.display_projection(value, inside.timestamp())["server_validity"]
    assert shown["usable"] is False and shown["reason"] == "clock_health_unavailable"


def test_build_app_registers_the_runtime_reader(tmp_path):
    from azazel_nexus_runtime import knowledge_context_config as config, ui_serve
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
        ui_serve.build_app(sock, fixture=None, login_file=tmp_path / "login")
    finally:
        sock.close()
    assert tk._clock_health_provider is config._clock_health
