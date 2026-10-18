"""Listener scheduling and registry isolation without real socket binds."""
from pathlib import Path

from azazel_nexus_runtime import serve


def test_busy_listeners_rotate_and_use_separate_registries(monkeypatch):
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class Listener:
        def settimeout(self, timeout):
            pass

        def accept(self):
            return Connection(), None

        def close(self):
            pass

    listeners = [Listener(), Listener()]
    remaining = iter(listeners)
    monkeypatch.setattr(serve, "bind_socket", lambda *a, **kw: next(remaining))
    monkeypatch.setattr(serve.select, "select", lambda *a: (listeners, [], []))
    served = []
    class Engine:
        def __init__(self, *, registry, **kw):
            self.registry = registry

        def serve_connection(self, connection, handler):
            served.append(self.registry)

    monkeypatch.setattr(serve, "SocketServer", Engine)
    assert serve.serve_forever(
        path=Path('/nonexistent/operator.sock'), registry='operator', policy=None,
        audit=lambda event: None, handler=lambda request: None,
        additional_sockets=((Path('/nonexistent/read.sock'), 123, 'lookup'),),
        stop=lambda: len(served) == 6) == 0
    assert served == ['operator', 'lookup'] * 3
