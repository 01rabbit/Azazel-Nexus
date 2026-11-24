"""#467: the success paths with real peers (the entry daemon and the reference daemon over sockets).

The acceptance test in `test_w467_audit_unavailable.py` stubs the peers of the
entry daemon, and the reference daemon there has no playbook. Here both are the
real ones with a verified, activated playbook pack (as in
`test_mio_reference_socket.py`), so what is refused or kept is a real reference.
"""

from __future__ import annotations

import errno
import json
import os
import socket
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_playbooks
from azazel_nexus_runtime import mio_referenced as referenced
from azazel_nexus_runtime import runtime_paths, transport
from azazel_nexus_runtime.transport import read_frame, send_frame
from azazel_nexus.audit import AuditLedger
from azazel_nexus.route_ledger import RouteChain

from test_mio_reference_socket import FRAME, Daemon, root  # noqa: F401 - the fixture
from test_playbook_selection import activate

pytest_plugins = ["test_mission_pack", "test_playbook_selection"]


@pytest.fixture(autouse=True)
def peer_credentials(monkeypatch):
    # SO_PEERCRED exists on Linux only; the rest of the transport is the real one.
    monkeypatch.setattr(transport, "peer_credentials",
                        lambda connection: (os.getppid(), os.getuid(), os.getgid()))
    monkeypatch.setattr(transport, "peer_supplementary_groups", lambda connection: ())
    from azazel_nexus_runtime import mio_socket_client
    monkeypatch.setattr(mio_socket_client, "peer_credentials",
                        lambda connection: (os.getppid(), os.getuid(), os.getgid()))


@pytest.fixture(autouse=True)
def own_group(root):  # noqa: F811
    # Where a new directory takes its parent's group (macOS), the sockets would
    # carry a group that is not the process's; give the tree the process's group.
    for directory, _, _ in os.walk(root):
        os.chown(directory, -1, os.getgid())


def ask(frame=FRAME):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(8)
        connection.connect(str(runtime_paths.socket_path("mio-entry")))
        send_frame(connection, {"verb": "mio.advise", "arguments": {"deadline_ms": 2000},
                                "event": frame})
        connection.shutdown(socket.SHUT_WR)
        return json.loads(read_frame(connection))


def fail_fsync(monkeypatch, directory, suffix, nth):
    """The nth fsync of a ledger file under `directory` fails (and is not run)."""
    real, state = os.fsync, {"n": 0}

    def inodes():
        return {(info.st_dev, info.st_ino) for info in
                (path.stat() for path in directory.rglob(suffix))}

    def fsync(fd):
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) in inodes():
            state["n"] += 1
            if state["n"] == nth:
                raise OSError(errno.EIO, "injected")
        return real(fd)
    monkeypatch.setattr(os, "fsync", fsync)
    return real


def pack(monkeypatch, selection_node):
    ctx = activate(selection_node)
    monkeypatch.setattr(mio_playbooks, "selection_context", lambda config, pack_root: ctx)
    monkeypatch.setattr(referenced, "mission_pack_root", lambda: ctx.root)


def reference_events():
    return [entry_.event for entry_ in AuditLedger(
        runtime_paths.mio_reference_state_dir() / "reference.jsonl")]


def test_a_reference_whose_record_failed_is_not_attached_and_the_next_one_is(
        root, selection_node, monkeypatch):
    pack(monkeypatch, selection_node)
    with Daemon(referenced.main), Daemon(entry.main):
        clean = ask()
        assert clean["ok"] and clean["result"]["reference_status"] == "attached"
        before = len(reference_events())
        real = fail_fsync(monkeypatch, runtime_paths.mio_reference_state_dir(), "reference.jsonl", 1)
        faulted = ask()
        monkeypatch.setattr(os, "fsync", real)
        assert faulted["ok"], faulted
        # The reference was computed and its record is unknown: it is not attached.
        assert faulted["result"]["reference_status"] == "unavailable"
        assert "reference" not in faulted["result"]
        again = ask()
        assert again["result"]["reference_status"] == "attached"
    events = reference_events()
    kinds = [e["event_type"] for e in events[before:] if e["event_type"] != "runtime.request_refused"]
    assert kinds == ["mio.reference.reply", "audit.outcome_settled", "mio.reference.reply"]
    assert [e for e in events if e["event_type"] == "audit.outcome_settled"][0]["outcome"] == "present"
    AuditLedger(runtime_paths.mio_reference_state_dir() / "reference.jsonl").verify()


def test_an_entry_whose_last_record_failed_does_not_return_the_reference(
        root, selection_node, monkeypatch):
    pack(monkeypatch, selection_node)
    with Daemon(referenced.main), Daemon(entry.main):
        clean = ask()
        assert clean["ok"] and clean["result"]["reference_status"] == "attached"
        sent_before = len([e for e in RouteChain(runtime_paths.mio_state_dir() / "route")
                           if e.event["event_type"] == "mio.entry.handoff"])
        # The handoff record is the last append of the request: the 7th fsync of its segment.
        real = fail_fsync(monkeypatch, runtime_paths.mio_state_dir() / "route", "*.jsonl", 7)
        faulted = ask()
        monkeypatch.setattr(os, "fsync", real)
        assert faulted == {"ok": False, "refusal": "verb_unavailable"}, faulted
        retry = ask()
        assert retry["ok"] and retry["result"]["reference_status"] == "attached"
    events = [e.event for e in RouteChain(runtime_paths.mio_state_dir() / "route")]
    kinds = [e["event_type"] for e in events]
    assert kinds.count("audit.outcome_settled") == 1
    # The handoff of the faulted request landed once; the retry is a new request with its own.
    assert kinds.count("mio.entry.handoff") == sent_before + 2
    RouteChain(runtime_paths.mio_state_dir() / "route").verify()
