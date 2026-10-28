"""The Knowledge Lite clock floor's persistence order, read-back and creation audit."""

import os
import stat

import pytest
from test_knowledge_lited import NOW, floor_dir
from test_knowledge_lited import node as commissioned_node

from azazel_nexus_runtime import knowledge_clock_floor
from azazel_nexus_runtime import knowledge_lited as daemon
from azazel_nexus_runtime.knowledge_clock_floor import ClockFloor, FloorUnavailable


@pytest.fixture
def node(tmp_path, monkeypatch):
    return commissioned_node.__wrapped__(tmp_path, monkeypatch)


def _recording(private_os):
    """Record fsync (of a file or a directory) and rename, in call order."""
    fake = private_os(knowledge_clock_floor)
    calls = []

    def fsync(fd):
        kind = "dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
        calls.append("fsync-" + kind)
        return os.fsync(fd)

    def rename(*args, **kwargs):
        calls.append("rename")
        return os.rename(*args, **kwargs)

    fake.fsync, fake.rename = fsync, rename
    return calls


def test_file_is_synced_before_rename_and_directory_before_the_answer(tmp_path, private_os):
    calls = _recording(private_os)
    floor = ClockFloor(floor_dir(tmp_path))
    assert floor.admit("2026-10-18T00:00:00Z") is True
    # Everything happened before admit returned, i.e. before any reply.
    assert calls == ["fsync-file", "rename", "fsync-dir"]
    calls.clear()
    assert floor.admit("2026-10-18T00:00:00.5Z") is True
    assert calls == []  # same second: nothing written
    assert floor.admit("2026-10-18T00:00:02Z") is True
    assert calls == ["fsync-file", "rename", "fsync-dir"]


def test_read_back_that_differs_is_refused(tmp_path, monkeypatch):
    floor = ClockFloor(floor_dir(tmp_path))
    original = ClockFloor._read
    reads = []

    def read(self):
        reads.append(1)
        value = original(self)
        # The second read is the read-back after the write.
        if len(reads) == 2:
            return knowledge_clock_floor._instant("2026-10-17T00:00:00Z")
        return value

    monkeypatch.setattr(ClockFloor, "_read", read)
    with pytest.raises(FloorUnavailable):
        floor.admit("2026-10-18T00:00:00Z")
    assert len(reads) == 2


def test_creation_causes(tmp_path):
    state = floor_dir(tmp_path)
    path = state / knowledge_clock_floor.FILENAME
    floor = ClockFloor(state)
    assert floor.admit("2026-10-18T00:00:00Z") is True
    assert floor.created == "initial"
    assert floor.admit("2026-10-18T00:00:05Z") is True
    assert floor.created is None
    # Removed while this process kept it.
    path.unlink()
    assert floor.admit("2026-10-18T00:00:06Z") is True
    assert floor.created == "absent_after_use"
    # A new process whose leaf already holds other state.
    path.unlink()
    (state / "events.jsonl").write_text("{}\n")
    restarted = ClockFloor(state)
    assert restarted.admit("2026-10-18T00:00:07Z") is True
    assert restarted.created == "absent_after_use"


def test_service_audits_each_creation(node, tmp_path):
    _, root, trust, _ = node
    state = floor_dir(tmp_path)
    events = []
    clock = iter(["2026-10-18T00:00:00Z", "2026-10-18T00:00:01Z", "2026-10-18T00:00:02Z"])
    service = daemon.KnowledgeLiteService(root=root, trust_root=trust, clock_floor=ClockFloor(state),
                                          now=lambda: next(clock), audit=events.append)
    service.handle(None)
    service.handle(None)
    (state / knowledge_clock_floor.FILENAME).unlink()
    service.handle(None)
    created = [e for e in events if e["event_type"] == "knowledge.clock_floor_created"]
    assert created == [{"event_type": "knowledge.clock_floor_created", "cause": "initial"},
                       {"event_type": "knowledge.clock_floor_created", "cause": "absent_after_use"}]
    assert NOW not in repr(events) and str(tmp_path) not in repr(events)
