"""Operator-readable snapshots (U2): Knowledge Lite, M.I.O. capability, unit states, storage.

Each snapshot is written by the daemon that owns the facts, into its own
`2750 <daemon>:azazel-operator` leaf, and read through a strict reader that
refuses anything outside the closed shape. These tests cover the readers'
refusals (broken, foreign, extra/missing/duplicate key, out-of-vocabulary,
oversized, symlink, directory), freshness (old, future, a stopped writer),
the writers (atomic rename, mode, size bound, never raising), the daemons'
wiring, the read-only unit reader, the storage measurement, and the unit
and installer declarations. Mock evidence: no systemd, no real daemon
process; `UnitStatesReader` runs against a fake bus session.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus import operator_snapshots as snap
from azazel_nexus import runtime_paths as paths
from azazel_nexus import status_view
from test_knowledge_lited import node  # noqa: F401 - the fixture, reused

REPO = Path(__file__).resolve().parents[2]
NOW = 1_790_000_000.0

REASONS = {"profile": "LITE", "resource": "core_reserve_unmeasured", "trust": "not-checked",
           "topology": "no_verified_egress",
           "health": {"local": "not_admitted", "remote": "unavailable"}}


def _raw(value) -> bytes:
    return json.dumps(value).encode()


def _knowledge(**extra):
    value = snap.knowledge_snapshot({"state": "available", "reason_code": "available",
                                     "generation": 5, "freshness": "current"}, NOW)
    value.update(extra)
    return value


def _mio(**extra):
    value = snap.mio_snapshot({"state": "CORE", "reasons": REASONS},
                              "2026-09-21T04:00:00+00:00", uncertain=False, written_at=NOW)
    value.update(extra)
    return value


def _units(**extra):
    states = {unit: {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
              for unit in snap.OBSERVED_UNITS}
    value = snap.units_snapshot(states, NOW)
    value.update(extra)
    return value


READERS = {
    "knowledge": (snap.read_knowledge_status, _knowledge, snap.KNOWLEDGE_BYTES),
    "mio": (snap.read_mio_status, _mio, snap.MIO_BYTES),
    "units": (snap.read_units_status, _units, snap.UNITS_BYTES),
}


# -- the readers ---------------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(READERS))
def test_a_written_snapshot_reads_back_unchanged(kind):
    reader, build, _ = READERS[kind]
    value = build()
    assert reader(_raw(value)) == value


@pytest.mark.parametrize("kind", sorted(READERS))
@pytest.mark.parametrize("damage", [
    "broken", "not_object", "foreign_schema", "extra_key", "missing_key", "duplicate_key",
    "negative_time", "string_time", "nan_time", "oversized", "not_bytes", "not_utf8",
])
def test_the_readers_refuse_anything_outside_the_closed_shape(kind, damage):
    reader, build, limit = READERS[kind]
    value = build()
    raw = {
        "broken": lambda: b"{",
        "not_object": lambda: b"[]",
        "foreign_schema": lambda: _raw({**value, "schema": "azazel-nexus/audit-status/v1"}),
        "extra_key": lambda: _raw({**value, "interface": "enp4s0"}),
        "missing_key": lambda: _raw({k: v for k, v in value.items() if k != "written_at"}),
        "duplicate_key": lambda: _raw(value)[:-1] + b',"schema":"' + value["schema"].encode() + b'"}',
        "negative_time": lambda: _raw({**value, "written_at": -1}),
        "string_time": lambda: _raw({**value, "written_at": str(NOW)}),
        "nan_time": lambda: _raw(value).replace(str(NOW).encode(), b"NaN", 1),
        "oversized": lambda: _raw(value) + b" " * (limit + 1),
        "not_bytes": lambda: json.dumps(value),
        "not_utf8": lambda: b"\xff" + _raw(value),
    }[damage]()
    assert reader(raw) is None


@pytest.mark.parametrize("field, bad", [
    ("state", "healthy"), ("reason_code", "SECRET 192.0.2.1"), ("freshness", "fresh"),
    ("generation", -1), ("generation", "5"), ("generation", 2**63), ("generation", True),
])
def test_knowledge_vocabulary_is_closed(field, bad):
    assert snap.read_knowledge_status(_raw(_knowledge(**{field: bad}))) is None


def test_a_knowledge_summary_outside_the_vocabulary_is_written_as_unrecognised():
    value = snap.knowledge_snapshot({"state": "available", "reason_code": "available",
                                     "generation": 5, "freshness": "current",
                                     "path": "/var/lib/azazel/knowledge"}, NOW)
    assert value["state"] == "available" and "path" not in value
    for summary in (None, {"state": "green"}, {"state": "available", "reason_code": "x",
                                               "generation": 1, "freshness": "current"}):
        value = snap.knowledge_snapshot(summary, NOW)
        assert (value["state"], value["reason_code"]) == ("unavailable", "status_unrecognised")
        assert snap.read_knowledge_status(_raw(value)) == value
    value = snap.knowledge_snapshot(None, NOW, reason="internal_error")
    assert value["reason_code"] == "internal_error"


@pytest.mark.parametrize("change", [
    {"state": "MAX"}, {"ceiling": "FULL"}, {"recorded": 1}, {"record_uncertain": "no"},
    {"observed_at": "2026-09-21 04:00:00"}, {"observed_at": "2026-09-21T04:00:00\n+00:00"},
    {"observed_at": None}, {"reasons": {**REASONS, "trust": "trusted"}},
    {"reasons": {**REASONS, "extra": 1}},
    {"reasons": {**REASONS, "health": {"local": "admitted", "remote": "unavailable"}}},
    {"recorded": False},
])
def test_mio_vocabulary_is_closed(change):
    assert snap.read_mio_status(_raw(_mio(**change))) is None


def test_mio_snapshot_before_any_record_and_with_a_malformed_reading():
    empty = snap.mio_snapshot(None, None, uncertain=False, written_at=NOW)
    assert empty["recorded"] is False and empty["state"] is None and empty["reasons"] == {}
    assert snap.read_mio_status(_raw(empty)) == empty
    bad = snap.mio_snapshot({"state": "CORE", "reasons": {"profile": "LITE"}},
                            "2026-09-21T04:00:00+00:00", uncertain=True, written_at=NOW)
    assert bad["recorded"] is False and bad["record_uncertain"] is True
    # A recorded time in another ISO spelling is written as isoformat writes it.
    value = snap.mio_snapshot({"state": "CORE", "reasons": REASONS},
                              "2026-09-21T04:00:00Z", uncertain=False, written_at=NOW)
    assert value["observed_at"] == "2026-09-21T04:00:00+00:00"


@pytest.mark.parametrize("change", [
    lambda units: units.pop(),
    lambda units: units.reverse(),
    lambda units: units.append(dict(units[0])),
    lambda units: units[0].update(unit="sshd.service"),
    lambda units: units[0].update(load_state="sideloaded"),
    lambda units: units[0].update(active_state="green"),
    lambda units: units[0].update(sub_state="Running"),
    lambda units: units[0].update(reason_code="read_refused"),
    lambda units: units[0].update(status="unknown"),
    lambda units: units[0].update(status="ok"),
    lambda units: units[0].update(extra=1),
])
def test_unit_snapshot_is_closed(change):
    value = _units()
    change(value["units"])
    assert snap.read_units_status(_raw(value)) is None


def test_units_snapshot_reports_unknown_with_a_fixed_reason():
    value = snap.units_snapshot({snap.OBSERVED_UNITS[0]: "bus_unavailable",
                                 snap.OBSERVED_UNITS[1]: {"LoadState": "loaded",
                                                          "ActiveState": "exploded",
                                                          "SubState": "x"},
                                 snap.OBSERVED_UNITS[2]: "SECRET text"}, NOW)
    units = value["units"]
    assert [u["unit"] for u in units] == list(snap.OBSERVED_UNITS)
    assert (units[0]["status"], units[0]["reason_code"]) == ("unknown", "bus_unavailable")
    assert (units[1]["status"], units[1]["reason_code"]) == ("unknown", "read_refused")
    assert (units[2]["status"], units[2]["reason_code"]) == ("unknown", "read_refused")
    assert all(u["reason_code"] == "read_refused" for u in units[3:])
    assert "SECRET" not in json.dumps(value)
    assert snap.read_units_status(_raw(value)) == value
    assert len(_raw(_units())) < snap.UNITS_BYTES


def test_the_observed_units_are_exactly_the_packaged_services():
    from azazel_nexus_runtime.hardening import ALL_PROFILES

    assert snap.OBSERVED_UNITS == tuple(sorted(p.unit for p in ALL_PROFILES))


def test_the_core_vocabulary_matches_the_bus_reader():
    from azazel_nexus_runtime import systemd_bus

    assert snap.ACTIVE_STATES == systemd_bus._ACTIVE_STATES
    assert snap.LOAD_STATES == systemd_bus._LOAD_STATES | {"not-loaded"}
    assert snap._SUB_STATE.pattern == systemd_bus._SUB_STATE.pattern


# -- the files, as status reads them -------------------------------------------


SECTIONS = {
    "knowledge": (paths.knowledge_status_path, status_view._knowledge_status, _knowledge,
                  snap.KNOWLEDGE_STALE_S),
    "mio": (paths.mio_status_path, status_view._mio_status, _mio, snap.MIO_STALE_S),
    "units": (paths.units_status_path, status_view._services, _units, snap.UNITS_STALE_S),
}


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    return tmp_path


def _place(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


@pytest.mark.parametrize("kind", sorted(SECTIONS))
def test_fresh_stale_future_and_absent(root, kind):
    where, section, build, stale = SECTIONS[kind]
    assert section(NOW)["status"] == "unavailable"
    assert section(NOW)["reason_code"] == "snapshot_absent_or_refused"
    _place(where(), _raw(build()))
    fresh = section(NOW + 1)
    assert fresh["status"] in ("available", "recorded", "read")
    assert fresh["status"] != "running" and fresh["freshness"] == "fresh"
    assert fresh["source"]["freshness"] == "fresh"
    assert fresh["source"]["schema"] == build()["schema"]
    old = section(NOW + stale + 1)
    assert (old["status"], old["reason_code"]) == ("stale", "snapshot_expired")
    future = section(NOW - snap.FUTURE_S - 1)
    assert (future["status"], future["reason_code"]) == ("stale", "snapshot_dated_in_future")
    unknown = section(None)
    assert unknown["status"] == "unknown" and unknown["source"]["reason_code"] == "clock_unknown"


@pytest.mark.parametrize("kind", sorted(SECTIONS))
@pytest.mark.parametrize("damage", ["symlink", "directory", "oversized", "broken", "fifo"])
def test_a_damaged_file_is_unavailable_not_health(root, kind, damage):
    where, section, build, _ = SECTIONS[kind]
    path = where()
    path.parent.mkdir(parents=True, exist_ok=True)
    if damage == "symlink":
        real = root / "elsewhere.json"
        real.write_bytes(_raw(build()))
        path.symlink_to(real)
    elif damage == "directory":
        path.mkdir()
    elif damage == "oversized":
        path.write_bytes(_raw(build()) + b" " * 20000)
    elif damage == "broken":
        path.write_bytes(b'{"schema":')
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("no FIFO on this platform")
        os.mkfifo(path)
    value = section(NOW)
    assert (value["status"], value["reason_code"]) == ("unavailable", "snapshot_absent_or_refused")
    assert value["snapshot"] is None


def test_mio_section_says_unknown_until_a_record_and_while_uncertain(root):
    _place(paths.mio_status_path(), _raw(snap.mio_snapshot(None, None, uncertain=False,
                                                           written_at=NOW)))
    value = status_view._mio_status(NOW)
    assert (value["status"], value["reason_code"]) == ("unknown",
                                                       "no_recorded_capability_transition")
    _place(paths.mio_status_path(), _raw(_mio(record_uncertain=True)))
    value = status_view._mio_status(NOW)
    assert (value["status"], value["reason_code"]) == ("unknown", "capability_record_uncertain")
    _place(paths.mio_status_path(), _raw(_mio()))
    value = status_view._mio_status(NOW)
    assert value["status"] == "recorded" and value["snapshot"]["ceiling"] == "LITE"
    assert "not a grant" in value["notice"]


# -- the writer ----------------------------------------------------------------


def test_the_writer_replaces_atomically_with_mode_0640_and_sweeps(tmp_path):
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    leaf = tmp_path / "leaf"
    leaf.mkdir()
    (leaf / ".status-leftover").write_text("half")
    target = leaf / "status.json"
    clock = [0.0]
    writes = []
    writer = SnapshotWriter(target, lambda: writes.append(1) or _knowledge(), limit=4096,
                            interval_s=60, name="test", monotonic=lambda: clock[0])
    writer.tick()
    assert snap.read_knowledge_status(target.read_bytes()) == _knowledge()
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert sorted(p.name for p in leaf.iterdir()) == ["status.json"]
    writer.tick()
    assert len(writes) == 1
    clock[0] = 60.0
    writer.tick()
    assert len(writes) == 2


def test_the_temp_file_is_created_in_the_leaf_private_then_renamed(tmp_path, monkeypatch):
    from azazel_nexus_runtime import status_snapshot
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    leaf = tmp_path / "leaf"
    leaf.mkdir()
    real = status_snapshot.tempfile.mkstemp
    created = []

    def mkstemp(*args, **kwargs):
        fd, name = real(*args, **kwargs)
        created.append((kwargs.get("dir"), Path(name).parent,
                        stat.S_IMODE(os.fstat(fd).st_mode)))
        return fd, name
    monkeypatch.setattr(status_snapshot.tempfile, "mkstemp", mkstemp)
    writer = SnapshotWriter(leaf / "status.json", _knowledge, limit=4096, interval_s=0,
                            name="test")
    assert writer.write()
    assert created == [(leaf, leaf, 0o600)]
    assert stat.S_IMODE((leaf / "status.json").stat().st_mode) == 0o640


def test_a_symlinked_snapshot_is_replaced_not_followed(tmp_path):
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    leaf = tmp_path / "leaf"
    leaf.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep")
    (leaf / "status.json").symlink_to(victim)
    assert SnapshotWriter(leaf / "status.json", _knowledge, limit=4096, interval_s=0,
                          name="test").write()
    assert victim.read_text() == "keep"
    assert not (leaf / "status.json").is_symlink()
    assert snap.read_knowledge_status((leaf / "status.json").read_bytes()) == _knowledge()


def test_a_failing_logger_does_not_escape_the_writer(tmp_path):
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    def warn(message):
        raise BrokenPipeError("stderr is gone")
    writer = SnapshotWriter(tmp_path / "absent" / "status.json", _knowledge, limit=4096,
                            interval_s=0, name="test", warn=warn)
    assert writer.write() is False
    writer.tick()


def test_entryd_survives_a_failing_snapshot_log(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths as runtime
    from azazel_nexus_runtime import status_snapshot

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime.mio_state_dir().mkdir(parents=True)
    runtime.socket_path("mio-advise").parent.mkdir(parents=True, exist_ok=True)

    class Closed:
        def write(self, text):
            raise OSError("stderr closed")

        def flush(self):
            raise OSError("stderr closed")
    monkeypatch.setattr(sys, "stderr", Closed())
    assert status_snapshot._stderr is not None
    captured = {}
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: "policy")
    # The leaf is missing, so every write fails and logs through a broken stderr.
    assert entry.main([], ready=lambda: None) == 0
    assert captured["stop"]() is False


def test_entryd_writes_at_once_when_the_recorded_reading_changes(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths as runtime

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime.mio_state_dir().mkdir(parents=True)
    runtime.socket_path("mio-advise").parent.mkdir(parents=True, exist_ok=True)
    paths.mio_status_path().parent.mkdir(parents=True)
    captured = {}
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: "policy")
    assert entry.main([], ready=lambda: None) == 0
    service = captured["handler"].__self__
    first = snap.read_mio_status(paths.mio_status_path().read_bytes())
    assert first["recorded"] is True
    # No change and not due: the tick writes nothing.
    paths.mio_status_path().unlink()
    assert captured["stop"]() is False
    assert not paths.mio_status_path().exists()
    # A recorded change (here, a write of unknown outcome) is written at once,
    # long before the 60 s interval.
    monkeypatch.setattr(service, "reconcile_capability", lambda *a, **k: None)
    service._capability_uncertain = True
    assert captured["stop"]() is False
    changed = snap.read_mio_status(paths.mio_status_path().read_bytes())
    assert changed["record_uncertain"] is True


def test_a_fresh_snapshot_of_a_problem_is_not_running(root):
    """A UI must not read a fresh snapshot as health."""
    _place(paths.knowledge_status_path(), _raw(_knowledge(state="quarantined",
                                                          reason_code="revoked")))
    value = status_view._knowledge_status(NOW + 1)
    assert (value["status"], value["reason_code"], value["freshness"]) == (
        "degraded", "revoked", "fresh")
    assert value["content_freshness_evaluated_at"] == NOW
    _place(paths.knowledge_status_path(), _raw(_knowledge(state="unavailable",
                                                          reason_code="no_bundle",
                                                          generation=None, freshness="absent")))
    assert status_view._knowledge_status(NOW + 1)["status"] == "degraded"
    units = _units()
    units["units"][3]["active_state"] = "failed"
    _place(paths.units_status_path(), _raw(units))
    value = status_view._services(NOW + 1)
    assert (value["status"], value["reason_code"]) == ("degraded", "unit_failed")
    _place(paths.units_status_path(), _raw(_units()))
    assert status_view._services(NOW + 1)["status"] == "read"
    for section in (status_view._knowledge_status, status_view._mio_status,
                    status_view._services):
        for now in (NOW + 1, NOW + 10_000, None):
            assert section(now)["status"] != "running"


def test_the_writer_never_raises_and_warns_once(tmp_path):
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter

    warnings = []
    missing = SnapshotWriter(tmp_path / "absent-leaf" / "status.json", _knowledge, limit=4096,
                             interval_s=0, name="test", warn=warnings.append)
    assert missing.write() is False
    assert missing.write() is False
    assert len(warnings) == 1 and "status snapshot" in warnings[0]
    oversized = tmp_path / "big"
    oversized.mkdir()
    big = SnapshotWriter(oversized / "status.json", _units, limit=64, interval_s=0,
                         name="test", warn=warnings.append)
    assert big.write() is False and list(oversized.iterdir()) == []

    def boom():
        raise RuntimeError("SECRET /var/lib/azazel")
    failing = SnapshotWriter(oversized / "status.json", boom, limit=4096, interval_s=0,
                             name="test", warn=warnings.append)
    failing.tick()
    assert all("SECRET" not in text for text in warnings)


# -- the daemons ---------------------------------------------------------------


def test_knowledge_lited_snapshot_follows_its_status_and_goes_stale_when_it_stops(node):
    from azazel_nexus_runtime import knowledge_lited as daemon
    from azazel_nexus_runtime.status_snapshot import SnapshotWriter
    from test_knowledge_lited import admit

    service = node[0]
    writer = SnapshotWriter(paths.knowledge_status_path(),
                            lambda: service.status_snapshot(wall_clock=lambda: NOW),
                            limit=snap.KNOWLEDGE_BYTES, interval_s=0, name="test")
    paths.knowledge_status_path().parent.mkdir(parents=True)
    assert writer.write()
    before = status_view._knowledge_status(NOW + 1)
    assert (before["status"], before["freshness"]) == ("degraded", "fresh")
    assert before["snapshot"]["state"] == service.handle(
        SimpleNamespace(verb=daemon.STATUS_VERB, arguments={}))["state"]
    admit(node)
    assert writer.write()
    after = status_view._knowledge_status(NOW + 1)["snapshot"]
    assert (after["state"], after["generation"]) == ("available", 5)
    # The daemon stops: nothing rewrites the snapshot, and it goes stale.
    stopped = status_view._knowledge_status(NOW + snap.KNOWLEDGE_STALE_S + 1)
    assert (stopped["status"], stopped["reason_code"]) == ("stale", "snapshot_expired")
    paths.knowledge_status_path().unlink()
    assert status_view._knowledge_status(NOW + 1)["status"] == "unavailable"


def test_knowledge_lited_status_snapshot_never_carries_exception_text(tmp_path, monkeypatch):
    from azazel_nexus_runtime import knowledge_lited as daemon

    def boom(**kwargs):
        raise RuntimeError("SECRET /var/lib/azazel/lite-trust")
    monkeypatch.setattr(daemon, "status_summary", boom)
    service = daemon.KnowledgeLiteService(root=tmp_path, trust_root=tmp_path,
                                          clock_floor=_clock_floor(tmp_path))
    value = service.status_snapshot(wall_clock=lambda: NOW)
    assert (value["state"], value["reason_code"]) == ("unavailable", "internal_error")
    assert "SECRET" not in json.dumps(value)


def _clock_floor(tmp_path):
    from azazel_nexus_runtime.knowledge_clock_floor import ClockFloor

    state = tmp_path / "floor"
    state.mkdir(mode=0o700, exist_ok=True)
    state.chmod(0o700)
    return ClockFloor(state)


def test_knowledge_lited_status_snapshot_follows_the_clock_floor(tmp_path, monkeypatch):
    # The snapshot is the same answer `knowledge.status` gives (#359): with
    # the wall clock behind the persisted floor nothing is read, and the
    # snapshot says `unavailable` / `state_untrusted`, never the store's state.
    from azazel_nexus_runtime import knowledge_lited as daemon

    read = []
    monkeypatch.setattr(daemon, "status_summary", lambda **kw: read.append(kw) or {
        "state": "available", "reason_code": "available", "generation": 3,
        "freshness": "current"})
    floor = _clock_floor(tmp_path)
    assert floor.admit("2026-10-18T00:00:00Z") is True
    clock = {"now": "2026-10-17T00:00:00Z"}
    events = []
    service = daemon.KnowledgeLiteService(root=tmp_path, trust_root=tmp_path,
                                          clock_floor=floor, now=lambda: clock["now"],
                                          audit=events.append)
    value = service.status_snapshot(wall_clock=lambda: NOW)
    assert snap.read_knowledge_status(json.dumps(value).encode()) == value
    assert (value["state"], value["reason_code"], value["generation"],
            value["freshness"]) == ("unavailable", "state_untrusted", None, "absent")
    assert read == []
    assert [e["event_type"] for e in events] == ["knowledge.clock_untrusted"]
    clock["now"] = "2026-10-19T00:00:00Z"
    value = service.status_snapshot(wall_clock=lambda: NOW)
    assert (value["state"], value["generation"]) == ("available", 3)
    assert read == [{"root": tmp_path, "trust_root": tmp_path,
                     "query_as_of": "2026-10-19T00:00:00Z"}]


def test_knowledge_lited_main_writes_after_ready_and_on_its_tick(tmp_path, monkeypatch):
    from azazel_nexus_runtime import knowledge_lited as daemon
    from azazel_nexus_runtime import runtime_paths as runtime
    from azazel_nexus_runtime import serve

    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    monkeypatch.setattr(runtime, "audit_sink", lambda name: (lambda event: None))
    monkeypatch.setattr(daemon.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=1))
    monkeypatch.setattr(daemon.PrincipalPolicy, "resolve", lambda **kw: "policy")
    leaf = tmp_path / "var/lib/azazel/run/knowledge-status"
    leaf.mkdir(parents=True)
    seen = {}

    order = []

    def serve_forever(**kwargs):
        # Nothing is written before the bind; READY comes first, then the write.
        seen["before"] = (leaf / "status.json").exists()
        kwargs["ready"]()
        seen["after_ready"] = (leaf / "status.json").exists()
        (leaf / "status.json").unlink()
        assert kwargs["stop"]() is True
        return 0
    monkeypatch.setattr(serve, "serve_forever", serve_forever)
    # Due again at the first tick, so the stop callback is seen to write.
    monkeypatch.setattr(snap, "KNOWLEDGE_INTERVAL_S", 0)
    assert daemon.main([], stop=lambda: True,
                       ready=lambda: order.append(("ready", (leaf / "status.json").exists()))) == 0
    assert seen["before"] is False and seen["after_ready"] is True
    assert order == [("ready", False)]
    # The stop callback ticked the writer, which was due again.
    assert snap.read_knowledge_status((leaf / "status.json").read_bytes()) is not None


def test_entryd_snapshot_is_the_recorded_reading_and_main_writes_it(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths as runtime

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime.mio_state_dir().mkdir(parents=True)
    service = entry.MioEntryService(wall_clock=lambda: NOW)
    before = service.status_snapshot()
    assert before["recorded"] is False
    service.reconcile_capability()
    value = service.status_snapshot()
    assert value["recorded"] is True and value["state"] == "CORE"
    assert snap.read_mio_status(_raw(value)) == value
    # The same reading `status` reads from the 0700 ledger as root.
    from azazel_nexus.mio_status import status_summary
    ledger = status_summary(root=tmp_path)
    assert (ledger["state"], ledger["ceiling"], ledger["reasons"]) == (
        value["state"], value["ceiling"], value["reasons"])
    assert ledger["observed_at"] == value["observed_at"]

    captured = {}
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: "policy")
    runtime.socket_path("mio-advise").parent.mkdir(parents=True, exist_ok=True)
    leaf = paths.mio_status_path().parent
    leaf.mkdir(parents=True)
    assert entry.main([], ready=lambda: None) == 0
    written = snap.read_mio_status(paths.mio_status_path().read_bytes())
    assert written is not None and written["recorded"] is True
    paths.mio_status_path().unlink()
    assert captured["stop"]() is False
    assert paths.mio_status_path().exists() is False  # not due, nothing changed


def test_entryd_main_starts_without_the_leaf(tmp_path, monkeypatch, capsys):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths as runtime

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime.mio_state_dir().mkdir(parents=True)
    runtime.socket_path("mio-advise").parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(entry, "serve_forever", lambda **kw: 0)
    monkeypatch.setattr(entry.PrincipalPolicy, "resolve", lambda **kw: "policy")
    assert entry.main([], ready=lambda: None) == 0
    assert "cannot write its status snapshot" in capsys.readouterr().err


# -- the unit-state reader and observer ------------------------------------------


class _Session:
    def __init__(self, states, fail=()):
        from azazel_nexus_runtime.systemd_bus import (
            MANAGER_INTERFACE, PROPERTIES_INTERFACE, _unit_object_path,
        )
        self.calls = []
        self.closed = False
        self._states, self._fail = states, set(fail)
        self._paths = {_unit_object_path(u): u for u in snap.OBSERVED_UNITS}
        self._manager, self._properties = MANAGER_INTERFACE, PROPERTIES_INTERFACE

    def _exchange(self, interface, member, signature, body, **kwargs):
        self.calls.append((interface, member, signature, tuple(body), kwargs.get("path")))
        from azazel_nexus_runtime.systemd_bus import _unit_object_path
        if member == "GetUnit":
            unit = body[0]
            if unit in self._fail:
                raise RuntimeError("SECRET bus text")
            if unit not in self._states:
                return SimpleNamespace(no_such_unit=True)
            return SimpleNamespace(signature="o", body=[_unit_object_path(unit)],
                                   no_such_unit=False)
        unit = self._paths[kwargs["path"]]
        return SimpleNamespace(signature="v", body=[
            SimpleNamespace(signature="s", value=self._states[unit][body[1]])],
            no_such_unit=False)

    def close(self):
        self.closed = True


def test_unit_states_reader_reads_only_the_fixed_units(monkeypatch):
    from azazel_nexus_runtime import systemd_bus

    monkeypatch.setattr(systemd_bus.SystemdUnitCalls, "_one",
                        staticmethod(lambda reply, signature, name: reply.body[0]))
    states = {u: {"LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead"}
              for u in snap.OBSERVED_UNITS[:-2]}
    states[snap.OBSERVED_UNITS[0]]["ActiveState"] = "exploded"
    session = _Session(states, fail={snap.OBSERVED_UNITS[1]})
    result = systemd_bus.UnitStatesReader(connect=lambda: session).read_all()
    assert session.closed
    assert set(result) == set(snap.OBSERVED_UNITS)
    assert result[snap.OBSERVED_UNITS[0]] == "read_refused"   # unknown ActiveState
    assert result[snap.OBSERVED_UNITS[1]] == "read_refused"   # the call failed
    assert result[snap.OBSERVED_UNITS[-1]]["LoadState"] == "not-loaded"
    assert result[snap.OBSERVED_UNITS[2]] == {"LoadState": "loaded", "ActiveState": "inactive",
                                              "SubState": "dead"}
    members = {(c[0], c[1], c[2]) for c in session.calls}
    assert members <= {(systemd_bus.MANAGER_INTERFACE, "GetUnit", "s"),
                       (systemd_bus.PROPERTIES_INTERFACE, "Get", "ss")}
    assert {c[3][0] for c in session.calls if c[1] == "GetUnit"} == set(snap.OBSERVED_UNITS)


def test_unit_states_reader_without_a_bus_reports_every_unit_unavailable():
    from azazel_nexus_runtime import systemd_bus

    def refuse():
        raise OSError("SECRET no bus")
    result = systemd_bus.UnitStatesReader(connect=refuse).read_all()
    assert result == {u: "bus_unavailable" for u in snap.OBSERVED_UNITS}


def test_the_state_reader_refuses_a_unit_off_the_list_before_the_bus():
    from azazel_nexus_runtime import systemd_bus
    from azazel_nexus_runtime.units import UnitOperationFailed

    calls = []
    with pytest.raises(UnitOperationFailed):
        systemd_bus._read_unit_state(lambda *a, **k: calls.append(a), "sshd.service")
    assert calls == []
    read = systemd_bus._read_only(lambda *a, **k: calls.append(a))
    for call in (("org.freedesktop.systemd1.Manager", "MaskUnitFiles", "asbb"),
                 ("org.freedesktop.systemd1.Manager", "StopUnit", "ss"),
                 ("org.freedesktop.systemd1.Manager", "StartUnit", "ss")):
        with pytest.raises(UnitOperationFailed):
            read(*call, [])
    assert calls == []


def test_the_observer_writes_one_snapshot_and_takes_no_argument(root, monkeypatch):
    from azazel_nexus_runtime import runtime_paths as runtime
    from azazel_nexus_runtime import units_observe

    monkeypatch.setattr(runtime, "ROOT", root)
    reader = SimpleNamespace(read_all=lambda: {u: "bus_unavailable" for u in snap.OBSERVED_UNITS})
    assert units_observe.main([], reader=reader, clock=lambda: NOW) == 1  # no leaf yet
    paths.units_status_path().parent.mkdir(parents=True)
    assert units_observe.main([], reader=reader, clock=lambda: NOW) == 0
    value = status_view._services(NOW + 1)
    assert (value["status"], value["reason_code"]) == ("unknown", "unit_state_unread")
    assert {u["reason_code"] for u in value["snapshot"]["units"]} == {"bus_unavailable"}
    assert status_view._services(NOW + snap.UNITS_STALE_S + 1)["status"] == "stale"
    with pytest.raises(SystemExit, match="takes no arguments"):
        units_observe.main(["--unit", "sshd.service"], reader=reader)


# -- storage -------------------------------------------------------------------


def test_storage_is_measured_under_fixed_labels_without_paths(tmp_path):
    for _, relative in snap.STORAGE_LOCATIONS[:3]:
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    entries = snap.read_storage(tmp_path)
    assert [e["label"] for e in entries] == [label for label, _ in snap.STORAGE_LOCATIONS]
    measured = [e for e in entries if e["status"] == "measured"]
    assert len(measured) == 3
    assert measured[0]["same_filesystem_as"] is None
    assert all(e["same_filesystem_as"] == "state_root" for e in measured[1:])
    assert all(e["total_bytes"] >= e["free_bytes"] >= 0 for e in measured)
    assert [e["reason_code"] for e in entries[3:]] == ["absent", "absent"]
    assert str(tmp_path) not in json.dumps(entries)


def test_storage_reports_refusal_codes_not_exception_text(tmp_path):
    def statvfs(path):
        if path.name == "audit":
            raise PermissionError("SECRET")
        if path.name == "models":
            raise OSError(5, "SECRET")
        raise FileNotFoundError("SECRET")
    entries = snap.read_storage(tmp_path, statvfs=statvfs)
    codes = {e["label"]: e["reason_code"] for e in entries}
    assert codes == {"state_root": "absent", "audit": "not_permitted",
                     "edge_incidents": "absent", "models": "read_failed",
                     "mission_data": "absent"}
    assert "SECRET" not in json.dumps(entries)
    section = status_view._storage(NOW)
    assert section["source"]["withheld"] == ["path"]


# -- declarations ----------------------------------------------------------------


def test_no_unit_requires_binds_to_or_is_ordered_on_an_observer():
    from azazel_nexus_runtime.hardening import (
        ALL_PROFILES, OBSERVER_SERVICE_UNITS, packaged_unit_files,
    )

    observers = set(OBSERVER_SERVICE_UNITS) | {"azazel-units-observe.timer",
                                               "azazel-noc-observe.timer"}
    for profile in ALL_PROFILES:
        assert not observers & set(profile.requires + profile.binds_to + profile.after
                                   + profile.before), profile.unit
    for name, text in packaged_unit_files():
        if name in observers:
            continue
        for line in text.splitlines():
            if line.split("=", 1)[0] in ("Requires", "BindsTo", "Wants", "Requisite",
                                         "PartOf", "After", "Before", "OnFailure"):
                assert not any(unit in line for unit in observers), (name, line)


def test_the_observer_unit_and_timer_are_narrow():
    from azazel_nexus_runtime.hardening import packaged_unit_files

    files = dict(packaged_unit_files())
    service = files["azazel-units-observe.service"]
    assert "User=azprobe" in service and "Type=oneshot" in service
    assert "RestrictAddressFamilies=AF_UNIX\n" in service
    assert "IPAddressDeny=any" in service and "CapabilityBoundingSet=\n" in service
    assert "ReadWritePaths=-/var/lib/azazel/run/units-status\n" in service
    assert service.count("ReadWritePaths=") == 1
    assert "\n[Install]" not in service and "ConditionPathExists" not in service
    timer = files["azazel-units-observe.timer"]
    assert "Unit=azazel-units-observe.service" in timer
    assert "WantedBy=timers.target" in timer
    assert not re.search(r"^(Requires|BindsTo|Persistent|WakeSystem)=", timer, re.M)
    for name in ("azazel-units-observe.service", "azazel-units-observe.timer"):
        assert (REPO / "packaging/systemd" / name).read_text(encoding="utf-8") == files[name]


def test_the_installer_creates_the_leaves_and_never_enables_or_masks_the_observer():
    installer = (REPO / "packaging/install.sh").read_text(encoding="utf-8")
    for line in ("make_owned_dir 2750 azknowledge azazel-operator /var/lib/azazel/run/knowledge-status",
                 "make_owned_dir 2750 azmioentry azazel-operator /var/lib/azazel/run/mio-status",
                 "make_owned_dir 2750 azprobe azazel-operator /var/lib/azazel/run/units-status"):
        assert line in installer
    assert not re.search(r"systemctl (enable|mask|start).*units-observe", installer)
    preset = (REPO / "packaging/azazel-nexus.preset").read_text(encoding="utf-8")
    assert "units-observe" not in preset
    # No new group: every new leaf belongs to azazel-operator.
    from azazel_nexus.layout import LAYOUT
    leaves = {spec.path: spec for spec in LAYOUT}
    for name, owner in (("knowledge-status", "azknowledge"), ("mio-status", "azmioentry"),
                        ("units-status", "azprobe")):
        spec = leaves[f"/var/lib/azazel/run/{name}"]
        assert (spec.mode, spec.owner, spec.group) == (0o2750, owner, "azazel-operator")


@pytest.mark.skipif(sys.platform != "linux", reason="Linux setgid-directory semantics")
def test_status_reads_every_new_section_through_json(root, monkeypatch, capsys):
    """`status --json` carries the four sections; the text screen does not change."""
    from azazel_nexus.cli import main

    _place(paths.knowledge_status_path(), _raw(_knowledge(written_at=NOW - 10)))
    _place(paths.mio_status_path(), _raw(_mio(written_at=NOW - 10)))
    _place(paths.units_status_path(), _raw(_units(written_at=NOW - 10)))
    from datetime import datetime, timezone
    as_of = datetime.fromtimestamp(NOW, timezone.utc).isoformat().replace("+00:00", "Z")
    import io
    out = io.StringIO()
    assert main(["--as-of", as_of, "status", "--json"], out=out) == 0
    sections = json.loads(out.getvalue())["sections"]
    assert sections["knowledge_status"]["snapshot"]["generation"] == 5
    assert sections["mio_status"]["snapshot"]["state"] == "CORE"
    assert len(sections["services"]["snapshot"]["units"]) == len(snap.OBSERVED_UNITS)
    assert sections["storage"]["locations"][0]["label"] == "state_root"
    assert all(s["status"] in ("available", "recorded", "read", "measured")
               for name, s in sections.items()
               if name in ("knowledge_status", "mio_status", "services", "storage"))
