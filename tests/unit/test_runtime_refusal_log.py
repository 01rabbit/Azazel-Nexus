"""Per-daemon refusal logs are bounded (#211)."""

from __future__ import annotations

import json
import os
import stat

import pytest
from azazel_nexus_runtime import runtime_paths, serve
from azazel_nexus_runtime.auditd import summarized_refusals
from azazel_nexus_runtime.refusal_log import (
    REFUSAL_EVENT,
    REFUSAL_LOG_KEEP,
    REFUSAL_LOG_MAX_BYTES,
    REFUSAL_SUMMARY_EVENT,
    BoundedRefusalLog,
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _refusal(uid=1001, reason="malformed_frame", **extra) -> dict:
    return {"event_type": REFUSAL_EVENT, "reason": reason, "request_bytes": 3,
            "request_fingerprint": "0" * 16, "uid": uid, "gid": uid, "pid": 7,
            "classes": ["operator"], **extra}


def _lines(path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _log(tmp_path, **kwargs) -> tuple[BoundedRefusalLog, Clock]:
    clock = Clock()
    return BoundedRefusalLog(tmp_path / "refusals.jsonl", clock=clock, **kwargs), clock


def test_the_defaults_are_the_documented_bounds():
    assert REFUSAL_LOG_MAX_BYTES == 4 * 1024 * 1024
    assert REFUSAL_LOG_KEEP == 2


def test_a_flood_writes_one_line_per_key_per_window_with_the_count(tmp_path):
    log, clock = _log(tmp_path, window_s=60)
    for second in range(300):
        clock.now = 1000.0 + second
        for _ in range(10):
            log(_refusal())
    log.flush_due()
    lines = _lines(log.path)
    # The first refusal as it is, then one summary per completed window.
    assert lines[0]["event_type"] == REFUSAL_EVENT
    summaries = lines[1:]
    assert [line["event_type"] for line in summaries] == [REFUSAL_SUMMARY_EVENT] * 4
    assert all(line["uid"] == 1001 and line["reason"] == "malformed_frame" for line in summaries)
    clock.now += 60
    log.flush_due()
    summaries = _lines(log.path)[1:]
    assert sum(line["suppressed"] for line in summaries) == 2999
    assert log.counters() == {"written": len(summaries) + 1, "suppressed": 2999,
                              "unrecorded": 0, "rotations": 0}


def test_the_count_is_written_when_the_flood_stops_and_then_the_key_is_forgotten(tmp_path):
    log, clock = _log(tmp_path, window_s=60)
    for _ in range(5):
        log(_refusal())
    clock.now += 59
    log.flush_due()
    assert len(_lines(log.path)) == 1
    clock.now += 1
    log.flush_due()
    summary = _lines(log.path)[-1]
    assert summary == {"event_type": REFUSAL_SUMMARY_EVENT, "uid": 1001,
                       "reason": "malformed_frame", "suppressed": 4, "window_s": 60,
                       "unrecorded": 0, "last_request_fingerprint": "0" * 16}
    clock.now += 60
    log.flush_due()  # an empty window writes nothing and closes the key
    assert len(_lines(log.path)) == 2
    log(_refusal())
    assert _lines(log.path)[-1]["event_type"] == REFUSAL_EVENT


def test_keys_are_caller_uid_and_reason(tmp_path):
    log, _ = _log(tmp_path)
    log(_refusal(uid=1001, reason="malformed_frame"))
    log(_refusal(uid=1001, reason="unknown_verb"))
    log(_refusal(uid=1002, reason="malformed_frame"))
    log(_refusal(uid=1002, reason="malformed_frame"))
    assert [(line["uid"], line["reason"]) for line in _lines(log.path)] == [
        (1001, "malformed_frame"), (1001, "unknown_verb"), (1002, "malformed_frame")]


def test_other_events_go_to_their_own_file_and_are_not_aggregated(tmp_path):
    log, _ = _log(tmp_path)
    for _ in range(3):
        log({"event_type": "knowledge.lookup", "technique_ids": ["T1110"], "count": 1})
    assert not log.path.exists()
    assert log.events_path == tmp_path / "events.jsonl"
    assert len(_lines(log.events_path)) == 3


def test_a_lookup_flood_never_rotates_a_refusal_line_away(tmp_path):
    log, _ = _log(tmp_path, max_bytes=1024, keep=2)
    log(_refusal(uid=7, reason="principal_denied"))
    for _ in range(2000):
        log({"event_type": "knowledge.lookup", "technique_ids": ["T1110"], "count": 1})
    assert log.counters()["rotations"] > 2
    assert [line["uid"] for line in _lines(log.path)] == [7]
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "events.jsonl", "events.jsonl.1", "events.jsonl.2", "refusals.jsonl"]
    assert all(path.stat().st_size <= 1024 for path in tmp_path.iterdir())


def test_a_summary_names_the_last_suppressed_fingerprint_and_verb(tmp_path):
    log, clock = _log(tmp_path, window_s=60)
    log(_refusal(reason="principal_denied", verb="watchdog.probe"))
    log(_refusal(reason="principal_denied", verb="watchdog.probe", request_fingerprint="a" * 16))
    log(_refusal(reason="principal_denied", request_fingerprint="b" * 16, verb="watchdog.status"))
    clock.now += 60
    log.flush_due()
    summary = _lines(log.path)[-1]
    assert summary["suppressed"] == 2
    assert summary["last_request_fingerprint"] == "b" * 16
    assert summary["last_verb"] == "watchdog.status"


def test_tracked_keys_are_bounded_and_an_evicted_count_is_written(tmp_path):
    log, _ = _log(tmp_path, max_keys=2)
    log(_refusal(uid=1))
    log(_refusal(uid=1))
    log(_refusal(uid=2))
    log(_refusal(uid=3))  # evicts uid 1, whose one suppressed refusal is summarized
    assert len(log._windows) == 2
    kinds = [(line["event_type"], line["uid"]) for line in _lines(log.path)]
    assert kinds == [(REFUSAL_EVENT, 1), (REFUSAL_EVENT, 2),
                     (REFUSAL_SUMMARY_EVENT, 1), (REFUSAL_EVENT, 3)]


def test_rotation_keeps_at_most_n_files_of_at_most_the_cap(tmp_path):
    previous = os.umask(0o027)
    try:
        log, _ = _log(tmp_path, max_bytes=1024, keep=2, max_keys=1000)
        for uid in range(400):  # distinct keys: every one is written
            log(_refusal(uid=uid))
    finally:
        os.umask(previous)
    names = sorted(path.name for path in tmp_path.iterdir())
    assert names == ["refusals.jsonl", "refusals.jsonl.1", "refusals.jsonl.2"]
    for path in tmp_path.iterdir():
        assert path.stat().st_size <= 1024
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
        assert all(line["event_type"] == REFUSAL_EVENT for line in _lines(path))
    # The newest refusals survive; the oldest file was deleted.
    assert _lines(log.path)[-1]["uid"] == 399
    assert _lines(tmp_path / "refusals.jsonl.2")[0]["uid"] > 0
    assert log.counters()["rotations"] > 2
    assert log.counters()["unrecorded"] == 0


def test_keep_zero_truncates_by_replacement(tmp_path):
    log, _ = _log(tmp_path, max_bytes=512, keep=0)
    for uid in range(50):
        log(_refusal(uid=uid))
    assert [path.name for path in tmp_path.iterdir()] == ["refusals.jsonl"]
    assert log.path.stat().st_size <= 512


def test_a_failure_to_log_is_counted_never_raised(tmp_path):
    log = BoundedRefusalLog(tmp_path / "missing" / "refusals.jsonl")
    log(_refusal())
    log({"event_type": "knowledge.lookup"})
    log.flush_due()
    assert log.counters()["unrecorded"] == 2
    assert log.counters()["written"] == 0


def test_a_lost_summary_counts_every_refusal_it_stood_for(tmp_path):
    directory = tmp_path / "leaf"
    directory.mkdir()
    clock = Clock()
    log = BoundedRefusalLog(directory / "refusals.jsonl", clock=clock)
    for _ in range(5):
        log(_refusal())
    (directory / "refusals.jsonl").unlink()
    directory.rmdir()
    clock.now += 60
    log.flush_due()
    assert log.counters() == {"written": 1, "suppressed": 4, "unrecorded": 4, "rotations": 0}


def test_a_symlink_is_not_followed(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("", encoding="utf-8")
    (tmp_path / "refusals.jsonl").symlink_to(target)
    log, _ = _log(tmp_path)
    log(_refusal())
    assert target.read_text(encoding="utf-8") == ""
    assert log.counters()["unrecorded"] == 1


def test_bounds_must_be_positive(tmp_path):
    for kwargs in ({"max_bytes": 0}, {"keep": -1}, {"window_s": 0}, {"max_keys": 0}):
        with pytest.raises(ValueError):
            BoundedRefusalLog(tmp_path / "refusals.jsonl", **kwargs)


def test_every_daemon_sink_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    for service in ("audit", "knowledge", "commission", "watchdog", "fetch"):
        sink = runtime_paths.audit_sink(service)
        assert isinstance(sink, BoundedRefusalLog)
        assert sink.path.name == "refusals.jsonl"
        assert sink.max_bytes == REFUSAL_LOG_MAX_BYTES and sink.keep == REFUSAL_LOG_KEEP


def test_auditd_summarized_sink_keeps_the_bounded_log_reachable(tmp_path):
    log, _ = _log(tmp_path)
    sink = summarized_refusals(log)
    sink(_refusal(reason="rate_limited"))
    sink(_refusal())
    sink.flush_due()
    assert sink.counters()["written"] == 1
    assert [line["reason"] for line in _lines(log.path)] == ["malformed_frame"]


def test_the_serve_loop_flushes_due_summaries_between_connections(tmp_path, monkeypatch):
    class Listener:
        def settimeout(self, _):
            pass

        def accept(self):
            raise TimeoutError

        def close(self):
            pass

    class Sink:
        flushes = 0

        def __call__(self, event):
            pass

        def flush_due(self):
            Sink.flushes += 1

    monkeypatch.setattr(serve, "bind_socket", lambda path, expected_gid=None: Listener())
    stops = iter([False, False, False, True])
    serve.serve_forever(path=tmp_path / "x.sock", registry=None, policy=object(),
                        audit=Sink(), handler=lambda request: None,
                        stop=lambda: next(stops))
    assert Sink.flushes == 3
