"""auditd's operator-readable capacity snapshot and the status `audit` line (#211).

What must hold: auditd writes a bounded, closed-shape snapshot that carries no
record content and no uid; a missing leaf never stops auditd; the reader
refuses anything outside the shape; and status says absent, stale and
warning honestly instead of turning them into health. Nothing is deleted.
"""

from __future__ import annotations

import io
import json
import stat

import pytest
from azazel_nexus import audit_status
from azazel_nexus.audit_status import (
    RATE_LIMITED_KEYS,
    STATUS_BYTES,
    STATUS_INTERVAL_S,
    STATUS_SCHEMA,
    STATUS_STALE_S,
    audit_health,
    read_audit_status,
)
from azazel_nexus.cli import main
from azazel_nexus_runtime import auditd, runtime_paths
from azazel_nexus_runtime.auditd import AuditService, SegmentedLedger
from test_runtime_auditd_limits import (
    _incident,
    _refused,
    _service,
)
from test_wizard_and_cli import _tree


def _with_status(tmp_path, monkeypatch, **kwargs):
    service, clocks = _service(tmp_path, monkeypatch, **kwargs)
    leaf = tmp_path / "run/audit-status"
    leaf.mkdir(parents=True)
    service.status_path = leaf / "status.json"
    return service, clocks


def _read(service):
    return read_audit_status(service.status_path.read_bytes())


def _no_uid(value):
    """The writer's uid (901) is no key and no string anywhere in the snapshot.

    Sizes are numbers that may contain those digits by chance, so only keys
    and strings are searched.
    """

    def walk(item):
        if isinstance(item, dict):
            for key, inner in item.items():
                assert "901" not in key
                walk(inner)
        elif isinstance(item, list):
            for inner in item:
                walk(inner)
        elif isinstance(item, str):
            assert "901" not in item
    walk(value)


def _snapshot(**overrides):
    value = {"schema": STATUS_SCHEMA, "written_at": 1000.0, "chain_verified": True,
             "chain_bytes": 4096, "segments": 2, "filesystem_free_bytes": 50 << 30,
             "warning": False, "warning_reasons": [], "warn_chain_bytes": 1 << 30,
             "warn_free_bytes": 1 << 30, "rate_limited": {},
             "rate_limit_summaries_dropped": 0}
    value.update(overrides)
    return value


def _raw(value):
    return json.dumps(value).encode()


# -- the writer -------------------------------------------------------------


def test_auditd_writes_a_readable_snapshot_without_record_content(tmp_path, monkeypatch):
    service, clocks = _with_status(tmp_path, monkeypatch)
    _incident(service, clocks)
    service.write_status()
    value = _read(service)
    assert value is not None
    assert value["chain_verified"] is True and value["segments"] == 1
    assert value["chain_bytes"] == sum(p.stat().st_size for p in service.ledger.segments())
    assert value["written_at"] == clocks.wall
    assert value["warn_chain_bytes"] == auditd.CAPACITY_WARN_CHAIN_BYTES
    assert value["warn_free_bytes"] == auditd.CAPACITY_WARN_FREE_BYTES
    raw = service.status_path.read_text()
    assert "inc-" not in raw and "occurred_at" not in raw
    _no_uid(value)
    assert stat.S_IMODE(service.status_path.stat().st_mode) == 0o640
    # Only the snapshot is left in the leaf: no temp files.
    assert [p.name for p in service.status_path.parent.iterdir()] == ["status.json"]


def test_rate_limited_totals_reach_the_snapshot_by_class_not_uid(tmp_path, monkeypatch):
    service, clocks = _with_status(tmp_path, monkeypatch)
    monkeypatch.setattr(auditd, "INCIDENT_RATE", auditd.RateLimit(burst=1, per_second=0.0))
    _incident(service, clocks)
    assert _refused(lambda: _incident(service, clocks)) == "rate"
    service.write_status()
    value = _read(service)
    assert value["rate_limited"] == {"rate:edge.incident.opened:ordinary": 1}
    _no_uid(value)


def test_the_snapshot_is_bounded_however_many_keys_are_limited(tmp_path, monkeypatch):
    service, _ = _with_status(tmp_path, monkeypatch)
    # More keys than auditd can produce today, each with the longest event
    # type and count the reader admits: the worst case still fits.
    for index in range(2 * RATE_LIMITED_KEYS):
        event_type = f"t{index:03d}".ljust(64, "x")
        service.rate_limited[f"daily:{event_type}:ordinary"] = 2**63 - 1 - index
    service.summaries_dropped = 2**63 - 1
    service.write_status()
    raw = service.status_path.read_bytes()
    assert len(raw) <= STATUS_BYTES
    value = read_audit_status(raw)
    assert value is not None and len(value["rate_limited"]) == RATE_LIMITED_KEYS
    # The largest counts are the ones kept.
    assert min(value["rate_limited"].values()) >= max(
        v for k, v in service.rate_limited.items() if k not in value["rate_limited"])


def test_a_capacity_warning_is_in_the_snapshot_and_nothing_is_deleted(tmp_path, monkeypatch):
    service, clocks = _with_status(tmp_path, monkeypatch)
    _incident(service, clocks)
    before = [p.read_bytes() for p in service.ledger.segments()]
    monkeypatch.setattr(auditd, "CAPACITY_WARN_CHAIN_BYTES", 1)
    service.write_status()
    value = _read(service)
    assert value["warning"] is True and value["warning_reasons"][0] == "chain_size"
    assert [p.read_bytes() for p in service.ledger.segments()] == before


def test_the_tick_rewrites_the_snapshot_every_interval(tmp_path, monkeypatch):
    service, clocks = _with_status(tmp_path, monkeypatch)
    service.tick()
    first = _read(service)["written_at"]
    clocks.advance(STATUS_INTERVAL_S - 1)
    service.tick()
    assert _read(service)["written_at"] == first
    monkeypatch.setattr(auditd, "CAPACITY_WARN_FREE_BYTES", 2**63 - 1)
    clocks.advance(1)
    service.tick()
    value = _read(service)
    # The warning turning on shows within one interval.
    assert value["written_at"] == first + STATUS_INTERVAL_S
    assert value["warning_reasons"] == ["filesystem_free"]


def test_a_missing_leaf_is_logged_once_and_auditd_keeps_working(tmp_path, monkeypatch, private_os):
    private_os(auditd)
    warnings = []
    service, clocks = _service(tmp_path, monkeypatch, warnings=warnings)
    service.status_path = tmp_path / "run/audit-status/status.json"  # never created
    service.write_status()
    for _ in range(3):
        clocks.advance(STATUS_INTERVAL_S)
        service.tick()
    assert len(warnings) == 1
    assert "install.sh" in warnings[0] and "FileNotFoundError" in warnings[0]
    assert _incident(service, clocks)["sequence"] == 1
    # Once the leaf exists the snapshot resumes, and a later failure is
    # logged again.
    service.status_path.parent.mkdir(parents=True)
    clocks.advance(STATUS_INTERVAL_S)
    service.tick()
    assert _read(service) is not None and len(warnings) == 1
    def refuse(*_):
        raise PermissionError("read-only")
    monkeypatch.setattr(auditd.os, "replace", refuse)
    service.write_status()
    assert len(warnings) == 2 and "PermissionError" in warnings[1]
    assert [p.name for p in service.status_path.parent.iterdir()] == ["status.json"]


def test_a_broken_chain_is_in_the_snapshot(tmp_path, monkeypatch):
    service, clocks = _with_status(tmp_path, monkeypatch)
    _incident(service, clocks)
    segment = service.ledger.segments()[0]
    segment.write_text(segment.read_text().replace('"count":1', '"count":2'))
    service.start()
    assert service.verified is False
    service.write_status()
    assert _read(service)["chain_verified"] is False


def test_main_writes_the_snapshot_before_serving(tmp_path, monkeypatch):

    from azazel_nexus_runtime import principal, serve
    seen = {}

    def fake_serve(**kwargs):
        seen["snapshot"] = (tmp_path / "audit-status/status.json").exists()
        return 0

    monkeypatch.setattr(serve, "serve_forever", fake_serve)
    (tmp_path / "ledger").mkdir()
    (tmp_path / "audit-status").mkdir()
    monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path / "ledger")
    monkeypatch.setattr(runtime_paths, "audit_status_path",
                        lambda: tmp_path / "audit-status/status.json")
    monkeypatch.setattr(runtime_paths, "dedicated_listener",
                        lambda name, registry: (tmp_path / f"{name}.sock", 0, registry))
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda _: lambda event: None)
    monkeypatch.setattr(auditd.pwd, "getpwnam", _explainer_account(901))
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", classmethod(lambda cls, **_: None))
    assert auditd.main([], ready=lambda: None) == 0
    assert seen == {"snapshot": True}


def test_main_serves_when_the_leaf_is_missing(tmp_path, monkeypatch, capsys):

    from azazel_nexus_runtime import principal, serve
    monkeypatch.setattr(serve, "serve_forever", lambda **_: 0)
    (tmp_path / "ledger").mkdir()
    monkeypatch.setattr(runtime_paths, "ledger_dir", lambda: tmp_path / "ledger")
    monkeypatch.setattr(runtime_paths, "audit_status_path",
                        lambda: tmp_path / "audit-status/status.json")
    monkeypatch.setattr(runtime_paths, "dedicated_listener",
                        lambda name, registry: (tmp_path / f"{name}.sock", 0, registry))
    monkeypatch.setattr(runtime_paths, "audit_sink", lambda _: lambda event: None)
    monkeypatch.setattr(auditd.pwd, "getpwnam", _explainer_account(901))
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", classmethod(lambda cls, **_: None))
    assert auditd.main([], ready=lambda: None) == 0
    assert capsys.readouterr().err.count("cannot write") == 1


def test_a_service_without_a_status_path_writes_nothing(tmp_path, monkeypatch):
    service = AuditService(SegmentedLedger(tmp_path), warn=pytest.fail)
    service.write_status()
    service.tick()
    assert list(tmp_path.iterdir()) == []


# -- the reader -------------------------------------------------------------


def test_the_reader_accepts_the_declared_shape_only():
    assert read_audit_status(_raw(_snapshot())) is not None
    assert read_audit_status(_raw(_snapshot(filesystem_free_bytes=None))) is not None
    refused = [
        {"schema": "azazel-nexus/audit-status/v2"},
        {"extra": 1},
        {"chain_verified": 1},
        {"chain_bytes": -1},
        {"chain_bytes": 1.5},
        {"segments": True},
        {"written_at": float("inf")},
        {"written_at": "now"},
        # Reasons must be exactly what the numbers imply.
        {"warning": True},
        {"warning_reasons": ["chain_size"]},
        {"chain_bytes": 1 << 30},
        {"filesystem_free_bytes": 1},
        {"rate_limited": {"rate:edge.incident.opened:ordinary": -1}},
        {"rate_limited": {"rate:edge.incident.opened:uid-901": 1}},
        {"rate_limited": {"rate:Edge Incident:ordinary": 1}},
        {"rate_limited": {f"rate:t{i}:service": 1 for i in range(RATE_LIMITED_KEYS + 1)}},
        {"rate_limited": []},
    ]
    for change in refused:
        assert read_audit_status(_raw(_snapshot(**change))) is None, change
    missing = _snapshot()
    del missing["segments"]
    assert read_audit_status(_raw(missing)) is None
    assert read_audit_status(b'{"schema": 1, "schema": 2}') is None
    assert read_audit_status(b"\xff") is None
    assert read_audit_status(b"x" * (STATUS_BYTES + 1)) is None
    assert read_audit_status("text") is None
    ok = _snapshot(chain_bytes=1 << 30, warning=True, warning_reasons=["chain_size"])
    assert read_audit_status(_raw(ok)) is not None


def test_health_is_unknown_when_absent_stale_or_without_a_clock():
    healthy, detail, advisory = audit_health(None, 1000)
    assert healthy is None and "install.sh" in detail and "not inspected" in detail
    assert advisory is None
    value = _snapshot()
    healthy, detail, _ = audit_health(value, 1000.0 + STATUS_STALE_S + 1)
    assert healthy is None and "stale" in detail and "last snapshot: chain 4.0 KiB" in detail
    healthy, detail, _ = audit_health(value, 1000.0 - 60)
    assert healthy is None and "future" in detail
    healthy, detail, _ = audit_health(value, None)
    assert healthy is None and "age unknown" in detail
    # A stale warning is still shown, labelled as the last snapshot's, and is
    # not turned into a current next action.
    warn = _snapshot(chain_bytes=2 << 30, warning=True, warning_reasons=["chain_size"])
    healthy, detail, advisory = audit_health(warn, 1000.0 + STATUS_STALE_S + 1)
    assert healthy is None and "capacity warning (chain_size)" in detail and advisory is None


def test_health_reports_fresh_values_warning_and_broken_chain():
    healthy, detail, advisory = audit_health(_snapshot(), 1012.0)
    assert healthy is True and advisory is None
    assert detail == ("chain verified at auditd start; chain 4.0 KiB in 2 segment(s); "
                      "50.0 GiB free on its filesystem; warns at >= 1.0 GiB chain or "
                      "< 1.0 GiB free; rate_limited: none (snapshot 12s old)")
    warn = _snapshot(filesystem_free_bytes=5 << 20, warning=True,
                     warning_reasons=["filesystem_free"],
                     rate_limited={"rate:edge.incident.opened:ordinary": 7,
                                   "daily:edge.incident.closed:ordinary": 2},
                     rate_limit_summaries_dropped=3)
    healthy, detail, advisory = audit_health(warn, 1000.0)
    # A capacity warning is not a failure: ok, with the warning stated first.
    assert healthy is True
    assert detail.startswith("WARNING: capacity warning (filesystem_free): nothing is deleted")
    assert advisory.startswith("capacity warning (filesystem_free): nothing is deleted")
    assert "5.0 MiB free" in detail
    assert ("rate_limited: 9 (rate:edge.incident.opened:ordinary=7, "
            "daily:edge.incident.closed:ordinary=2); summaries dropped: 3") in detail
    # FAILED is reserved for a chain that did not verify at auditd's start.
    healthy, detail, advisory = audit_health(_snapshot(chain_verified=False), 1000.0)
    assert healthy is False and detail.startswith("chain did not verify at auditd start")
    assert advisory is None


# -- the status screen ---------------------------------------------------------


def _health(tmp_path, monkeypatch, value=None, *, as_of="1970-01-01T00:16:50Z"):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    if value is not None:
        path = tmp_path / "var/lib/azazel/run/audit-status/status.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_raw(value) if isinstance(value, dict) else value)
    out = io.StringIO()
    main(["--sysfs", str(_tree(tmp_path)), "--as-of", as_of, "health"], out=out)
    return out.getvalue()


def test_status_shows_a_fresh_snapshot(tmp_path, monkeypatch):
    text = _health(tmp_path, monkeypatch, _snapshot())  # as of 1010
    assert "    audit: ok -- chain verified at auditd start; chain 4.0 KiB" in text
    assert "(snapshot 10s old)" in text
    assert "audit chain: unknown" not in text


def test_status_says_absent_refused_and_stale_honestly(tmp_path, monkeypatch):
    assert "    audit: unknown -- no readable auditd status snapshot" in _health(
        tmp_path / "absent", monkeypatch)
    assert "    audit: unknown -- no readable auditd status snapshot" in _health(
        tmp_path / "refused", monkeypatch, b"{not json")
    stale = _health(tmp_path / "stale", monkeypatch, _snapshot(), as_of="1970-01-01T01:00:00Z")
    assert "    audit: unknown -- auditd status snapshot is stale" in stale


def test_a_capacity_warning_is_ok_with_a_note_and_a_next_action(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    path = tmp_path / "var/lib/azazel/run/audit-status/status.json"
    path.parent.mkdir(parents=True)
    from test_wizard_and_cli import _status
    # `_status` runs as of 2026-09-21T00:00:00Z; the snapshot is 5 s older.
    path.write_bytes(_raw(_snapshot(chain_bytes=2 << 30, warning=True,
                                    warning_reasons=["chain_size"], written_at=1789948795)))
    text = _status(tmp_path)
    assert "    audit: ok -- WARNING: capacity warning (chain_size): nothing is deleted" in text
    assert "audit: FAILED" not in text
    assert text.index("    audit: capacity warning (chain_size)") > text.index("next:")


def test_a_broken_chain_is_failed_and_a_next_action(tmp_path, monkeypatch):
    text = _health(tmp_path, monkeypatch, _snapshot(chain_verified=False))
    assert "    audit: FAILED -- chain did not verify at auditd start" in text


def test_a_reader_fault_never_stops_the_health_section(tmp_path, monkeypatch):
    def boom(*_):
        raise RuntimeError("x")
    monkeypatch.setattr(audit_status, "audit_health", boom)
    text = _health(tmp_path, monkeypatch, _snapshot())
    assert "    audit: unknown -- auditd status snapshot unavailable (internal)" in text


def test_temp_files_a_killed_predecessor_left_are_removed_once(tmp_path, monkeypatch):
    service, clocks = _with_status(tmp_path, monkeypatch)
    leaf = service.status_path.parent
    (leaf / ".status-abandoned").write_text("partial")
    (leaf / "other").write_text("kept")
    service.write_status()
    assert sorted(p.name for p in leaf.iterdir()) == ["other", "status.json"]
    assert _read(service) is not None


def _explainer_account(uid):
    """`pwd.getpwnam` resolving only azexplain; other accounts are absent.

    auditd binds Knowledge Lite event types to azknowledge and azcommission
    in both directions (P4); a stub that gave every account the explainer's
    uid would make the explainer those writers too.
    """
    import types

    def getpwnam(name):
        if name != "azexplain":
            raise KeyError(name)
        return types.SimpleNamespace(pw_uid=uid)

    return getpwnam
