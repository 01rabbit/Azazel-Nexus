"""Synthetic historical capability observations; never hardware evidence."""

import pytest

from azazel_nexus.audit import AuditLedger
from azazel_nexus.mio_status import ROUTE_LEDGER, describe, status_summary


@pytest.mark.parametrize("ceiling", ["CORE", "LITE", "FULL"])
def test_last_transition_ceiling_is_separate_from_capability(tmp_path, ceiling):
    path = tmp_path / ROUTE_LEDGER.lstrip("/")
    path.parent.mkdir(parents=True)
    ledger = AuditLedger(path)
    for profile in ("CORE", ceiling):
        ledger.append({"event_type": "mio.capability.transition", "to": "CORE",
                       "occurred_at": "2026-10-19T00:00:00Z",
                       "reasons": {"profile": profile, "resource": "core_reserve_unmeasured"}})
    ledger.append({"event_type": "mio.route"})
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    reading = status_summary(root=tmp_path)
    assert reading["ceiling"] == ceiling
    assert reading["state"] == "CORE"
    text = describe(reading)
    assert "core_reserve_unmeasured" in text
    assert "not a grant or admission" in text
    assert "last recorded observation" in text
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize("case", ["missing", "empty", "broken", "malformed", "permission"])
def test_unknown_evidence_never_infers_from_ram(tmp_path, monkeypatch, case):
    path = tmp_path / ROUTE_LEDGER.lstrip("/")
    path.parent.mkdir(parents=True)
    if case == "empty":
        path.touch()
    elif case == "broken":
        path.write_text("not a ledger")
    elif case == "malformed":
        AuditLedger(path).append({"event_type": "mio.capability.transition", "to": "FULL", "reasons": {}})
    elif case == "permission":
        path.touch()
        def denied(self):
            raise PermissionError("secret path")
        monkeypatch.setattr(AuditLedger, "__iter__", denied)
    reading = status_summary(root=tmp_path)
    assert reading["state"] is None and reading["ceiling"] is None
    assert "unknown" in reading["availability"]
    assert "secret" not in str(reading)
