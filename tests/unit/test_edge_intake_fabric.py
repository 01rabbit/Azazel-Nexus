"""The optional export is a reference, never a prerequisite for local evidence."""

import pytest
from test_edge_intake import parsed

from azazel_nexus.edge_intake import EvidenceRecord
from azazel_nexus.fabric_boundary import FABRIC_PIN, project_edge_evidence


def test_edge_evidence_reference():
    fabric = pytest.importorskip("azazel_fabric")
    if fabric.__version__ != FABRIC_PIN.lstrip("v"):
        pytest.skip("pinned Fabric required")
    record = EvidenceRecord.receive(parsed(), lambda: 0)
    projection = project_edge_evidence(record)
    assert projection.available
    assert projection.view.model_dump() == {
        "evidence_id": record.digest,
        "source": "edge-core",
        "trace_id": "trace-1",
        "observed_at": "1970-01-01T00:00:00Z",
    }


def test_absent_fabric_does_not_prevent_evidence(monkeypatch):
    from azazel_nexus import fabric_boundary

    monkeypatch.setattr(
        fabric_boundary, "_import_fabric", lambda: (None, "unavailable")
    )
    record = EvidenceRecord.receive(parsed(), lambda: 0)
    result = project_edge_evidence(record)
    assert not result.available
    assert result.reason == "unavailable"
    assert record.digest.startswith("sha256:")
