"""Raw snapshot inputs for the systemd rehearsal, built by the product's own
builders and the status read-model test builders (fixtures, not daemons)."""
import json, sys, tempfile, pathlib
sys.path.insert(0, "/w/tests/unit")
import test_status_view as tsv
import test_operator_snapshots as tos
from azazel_nexus import operator_snapshots as snap
out = pathlib.Path(sys.argv[1]); out.mkdir(exist_ok=True)
NOW = tsv.NOW
with tempfile.TemporaryDirectory() as d:
    values = {
        "audit_status": tsv._audit(NOW),
        "edge_intake_status": tsv._intake(NOW, open_incidents=2),
        "incident_explain_status": tsv._explainer(pathlib.Path(d), NOW),
        "incident_recent": tsv._recent(NOW),
        # What knowledge-lited writes on a node without a commissioned trust.
        "knowledge_status": snap.knowledge_snapshot({"state": "unavailable", "reason_code": "trust_unreadable",
                                                     "generation": None, "freshness": "absent"}, NOW),
        "mio_status": tos._mio(),
    }
for name, value in values.items():
    (out / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
(out / "NOW").write_text(str(NOW))
print(sorted(values))
