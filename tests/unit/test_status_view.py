"""`azazel-nexus status` as a read model (U1): golden text and the JSON view.

The text an operator reads is rendered from the read model
(`azazel_nexus.status_view`). The golden files under
`tests/fixtures/status-view/` were written by the renderer **before** it was
moved onto the read model, so a byte-for-byte match is what says the move
changed no wording and no behaviour. Regenerate them only for a deliberate
wording change, and review the diff as a wording change.

Every scenario is built from fixed inputs: the clock (`--as-of`), the sysfs
tree, the snapshots, the profile reading, Fabric's projection and the lab-host
marker. `tmp_path` is the only varying part and is replaced by `<TMP>`.
"""

from __future__ import annotations

import io
import json
import os
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus.cli import main

GOLDEN = Path(__file__).resolve().parents[1] / "fixtures" / "status-view"
AS_OF = "2026-09-21T04:01:00Z"
NOW = datetime.fromisoformat(AS_OF).timestamp()
BOOT = "0f0e0d0c-0b0a-4908-8706-050403020100"


@pytest.fixture(autouse=True)
def probe_account(monkeypatch):
    monkeypatch.setattr("azazel_nexus.edge_package._probe_owner_uid", os.geteuid)


# -- inputs --------------------------------------------------------------


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")


def _intake(written_at, **extra):
    from azazel_nexus.edge_intake import STATUS_SCHEMA

    value = {"schema": STATUS_SCHEMA, "written_at": written_at, "last_accepted_at": NOW - 40,
             "accepted": 12, "processed": 15, "last_processed_at": NOW - 35,
             "refused": {"queue_full": 2, "EDGE_JSON": 5, "EDGE_SHAPE": 4, "overloaded": 3,
                         "read_error": 3, "evidence_segment_full": 1, "DECOY_JSON": 2,
                         "decoy_rate_limited": 1},
             "open_incidents": 1, "queue_drops": 2, "storage_failed": False}
    value.update(extra)
    return value


def _explainer(tmp_path, written_at, **extra):
    from test_incident_explaind import make

    base = tmp_path / "explainer-fixture"
    base.mkdir(exist_ok=True)
    value = make(base).snapshot()
    value.update(written_at=written_at, **extra)
    return value


def _recent(written_at):
    from azazel_nexus.incident_explain import build_recent_incident, build_recent_incidents
    from azazel_nexus.local_advisory import HANDOFF_NOTICE
    from test_incident_explain import transition

    explained = build_recent_incident(transition(edge_would="isolate", incident_id="inc-00000000000000a1",
                                                 first_seen=NOW - 300, last_seen=NOW - 20))
    explained["explanation"] = {
        "state": "explained", "route": "local", "outcome": "answered",
        "summary": "Inspect the interpreter launch", "failure_codes": [],
        "content_kind": "ai_advice",
        "knowledge_refs": [{"technique_id": "T1059", "name": "Command and Scripting Interpreter",
                            "claim_id": "T1059"}]}
    notice = build_recent_incident(transition(edge_would="notify", incident_id="inc-00000000000000b2",
                                              first_seen=NOW - 600, last_seen=NOW - 120))
    notice["state"] = "closed"
    notice["explanation"] = {
        "state": "notice_shown", "route": "deterministic handoff", "outcome": "unavailable",
        "summary": "", "failure_codes": [], "knowledge_refs": [],
        "content_kind": "deterministic_notice", "notice": HANDOFF_NOTICE["en"]}
    notice["evidence_stored"] = False
    pending = build_recent_incident(transition(edge_would="observe", incident_id="inc-00000000000000c3",
                                               first_seen=NOW - 900, last_seen=NOW - 800))
    return build_recent_incidents([explained, notice, pending], written_at)


def _audit(written_at, *, verified=True):
    from azazel_nexus.audit_status import STATUS_SCHEMA, warning_reasons

    chain, free, warn_chain, warn_free = 3 << 30, 1 << 30, 2 << 30, 2 << 30
    reasons = warning_reasons(chain, free, warn_chain, warn_free)
    return {"schema": STATUS_SCHEMA, "written_at": written_at, "chain_verified": verified,
            "chain_bytes": chain, "segments": 3, "filesystem_free_bytes": free,
            "warning": bool(reasons), "warning_reasons": reasons,
            "warn_chain_bytes": warn_chain, "warn_free_bytes": warn_free,
            "rate_limited": {"daily:edge.alert:ordinary": 4, "rate:mio.request:service": 2},
            "rate_limit_summaries_dropped": 1}


def _snapshots(tmp_path, *, intake=None, explainer=None, recent=None, audit=None):
    from azazel_nexus import runtime_paths as paths

    for path, value in ((paths.edge_intake_status_path(), intake),
                        (paths.incident_explain_status_path(), explainer),
                        (paths.incident_recent_path(), recent),
                        (paths.audit_status_path(), audit)):
        if value is not None:
            _write(path, value)


def _measured(monkeypatch):
    from azazel_nexus import cli
    from azazel_nexus.resource_profile import ResourceReading, select_profile

    monkeypatch.setattr(cli, "take_reading",
                        lambda: ResourceReading(usable_mib=7800, profile=select_profile(7800)))


def _unmeasured(monkeypatch):
    from azazel_nexus import cli
    from azazel_nexus.resource_profile import UsableMemoryUnavailable

    def fail():
        raise UsableMemoryUnavailable("MemAvailable could not be read from /proc/meminfo (test)")
    monkeypatch.setattr(cli, "take_reading", fail)


def _fabric(monkeypatch, outcome):
    from azazel_nexus import fabric_boundary

    def project(state, available):
        if outcome == "refused":
            raise ValueError("SECRET 192.0.2.1")
        if outcome == "absent":
            return SimpleNamespace(available=False, fabric_version=None)
        return SimpleNamespace(available=True, fabric_version=outcome)
    monkeypatch.setattr(fabric_boundary, "project_capability", project)


def _lab_host(tmp_path, monkeypatch, present):
    from azazel_nexus import lab_host

    marker = tmp_path / "etc-azazel-lab" / "LAB-HOST"
    if present:
        _write(marker, "")
    monkeypatch.setattr(lab_host, "LAB_HOST_MARKER", marker)


def _boot(monkeypatch, readable=True):
    from azazel_nexus import cli
    from azazel_nexus.edge_package import EdgePackageRefused

    def reader():
        if not readable:
            raise EdgePackageRefused("the boot id could not be read: test")
        return BOOT
    monkeypatch.setattr(cli, "read_current_boot_id", reader)


def _fixed_storage(monkeypatch):
    """Free space is the host's; every scenario measures a fixed filesystem."""
    from azazel_nexus import status_view

    usage = SimpleNamespace(f_blocks=1000, f_bfree=600, f_bavail=500, f_frsize=4096, f_flag=0)
    monkeypatch.setattr(status_view, "_storage_probes",
                        (lambda path: usage, lambda path: SimpleNamespace(st_dev=7)))


def _base(tmp_path, monkeypatch, *, lab=False, fabric="absent", measured=True):
    monkeypatch.setattr("azazel_nexus.edge_package._probe_owner_uid", os.geteuid)
    _fixed_storage(monkeypatch)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    _lab_host(tmp_path, monkeypatch, lab)
    _fabric(monkeypatch, fabric)
    (_measured if measured else _unmeasured)(monkeypatch)
    _boot(monkeypatch)


def _argv(tmp_path, *extra, edge_root=None, probe=None, json_flag=False):
    from test_wizard_and_cli import _tree

    return ["--sysfs", str(_tree(tmp_path)),
            "--edge-root", str(edge_root or tmp_path / "edge-root"),
            "--edge-probe", str(probe or tmp_path / "edge-probe-absent.json"),
            "--knowledge-lite", "/nonexistent/knowledge-lite",
            "--as-of", AS_OF, *extra, "status", *(["--json"] if json_flag else [])]


# -- scenarios -----------------------------------------------------------


def _absent(tmp_path, monkeypatch):
    """Nothing written by any daemon; no profile; Fabric refuses."""
    _base(tmp_path, monkeypatch, fabric="refused", measured=False)
    return {}


def _loop(tmp_path, monkeypatch):
    """Every snapshot fresh; forwarder and decoy reported; chain broken."""
    _base(tmp_path, monkeypatch, fabric="0.10.0")
    _snapshots(
        tmp_path,
        intake=_intake(NOW - 5, ledger_recovered=1,
                       edge_forward={"dropped": 1, "failed": 2, "sent": 40, "since": 1789900000,
                                     "reported_at": NOW - 1000, "restarts": 1},
                       decoy={"accepted": 3, "last_accepted_at": NOW - 7}),
        explainer=_explainer(tmp_path, NOW - 3, chain_broken=True, mio_available=False,
                             knowledge_available=True,
                             recovery_hint="inspect_incident_chain_then_remove_cursor_and_restart",
                             refused={"mio_reply_refused": 2}),
        recent=_recent(NOW - 2),
        audit=_audit(NOW - 20))
    return {}


def _stale(tmp_path, monkeypatch):
    """Snapshots too old, or dated in the future; the decoy closed."""
    _base(tmp_path, monkeypatch)
    _snapshots(tmp_path, intake=_intake(NOW + 60),
               explainer=_explainer(tmp_path, NOW - 31),
               recent=_recent(NOW - 120), audit=_audit(NOW - 301, verified=False))
    return {}


def _refused(tmp_path, monkeypatch):
    """Snapshots present and refused: malformed, oversized, a directory."""
    from azazel_nexus import runtime_paths as paths

    _base(tmp_path, monkeypatch)
    _write(paths.edge_intake_status_path(), "{")
    _write(paths.incident_recent_path(), "x" * (256 * 1024 + 1))
    paths.incident_explain_status_path().mkdir(parents=True, exist_ok=True)
    _write(paths.audit_status_path(), {"schema": "foreign"})
    _write(tmp_path / "edge-probe-garbage.json", "not a probe result")
    (tmp_path / "edge-probe-garbage.json").chmod(0o644)
    return {"probe": tmp_path / "edge-probe-garbage.json"}


def _edge_ready(tmp_path, monkeypatch):
    """A verified package and a fresh probe result, on a lab host."""
    from test_wizard_and_cli import _probe_state, _verified_package

    _base(tmp_path, monkeypatch, lab=True)
    root, digest = _verified_package(tmp_path)
    probe = _probe_state(tmp_path, digest)
    probe.chmod(0o644)  # the reader refuses a group-writable result; umask is not ours
    return {"edge_root": root, "probe": probe}


def _edge_tampered_no_boot(tmp_path, monkeypatch):
    """A digest mismatch, and a probe result whose boot cannot be checked."""
    from test_wizard_and_cli import _probe_state, _tampered_package

    _base(tmp_path, monkeypatch)
    _boot(monkeypatch, readable=False)
    root = _tampered_package(tmp_path)
    probe = _probe_state(tmp_path, "sha256:" + "0" * 64)
    probe.chmod(0o644)
    return {"edge_root": root, "probe": probe}


def _issuer_authenticated(tmp_path, monkeypatch):
    """A verified package whose issuer is authenticated, with revocations in force.

    The inspection is the real one, with an authenticated issuer result put in
    its place at the `cli.inspect_edge` seam: the renderer is what is under
    test, and the issuer chain has its own tests (`test_edge_issuer.py`).
    """
    from dataclasses import replace

    from azazel_nexus import cli
    from azazel_nexus.edge_issuer import NOTE_STATE_UNPROTECTED, IssuerVerification
    from azazel_nexus.edge_package import AUTHENTICATED_CAVEAT, PIN
    from test_wizard_and_cli import _probe_state, _verified_package

    _base(tmp_path, monkeypatch)
    root, digest = _verified_package(tmp_path)
    real = cli.inspect_edge

    def inspect(*args, **kwargs):
        return replace(real(*args, **kwargs), caveats=(AUTHENTICATED_CAVEAT,),
                       issuer=IssuerVerification(
                           digest_verified=True, issuer_authenticated=True,
                           issuer_status="authenticated", issuer="lab-issuer-test",
                           revocation_status="in_force", revocation_sequence=3, revoked="none",
                           floor_status="held", floor_version=PIN.version, version=PIN.version,
                           package_digest=digest, notes=(NOTE_STATE_UNPROTECTED,)))
    monkeypatch.setattr(cli, "inspect_edge", inspect)
    probe = _probe_state(tmp_path, digest)
    probe.chmod(0o644)
    return {"edge_root": root, "probe": probe}


#: What `lite_import.status_summary` returns for an admitted, current bundle.
KNOWLEDGE_AVAILABLE = {"state": "available", "reason_code": "available", "generation": 5,
                       "freshness": "current"}


def _knowledge_available(tmp_path, monkeypatch):
    """Knowledge Lite admitted and current, at the `cli._knowledge_reading` seam.

    The reading is the closed shape the daemon's status verb also returns;
    reading a real bundle is `test_operator_flow_cli.py`'s.
    """
    from azazel_nexus import cli

    _base(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_knowledge_reading",
                        lambda root, *, as_of: dict(KNOWLEDGE_AVAILABLE))
    return {}


def _ledger_missing(tmp_path, monkeypatch):
    _base(tmp_path, monkeypatch)
    return {"extra": ("--ledger", str(tmp_path / "no-ledger.jsonl"))}


def _ledger_broken(tmp_path, monkeypatch):
    _base(tmp_path, monkeypatch)
    _write(tmp_path / "broken-ledger.jsonl", "not a ledger line\n")
    return {"extra": ("--ledger", str(tmp_path / "broken-ledger.jsonl"))}


SCENARIOS = {
    "absent": _absent,
    "loop": _loop,
    "stale": _stale,
    "refused": _refused,
    "edge-ready-lab-host": _edge_ready,
    "edge-tampered-no-boot": _edge_tampered_no_boot,
    "edge-issuer-authenticated": _issuer_authenticated,
    "knowledge-available": _knowledge_available,
    "ledger-missing": _ledger_missing,
    "ledger-broken": _ledger_broken,
}


def run_scenario(name, tmp_path, monkeypatch, *, json_flag=False):
    """`(exit code, stdout, stderr)` of `status` in the named scenario.

    Every scene is a deployment-baseline (x86_64) node, whatever CPU runs the
    test: the Edge package is looked for, written and checked as the x86_64
    one, so the golden text and the cross-CPU vector (`status.read_model`)
    name the same files on both CPUs. The per-CPU checks themselves are
    tested in `test_edge_package.py` on the real host CPU.
    """
    from azazel_nexus import edge_package

    monkeypatch.setattr(edge_package, "host_architecture", lambda: "x86_64")
    monkeypatch.setattr(edge_package, "PIN", edge_package.PINS["x86_64"])
    options = SCENARIOS[name](tmp_path, monkeypatch)
    out, err = io.StringIO(), io.StringIO()
    code = main(_argv(tmp_path, *options.get("extra", ()), edge_root=options.get("edge_root"),
                      probe=options.get("probe"), json_flag=json_flag), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def normalized(text, tmp_path):
    return text.replace(str(tmp_path), "<TMP>")


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_text_matches_the_pre_read_model_golden(name, tmp_path, monkeypatch):
    code, out, _ = run_scenario(name, tmp_path, monkeypatch)
    assert code == 0
    expected = (GOLDEN / f"{name}.txt").read_text(encoding="utf-8")
    assert normalized(out, tmp_path) == expected


# -- the read model --------------------------------------------------------


def _view(name, tmp_path, monkeypatch):
    code, out, err = run_scenario(name, tmp_path, monkeypatch, json_flag=True)
    assert code == 0
    return json.loads(out), out, err


#: Every key the read model may carry, by path (list items are `[]`). The
#: view is built by allowlist; this is the test that a key outside it --
#: a field an upstream reader grew, or something copied whole -- fails.
#: `refused`, `rate_limited`-style maps are keyed by fixed codes and listed
#: as `{code}`; `reasons` is the M.I.O. transition's closed shape.
ALLOWED = {
    "schema", "as_of", "clock", "clock.status", "clock.reason_code", "lab_host",
    "authority", "authority.decision_and_enforcement", "authority.nexus",
    "authority.edge_decisions", "authority.execution_results", "authority.reason_code",
    "sections",
    # profile
    "sections.profile", *(f"sections.profile.{k}" for k in (
        "status", "reason_code", "profile", "usable_mib", "source", "source.kind",
        "source.reader", "withheld", "withheld[]")),
    # mio
    "sections.mio", *(f"sections.mio.{k}" for k in (
        "status", "reason_code", "reading", "reading.ceiling", "reading.state",
        "reading.reasons", "reading.reasons.{code}", "reading.reasons.health",
        "reading.reasons.health.{code}",
        "reading.source", "reading.observed_at", "reading.availability", "reading.notice",
        "age_s", "age_reason", "liveness", "liveness.status", "liveness.reason_code",
        "liveness.evidence", "liveness.operator_snapshot", "liveness.route_ledger_record",
        *(f"liveness.operator_snapshot.{k}" for k in (
            "status", "reason_code", "written_at", "age_s", "stale_after_s")),
        *(f"liveness.route_ledger_record.{k}" for k in (
            "status", "reason_code", "recorded_at", "basis", "age_s", "stale_after_s")),
        "source", "source.kind", "source.reader", "source.observed_at")),
    # capability
    "sections.capability", *(f"sections.capability.{k}" for k in (
        "status", "reason_code", "state", "retained", "retained[]", "lost", "lost[]",
        "source", "source.kind", "source.live_provider_assessment")),
    # enforcement
    "sections.enforcement", *(f"sections.enforcement.{k}" for k in (
        "enforcement_ready", "edge_baseline_ready", "commissioning_record",
        "missing_profiles", "missing_profiles[]", "observe_only", "reason_code")),
    # interfaces
    "sections.interfaces", *(f"sections.interfaces.{k}" for k in (
        "status", "reason_code", "items", "items[]", "items[].handle", "items[].state",
        "items[].role", "items[].commissionable", "items[].blocked_by", "items[].blocked_by[]",
        "items[].withheld", "items[].withheld[]", "source", "source.kind", "source.reader")),
    # external modules
    "sections.external_modules", "sections.external_modules[]",
    *(f"sections.external_modules[].{k}" for k in ("name", "state", "reason", "working",
                                                    "withheld", "withheld[]")),
    # knowledge lite
    "sections.knowledge_lite", *(f"sections.knowledge_lite.{k}" for k in (
        "status", "reason_code", "generation", "freshness", "readiness",
        "readiness.functional", "readiness.word", "readiness.means",
        "readiness.does_not_mean", "readiness.does_not_mean[]",
        "bundle", "bundle.digest_short", "bundle.signer_key_ids", "bundle.signer_key_ids[]",
        "bundle.static_count", "bundle.current_count", "bundle.next_expiry",
        "cryptographic_implementation", "cryptographic_implementation.status",
        "cryptographic_implementation.reason_code", "source", "source.kind", "source.reader",
        "source.written_at", "source.trust", "withheld", "withheld[]")),
    # edge core
    "sections.edge_core", *(f"sections.edge_core.{k}" for k in (
        "status", "reason_code", "ready", "root_configured", "findings", "findings[]",
        "findings[].check", "findings[].evidence", "findings[].security",
        "findings[].withheld", "findings[].withheld[]", "issuer",
        *(f"issuer.{f}" for f in ("digest_verified", "issuer_authenticated", "issuer_status",
                                   "revocation_status", "revoked", "floor_status", "notes",
                                   "notes[]", "issuer_reason", "withheld", "withheld[]")),
        "caveats", "caveats[]", "caveats[].text", "caveats[].withheld", "caveats[].withheld[]",
        "probe", "probe.result", "probe.boot_id", "probe.observed_at",
        "source", "source.kind", "source.reader", "source.probe_reader",
        "withheld", "withheld[]")),
    # integration
    "sections.integration", *(f"sections.integration.{k}" for k in (
        "status", "reason_code", "rows", "rows[]", "rows[].axis", "rows[].subject",
        "rows[].value", "rows[].defect", "rows[].reason", "rows[].withheld",
        "rows[].withheld[]", "enforcement_capable",
        "baseline_ready", "continues", "continues[]", "broker", "broker.status_level",
        "broker.informational", "broker.core", "broker.transport", "broker.transport_reason")),
    # fabric
    "sections.fabric", "sections.fabric.status", "sections.fabric.reason_code",
    "sections.fabric.version",
    # health and next actions
    "sections.health", "sections.health[]", *(f"sections.health[].{k}" for k in (
        "subject", "status", "detail", "advisory", "advisory_code", "withheld", "withheld[]",
        "reason_code", "source", "source.kind", "source.schema", "source.written_at",
        "source.freshness", "source.reason_code", "source.age_s", "source.age_reason",
        "source.withheld", "source.withheld[]", "capacity", "capacity.warning_reasons[]",
        "capacity.rate_limited_total",
        *(f"capacity.{f}" for f in ("chain_verified", "chain_bytes", "segments",
                                    "filesystem_free_bytes", "warning", "warning_reasons",
                                    "warn_chain_bytes", "warn_free_bytes",
                                    "rate_limit_summaries_dropped")))),
    "sections.next_actions", "sections.next_actions[]", *(f"sections.next_actions[].{k}" for k in (
        "summary", "command", "lab_host_unavailable_step", "withheld", "withheld[]")),
}
_LOOP = "sections.edge_loop"
_SOURCE = ("source", "source.kind", "source.schema", "source.written_at", "source.freshness",
           "source.reason_code", "source.age_s", "source.age_reason", "conditions",
           "conditions[]")
ALLOWED |= {_LOOP, *(f"{_LOOP}.{k}" for k in (
    "authority", "authority.decision_and_enforcement", "authority.nexus",
    "authority.edge_decisions", "authority.execution_results", "authority.reason_code",
    "evaluated_at", "status", "reason_code", "content_labels", "content_labels.{code}"))}
for _name, _fields in (
        ("intake", ("schema", "written_at", "last_accepted_at", "accepted", "processed",
                    "last_processed_at", "refused", "refused.{code}", "open_incidents",
                    "queue_drops", "storage_failed", "ledger_recovered", "edge_forward",
                    *(f"edge_forward.{f}" for f in ("dropped", "failed", "sent", "since",
                                                    "reported_at", "restarts")),
                    "edge_forward_freshness", "edge_forward_freshness.status",
                    "edge_forward_freshness.reported_by", "edge_forward_freshness.age_s",
                    "edge_forward_freshness.age_reason",
                    "decoy", "decoy.accepted", "decoy.last_accepted_at", "decoy_status",
                    "decoy_status.listening", "decoy_status.observer",
                    "decoy_status.hardware_evidence", "decoy_status.refused",
                    "decoy_status.refused.{code}")),
        ("explainer", ("schema", "written_at", "last_explained_at", "explained", "refused",
                       "refused.{code}", "pending", "cursor_lag", "chain_broken",
                       "recovery_hint", "storage_failed", "mio_available",
                       "knowledge_available", "audit_forward_dropped",
                       "audit_forward_refused")),
        ("recent", ("schema", "written_at", "incidents", "incidents[]",
                    *(f"incidents[].{f}" for f in (
                        "incident_id", "state", "first_seen", "last_seen", "count",
                        "most_severe", "edge_would", "policy_reason", "technique_ids",
                        "technique_ids[]", "evidence_stored", "explanation",
                        "explanation.state", "explanation.route", "explanation.outcome",
                        "explanation.summary", "explanation.failure_codes",
                        "explanation.failure_codes[]", "explanation.content_kind",
                        "explanation.notice", "explanation.knowledge_refs",
                        "explanation.knowledge_refs[]",
                        "explanation.knowledge_refs[].technique_id",
                        "explanation.knowledge_refs[].name",
                        "explanation.knowledge_refs[].claim_id",
                        *(f"explanation.knowledge_refs[].{f}" for f in (
                            "bundle_digest_short", "generation", "freshness", "as_of",
                            "citation", "citation_state", "withheld", "withheld[]")),
                        "explanation.knowledge_refs_omitted",
                        "edge_decision", "edge_decision.kind", "edge_decision.action",
                        "edge_decision.executed", "edge_decision.decided_by",
                        "execution_result", "execution_result.status",
                        "execution_result.reason_code"))))):
    ALLOWED |= {f"{_LOOP}.{_name}", f"{_LOOP}.{_name}.status", f"{_LOOP}.{_name}.reason_code",
                f"{_LOOP}.{_name}.snapshot",
                *(f"{_LOOP}.{_name}.{k}" for k in _SOURCE),
                *(f"{_LOOP}.{_name}.snapshot.{k}" for k in _fields)}

# The operator snapshots (U2) and the storage measurement.
# `source.leaf` (ADR-0007): which copy was read, the operator's or the UI's.
_SNAP_SOURCE = (*_SOURCE, "source.writer", "source.leaf")
for _name, _fields in (
        ("knowledge_status", ("state", "reason_code", "generation", "freshness")),
        ("mio_status", ("recorded", "state", "ceiling", "reasons", "reasons.{code}",
                        "reasons.health", "reasons.health.{code}", "observed_at",
                        "record_uncertain")),
        ("services", ("units", "units[]", *(f"units[].{f}" for f in (
            "unit", "status", "load_state", "active_state", "sub_state", "reason_code"))))):
    ALLOWED |= {f"sections.{_name}", f"sections.{_name}.status", f"sections.{_name}.freshness",
                f"sections.{_name}.conditions", f"sections.{_name}.conditions[]",
                f"sections.{_name}.source.age_reason",
                f"sections.{_name}.reason_code", f"sections.{_name}.snapshot",
                *(f"sections.{_name}.{k}" for k in _SNAP_SOURCE),
                f"sections.{_name}.snapshot.schema", f"sections.{_name}.snapshot.written_at",
                *(f"sections.{_name}.snapshot.{k}" for k in _fields)}
ALLOWED |= {"sections.knowledge_status.content_freshness_evaluated_at",
            "sections.knowledge_status.cryptographic_implementation",
            "sections.knowledge_status.cryptographic_implementation.status",
            "sections.knowledge_status.cryptographic_implementation.reason_code",
            "sections.mio_status.notice", "sections.services.source.reader",
            "sections.storage", *(f"sections.storage.{k}" for k in (
                "status", "reason_code", "locations", "locations[]",
                *(f"locations[].{f}" for f in (
                    "label", "status", "total_bytes", "free_bytes", "available_bytes",
                    "read_only", "same_filesystem_as", "reason_code")),
                "source", "source.kind", "source.observed_at", "source.withheld",
                "source.withheld[]"))}

# The NOC section (U3). Its snapshot below the top level is the closed shape
# `noc_status.read_noc_status` checks; test_noc_status covers it.
ALLOWED |= {"sections.noc", "sections.noc.status", "sections.noc.reason_code", "sections.noc.freshness",
            "sections.noc.conditions", "sections.noc.conditions[]", "sections.noc.source.age_reason",
            "sections.noc.snapshot", *(f"sections.noc.{k}" for k in _SNAP_SOURCE),
            "sections.noc.observation", *(f"sections.noc.observation.{k}" for k in (
                "kind", "transmission", "active_checks", "policy_rules_evaluated")),
            "sections.noc.not_measured", "sections.noc.not_measured[]",
            *(f"sections.noc.not_measured[].{k}" for k in ("field", "status", "reason_code")),
            "sections.noc.role", "sections.noc.role.status", "sections.noc.role.reason_code",
            "sections.noc.identity", "sections.noc.identity.interfaces_by",
            "sections.noc.identity.withheld", "sections.noc.identity.withheld[]"}

# Which copy of the operator snapshots the view read (ADR-0007).
ALLOWED |= {"snapshot_reader"}

# The operator view (S-04), a versioned section built by the read adapter.
# Its rows are `operator_view`'s own display rows (fixed English reasons,
# model ids, inbox display names), listed field by field.
_OV = "sections.operator_view"
ALLOWED |= {_OV, *(f"{_OV}.{k}" for k in (
    "schema", "status", "reason_code", "inputs", "inputs.model_store", "inputs.core_reserve",
    "inputs.mio_entry_record", "inputs.remote_consent", "unread_inputs", "unread_inputs[]",
    "provider", "provider.state", "provider.reason_codes", "provider.reason_codes[]",
    "admission_build_switch", "models_omitted", "status_sentence",
    "sections", "sections[]", "sections[].key", "sections[].title", "sections[].rows",
    "sections[].rows[]", *(f"sections[].rows[].{f}" for f in (
        "axis", "value", "reason", "reason_code", "reason_codes", "reason_codes[]",
        "model_id", "refused_by", "admitted", "entries", "entries[]",
        "nominal_gib", "profile", "is_this_node", "note")),
    "operations", "operations[]", *(f"operations[].{f}" for f in (
        "confirmation", "available", "reason", "transition")),
    "source", "source.kind", "source.reader", "source.writes"))}

#: Maps keyed by fixed codes rather than by field names.
CODE_KEYED = {"refused", "content_labels", "reasons", "health"}


def _paths(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            parent = prefix.rsplit(".", 1)[-1] if prefix else ""
            name = "{code}" if parent in CODE_KEYED and not (
                parent == "health" and prefix == "sections.health") else key
            if parent == "reasons" and key == "health":
                name = "health"
            path = f"{prefix}.{name}" if prefix else name
            yield path
            yield from _paths(item, path)
    elif isinstance(value, list):
        for item in value:
            yield prefix + "[]"
            yield from _paths(item, prefix + "[]")


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_key_in_the_view_is_on_the_allowlist(name, tmp_path, monkeypatch):
    view, _, _ = _view(name, tmp_path, monkeypatch)
    assert view["schema"] == "azazel-nexus/status-view/1"
    extra = sorted(set(_paths(view)) - ALLOWED)
    assert not extra, extra


def test_an_unlisted_upstream_field_does_not_reach_the_view(tmp_path, monkeypatch):
    """A reader that grows a field (here: through a patched reader) does not widen the view."""
    from azazel_nexus import edge_loop_status

    _loop(tmp_path, monkeypatch)
    real = edge_loop_status.read_edge_loop

    def grown():
        value = real()
        value["intake"]["interface"] = "enp4s0"
        value["recent"]["incidents"][0]["src_ip"] = "192.0.2.1"
        value["recent"]["incidents"][0]["explanation"]["knowledge_refs"][0]["raw"] = "SECRET"
        return value
    monkeypatch.setattr(edge_loop_status, "read_edge_loop", grown)
    out = io.StringIO()
    assert main(_argv(tmp_path, json_flag=True), out=out) == 0
    text = out.getvalue()
    for leaked in ("enp4s0", "192.0.2.1", "SECRET", '"interface"', '"src_ip"', '"raw"'):
        assert leaked not in text
    assert set(_paths(json.loads(text))) <= ALLOWED


#: Material the terminal may show and the read model must not carry.
SECRETS_IN_SCENARIOS = (
    "bus_path", "physical_label", "pci0000", "LAN1", "enp4s0", "enp5s0",  # interface identity
    "aa:bb:cc",                                                           # MAC
    "/proc/meminfo", "Expecting value", "broken-ledger", "no-ledger",      # exception text, paths
    "edge-probe-garbage", "the boot id could not be read",
    "192.0.2.1", "SECRET", "lab-issuer-test",                               # issuer identity
    "/etc/azazel", "docs/", ".md",                                          # install and doc paths
)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_the_view_carries_no_identity_path_or_exception_text(name, tmp_path, monkeypatch):
    _, raw, err = _view(name, tmp_path, monkeypatch)
    assert str(tmp_path) not in raw
    for secret in SECRETS_IN_SCENARIOS:
        assert secret not in raw, secret
    assert "Traceback" not in raw + err


def test_the_terminal_keeps_what_the_view_withholds(tmp_path, monkeypatch):
    view, _, _ = _view("ledger-broken", tmp_path, monkeypatch)
    sections = view["sections"]
    chain = next(h for h in sections["health"] if h["subject"] == "audit chain")
    assert chain["status"] == "failed" and chain["detail"] is None
    assert chain["withheld"] == ["detail"]
    assert chain["reason_code"] == "audit_chain_failed"
    withheld = [a for a in sections["next_actions"] if a["withheld"]]
    assert withheld and all(a["summary"] is None for a in withheld)
    assert all(i["withheld"] == ["description"] for i in sections["interfaces"]["items"])
    assert all(f["withheld"] == ["reason"] for f in sections["edge_core"]["findings"])
    assert sections["edge_core"]["withheld"] == ["root"]


def test_the_terminal_only_half_is_never_serialised(tmp_path, monkeypatch):
    from azazel_nexus import status_view

    _ledger_broken(tmp_path, monkeypatch)
    status = status_view.StatusView(view={"schema": status_view.SCHEMA},
                                    terminal={"preamble": "SECRET 192.0.2.1"})
    assert "SECRET" not in status_view.dumps(status)
    assert "SECRET" not in repr(status)


def test_unknown_is_never_reported_as_healthy(tmp_path, monkeypatch):
    view, _, _ = _view("absent", tmp_path, monkeypatch)
    s = view["sections"]
    assert (s["profile"]["status"], s["profile"]["reason_code"]) == (
        "not_measured", "profile_not_measured")
    assert s["mio"]["status"] == "unknown"
    assert s["mio"]["reason_code"] == "route_ledger_unreadable_or_refused"
    assert s["knowledge_lite"]["status"] == "unavailable"
    assert s["knowledge_lite"]["reason_code"] == "trust_unreadable"
    assert s["edge_core"]["status"] == "absent" and s["edge_core"]["ready"] is False
    assert s["edge_core"]["probe"] == {"result": "absent", "boot_id": "not_needed",
                                       "observed_at": None}
    assert s["fabric"] == {"status": "refused", "reason_code": "projection_refused",
                           "version": None}
    for name in ("intake", "explainer", "recent"):
        part = s["edge_loop"][name]
        assert (part["status"], part["reason_code"]) == (
            "unavailable", "snapshot_absent_or_refused")
        assert part["snapshot"] is None and part["source"]["freshness"] == "unavailable"
    health = {h["subject"]: h for h in s["health"]}
    assert health["systemd units"]["status"] == "unknown"
    assert health["systemd units"]["reason_code"] == "service_manager_not_queried"
    assert health["audit"]["status"] == "unknown"
    assert health["audit"]["reason_code"] == "snapshot_absent_or_refused"
    assert s["enforcement"]["reason_code"] == "no_commissioning_record"


def test_stale_and_future_snapshots_carry_their_reason(tmp_path, monkeypatch):
    view, _, _ = _view("stale", tmp_path, monkeypatch)
    loop = view["sections"]["edge_loop"]
    assert (loop["intake"]["status"], loop["intake"]["reason_code"]) == (
        "stale", "snapshot_dated_in_future")
    assert (loop["explainer"]["status"], loop["explainer"]["reason_code"]) == (
        "stale", "snapshot_expired")
    assert loop["recent"]["source"]["freshness"] == "stale"
    assert loop["recent"]["source"]["age_s"] == 120
    audit = next(h for h in view["sections"]["health"] if h["subject"] == "audit")
    assert audit["status"] == "unknown" and audit["reason_code"] == "snapshot_expired"
    assert audit["source"]["schema"] == "azazel-nexus/audit-status/v1"
    assert audit["source"]["written_at"] == NOW - 301


def test_sources_name_schema_written_at_and_freshness(tmp_path, monkeypatch):
    from azazel_nexus.edge_intake import STATUS_SCHEMA
    from azazel_nexus.incident_explain import RECENT_SCHEMA

    view, _, _ = _view("loop", tmp_path, monkeypatch)
    loop = view["sections"]["edge_loop"]
    assert loop["intake"]["source"] == {"kind": "snapshot", "schema": STATUS_SCHEMA,
                                        "written_at": NOW - 5, "freshness": "fresh",
                                        "reason_code": None, "age_s": 5, "age_reason": None}
    assert loop["explainer"]["source"]["schema"] == "azazel-nexus/incident-explain-status/v1"
    assert loop["recent"]["source"]["schema"] == RECENT_SCHEMA
    assert loop["intake"]["status"] == "running"
    # chain_broken is reader-checked and true in this scenario: not "running".
    assert (loop["explainer"]["status"], loop["explainer"]["reason_code"]) == (
        "degraded", "chain_broken")
    assert loop["explainer"]["conditions"] == ["chain_broken"]
    forward = loop["intake"]["snapshot"]["edge_forward_freshness"]
    assert forward == {"status": "stale", "reported_by": "edge", "age_s": 1000,
                       "age_reason": None}
    assert loop["intake"]["snapshot"]["decoy_status"]["observer"] == "nexus"
    audit = next(h for h in view["sections"]["health"] if h["subject"] == "audit")
    assert audit["status"] == "ok" and audit["source"]["freshness"] == "fresh"
    # The advisory names a document: a code in the view, the sentence on the terminal.
    assert audit["advisory"] is None and audit["withheld"] == ["detail", "advisory"]
    assert audit["advisory_code"] == "audit_capacity_warning"
    assert audit["capacity"]["warning_reasons"] == ["chain_size", "filesystem_free"]
    assert audit["capacity"]["rate_limited_total"] == 6
    assert view["sections"]["fabric"] == {"status": "projected", "reason_code": None,
                                          "version": "0.10.0"}
    assert view["as_of"] == AS_OF and view["clock"]["status"] == "known"


def test_edge_decisions_are_would_and_nothing_was_executed(tmp_path, monkeypatch):
    view, _, _ = _view("loop", tmp_path, monkeypatch)
    assert view["authority"]["execution_results"] == "not_accepted"
    rows = view["sections"]["edge_loop"]["recent"]["snapshot"]["incidents"]
    assert [r["edge_decision"]["action"] for r in rows] == ["isolate", "notify", "observe"]
    for row in rows:
        assert row["edge_decision"]["kind"] == "would"
        assert row["edge_decision"]["executed"] is False
        assert row["execution_result"] == {"status": "none",
                                           "reason_code": "nexus_accepts_observe_only"}
    advice = rows[0]["explanation"]
    assert advice["content_kind"] == "ai_advice"
    assert advice["knowledge_refs"] == [{"technique_id": "T1059",
                                         "name": "Command and Scripting Interpreter",
                                         "claim_id": "T1059"}]
    assert rows[1]["explanation"]["content_kind"] == "deterministic_notice"
    assert rows[1]["evidence_stored"] is False


def test_knowledge_refs_are_copied_with_every_field_the_reader_checks(tmp_path, monkeypatch):
    """The citation allowlist follows the reader. If the recent-incident row
    grows a citation field, this fails until the field is added to
    `KNOWLEDGE_REF_FIELDS` or `KNOWLEDGE_REF_DISPLAY_FIELDS` -- deliberately,
    not silently. Both shapes the reader accepts are listed (#362)."""
    from azazel_nexus import edge_loop_status, incident_explain, status_view

    assert status_view.KNOWLEDGE_REF_FIELDS == incident_explain.CITATION_FIELDS
    assert status_view.KNOWLEDGE_REF_DISPLAY_FIELDS == incident_explain.CITATION_DISPLAY_FIELDS
    _loop(tmp_path, monkeypatch)
    raw = edge_loop_status.read_edge_loop()["recent"]
    for row in raw["incidents"]:
        for ref in row["explanation"]["knowledge_refs"]:
            assert tuple(ref) == status_view.KNOWLEDGE_REF_FIELDS


def _sections(root, monkeypatch, tweak=None):
    monkeypatch.undo()
    root.mkdir()
    _base(root, monkeypatch, fabric="refused", measured=False)
    if tweak is not None:
        tweak(root, monkeypatch)
    out = io.StringIO()
    assert main(_argv(root, json_flag=True), out=out) == 0
    return json.loads(out.getvalue())["sections"]


def _changed(a, b):
    return {name for name in a if a[name] != b[name]}


@pytest.mark.parametrize("tweak, expected", [
    (lambda root, mp: _snapshots(root, intake=_intake(NOW - 1)), {"edge_loop"}),
    (lambda root, mp: _snapshots(root, recent=_recent(NOW - 1)), {"edge_loop"}),
    (lambda root, mp: _snapshots(root, audit=_audit(NOW - 1)), {"health", "next_actions"}),
    (lambda root, mp: _fabric(mp, "0.10.0"), {"fabric"}),
    # The measured envelope also enters the cognition axis's sentence (its
    # resource gate); that sentence names a document, so only the terminal has it.
    # The operator view (S-04) shows the same usable memory and the profile
    # it selects in its resources rows.
    (lambda root, mp: _measured(mp), {"profile", "next_actions", "operator_view"}),
])
def test_each_input_moves_only_its_own_section(tmp_path, monkeypatch, tweak, expected):
    """Changed inputs move their own axis; nothing is derived across sections."""
    base = _sections(tmp_path / "base", monkeypatch)
    moved = _sections(tmp_path / "moved", monkeypatch, tweak)
    assert _changed(base, moved) == expected


def test_unparsed_clock_is_unknown_not_fresh(tmp_path, monkeypatch):
    from azazel_nexus import cli

    _loop(tmp_path, monkeypatch)
    report = cli._report(None, None, now=None)
    status = cli._status_view(report, as_of="not a time")
    view = status.view
    assert view["clock"] == {"status": "unknown", "reason_code": "clock_unknown"}
    assert view["as_of"] is None
    loop = view["sections"]["edge_loop"]
    assert (loop["status"], loop["reason_code"]) == ("unavailable", "clock_unknown")
    out = io.StringIO()
    from azazel_nexus import status_view
    status_view.render_text(status, out)
    assert "edge loop: unavailable (internal)" in out.getvalue()


def test_json_on_a_lab_host_keeps_stdout_parseable(tmp_path, monkeypatch):
    view, raw, err = _view("edge-ready-lab-host", tmp_path, monkeypatch)
    assert err == "LAB HOST\n" and "LAB HOST" not in raw
    assert view["lab_host"] is True
    steps = [a["lab_host_unavailable_step"] for a in view["sections"]["next_actions"]]
    assert "commissioning" in steps
    edge = view["sections"]["edge_core"]
    assert edge["status"] == "verified-ready" and edge["ready"] is True
    assert edge["probe"]["result"] == "loaded" and edge["probe"]["boot_id"] == "read"


def test_json_reports_probe_and_boot_codes_instead_of_their_text(tmp_path, monkeypatch):
    view, raw, _ = _view("refused", tmp_path, monkeypatch)
    assert view["sections"]["edge_core"]["probe"]["result"] == "refused"
    assert "was refused" not in raw


def test_json_reports_an_unreadable_boot_id_as_a_code(tmp_path, monkeypatch):
    view, raw, _ = _view("edge-tampered-no-boot", tmp_path, monkeypatch)
    edge = view["sections"]["edge_core"]
    assert edge["probe"]["boot_id"] == "unreadable"
    assert edge["status"] == "digest-mismatch"
    assert [f["security"] for f in edge["findings"]].count(True) == 1


def test_internal_failure_in_the_loop_is_a_code_not_text(tmp_path, monkeypatch):
    from azazel_nexus import edge_loop_status

    _loop(tmp_path, monkeypatch)

    def fail(*_):
        raise RuntimeError("SECRET 192.0.2.1")
    monkeypatch.setattr(edge_loop_status, "read_recent_incidents", fail)
    monkeypatch.setattr(edge_loop_status, "fabric_status_result", fail)
    out = io.StringIO()
    assert main(_argv(tmp_path, json_flag=True), out=out) == 0
    view = json.loads(out.getvalue())
    assert view["sections"]["edge_loop"]["reason_code"] == "internal_error"
    assert view["sections"]["fabric"]["status"] == "internal_error"
    assert "SECRET" not in out.getvalue()


def test_text_freshness_and_view_freshness_agree(tmp_path, monkeypatch):
    for name in ("loop", "stale"):
        (tmp_path / name).mkdir()
        (tmp_path / f"{name}-text").mkdir()
        view, _, _ = _view(name, tmp_path / name, monkeypatch)
        monkeypatch.undo()
        _, text, _ = run_scenario(name, tmp_path / f"{name}-text", monkeypatch)
        monkeypatch.undo()
        loop = view["sections"]["edge_loop"]
        for part, label in (("intake", "intake"), ("explainer", "explainer")):
            stale = loop[part]["status"] == "stale"
            assert (f"    {label}: stale (snapshot expired)" in text) == stale


def test_a_recorded_mio_reading_is_copied_field_by_field(tmp_path, monkeypatch):
    from azazel_nexus import mio_status

    _absent(tmp_path, monkeypatch)
    reading = {"ceiling": "LITE", "state": "CORE", "source": "route-ledger",
               "observed_at": "2026-09-21T04:00:00+00:00", "notice": mio_status.NOTICE,
               "availability": "last recorded observation",
               "reasons": {"profile": "LITE", "resource": "core_reserve_unmeasured",
                           "trust": "not-checked", "topology": "no_verified_egress",
                           "health": {"local": "not_admitted", "remote": "unavailable"}},
               "credential": "SECRET"}
    monkeypatch.setattr(mio_status, "status_summary", lambda: dict(reading))
    out = io.StringIO()
    assert main(_argv(tmp_path, json_flag=True), out=out) == 0
    view = json.loads(out.getvalue())
    mio = view["sections"]["mio"]
    assert (mio["status"], mio["reason_code"]) == ("recorded", None)
    assert mio["reading"] == {k: v for k, v in reading.items() if k != "credential"}
    assert mio["source"]["observed_at"] == reading["observed_at"]
    assert "SECRET" not in out.getvalue()
    assert set(_paths(view)) <= ALLOWED
    (tmp_path / "t").mkdir()
    text = io.StringIO()
    assert main(_argv(tmp_path / "t"), out=text) == 0
    assert mio_status.describe(reading) in text.getvalue()



def _walk(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, k)
            if k == "reason_code":
                yield v
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item, key)


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_every_reason_code_is_from_the_fixed_vocabulary(name, tmp_path, monkeypatch):
    from azazel_nexus import status_view

    view, _, _ = _view(name, tmp_path, monkeypatch)
    allowed = status_view.REASON_CODES | status_view.KNOWLEDGE_REASONS
    codes = {code for code in _walk(view) if code is not None}
    assert codes <= allowed, codes - allowed


def _recorded_mio(monkeypatch, observed_at):
    from azazel_nexus import mio_status

    reading = {"ceiling": "LITE", "state": "CORE", "source": "route-ledger",
               "observed_at": observed_at, "notice": mio_status.NOTICE,
               "availability": "last recorded observation",
               "reasons": {"profile": "LITE", "resource": "core_reserve_unmeasured",
                           "trust": "not-checked", "topology": "no_verified_egress",
                           "health": {"local": "not_admitted", "remote": "unavailable"}}}
    monkeypatch.setattr(mio_status, "status_summary", lambda: json.loads(json.dumps(reading)))
    return reading


@pytest.mark.parametrize("observed_at, as_of, expected", [
    ("2026-09-21T04:00:00+00:00", AS_OF, ("recorded", None)),
    ("2026-09-21T04:05:00+00:00", AS_OF, ("stale", "observed_at_in_future")),
    # No snapshot here (`_absent`): the three-day-old record is the only
    # liveness evidence, and it is past its limit (#358 option 1).
    ("2026-09-18T04:00:00+00:00", AS_OF, ("stale", "liveness_evidence_expired")),
    ("2026-09-21T04:00:00+00:00", "not a time", ("unknown", "clock_unknown")),
    ("2026-09-21T04:00:00", AS_OF, ("unknown", "observed_at_unreadable")),
])
def test_mio_reading_freshness_is_judged_against_the_status_clock(
        tmp_path, monkeypatch, observed_at, as_of, expected):
    from azazel_nexus import cli

    _absent(tmp_path, monkeypatch)
    reading = _recorded_mio(monkeypatch, observed_at)
    status = cli._status_view(cli._report(None, None), as_of=as_of)
    mio = status.view["sections"]["mio"]
    assert (mio["status"], mio["reason_code"]) == expected
    assert mio["reading"]["reasons"] == reading["reasons"]


@pytest.mark.parametrize("mutation", [
    {"reasons": {"profile": "LITE", "resource": "anything at all", "trust": "not-checked",
                 "topology": "no_verified_egress",
                 "health": {"local": "not_admitted", "remote": "unavailable"}}},
    {"reasons": {"profile": "LITE", "extra": "SECRET"}},
    {"state": "SECRET"},
    {"availability": "SECRET /etc/azazel"},
    {"source": "SECRET"},
])
def test_mio_values_outside_the_vocabulary_refuse_the_reading(tmp_path, monkeypatch, mutation):
    from azazel_nexus import mio_status

    _absent(tmp_path, monkeypatch)
    reading = {**_recorded_mio(monkeypatch, "2026-09-21T04:00:00+00:00"), **mutation}
    monkeypatch.setattr(mio_status, "status_summary", lambda: dict(reading))
    out = io.StringIO()
    assert main(_argv(tmp_path, json_flag=True), out=out) == 0
    mio = json.loads(out.getvalue())["sections"]["mio"]
    assert (mio["status"], mio["reason_code"]) == ("unknown", "reading_refused")
    assert mio["reading"]["reasons"] == {} and mio["reading"]["state"] is None
    assert "SECRET" not in out.getvalue() and "anything at all" not in out.getvalue()


def _patched_loop(tmp_path, monkeypatch, change, *, json_flag=True):
    from azazel_nexus import edge_loop_status

    _loop(tmp_path, monkeypatch)
    real = edge_loop_status.read_edge_loop

    def changed():
        value = real()
        change(value)
        return value
    monkeypatch.setattr(edge_loop_status, "read_edge_loop", changed)
    out = io.StringIO()
    assert main(_argv(tmp_path, json_flag=json_flag), out=out) == 0
    if not json_flag:
        return None, out.getvalue()
    return json.loads(out.getvalue())["sections"]["edge_loop"], out.getvalue()


@pytest.mark.parametrize("part, change", [
    ("intake", lambda v: v["intake"]["refused"].update({"SECRET 192.0.2.1": 1})),
    ("intake", lambda v: v["intake"]["refused"].update({"queue_full": -1})),
    ("explainer", lambda v: v["explainer"]["refused"].update({"not_a_code": 1})),
    ("explainer", lambda v: v["explainer"].update(recovery_hint="SECRET")),
    ("recent", lambda v: v["recent"]["incidents"][0]["explanation"]["failure_codes"].append(
        "SECRET")),
    ("recent", lambda v: v["recent"]["incidents"][0].update(edge_would="SECRET")),
    ("recent", lambda v: v["recent"]["incidents"][0]["explanation"]["knowledge_refs"][0].update(
        claim_id="SECRET")),
    ("intake", lambda v: v["intake"].update(schema="SECRET")),
])
def test_codes_outside_their_sets_refuse_that_snapshot(tmp_path, monkeypatch, part, change):
    loop, raw = _patched_loop(tmp_path, monkeypatch, change)
    assert (loop[part]["status"], loop[part]["reason_code"]) == (
        "unavailable", "snapshot_refused_by_view")
    assert loop[part]["snapshot"] is None
    assert "SECRET" not in raw
    others = {"intake", "explainer", "recent"} - {part}
    assert all(loop[name]["snapshot"] is not None for name in others)


@pytest.mark.parametrize("flags, expected", [
    ({"storage_failed": True}, ("degraded", "storage_failed", ["storage_failed"])),
    ({"storage_failed": False}, ("running", None, [])),
])
def test_intake_storage_failure_is_degraded_not_running(tmp_path, monkeypatch, flags, expected):
    loop, _ = _patched_loop(tmp_path, monkeypatch, lambda v: v["intake"].update(flags))
    intake = loop["intake"]
    assert (intake["status"], intake["reason_code"], intake["conditions"]) == expected


def test_explainer_with_both_flags_lists_both(tmp_path, monkeypatch):
    loop, _ = _patched_loop(tmp_path, monkeypatch,
                            lambda v: v["explainer"].update(storage_failed=True))
    explainer = loop["explainer"]
    assert explainer["status"] == "degraded"
    assert explainer["conditions"] == ["chain_broken", "storage_failed"]


def test_huge_counters_and_ages_stay_exact_or_say_so(tmp_path, monkeypatch):
    def change(v):
        v["intake"].update(written_at=1e300, processed=2**64 - 1, accepted=2**53)
        v["explainer"].update(explained=2**53 - 1)
    loop, raw = _patched_loop(tmp_path, monkeypatch, change)
    intake = loop["intake"]
    assert intake["source"]["age_s"] is None
    assert intake["source"]["age_reason"] == "age_out_of_range"
    assert intake["status"] == "stale" and intake["reason_code"] == "snapshot_dated_in_future"
    assert intake["snapshot"]["processed"] == intake["snapshot"]["accepted"] == "too_large"
    assert loop["explainer"]["snapshot"]["explained"] == 2**53 - 1
    for match in __import__("re").finditer(r"-?\d{16,}", raw):
        assert abs(int(match.group())) <= 2**53 - 1


def test_a_lab_host_refused_step_carries_no_command(tmp_path, monkeypatch):
    view, _, _ = _view("edge-ready-lab-host", tmp_path, monkeypatch)
    actions = view["sections"]["next_actions"]
    refused = [a for a in actions if a["lab_host_unavailable_step"]]
    assert refused and all(a["command"] is None for a in refused)


def test_fixed_text_naming_a_path_is_a_code_in_the_view(tmp_path, monkeypatch):
    view, raw, _ = _view("edge-issuer-authenticated", tmp_path, monkeypatch)
    s = view["sections"]
    systemd = next(h for h in s["health"] if h["subject"] == "systemd units")
    assert systemd["detail"] is None and systemd["withheld"] == ["detail"]
    assert systemd["reason_code"] == "service_manager_not_queried"
    issuer = s["edge_core"]["issuer"]
    assert issuer["issuer_authenticated"] is True and issuer["issuer_status"] == "authenticated"
    assert issuer["withheld"] == ["issuer", "revocation_sequence", "floor_version"]
    assert issuer["notes"] == ["state_directory_unprotected"]
    assert s["edge_core"]["caveats"][0]["text"].startswith("the Edge manifest carries a valid")
    cognition = next(r for r in s["integration"]["rows"] if r["axis"] == "cognition_route")
    assert cognition["reason"] is None and cognition["withheld"] == ["reason"]
    monkeypatch.undo()
    (tmp_path / "absent").mkdir()
    absent, _, _ = _view("absent", tmp_path / "absent", monkeypatch)
    issuer = absent["sections"]["edge_core"]["issuer"]
    assert issuer["issuer_status"] == "not_configured"
    assert issuer["issuer_reason"] is None and "issuer_reason" in issuer["withheld"]


def test_knowledge_available_is_copied_and_unknown_words_are_refused(tmp_path, monkeypatch):
    from azazel_nexus import cli

    view, _, _ = _view("knowledge-available", tmp_path, monkeypatch)
    k = view["sections"]["knowledge_lite"]
    assert (k["status"], k["reason_code"], k["generation"], k["freshness"]) == (
        "available", "available", 5, "current")
    monkeypatch.setattr(cli, "_knowledge_reading", lambda root, *, as_of: {
        "state": "available", "reason_code": "SECRET", "generation": 5, "freshness": "current"})
    (tmp_path / "x").mkdir()
    out = io.StringIO()
    assert main(_argv(tmp_path / "x", json_flag=True), out=out) == 0
    k = json.loads(out.getvalue())["sections"]["knowledge_lite"]
    assert (k["status"], k["reason_code"], k["freshness"]) == ("unknown", "reading_refused", None)
    assert "SECRET" not in out.getvalue()


# -- Knowledge citation display (#362) through the read model ---------------

DISPLAY_REF = {"technique_id": "T1059", "name": "Shell", "claim_id": "T1059",
               "bundle_digest_short": "sha256:0123456789ab", "generation": 7,
               "freshness": "static", "as_of": "2026-09-21T04:00:00Z",
               "citation": "MITRE ATT&CK v14.1", "citation_state": "shown"}


def _with_display_refs(*refs, omitted=None):
    def change(value):
        explanation = value["recent"]["incidents"][0]["explanation"]
        explanation["knowledge_refs"].extend(dict(r) for r in refs)
        if omitted is not None:
            explanation["knowledge_refs_omitted"] = omitted
    return change


def test_citation_display_fields_are_checked_and_copied(tmp_path, monkeypatch):
    loop, _ = _patched_loop(tmp_path, monkeypatch, _with_display_refs(DISPLAY_REF, omitted=2))
    explanation = loop["recent"]["snapshot"]["incidents"][0]["explanation"]
    legacy, shown = explanation["knowledge_refs"]
    assert set(legacy) == {"technique_id", "name", "claim_id"}
    assert shown == {**DISPLAY_REF, "withheld": []}
    assert explanation["knowledge_refs_omitted"] == 2


def test_a_citation_naming_a_path_is_withheld_in_view_and_text(tmp_path, monkeypatch):
    ref = {**DISPLAY_REF, "citation": "see /etc/azazel/knowledge/SECRET.txt"}
    loop, raw = _patched_loop(tmp_path, monkeypatch, _with_display_refs(ref))
    shown = loop["recent"]["snapshot"]["incidents"][0]["explanation"]["knowledge_refs"][1]
    assert (shown["citation"], shown["citation_state"], shown["withheld"]) == (
        "", "withheld", ["citation"])
    assert "SECRET" not in raw
    (tmp_path / "t").mkdir()
    _, text = _patched_loop(tmp_path / "t", monkeypatch, _with_display_refs(ref), json_flag=False)
    assert "SECRET" not in text
    assert ("T1059 Shell [claim T1059] (static; Knowledge Lite bundle sha256:0123456789ab "
            "generation 7; as of 2026-09-21T04:00:00Z; source: declared, withheld (possible "
            "address or path form))") in text


def test_the_text_renders_citations_from_the_view(tmp_path, monkeypatch):
    _, text = _patched_loop(tmp_path, monkeypatch, _with_display_refs(DISPLAY_REF, omitted=1),
                            json_flag=False)
    assert ("T1059 Shell [claim T1059] (static; Knowledge Lite bundle sha256:0123456789ab "
            "generation 7; as of 2026-09-21T04:00:00Z; source: MITRE ATT&CK v14.1)") in text
    assert "1 more Knowledge citation(s) recorded, not shown" in text
    assert ("T1059 Command and Scripting Interpreter [claim T1059] "
            "(bundle, generation and lookup time not recorded)") in text


@pytest.mark.parametrize("change", [
    {"bundle_digest_short": "sha256:" + "a" * 64},
    {"generation": -1},
    {"generation": "7"},
    {"freshness": "SECRET"},
    {"as_of": "SECRET"},
    {"citation_state": "SECRET"},
    {"citation_state": "none"},
    {"citation": "x" * 161},
    {"raw": "SECRET"},
])
def test_citation_display_values_outside_their_shape_refuse_the_snapshot(
        tmp_path, monkeypatch, change):
    loop, raw = _patched_loop(tmp_path, monkeypatch,
                              _with_display_refs({**DISPLAY_REF, **change}))
    assert (loop["recent"]["status"], loop["recent"]["reason_code"]) == (
        "unavailable", "snapshot_refused_by_view")
    assert "SECRET" not in raw


@pytest.mark.parametrize("omitted", [0, 17, "2", True])
def test_an_omitted_count_outside_its_bound_refuses_the_snapshot(tmp_path, monkeypatch, omitted):
    loop, _ = _patched_loop(tmp_path, monkeypatch, _with_display_refs(omitted=omitted))
    assert loop["recent"]["reason_code"] == "snapshot_refused_by_view"


KNOWLEDGE_BUNDLE = {**KNOWLEDGE_AVAILABLE, "signer_key_ids": ["lab-signer"],
                    "bundle_digest_short": "sha256:0123456789ab", "static_count": 3,
                    "current_count": 1, "next_expiry": "2027-01-01T00:00:00Z"}


def _knowledge_status(tmp_path, monkeypatch, reading, *, json_flag):
    from azazel_nexus import cli

    _base(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "_knowledge_reading", lambda root, *, as_of: dict(reading))
    out = io.StringIO()
    assert main(_argv(tmp_path, json_flag=json_flag), out=out) == 0
    if json_flag:
        return json.loads(out.getvalue())["sections"]["knowledge_lite"], out.getvalue()
    return None, out.getvalue()


def test_knowledge_bundle_facts_are_copied_and_shown(tmp_path, monkeypatch):
    k, raw = _knowledge_status(tmp_path, monkeypatch, KNOWLEDGE_BUNDLE, json_flag=True)
    assert k["bundle"] == {"digest_short": "sha256:0123456789ab", "signer_key_ids": ["lab-signer"],
                           "static_count": 3, "current_count": 1,
                           "next_expiry": "2027-01-01T00:00:00Z"}
    assert k["withheld"] == []
    assert set(_paths(json.loads(raw))) <= ALLOWED
    (tmp_path / "t").mkdir()
    _, text = _knowledge_status(tmp_path / "t", monkeypatch, KNOWLEDGE_BUNDLE, json_flag=False)
    assert ("    freshness: current\n"
            "    bundle: sha256:0123456789ab (shortened); signing key ids: lab-signer\n"
            "    claims: static 3; current 1; nearest expiry: 2027-01-01T00:00:00Z\n"
            "    cryptographic implementation") in text


def test_a_four_key_or_refused_reading_has_no_bundle(tmp_path, monkeypatch):
    k, _ = _knowledge_status(tmp_path, monkeypatch, KNOWLEDGE_AVAILABLE, json_flag=True)
    assert k["bundle"] is None and k["withheld"] == []
    (tmp_path / "r").mkdir()
    refused = {"state": "unavailable", "reason_code": "no_bundle", "generation": None,
               "freshness": "absent", **{key: None for key in (
                   "signer_key_ids", "bundle_digest_short", "static_count", "current_count",
                   "next_expiry")}}
    k, _ = _knowledge_status(tmp_path / "r", monkeypatch, refused, json_flag=True)
    assert k["bundle"] is None and k["withheld"] == []


@pytest.mark.parametrize("change, field", [
    ({"bundle_digest_short": "sha256:" + "a" * 64}, "digest_short"),
    ({"bundle_digest_short": None}, "digest_short"),
    ({"signer_key_ids": "SECRET"}, "signer_key_ids"),
    ({"signer_key_ids": ["SECRET\n"]}, "signer_key_ids"),
    ({"static_count": -1}, "static_count"),
    ({"current_count": "1"}, "current_count"),
    ({"next_expiry": "SECRET"}, "next_expiry"),
])
def test_knowledge_bundle_facts_outside_their_shape_are_withheld(
        tmp_path, monkeypatch, change, field):
    k, raw = _knowledge_status(tmp_path, monkeypatch, {**KNOWLEDGE_BUNDLE, **change},
                               json_flag=True)
    assert k["status"] == "available"
    assert k["bundle"][field] is None and k["withheld"] == [f"bundle.{field}"]
    assert "SECRET" not in raw
    (tmp_path / "t").mkdir()
    _, text = _knowledge_status(tmp_path / "t", monkeypatch, {**KNOWLEDGE_BUNDLE, **change},
                                json_flag=False)
    assert "SECRET" not in text and "withheld" in text


def test_a_signing_key_id_naming_a_path_is_terminal_only(tmp_path, monkeypatch):
    reading = {**KNOWLEDGE_BUNDLE, "signer_key_ids": ["keys/SECRET-signer"]}
    k, raw = _knowledge_status(tmp_path, monkeypatch, reading, json_flag=True)
    assert k["bundle"]["signer_key_ids"] is None
    assert k["withheld"] == ["bundle.signer_key_ids"] and "SECRET" not in raw
    (tmp_path / "t").mkdir()
    _, text = _knowledge_status(tmp_path / "t", monkeypatch, reading, json_flag=False)
    assert "signing key ids: keys/SECRET-signer" in text


def test_bundle_facts_beside_a_state_without_a_trusted_bundle_are_withheld(tmp_path, monkeypatch):
    reading = {**KNOWLEDGE_BUNDLE, "state": "quarantined", "reason_code": "revoked",
               "freshness": "absent"}
    k, raw = _knowledge_status(tmp_path, monkeypatch, reading, json_flag=True)
    assert k["bundle"] is None and "sha256:0123456789ab" not in raw
    assert k["withheld"] == [f"bundle.{name}" for name in (
        "digest_short", "signer_key_ids", "static_count", "current_count", "next_expiry")]
# -- boundaries and precedence (mutants that survived the first review) -----


@pytest.mark.parametrize("observed_at, expected", [
    # Without a snapshot the record's own time is the liveness evidence, so
    # the two-day boundary stands; only its code says what expired (#358
    # option 1: the evidence that entryd is alive, not the observation).
    ("2026-09-19T04:01:00+00:00", ("recorded", None)),                  # exactly two days
    ("2026-09-19T04:00:59+00:00", ("stale", "liveness_evidence_expired")),  # and a second
    ("2026-09-21T04:01:05+00:00", ("recorded", None)),                  # five seconds ahead
    ("2026-09-21T04:01:06+00:00", ("stale", "observed_at_in_future")),  # six seconds ahead
])
def test_mio_freshness_boundaries(tmp_path, monkeypatch, observed_at, expected):
    """Kills `>` -> `>=` on the two-day limit and a zero future allowance."""
    from azazel_nexus import cli

    _absent(tmp_path, monkeypatch)
    _recorded_mio(monkeypatch, observed_at)
    mio = cli._status_view(cli._report(None, None), as_of=AS_OF).view["sections"]["mio"]
    assert (mio["status"], mio["reason_code"]) == expected


@pytest.mark.parametrize("offset, expected", [
    (30, ("running", None)), (31, ("stale", "snapshot_expired")),
    (-5, ("running", None)), (-6, ("stale", "snapshot_dated_in_future")),
])
def test_loop_snapshot_freshness_boundaries(tmp_path, monkeypatch, offset, expected):
    loop, _ = _patched_loop(tmp_path, monkeypatch,
                            lambda v: v["intake"].update(written_at=NOW - offset))
    assert (loop["intake"]["status"], loop["intake"]["reason_code"]) == expected


def test_stale_outranks_chain_broken_and_the_condition_stays_listed(tmp_path, monkeypatch):
    """Kills putting `degraded` ahead of `stale`: reason_code is the first
    reason only, and `conditions` keeps what the stale word does not say."""
    loop, _ = _patched_loop(tmp_path, monkeypatch, lambda v: v["explainer"].update(
        written_at=NOW - 31, chain_broken=True))
    explainer = loop["explainer"]
    assert (explainer["status"], explainer["reason_code"]) == ("stale", "snapshot_expired")
    assert explainer["conditions"] == ["chain_broken"]


def test_a_refused_audit_snapshot_is_unknown_not_ok(tmp_path, monkeypatch):
    """The view re-checks the warning codes; when it refuses them the line is
    unknown, and none of the refused snapshot's sentences or codes remain."""
    from azazel_nexus import audit_status

    for name in ("json", "text"):
        (tmp_path / name).mkdir()
    _loop(tmp_path / "json", monkeypatch)
    monkeypatch.setattr(audit_status, "WARNING_REASONS", ("chain_size",))
    out = io.StringIO()
    assert main(_argv(tmp_path / "json", json_flag=True), out=out) == 0
    audit = next(h for h in json.loads(out.getvalue())["sections"]["health"]
                 if h["subject"] == "audit")
    assert (audit["status"], audit["reason_code"]) == ("unknown", "snapshot_refused_by_view")
    assert audit["source"]["reason_code"] == "snapshot_refused_by_view"
    assert audit["detail"] is None and audit["advisory"] is None
    assert audit["advisory_code"] is None and audit["capacity"] is None
    assert audit["withheld"] == ["detail", "advisory"]
    # The terminal keeps the sentences, under the same word as the view.
    monkeypatch.undo()
    _loop(tmp_path / "text", monkeypatch)
    monkeypatch.setattr(audit_status, "WARNING_REASONS", ("chain_size",))
    text = io.StringIO()
    assert main(_argv(tmp_path / "text"), out=text) == 0
    assert "    audit: unknown -- WARNING: capacity warning" in text.getvalue()


# -- M.I.O. liveness (#358 option 1): an unchanged reading is not a stopped writer --


THREE_DAYS_AGO = "2026-09-18T04:01:00+00:00"


def _mio_snapshot(tmp_path, *, written_at, observed_at=THREE_DAYS_AGO, state="CORE",
                  uncertain=False, recorded=True):
    """entryd's operator snapshot, as `mio_snapshot` writes it."""
    from azazel_nexus import operator_snapshots as snap
    from azazel_nexus.runtime_paths import mio_status_path

    reasons = {"profile": "LITE", "resource": "core_reserve_unmeasured",
               "trust": "not-checked", "topology": "no_verified_egress",
               "health": {"local": "not_admitted", "remote": "unavailable"}}
    value = snap.mio_snapshot({"state": state, "reasons": reasons} if recorded else None,
                              observed_at, uncertain=uncertain, written_at=written_at)
    path = mio_status_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _mio_view(tmp_path, monkeypatch, *, observed_at=THREE_DAYS_AGO, recorded_at=None,
              as_of=AS_OF):
    from azazel_nexus import cli, mio_status

    reading = _recorded_mio(monkeypatch, observed_at)
    if recorded_at is not None:
        monkeypatch.setattr(mio_status, "status_summary",
                            lambda: {**json.loads(json.dumps(reading)), "recorded_at": recorded_at})
    view = cli._status_view(cli._report(None, None), as_of=as_of).view
    assert set(_paths(view)) <= ALLOWED
    return view["sections"]["mio"]


def test_a_stable_node_with_a_fresh_snapshot_is_not_stale(tmp_path, monkeypatch):
    """The transition was three days ago; entryd wrote its snapshot a minute ago."""
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW - 60)
    mio = _mio_view(tmp_path, monkeypatch)
    assert (mio["status"], mio["reason_code"]) == ("recorded", None)
    assert mio["age_s"] == 3 * 86400  # unchanged for three days: shown, not judged
    live = mio["liveness"]
    assert (live["status"], live["reason_code"], live["evidence"]) == (
        "evidenced", None, "operator_snapshot")
    assert live["operator_snapshot"] == {"status": "counted", "reason_code": None,
                                         "written_at": NOW - 60, "age_s": 60,
                                         "stale_after_s": 300}
    assert live["route_ledger_record"]["reason_code"] == "route_record_expired"


def test_a_stopped_node_whose_snapshot_is_old_is_stale(tmp_path, monkeypatch):
    """entryd stopped: its last snapshot is ten minutes old and the record three days."""
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW - 600)
    mio = _mio_view(tmp_path, monkeypatch)
    assert (mio["status"], mio["reason_code"]) == ("stale", "liveness_evidence_expired")
    live = mio["liveness"]
    assert (live["status"], live["evidence"]) == ("not_evidenced", None)
    assert live["operator_snapshot"]["reason_code"] == "snapshot_expired"
    assert live["route_ledger_record"]["status"] == "not_counted"


@pytest.mark.parametrize("age, expected", [
    (300, ("recorded", None)), (301, ("stale", "liveness_evidence_expired")),
    (-5, ("recorded", None)), (-6, ("stale", "liveness_evidence_in_future")),
])
def test_the_snapshot_evidence_uses_the_snapshot_stale_limit(tmp_path, monkeypatch, age, expected):
    """Kills `>` -> `>=` on `MIO_STALE_S` and a missing future allowance."""
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW - age)
    mio = _mio_view(tmp_path, monkeypatch)
    assert (mio["status"], mio["reason_code"]) == expected


@pytest.mark.parametrize("change, code", [
    ({"state": "LITE"}, "snapshot_reading_differs"),
    ({"observed_at": "2026-09-18T04:00:59+00:00"}, "snapshot_reading_differs"),
    ({"uncertain": True}, "capability_record_uncertain"),
    ({"recorded": False}, "no_recorded_capability_transition"),
])
def test_a_fresh_snapshot_of_another_reading_does_not_vouch_for_this_one(
        tmp_path, monkeypatch, change, code):
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW - 60, **change)
    mio = _mio_view(tmp_path, monkeypatch)
    assert (mio["status"], mio["reason_code"]) == ("stale", "liveness_evidence_expired")
    assert mio["liveness"]["operator_snapshot"]["status"] == "not_counted"
    assert mio["liveness"]["operator_snapshot"]["reason_code"] == code


def test_a_damaged_snapshot_is_no_evidence(tmp_path, monkeypatch):
    from azazel_nexus.runtime_paths import mio_status_path

    _absent(tmp_path, monkeypatch)
    path = mio_status_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'{"schema":')
    mio = _mio_view(tmp_path, monkeypatch)
    assert (mio["status"], mio["reason_code"]) == ("stale", "liveness_evidence_expired")
    assert mio["liveness"]["operator_snapshot"]["reason_code"] == "snapshot_absent_or_refused"


@pytest.mark.parametrize("recorded_at, expected, basis", [
    # The carried record a day's first write opened a segment with.
    ("2026-09-20T00:00:00+00:00", ("recorded", None), "record_written"),
    ("2026-09-19T04:01:00+00:00", ("recorded", None), "record_written"),      # two days
    ("2026-09-19T04:00:59+00:00", ("stale", "liveness_evidence_expired"), "record_written"),
    ("2026-09-21T04:01:06+00:00", ("stale", "liveness_evidence_in_future"), "record_written"),
    # Not later than the ledger holds: an earlier, unzoned or unreadable time
    # falls back to the observation, which is three days old.
    ("2026-09-17T00:00:00+00:00", ("stale", "liveness_evidence_expired"), "observation"),
    ("2026-09-20T00:00:00", ("stale", "liveness_evidence_expired"), "observation"),
    ("not a time", ("stale", "liveness_evidence_expired"), "observation"),
])
def test_the_route_ledger_record_is_the_secondary_evidence(
        tmp_path, monkeypatch, recorded_at, expected, basis):
    _absent(tmp_path, monkeypatch)
    mio = _mio_view(tmp_path, monkeypatch, recorded_at=recorded_at)
    assert (mio["status"], mio["reason_code"]) == expected
    record = mio["liveness"]["route_ledger_record"]
    assert record["basis"] == basis and record["stale_after_s"] == 2 * 86400
    if expected[0] == "recorded":
        assert mio["liveness"]["evidence"] == "route_ledger_record"


def test_a_future_dated_snapshot_outranks_a_recent_record(tmp_path, monkeypatch):
    """A clock that went back: stale, even though the ledger would vouch."""
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW + 3600, observed_at="2026-09-21T03:00:00+00:00")
    mio = _mio_view(tmp_path, monkeypatch, observed_at="2026-09-21T03:00:00+00:00")
    assert (mio["status"], mio["reason_code"]) == ("stale", "liveness_evidence_in_future")
    # The snapshot is there, so the recent record is not counted either.
    assert mio["liveness"]["route_ledger_record"]["reason_code"] == "operator_snapshot_present"


@pytest.mark.parametrize("observed_at, as_of, expected", [
    ("2026-09-21T04:05:00+00:00", AS_OF, ("stale", "observed_at_in_future")),
    ("2026-09-21T04:00:00", AS_OF, ("unknown", "observed_at_unreadable")),
    ("2026-09-21T04:00:00+00:00", "not a time", ("unknown", "clock_unknown")),
])
def test_a_fresh_snapshot_does_not_rescue_an_unsafe_reading(
        tmp_path, monkeypatch, observed_at, as_of, expected):
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW - 10, observed_at="2026-09-21T04:00:00+00:00")
    mio = _mio_view(tmp_path, monkeypatch, observed_at=observed_at, as_of=as_of)
    assert (mio["status"], mio["reason_code"]) == expected
    assert mio["liveness"]["status"] == "unknown"
    assert mio["liveness"]["reason_code"] == expected[1]
    assert mio["age_s"] is None  # never a negative period


def test_an_unreadable_ledger_is_unknown_whatever_the_snapshot_says(tmp_path, monkeypatch):
    from azazel_nexus import cli

    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, written_at=NOW - 10)
    mio = cli._status_view(cli._report(None, None), as_of=AS_OF).view["sections"]["mio"]
    assert (mio["status"], mio["reason_code"]) == ("unknown", "route_ledger_unreadable_or_refused")
    assert mio["liveness"] == {"status": "unknown",
                               "reason_code": "route_ledger_unreadable_or_refused",
                               "evidence": None, "operator_snapshot": None,
                               "route_ledger_record": None}
    assert mio["age_s"] is None


@pytest.mark.parametrize("snapshot, ledger", [
    # entryd stopped ten minutes ago; the day's carried record is a day old.
    ({"written_at": NOW - 600}, {"recorded_at": "2026-09-20T04:01:00+00:00"}),
    # The same, with a transition a day ago as the only record.
    ({"written_at": NOW - 600, "observed_at": "2026-09-20T04:01:00+00:00"},
     {"observed_at": "2026-09-20T04:01:00+00:00"}),
    # A fresh snapshot that does not count is not replaced by the ledger.
    ({"written_at": NOW - 60, "state": "LITE"}, {"recorded_at": "2026-09-20T04:01:00+00:00"}),
    ({"written_at": NOW - 60, "uncertain": True}, {"recorded_at": "2026-09-20T04:01:00+00:00"}),
    ({"written_at": NOW - 60, "recorded": False}, {"recorded_at": "2026-09-20T04:01:00+00:00"}),
])
def test_a_recent_record_does_not_keep_a_stopped_writer_alive(tmp_path, monkeypatch, snapshot, ledger):
    """Review M1 of #370: with entryd's snapshot present, a route ledger
    record up to two days old must not stand in for it."""
    _absent(tmp_path, monkeypatch)
    _mio_snapshot(tmp_path, **snapshot)
    mio = _mio_view(tmp_path, monkeypatch, **ledger)
    assert (mio["status"], mio["reason_code"]) == ("stale", "liveness_evidence_expired")
    live = mio["liveness"]
    assert (live["status"], live["evidence"]) == ("not_evidenced", None)
    assert live["route_ledger_record"] == {**live["route_ledger_record"],
                                           "status": "not_counted",
                                           "reason_code": "operator_snapshot_present"}


def test_without_a_snapshot_a_recent_record_still_counts(tmp_path, monkeypatch):
    _absent(tmp_path, monkeypatch)
    mio = _mio_view(tmp_path, monkeypatch, recorded_at="2026-09-20T04:01:00+00:00")
    assert (mio["status"], mio["reason_code"]) == ("recorded", None)
    assert mio["liveness"]["evidence"] == "route_ledger_record"


def test_recent_view_preserves_checked_slow_projection():
    from azazel_nexus.status_view import _recent_extra
    recent = _recent(NOW - 2)
    slow = {'state': 'degraded', 'usage': 'unknown', 'budget': {
        'version': 1, 'outcome': 'stop_unconfirmed', 'coverage': 'unknown',
        'cleanup_state': 'unconfirmed', 'superseded': False, 'omitted_units': 0,
        'reasons': ['timeout', 'stop_unconfirmed'], 'fence_state': 'unknown',
        'dispatch': [{'task': 'generate_hypotheses', 'dispatched': True},
                     {'task': 'identify_evidence_gaps', 'dispatched': False},
                     {'task': 'recommend', 'dispatched': False}]}}
    recent['incidents'][0]['explanation']['slow_analysis'] = slow
    snapshot = {}
    _recent_extra(recent, snapshot)
    from azazel_nexus.incident_explain import SLOW_WITHHOLD_REASONS
    assert snapshot['incidents'][0]['explanation']['slow_analysis'] == {
        **slow, 'reason_code': 'no_current_slow_result',
        'reason_ja': SLOW_WITHHOLD_REASONS['no_current_slow_result']}
    slow['budget']['reasons'].append('private payload')
    with pytest.raises(Exception):
        _recent_extra(recent, {})
