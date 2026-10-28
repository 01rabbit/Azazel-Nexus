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


def _base(tmp_path, monkeypatch, *, lab=False, fabric="absent", measured=True):
    monkeypatch.setattr("azazel_nexus.edge_package._probe_owner_uid", os.geteuid)
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
    _base(tmp_path, monkeypatch, fabric="0.9.0rc5")
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
    "ledger-missing": _ledger_missing,
    "ledger-broken": _ledger_broken,
}


def run_scenario(name, tmp_path, monkeypatch, *, json_flag=False):
    """`(exit code, stdout, stderr)` of `status` in the named scenario."""
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
    *(f"sections.external_modules[].{k}" for k in ("name", "state", "reason", "working")),
    # knowledge lite
    "sections.knowledge_lite", *(f"sections.knowledge_lite.{k}" for k in (
        "status", "reason_code", "generation", "freshness", "readiness",
        "readiness.functional", "readiness.word", "readiness.means",
        "readiness.does_not_mean", "readiness.does_not_mean[]",
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
        "rows[].value", "rows[].defect", "rows[].reason", "enforcement_capable",
        "baseline_ready", "continues", "continues[]", "broker", "broker.status_level",
        "broker.informational", "broker.core", "broker.transport", "broker.transport_reason")),
    # fabric
    "sections.fabric", "sections.fabric.status", "sections.fabric.reason_code",
    "sections.fabric.version",
    # health and next actions
    "sections.health", "sections.health[]", *(f"sections.health[].{k}" for k in (
        "subject", "status", "detail", "advisory", "withheld", "withheld[]", "reason_code",
        "source", "source.kind", "source.schema", "source.written_at", "source.freshness",
        "source.reason_code", "source.age_s", "source.withheld", "source.withheld[]")),
    "sections.next_actions", "sections.next_actions[]", *(f"sections.next_actions[].{k}" for k in (
        "summary", "command", "lab_host_unavailable_step", "withheld", "withheld[]")),
}
_LOOP = "sections.edge_loop"
_SOURCE = ("source", "source.kind", "source.schema", "source.written_at", "source.freshness",
           "source.reason_code", "source.age_s")
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
                        "edge_decision", "edge_decision.kind", "edge_decision.action",
                        "edge_decision.executed", "edge_decision.decided_by",
                        "execution_result", "execution_result.status",
                        "execution_result.reason_code"))))):
    ALLOWED |= {f"{_LOOP}.{_name}", f"{_LOOP}.{_name}.status", f"{_LOOP}.{_name}.reason_code",
                f"{_LOOP}.{_name}.snapshot",
                *(f"{_LOOP}.{_name}.{k}" for k in _SOURCE),
                *(f"{_LOOP}.{_name}.snapshot.{k}" for k in _fields)}

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
    "192.0.2.1", "SECRET",
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
    assert chain["withheld"] == ["detail", "advisory"]
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
                                        "reason_code": None, "age_s": 5}
    assert loop["explainer"]["source"]["schema"] == "azazel-nexus/incident-explain-status/v1"
    assert loop["recent"]["source"]["schema"] == RECENT_SCHEMA
    assert loop["intake"]["status"] == loop["explainer"]["status"] == "running"
    forward = loop["intake"]["snapshot"]["edge_forward_freshness"]
    assert forward == {"status": "stale", "reported_by": "edge", "age_s": 1000}
    assert loop["intake"]["snapshot"]["decoy_status"]["observer"] == "nexus"
    audit = next(h for h in view["sections"]["health"] if h["subject"] == "audit")
    assert audit["status"] == "ok" and audit["source"]["freshness"] == "fresh"
    assert audit["advisory"].startswith("capacity warning")
    assert view["sections"]["fabric"] == {"status": "projected", "reason_code": None,
                                          "version": "0.9.0rc5"}
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
    grows a citation field (provenance, time, digest), this fails until the
    field is added to `KNOWLEDGE_REF_FIELDS` -- deliberately, not silently."""
    from azazel_nexus import edge_loop_status, status_view

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
    (lambda root, mp: _fabric(mp, "0.9.0rc5"), {"fabric"}),
    # The measured envelope is an input of the cognition axis (its resource
    # gate), so the integration view moves with it -- by design, not leakage.
    (lambda root, mp: _measured(mp), {"profile", "next_actions", "integration"}),
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
