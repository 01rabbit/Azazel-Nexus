"""One bounded Linux process path through entryd, locald and Knowledge Lite.

This uses real service UIDs, SO_PEERCRED, the public runtime frame protocol
and production daemons. The knowledge-builder case imports unmodified output
from Knowledge's pinned build-lite CLI through the ROOT-only operator socket
and production audit daemon. All input data and signers are lab-only.
"""
from __future__ import annotations

import grp
import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/unit"))


def _identity(name: str):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        pytest.skip(f"disposable process identity {name} is not provisioned")


def _group(name: str) -> int:
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        pytest.skip(f"disposable process group {name} is not provisioned")


def _credentials(user: str, groups: tuple[int, ...]):
    record = _identity(user)
    if os.geteuid() != 0:
        pytest.skip("real service UID setup requires the disposable container's root")

    def drop():
        os.setgroups(list(groups))
        os.setgid(record.pw_gid)
        os.setuid(record.pw_uid)

    return drop


def _owned_dir(path: Path, uid: int, gid: int, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)
    os.chown(path, uid, gid)


def _own_tree(path: Path, uid: int, gid: int) -> None:
    for item in (path, *path.rglob("*")):
        item.chmod(0o750 if item.is_dir() else 0o640)
        os.chown(item, uid, gid)


def _wait_socket(path: Path, process: subprocess.Popen, deadline: float) -> None:
    while time.monotonic() < deadline:
        if process.poll() is not None:
            detail = process.stderr.read(4096).decode("utf-8", "replace") if process.stderr else ""
            pytest.fail(f"daemon exited before binding its declared socket: {detail[-600:]}")
        try:
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode):
                return
        except FileNotFoundError:
            pass
        time.sleep(0.025)
    pytest.fail("daemon did not bind its declared socket before the deadline")


def _request_child(env: dict[str, str], user: str, groups: tuple[int, ...], *, deadline_ms=500):
    # The child sends the normal public `mio.advise` request and prints only a
    # fixed, redacted projection. No question, context, citation text, digest,
    # or service log is surfaced as process evidence.
    code = r'''
import json
import sys
import time
from azazel_nexus_runtime.mio_socket_client import _exchange
frame = {
  "request_id": "process-evidence",
  "privacy_class": "P3-restricted",
  "question": "SSH brute-force observations; technique T1110",
  "context": [{"kind": "auth_log", "text": "redacted test fixture"}],
}
try:
  started = time.monotonic()
  reply = _exchange("mio-advise", "azmioentry", "mio.advise",
                    {"deadline_ms": int(sys.argv[1])}, payload=frame,
                    deadline_s=int(sys.argv[1]) / 1000 + .25)
  elapsed_ms = (time.monotonic() - started) * 1000
  fast = reply["fast_assistance"]
  knowledge = fast["knowledge"]
  print(json.dumps({
    "route": reply["route"],
    "state": fast["state"],
    "knowledge_status": fast["dependency_outcome"]["knowledge"],
    "knowledge_count": len(knowledge),
    "knowledge_technique": knowledge[0]["technique_id"] if knowledge else None,
    "knowledge_generation": knowledge[0]["generation"] if knowledge else None,
    "knowledge_source_kind": knowledge[0]["source_kind"] if knowledge else None,
    "knowledge_trust_check": knowledge[0]["trust_check"] if knowledge else None,
    "knowledge_revocation_status": knowledge[0]["revocation_status"] if knowledge else None,
    "same_handoff": fast["handoff"] is not None and fast["handoff"]["frame_id"] == fast["frame_id"],
    "empty_summary": knowledge[0]["summary"] == "" if knowledge else None,
    "canonical_citation": knowledge[0]["citation"] == knowledge[0]["claim_id"] if knowledge else None,
    "source_citation_preserved": knowledge[0]["source_citation"] == "MITRE ATT&CK technique, as ingested into azazel-knowledge intel.attack_technique" if knowledge else None,
    "elapsed_ms": elapsed_ms,
  }, sort_keys=True))
except Exception as error:
  print(getattr(error, "refusal", type(error).__name__))
  raise SystemExit(1)
'''
    proc = subprocess.run(
        [sys.executable, "-B", "-c", code, str(deadline_ms)], cwd=ROOT, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=6, check=False, preexec_fn=_credentials(user, groups),
        text=True,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[:80]
    # Strictly parse the bounded child projection; no raw daemon output passes.
    result = json.loads(proc.stdout)
    assert set(result) == {
        "route", "state", "knowledge_status", "knowledge_count",
        "knowledge_technique", "knowledge_generation", "knowledge_source_kind",
        "knowledge_trust_check", "knowledge_revocation_status",
        "elapsed_ms", "same_handoff", "empty_summary", "canonical_citation",
        "source_citation_preserved",
    }
    return result


def _poll_generation_child(env: dict[str, str], user: str, groups: tuple[int, ...]):
    """Exercise the explainer-only entry socket and expose only terminal state."""
    code = r'''
import json
from azazel_nexus_runtime.mio_socket_client import _exchange
trace = "mio-0123456789abcdef-1"
reply = _exchange("mio-advise", "azmioentry", "mio.generation.result", {
  "deadline_ms": 50, "result_handle": "a" * 64,
  "generation_id": "process-generation", "frame_id": trace + ":frame",
  "trace_id": trace,
}, deadline_s=.25)
value = reply["slow_analysis"]
print(json.dumps({"outcome": reply["outcome"], "state": value["state"],
                  "usage": value["usage"]}, sort_keys=True))
'''
    proc = subprocess.run(
        [sys.executable, "-B", "-c", code], cwd=ROOT, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=3, check=False, preexec_fn=_credentials(user, groups), text=True,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[:80]
    result = json.loads(proc.stdout)
    assert set(result) == {"outcome", "state", "usage"}
    return result


def _send_edge_alert(env: dict[str, str], socket_path: Path, groups: tuple[int, ...]) -> None:
    """Send one fixed producer fixture through the public intake socket as azedge."""
    from tools.e2e_loop import golden_lines

    proc = subprocess.run(
        [sys.executable, "-B", "-c", (
            "import socket,sys; s=socket.socket(socket.AF_UNIX); "
            "s.settimeout(2); s.connect(sys.argv[1]); "
            "s.sendall(bytes.fromhex(sys.argv[2])); s.close()"
        ), str(socket_path), golden_lines()[0].hex() + "0a"],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=4, check=False,
        preexec_fn=_credentials("azedge", groups), text=True,
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[:80]


def _assert_socket_identity(path: Path, uid: int, gid: int) -> None:
    # transport.bind_socket uses principal.REQUIRED_SOCKET_MODE (0660).
    from azazel_nexus_runtime.principal import REQUIRED_SOCKET_MODE
    info = path.lstat()
    assert stat.S_ISSOCK(info.st_mode)
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, REQUIRED_SOCKET_MODE)


def _refuse_operator_calls(env: dict[str, str], entry_id: str, groups: tuple[int, ...]) -> None:
    # Give the non-root operator DAC access so this exercises verb admission,
    # rather than merely failing to traverse the socket's parent directory.
    # knowledge.IMPORT_VERB admits ROOT; audit.VERBS admits ROOT/SERVICE.
    code = r'''
import sys
from azazel_nexus_runtime.mio_socket_client import _exchange, ServiceRefused
calls = (
    ("knowledge", "azknowledge", "knowledge.import", {"entry_id": sys.argv[1]}),
    ("audit-submit", "azaudit", "audit.append", {"event_type": "knowledge.lite.import_started"}),
)
for leaf, account, verb, arguments in calls:
    try:
        _exchange(leaf, account, verb, arguments, deadline_s=1)
    except ServiceRefused as error:
        assert error.refusal == "principal_denied"
    else:
        raise AssertionError("unauthorized call admitted")
'''
    result = subprocess.run([sys.executable, "-B", "-c", code, entry_id], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=4, check=False,
                            preexec_fn=_credentials("azoperator", groups))
    assert result.returncode == 0, "unauthorized operator call did not refuse as declared"


@pytest.mark.real_process
@pytest.mark.parametrize("real_producer", [False, True], ids=["synthetic-reader", "knowledge-builder"])
@pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is required")
def test_edge_intake_normal_process_reaches_explainer_mio_and_knowledge(request, monkeypatch, real_producer):
    """One producer-shaped alert follows both production daemon entrypoints."""
    package_installed = importlib.util.find_spec("azazel_mio") is not None
    import test_knowledge_lited as knowledge_tests
    from test_knowledge_lookup import _producer_manifest, admit_rows
    from azazel_nexus.incident_explain import read_record

    if os.geteuid() != 0:
        pytest.skip("requires root only inside the disposable test container")
    ids = {name: _identity(name) for name in (
        "azknowledge", "azmio", "azmioentry", "azintake", "azedge", "azexplain")}
    groups = {name: _group(name) for name in (
        "azazel-operator", "azknowledge-read", "azincident-read", "azedge", "azmio-advise",
        "azmission-read")}
    runtime_root = Path(tempfile.mkdtemp(prefix="nxs-edge-mio-", dir="/tmp"))
    runtime_root.chmod(0o755)
    request.addfinalizer(lambda: shutil.rmtree(runtime_root, ignore_errors=True))
    monkeypatch.setenv("AZAZEL_ROOT", str(runtime_root))
    _, store, trust, _ = knowledge_tests.node.__wrapped__(runtime_root, monkeypatch)
    if real_producer:
        from test_real_knowledge_lite_fixture import commission_real_fixture
        entry_id = commission_real_fixture(store, trust)
        ids["azaudit"] = _identity("azaudit")
        ids["azoperator"] = _identity("azoperator")
        groups["azaudit-submit"] = _group("azaudit-submit")
    else:
        manifest, rows = _producer_manifest()
        admit_rows((None, store, trust, None), rows, profile=manifest["profile"])

    azazel = runtime_root / "var/lib/azazel"
    for path, mode in ((runtime_root / "var", 0o755), (runtime_root / "var/lib", 0o755),
                       (azazel, 0o711), (azazel / "run", 0o711),
                       (azazel / "run/ui-read", 0o711)):
        _owned_dir(path, 0, 0, mode)
    run = azazel / "run"
    _owned_dir(run / "knowledge", ids["azknowledge"].pw_uid, groups["azazel-operator"], 0o2710)
    _owned_dir(run / "knowledge-read", ids["azknowledge"].pw_uid, groups["azknowledge-read"], 0o2710)
    _owned_dir(run / "mio", ids["azmio"].pw_uid, groups["azazel-operator"], 0o2710)
    _owned_dir(run / "mio-entry", ids["azmioentry"].pw_uid, groups["azazel-operator"], 0o2710)
    _owned_dir(run / "mio-advise", ids["azmioentry"].pw_uid, groups["azmio-advise"], 0o2710)
    _owned_dir(run / "edge-intake", ids["azintake"].pw_uid, groups["azedge"], 0o2710)
    _owned_dir(run / "knowledge-status", ids["azknowledge"].pw_uid, groups["azazel-operator"], 0o2750)
    _owned_dir(run / "mio-status", ids["azmioentry"].pw_uid, groups["azazel-operator"], 0o2750)
    _owned_dir(run / "edge-intake-status", ids["azintake"].pw_uid, groups["azazel-operator"], 0o2750)
    _owned_dir(run / "incident-explain-status", ids["azexplain"].pw_uid, groups["azazel-operator"], 0o2750)
    _owned_dir(run / "ui-read/edge-intake", ids["azintake"].pw_uid, 0, 0o2750)
    _owned_dir(run / "ui-read/incident-explain", ids["azexplain"].pw_uid, 0, 0o2750)
    _owned_dir(azazel / "state", 0, 0, 0o711)
    _owned_dir(azazel / "state/knowledge", ids["azknowledge"].pw_uid, ids["azknowledge"].pw_gid, 0o700)
    _owned_dir(azazel / "state/mio", ids["azmioentry"].pw_uid, 0, 0o700)
    _owned_dir(azazel / "mio", ids["azmio"].pw_uid, ids["azmio"].pw_gid, 0o750)
    _owned_dir(azazel / "edge-intake", ids["azintake"].pw_uid, 0, 0o700)
    _owned_dir(azazel / "edge-incidents", ids["azintake"].pw_uid, groups["azincident-read"], 0o2750)
    _owned_dir(azazel / "incident-explain", ids["azexplain"].pw_uid, 0, 0o700)
    _own_tree(store, ids["azknowledge"].pw_uid, groups["azazel-operator"])
    _own_tree(trust, ids["azknowledge"].pw_uid, ids["azknowledge"].pw_gid)

    if real_producer:
        for leaf, gid, mode in (("audit", groups["azazel-operator"], 0o2710),
                                ("audit-submit", groups["azaudit-submit"], 0o2710),
                                ("audit-status", groups["azazel-operator"], 0o2750)):
            _owned_dir(run / leaf, ids["azaudit"].pw_uid, gid, mode)
        _owned_dir(azazel / "state/audit", ids["azaudit"].pw_uid, ids["azaudit"].pw_gid, 0o700)
        _owned_dir(run / "ui-read/audit", ids["azaudit"].pw_uid, 0, 0o2750)

    env = os.environ.copy()
    env.update({"AZAZEL_ROOT": str(runtime_root),
                "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "runtime/src"), str(ROOT / "tests"))),
                "PYTHONDONTWRITEBYTECODE": "1"})
    children = []
    try:
        launch_specs = (
            ("azknowledge", (groups["azazel-operator"],) +
             ((groups["azaudit-submit"],) if real_producer else ()), "azazel_nexus_runtime.knowledge_lited"),
            ("azmio", (groups["azknowledge-read"], groups["azmission-read"]), "azazel_nexus_runtime.mio_locald"),
            ("azmioentry", (groups["azazel-operator"],), "azazel_nexus_runtime.mio_entryd"),
            ("azintake", (groups["azincident-read"],), "azazel_nexus_runtime.edge_intaked"),
            ("azexplain", (groups["azincident-read"], groups["azknowledge-read"], groups["azmio-advise"]),
             "azazel_nexus_runtime.incident_explaind"),
        )
        if real_producer:
            launch_specs += (("azaudit", (), "azazel_nexus_runtime.auditd"),)
        for account, extra_groups, module in launch_specs:
            script = f"from {module} import main; raise SystemExit(main())"
            children.append(subprocess.Popen(
                [sys.executable, "-B", "-c", script], cwd=ROOT, env=env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                preexec_fn=_credentials(account, extra_groups)))
        for path, child in ((run / "knowledge/knowledge.sock", children[0]),
                            (run / "knowledge-read/knowledge-read.sock", children[0]),
                            (run / "mio/mio.sock", children[1]),
                            (run / "mio-entry/mio-entry.sock", children[2]),
                            (run / "edge-intake/edge-intake.sock", children[3])):
            _wait_socket(path, child, time.monotonic() + 6)
        _wait_socket(run / "mio-advise/mio-advise.sock", children[2], time.monotonic() + 6)
        poll = _poll_generation_child(env, "azexplain", (groups["azmio-advise"],))
        assert poll == {"outcome": "generation_result", "state": "stale", "usage": "unknown"}
        if real_producer:
            _wait_socket(run / "audit-submit/audit-submit.sock", children[-1], time.monotonic() + 6)
            for leaf, account, group in (
                ("knowledge", "azknowledge", "azazel-operator"),
                ("knowledge-read", "azknowledge", "azknowledge-read"),
                ("mio", "azmio", "azazel-operator"),
                ("mio-entry", "azmioentry", "azazel-operator"),
                ("mio-advise", "azmioentry", "azmio-advise"),
                ("edge-intake", "azintake", "azedge"),
                ("audit", "azaudit", "azazel-operator"),
                ("audit-submit", "azaudit", "azaudit-submit"),
            ):
                _assert_socket_identity(run / leaf / (leaf + ".sock"), ids[account].pw_uid, groups[group])
            before = knowledge_tests.snapshot(store, trust, azazel / "state/audit")
            _refuse_operator_calls(env, entry_id, (groups["azazel-operator"], groups["azaudit-submit"]))
            assert knowledge_tests.snapshot(store, trust, azazel / "state/audit") == before
            code = ("from azazel_nexus_runtime.lite_operator_cli import run_import; "
                    f"raise SystemExit(run_import({entry_id!r}))")
            imported = subprocess.run([sys.executable, "-B", "-c", code], cwd=ROOT, env=env,
                                      capture_output=True, text=True, timeout=12, check=False)
            assert imported.returncode == 0, imported.stdout[:200]
            assert json.loads(imported.stdout)["audit_complete"] is True
            assert hashlib.sha256((store / "admitted/current.tar.gz").read_bytes()).hexdigest() == entry_id
        _send_edge_alert(env, run / "edge-intake/edge-intake.sock", (groups["azedge"],))

        explanation_dir = azazel / "incident-explain/explanations"
        status_path = run / "incident-explain-status/status.json"
        deadline = time.monotonic() + 12
        status, lines = {}, []
        while time.monotonic() < deadline:
            assert all(child.poll() is None for child in children)
            try:
                status = json.loads(status_path.read_text())
                records = sorted(explanation_dir.glob("*.jsonl"))
                lines = [line for path in records for line in path.read_bytes().splitlines()]
                if status.get("explained", 0) >= 1 and lines:
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.05)
        assert status["explained"] >= 1
        assert len(lines) >= 1
        record = read_record(json.loads(lines[0]))
        assert record["transition"] == "opened"
        assert record["technique_ids"] == ["T1021.004", "T1110"]
        assert record["mio"]["route"] == "deterministic handoff"
        # The MIO fast-assistance object comes from entryd's reply, validated
        # by read_mio_reply. The 500ms incident path preserves the core and
        # delivery reserves, leaving no optional lookup share.
        mio_fast = record["mio"]["fast_assistance"]
        if package_installed:
            outcome = mio_fast["dependency_outcome"]["knowledge"]
            assert mio_fast["knowledge"] == []
            expected_refs = [ref["evidence_id"] for ref in record["evidence"]["refs"]]
            assert expected_refs and all(ref.startswith("sha256:") and len(ref) == 71
                                          for ref in expected_refs)
            if real_producer:
                # The real-builder path must prove the shared fast core
                # completed without a Knowledge query; no timeout is allowed.
                assert outcome == "not_queried"
            else:
                # Synthetic-reader runs share the 500 ms explainer deadline
                # with earlier ledger and probe work, so the typed timeout
                # fallback is accepted here only.
                assert outcome in {"not_queried", "timeout"}
            if outcome == "not_queried":
                from azazel_nexus.audit import AuditLedger

                incident_hex = record["incident_id"][4:]
                expected_event = "edge.incident." + record["transition"]
                matching_entries = [
                    entry
                    for path in sorted((azazel / "edge-incidents").glob("????-??-??.jsonl"))
                    for entry in AuditLedger(path, private=True)
                    if entry.event.get("incident_id") == record["incident_id"]
                    and entry.event.get("event_type") == expected_event
                ]
                assert matching_entries
                expected_sequence = matching_entries[-1].sequence
                assert mio_fast["trace_id"] == f"mio-{incident_hex}-{expected_sequence}"
                assert mio_fast["frame_id"] == mio_fast["trace_id"] + ":frame"
                grounded_refs = [ref for hypothesis in mio_fast["hypotheses"]
                                 for ref in hypothesis.get("supporting_evidence_refs", [])]
                assert grounded_refs == expected_refs
                assert mio_fast["observations"] == []
            else:
                # A fixed dependency-unavailable response has no incident-bound
                # trace; the delivery reader has already validated its shape.
                assert outcome == "timeout"
                assert mio_fast["state"] == "dependency_unavailable"
                assert mio_fast["observations"] == []
                assert mio_fast["hypotheses"] == []
                assert not mio_fast["trace_id"].startswith(
                    f"mio-{record['incident_id'][4:]}-")
            assert record["edge_would"] == "notify"
        else:
            assert mio_fast["state"] == "dependency_unavailable"
            assert mio_fast["dependency_outcome"]["knowledge"] == "unavailable"
        assert mio_fast["knowledge"] == []

        # These refs are the explainer's separate Knowledge Lite query.
        assert record["knowledge_state"] == "available"
        assert record["knowledge_refs"]
        assert any(ref["technique_id"] == "T1110" for ref in record["knowledge_refs"])
        assert all(ref["source_kind"] == "knowledge_lite"
                   and ref["trust_check"] == "verified"
                   and ref["generation"] == 5
                   and ref["claim_id"] == ref["technique_id"]
                   and ref["freshness"] in {"current", "static"}
                   and len(ref["bundle_digest"]) == 71
                   and ref["bundle_digest"].startswith("sha256:")
                   and all(char in "0123456789abcdef" for char in ref["bundle_digest"][7:])
                   for ref in record["knowledge_refs"])
        assert all(child.poll() is None for child in children)
        if real_producer and package_installed:
            # Same real imported bundle, authenticated locald, ordinary public
            # advise entrypoint. A larger legal request budget funds optional
            # context without stealing the 500ms incident path's reserves.
            claim = _request_child(env, "azexplain", (groups["azmio-advise"],), deadline_ms=1500)
            assert claim["knowledge_status"] == "available"
            assert claim["knowledge_count"] == 1
            assert claim["knowledge_technique"] == "T1110"
            assert claim["knowledge_generation"] == "5"
            assert claim["knowledge_source_kind"] == "knowledge_lite"
            assert claim["knowledge_trust_check"] == "verified"
            assert claim["knowledge_revocation_status"] == "clear"
            assert claim["empty_summary"] is True
            assert claim["canonical_citation"] is True
            assert claim["source_citation_preserved"] is True
            assert claim["same_handoff"] is True
            assert claim["route"] == "deterministic handoff"
            children[0].terminate()
            children[0].wait(timeout=2)
            degraded = _request_child(env, "azexplain", (groups["azmio-advise"],), deadline_ms=1500)
            assert degraded["knowledge_status"] == "unavailable"
            assert degraded["knowledge_count"] == 0
            assert degraded["route"] == "deterministic handoff"
            assert children[1].poll() is None
        private_markers = (b"SSH brute-force observations", b"redacted test fixture")
        for path in (azazel / "state").rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                assert all(marker not in raw for marker in private_markers)
        assert b"10.0.0.8" not in b"\n".join(lines)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)


@pytest.mark.real_process
@pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is required")
def test_500ms_explainer_process_reaches_shared_core_and_readonly_knowledge(
    request, monkeypatch,
):
    """Production path with a 500 ms route deadline and 250 ms caller margin."""
    import test_knowledge_lited as knowledge_tests
    from test_knowledge_lookup import _producer_manifest, admit_rows

    if os.geteuid() != 0:
        pytest.skip("requires root only inside the disposable test container")
    ids = {name: _identity(name) for name in
           ("azknowledge", "azmio", "azmioentry", "azoperator", "azexplain")}
    operator_gid = _group("azazel-operator")
    knowledge_read_gid = _group("azknowledge-read")
    mission_read_gid = _group("azmission-read")
    advise_gid = _group("azmio-advise")
    runtime_root = Path(tempfile.mkdtemp(prefix="nxs-mio-", dir="/tmp"))
    runtime_root.chmod(0o755)
    request.addfinalizer(lambda: shutil.rmtree(runtime_root, ignore_errors=True))

    # Use the suite's commissioned test node, then admit the checked-in
    # producer-shaped fixture through the same reader used by Knowledge Lite.
    monkeypatch.setenv("AZAZEL_ROOT", str(runtime_root))
    _, store, trust, _ = knowledge_tests.node.__wrapped__(runtime_root, monkeypatch)
    manifest, rows = _producer_manifest()
    # Preserve the producer snapshot's empty technique summary verbatim.
    admit_rows((None, store, trust, None), rows, profile=manifest["profile"])

    azazel = runtime_root / "var/lib/azazel"
    (runtime_root / "var").mkdir(exist_ok=True)
    (runtime_root / "var").chmod(0o755)
    (runtime_root / "var/lib").mkdir(exist_ok=True)
    (runtime_root / "var/lib").chmod(0o755)
    azazel.mkdir(parents=True, exist_ok=True)
    azazel.chmod(0o755)

    # Set only the temporary runtime layout to the same account/group/mode
    # contract as packaging/install.sh. Nothing touches host service paths.
    run = azazel / "run"
    _owned_dir(run, 0, 0, 0o755)
    _owned_dir(run / "knowledge", ids["azknowledge"].pw_uid, operator_gid, 0o2710)
    _owned_dir(run / "knowledge-read", ids["azknowledge"].pw_uid, knowledge_read_gid, 0o2710)
    _owned_dir(run / "mio", ids["azmio"].pw_uid, operator_gid, 0o2710)
    _owned_dir(run / "mio-entry", ids["azmioentry"].pw_uid, operator_gid, 0o2710)
    _owned_dir(run / "mio-advise", ids["azmioentry"].pw_uid, advise_gid, 0o2710)
    _owned_dir(run / "knowledge-status", ids["azknowledge"].pw_uid, operator_gid, 0o2750)
    _owned_dir(run / "mio-status", ids["azmioentry"].pw_uid, operator_gid, 0o2750)
    _owned_dir(azazel / "state", 0, 0, 0o755)
    _owned_dir(azazel / "state/knowledge", ids["azknowledge"].pw_uid, ids["azknowledge"].pw_gid, 0o700)
    _owned_dir(azazel / "state/mio", ids["azmioentry"].pw_uid, 0, 0o700)
    _owned_dir(azazel / "mio", ids["azmio"].pw_uid, ids["azmio"].pw_gid, 0o750)
    _own_tree(store, ids["azknowledge"].pw_uid, operator_gid)
    _own_tree(trust, ids["azknowledge"].pw_uid, ids["azknowledge"].pw_gid)

    root_env = os.environ.copy()
    root_env.update({
        "AZAZEL_ROOT": str(runtime_root),
        "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "runtime/src"))),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    children: list[subprocess.Popen] = []
    try:
        launch_specs = (
            ("azknowledge", (operator_gid,), "azazel_nexus_runtime.knowledge_lited"),
            ("azmio", (knowledge_read_gid, mission_read_gid), "azazel_nexus_runtime.mio_locald"),
            ("azmioentry", (operator_gid,), "azazel_nexus_runtime.mio_entryd"),
        )
        for account, extra_groups, module in launch_specs:
            script = f"from {module} import main; raise SystemExit(main())"
            children.append(subprocess.Popen(
                [sys.executable, "-B", "-c", script], cwd=ROOT, env=root_env,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                preexec_fn=_credentials(account, extra_groups),
            ))

        _wait_socket(run / "knowledge/knowledge.sock", children[0], time.monotonic() + 5)
        _wait_socket(run / "knowledge-read/knowledge-read.sock", children[0], time.monotonic() + 2)
        _wait_socket(run / "mio/mio.sock", children[1], time.monotonic() + 5)
        _wait_socket(run / "mio-entry/mio-entry.sock", children[2], time.monotonic() + 5)
        result = _request_child(root_env, "azexplain", (advise_gid,))
        # The route deadline is 500 ms; the public caller gives 250 ms for
        # connection/framing/delivery. This asserts the documented 750 ms
        # caller bound, not a sub-500 ms wall-clock duration.
        assert result["elapsed_ms"] < 750

        assert result["route"] == "deterministic handoff"
        if importlib.util.find_spec("azazel_mio") is None:
            assert result["state"] == "dependency_unavailable"
            assert result["knowledge_status"] == "unavailable"
            assert result["knowledge_count"] == 0
            assert children[1].poll() is None
            # A second normal public request proves a missing shared wheel
            # degraded the verb without killing the locald daemon.
            second = _request_child(root_env, "azexplain", (advise_gid,))
            assert second["route"] == result["route"]
            assert second["knowledge_status"] == "unavailable"
            assert second["knowledge_count"] == 0
            assert second["elapsed_ms"] < 750
            assert children[1].poll() is None
        else:
            # The 500ms path has no optional lookup share after reserves.
            assert result["knowledge_status"] == "not_queried"
            assert result["knowledge_count"] == 0
            # The production build keeps model admission disabled; the route
            # remains a deterministic handoff even with trusted Knowledge.
            assert result["route"] == "deterministic handoff"

        # No input prompt/context makes it into the bounded persistent ledgers.
        private_markers = (b"SSH brute-force observations", b"redacted test fixture")
        for path in (azazel / "state").rglob("*"):
            if path.is_file():
                raw = path.read_bytes()
                assert all(marker not in raw for marker in private_markers)
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)


@pytest.mark.real_process
@pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is required")
def test_entryd_without_locald_runs_shared_core_or_degrades_explicitly(request):
    """Only entryd runs (locald absent): one ordinary advise request, no socket to locald."""
    if os.geteuid() != 0:
        pytest.skip("requires root only inside the disposable test container")
    ids = {name: _identity(name) for name in ("azmioentry", "azexplain")}
    operator_gid = _group("azazel-operator")
    advise_gid = _group("azmio-advise")
    runtime_root = Path(tempfile.mkdtemp(prefix="nxs-mio-", dir="/tmp"))
    runtime_root.chmod(0o755)
    request.addfinalizer(lambda: shutil.rmtree(runtime_root, ignore_errors=True))

    azazel = runtime_root / "var/lib/azazel"
    (runtime_root / "var").mkdir(exist_ok=True)
    (runtime_root / "var").chmod(0o755)
    (runtime_root / "var/lib").mkdir(exist_ok=True)
    (runtime_root / "var/lib").chmod(0o755)
    azazel.mkdir(parents=True, exist_ok=True)
    azazel.chmod(0o755)

    # The same account/group/mode contract as the 500 ms test; no locald
    # directory exists, so the mio socket is absent for this process.
    run = azazel / "run"
    _owned_dir(run, 0, 0, 0o755)
    _owned_dir(run / "mio-entry", ids["azmioentry"].pw_uid, operator_gid, 0o2710)
    _owned_dir(run / "mio-advise", ids["azmioentry"].pw_uid, advise_gid, 0o2710)
    _owned_dir(run / "mio-status", ids["azmioentry"].pw_uid, operator_gid, 0o2750)
    _owned_dir(azazel / "state", 0, 0, 0o755)
    _owned_dir(azazel / "state/mio", ids["azmioentry"].pw_uid, 0, 0o700)

    root_env = os.environ.copy()
    root_env.update({
        "AZAZEL_ROOT": str(runtime_root),
        "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "runtime/src"))),
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    child = subprocess.Popen(
        [sys.executable, "-B", "-c",
         "from azazel_nexus_runtime.mio_entryd import main; raise SystemExit(main())"],
        cwd=ROOT, env=root_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, preexec_fn=_credentials("azmioentry", (operator_gid,)),
    )
    try:
        _wait_socket(run / "mio-entry/mio-entry.sock", child, time.monotonic() + 5)
        _wait_socket(run / "mio-advise/mio-advise.sock", child, time.monotonic() + 5)
        assert not (run / "mio/mio.sock").exists()
        result = _request_child(root_env, "azexplain", (advise_gid,))
        assert result["elapsed_ms"] < 750
        assert result["route"] == "deterministic handoff"
        if importlib.util.find_spec("azazel_mio") is None:
            # Package absent: explicit degradation, never an executed assessment.
            assert result["state"] == "dependency_unavailable"
            assert result["knowledge_status"] == "unavailable"
        else:
            # The shared core ran in-process: it queries no Knowledge.
            assert result["knowledge_status"] == "not_queried"
        assert result["knowledge_count"] == 0
        assert child.poll() is None
        private_markers = (b"SSH brute-force observations", b"redacted test fixture")
        for path in (azazel / "state").rglob("*"):
            if path.is_file():
                assert all(marker not in path.read_bytes() for marker in private_markers)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)
