"""One bounded Linux process path through entryd, locald and Knowledge Lite.

This uses real service UIDs, SO_PEERCRED, the public runtime frame protocol,
the production daemons and the checked-in Lite test fixture. The fixture is
re-signed with the suite's test key; it is not a live Knowledge producer or
full-node interoperability claim.
"""
from __future__ import annotations

import grp
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


def _request_child(env: dict[str, str], user: str, groups: tuple[int, ...]):
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
                    {"deadline_ms": 500}, payload=frame, deadline_s=0.75)
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
    "elapsed_ms": elapsed_ms,
  }, sort_keys=True))
except Exception as error:
  print(getattr(error, "refusal", type(error).__name__))
  raise SystemExit(1)
'''
    proc = subprocess.run(
        [sys.executable, "-B", "-c", code], cwd=ROOT, env=env,
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
        "elapsed_ms",
    }
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


@pytest.mark.real_process
@pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is required")
def test_edge_intake_normal_process_reaches_explainer_mio_and_knowledge(request, monkeypatch):
    """One producer-shaped alert follows both production daemon entrypoints."""
    if importlib.util.find_spec("azazel_mio") is None:
        pytest.skip("normal-entry healthy path requires the pinned shared MIO wheel")
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
    manifest, rows = _producer_manifest()
    rows = [({**row, "description": "Fixture technique reference"}
             if row.get("technique_id") == "T1110" else row) for row in rows]
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

    env = os.environ.copy()
    env.update({"AZAZEL_ROOT": str(runtime_root),
                "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT / "runtime/src"), str(ROOT / "tests"))),
                "PYTHONDONTWRITEBYTECODE": "1"})
    children = []
    try:
        launch_specs = (
            ("azknowledge", (groups["azazel-operator"],), "azazel_nexus_runtime.knowledge_lited"),
            ("azmio", (groups["azknowledge-read"], groups["azmission-read"]), "azazel_nexus_runtime.mio_locald"),
            ("azmioentry", (groups["azazel-operator"],), "azazel_nexus_runtime.mio_entryd"),
            ("azintake", (groups["azincident-read"],), "azazel_nexus_runtime.edge_intaked"),
            ("azexplain", (groups["azincident-read"], groups["azknowledge-read"], groups["azmio-advise"]),
             "azazel_nexus_runtime.incident_explaind"),
        )
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
        assert record["knowledge_state"] == "available"
        assert record["knowledge_refs"]
        assert any(ref["technique_id"] == "T1110" for ref in record["knowledge_refs"])
        assert all((ref["source_kind"], ref["trust_check"], ref["revocation_status"]) ==
                   ("knowledge_lite", "verified", "clear") for ref in record["knowledge_refs"])
        assert all(child.poll() is None for child in children)
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
    # The published snapshot's technique rows have no display summary. Add a
    # bounded test-only summary before re-signing so the downstream MIO type
    # accepts and carries a non-empty advisory description.
    rows = [({**row, "description": "Fixture technique reference"}
             if row.get("technique_id") == "T1110" else row) for row in rows]
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
            # With the shared MIO wheel installed, this is the healthy
            # full-path case: the bounded Knowledge fixture must arrive as a
            # trusted ref under the route's 500 ms deadline. Degradation is
            # exercised only by the explicit no-wheel branch above.
            assert result["knowledge_status"] == "available"
            assert result["knowledge_count"] == 1
            assert result["knowledge_technique"] == "T1110"
            assert result["knowledge_generation"] == "5"
            assert result["knowledge_source_kind"] == "knowledge_lite"
            assert result["knowledge_trust_check"] == "verified"
            assert result["knowledge_revocation_status"] == "clear"
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
