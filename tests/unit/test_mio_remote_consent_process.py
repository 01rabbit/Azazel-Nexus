"""A pending opt-in is closed to a sender in another OS process.

Real subprocesses over the same on-disk store: the reader runs the real
`RemoteInferenceService` send decision (signed envelope, send gate,
`_consent_refusal`) against a counting transport. The writer is entryd's real
`mio.remote.opt_in.set` path. Portable (no root, no SO_PEERCRED), so it lives
in `tests/unit` and runs in the ordinary CI job, and is marked
`real_process`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_entryd as entry
from azazel_nexus_runtime import mio_socket_client as client
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.mio_remote_consent import ConsentRefused, ConsentStore
from azazel_nexus_runtime.principal import Principal, PrincipalClass

from azazel_nexus.audit import AuditChainBroken
from azazel_nexus.mio_profile import PREREQUISITES

pytestmark = pytest.mark.real_process

CHILD = Path(__file__).with_name("_mio_remote_consent_child.py")
OPERATOR = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))


def _child_env():
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root / "src"), str(root / "runtime" / "src"), env.get("PYTHONPATH", "")])
    return env


def send_in_new_process(state_dir, generation) -> dict:
    done = subprocess.run(
        [sys.executable, str(CHILD), "send", str(state_dir), str(generation)],
        capture_output=True, text=True, timeout=60, env=_child_env(), check=True)
    return json.loads(done.stdout.strip().splitlines()[-1])


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(client.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid()))
    monkeypatch.setattr(client.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getgid()))
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    return entry.MioEntryService()


def set_prerequisite(service, prerequisite):
    return service.handle(SimpleNamespace(
        verb=entry.OPT_IN_SET_VERB, principal=OPERATOR,
        arguments={"prerequisite": prerequisite.value,
                   "expected_generation": service.consent.reading().generation}))


def test_w9_2_after_the_record_and_the_withdrawal_both_fail_no_process_sends(
        service, monkeypatch):
    for prerequisite in list(PREREQUISITES)[:-1]:
        set_prerequisite(service, prerequisite)
    real = service.router._record

    def record(event, **kw):
        if event.get("event_type") == "mio.remote.opt_in":
            raise AuditChainBroken("fixture")
        return real(event, **kw)

    def refuse(*a, **kw):
        raise ConsentRefused("fixture: busy")

    monkeypatch.setattr(service.router, "_record", record)
    monkeypatch.setattr(service.consent, "withdraw", refuse)
    with pytest.raises(entry.RequestRefused):
        set_prerequisite(service, list(PREREQUISITES)[-1])

    state = runtime_paths.mio_state_dir()
    pending = ConsentStore(state).reading()
    assert pending.status == "unconfirmed" and not pending.permits
    for generation in (pending.generation, pending.generation + 1):
        result = send_in_new_process(state, generation)
        assert result["calls"] == 0
        assert result["refusal"] == "opt_in_not_granted"
        assert result["status"] == "unconfirmed"


def test_w9_3_a_writer_killed_before_confirm_leaves_the_store_closed(tmp_path):
    root, ready = tmp_path / "root", tmp_path / "ready"
    root.mkdir()
    writer = subprocess.Popen(
        [sys.executable, str(CHILD), "writer", str(root), str(ready)],
        env=_child_env(), stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert writer.poll() is None, writer.stderr.read().decode()
            assert time.monotonic() < deadline, "writer never reached its audit record"
            time.sleep(0.02)
        state = Path(ready.read_text())
        writer.send_signal(signal.SIGKILL)
        writer.wait(timeout=10)
    finally:
        if writer.poll() is None:
            writer.kill()
            writer.wait(timeout=10)
        writer.stderr.close()
    assert writer.returncode == -signal.SIGKILL

    first = ConsentStore(state).reading()
    assert first.status == "unconfirmed" and first.generation == 4
    for generation in (4, 5):
        result = send_in_new_process(state, generation)
        assert result["calls"] == 0 and result["refusal"] == "opt_in_not_granted"
    # A restart: a new store, a new process, the same answer.
    restarted = ConsentStore(state)
    assert restarted.reading().status == "unconfirmed" and not restarted.reading().permits
    assert send_in_new_process(state, 4)["status"] == "unconfirmed"


def test_w9_4_a_normal_grant_is_sent_once_by_another_process_after_confirm(service):
    for prerequisite in PREREQUISITES:
        reply = set_prerequisite(service, prerequisite)
    assert reply["status"] == "granted"
    state = runtime_paths.mio_state_dir()
    result = send_in_new_process(state, reply["generation"])
    assert result["calls"] == 1 and result["refusal"] is None
    assert result["outcome"] == "advisory"
