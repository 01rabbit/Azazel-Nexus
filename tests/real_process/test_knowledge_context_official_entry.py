"""Official-entry acceptance for the Knowledge Context commissioning bundle (U34).

Runs only in the isolated root container runner. The shipped
`azazel_nexus_runtime.knowledge_contextd.main()` is spawned as a real process
under the real service uid/gid (azknowledgeegress), with no test entry point, no
client injection and no monkeypatch of authentication or transport. The only
inputs are the root-owned commissioning bundle (relocated with AZAZEL_ROOT) and
a synthetic loopback mTLS peer (`_official_entry_peer.SyntheticPeer`) whose
accept / handshake / request counters prove "no communication".

Test-only seams, all outside product code: AZAZEL_ROOT relocation; the existing
`_mio_locald_context_process.py` wrapper (locald with an 8 s Knowledge budget,
as used by the U29 chain tests) for the MIO side; a synthetic peer. Not real
here: systemd, IPAddressAllow/Deny, ProtectSystem.
"""

from __future__ import annotations

import json
import os
import pwd
import secrets
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from test_knowledge_context_process_interop import (  # noqa: F401
    ROOT, _normal_entry_advisory, _pki, _ready, pytestmark)
from test_knowledge_context_linux_acceptance import (
    Stack, _doc, _free_port, _refused, _start_chain, _assert_advisory_only)
from azazel_nexus.spki import spki_pin
from _knowledge_context_bundle_fixture import build_bundle
from _official_entry_peer import PROVIDER_ID, SyntheticPeer

QUESTION_TEXT = "synthetic public context"          # the P0 question sent by _doc()
MISSION = "official-entry-mission-marker"
ALIAS = b"U34-ALIAS-KEY-MARKER-0123456789abcdef"[:32] + b"!"  # >= 32 bytes
ENTRY_QUESTION = "synthetic public observation context"
BUNDLE_REL = Path("etc/azazel/knowledge-context/commissioning")

# Fixed reason codes the loader may emit (closed set; anything else is a failure).
REASON_CODES = {
    "manifest_missing", "file_missing", "bundle_incomplete", "bundle_unexpected",
    "manifest_schema", "enabled_not_true", "ttl_invalid", "registry_keys",
    "registry_signature", "registry_digest", "registry_expired", "registry_invalid",
    "peer_unknown", "identity_mismatch", "privacy_class", "policy_invalid",
    "alias_short", "identity_unusable", "path_unsafe", "perm_unsafe",
}


class Official(Stack):
    """Service tree + synthetic peer + bundle + shipped daemon."""

    def __init__(self, tmp: Path, pki: Path) -> None:  # noqa: D107 (does not call super)
        self.tmp = tmp
        self.pki = pki
        self.service_root = tmp / "service-root"
        self.producer = self.broker = self.locald = self.entryd = None
        self.daemon: subprocess.Popen | None = None
        self.egress = pwd.getpwnam("azknowledgeegress")
        self.mio = pwd.getpwnam("azmio")
        self.entry = pwd.getpwnam("azmioentry")
        self.operator = pwd.getpwnam("azoperator")
        import grp
        self.ctx_gid = grp.getgrnam("azknowledge-context-client").gr_gid
        self.operator_gid = grp.getgrnam("azazel-operator").gr_gid
        self.server_der = ssl.PEM_cert_to_DER_cert((pki / "server.pem").read_text())
        self._layout()
        self.state = self.service_root / "var/lib/azazel/state/knowledge-context"
        self.env = {**os.environ, "AZAZEL_ROOT": str(self.service_root)}
        self.bundle = self.service_root / BUNDLE_REL
        self.peer: SyntheticPeer | None = None
        self.peer_seed = secrets.token_hex(32)
        self.registry_key = SigningKey(secrets.token_bytes(32))
        self.daemon_out = ""

    # -- peer / bundle ----------------------------------------------------
    def start_peer(self, mode="valid", delay_s=0.0, listening=True) -> int:
        if listening:
            self.peer = SyntheticPeer(self.pki, self.peer_seed, mode=mode, delay_s=delay_s)
            self.port = self.peer.port
        else:
            self.port = _free_port()  # nothing listens: connection refused
        return self.port

    def make_bundle(self, **kw) -> Path:
        """Root-owned, group-readable by the service gid; relocated under AZAZEL_ROOT."""
        # Every ancestor below the trust base must be root-owned and not group/other writable.
        cur = self.service_root
        for part in BUNDLE_REL.parts[:-1]:
            cur = cur / part
            cur.mkdir(exist_ok=True)
            os.chown(cur, 0, 0)
            cur.chmod(0o755)
        defaults = dict(
            peer_id=PROVIDER_ID, peer_address="127.0.0.1", peer_host="knowledge.test",
            peer_port=self.port, certificate_pin=spki_pin(self.server_der),
            peer_signing_key=SigningKey(bytes.fromhex(self.peer_seed)),
            registry_signing_key=self.registry_key,
            ca=self.pki / "ca.pem", client_cert=self.pki / "nexus.pem",
            client_key=self.pki / "nexus.key", client_identity="nexus-official-test",
            mission=MISSION, alias_key=ALIAS, max_ttl_seconds=30,
            mode=0o640, secret_mode=0o640, owner=(0, self.egress.pw_gid),
        )
        defaults.update(kw)
        out = build_bundle(self.bundle, **defaults)
        os.chown(self.bundle, 0, self.egress.pw_gid)
        self.bundle.chmod(0o750)
        return out

    # -- shipped daemon ---------------------------------------------------
    def start_daemon(self, extra_groups=()) -> None:
        egress = self.egress
        groups = (f"--groups={','.join(str(g) for g in extra_groups)}"
                  if extra_groups else "--clear-groups")
        command = [
            "setpriv", f"--reuid={egress.pw_uid}", f"--regid={egress.pw_gid}", groups,
            "--no-new-privs", "--inh-caps=-all", "sh", "-c",
            "umask 0027; exec " + sys.executable + " -B -c "
            "'from azazel_nexus_runtime.knowledge_contextd import main; raise SystemExit(main())'"]
        self.daemon = subprocess.Popen(
            command, cwd=ROOT, env=self.env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        sock = self.service_root / "var/lib/azazel/run/knowledge-context/knowledge-context.sock"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert self.daemon.poll() is None, self.daemon.stderr.read()[-800:]
            if sock.exists():
                return
            time.sleep(0.05)
        raise AssertionError("daemon did not bind its socket")

    def stop_daemon(self) -> None:
        d, self.daemon = self.daemon, None
        if d is None:
            return
        if d.poll() is None:
            d.terminate()
            try:
                d.wait(timeout=10)
            except subprocess.TimeoutExpired:
                d.kill(); d.wait(timeout=5)
        self.daemon_out = (d.stdout.read() or "") + (d.stderr.read() or "")
        d.stdout.close(); d.stderr.close()

    def shutdown(self) -> None:
        for name in ("entryd", "locald"):
            process = getattr(self, name)
            if process is not None and process.poll() is None:
                process.terminate(); process.wait(timeout=10)
        self.stop_daemon()
        if self.peer:
            self.peer.close()

    # -- evidence ---------------------------------------------------------
    def ledger(self) -> list[dict]:
        path = self.state / "context.jsonl"
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text().splitlines() if line]
        return [r["event"] if isinstance(r.get("event"), dict) else r for r in rows]

    def ledger_text(self) -> str:
        path = self.state / "context.jsonl"
        return path.read_text() if path.exists() else ""

    def events(self, event_type: str) -> list[dict]:
        return [e for e in self.ledger() if e.get("event_type") == event_type]

    def commissioning_event(self) -> dict:
        found = self.events("knowledge.context.commissioning")
        assert len(found) == 1, found
        return found[0]

    def assert_no_leak(self) -> None:
        """Nothing secret or free-text reaches the ledger or the daemon's output."""
        blob = self.ledger_text() + self.daemon_out
        for marker in (QUESTION_TEXT, ENTRY_QUESTION, MISSION, ALIAS.decode(),
                       "PRODUCER-FACT-VALUE", "PRODUCER-LIMITATION", "PRODUCER-UNKNOWN",
                       str(self.bundle), "knowledge.test", "BEGIN"):
            assert marker not in blob, marker

    def start_chain(self) -> None:
        _start_chain(self)


@pytest.fixture(scope="module")
def pki_dir():
    base = Path(tempfile.mkdtemp(prefix="u34pki-", dir="/tmp"))
    base.chmod(0o755)
    try:
        yield _pki(base / "pki")
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def official(pki_dir):
    base = Path(tempfile.mkdtemp(prefix="u34-", dir="/tmp"))
    base.chmod(0o755)
    state = None
    try:
        state = Official(base, pki_dir)
        yield state
    finally:
        if state is not None:
            state.stop_daemon()
            print("U34-DIAG ledger", [{k: v for k, v in e.items() if k != "hash"} for e in state.ledger()])
            print("U34-DIAG daemon-output", state.daemon_out[-1500:])
            print("U34-DIAG peer", state.peer.counters() if state.peer else None)
            state.shutdown()
        shutil.rmtree(base, ignore_errors=True)


def _refusal(reply):
    return _refused(reply)


def _degraded(entry):
    assert entry["full_node_context_status"] == "unavailable", entry
    assert entry["advisory_authority"] is None, entry
    assert entry["advisory_claim_status"] is None and entry["advisory_trust"] is None, entry
    assert entry["lite_claim_count"] == 0 and entry["observation_count"] == 0, entry
    assert entry["handoff_action"] is None, entry
    assert entry["knowledge_status"] == "unavailable", entry


# ---------------------------------------------------------------------------
# Group 1: valid bundle -> real main() -> real AF_UNIX -> ordinary mio.advise path
# ---------------------------------------------------------------------------

def test_g1_valid_bundle_reaches_mio_as_unverified_advisory(official: Official):
    official.start_peer("valid")
    official.make_bundle()
    official.start_daemon()
    # daemon runs as the real service identity, not root and not a test entry
    pid = official.daemon.pid
    status = Path(f"/proc/{pid}/status").read_text()
    assert f"Uid:\t{official.egress.pw_uid}" in status, status
    assert official.peer.counters()["accepted"] == 0, "loading the bundle must not communicate"
    official.start_chain()
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    counters = official.peer.counters()
    assert counters["requests"] == 1 and counters["handshakes"] >= 1, counters
    event = official.commissioning_event()
    assert event["outcome"] == "commissioned" and "reason_code" not in event, event
    assert official.events("knowledge.context.completed")[-1]["outcome"] == "verified_advisory"
    # the peer saw only the sanitized P0 question
    body = json.loads(official.peer.request_bodies[0])
    assert ENTRY_QUESTION in json.dumps(body)
    official.stop_daemon()
    official.assert_no_leak()
    print("U34-OBS g1 peer", json.dumps(counters))


# ---------------------------------------------------------------------------
# Group 2: bundle absent / explicitly disabled -> unavailable, zero peer traffic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("case", ["absent", "enabled_false"])
def test_g2_absent_or_disabled_bundle_is_unavailable_with_zero_peer_traffic(official, case):
    official.start_peer("valid")
    if case == "enabled_false":
        official.make_bundle(defect="enabled_false")
    official.start_daemon()
    official.start_chain()
    _degraded(_normal_entry_advisory(official.service_root))
    assert _refusal(official.as_service()) == "unavailable"
    assert official.peer.counters() == {"accepted": 0, "handshakes": 0, "requests": 0}
    event = official.commissioning_event()
    if case == "absent":
        assert event["outcome"] == "absent" and "reason_code" not in event, event
    else:
        assert event["outcome"] == "refused" and event["reason_code"] == "enabled_not_true", event
    official.stop_daemon()
    official.assert_no_leak()


# ---------------------------------------------------------------------------
# Group 3: invalid bundle -> closed broker, fixed reason code, zero peer traffic
# ---------------------------------------------------------------------------

def _chmod(name, mode):
    return lambda o: os.chmod(o.bundle / name, mode)


def _chown_egress(name):
    return lambda o: os.chown(o.bundle / name, o.egress.pw_uid, o.egress.pw_gid)


def _symlink(name):
    def apply(o):
        target = o.bundle.parent / "elsewhere"
        target.write_bytes((o.bundle / name).read_bytes())
        (o.bundle / name).unlink()
        (o.bundle / name).symlink_to(target)
    return apply


def _hardlink(name):
    return lambda o: os.link(o.bundle / name, o.bundle.parent / "second-name")


def _extra_file(o):
    (o.bundle / "extra.txt").write_text("x")
    os.chown(o.bundle / "extra.txt", 0, o.egress.pw_gid)


def _drop(name):
    return lambda o: (o.bundle / name).unlink()


def _dir_group_writable(o):
    o.bundle.chmod(0o770)


def _ancestor_group_writable(o):
    (o.service_root / "etc").chmod(0o775)


def _bundle_dir_symlink(o):
    real = o.bundle.parent / "real-commissioning"
    o.bundle.rename(real)
    o.bundle.symlink_to(real)


def _empty_file(name):
    return lambda o: (o.bundle / name).write_bytes(b"")


def _bad_json_manifest(o):
    (o.bundle / "manifest.json").write_text("{not json")


CASES = [
    # (id, build_bundle kwargs, post-build mutation, expected reason)
    ("missing_required_value", dict(defect="missing_value"), None, "manifest_schema"),
    ("enabled_not_boolean", dict(defect="enabled_string"), None, "manifest_schema"),
    ("registry_bad_signature", dict(defect="bad_signature"), None, "registry_signature"),
    ("registry_expired", dict(defect="expired_registry"), None, "registry_expired"),
    ("ttl_zero", dict(defect="bad_ttl"), None, "ttl_invalid"),
    ("alias_too_short", dict(defect="short_alias"), None, "alias_short"),
    ("identity_mismatch", dict(defect="wrong_identity"), None, "identity_mismatch"),
    ("manifest_not_json", {}, _bad_json_manifest, "manifest_schema"),
    ("manifest_missing", {}, _drop("manifest.json"), "manifest_missing"),
    ("file_missing_alias", {}, _drop("alias.key"), "bundle_incomplete"),
    ("extra_file", {}, _extra_file, "bundle_unexpected"),
    ("empty_registry_file", {}, _empty_file("registry.signed"), "path_unsafe"),
    ("manifest_group_writable", {}, _chmod("manifest.json", 0o660), "perm_unsafe"),
    ("manifest_world_writable", {}, _chmod("manifest.json", 0o666), "perm_unsafe"),
    ("secret_other_readable_key", {}, _chmod("client.key", 0o644), "perm_unsafe"),
    ("secret_other_readable_alias", {}, _chmod("alias.key", 0o644), "perm_unsafe"),
    ("file_owned_by_service_uid", {}, _chown_egress("manifest.json"), "perm_unsafe"),
    ("secret_owned_by_service_uid", {}, _chown_egress("client.key"), "perm_unsafe"),
    ("symlinked_file", {}, _symlink("alias.key"), "path_unsafe"),
    ("symlinked_ca", {}, _symlink("ca.pem"), "path_unsafe"),
    ("hardlinked_file", {}, _hardlink("manifest.json"), "path_unsafe"),
    ("dir_group_writable", {}, _dir_group_writable, "perm_unsafe"),
    ("ancestor_group_writable", {}, _ancestor_group_writable, "perm_unsafe"),
    ("bundle_dir_is_symlink", {}, _bundle_dir_symlink, "path_unsafe"),
]


@pytest.mark.parametrize("name,kwargs,mutate,reason", CASES, ids=[c[0] for c in CASES])
def test_g3_invalid_bundle_is_closed_with_fixed_reason_and_zero_peer_traffic(
        official, name, kwargs, mutate, reason):
    official.start_peer("valid")           # a live, listening peer: any attempt is counted
    official.make_bundle(**kwargs)
    if mutate:
        mutate(official)
    official.start_daemon()
    assert _refusal(official.as_service()) == "unavailable"
    assert _refusal(official.as_service(_doc(question="second synthetic public question"))) == "unavailable"
    assert official.peer.counters() == {"accepted": 0, "handshakes": 0, "requests": 0}, name
    event = official.commissioning_event()
    assert event["outcome"] == "refused", event
    assert event["reason_code"] in REASON_CODES, event
    assert event["reason_code"] == reason, event
    assert set(event) <= {"event_type", "outcome", "reason_code", "registry_version"}, event
    assert not official.events("knowledge.context.requested"), "closed broker must not attempt"
    official.stop_daemon()
    official.assert_no_leak()


@pytest.mark.parametrize("key", ["client.key", "alias.key"])
def test_g3_secret_readable_by_unrelated_group_is_perm_unsafe_with_zero_peer_traffic(official, key):
    official.start_peer("valid")
    official.make_bundle()
    os.chown(official.bundle / key, 0, official.operator_gid)   # 0640, group not the service group
    # the daemon is also a member of that group, so the file is readable and only the
    # group check can refuse it (without membership the open itself would fail)
    official.start_daemon(extra_groups=(official.operator_gid,))
    assert _refusal(official.as_service()) == "unavailable"
    assert official.peer.counters() == {"accepted": 0, "handshakes": 0, "requests": 0}
    event = official.commissioning_event()
    assert (event["outcome"], event["reason_code"]) == ("refused", "perm_unsafe"), event
    official.stop_daemon()
    official.assert_no_leak()


def test_g3_removed_bundle_latches_closed_until_restart(official):
    official.start_peer("valid")
    official.make_bundle()
    official.start_daemon()
    official.start_chain()
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    assert official.peer.counters()["requests"] == 1
    manifest = official.bundle / "manifest.json"
    saved = manifest.read_bytes()
    manifest.unlink()
    for _ in range(2):
        assert _refusal(official.as_service()) == "unavailable"
    assert official.peer.counters()["requests"] == 1, "removed bundle must not reach the peer"
    manifest.write_bytes(saved)
    os.chown(manifest, 0, official.egress.pw_gid)
    manifest.chmod(0o640)
    assert _refusal(official.as_service()) == "unavailable"   # restored content stays latched
    assert official.peer.counters()["requests"] == 1
    official.stop_daemon()
    official.assert_no_leak()


# ---------------------------------------------------------------------------
# Group 4: bad / mis-bound responses -> unavailable, no advisory (valid before and after)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", [
    "bad-signature", "wrong-key-id", "wrong-request-id", "wrong-correlation",
    "wrong-subject", "wrong-provider"])
def test_g4_bad_or_unbound_response_is_unavailable_without_advisory(official, mode):
    official.start_peer("valid")
    official.make_bundle()
    official.start_daemon()
    official.start_chain()
    _assert_advisory_only(_normal_entry_advisory(official.service_root))      # control
    official.peer.mode = mode
    before = official.peer.counters()["requests"]
    degraded = _normal_entry_advisory(official.service_root)
    assert official.peer.counters()["requests"] == before + 1, "the defect must have been offered"
    _degraded(degraded)
    assert _refusal(official.as_service()) == "unavailable"
    official.peer.mode = "valid"                                               # recovery
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    outcomes = [e["outcome"] for e in official.events("knowledge.context.completed")]
    assert outcomes.count("verified_advisory") == 2 and "unavailable" in outcomes, outcomes
    official.stop_daemon()
    official.assert_no_leak()


# ---------------------------------------------------------------------------
# Group 5: expired / late responses -> safe degradation; late answers are not adopted
# ---------------------------------------------------------------------------

def _answers_sent(peer, expected, timeout=2.0):
    deadline = time.monotonic() + timeout
    while True:
        with peer.lock:
            value = peer.answers_sent
        if value >= expected or time.monotonic() >= deadline:
            return value
        time.sleep(0.02)


@pytest.mark.parametrize("mode", ["expired-envelope", "expired-semantic"])
def test_g5_expired_response_is_unavailable(official, mode):
    official.start_peer("valid")
    official.make_bundle()
    official.start_daemon()
    official.start_chain()
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    before = official.peer.counters()["requests"]
    with official.peer.lock:
        sent_before = official.peer.answers_sent
    completed_before = len(official.events("knowledge.context.completed"))
    official.peer.mode = mode
    _degraded(_normal_entry_advisory(official.service_root))
    # the expired answer was really received: the peer read the request and wrote
    # a complete signed answer (no peer-thread failure, no connection drop)
    assert official.peer.counters()["requests"] == before + 1
    assert _answers_sent(official.peer, sent_before + 1) == sent_before + 1
    assert _refusal(official.as_service()) == "unavailable"
    assert official.peer.counters()["requests"] == before + 2
    assert _answers_sent(official.peer, sent_before + 2) == sent_before + 2
    # The product ledger has one refusal vocabulary for every failure ("unavailable",
    # knowledge_contextd.py:148); it cannot tell a semantic expiry from a bad
    # signature or a dropped connection. The most specific fixed result available is
    # an "unavailable" completion carrying no response_bytes (never verified_advisory).
    done = official.events("knowledge.context.completed")[completed_before:]
    assert [e["outcome"] for e in done] == ["unavailable", "unavailable"], done
    assert all("response_bytes" not in e for e in done), done
    official.peer.mode = "valid"
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    official.stop_daemon()
    official.assert_no_leak()


def test_g5_late_response_is_not_adopted(official):
    official.start_peer("delay", delay_s=3.0)
    official.make_bundle()
    official.start_daemon()
    start = time.monotonic()
    reply = official.as_service(_doc(mono="MONO+1000", deadline_ms=1000))
    elapsed = time.monotonic() - start
    assert (reply["connect"] == "ok" and reply["reply"].get("ok") is not True) or \
        ("response" not in reply["reply"].get("result", {})), reply
    assert _refusal(reply) in {"timeout", "unavailable"}, reply
    assert elapsed < 2.5, elapsed                    # bounded by the caller deadline, not the peer
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and not official.peer.sent_after_delay:
        time.sleep(0.1)
    assert official.peer.sent_after_delay, "peer never produced the late answer (test not exercised)"
    # the late (valid) answer sits unread; the next call is a fresh exchange
    official.peer.mode = "valid"
    again = official.as_service()
    assert again["reply"]["ok"] is True and "response" in again["reply"]["result"], again
    assert official.peer.counters()["requests"] == 2
    outcomes = [e["outcome"] for e in official.events("knowledge.context.completed")]
    assert outcomes[0] in {"timeout", "unavailable"} and outcomes[-1] == "verified_advisory", outcomes
    official.stop_daemon()
    official.assert_no_leak()


def test_g5_delayed_peer_through_ordinary_path_degrades_then_recovers(official):
    """Ordinary mio.advise path with a peer slower than the caller's 5.25 s budget."""
    official.start_peer("delay", delay_s=7.0)
    official.make_bundle()
    official.start_daemon()
    official.start_chain()
    degraded = _normal_entry_advisory(official.service_root)
    _degraded(degraded)
    official.peer.mode = "valid"
    _assert_advisory_only(_normal_entry_advisory(official.service_root))
    official.stop_daemon()
    official.assert_no_leak()


# ---------------------------------------------------------------------------
# Group 6: connection refused -> unavailable, local evaluation continues, fixed audit
# ---------------------------------------------------------------------------

def test_g6_connection_refused_is_unavailable_and_local_evaluation_continues(official):
    official.start_peer(listening=False)                 # port with no listener
    official.make_bundle()
    official.start_daemon()
    official.start_chain()
    entry = _normal_entry_advisory(official.service_root)
    _degraded(entry)
    assert entry["state"] and entry["route"], entry      # local MIO evaluation still produced a result
    assert _refusal(official.as_service()) == "unavailable"
    assert official.events("knowledge.context.commissioning")[0]["outcome"] == "commissioned"
    completed = official.events("knowledge.context.completed")
    assert completed and all(e["outcome"] == "unavailable" for e in completed), completed
    assert set(completed[0]) <= {"event_type", "outcome", "elapsed_ms"}, completed[0]
    official.stop_daemon()
    official.assert_no_leak()
    print("U34-OBS g6 entry", json.dumps({k: entry[k] for k in ("route", "state", "knowledge_status")}))
