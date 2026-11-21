"""Nexus KnowledgeClient against the real Knowledge mTLS app in a child process.

This runs only in the isolated container runner. Its CA, keys, database and
Knowledge server process live under pytest's temporary directory.

Since ADR-0010 (#439) the broker's one client is the model-free context
observation unit (`azmioctx`), reached only by entryd (`azmioentry`), and the
broker accepts only the technique query; a free-form question is refused
before sending. The chain here runs those processes under their real uids on
real sockets.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import select
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus.spki import spki_pin
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient

ROOT = Path(__file__).resolve().parents[2]


def _real_process_prerequisite_error() -> str | None:
    """Keep this privileged integration suite explicit outside its container."""
    if not sys.platform.startswith("linux"):
        return "requires Linux AF_UNIX credentials and Linux account semantics"
    if os.geteuid() != 0:
        return "requires the isolated root container runner"
    if not os.environ.get("KNOWLEDGE_TEST_SRC"):
        return "KNOWLEDGE_TEST_SRC is not set by the isolated runner"
    if shutil.which("openssl") is None:
        return "openssl is required by the isolated runner"
    import grp
    import pwd

    try:
        for name in ("azknowledgeegress", "azmio", "azmioentry", "azmioctx", "azoperator",
                     "azexplain"):
            pwd.getpwnam(name)
        for name in ("azknowledge-context-client", "azazel-operator", "azmio-advise",
                     "azmio-contextobs"):
            grp.getgrnam(name)
    except KeyError as exc:
        return f"isolated runner identity is missing: {exc}"
    return None


_PREREQUISITE_ERROR = _real_process_prerequisite_error()
_REQUIRE_REAL_PROCESS = os.environ.get("NEXUS_REQUIRE_REAL_PROCESS") == "1"
if _REQUIRE_REAL_PROCESS and _PREREQUISITE_ERROR is not None:
    raise RuntimeError(
        "required isolated real-process runner is misconfigured: "
        f"{_PREREQUISITE_ERROR}"
    )
pytestmark = pytest.mark.skipif(
    _PREREQUISITE_ERROR is not None,
    reason=_PREREQUISITE_ERROR or "isolated real-process prerequisites unavailable",
)


def _openssl(args: list[str], cwd: Path) -> None:
    subprocess.run(
        ["openssl", *args], cwd=cwd, check=True, capture_output=True, timeout=30
    )


def _pki(root: Path) -> Path:
    root.mkdir()
    _openssl(
        ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
         "-out", "ca.pem", "-subj", "/CN=process-test-ca", "-days", "2",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash"],
        root,
    )
    (root / "server.ext").write_text(
        "subjectAltName=DNS:knowledge.test\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "authorityKeyIdentifier=keyid\n"
        "extendedKeyUsage=serverAuth\n"
    )
    (root / "client.ext").write_text(
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "authorityKeyIdentifier=keyid\n"
        "extendedKeyUsage=clientAuth\n"
    )
    for name, ext in (("server", "server.ext"), ("nexus", "client.ext")):
        _openssl(
            ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
             "-out", f"{name}.csr", "-subj", f"/CN={name}"],
            root,
        )
        _openssl(
            ["x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey",
             "ca.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", "2",
             "-extfile", ext],
            root,
        )
    return root


def _ready(process: subprocess.Popen[str], timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    assert process.stdout is not None and process.stderr is not None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"Knowledge process exited rc={process.returncode}: "
                f"{process.stderr.read()[-1000:]}"
            )
        readable, _, _ = select.select([process.stdout], [], [], 0.2)
        if readable:
            line = process.stdout.readline()
            if line:
                return json.loads(line)
            if process.poll() is not None:
                raise AssertionError(
                    f"Knowledge-side process exited rc={process.returncode}: "
                    f"{process.stderr.read()[-2000:]}"
                )
    raise AssertionError("Knowledge process readiness timeout")


def _drop_to(account_name: str, supplementary_group: str) -> None:
    import grp
    import pwd

    account = pwd.getpwnam(account_name)
    group = grp.getgrnam(supplementary_group)
    os.setgroups([group.gr_gid])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)


def _wait_socket(path: Path, process: subprocess.Popen[str], timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            assert process.stderr is not None
            raise AssertionError(
                f"entryd exited rc={process.returncode}: {process.stderr.read()[-1000:]}"
            )
        try:
            if stat.S_ISSOCK(path.lstat().st_mode):
                return
        except FileNotFoundError:
            pass
        time.sleep(0.025)
    raise AssertionError("entryd did not bind its declared mio.advise socket")


# ---------------------------------------------------------------------------
# The B5 path (#439, ADR-0010): entryd (azmioentry) -> contextobsd (azmioctx)
# -> contextd (azknowledgeegress) -> Knowledge. Shared by the process suites.
# ---------------------------------------------------------------------------

CONTEXTD_UNIT = "azazel-knowledge-contextd.service"
#: The one frame the broker accepts: the observation-origin technique query.
TECHNIQUES = ["T1059", "T1059.001"]
TECHNIQUE_FRAME = {"privacy_class": "P0-public", "techniques": TECHNIQUES}


def _grant_contextd() -> None:
    """This boot's grant marker for contextd, as the activation pass writes it.

    The broker refuses every request without it (`reason_code: withdrawn`).
    The container is disposable; the marker is written by the product's own
    `write_grant_markers` under the real `/run`, which is root's.
    """
    from azazel_nexus_runtime import activation_markers

    if activation_markers.inspect_grant_marker(CONTEXTD_UNIT) is not None:
        return
    parent = Path("/run/azazel-activation")
    parent.mkdir(mode=0o755, exist_ok=True)
    parent.chmod(0o755)
    os.chown(parent, 0, 0)
    granted = parent / "granted"
    if granted.exists():
        shutil.rmtree(granted)
    activation_markers.write_grant_markers([CONTEXTD_UNIT])
    assert activation_markers.inspect_grant_marker(CONTEXTD_UNIT) is not None


def _place_observation_rule(service_root: Path, limit: int = 60) -> Path:
    """The root-owned observation rule (`technique-set/1`) under AZAZEL_ROOT.

    Without it the broker refuses every technique query before sending. The
    product loader (`load_observation_rule`) reads it; nothing here bypasses it.
    """
    from azazel_nexus_runtime.knowledge_context_config import OBSERVATION_RULE_SCHEMA

    directory = service_root / "etc/azazel/knowledge-context"
    directory.mkdir(parents=True, exist_ok=True)
    for part in (service_root / "etc", service_root / "etc/azazel", directory):
        part.chmod(0o755)
        os.chown(part, 0, 0)
    path = directory / "observation-query.json"
    path.write_text(json.dumps({"schema": OBSERVATION_RULE_SCHEMA, "rule": "technique-set/1",
                                "max_requests_per_minute": limit}))
    path.chmod(0o644)
    os.chown(path, 0, 0)
    return path


def _contextobs_layout(service_root: Path) -> None:
    """The context observation unit's socket and ledger leaves (install.sh)."""
    import grp
    import pwd

    ctx = pwd.getpwnam("azmioctx")
    contextobs_gid = grp.getgrnam("azmio-contextobs").gr_gid
    for leaf, owner, group, mode in (
            ("run/mio-contextobs", ctx.pw_uid, contextobs_gid, 0o2710),
            ("state/mio-contextobs", ctx.pw_uid, 0, 0o700)):
        directory = service_root / "var/lib/azazel" / leaf
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(mode)
        os.chown(directory, owner, group)


def _start_contextobsd(service_root: Path, env: dict) -> subprocess.Popen:
    """The shipped `mio_contextobsd.main()` as azmioctx, with only the broker's client group."""
    import grp
    import pwd

    ctx = pwd.getpwnam("azmioctx")
    client_gid = grp.getgrnam("azknowledge-context-client").gr_gid

    def apply():
        os.setgroups([client_gid])
        os.setgid(ctx.pw_gid)
        os.setuid(ctx.pw_uid)

    process = subprocess.Popen(
        [sys.executable, "-B", "-c",
         "from azazel_nexus_runtime.mio_contextobsd import main; raise SystemExit(main())"],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, preexec_fn=apply)
    _wait_socket(service_root / "var/lib/azazel/run/mio-contextobs/mio-contextobs.sock", process)
    return process


def _start_entryd(service_root: Path, env: dict) -> subprocess.Popen:
    """The shipped entryd as azmioentry with its two unit groups."""
    import grp
    import pwd

    entry = pwd.getpwnam("azmioentry")
    groups = [grp.getgrnam("azazel-operator").gr_gid, grp.getgrnam("azmio-contextobs").gr_gid]

    def apply():
        os.setgroups(groups)
        os.setgid(entry.pw_gid)
        os.setuid(entry.pw_uid)

    process = subprocess.Popen(
        [sys.executable, "-B", "-c",
         "from azazel_nexus_runtime.mio_entryd import main; raise SystemExit(main())"],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, preexec_fn=apply)
    _wait_socket(service_root / "var/lib/azazel/run/mio-advise/mio-advise.sock", process)
    return process


OBSERVE_CALLER = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
from test_mio_context_observe import obs_frame
from azazel_nexus_runtime.mio_socket_client import _exchange
ids = json.loads(sys.argv[2])
reply = _exchange("mio-advise", "azmioentry", "mio.context.observe",
                  {"deadline_ms": 350}, payload=obs_frame(ids), deadline_s=1.5)
fast = reply["fast_assistance"]
record = fast.get("technique_knowledge") or {}
print(json.dumps({
  "outcome": reply["outcome"],
  "timing_keys": sorted(reply["timing"]),
  "hop_timing": reply["timing"]["locald"],
  "full_node_context_status": fast.get("full_node_context_status"),
  "fabric_advisory": "fabric_knowledge_context_advisory" in fast,
  "transport": record.get("transport"),
  "verification": record.get("verification"),
  "techniques": [t["technique_id"] for t in record.get("techniques") or []],
  "coverage": [t["coverage"] for t in record.get("techniques") or []],
}, sort_keys=True))
'''


def _observe_via_entry(service_root: Path, ids=TECHNIQUES) -> dict:
    """One explainer `mio.context.observe` through the real entryd socket, as azexplain."""
    result = subprocess.run(
        [sys.executable, "-B", "-c", OBSERVE_CALLER, str(ROOT / "tests/unit"), json.dumps(list(ids))],
        cwd=ROOT, env={**os.environ, "AZAZEL_ROOT": str(service_root)},
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10, check=False,
        preexec_fn=lambda: _drop_to("azexplain", "azmio-advise"))
    assert result.returncode == 0, (result.stdout + result.stderr)[-1500:]
    value = json.loads(result.stdout)
    assert value["outcome"] == "context_observed", value
    # The reply keeps its shape: the hop's timing under `locald` (ADR-0010).
    assert value["timing_keys"] == ["entry_ms", "locald"], value
    # The answer is never handed to M.I.O.
    assert value["fabric_advisory"] is False, value
    assert value["full_node_context_status"] == "unavailable", value
    return value


def _assert_technique_received(value: dict, ids=TECHNIQUES) -> None:
    assert (value["transport"], value["verification"]) == ("received", "ok"), value
    assert value["techniques"] == sorted(set(ids)), value
    assert value["hop_timing"]["context"] == "received", value


def _assert_technique_not_received(value: dict) -> None:
    assert value["transport"] in {"unavailable", "refused"}, value
    assert value["verification"] in {"not_run", "failed"}, value
    assert value["hop_timing"] is None or value["hop_timing"]["context"] != "received", value


@pytest.fixture
def service_accessible_root():
    """Use a synthetic root traversable by the distinct service accounts."""
    root = Path(tempfile.mkdtemp(prefix="n395-", dir="/tmp"))
    root.chmod(0o755)
    try:
        yield root
    finally:
        shutil.rmtree(root)


def test_nexus_client_interoperates_with_knowledge_mtls_process(service_accessible_root: Path):
    knowledge = Path(os.environ["KNOWLEDGE_TEST_SRC"]).resolve()
    server_script = knowledge / "tests/unit/_knowledge_context_mtls_server.py"
    assert server_script.is_file()
    root = service_accessible_root
    pki = _pki(root / "pki")
    pythonpath = os.pathsep.join(
        [str(knowledge / "src"), str(knowledge / "tests/unit"),
         os.environ.get("PYTHONPATH", "")]
    )
    server = subprocess.Popen(
        [sys.executable, str(server_script), str(root / "knowledge-root"), str(pki)],
        cwd=server_script.parent,
        env={**os.environ, "PYTHONPATH": pythonpath},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready = None
    try:
        ready = _ready(server)
        assert ready["ready"] is True and ready["pid"] == server.pid != os.getpid()
        assert ready["host"] == "127.0.0.1"

        # Matched TLS 1.3 controls: same CA, hostname/SNI, timeout, protocol,
        # and malformed probe. The positive adds only the client certificate.
        # The malformed request line exercises the TLS listener without
        # sending a valid Knowledge request to the application.
        authenticated = ssl.create_default_context(cafile=str(pki / "ca.pem"))
        authenticated.minimum_version = ssl.TLSVersion.TLSv1_3
        authenticated.maximum_version = ssl.TLSVersion.TLSv1_3
        authenticated.load_cert_chain(
            certfile=str(pki / "nexus.pem"), keyfile=str(pki / "nexus.key")
        )
        assert authenticated.check_hostname is True
        assert authenticated.verify_mode == ssl.CERT_REQUIRED
        probe = b"X\r\n\r\n"
        with socket.create_connection((ready["host"], ready["port"]), timeout=3) as raw:
            raw.settimeout(3)
            with authenticated.wrap_socket(raw, server_hostname="knowledge.test") as tls:
                assert tls.version() == "TLSv1.3"
                tls.sendall(probe)
                status_line = tls.makefile("rb").readline(128)
                assert status_line.startswith((b"HTTP/1.0 400 ", b"HTTP/1.1 400 ")), (
                    f"expected HTTP 400 from authenticated TLS 1.3 control, got {status_line!r}"
                )

        # The only missing credential is the client certificate. TLS 1.3 may
        # surface its alert during handshake, write, or read; all other
        # failures (including EOF/reset) must fail this test.
        unauthenticated = ssl.create_default_context(cafile=str(pki / "ca.pem"))
        unauthenticated.minimum_version = ssl.TLSVersion.TLSv1_3
        unauthenticated.maximum_version = ssl.TLSVersion.TLSv1_3
        assert unauthenticated.check_hostname is True
        assert unauthenticated.verify_mode == ssl.CERT_REQUIRED
        with socket.create_connection((ready["host"], ready["port"]), timeout=3) as raw:
            raw.settimeout(3)
            rejection_reason = None
            try:
                unauthenticated_socket = unauthenticated.wrap_socket(
                    raw, server_hostname="knowledge.test"
                )
                with unauthenticated_socket:
                    unauthenticated_socket.sendall(probe)
                    unauthenticated_socket.recv(1)
            except ssl.SSLError as exc:
                rejection_reason = exc.reason
            else:
                pytest.fail("TLS server accepted a client without a certificate")
            assert rejection_reason == "TLSV13_ALERT_CERTIFICATE_REQUIRED", (
                "expected TLS 1.3 client-certificate rejection, got "
                f"{rejection_reason}"
            )

        now = datetime.now(UTC)
        server_der = ssl.PEM_cert_to_DER_cert((pki / "server.pem").read_text())
        endpoint = ProviderRecord(
            provider_id="azazel-knowledge",
            host="knowledge.test",
            port=ready["port"],
            path_template="/knowledge/{model}",
            certificate_pin=spki_pin(server_der),
            client_identity="nexus-process-test",
            model_id="knowledge-v1",
            max_request_bytes=4096,
            max_response_bytes=8192,
            deadline_seconds=8,
            allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,),
        )
        public_key = bytes.fromhex(ready["public_key"])
        assert ready["key_id"] == "sha256:" + hashlib.sha256(public_key).hexdigest()
        peer = KnowledgePeer(endpoint, ("127.0.0.1",), public_key, 1)
        registry = KnowledgeRegistry(
            "sha256:" + "a" * 64,
            {endpoint.provider_id: peer},
            (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            1,
        )
        client = KnowledgeClient(
            registry=registry,
            peer_id=endpoint.provider_id,
            ca_certificate=str(pki / "ca.pem"),
            identities={
                "nexus-process-test": (str(pki / "nexus.pem"), str(pki / "nexus.key"))
            },
            knowledge_context_enabled=True,
            knowledge_context_max_ttl_seconds=30,
            utc_now=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        policy = SanitizerPolicy.from_mapping(
            {
                "version": "knowledge-process-test-1",
                "remote_default": "deny",
                "classes": {"P0-public": {"remote": "allow", "fields": ["ip", "question"]}},
                "aliases": [],
                "redactions": ["secret"],
                "limits": {"max_bytes": 2048},
            }
        )
        response = client.request_context(
            frame={"ip": "203.0.113.7", "secret": "must-not-egress"},
            privacy_class=PrivacyClass.P0_PUBLIC,
            policy=policy,
            mission="synthetic-process-test",
            alias_key=b"process-test-only",
            deadline_s=8,
        )
        assert response.schema_version == "knowledge-context-response/v1"
        assert response.source_product == "azazel_nexus"
        assert response.authority == "advisory_only"
        assert response.provider_id == "azazel-knowledge"
        assert response.snapshot.state == "partial"
        assert response.request_id and response.correlation_id
        assert "must-not-egress" not in response.model_dump_json()

        # The broker's handler around the same production KnowledgeClient, with
        # its actual Knowledge peer still running: the technique query is
        # served and verified, a free-form question is refused before sending.
        from types import SimpleNamespace
        from azazel_nexus.technique_knowledge import project_technique_response
        from azazel_nexus_runtime.knowledge_context_config import ObservationRule
        from azazel_nexus_runtime.knowledge_contextd import CONTEXT_VERB, KnowledgeContextBroker

        posts = []
        original_post = client._post_path

        def counted_post(*args, **kwargs):
            posts.append(1)
            return original_post(*args, **kwargs)

        client._post_path = counted_post
        rule_file = root / "in-process-rule"
        rule_file.write_text("rule")
        info = os.lstat(rule_file)
        audit_events = []
        broker = KnowledgeContextBroker(
            client=client, policy=policy, mission="synthetic-process-test",
            alias_key=b"p" * 32, enabled=True, audit=audit_events.append,
            observation_rule=(ObservationRule("technique-set/1", 60),
                              (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)),
            observation_rule_path=rule_file, grant_marker=lambda: ("granted",))

        def ask(frame):
            return broker.handle(SimpleNamespace(
                verb=CONTEXT_VERB, arguments={
                    "deadline_ms": 8000,
                    "deadline_monotonic_ns": int((time.monotonic() + 8) * 1_000_000_000),
                },
                payload={"frame": frame}))

        broker_reply = ask(dict(TECHNIQUE_FRAME))
        assert "response" in broker_reply, (broker_reply, audit_events[-1:])
        assert broker_reply["response"]["authority"] == "advisory_only"
        assert len(posts) == 1
        record = project_technique_response(broker_reply["response"], TECHNIQUES)
        assert (record["transport"], record["verification"]) == ("received", "ok"), record
        assert [t["technique_id"] for t in record["techniques"]] == TECHNIQUES
        print("B5-OBS interop technique coverage",
              [(t["technique_id"], t["coverage"]) for t in record["techniques"]])
        for question in ("synthetic public context", "ATT&CK technique context: T1059"):
            marks = len(audit_events)
            # Every refusal names how far it got (60c990e): before sending.
            assert ask({"privacy_class": "P0-public", "question": question}) == {
                "refusal": "unavailable", "stage": "refused_before_send"}
            assert len(posts) == 1                       # Knowledge was not reached
            assert [e["event_type"] for e in audit_events[marks:]] == [
                "knowledge.context.completed"]
            assert audit_events[-1]["reason_code"] == "refused_before_send"
        client._post_path = original_post

        # Full path: four distinct identities and processes on real sockets.
        # Knowledge producer <- broker (azknowledgeegress) <- context
        # observation (azmioctx) <- entryd (azmioentry) <- explainer (azexplain).
        import grp
        import pwd

        _grant_contextd()
        service_root = root / "service-root"
        (service_root / "var/lib/azazel/run/knowledge-context").mkdir(parents=True)
        (service_root / "var/lib/azazel/run/mio").mkdir(parents=True)
        (service_root / "var/lib/azazel/run/mio-entry").mkdir(parents=True)
        (service_root / "var/lib/azazel/run/mio-advise").mkdir(parents=True)
        (service_root / "var/lib/azazel/run/mio-status").mkdir(parents=True)
        (service_root / "var/lib/azazel/run/ui-read/mio").mkdir(parents=True)
        (service_root / "var/lib/azazel/state/mio").mkdir(parents=True)
        (service_root / "var/lib/azazel/state/knowledge-context").mkdir(parents=True)
        egress = pwd.getpwnam("azknowledgeegress")
        mio = pwd.getpwnam("azmio")
        entry = pwd.getpwnam("azmioentry")
        ctx = pwd.getpwnam("azmioctx")
        operator = pwd.getpwnam("azoperator")
        context_gid = grp.getgrnam("azknowledge-context-client").gr_gid
        operator_gid = grp.getgrnam("azazel-operator").gr_gid
        advise_gid = grp.getgrnam("azmio-advise").gr_gid
        for directory, owner, group, mode in (
            (service_root, 0, 0, 0o755),
            (service_root / "var", 0, 0, 0o755),
            (service_root / "var/lib", 0, 0, 0o755),
            (service_root / "var/lib/azazel", 0, 0, 0o711),
            (service_root / "var/lib/azazel/run", 0, 0, 0o711),
            (service_root / "var/lib/azazel/run/knowledge-context", egress.pw_uid, context_gid, 0o2710),
            (service_root / "var/lib/azazel/run/mio", mio.pw_uid, operator_gid, 0o2710),
            (service_root / "var/lib/azazel/run/mio-entry", entry.pw_uid, operator_gid, 0o2710),
            (service_root / "var/lib/azazel/run/mio-advise", entry.pw_uid, advise_gid, 0o2710),
            (service_root / "var/lib/azazel/run/mio-status", entry.pw_uid, operator_gid, 0o2750),
            (service_root / "var/lib/azazel/run/ui-read", 0, 0, 0o711),
            (service_root / "var/lib/azazel/run/ui-read/mio", entry.pw_uid, 0, 0o2750),
            (service_root / "var/lib/azazel/state", 0, 0, 0o711),
            (service_root / "var/lib/azazel/state/knowledge-context", egress.pw_uid, 0, 0o700),
            (service_root / "var/lib/azazel/state/mio", entry.pw_uid, 0, 0o700),
        ):
            directory.chmod(mode)
            os.chown(directory, owner, group)
        _contextobs_layout(service_root)
        _place_observation_rule(service_root)
        os.chmod(pki, 0o750)
        os.chown(pki, 0, egress.pw_gid)
        for name in ("ca.pem", "nexus.pem", "nexus.key"):
            path = pki / name
            path.chmod(0o640 if name.endswith(".key") else 0o644)
            os.chown(path, 0, egress.pw_gid)
        broker_audit = service_root / "var/lib/azazel/state/knowledge-context/audit.jsonl"
        test_env = {**os.environ, "AZAZEL_ROOT": str(service_root),
                    "U29_AUDIT_FILE": str(broker_audit)}

        def credentials(account, supplementary=()):
            def apply():
                os.setgroups(list(supplementary))
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
            return apply

        def broker_events():
            if not broker_audit.exists():
                return []
            return [json.loads(line) for line in broker_audit.read_text().splitlines() if line]

        broker_args = [
            sys.executable,
            str(ROOT / "tests/real_process/_knowledge_context_broker_process.py"),
            str(service_root), str(pki), str(ready["port"]), ready["public_key"],
            spki_pin(server_der),
        ]

        def start_broker():
            return subprocess.Popen(
                broker_args, cwd=ROOT, env=test_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                preexec_fn=credentials(egress),
            )

        broker_process = start_broker()
        contextobsd_process = None
        entryd_process = None
        try:
            assert _ready(broker_process)["ready"] is True
            broker_dir = service_root / "var/lib/azazel/run/knowledge-context"
            # The ancestors are fixture setup; keep them traversable so the
            # negative identity is refused at the dedicated client-group leaf.
            for parent in (
                service_root / "var/lib/azazel",
                service_root / "var/lib/azazel/run",
            ):
                assert stat.S_IMODE(parent.stat().st_mode) == 0o711
            broker_dir_stat = broker_dir.stat()
            assert broker_dir_stat.st_uid == egress.pw_uid
            assert broker_dir_stat.st_gid == context_gid
            assert stat.S_IMODE(broker_dir_stat.st_mode) == 0o2710
            broker_socket = broker_dir / "knowledge-context.sock"
            broker_socket_stat = broker_socket.lstat()
            assert stat.S_ISSOCK(broker_socket_stat.st_mode)
            assert broker_socket_stat.st_uid == egress.pw_uid
            assert broker_socket_stat.st_gid == context_gid
            assert stat.S_IMODE(broker_socket_stat.st_mode) == 0o660
            assert operator.pw_uid != 0
            assert operator.pw_uid != egress.pw_uid
            assert operator.pw_gid != context_gid

            # A process outside the reviewed socket group receives kernel
            # EACCES on connect to the real broker socket. The check asserts
            # identity and filesystem modes, but does not claim which kernel
            # permission check (directory search or socket write) denied it.
            refusal_code = """
import errno, socket
from pathlib import Path
import os
path = str(Path(os.environ['AZAZEL_ROOT']) / 'var/lib/azazel/run/knowledge-context/knowledge-context.sock')
real_uid, effective_uid, saved_uid = os.getresuid()
real_gid, effective_gid, saved_gid = os.getresgid()
if 0 in (real_uid, effective_uid, saved_uid):
    raise SystemExit('outsider unexpectedly has a root uid')
if len({real_uid, effective_uid, saved_uid}) != 1:
    raise SystemExit('outsider uid identities do not match')
if len({real_gid, effective_gid, saved_gid}) != 1:
    raise SystemExit('outsider gid identities do not match')
if os.getgroups():
    raise SystemExit('outsider unexpectedly has supplementary groups')
capabilities = {}
for line in Path('/proc/self/status').read_text().splitlines():
    if line.startswith(('CapEff:', 'CapPrm:')):
        name, value = line.split(':', 1)
        capabilities[name] = int(value.strip(), 16)
if capabilities != {'CapEff': 0, 'CapPrm': 0}:
    raise SystemExit(f'outsider unexpectedly has capabilities: {capabilities}')
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    client.connect(path)
except PermissionError as exc:
    if exc.errno != errno.EACCES:
        raise
    print('permission-denied')
else:
    raise SystemExit(2)
finally:
    client.close()
"""
            refused = subprocess.run(
                [sys.executable, "-B", "-c", refusal_code],
                cwd=ROOT, env=test_env, capture_output=True, text=True, timeout=5,
                preexec_fn=credentials(operator),
            )
            assert refused.returncode == 0, refused.stderr[-1000:]
            assert refused.stdout.strip() == "permission-denied"
            assert broker_process.poll() is None

            # The model host's account is no broker client: given the client
            # group so the filesystem passes, it is refused by the kernel peer
            # credentials, and the producer is not reached.
            peer_code = """
import json, sys
from azazel_nexus_runtime.knowledge_context_socket import (
    KnowledgeContextUnavailable, request_context)
frame = json.loads(sys.argv[1])
try:
    request_context(frame, deadline_s=8)
    print(json.dumps({"outcome": "response"}))
except KnowledgeContextUnavailable as exc:
    print(json.dumps({"outcome": "unavailable", "stage": getattr(exc, "stage", None)}))
"""

            def ask_broker(account, frame):
                result = subprocess.run(
                    [sys.executable, "-B", "-c", peer_code, json.dumps(frame)],
                    cwd=ROOT, env=test_env, capture_output=True, text=True, timeout=15,
                    preexec_fn=credentials(account, (context_gid,)))
                assert result.returncode == 0, result.stderr[-1000:]
                return json.loads(result.stdout)

            marks = len(broker_events())
            assert ask_broker(mio, dict(TECHNIQUE_FRAME))["outcome"] == "unavailable"
            denied = [e for e in broker_events()[marks:]
                      if e.get("event_type") == "runtime.request_refused"]
            assert [(e["uid"], e["reason"]) for e in denied] == [(mio.pw_uid, "principal_denied")]
            assert not [e for e in broker_events()[marks:]
                        if e.get("event_type") == "knowledge.context.requested"]
            # The context observation account is served for the technique form
            # and refused, before sending, for a free-form question.
            marks = len(broker_events())
            assert ask_broker(ctx, dict(TECHNIQUE_FRAME)) == {"outcome": "response"}
            assert [e["event_type"] for e in broker_events()[marks:]] == [
                "knowledge.context.requested", "knowledge.context.completed"]
            assert broker_events()[-1]["outcome"] == "verified_advisory"
            marks = len(broker_events())
            assert ask_broker(ctx, {"privacy_class": "P0-public",
                                    "question": "synthetic public context"})["outcome"] == (
                "unavailable")
            after = broker_events()[marks:]
            assert [e["event_type"] for e in after] == ["knowledge.context.completed"], after
            assert after[0]["reason_code"] == "refused_before_send"

            # The explainer's observation-origin request through entryd and the
            # context observation unit, against the same running broker.
            contextobsd_process = _start_contextobsd(service_root, test_env)
            entryd_process = _start_entryd(service_root, test_env)
            observed = _observe_via_entry(service_root)
            _assert_technique_received(observed)
            print("B5-OBS interop chain", observed)
            assert broker_events()[-1]["outcome"] == "verified_advisory"

            # A stopped broker leaves no earlier answer in the path, and a
            # restart restores it without changing caller identity or policy.
            broker_process.terminate()
            broker_process.wait(timeout=10)
            assert broker_process.returncode == 0
            _assert_technique_not_received(_observe_via_entry(service_root))
            broker_process = start_broker()
            assert _ready(broker_process)["ready"] is True
            _assert_technique_received(_observe_via_entry(service_root))
        finally:
            for process in (entryd_process, contextobsd_process, broker_process):
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                    assert process is None or process.poll() is not None
        assert server.poll() is None
    finally:
        if server.poll() is None:
            server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
            raise AssertionError("Knowledge process did not stop on SIGTERM")
        if server.stdout:
            server.stdout.close()
        if server.stderr:
            server.stderr.close()
    assert server.returncode == 0
    assert (root / "knowledge-root/data/local.db").exists()
    assert ready is not None
    with pytest.raises(OSError):
        socket.create_connection((ready["host"], ready["port"]), timeout=1).close()
