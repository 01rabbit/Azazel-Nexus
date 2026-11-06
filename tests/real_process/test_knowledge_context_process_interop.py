"""Nexus KnowledgeClient against the real Knowledge mTLS app in a child process.

This runs only in the isolated container runner. Its CA, keys, database and
Knowledge server process live under pytest's temporary directory.
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
        for name in ("azknowledgeegress", "azmio", "azmioentry", "azoperator"):
            pwd.getpwnam(name)
        for name in ("azknowledge-context-client", "azazel-operator", "azmio-advise"):
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
         "-out", "ca.pem", "-subj", "/CN=process-test-ca", "-days", "2"],
        root,
    )
    (root / "server.ext").write_text(
        "subjectAltName=DNS:knowledge.test\nextendedKeyUsage=serverAuth\n"
    )
    (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
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


def _normal_entry_advisory(root: Path) -> dict:
    """Send one P0 request through the production mio.advise entry socket.

    Only a small, allowlisted projection is written to pytest output. The full
    Knowledge response remains in-process and is checked below.
    """
    code = r'''
import json
from azazel_nexus_runtime.mio_socket_client import _exchange
frame = {"request_id":"normal-entry-context", "privacy_class":"P0-public",
         "question":"synthetic public observation context", "context":[]}
reply = _exchange("mio-entry", "azmioentry", "mio.advise",
                  {"deadline_ms":5000}, payload=frame, deadline_s=5.25)
fast = reply["fast_assistance"]
advisory = fast.get("fabric_knowledge_context_advisory")
print(json.dumps({
  "route": reply["route"],
  "state": fast["state"],
  "knowledge_status": fast["dependency_outcome"]["knowledge"],
  "full_node_context_status": fast.get("full_node_context_status"),
  "lite_claim_count": len(fast["knowledge"]),
  "observation_count": len(fast["observations"]),
  "advisory_authority": advisory.get("authority") if advisory else None,
  "advisory_claim_status": advisory.get("claim_status") if advisory else None,
  "advisory_trust": advisory.get("trust") if advisory else None,
  "snapshot_state": advisory.get("snapshot_state") if advisory else None,
  "partial_warning": "KNOWLEDGE_CONTEXT_PARTIAL" in fast["unknowns"],
  "partial_check": bool(fast["next_checks"]) and fast["next_checks"][0] ==
    "Request an authorized current full-node Knowledge snapshot; this partial or stale advisory is not a complete current snapshot.",
  "question_unknown_only": bool(advisory) and not advisory["facts"] and any(
    "could not be normalized" in item for item in advisory["unknowns"]),
  "handoff_action": fast["handoff"]["current_action"] if fast.get("handoff") else None,
}, sort_keys=True))
'''
    result = subprocess.run(
        [sys.executable, "-B", "-c", code], cwd=ROOT,
        env={**os.environ, "AZAZEL_ROOT": str(root)},
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=8, check=False,
        preexec_fn=lambda: _drop_to("azoperator", "azazel-operator"),
    )
    assert result.returncode == 0, (result.stdout + result.stderr)[-1000:]
    value = json.loads(result.stdout)
    assert set(value) == {
        "route", "state", "knowledge_status", "full_node_context_status", "lite_claim_count",
        "observation_count", "advisory_authority", "advisory_claim_status",
        "advisory_trust", "snapshot_state", "partial_warning", "partial_check",
        "question_unknown_only", "handoff_action",
    }
    return value


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

        # Exercise the service's ordinary AF-independent handler around the
        # same production KnowledgeClient while its actual Knowledge peer is
        # still running in a separate loopback process.
        from types import SimpleNamespace
        from azazel_nexus_runtime.knowledge_contextd import CONTEXT_VERB, KnowledgeContextBroker
        broker = KnowledgeContextBroker(
            client=client, policy=policy, mission="synthetic-process-test",
            alias_key=b"p" * 32, enabled=True,
        )
        broker_reply = broker.handle(SimpleNamespace(
            verb=CONTEXT_VERB, arguments={
                "deadline_ms": 8000,
                "deadline_monotonic_ns": int((time.monotonic() + 8) * 1_000_000_000),
            },
            payload={"frame": {"privacy_class": "P0-public",
                               "question": "synthetic public context"}},
        ))
        assert broker_reply["response"]["authority"] == "advisory_only"
        assert "must-not-egress" not in json.dumps(broker_reply)
        from azazel_nexus_runtime.mio_fast_assistance import fast_assistance

        producer_response = broker_reply["response"]
        projected = fast_assistance(
            {"request_id": "normal-process", "privacy_class": "P0-public",
             "question": "synthetic public context", "context": []},
            deadline_s=1.0,
            fabric_knowledge_context_response=producer_response,
        )
        assert "fabric_knowledge_context_advisory" in projected, (
            "MIO rejected signed producer response: "
            f"snapshot={producer_response.get('snapshot')}; "
            f"facts={len(producer_response.get('facts', []))}; "
            f"subject_types={[item.get('subject', {}).get('entity_type') for item in producer_response.get('facts', [])]}; "
            f"inferences={len(producer_response.get('inferences', []))}; "
            f"unknowns={producer_response.get('unknowns')}; "
            f"limitations={producer_response.get('limitations')}"
        )

        # Full normal path: three distinct child identities/processes for the
        # Knowledge producer, its Nexus broker, and M.I.O. locald. The caller
        # is the entry service and can only reach locald's declared socket.
        import grp
        import pwd

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
            (service_root / "var/lib/azazel/state/knowledge-context", egress.pw_uid, 0, 0o700),
            (service_root / "var/lib/azazel/state/mio", entry.pw_uid, 0, 0o700),
        ):
            directory.chmod(mode)
            os.chown(directory, owner, group)
        os.chmod(pki, 0o750)
        os.chown(pki, 0, egress.pw_gid)
        for name in ("ca.pem", "nexus.pem", "nexus.key"):
            path = pki / name
            path.chmod(0o640 if name.endswith(".key") else 0o644)
            os.chown(path, 0, egress.pw_gid)

        test_env = {**os.environ, "AZAZEL_ROOT": str(service_root)}

        def credentials(account, supplementary=()):
            def apply():
                os.setgroups(list(supplementary))
                os.setgid(account.pw_gid)
                os.setuid(account.pw_uid)
            return apply

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
        locald_process = None
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

            # The subsequent authorized MIO/entry request is the positive
            # control against this same still-running broker socket/listener.
            locald_process = subprocess.Popen(
                [sys.executable, str(ROOT / "tests/real_process/_mio_locald_context_process.py")],
                cwd=ROOT, env=test_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                preexec_fn=credentials(mio, (context_gid,)),
            )
            assert _ready(locald_process)["ready"] is True
            entryd_process = subprocess.Popen(
                [sys.executable, "-B", "-c",
                 "from azazel_nexus_runtime.mio_entryd import main; raise SystemExit(main())"],
                cwd=ROOT, env=test_env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                preexec_fn=credentials(entry, (operator_gid,)),
            )
            _wait_socket(service_root / "var/lib/azazel/run/mio-advise/mio-advise.sock",
                         entryd_process)
            caller = subprocess.run(
                [sys.executable, "-c",
                 "import json; from azazel_nexus_runtime.mio_socket_client import LocalSocketClient; "
                 "c=LocalSocketClient(); r=c.assess({'request_id':'normal-process',"
                 "'privacy_class':'P0-public','question':'synthetic public context',"
                 "'context':[]}, deadline_s=10); print(json.dumps(r))"],
                cwd=ROOT, env=test_env, capture_output=True, text=True, timeout=15,
                preexec_fn=credentials(entry, (operator_gid,)),
            )
            assert caller.returncode == 0, caller.stderr[-2000:]
            assessed = json.loads(caller.stdout)
            advisory = assessed.get("fabric_knowledge_context_advisory")
            assert type(advisory) is dict, (
                "full-node response was not projected by MIO: "
                f"knowledge={assessed.get('dependency_outcome', {}).get('knowledge')}; "
                f"unknowns={assessed.get('unknowns')}"
            )
            assert advisory["authority"] == "advisory_only"
            assert advisory["claim_status"] == "source_reported_unverified"
            assert advisory["trust"] == "unverified_advisory_only"
            assert assessed["dependency_outcome"]["knowledge"] == "unavailable"
            assert assessed["full_node_context_status"] == "received"
            assert advisory["snapshot_state"] == "partial"
            assert "KNOWLEDGE_CONTEXT_PARTIAL" in assessed["unknowns"]
            assert assessed["next_checks"][0] == (
                "Request an authorized current full-node Knowledge snapshot; "
                "this partial or stale advisory is not a complete current snapshot.")
            # A question is not a typed IOC. No exact match is claimed.
            assert advisory["facts"] == []
            assert any("could not be normalized" in item for item in advisory["unknowns"])
            assert assessed["knowledge"] == []
            assert assessed["observations"] == []
            assert assessed["handoff"]["current_action"] is None
            assert "must-not-egress" not in caller.stdout

            # The same real Knowledge response must also cross Nexus's ordinary
            # operator entryd -> locald -> broker composition. This is separate
            # from the lower-level locald call above and preserves Knowledge
            # output as an unverified advisory.
            entry_reply = _normal_entry_advisory(service_root)
            assert entry_reply["knowledge_status"] == "unavailable", entry_reply
            assert entry_reply["full_node_context_status"] == "received", entry_reply
            assert entry_reply["snapshot_state"] == "partial", entry_reply
            assert entry_reply["partial_warning"] is True, entry_reply
            assert entry_reply["partial_check"] is True, entry_reply
            assert entry_reply["question_unknown_only"] is True, entry_reply
            assert entry_reply["lite_claim_count"] == 0, entry_reply
            assert entry_reply["observation_count"] == 0, entry_reply
            assert entry_reply["advisory_authority"] == "advisory_only", entry_reply
            assert entry_reply["advisory_claim_status"] == "source_reported_unverified", entry_reply
            assert entry_reply["advisory_trust"] == "unverified_advisory_only", entry_reply
            assert entry_reply["handoff_action"] is None, entry_reply

            # A stopped egress service must not leave its previous advisory in
            # the ordinary path. Restarting the same isolated service should
            # restore the route without changing caller identity or policy.
            broker_process.terminate()
            broker_process.wait(timeout=10)
            assert broker_process.returncode == 0
            degraded = _normal_entry_advisory(service_root)
            assert degraded["advisory_authority"] is None, degraded
            assert degraded["knowledge_status"] == "unavailable", degraded
            assert degraded["full_node_context_status"] == "unavailable", degraded
            assert degraded["lite_claim_count"] == 0, degraded
            assert degraded["observation_count"] == 0, degraded
            assert degraded["handoff_action"] is None, degraded

            broker_process = start_broker()
            assert _ready(broker_process)["ready"] is True
            recovered = _normal_entry_advisory(service_root)
            assert recovered["knowledge_status"] == "unavailable", recovered
            assert recovered["full_node_context_status"] == "received", recovered
            assert recovered["snapshot_state"] == "partial", recovered
            assert recovered["partial_warning"] is True, recovered
            assert recovered["partial_check"] is True, recovered
            assert recovered["question_unknown_only"] is True, recovered
            assert recovered["advisory_authority"] == "advisory_only", recovered
            assert recovered["advisory_claim_status"] == "source_reported_unverified", recovered
            assert recovered["advisory_trust"] == "unverified_advisory_only", recovered
            assert recovered["lite_claim_count"] == 0, recovered
            assert recovered["observation_count"] == 0, recovered
            assert recovered["handoff_action"] is None, recovered
        finally:
            for process in (entryd_process, locald_process, broker_process):
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
