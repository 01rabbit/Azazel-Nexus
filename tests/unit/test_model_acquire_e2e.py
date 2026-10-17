"""The commissioned service path, including real loopback mTLS and #95 import."""

import socket
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import artifact_egress, model_fetch
from azazel_nexus_runtime.artifact_egress import EgressRefused, EgressResult, Outcome
from azazel_nexus_runtime.model_fetch import AcquisitionState, acquire, compose_service
from nacl.signing import SigningKey
from test_artifact_egress import PINS, Server, client_context, partial_from, whole_body
from test_model_import import (
    ACTOR,
    COMMISSIONING,
    NOW,
    WEIGHTS,
    _write_catalog,
    an_entry,
    trusted,
)

from azazel_nexus import activation, cognition, model_import
from azazel_nexus.model_acquisition import MAX_ATTEMPTS, NO_CONSENT, SourceConsent
from azazel_nexus.model_catalog import CatalogRefused, artifact_filename
from azazel_nexus.model_import import ModelImport
from azazel_nexus.source_registry import (
    REGISTRY_DOMAIN,
    ArtifactClass,
    CommissionedSources,
    RegistryRefused,
    SourceRecord,
    read_registry,
    registry_payload,
)

SENTINEL = "az96-secret-sentinel-unique"


@pytest.fixture(autouse=True)
def boundaries(monkeypatch):
    """A bad resolver or dial fails before it could leave this machine."""
    dials, peers = [], []
    real_resolve = socket.getaddrinfo
    real_connect = socket.create_connection
    real_accept = socket.socket.accept

    def resolve(host, port, *args, **kwargs):
        assert host in ("fetch.azazel.test", "127.0.0.1")
        return real_resolve("127.0.0.1", port, *args, **kwargs)

    def connect(address, *args, **kwargs):
        assert address[0] == "127.0.0.1"
        dials.append(address)
        return real_connect(address, *args, **kwargs)

    def accept(listener):
        stream, peer = real_accept(listener)
        assert peer[0] == "127.0.0.1"
        peers.append(peer)
        return stream, peer

    def forbidden(*args, **kwargs):
        pytest.fail("acquisition attempted admission or activation")

    monkeypatch.setattr(artifact_egress.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(artifact_egress.socket, "create_connection", connect)
    monkeypatch.setattr(socket.socket, "accept", accept)
    monkeypatch.setattr(cognition, "admit_local_model", forbidden)
    monkeypatch.setattr(activation.ActivationController, "activate", forbidden)
    yield SimpleNamespace(dials=dials, peers=peers)
    assert all(address[0] == "127.0.0.1" for address in dials + peers)


@pytest.fixture
def servers():
    opened = []

    def start(responder=whole_body, *, connections=1, **kwargs):
        kwargs.setdefault("certificate", "server-fetch")
        class RepeatedServer(Server):
            def _serve(self):
                for _ in range(connections):
                    super()._serve()

        server = RepeatedServer(responder=responder, **kwargs)
        opened.append(server)
        return server

    yield start
    for server in opened:
        try:
            server.listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        server.close()
        server.thread.join(timeout=1)


@pytest.fixture
def setup(tmp_path):
    def build(server=None, *, classes=(ArtifactClass.MODEL_WEIGHTS,), records=True,
              pin=None, entry=None, **overrides):
        entry = entry or an_entry(source_id="vendor-primary")
        root = tmp_path / "node"
        root.mkdir(exist_ok=True)
        models = model_import.CommissionedModels(root, trusted(), COMMISSIONING)
        _write_catalog(root, [entry])
        registry_key = SigningKey(b"r" * 32)
        commissioned = CommissionedSources(
            trusted(), {"registry": bytes(registry_key.verify_key)}, COMMISSIONING,
        )
        record = SourceRecord(
            source_id="vendor-primary", host="fetch.azazel.test",
            port=server.port if server else 443, path_template="/artifacts/{digest}",
            certificate_pin=pin or PINS["server-fetch"], client_identity=SENTINEL,
            bandwidth_bytes_per_second=100 * 1024 * 1024,
            allowed_artifact_classes=classes,
        )
        payload = registry_payload(version=1, commissioning_digest=COMMISSIONING,
                                   records=[record] if records else [])
        path = tmp_path / "registry"
        path.write_bytes(bytes(registry_key.sign(REGISTRY_DOMAIN + payload).signature) + payload)
        registry = read_registry(path, commissioned=commissioned)
        events = []
        options = {
            "consent": SourceConsent(frozenset({"vendor-primary"}), ACTOR, NOW),
            "registry": registry, "models": models, "context": client_context(),
            "allowed_addresses": ["127.0.0.1"], "fetch_dir": tmp_path / "fetch",
            "free_bytes": 10**12, "installed": {}, "license_acknowledged": True,
            "now": NOW, "actor": ACTOR, "deadline_seconds": 10,
            "recorder": lambda step, event: events.append((step, dict(event))),
            "sleeper": lambda seconds: None,
        }
        options.update(overrides)
        return Scenario(entry, options, events)

    return build


class Scenario:
    def __init__(self, entry, options, events):
        self.entry, self.options, self.events = entry, options, events
        self.models = options["models"]

    @property
    def part(self):
        return self.options["fetch_dir"] / (self.entry.digest.split(":")[1] + ".part")

    def service(self, **overrides):
        options = {**self.options, **overrides}
        for key in ("free_bytes", "now"):
            value = options[key]
            if value is not None and not callable(value):
                options[key] = lambda value=value: value
        value = options.pop("installed")
        if value:
            options["installed"] = value if callable(value) else lambda: value
        return compose_service(**options)

    def request(self, **arguments):
        args = {"model_id": self.entry.model_id, "source_id": self.entry.source_id,
                    "digest": self.entry.digest, "size_bytes": self.entry.size_bytes, "resume_from": 0}
        args.update(arguments)
        return SimpleNamespace(arguments=args)

    def call(self, **arguments):
        return self.service().handle(self.request(**arguments))

    def check(self, reply, state, *, partial=None, imported=False, quarantine=False):
        assert reply["outcome"] == state.value
        assert reply["admitted"] is False
        assert bool(reply["offline_import"]) is (state is not AcquisitionState.PROMOTED)
        assert SENTINEL not in repr((reply, self.events))
        allowed = {"model_id", "source_id", "digest", "size", "received", "state", "reason"}
        assert all(set(event) <= allowed for _, event in self.events)
        if partial is None:
            assert not self.part.exists()
        else:
            assert self.part.read_bytes() == partial
        assert list(self.options["fetch_dir"].glob("*.part")) == (
            [] if partial is None else [self.part]
        )
        assert bool(list(self.models.inbox.glob("*"))) is imported
        assert bool(list(self.models.quarantine.glob("*.held"))) is quarantine
        generation = ModelImport(self.models).current_generation()
        if state is AcquisitionState.PROMOTED:
            assert generation.installed[self.entry.model_id] == self.entry.digest
            assert (self.models.store / artifact_filename(self.entry)).read_bytes() == WEIGHTS
        else:
            assert generation is None
            assert not self.models.current_path.exists()
            assert not list(self.models.store.glob("*"))


def body_case(setup, servers, real_tls, body):
    if real_tls:
        return setup(servers(response(body)))

    def transport(**kwargs):
        kwargs["sink"](body)
        return EgressResult(Outcome.COMPLETE, len(body), 200, SENTINEL)

    return setup(transport=transport)


def response(body):
    return lambda stream, request: whole_body(stream, request, body)


@pytest.mark.parametrize("real_tls", [True, pytest.param(False, marks=pytest.mark.injected)])
def test_success_and_rollback(setup, servers, boundaries, real_tls):
    case = body_case(setup, servers, real_tls, WEIGHTS)
    reply = case.call()
    case.check(reply, AcquisitionState.PROMOTED, imported=True)
    assert len(boundaries.dials) == len(boundaries.peers) == int(real_tls)
    assert [step for step, _ in case.events] == ["plan", "fetch", "import", "import", "outcome"]
    assert ModelImport(case.models).reading_for(case.entry.model_id).admitted is False
    # A second generation through exactly the same service path, then #95 rollback.
    second = an_entry(source_id="vendor-primary", model_id="second")
    _write_catalog(case.models.root, [case.entry, second])
    next_server = servers(response(WEIGHTS)) if real_tls else SimpleNamespace(port=443)
    record = replace(case.options["registry"].records[0], port=next_server.port)
    case.options["registry"] = replace(case.options["registry"], records=(record,))
    args = {"model_id": "second", "source_id": "vendor-primary", "digest": second.digest,
                "size_bytes": second.size_bytes, "resume_from": 0}
    reply = case.service().handle(SimpleNamespace(arguments=args))
    assert reply["outcome"] == "promoted"
    importer = ModelImport(case.models)
    assert importer.current_generation().number == 2
    restored = importer.rollback(reason="fixture rollback", actor=ACTOR, now=NOW)
    assert restored.number == 1
    assert dict(restored.installed) == {case.entry.model_id: case.entry.digest}
    assert importer.current_generation() == restored


@pytest.mark.parametrize("options,reason", [
    ({"consent": NO_CONSENT}, "not_confirmed"),
    ({"records": False}, "unknown_source"),
    ({"free_bytes": 1}, "insufficient_disk"),
    ({"attempts_used": 3}, "attempts_exhausted"),
])
def test_preflight_without_network(setup, boundaries, options, reason):
    case = setup(**options)
    reply = case.call()
    case.check(reply, AcquisitionState.REFUSED)
    assert reply["reason"] == reason
    assert not boundaries.dials
    assert not list(case.models.staging.glob("*"))


def test_catalog_registry_role_collision(boundaries):
    with pytest.raises(RegistryRefused) as caught:
        CommissionedSources(trusted(), {"another-id": next(iter(trusted().values()))},
                            COMMISSIONING)
    assert caught.value.cause.value == "shared_signing_key"
    assert not boundaries.dials


@pytest.mark.parametrize("arguments", [
    {"digest": "sha256:" + "0" * 64}, {"size_bytes": 1}, {"source_id": "vendor-mirror"},
])
def test_request_plan_mismatch(setup, boundaries, arguments):
    case = setup()
    reply = case.call(**arguments)
    case.check(reply, AcquisitionState.REFUSED)
    assert reply["reason"] == "plan_mismatch"
    assert not boundaries.dials
    assert not case.events


@pytest.mark.parametrize("certificate,client,ca", [
    ("server-untrusted-ca", "client", "trusted-ca.crt"),
    ("server-wrong-name", "client", "trusted-ca.crt"),
    ("server-expired", "client", "trusted-ca.crt"),
    ("server-fetch", "client-untrusted", "trusted-ca.crt"),
    ("server-fetch", "client", "untrusted-ca.crt"),
])
def test_tls_failures(setup, servers, certificate, client, ca):
    server = servers(response(WEIGHTS), certificate=certificate)
    case = setup(server, pin=PINS[certificate], context=client_context(ca=ca, client=client))
    reply = case.call()
    case.check(reply, AcquisitionState.FETCH_FAILED)
    assert reply["reason"] == "transport_failed"


def test_pin_mismatch(setup, servers):
    server = servers(response(WEIGHTS))
    case = setup(server, pin=PINS["server"])
    case.check(case.call(), AcquisitionState.FETCH_REFUSED)
    assert not server.requests


def test_redirect_and_secret_body(setup, servers):
    def redirect(stream, request):
        body = SENTINEL.encode()
        stream.sendall(b"HTTP/1.1 302 X\r\nLocation: /" + body + b"\r\n\r\n" + body)

    case = setup(servers(redirect))
    case.check(case.call(), AcquisitionState.FETCH_REFUSED)


def test_dns_outside_allowlist_never_connects(setup, monkeypatch, boundaries):
    monkeypatch.setattr(artifact_egress.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.96", 443)),
    ])
    case = setup()
    case.check(case.call(), AcquisitionState.FETCH_REFUSED)
    assert not boundaries.dials


def test_overrun(setup, servers):
    case = setup(servers(response(WEIGHTS + b"extra")))
    case.check(case.call(), AcquisitionState.FETCH_REFUSED)


def interrupted(stream, request):
    stream.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {len(WEIGHTS)}\r\n\r\n".encode())
    stream.sendall(WEIGHTS[:100])


def test_interruption_and_resume(setup, servers):
    case = setup(servers(interrupted))
    reply = case.call()
    case.check(reply, AcquisitionState.FETCH_INCOMPLETE, partial=WEIGHTS[:100])
    assert reply["received"] == 100 and reply["resumable"]
    server = servers(partial_from(100, WEIGHTS))
    record = replace(case.options["registry"].records[0], port=server.port)
    case.options["registry"] = replace(case.options["registry"], records=(record,))
    case.check(case.call(resume_from=100), AcquisitionState.PROMOTED, imported=True)
    assert "Range: bytes=100-" in server.requests[0]


def test_deadline(setup, servers):
    ticks = [0.0]

    def sleeper(seconds):
        ticks[0] += 20

    case = setup(servers(interrupted), clock=lambda: ticks[0], sleeper=sleeper)
    reply = case.call()
    case.check(reply, AcquisitionState.FETCH_INCOMPLETE, partial=WEIGHTS[:100])
    assert reply["reason"] == "timed_out" and reply["received"] == 100


@pytest.mark.parametrize("present,offset", [(None, 1), (b"abc", 1), (b"abc", 0)])
def test_resume_length_mismatch(setup, boundaries, present, offset):
    case = setup()
    if present is not None:
        case.part.parent.mkdir()
        case.part.write_bytes(present)
    reply = case.call(resume_from=offset)
    case.check(reply, AcquisitionState.REFUSED, partial=present)
    assert reply["reason"] == "resume_mismatch"
    assert reply["received"] == len(present or b"")
    assert reply["retained"] == ("partial" if present is not None else "none")
    assert not boundaries.dials


def test_server_ignores_range(setup, servers):
    case = setup(servers(response(WEIGHTS)))
    case.part.parent.mkdir()
    case.part.write_bytes(WEIGHTS[:100])
    case.check(case.call(resume_from=100), AcquisitionState.FETCH_REFUSED)


@pytest.mark.parametrize("real_tls", [True, pytest.param(False, marks=pytest.mark.injected)])
def test_digest_mismatch_is_quarantined_by_importer(setup, servers, real_tls):
    case = body_case(setup, servers, real_tls, b"x" * len(WEIGHTS))
    reply = case.call()
    case.check(reply, AcquisitionState.IMPORT_REFUSED, imported=True, quarantine=True)
    assert reply["retained"] == "inbox"
    assert next(case.models.quarantine.glob("*.held")).read_bytes() == b"x" * len(WEIGHTS)


@pytest.mark.parametrize("real_tls", [True, pytest.param(False, marks=pytest.mark.injected)])
def test_sink_disk_full(setup, servers, monkeypatch, real_tls):
    case = body_case(setup, servers, real_tls, WEIGHTS)
    real_fdopen = model_fetch.os.fdopen

    class BrokenSink:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, chunk):
            self.stream.write(chunk[:10])
            raise OSError(SENTINEL)

    monkeypatch.setattr(model_fetch.os, "fdopen", lambda *a, **k: BrokenSink(real_fdopen(*a, **k)))
    reply = case.call()
    case.check(reply, AcquisitionState.WRITE_FAILED)
    assert reply["reason"] == "write_failed"
    assert reply["received"] == 0 and reply["retained"] == "none"


@pytest.mark.parametrize("real_tls", [True, pytest.param(False, marks=pytest.mark.injected)])
def test_promotion_failure(setup, servers, monkeypatch, real_tls):
    case = body_case(setup, servers, real_tls, WEIGHTS)
    real_replace = model_import.os.replace

    def fail_store(source, destination):
        if destination.parent == case.models.store:
            raise OSError(SENTINEL)
        return real_replace(source, destination)

    monkeypatch.setattr(model_import.os, "replace", fail_store)
    reply = case.call()
    case.check(reply, AcquisitionState.IMPORT_FAILED, imported=True)
    assert reply["reason"] == "import_failed_inbox_retained"
    assert reply["retained"] == "inbox" and reply["received"] == len(WEIGHTS)
    assert (case.models.inbox / artifact_filename(case.entry)).read_bytes() == WEIGHTS
    assert not list(case.models.quarantine.glob("*"))


def test_transport_exception_sentinel_and_immutable_result(setup):
    def failed(**kwargs):
        raise OSError("fake/key/path/" + SENTINEL)

    case = setup(transport=failed)
    result = acquire(entry=case.entry, **case.options)
    assert result.state is AcquisitionState.FETCH_FAILED
    assert result.offline_import and not result.admitted
    assert SENTINEL not in repr((result, result.__dict__, case.events))
    with pytest.raises(FrozenInstanceError):
        result.reason = "changed"
    case.check(case.call(), AcquisitionState.FETCH_FAILED)


def test_candidate_plan_mismatch(setup, monkeypatch, boundaries):
    case = setup()
    real_resolve = model_fetch.resolve_candidate
    monkeypatch.setattr(model_fetch, "resolve_candidate", lambda *a, **k:
                        replace(real_resolve(*a, **k), size_bytes=1))
    result = acquire(entry=case.entry, **case.options)
    assert result.state is AcquisitionState.REFUSED
    assert result.reason == "plan_mismatch" and result.offline_import
    assert not boundaries.dials
    assert not case.part.exists()


def test_egress_exception_never_leaks(setup):
    def failed(**kwargs):
        raise EgressRefused(SENTINEL)

    case = setup(transport=failed)
    case.check(case.call(), AcquisitionState.FETCH_REFUSED)


@pytest.mark.injected
def test_artifact_class_policy_denial(setup, monkeypatch, boundaries):
    # Only MODEL_WEIGHTS exists today; a valid nonempty signed registry cannot
    # yet express a different class. Exercise the resolver's policy decision.
    case = setup()
    monkeypatch.setattr(SourceRecord, "allows", lambda self, artifact_class: False)
    reply = case.call()
    case.check(reply, AcquisitionState.REFUSED)
    assert reply["reason"] == "artifact_class_not_allowed"
    assert not boundaries.dials


@pytest.mark.injected
@pytest.mark.parametrize("outcome", ["complete", "interrupted", "timed_out", "refused", "failed"])
def test_composition_with_injected_transport(setup, outcome, boundaries):
    calls = []

    def transport(**kwargs):
        calls.append(kwargs)
        assert kwargs["host"] == "fetch.azazel.test"
        assert kwargs["expected_pin"] == PINS["server-fetch"]
        assert kwargs["allowed_addresses"] == ["127.0.0.1"]
        assert kwargs["expected_size"] == len(WEIGHTS)
        assert kwargs["resume_from"] == 0
        if outcome == "refused":
            raise EgressRefused(SENTINEL)
        if outcome == "failed":
            raise OSError(SENTINEL)
        body = WEIGHTS if outcome == "complete" else WEIGHTS[:100]
        kwargs["sink"](body)
        return EgressResult(Outcome(outcome), len(body), 200, SENTINEL)

    case = setup(transport=transport)
    reply = case.call()
    expected = {
        "complete": AcquisitionState.PROMOTED,
        "interrupted": AcquisitionState.FETCH_INCOMPLETE,
        "timed_out": AcquisitionState.FETCH_INCOMPLETE,
        "refused": AcquisitionState.FETCH_REFUSED,
        "failed": AcquisitionState.FETCH_FAILED,
    }[outcome]
    partial = WEIGHTS[:100] if outcome in ("interrupted", "timed_out") else None
    case.check(reply, expected, partial=partial, imported=outcome == "complete")
    assert len(calls) == 1
    assert not boundaries.dials


@pytest.mark.injected
@pytest.mark.parametrize("directory", ["staging", "inbox", "store", "quarantine", "trust", "state"])
def test_import_directories_never_hold_partials(setup, boundaries, directory):
    case = setup()
    case.options["fetch_dir"] = case.models.root / directory / "nested"
    result = acquire(entry=case.entry, **case.options)
    assert result.state is AcquisitionState.REFUSED
    assert result.reason == "unsafe_fetch_dir" and result.offline_import
    assert not case.options["fetch_dir"].exists()
    assert not boundaries.dials


@pytest.mark.injected
def test_resume_prefix_still_goes_through_full_digest_check(setup, boundaries):
    case = setup()
    case.part.parent.mkdir()
    case.part.write_bytes(b"x" * 100)

    def transport(**kwargs):
        assert kwargs["resume_from"] == 100
        kwargs["sink"](WEIGHTS[100:])
        return EgressResult(Outcome.COMPLETE, len(WEIGHTS), 206, SENTINEL)

    case.options["transport"] = transport
    case.check(case.call(resume_from=100), AcquisitionState.IMPORT_REFUSED,
               imported=True, quarantine=True)
    assert not boundaries.dials


@pytest.mark.injected
def test_resolver_exception_sentinel(setup, monkeypatch):
    case = setup()

    def failed(*args, **kwargs):
        raise LookupError(SENTINEL)

    monkeypatch.setattr(model_import.CommissionedModels, "catalog", failed)
    reply = case.call()
    assert reply["reason"] == "source_unavailable"
    assert reply["offline_import"] and not reply["admitted"]
    assert SENTINEL not in repr(reply)
    assert not case.part.exists()


@pytest.mark.parametrize("source,reason", [(None, "source_unavailable"),
                                           ("not-commissioned", "unknown_source")])
def test_acquire_source_refusal(setup, boundaries, source, reason):
    case = setup(entry=an_entry(source_id=source))
    result = acquire(entry=case.entry, **case.options)
    assert result.state is AcquisitionState.REFUSED
    assert result.reason == reason and result.offline_import
    assert not result.admitted and not result.resumable
    assert not boundaries.dials
    assert not case.part.exists()
    assert not list(case.models.inbox.glob("*"))
    assert not list(case.models.store.glob("*"))
    assert not list(case.models.quarantine.glob("*"))
    assert not case.models.current_path.exists()
    assert case.events[-1][1]["reason"] == reason


@pytest.mark.injected
def test_fsync_failure_is_a_write_failure(setup, monkeypatch):
    case = body_case(setup, None, False, WEIGHTS)

    def failed(descriptor):
        raise OSError(SENTINEL)

    monkeypatch.setattr(model_fetch.os, "fsync", failed)
    case.check(case.call(), AcquisitionState.WRITE_FAILED)


@pytest.mark.injected
def test_symlink_part_is_untrusted(setup, tmp_path, boundaries):
    case = setup()
    target = tmp_path / "unrelated"
    target.write_bytes(b"abc")
    case.part.parent.mkdir()
    case.part.symlink_to(target)
    reply = case.call(resume_from=3)
    case.check(reply, AcquisitionState.REFUSED)
    assert reply["reason"] == "resume_mismatch"
    assert reply["received"] == 0 and reply["retained"] == "none"
    assert target.read_bytes() == b"abc"
    assert not boundaries.dials


@pytest.mark.injected
@pytest.mark.parametrize("offset", [-1, len(WEIGHTS) + 1])
def test_resume_bounds_before_plan(setup, boundaries, offset):
    case = setup(free_bytes=0)
    reply = case.call(resume_from=offset)
    case.check(reply, AcquisitionState.REFUSED)
    assert reply["reason"] == "resume_mismatch"
    assert reply["received"] == 0
    assert not boundaries.dials


@pytest.mark.injected
def test_handoff_failure_retains_partial(setup, monkeypatch):
    case = body_case(setup, None, False, WEIGHTS)
    real_replace = model_fetch.os.replace

    def failed(source, destination):
        if source == case.part:
            raise OSError(SENTINEL)
        return real_replace(source, destination)

    monkeypatch.setattr(model_fetch.os, "replace", failed)
    reply = case.call()
    case.check(reply, AcquisitionState.IMPORT_FAILED, partial=WEIGHTS)
    assert reply["reason"] == "handoff_failed"
    assert reply["retained"] == "partial" and reply["received"] == len(WEIGHTS)


@pytest.mark.injected
def test_import_failure_retains_inbox(setup, monkeypatch):
    case = body_case(setup, None, False, WEIGHTS)

    def failed(*args, **kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(ModelImport, "import_entry", failed)
    reply = case.call()
    case.check(reply, AcquisitionState.IMPORT_FAILED, imported=True)
    assert reply["reason"] == "import_failed_inbox_retained"
    assert reply["retained"] == "inbox" and reply["received"] == len(WEIGHTS)
    assert "already in" in reply["offline_import"]
    assert (case.models.inbox / artifact_filename(case.entry)).read_bytes() == WEIGHTS


@pytest.mark.parametrize("real_tls,failure", [
    (True, "refused"),
    pytest.param(False, "failed", marks=pytest.mark.injected),
    pytest.param(False, "interrupted", marks=pytest.mark.injected),
    pytest.param(False, "timed_out", marks=pytest.mark.injected),
])
def test_attempts_exhausted_on_same_service(setup, servers, boundaries, real_tls, failure):
    def refused(stream, request):
        stream.sendall(b"HTTP/1.1 503 Refused\r\nContent-Length: 0\r\n\r\n")

    calls = []

    def transport(**kwargs):
        calls.append(kwargs)
        if failure == "failed":
            raise OSError(SENTINEL)
        return EgressResult(Outcome(failure), 0, 200, SENTINEL)

    server = servers(refused, connections=MAX_ATTEMPTS + 1) if real_tls else None
    case = setup(server, **({} if real_tls else {"transport": transport}))
    service = case.service()
    for _ in range(MAX_ATTEMPTS):
        reply = service.handle(case.request())
        expected = "fetch_failed" if failure == "failed" else "fetch_incomplete"
        assert reply["outcome"] == ("fetch_refused" if real_tls else expected)
        assert reply["received"] == 0
    before = (len(boundaries.dials), len(boundaries.peers), len(calls))
    reply = service.handle(case.request())
    assert reply["reason"] == "attempts_exhausted" and reply["outcome"] == "refused"
    assert (len(boundaries.dials), len(boundaries.peers), len(calls)) == before
    assert (len(server.requests) if real_tls else len(calls)) == MAX_ATTEMPTS


@pytest.mark.parametrize("real_tls", [True, pytest.param(False, marks=pytest.mark.injected)])
def test_installed_state_refreshed_after_promotion(setup, servers, boundaries, real_tls):
    case = body_case(setup, servers, real_tls, WEIGHTS)
    service = case.service()
    assert service.handle(case.request())["outcome"] == "promoted"
    before = len(boundaries.dials)
    reply = service.handle(case.request())
    assert reply["outcome"] == "refused" and reply["reason"] == "already_installed"
    assert len(boundaries.dials) == before
    assert len(boundaries.peers) == int(real_tls)


@pytest.mark.injected
def test_disk_free_measured_after_composition(setup, boundaries):
    case = setup()
    available = [10**12]
    service = case.service(free_bytes=lambda: available[0])
    available[0] = 0
    reply = service.handle(case.request())
    case.check(reply, AcquisitionState.REFUSED)
    assert reply["reason"] == "insufficient_disk"
    assert not boundaries.dials


@pytest.mark.injected
@pytest.mark.parametrize("measurement,error,reason", [
    ("installed", CatalogRefused, "installed_state_unavailable"),
    ("installed", OSError, "installed_state_unavailable"),
    ("free_bytes", OSError, "capacity_unavailable"),
    ("default_disk", OSError, "capacity_unavailable"),
    ("default_installed", CatalogRefused, "installed_state_unavailable"),
    ("default_installed", OSError, "installed_state_unavailable"),
])
def test_preflight_measurement_failure(setup, monkeypatch, boundaries, measurement, error, reason):
    calls = []
    unavailable = [True]

    def measure(*args):
        if unavailable[0]:
            raise error(SENTINEL)
        if measurement == "default_disk":
            return SimpleNamespace(free=10**12)
        if measurement == "default_installed":
            return None
        return {} if measurement == "installed" else 10**12

    def transport(**kwargs):
        calls.append(kwargs)
        raise OSError(SENTINEL)

    case = setup(transport=transport, attempts_used=MAX_ATTEMPTS - 1)
    if measurement == "default_disk":
        monkeypatch.setattr(model_fetch.shutil, "disk_usage", measure)
        service = case.service(free_bytes=None)
    elif measurement == "default_installed":
        monkeypatch.setattr(ModelImport, "current_generation", measure)
        service = case.service()
    else:
        service = case.service(**{measurement: measure})
    reply = service.handle(case.request())
    assert reply == {
        "model_id": case.entry.model_id, "source_id": case.entry.source_id,
        "outcome": "refused", "received": 0, "reason": reason,
        "admitted": False, "resumable": False, "retained": "none",
        "offline_import": model_fetch.OFFLINE_IMPORT,
    }
    assert reply["offline_import"]
    assert SENTINEL not in repr((reply, case.events))
    assert not calls and not boundaries.dials
    assert not case.part.exists()
    unavailable[0] = False
    assert service.handle(case.request())["outcome"] == "fetch_failed"
    assert service.handle(case.request())["reason"] == "attempts_exhausted"
    assert len(calls) == 1 and not boundaries.dials


@pytest.mark.injected
def test_directory_part_retained_after_discard_failure(setup, boundaries):
    calls = []

    def transport(**kwargs):
        calls.append(kwargs)
        pytest.fail("a directory at the handoff location must prevent transport")

    case = setup(transport=transport)
    case.part.mkdir(parents=True)
    reply = case.call()
    assert reply["outcome"] == "refused" and reply["reason"] == "resume_mismatch"
    assert reply["retained"] == "partial" and reply["received"] == 0
    assert reply["offline_import"] and not reply["admitted"] and not reply["resumable"]
    assert SENTINEL not in repr((reply, case.events))
    assert case.part.is_dir()
    assert not calls and not boundaries.dials
    assert not list(case.models.inbox.glob("*"))
    assert not list(case.models.store.glob("*"))
    assert not case.models.current_path.exists()


@pytest.mark.injected
def test_default_disk_measurement_and_now_per_request(setup, monkeypatch):
    calls, times = [], []
    case = setup()

    def usage(path):
        calls.append(path)
        return SimpleNamespace(free=0 if len(calls) == 3 else 10**12)

    def now():
        times.append(NOW)
        return NOW

    def failed(**kwargs):
        raise OSError(SENTINEL)

    monkeypatch.setattr(model_fetch.shutil, "disk_usage", usage)
    service = case.service(free_bytes=None, now=now, transport=failed)
    assert service.handle(case.request())["outcome"] == "fetch_failed"
    assert service.handle(case.request())["reason"] == "insufficient_disk"
    assert len(calls) == 4
    assert len(times) == 2
    assert all(path.exists() for path in calls)


@pytest.mark.injected
def test_promotion_clears_attempts_budget(setup):
    calls = []

    def transport(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            kwargs["sink"](WEIGHTS)
            return EgressResult(Outcome.COMPLETE, len(WEIGHTS), 200, SENTINEL)
        raise OSError(SENTINEL)

    case = setup(transport=transport, attempts_used=MAX_ATTEMPTS - 2)
    service = case.service(installed=dict)
    assert service.handle(case.request())["outcome"] == "fetch_failed"
    assert service.handle(case.request())["outcome"] == "promoted"
    for _ in range(MAX_ATTEMPTS):
        assert service.handle(case.request())["outcome"] == "fetch_failed"
    assert service.handle(case.request())["reason"] == "attempts_exhausted"
    assert len(calls) == MAX_ATTEMPTS + 2


@pytest.mark.injected
def test_attempts_are_per_model_and_digest(setup):
    calls = []

    def failed(**kwargs):
        calls.append(kwargs)
        raise OSError(SENTINEL)

    case = setup(transport=failed)
    service = case.service()
    for _ in range(MAX_ATTEMPTS):
        assert service.handle(case.request())["outcome"] == "fetch_failed"
    assert service.handle(case.request())["reason"] == "attempts_exhausted"
    other = an_entry(source_id="vendor-primary", model_id="other")
    changed = replace(case.entry, digest="sha256:" + "0" * 64)
    _write_catalog(case.models.root, [changed, other])
    assert service.handle(case.request(model_id=other.model_id))["outcome"] == "fetch_failed"
    assert service.handle(case.request(digest=changed.digest))["outcome"] == "fetch_failed"
    assert len(calls) == MAX_ATTEMPTS + 2


@pytest.mark.injected
def test_discard_reports_zero_after_transport_wrote(setup):
    def failed(**kwargs):
        kwargs["sink"](WEIGHTS[:100])
        raise OSError(SENTINEL)

    case = setup(transport=failed)
    reply = case.call()
    case.check(reply, AcquisitionState.FETCH_FAILED)
    assert reply["received"] == 0 and reply["retained"] == "none"


@pytest.mark.injected
@pytest.mark.parametrize("failure,reason", [("full", "insufficient_disk"), ("unreadable", "capacity_unavailable")])
@pytest.mark.parametrize("resume", [False, True])
def test_import_checks_models_filesystem_before_transport(setup, monkeypatch, boundaries, failure, reason, resume):
    from azazel_nexus.model_acquisition import MIN_FREE_HEADROOM_BYTES

    case = setup()
    calls = []
    if resume:
        case.part.parent.mkdir(parents=True, exist_ok=True)
        case.part.write_bytes(WEIGHTS[:1])

    def usage(path):
        calls.append(path)
        if path == case.models.root:
            if failure == "unreadable":
                raise OSError(SENTINEL)
            return SimpleNamespace(free=case.entry.size_bytes + MIN_FREE_HEADROOM_BYTES - 1)
        return SimpleNamespace(free=10**12)

    monkeypatch.setattr(model_fetch.shutil, "disk_usage", usage)
    reply = case.service(free_bytes=None).handle(case.request(resume_from=1 if resume else 0))
    assert reply["outcome"] == "refused" and reply["reason"] == reason
    assert case.models.root in calls
    assert not boundaries.dials
    assert SENTINEL not in repr(reply)
