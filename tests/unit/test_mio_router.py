"""Real in-process producer -> persisted, verified chain; no live transport."""

from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_router, runtime_paths
from azazel_nexus_runtime.inference_egress import EgressReport, TransportOutcome
from azazel_nexus_runtime.mio_locald import LocalRuntimeService
from test_mio_remoted import NOW, Request, _seal, _service

from azazel_nexus import model_runtime
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.core_reserve import CoreReserve
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.remote_trust import Exclusion, RemoteAdmission
from azazel_nexus.resource_profile import ResourceProfile
from azazel_nexus.route_evidence import Prediction
from azazel_nexus.route_ledger import RouteChain
from azazel_nexus.route_selection import RequestOutcome, TerminalEvent
from azazel_nexus.routing import Route
from azazel_nexus.sanitizer import PrivacyClass

SENTINEL = b'PROMPT_BODY_CREDENTIAL_SENTINEL'


@pytest.fixture
def setup_router(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, 'ROOT', tmp_path)
    calls = []

    def make(outcome=TransportOutcome.RECEIVED, body=b'{"advice":"safe","fields":{}}'):
        def transport(**kwargs):
            calls.append('remote')
            return EgressReport(outcome, len(body), 200, 'fixture transport reason'), body

        return mio_router.MioRouter(
            remote=_service(transport=transport), local=LocalRuntimeService(), clock=lambda: NOW
        ), calls

    return make


def invoke(
    router, *, local=False, mismatch=False,
    privacy_class=PrivacyClass.P1_SANITIZED, remote_request=None,
):
    return router.handle(
        local_request=SimpleNamespace(arguments={'model_id': 'test-model', 'runtime_id': 'fixture'}),
        remote_request=remote_request or Request(
            frame=SENTINEL, envelope=_seal(frame=b'other' if mismatch else SENTINEL)
        ),
        profile=MioProfile.FASTEST_PERMITTED,
        privacy_class=privacy_class,
        remote=(
            RemoteAdmission(False, Exclusion.PRIVACY_CLASS, 'fixture privacy class forbids remote')
            if privacy_class in {PrivacyClass.P2_MISSION, PrivacyClass.P3_RESTRICTED}
            else RemoteAdmission(True, None, 'fixture permitted')
        ),
        local_admitted=True,
        local_refusal='fixture local admitted',
        predictions={
            route: Prediction(route.value, True, ms, 10, 10, False, 'fixture observations')
            for route, ms in [(Route.LOCAL, 1 if local else 20), (Route.REMOTE, 10)]
        },
        deadline_ms=1000,
    )


def events(router):
    # The whole retained chain, so a run across UTC midnight still verifies.
    ledger = RouteChain(router.ledger.directory)
    ledger.verify()
    for segment in ledger.segments():
        assert SENTINEL.decode() not in segment.read_text()
    for entry in ledger:
        if entry.event['event_type'] == 'mio.route.terminal':
            TerminalEvent(entry.event['terminal_event'])
    return [entry.event for entry in ledger]


def test_local_selected_records_real_readiness_without_claiming_an_answer(
    setup_router, tmp_path, monkeypatch,
):
    monkeypatch.setattr(model_runtime, 'RUNTIMES', {
        'fixture': model_runtime.RuntimeBinary(
            runtime_id='fixture', executable='/usr/libexec/azazel/az-runtime',
            version='1', digest='sha256:' + '0' * 64,
            argv=('/usr/libexec/azazel/az-runtime',),
        ),
    })
    (tmp_path / 'test-model.model').write_bytes(b'GGUF' + b'\x00' * 4096)
    reserve = CoreReserve(
        profile=ResourceProfile.STANDARD, reserve_mib=512,
        host_digest='sha256:' + '0' * 64, harness_version='fixture',
        sample_count=64, duration_seconds=3600,
    )
    router, calls = setup_router()
    router._local = LocalRuntimeService(
        staging=tmp_path, reserve=reserve, admitted=lambda model_id: True,
    )
    result = invoke(router, local=True)
    recorded = events(router)
    assert result.selection.route is Route.LOCAL
    assert recorded[0]['candidates'][0]['reason']
    assert any(e['event_type'] == 'mio.local.readiness' and e['readiness'] == 'ready' for e in recorded)
    assert result.reply['readiness'] == 'ready'
    assert result.route is Route.LOCAL
    assert result.outcome is RequestOutcome.REFUSED
    assert recorded[-1]['terminal_event'] == TerminalEvent.NO_ANSWER.value
    assert recorded[-1]['reason'] == 'local_ready_no_answer'
    assert recorded[-1]['fallback_available'] is False
    assert not any(e['event_type'] == 'mio.route.fallback' for e in recorded)
    assert calls == []


def test_remote_answer_has_provenance_transport_and_terminal(setup_router):
    router, calls = setup_router()
    result = invoke(router)
    recorded = events(router)
    assert result.outcome is RequestOutcome.ANSWERED
    assert result.selection.route is Route.REMOTE
    assert calls == ['remote']
    assert [e['event_type'] for e in recorded] == [
        'mio.route.selected', 'mio.remote.envelope.opened',
        'mio.remote.transport.attempt', 'mio.remote.response', 'mio.route.terminal',
    ]
    assert recorded[1]['content_digest'].startswith('sha256:')
    assert recorded[1]['provider_id']
    assert recorded[3]['response_digest'].startswith('sha256:')
    assert recorded[-1]['terminal_event'] == TerminalEvent.ANSWERED.value


def test_timeout_records_one_fallback_and_no_retry(setup_router):
    router, calls = setup_router(TransportOutcome.TIMED_OUT)
    result = invoke(router)
    recorded = events(router)
    assert calls == ['remote']
    assert result.route is Route.LOCAL
    assert result.outcome is RequestOutcome.REFUSED
    fallbacks = [e for e in recorded if e['event_type'] == 'mio.route.fallback']
    assert len(fallbacks) == 1
    assert fallbacks[0]['reason'] and fallbacks[0]['spent']
    assert any(e.get('terminal_event') == TerminalEvent.TIMED_OUT.value for e in recorded)
    assert any(e.get('outcome') == 'timed_out' and e.get('reason') for e in recorded)


def test_mismatch_records_exact_refusal_and_does_not_send(setup_router):
    router, calls = setup_router()
    result = invoke(router, mismatch=True)
    recorded = events(router)
    assert calls == []
    assert result.outcome is RequestOutcome.REFUSED
    refusal = next(e for e in recorded if e['event_type'] == 'mio.remote.refused')
    assert refusal['refusal'] == 'content_mismatch'
    assert refusal['reason']
    assert recorded[-1]['terminal_event'] == TerminalEvent.SANITIZER_FAILED.value
    assert not any(e['event_type'] == 'mio.route.fallback' for e in recorded)


def test_unwritable_ledger_dispatches_nothing(setup_router, monkeypatch, tmp_path):
    router, calls = setup_router()
    blocked = tmp_path / 'blocked'
    blocked.write_text('file, not directory')
    router.ledger = AuditLedger(blocked / 'route.jsonl')
    monkeypatch.setattr(router._local, 'handle', lambda request: pytest.fail('local dispatched'))
    with pytest.raises(AuditUnavailable):
        invoke(router)
    assert calls == []


@pytest.mark.parametrize(('reply', 'expected'), [
    ({'outcome': 'tls_failed'}, TerminalEvent.TLS_FAILED),
    ({'outcome': 'not_advice'}, TerminalEvent.NOT_ADVICE),
    ({'outcome': 'interrupted'}, TerminalEvent.FAILED),
])
def test_terminal_mapping_never_promotes_non_advice(reply, expected):
    assert mio_router.terminal_for(reply) is expected


def test_envelope_audit_failure_stops_transport(setup_router, monkeypatch):
    router, calls = setup_router()
    append = router.ledger.append

    def record(event):
        if event['event_type'] == 'mio.remote.envelope.opened':
            raise AuditUnavailable('fixture envelope append failure')
        return append(event)

    monkeypatch.setattr(router.ledger, 'append', record)
    with pytest.raises(AuditUnavailable):
        invoke(router)
    assert calls == []
    assert len(events(router)) == 1


def test_fallback_audit_failure_stops_local_dispatch(setup_router, monkeypatch):
    router, calls = setup_router(TransportOutcome.TIMED_OUT)
    append = router.ledger.append

    def record(event):
        if event['event_type'] == 'mio.route.fallback':
            raise AuditUnavailable('fixture fallback append failure')
        return append(event)

    monkeypatch.setattr(router.ledger, 'append', record)
    monkeypatch.setattr(router._local, 'handle', lambda request: pytest.fail('local dispatched'))
    with pytest.raises(AuditUnavailable):
        invoke(router)
    assert calls == ['remote']
    assert not any(e['event_type'] == 'mio.local.readiness' for e in events(router))


@pytest.mark.parametrize('remote_outcome', [TransportOutcome.RECEIVED, TransportOutcome.TIMED_OUT])
def test_real_local_refusal_falls_back_to_remote_once(setup_router, remote_outcome):
    router, calls = setup_router(remote_outcome)
    result = invoke(router, local=True)
    recorded = events(router)
    readiness = next(e for e in recorded if e['event_type'] == 'mio.local.readiness')
    assert readiness['readiness'] == 'refused'
    assert 'Core reserve is unmeasured' in readiness['reason']
    assert Route.REMOTE in result.selection.permitted
    assert result.route is Route.REMOTE
    assert calls == ['remote']
    fallbacks = [e for e in recorded if e['event_type'] == 'mio.route.fallback']
    assert len(fallbacks) == 1
    assert fallbacks[0]['failed_route'] == Route.LOCAL.value
    assert readiness['reason'] in fallbacks[0]['reason']
    assert recorded[-1]['fallback_available'] is False


@pytest.mark.parametrize('privacy_class', [PrivacyClass.P2_MISSION, PrivacyClass.P3_RESTRICTED])
def test_real_local_refusal_cannot_fall_back_to_forbidden_remote(setup_router, privacy_class):
    router, calls = setup_router()
    result = invoke(router, local=True, privacy_class=privacy_class)
    recorded = events(router)
    assert result.selection.route is Route.LOCAL
    assert Route.REMOTE not in result.selection.permitted
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.outcome is RequestOutcome.REFUSED
    assert calls == []
    fallback = next(e for e in recorded if e['event_type'] == 'mio.route.fallback')
    assert 'Core reserve is unmeasured' in fallback['reason']


@pytest.mark.parametrize(('readiness', 'reason'), [
    ('not_assessed', 'local_not_assessed_no_answer'),
    ('unknown', 'local_unknown_readiness_no_answer'),
])
def test_local_without_a_failure_does_not_trigger_remote(setup_router, monkeypatch, readiness, reason):
    router, calls = setup_router()
    monkeypatch.setattr(router._local, 'handle', lambda request: {
        'readiness': readiness, 'reason': 'fixture assessment absent',
    })
    result = invoke(router, local=True)
    recorded = events(router)
    assert result.outcome is RequestOutcome.REFUSED
    assert recorded[-1]['terminal_event'] == TerminalEvent.NO_ANSWER.value
    assert recorded[-1]['reason'] == reason
    assert recorded[-1]['fallback_available'] is False
    assert not any(e['event_type'] == 'mio.route.fallback' for e in recorded)
    assert calls == []


@pytest.mark.parametrize('payload', [
    {SENTINEL.decode(): 'caller key'},
    {'frame': SENTINEL.decode() + '!', 'envelope': ''},
    {'frame': 'é' + SENTINEL.decode(), 'envelope': ''},
])
def test_malformed_payload_audits_only_fixed_reason(setup_router, payload):
    router, calls = setup_router()
    request = Request(frame=SENTINEL, envelope=_seal(frame=SENTINEL))
    request.payload = payload
    result = invoke(router, remote_request=request)
    recorded = events(router)
    assert calls == []
    assert result.outcome is RequestOutcome.REFUSED
    assert result.reply['reason'] == 'malformed_payload'
    refusal = next(e for e in recorded if e['event_type'] == 'mio.remote.refused')
    assert refusal['refusal'] == refusal['reason'] == 'malformed_payload'


def test_no_answer_terminal_audit_failure_propagates(setup_router, monkeypatch):
    router, calls = setup_router()
    monkeypatch.setattr(router._local, 'handle', lambda request: {
        'readiness': 'not_assessed', 'reason': 'fixture assessment absent',
    })
    append = router.ledger.append

    def record(event):
        if event['event_type'] == 'mio.route.terminal':
            raise AuditUnavailable('fixture terminal append failure')
        return append(event)

    monkeypatch.setattr(router.ledger, 'append', record)
    with pytest.raises(AuditUnavailable):
        invoke(router, local=True)
    assert calls == []
    assert not any(e['event_type'] == 'mio.route.fallback' for e in events(router))
