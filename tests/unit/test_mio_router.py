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
    local_admitted=True, **extra,
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
        local_admitted=local_admitted,
        local_refusal='fixture local admitted' if local_admitted else 'fixture local not admitted',
        predictions={
            route: Prediction(route.value, True, ms, 10, 10, False, 'fixture observations')
            for route, ms in [(Route.LOCAL, 1 if local else 20), (Route.REMOTE, 10)]
        },
        deadline_ms=1000,
        **extra,
    )


def local_terminal(recorded):
    return next(e for e in recorded if e['event_type'] == 'mio.route.terminal'
                and e['route'] == Route.LOCAL.value)


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
    # Readiness is no answer: the request ends in the deterministic handoff,
    # with the local attempt's own terminal record kept.
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.outcome is RequestOutcome.REFUSED
    assert result.ai_attempts == 1
    assert result.failures == ({'route': 'local', 'terminal_event': 'no answer',
                                'refusal': 'local_ready_no_answer'},)
    local = local_terminal(recorded)
    assert local['terminal_event'] == TerminalEvent.NO_ANSWER.value
    assert local['reason'] == 'local_ready_no_answer'
    assert local['fallback_available'] is False
    assert recorded[-1]['route'] == Route.DETERMINISTIC_HANDOFF.value
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
    # Both AI routes failed; the terminal step is the deterministic handoff.
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.outcome is RequestOutcome.REFUSED
    assert result.ai_attempts == 2
    assert [f['route'] for f in result.failures] == ['remote', 'local']
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
    remote = next(e for e in recorded if e['event_type'] == 'mio.route.terminal'
                  and e['route'] == Route.REMOTE.value)
    assert remote['terminal_event'] == TerminalEvent.SANITIZER_FAILED.value
    # No fallback and no other AI: the handoff ends it.
    assert not any(e['event_type'] == 'mio.route.fallback' for e in recorded)
    assert result.route is Route.DETERMINISTIC_HANDOFF and result.ai_attempts == 1


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
    # Answered by the fallback, or -- when it timed out too -- handed to the
    # deterministic path. Never a third attempt.
    expected = (Route.REMOTE if remote_outcome is TransportOutcome.RECEIVED
                else Route.DETERMINISTIC_HANDOFF)
    assert result.route is expected
    assert calls == ['remote']
    fallbacks = [e for e in recorded if e['event_type'] == 'mio.route.fallback']
    assert len(fallbacks) == 1
    assert fallbacks[0]['failed_route'] == Route.LOCAL.value
    assert readiness['reason'] in fallbacks[0]['reason']
    remote = next(e for e in recorded if e['event_type'] == 'mio.route.terminal'
                  and e['route'] == Route.REMOTE.value)
    assert remote['fallback_available'] is False


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
    local = local_terminal(recorded)
    assert local['terminal_event'] == TerminalEvent.NO_ANSWER.value
    assert local['reason'] == reason
    assert local['fallback_available'] is False
    assert not any(e['event_type'] == 'mio.route.fallback' for e in recorded)
    assert result.route is Route.DETERMINISTIC_HANDOFF
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
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.failures[0]['refusal'] == 'malformed_payload'
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


# -- Remote permission rechecked after selection (mock providers) -------------

WITHDRAWN = RemoteAdmission(False, Exclusion.CONSENT, 'fixture consent withdrawn')
PERMITTED = RemoteAdmission(True, None, 'fixture permitted')


class Recheck:
    """Counts its calls; each call returns (or raises) the next scripted answer."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0

    def __call__(self):
        self.calls += 1
        answer = self.answers[min(self.calls, len(self.answers)) - 1]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def remote_terminal(recorded):
    return next(e for e in recorded if e['event_type'] == 'mio.route.terminal'
                and e['route'] == Route.REMOTE.value)


def test_permitted_recheck_keeps_remote_answer(setup_router):
    router, calls = setup_router()
    recheck = Recheck(PERMITTED)
    result = invoke(router, remote_recheck=recheck)
    assert result.outcome is RequestOutcome.ANSWERED and result.route is Route.REMOTE
    assert calls == ['remote']
    # Asked once, just before the attempt; an answer needs no fallback.
    assert recheck.calls == 1
    assert not any(e.get('terminal_event') == TerminalEvent.OPT_IN_WITHDRAWN.value
                   for e in events(router))


def test_withdrawal_after_selection_skips_remote_and_falls_back_to_local_once(
    setup_router, monkeypatch,
):
    router, calls = setup_router()
    local_calls = []

    def local(request):
        local_calls.append(request)
        return {'outcome': 'advisory', 'refusal': None, 'advice': 'safe', 'fields': {}}

    monkeypatch.setattr(router._local, 'handle', local)
    recheck = Recheck(WITHDRAWN)
    result = invoke(router, remote_recheck=recheck)
    recorded = events(router)
    assert result.selection.route is Route.REMOTE
    assert calls == []
    assert len(local_calls) == 1
    assert result.route is Route.LOCAL and result.outcome is RequestOutcome.ANSWERED
    # The withdrawal is no attempt and no failure, and nothing else was sent.
    assert result.ai_attempts == 1 and result.failures == ()
    remote = remote_terminal(recorded)
    assert remote['terminal_event'] == TerminalEvent.OPT_IN_WITHDRAWN.value
    assert remote['outcome'] == RequestOutcome.FELL_BACK.value
    assert remote['reason'] == mio_router.REMOTE_WITHDRAWN
    assert not any(e['event_type'].startswith('mio.remote.') for e in recorded)
    fallbacks = [e for e in recorded if e['event_type'] == 'mio.route.fallback']
    assert [(f['failed_route'], f['route'], f['spent']) for f in fallbacks] == [
        (Route.REMOTE.value, Route.LOCAL.value, True)]


def test_withdrawal_then_local_failure_is_not_a_second_fallback(setup_router):
    # The real local service refuses (Core reserve unmeasured). The withdrawal
    # spent the one fallback, so the local failure ends in the handoff and
    # the withdrawn remote is never tried in its place.
    router, calls = setup_router()
    recheck = Recheck(WITHDRAWN, PERMITTED)
    result = invoke(router, remote_recheck=recheck)
    recorded = events(router)
    assert calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.outcome is RequestOutcome.REFUSED
    assert result.ai_attempts == 1
    assert [f['route'] for f in result.failures] == ['local']
    assert local_terminal(recorded)['fallback_available'] is False
    assert len([e for e in recorded if e['event_type'] == 'mio.route.fallback']) == 1
    assert remote_terminal(recorded)['terminal_event'] == TerminalEvent.OPT_IN_WITHDRAWN.value


def test_withdrawal_without_local_is_refused(setup_router, monkeypatch):
    router, calls = setup_router()
    monkeypatch.setattr(router._local, 'handle', lambda request: pytest.fail('local dispatched'))
    recheck = Recheck(WITHDRAWN)
    result = invoke(router, local_admitted=False, remote_recheck=recheck)
    recorded = events(router)
    assert result.selection.route is Route.REMOTE
    assert Route.LOCAL not in result.selection.permitted
    assert calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert result.outcome is RequestOutcome.REFUSED
    assert result.ai_attempts == 0
    remote = remote_terminal(recorded)
    assert remote['terminal_event'] == TerminalEvent.OPT_IN_WITHDRAWN.value
    assert remote['outcome'] == RequestOutcome.REFUSED.value
    assert remote['fallback_available'] is False
    assert not any(e['event_type'] == 'mio.route.fallback' for e in recorded)
    handoff = next(e for e in recorded if e['event_type'] == 'mio.route.handoff')
    assert handoff['cause'] == mio_router.REMOTE_WITHDRAWN


@pytest.mark.parametrize('answer', [
    RuntimeError('fixture recheck failure ' + SENTINEL.decode()),
    None,
    True,
    SimpleNamespace(permitted=True, excluded_by=None, reason='duck-typed'),
    RemoteAdmission(1, None, 'truthy but not True'),
])
def test_recheck_that_cannot_be_read_excludes_remote(setup_router, answer):
    router, calls = setup_router()
    result = invoke(router, local_admitted=False, remote_recheck=Recheck(answer))
    recorded = events(router)  # also asserts the sentinel is never recorded
    assert calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF
    remote = remote_terminal(recorded)
    assert remote['terminal_event'] == TerminalEvent.OPT_IN_WITHDRAWN.value
    assert remote['reason'] in {mio_router.REMOTE_RECHECK_FAILED, mio_router.REMOTE_WITHDRAWN}


@pytest.mark.parametrize('privacy_class', [PrivacyClass.P2_MISSION, PrivacyClass.P3_RESTRICTED])
def test_recheck_never_widens_the_permitted_set(setup_router, privacy_class):
    # Remote was excluded at selection; a recheck answering "permitted" is not
    # even asked, and the local refusal's fallback still cannot reach remote.
    router, calls = setup_router()
    recheck = Recheck(PERMITTED)
    result = invoke(router, local=True, privacy_class=privacy_class, remote_recheck=recheck)
    recorded = events(router)
    assert Route.REMOTE not in result.selection.permitted
    assert recheck.calls == 0
    assert calls == []
    assert result.route is Route.DETERMINISTIC_HANDOFF
    fallback = next(e for e in recorded if e['event_type'] == 'mio.route.fallback')
    assert fallback['route'] == Route.DETERMINISTIC_HANDOFF.value


def test_narrowing_helpers_never_return_a_route_outside_the_selection(setup_router):
    router, _ = setup_router()
    result = invoke(router, local=True, privacy_class=PrivacyClass.P3_RESTRICTED)
    selection = result.selection
    assert Route.REMOTE not in selection.permitted
    for recheck in (None, Recheck(PERMITTED), Recheck(WITHDRAWN), Recheck(RuntimeError())):
        assert router._remote_recheck(selection, recheck) is not None
        for failed in (Route.LOCAL, Route.REMOTE):
            narrowed = router._still_permitted(selection, failed, recheck)
            assert set(narrowed) <= set(selection.permitted)
            assert Route.DETERMINISTIC_HANDOFF in narrowed


def test_withdrawal_at_local_fallback_lands_on_handoff(setup_router):
    # Local selected and refused; remote was permitted at selection but is
    # withdrawn when the fallback is chosen, so the fallback does not reach it.
    router, calls = setup_router()
    recheck = Recheck(WITHDRAWN)
    result = invoke(router, local=True, remote_recheck=recheck)
    recorded = events(router)
    assert result.selection.route is Route.LOCAL
    assert Route.REMOTE in result.selection.permitted
    assert calls == []
    assert recheck.calls == 1
    fallback = next(e for e in recorded if e['event_type'] == 'mio.route.fallback')
    assert fallback['failed_route'] == Route.LOCAL.value
    assert fallback['route'] == Route.DETERMINISTIC_HANDOFF.value
    assert result.route is Route.DETERMINISTIC_HANDOFF
    handoff = next(e for e in recorded if e['event_type'] == 'mio.route.handoff')
    assert handoff['cause'] == 'no_permitted_fallback'


def test_withdrawal_between_fallback_and_attempt_refuses(setup_router):
    # Permitted when the fallback chose remote, withdrawn just before the
    # attempt: not sent, and no further fallback (it was spent).
    router, calls = setup_router()
    recheck = Recheck(PERMITTED, WITHDRAWN)
    result = invoke(router, local=True, remote_recheck=recheck)
    recorded = events(router)
    assert recheck.calls == 2
    assert calls == []
    remote = remote_terminal(recorded)
    assert remote['terminal_event'] == TerminalEvent.OPT_IN_WITHDRAWN.value
    assert remote['outcome'] == RequestOutcome.REFUSED.value
    assert result.route is Route.DETERMINISTIC_HANDOFF
    assert len([e for e in recorded if e['event_type'] == 'mio.route.fallback']) == 1


def test_permitted_recheck_at_local_fallback_keeps_remote_fallback(setup_router):
    router, calls = setup_router()
    recheck = Recheck(PERMITTED)
    result = invoke(router, local=True, remote_recheck=recheck)
    assert calls == ['remote']
    assert result.route is Route.REMOTE and result.outcome is RequestOutcome.ANSWERED
    # Once at the fallback, once before the attempt.
    assert recheck.calls == 2
