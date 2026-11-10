"""Unit 30: wall-clock rollback at the ordinary product entry (isolated container).

The clock is injected only through the product's own `utc_now` parameter of the
broker's KnowledgeClient (U30_CLOCK_FILE offset in the broker harness process);
the host clock is not changed and no verification step is bypassed. The producer
signs with its real clock. Entry: service account -> real broker socket -> real
KnowledgeClient -> mTLS -> synthetic producer; the replay hook makes the network
edge return a previously captured envelope for a NEW request.

Results are observations for this single-host model, not a safety proof.
"""
from __future__ import annotations

import json
import signal
from datetime import UTC, datetime, timedelta

import pytest

from test_knowledge_context_linux_acceptance import (  # noqa: F401  (stack is a fixture)
    QUESTION, Stack, _binding_control, _doc, _end_replay, _envelope_times,
    _fresh_capture, _ok_response, _refused, _restart_broker_with_replay, _window, stack,
)


def _set_offset(stack: Stack, seconds: float) -> None:
    (stack.tmp / "clock.offset").write_text(str(seconds))


def _offset_for(stack: Stack, target: datetime) -> float:
    return (target - datetime.now(UTC)).total_seconds()


@pytest.fixture(autouse=True)
def _clock_env(stack: Stack):
    stack.env["U30_CLOCK_FILE"] = str(stack.tmp / "clock.offset")
    _set_offset(stack, 0)
    stack.stop_broker()
    stack.start_broker()          # broker reads the clock file at every call
    yield
    _set_offset(stack, 0)


def test_clock_cases_1_to_3_at_the_service_entry(stack: Stack):
    """Cases 1-3: new request with an old response; expiry; rollback."""
    rid1, req1, env1 = _fresh_capture(stack)
    low, high, _doc1 = _window(env1)
    life = (high - low).total_seconds()
    assert life < 240, "registry window in the harness is 5 minutes; keep the offset inside it"

    # Forward clock past the window: the live response of a new request is expired.
    _set_offset(stack, life + 20)
    marks = len(stack.exchanges())
    assert _refused(stack.as_service()) == "unavailable"
    notes = sorted(stack.exchange.glob("*.postfail.note"))
    print("U30-OBS forward-clock layer", len(stack.exchanges()) - marks, [n.read_text() for n in notes])
    # Observed: with the broker clock ahead the producer refuses over HTTP before any
    # envelope exists (the layer is the producer's own request check; its exact reason
    # is not exposed to Nexus). Envelope expiry itself is covered by D1 and by the
    # replay case below.
    assert len(stack.exchanges()) == marks and notes and "KnowledgeRefused" in notes[-1].read_text()
    assert stack.audit_events()[-1]["outcome"] == "unavailable"

    # Roll back: a new request is served again (no permanent refusal, no state).
    _set_offset(stack, 0)
    rid2, req2, env2 = _fresh_capture(stack)
    assert rid2 != rid1 and env2 != env1

    # Case 1 + 3: roll the clock back INTO env1's window and make the network edge
    # offer env1 for a new request. The old envelope is time-valid again; it is
    # refused only by request binding. Control: accepted for its own request.
    _set_offset(stack, _offset_for(stack, low + (high - low) / 2))
    stack.stop_broker()
    stack.replay.write_bytes(env1)
    stack.start_broker(replay=True)
    try:
        before = len(stack.exchanges())
        assert _refused(stack.as_service()) == "unavailable"
        rows = stack.exchanges()
        assert rows[-1][1] == "replayed" and rows[-1][3] == env1 and len(rows) == before + 1
        new_rid = json.loads(rows[-1][2])["request_id"]
        assert new_rid not in (rid1, rid2)
        _binding_control(stack, req1, env1, rows[-1][2])
        assert not any(e.get("outcome") == "verified_advisory" for e in stack.audit_events()[-2:])
    finally:
        _end_replay(stack)


def test_clock_case_2_same_request_cannot_be_resubmitted_through_the_entry(stack: Stack):
    """Case 2: the entry accepts no request_id, response or envelope from a caller."""
    rid1, _, _ = _fresh_capture(stack)
    rid2, _, _ = _fresh_capture(stack)
    assert rid1 != rid2                                   # identical frame, new random id
    marks = len(stack.exchanges())
    for extra in ({"request_id": rid1}, {"envelope": "00"}, {"correlation_id": rid1}):
        frame = {"privacy_class": "P0-public", "question": QUESTION, **extra}
        assert _refused(stack.as_service(_doc(frame=frame))) == "unavailable"
    assert len(stack.exchanges()) == marks                # producer never reached


def test_clock_case_4_nothing_is_stored_or_re_read_by_the_context_path(stack: Stack):
    """Case 4 (server side): the broker keeps only metadata in its audit ledger."""
    _fresh_capture(stack)
    context = [e for e in stack.audit_events()
               if str(e.get("event_type", "")).startswith("knowledge.context.")
               and "uid" not in e]
    assert context
    for event in context:
        assert set(event) <= {"event_type", "outcome", "response_bytes", "elapsed_ms"}, event
    text = stack.audit.read_text()
    assert "request_id" not in text and "claims" not in text and "signature" not in text


def test_clock_case_5_restart_with_rolled_back_clock(stack: Stack):
    """Case 5: broker killed and restarted while the clock is rolled back."""
    rid1, req1, env1 = _fresh_capture(stack)
    low, high, _ = _window(env1)
    _set_offset(stack, _offset_for(stack, low + (high - low) / 2))
    _restart_broker_with_replay(stack, env1, signal.SIGKILL)
    try:
        assert _refused(stack.as_service()) == "unavailable"
        rows = stack.exchanges()
        assert rows[-1][1] == "replayed"
        assert json.loads(rows[-1][2])["request_id"] != rid1
    finally:
        _end_replay(stack)
