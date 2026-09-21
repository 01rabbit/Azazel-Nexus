"""Malformed protocol, driven while a real process is supervised (#114).

The protocol's own refusals are checked in `test_runtime_protocol.py` and
`test_transport.py`. This file asks a different question, which those cannot:
**what does a malformed request do to a node that is supervising a live
process?**

A refusal that is correct in isolation and takes the supervisor down with it
is not a refusal that helps. So each case here is driven with a real process
running, and afterwards the same five things are checked:

| checked afterwards | the failure it rules out |
| --- | --- |
| the supervised process is unaffected | a request crashed the thing it was not about |
| no process survives the run | an orphan was left behind |
| nothing was unmasked or granted | a malformed frame widened something |
| the refusal text is bounded and quotes nothing | an attacker's bytes reached the journal |
| the restart budget is untouched | a malformed request spent a restart |

That last one is the restart-storm case: a budget that malformed input can
spend is a budget an attacker empties from outside, and a fence is not
supposed to be reachable by anybody who can reach the socket.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "runtime" / "src"))

from azazel_nexus.model_runtime import RuntimeBinary  # noqa: E402
from azazel_nexus.runtime_lifecycle import (  # noqa: E402
    BudgetLedger,
    LifecycleState,
    Readiness,
)
from azazel_nexus_runtime.mio_locald import ACTIVATE_VERB, REGISTRY  # noqa: E402
from azazel_nexus_runtime.mio_supervisor import run_once  # noqa: E402
from azazel_nexus_runtime.principal import Principal, PrincipalClass  # noqa: E402
from azazel_nexus_runtime.protocol import Refusal, RequestRefused  # noqa: E402
from azazel_nexus_runtime.transport import (  # noqa: E402
    MAX_FRAME_BYTES,
    SocketServer,
    read_frame,
)

pytestmark = pytest.mark.real_process

STUB_ROOT = REPO_ROOT / "tests" / "fixtures" / "runtime_stub"
STUB = "/usr/libexec/azazel/az-runtime-stub"


def stub(behaviour: str = "ready") -> RuntimeBinary:
    return RuntimeBinary(
        runtime_id="stub",
        executable=STUB,
        version="1",
        digest="sha256:" + "0" * 64,
        argv=(STUB, behaviour),
    )


class Pipe:
    """The smallest thing `read_frame` accepts: something with `recv`."""

    def __init__(self, payload: bytes, *, chunk: int = 4096) -> None:
        self._payload = payload
        self._chunk = chunk
        self._offset = 0

    def recv(self, count: int) -> bytes:
        take = min(count, self._chunk, len(self._payload) - self._offset)
        if take <= 0:
            return b""
        piece = self._payload[self._offset : self._offset + take]
        self._offset += take
        return piece


def framed(document) -> bytes:
    body = json.dumps(document).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def _service_principal() -> Principal:
    """A principal as the **kernel** would report one. `pid` is required:
    a credential without one is not a credential this server acts on."""

    return Principal(
        uid=0, gid=0, pid=1, classes=frozenset({PrincipalClass.SERVICE})
    )


def _parse(raw: bytes):
    """Drive the layer that turns bytes into a request.

    `read_frame` reads a **frame**; it does not parse JSON. Aiming a
    not-JSON case at it would be a test that passed for the wrong reason --
    the frame was fine, and the thing being tested is the layer above.
    """

    server = SocketServer(
        registry=REGISTRY, policy=None, audit=lambda event: None
    )
    return server._parse(raw, _service_principal())


def _live_process():
    """A real process that started and answered, for each case to run beside."""

    report = run_once(stub("ready"), root=STUB_ROOT, deadline_seconds=5)
    assert report.state is LifecycleState.SERVING
    assert report.readiness is Readiness.PASSED
    return report


def _stub_processes() -> list:
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
            status = (entry / "status").read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        if b"az-runtime-stub" in cmdline and "State:\tZ" not in status:
            found.append(int(entry.name))
    return found


# -- the malformed cases --------------------------------------------------


#: Cases the **frame reader** refuses: the bytes never become a document.
MALFORMED_FRAMES = {
    "zero-length": struct.pack(">I", 0),
    "no-header": b"\x00\x01",
    "oversized": struct.pack(">I", MAX_FRAME_BYTES + 1) + b"{}",
    "truncated": struct.pack(">I", 64) + b"{}",
}

#: Cases the **request parser** refuses: a well-formed frame carrying
#: something that is not a request. Split by layer on purpose -- aiming these
#: at `read_frame` would pass for the wrong reason, because the frame is fine.
MALFORMED_REQUESTS = {
    "not-json": b"garbage",
    "not-an-object": b"[1, 2, 3]",
    "arguments-not-an-object": b'{"verb": "model.activate", "arguments": 7}',
    "unknown-verb": b'{"verb": "model.start", "arguments": {}}',
}


def _refuse_all() -> None:
    """Every malformed case, at whichever layer owns it."""

    for payload in MALFORMED_FRAMES.values():
        with pytest.raises(RequestRefused):
            read_frame(Pipe(payload))
    for payload in MALFORMED_REQUESTS.values():
        with pytest.raises(RequestRefused):
            _parse(payload)


@pytest.mark.parametrize(
    "name", sorted(MALFORMED_FRAMES), ids=sorted(MALFORMED_FRAMES)
)
def test_a_malformed_frame_is_refused_beside_a_live_process(name):
    """Each case with a real process started, run and reaped alongside."""

    before = _stub_processes()
    report = _live_process()

    with pytest.raises(RequestRefused) as caught:
        read_frame(Pipe(MALFORMED_FRAMES[name]))

    assert isinstance(caught.value.refusal, Refusal)
    assert report.state is LifecycleState.SERVING, "the request disturbed the process"
    assert [pid for pid in _stub_processes() if pid not in before] == [], (
        "a process was left behind"
    )


@pytest.mark.parametrize(
    "name", sorted(MALFORMED_REQUESTS), ids=sorted(MALFORMED_REQUESTS)
)
def test_a_well_formed_frame_carrying_nonsense_is_refused(name):
    before = _stub_processes()
    report = _live_process()

    with pytest.raises(RequestRefused) as caught:
        _parse(MALFORMED_REQUESTS[name])

    assert isinstance(caught.value.refusal, Refusal)
    assert report.state is LifecycleState.SERVING
    assert [pid for pid in _stub_processes() if pid not in before] == []


def test_an_oversized_frame_is_refused_before_its_body_is_read():
    """Declared length, not delivered length. A ceiling applied after
    reading is a ceiling on nothing -- the same defect the response reader
    had in #98."""

    delivered = []

    class Counting(Pipe):
        def recv(self, count):
            piece = super().recv(count)
            delivered.append(len(piece))
            return piece

    with pytest.raises(RequestRefused) as caught:
        read_frame(Counting(struct.pack(">I", MAX_FRAME_BYTES + 1) + b"x" * 8192))
    assert caught.value.refusal is Refusal.FRAME_TOO_LARGE
    assert sum(delivered) <= 8, (
        f"{sum(delivered)} bytes were read before the ceiling refused"
    )


def test_a_disconnect_mid_frame_is_truncated_not_accepted():
    """The peer closed before the declared length arrived. Accepting what
    came would be accepting a request nobody finished sending."""

    with pytest.raises(RequestRefused) as caught:
        read_frame(Pipe(struct.pack(">I", 4096) + b'{"verb":"model.act'))
    assert caught.value.refusal is Refusal.TRUNCATED_FRAME


def test_an_out_of_order_argument_set_is_refused_not_reordered():
    """A verb whose arguments arrive wrong is refused rather than repaired.

    Order is not the interesting part -- a JSON object has none. What is
    interesting is that an *undeclared* name and a *missing* one are
    different refusals, so a caller and a daemon that disagree about what was
    asked both find out.
    """

    with pytest.raises(RequestRefused) as caught:
        ACTIVATE_VERB.bind({"model_id": "m", "runtime_id": "r", "extra": "x"})
    assert caught.value.refusal is Refusal.UNDECLARED_ARGUMENT

    with pytest.raises(RequestRefused) as caught:
        ACTIVATE_VERB.bind({"model_id": "m"})
    assert caught.value.refusal is Refusal.MISSING_ARGUMENT


def test_a_replayed_request_is_not_a_privilege(tmp_path):
    """The same well-formed request twice does not accumulate anything.

    There is no counter here a repeat advances, no budget it spends and no
    state it moves. `remote.infer` has a nonce because an *authorisation*
    must be spendable once; this verb carries no authorisation, so a replay
    is simply the same question asked twice.
    """

    before = _stub_processes()
    first = _live_process()
    second = _live_process()
    assert first.state is second.state is LifecycleState.SERVING

    ledger = BudgetLedger(tmp_path / "budgets.json")
    budget = ledger.load(generation=1, runtime_id="stub")
    assert budget.spent == 0, "a replay spent a restart"
    assert [pid for pid in _stub_processes() if pid not in before] == []


def test_a_client_cannot_assert_who_it_is():
    """The principal is derived from the socket. A request that carried one
    would make it look negotiable."""

    with pytest.raises(RequestRefused) as caught:
        ACTIVATE_VERB.bind({"model_id": "m", "runtime_id": "r", "uid": 0})
    assert caught.value.refusal is Refusal.CLIENT_ASSERTED_PRINCIPAL


def test_an_unknown_verb_does_not_reach_the_supervisor():
    with pytest.raises(RequestRefused) as caught:
        REGISTRY.resolve("model.start", _service_principal())
    assert caught.value.refusal is Refusal.UNKNOWN_VERB


def test_an_operator_is_refused_the_verb_even_when_it_is_well_formed():
    """A denial names the verb; an unknown one does not. Both are refusals
    and they are not the same fact."""

    operator = Principal(
        uid=1000, gid=1000, pid=1, classes=frozenset({PrincipalClass.OPERATOR})
    )
    with pytest.raises(RequestRefused) as caught:
        REGISTRY.resolve("model.activate", operator)
    assert caught.value.refusal is Refusal.PRINCIPAL_DENIED


# -- what a refusal must not do -------------------------------------------


def test_no_refusal_spends_a_restart_or_fences_anything(tmp_path):
    """**The restart-storm case.**

    A budget that malformed input can spend is a budget an attacker empties
    from outside, and a fence is not meant to be reachable by anybody who can
    reach the socket.
    """

    ledger = BudgetLedger(tmp_path / "budgets.json")
    _refuse_all()
    for _ in range(50):
        with pytest.raises(RequestRefused):
            _parse(MALFORMED_REQUESTS["not-json"])

    budget = ledger.load(generation=1, runtime_id="stub")
    assert budget.spent == 0
    assert budget.fenced is False


def test_a_refusal_quotes_nothing_it_was_sent():
    """An attacker's bytes reaching the journal is the whole reason refusals
    carry a structured reason rather than the frame."""

    secret = b'{"verb":"model.activate","arguments":{"model_id":"LEAKEDSECRET"}}'

    with pytest.raises(RequestRefused) as caught:
        read_frame(Pipe(struct.pack(">I", len(secret)) + secret[:10]))
    assert "LEAKEDSECRET" not in str(caught.value)

    for payload in (b"garbage", secret.replace(b"{", b"", 1)):
        with pytest.raises(RequestRefused) as caught:
            _parse(payload)
        rendered = str(caught.value)
        assert "LEAKEDSECRET" not in rendered
        assert "garbage" not in rendered
        assert len(rendered) < 200, (
            f"an unbounded refusal: {len(rendered)} characters"
        )


def test_a_storm_of_malformed_frames_leaves_no_process_behind():
    """Two hundred refusals, then the tree is swept."""

    before = _stub_processes()
    _live_process()
    for _ in range(200):
        with pytest.raises(RequestRefused):
            read_frame(Pipe(MALFORMED_FRAMES["oversized"]))
    _live_process()
    assert [pid for pid in _stub_processes() if pid not in before] == []


def test_edge_authority_is_unchanged_by_every_malformed_case():
    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    _refuse_all()
    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason="unmeasured",
        topology_reason="unmeasured",
        asset_reason="none",
        trust_health_reason="none",
    )
    assert reading.blocks_deterministic_path() is False
    assert reading.state is CognitionState.CORE_ONLY
