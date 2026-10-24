"""SO-06 consumer loop: one fault, real Nexus intake, evidence and audit code.

Golden Edge observations go through the real `IntakeServer` (socket, closed
parsing, evidence store, incident ledger) and the real `Explainer` (incident
chain, M.I.O. and Knowledge clients, audit forwarding) into a durable
`AuditLedger`. One external dependency is faulted at the only boundary this
loop calls for it:

- Deception: the decoy intake socket of the same `IntakeServer`.
- Knowledge: `knowledge.lookup` behind the production `lookup_context` client.
- Remote cognition: `mio.advise`, the only way the loop reaches cognition.

Only the socket transport under the two clients is replaced, because the real
one verifies service accounts this harness does not have. Their deadline
argument, error classification and reply validation run unchanged. Nothing
here executes Edge: the observations are the hand-derived golden fixture, so
this drives Nexus's consumer paths and never Edge's evaluator.
"""

from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
from collections import Counter
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from azazel_nexus.decoy_interaction import build_interaction
from azazel_nexus.incident_explain import read_record

#: One fixed clock for intake and explainer, so separate runs can be compared
#: byte for byte. Wall time would differ between any two runs.
FIXED_NOW = 1_790_000_000.0
#: Peer identities seen through the intake's `peer_uid` seam.
EDGE_UID, DECOY_UID = 61001, 61002
#: The intake's own read deadline for Edge and decoy connections.
READ_DEADLINE_S = 0.3
WAIT_S = 5
DEPENDENCY_BOUNDARY = {
    "knowledge_node_absent": "knowledge-read",
    "remote_path_unreachable": "mio-advise",
}
BOUNDARY_PEERS = {
    "knowledge-read": ("azknowledge", "knowledge.lookup"),
    "mio-advise": ("azmioentry", "mio.advise"),
}
KNOWLEDGE_REF = {
    "technique_id": "T1110", "name": "Brute Force",
    "summary": "Repeated authentication attempts.", "claim_id": "T1110",
    "bundle_digest": "sha256:" + "1" * 64, "freshness": "static",
    "source_kind": "knowledge_lite", "generation": 1, "trust_check": "verified",
}

# Independent oracle of what each fault must look like where it is consumed.
# A changed production mapping must fail expected_behaviour, not pass.
EXPECTED_KNOWLEDGE = {
    "healthy": ("available", []),
    "absent": ("unavailable", ["knowledge_unavailable"]),
    "refusing": ("unavailable", ["knowledge_unavailable"]),
    "hanging": ("unavailable", ["knowledge_unavailable"]),
    "corrupt": ("unavailable", ["knowledge_reply_refused"]),
    "expired": ("no_context", []),
}
EXPECTED_MIO = {
    "healthy": ("deterministic handoff", "answered", ["mio_handoff"]),
    "absent": ("unavailable", "unavailable", ["mio_unavailable"]),
    "refusing": ("unavailable", "unavailable", ["mio_unavailable"]),
    "hanging": ("unavailable", "unavailable", ["mio_unavailable"]),
    "corrupt": ("unavailable", "unavailable", ["mio_reply_refused"]),
    "expired": ("deterministic handoff", "fell back", ["mio_handoff"]),
}
#: Decoy intake state: (listening, accepted, refusal code or None).
EXPECTED_DECOY = {
    "healthy": (True, 1, None),
    "absent": (False, 0, None),
    "refusing": (True, 0, "DECOY_SHAPE"),
    "hanging": (True, 0, "decoy_read_deadline"),
    "corrupt": (True, 0, "DECOY_JSON"),
    "expired": (True, 0, "DECOY_CLOCK"),
}


def golden_lines() -> list[bytes]:
    from tools.e2e_loop import golden_lines as lines

    return lines()


def handoff(outcome="answered", reason="no admitted model") -> dict:
    return {"route": "deterministic handoff", "outcome": outcome, "reason": reason,
            "ledger_seq": 1, "reference_status": "unavailable"}


class Boundary:
    """The socket exchange under the production clients, one leaf faulted.

    `hanging` is a reply still pending when the caller's own `deadline_s`
    passes, on harness-owned virtual time: the client sees the timeout its
    socket would raise. This is not a test of socket timeouts.
    """

    def __init__(self, leaf: str | None, mode: str | None):
        self.leaf, self.mode = leaf, mode
        self.calls = Counter()
        self.unexpected = 0
        self.virtual_s = 0.0

    def __call__(self, leaf, account, verb, arguments, *, payload=None, deadline_s=0.5):
        if (BOUNDARY_PEERS.get(leaf) != (account, verb)
                or type(deadline_s) not in {int, float} or not 0 < deadline_s <= 60):
            self.unexpected += 1
            raise ValueError("unexpected boundary")
        self.calls[leaf] += 1
        mode = self.mode if leaf == self.leaf else "healthy"
        if mode == "absent":
            raise FileNotFoundError("no socket at the declared path")
        if mode == "refusing":
            from azazel_nexus_runtime.mio_socket_client import ServiceRefused

            raise ServiceRefused("principal_denied")
        if mode == "hanging":
            self.virtual_s += deadline_s + 0.001
            raise TimeoutError("timed out")
        if leaf == "knowledge-read":
            wanted = set(arguments["technique_ids"])
            refs = [KNOWLEDGE_REF] if KNOWLEDGE_REF["technique_id"] in wanted else []
            return {
                "healthy": {"refs": refs, "reason_code": "available" if refs else "no_context"},
                "corrupt": {"refs": [{"technique_id": "T1110"}], "reason_code": "available"},
                # Rows past their expiry are not served (lite_import.iter_served).
                "expired": {"refs": [], "reason_code": "no_context"},
            }[mode]
        return {
            "healthy": handoff(),
            "corrupt": {"route": "remote", "outcome": "answered", "reason": "x",
                        "ledger_seq": 1},
            "expired": handoff("fell back", "remote envelope expired"),
        }[mode]


def _iso(instant: float) -> str:
    return datetime.fromtimestamp(instant, UTC).isoformat().replace("+00:00", "Z")


def _connect(path: Path) -> socket.socket:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    client.connect(str(path))
    return client


def _send(path: Path, data: bytes) -> None:
    with _connect(path) as client:
        client.sendall(data)


def _wait(predicate, what: str) -> None:
    until = time.monotonic() + WAIT_S
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.01)
    raise RuntimeError(f"consumer loop did not reach: {what}")


def _decoy_fault(server, mode: str, stack: ExitStack) -> None:
    """What the decoy does at its only Nexus boundary, before Edge sends."""
    path = server.decoy_path
    if mode == "healthy":
        _send(path, _interaction(FIXED_NOW))
    elif mode == "refusing":
        _connect(path).close()  # declines to report: no line at all
    elif mode == "hanging":
        stack.enter_context(_connect(path)).sendall(b'{"schema":')  # never completes
    elif mode == "corrupt":
        _send(path, b"{not json\n")
    elif mode == "expired":
        _send(path, _interaction(FIXED_NOW - 3600))


def _interaction(observed: float) -> bytes:
    return build_interaction(decoy_name="ssh-decoy", bytes_received=12, truncated=False,
                             responder="ssh-banner", observed_at=_iso(observed)).line


def _decoy_settled(server, mode: str):
    listening, accepted, code = EXPECTED_DECOY[mode]
    if not listening:
        return lambda: True
    if code is None:
        return lambda: server.decoy_accepted >= accepted
    return lambda: server.refused[code] >= 1


def _records(directory: Path) -> list[dict]:
    return [json.loads(line) for path in sorted(directory.glob("*.jsonl"))
            for line in path.read_bytes().splitlines()]


def run_loop(case: str, audit) -> dict:
    """Run intake then the explainer once; `audit` receives forwarded events."""
    from azazel_nexus_runtime import edge_intaked, incident_explaind, knowledge_client

    dependency, mode = case.split("/") if case != "healthy" else (None, None)
    decoy_mode = mode if dependency == "deception_node_absent" else "healthy"
    leaf = DEPENDENCY_BOUNDARY.get(dependency)
    boundary = Boundary(leaf, mode)
    base = Path("/tmp") if Path("/tmp").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="azso06-", dir=base) as temporary, ExitStack() as stack:
        root = Path(temporary)
        state, incidents = root / "intake", root / "edge-incidents"
        state.mkdir()
        incidents.mkdir()
        explainer = incident_explaind.Explainer(
            incidents=incidents, state=root / "explain", status_path=root / "explain.json",
            clock=lambda: FIXED_NOW, monotonic=lambda: 0, audit=audit)
        explainer.prepare()  # before intake writes, as the running daemon is
        decoy_path = root / "decoy.sock" if decoy_mode != "absent" else None
        server = edge_intaked.IntakeServer(
            path=root / "edge.sock", state=state, status_path=root / "intake.json",
            edge_uid=EDGE_UID, incident_root=incidents, clock=lambda: FIXED_NOW,
            read_deadline=READ_DEADLINE_S, decoy_path=decoy_path,
            decoy_uid=DECOY_UID if decoy_path else None,
            peer_uid=lambda c: DECOY_UID if c.getsockname() == str(decoy_path) else EDGE_UID)
        stop, ready, errors = threading.Event(), threading.Event(), []

        def serve():
            try:
                errors.append(server.serve(stop=stop.is_set, ready=ready.set))
            except BaseException as exc:  # noqa: BLE001 - reported below, never passes
                errors.append(exc)
                ready.set()

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            if not ready.wait(WAIT_S) or errors:
                raise RuntimeError(f"intake did not start: {errors}")
            with ExitStack() as held:
                _decoy_fault(server, decoy_mode, held)
                lines = golden_lines()
                for line in lines:
                    _send(server.path, line + b"\n")
                _wait(lambda: server.processed == len(lines), "Edge observations processed")
                _wait(_decoy_settled(server, decoy_mode), "decoy outcome")
                # Read while serving: the listener closes at shutdown.
                decoy = {"listening": server.decoy_listening,
                         "accepted": server.decoy_accepted}
        finally:
            stop.set()
            thread.join(WAIT_S)
        if thread.is_alive() or errors != [0]:
            raise RuntimeError(f"intake did not stop cleanly: {errors}")
        with mock.patch.object(knowledge_client, "_exchange", boundary), \
                mock.patch.object(incident_explaind, "_exchange", boundary):
            explainer.poll()
        halt = threading.Event()
        worker = threading.Thread(target=explainer.forward_audit, args=(halt,))
        worker.start()
        _wait(lambda: explainer.audit_pending.unfinished_tasks == 0, "audit forwarded")
        halt.set()
        worker.join(WAIT_S)
        evidence = _records(state / "evidence")
        explanations = [read_record(r) for r in _records(root / "explain" / "explanations")]
        intake = server.snapshot()
        return {
            "evidence_records": evidence,
            "observed": {
                "intake": {k: intake[k] for k in ("accepted", "processed", "storage_failed")}
                | {"refused": dict(sorted(intake["refused"].items()))},
                "decoy": decoy,
                "explanations": [
                    {"transition": r["transition"], "edge_would": r["edge_would"],
                     "knowledge_state": r["knowledge_state"],
                     "mio": [r["mio"]["route"], r["mio"]["outcome"]],
                     "failure_codes": r["failure_codes"]}
                    for r in explanations
                ],
                "boundary_calls": dict(sorted(boundary.calls.items())),
                "unexpected_boundary_calls": boundary.unexpected,
                "audit_forward": [explainer.audit_forward_dropped,
                                  explainer.audit_forward_refused],
            },
            "expected_behaviour": _expected(dependency, mode, len(lines), intake, decoy,
                                            explanations, boundary, explainer),
        }


def _expected(dependency, mode, sent, intake, decoy_state, explanations, boundary,
              explainer) -> bool:
    """The fault reached its boundary, had its declared effect, and only that."""
    knowledge = mode if dependency == "knowledge_node_absent" else "healthy"
    mio = mode if dependency == "remote_path_unreachable" else "healthy"
    decoy = mode if dependency == "deception_node_absent" else "healthy"
    listening, accepted, code = EXPECTED_DECOY[decoy]
    edge_refused = {k: v for k, v in intake["refused"].items()
                    if v and not k.startswith(("DECOY_", "decoy_"))}
    k_state, k_codes = EXPECTED_KNOWLEDGE[knowledge]
    m_route, m_outcome, m_codes = EXPECTED_MIO[mio]
    return (
        intake["accepted"] == intake["processed"] == sent
        and not intake["storage_failed"] and not edge_refused
        and decoy_state == {"listening": listening, "accepted": accepted}
        and (code is None or intake["refused"].get(code) == 1)
        and len(explanations) == sent
        and all(r["knowledge_state"] == k_state
                and [r["mio"]["route"], r["mio"]["outcome"]] == [m_route, m_outcome]
                and sorted(r["failure_codes"]) == sorted(k_codes + m_codes)
                for r in explanations)
        and boundary.calls == Counter({"knowledge-read": sent, "mio-advise": sent})
        and boundary.unexpected == 0
        and (explainer.audit_forward_dropped, explainer.audit_forward_refused) == (0, 0)
    )
