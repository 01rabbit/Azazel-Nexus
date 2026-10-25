"""Drive Nexus consumer policy, integration reporting and durable audit for SO-06.

Evidence records and the audit chain come from the real consumer loop in
`tools.so06_loop`. With `--edge-core`, every run also executes the real
observe-only Edge Core on a pinned clock (`tools.so06_edge`): its forwarded
observations are `evaluation_outcomes` and are what the loop's intake reads.
Paths that need Edge execution and are not executed are explicitly not_driven
and cannot pass.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from azazel_nexus import degradation, integration
from azazel_nexus.audit import AuditLedger, canonical_event_bytes
from azazel_nexus.capability import CORE_CAPABILITIES
from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState
from tools import so06_edge, so06_loop
from tools.service_objectives import (
    CASES,
    PATHS,
    RULES,
    SCHEMA,
    digest,
    replay_samples,
    require,
    validate_record,
)

# Independent acceptance oracle: a changed production mapping must fail.
EXPECTED = {
    "absent": "not_configured",
    "refusing": "refused",
    "hanging": "deadline_exceeded",
    "corrupt": "quarantined",
    "expired": "stale",
}
BUDGET_MS = 10
INPUT_SCHEMA = "azazel-nexus/so06-input/v3"
EVIDENCE_SOURCE = (
    "golden fixture replay: tests/fixtures/edge/rust_event_engine_v1.jsonl lines 4 and 6, "
    "hand-derived Edge observations; Edge is not executed"
)
EDGE_EVIDENCE_SOURCE = (
    "real observe-only Edge Core binary, run once per case on fresh state with the "
    "shipped unit environment, on tools.e2e_loop.eve_events(); its CLOCK_REALTIME is "
    f"pinned to {so06_edge.PINNED_EPOCH} by a harness-only preload library; the "
    "forwarded observations are evaluation_outcomes and the intake's input"
)
NOT_DRIVEN = {
    "evaluation_outcomes": (
        "Edge's evaluator is not executed here: no --edge-core binary was supplied, the "
        "observations are the hand-derived golden fixture, and Nexus records Edge's "
        "decision without evaluating"
    ),
    "enforcement_lease_records": (
        "the shipped Edge Core is observe-only (ENFORCE=false, DRY_RUN=true) and intake "
        "refuses any other posture (EDGE_NOT_OBSERVE_ONLY); nothing issues an enforcement "
        "lease until Azazel-Edge#412 declares the single enforcement path"
    ),
}


class FaultClock:
    """Virtual dependency time, separate from measured CLOCK_MONOTONIC time."""

    def __init__(self):
        self.ms = 0

    def __call__(self):
        return self.ms


def observe_fault(mode: str, clock: FaultClock) -> degradation.FailureMode:
    """Inject boundary responses; the harness, not the callee, owns timeout.

    A pending response advances virtual time beyond budget. No hung callable,
    sleep, network, or assertion supplied by a runner is trusted.
    """

    def boundary_response():
        if mode == "hanging":
            clock.ms += BUDGET_MS + 1
        return {
            "absent": None,
            "refusing": {"accepted": False},
            "hanging": {"accepted": True},
            "corrupt": b"invalid-json",
            "expired": {"accepted": True, "expires_ms": -1},
        }[mode]

    try:
        response = degradation.call_with_deadline(
            boundary_response,
            budget_ms=BUDGET_MS,
            clock=clock,
        )
    except degradation.DeadlineExceeded:
        return degradation.FailureMode.HANGING
    if response is None:
        return degradation.FailureMode.ABSENT
    if isinstance(response, bytes):
        try:
            json.loads(response)
        except ValueError:
            return degradation.FailureMode.CORRUPT
    if not response["accepted"]:
        return degradation.FailureMode.REFUSING
    if response.get("expires_ms", clock()) < clock():
        return degradation.FailureMode.EXPIRED
    raise ValueError("fault injection unexpectedly returned a healthy response")


def edge_observations(edge: tuple[Path, Path]) -> list[bytes]:
    """One fresh run of the real Edge Core; `edge` is (binary, pinned-clock shim).

    The shim is required: a wall-clock Edge run is for the mutation check only
    and is never captured as SO-06 evidence.
    """
    from tools.e2e_loop import eve_events

    binary, shim = edge
    if not isinstance(shim, Path):
        raise so06_edge.EdgeUnavailable("SO-06 runs Edge only on the pinned clock")
    events = eve_events()
    return so06_edge.run_edge(binary, events, shim=shim,
                              expected=sum(e["event_type"] == "alert" for e in events))


def nexus_adapter(events: list, case: str,
                  edge: tuple[Path, Path] | None = None) -> dict:
    """Execute real Nexus modules afresh, without fabricating Edge outputs."""
    failures = {}
    mode = None
    if case != "healthy":
        dependency, mode = case.split("/")
        failures[dependency] = observe_fault(mode, FaultClock())
    outcome = degradation.assess(
        CORE_CAPABILITIES
        | {
            "extended_knowledge",
            "full_host_redirect",
            "remote_cognition",
            "local_cognition",
        },
        failures,
    )
    view = integration.build_view(
        capability=outcome.state,
        knowledge=None,
        decoy=None,
        cognition=CognitionReading(
            state=CognitionState.CORE_ONLY,
            remote=RemoteState.UNAVAILABLE if failures else RemoteState.DISABLED,
            resource_reason="no measured reserve",
            topology_reason="replay boundary",
            asset_reason="no model",
            trust_health_reason="no provider",
        ),
        edge=integration.EdgePresence.ABSENT,
        knowledge_peer="extended_knowledge" in outcome.retained,
        deception_peer="full_host_redirect" in outcome.retained,
    )
    paths = {path: [] for path in PATHS}
    with tempfile.TemporaryDirectory(prefix="azso06-") as temporary:
        ledger = AuditLedger(Path(temporary) / "audit.jsonl")
        for event in events:
            ledger.append(event)
        lines = edge_observations(edge) if edge else None
        # The explainer forwards incident transitions into the same ledger.
        loop = so06_loop.run_loop(case, audit=ledger.append, lines=lines)
        ledger.verify()
        if lines is not None:
            paths["evaluation_outcomes"] = [json.loads(line) for line in lines]
        paths["evidence_records"] = loop["evidence_records"]
        paths["audit_chain"] = [
            {
                "sequence": e.sequence,
                "previous_hash": e.previous_hash,
                "event_hash": e.event_hash,
                "event": dict(e.event),
            }
            for e in ledger
        ]
    retained = sorted(CORE_CAPABILITIES & set(outcome.retained))
    disposition = outcome.reasons[0].disposition.value if failures else "healthy"
    continues = list(view.row("capability").continues)
    expected = (
        set(retained) == CORE_CAPABILITIES
        and set(integration.NEXUS_ALWAYS) <= set(continues)
        and disposition == (EXPECTED[mode] if mode else "healthy")
        and not view.enforcement_capable
        and (view.row("knowledge_supplier").value == "AZ-04 peer")
        == ("extended_knowledge" in outcome.retained)
        and (view.row("deception_supplier").value == "AZ-06 peer")
        == ("full_host_redirect" in outcome.retained)
        and loop["expected_behaviour"]
    )
    return {
        "paths": paths,
        "observed": {
            "core_retained": retained,
            "disposition": disposition,
            "continues": continues,
            "expected_behaviour": expected,
            "integration_rows": [row.as_event() for row in view.rows],
            "consumer_loop": loop["observed"],
        },
        "not_driven": {k: v for k, v in NOT_DRIVEN.items()
                       if not (edge and k == "evaluation_outcomes")},
    }


def capture_replays(
    scenarios: list[dict],
    *,
    clock: Callable[[], int] = time.monotonic_ns,
    edge_core: Path | None = None,
) -> dict:
    """Measure each real adapter invocation; arbitrary runners are unsupported.

    `edge_core` executes that Edge binary in every run, on the pinned clock.
    """
    with tempfile.TemporaryDirectory(prefix="azso06s-") as temporary:
        edge = None
        if edge_core is not None:
            edge = (edge_core, so06_edge.build_shim(Path(temporary)))
        return _capture(scenarios, clock, edge)


def _capture(scenarios, clock, edge) -> dict:
    captured = []
    for scenario in scenarios:
        inputs = scenario["inputs"]
        expected_digest = digest(inputs)
        runs = {}
        for case in CASES:
            copied_inputs = json.loads(canonical_event_bytes(inputs))
            start = clock()
            observation = nexus_adapter(copied_inputs, case, edge)
            end = clock()
            require(digest(copied_inputs) == expected_digest, "adapter mutated inputs")
            runs[case] = {
                "inputs_sha256": expected_digest,
                "start_ns": start,
                "end_ns": end,
                **observation,
            }
        captured.append({"id": scenario["id"], "inputs": inputs, "runs": runs})
    bundle = {"schema": INPUT_SCHEMA,
              "evidence_source": EDGE_EVIDENCE_SOURCE if edge else EVIDENCE_SOURCE,
              "scenarios": captured}
    replay_samples(bundle)
    return bundle


def replay(bundle: dict, *, commit: str, product_configuration: str) -> dict:
    samples = replay_samples(bundle)
    failed = sum(not sample["passed"] for sample in samples)
    record = {
        "schema": SCHEMA,
        "objective_id": "SO-06",
        "owner_repository": "Azazel-Nexus",
        "owner_commit": commit,
        "class": "software",
        "clock": "CLOCK_MONOTONIC",
        "configuration": {
            "product_configuration": product_configuration,
            "scope": "nexus-in-repo-adapter",
            "replay_inputs": bundle,
        },
        "samples": samples,
        "pass_rule": RULES["SO-06"],
        "evaluation": {"comparisons": len(samples), "failed_comparisons": failed},
        # An execution result is not an attested gate verdict.
        "execution_result": "FAIL" if failed else "PASS",
    }
    require(validate_record(record) == "shape_only", "unexpected validation status")
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--configuration", required=True)
    parser.add_argument("--edge-core", type=Path,
                        help="built azazel-edge-core binary to execute on a pinned clock "
                             "(test tooling only; Linux and a C compiler)")
    args = parser.parse_args(argv)
    try:
        source = json.loads(args.inputs.read_text())
        record = replay(
            capture_replays(source["scenarios"], edge_core=args.edge_core),
            commit=args.commit,
            product_configuration=args.configuration,
        )
        args.output.write_bytes(canonical_event_bytes(record) + b"\n")
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        parser.exit(2, f"replay refused: {exc}\n")
    return 0 if record["execution_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
