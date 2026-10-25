"""Drive Nexus consumer policy, integration reporting and durable audit for SO-06.

Evidence records and the audit chain come from the real consumer loop in
`tools.so06_loop`. With `--edge-core`, every run also executes the real
observe-only Edge Core on a pinned clock (`tools.so06_edge`): its forwarded
observations are `evaluation_outcomes` and are what the loop's intake reads.
With `--lease-netns` as well, every run also executes the same binary enforcing,
inside a network namespace the harness creates (`tools.so06_lease`); the
release ledger it writes is `enforcement_lease_records`. Paths that need Edge
execution and are not executed are explicitly not_driven and cannot pass.
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
from tools import so06_edge, so06_lease, so06_loop
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
LEASE_EVIDENCE_SOURCE = EDGE_EVIDENCE_SOURCE + (
    "; the same binary is run a second time per case, enforcing (enforce on, dry run "
    "off, full-auto) only inside a harness-created network namespace with a dummy "
    "interface and an empty azazel_edge table, on the same pinned clock; its release "
    "ledger tasks are enforcement_lease_records, and its observations, which the "
    "intake refuses (EDGE_NOT_OBSERVE_ONLY), are not evidence"
)
NOT_DRIVEN = {
    "evaluation_outcomes": (
        "Edge's evaluator is not executed here: no --edge-core binary was supplied, the "
        "observations are the hand-derived golden fixture, and Nexus records Edge's "
        "decision without evaluating"
    ),
    "enforcement_lease_records": (
        "the shipped Edge Core is observe-only (ENFORCE=false, DRY_RUN=true) and intake "
        "refuses any other posture (EDGE_NOT_OBSERVE_ONLY), so no lease is issued in the "
        "consumer loop; an enforcing Edge in a harness network namespace was not run "
        "(needs --edge-core and --lease-netns, as root with CAP_NET_ADMIN)"
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


def edge_observations(edge: tuple) -> list[bytes]:
    """One fresh run of the real Edge Core; `edge` is (binary, pinned-clock shim, lease).

    The shim is required: a wall-clock Edge run is for the mutation check only
    and is never captured as SO-06 evidence.
    """
    from tools.e2e_loop import eve_events

    binary, shim = edge[:2]
    if not isinstance(shim, Path):
        raise so06_edge.EdgeUnavailable("SO-06 runs Edge only on the pinned clock")
    events = eve_events()
    return so06_edge.run_edge(binary, events, shim=shim,
                              expected=sum(e["event_type"] == "alert" for e in events))


def edge_lease(edge: tuple) -> dict:
    """One fresh enforcing run of the same binary in its own network namespace.

    The same pinned-clock requirement; the run's observations are only checked
    (the intake must refuse them), never fed to the loop.
    """
    from tools.e2e_loop import eve_events

    binary, shim = edge[:2]
    if not isinstance(shim, Path):
        raise so06_edge.EdgeUnavailable("SO-06 runs Edge only on the pinned clock")
    events = eve_events()
    return so06_lease.run_lease(binary, events, shim=shim,
                                expected=sum(e["event_type"] == "alert" for e in events))


def nexus_adapter(events: list, case: str, edge: tuple | None = None) -> dict:
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
        lease = edge_lease(edge) if edge and edge[2] else None
        # The explainer forwards incident transitions into the same ledger.
        loop = so06_loop.run_loop(case, audit=ledger.append, lines=lines)
        ledger.verify()
        if lines is not None:
            paths["evaluation_outcomes"] = [json.loads(line) for line in lines]
        if lease is not None:
            paths["enforcement_lease_records"] = lease["tasks"]
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
        and (lease is None or so06_lease.lease_expected(lease))
    )
    observed_lease = {} if lease is None else {
        "lease": {"states": so06_lease.lease_states(lease["tasks"]),
                  "intake_refused": so06_lease.refused_by_intake(lease["observations"])}}
    return {
        "paths": paths,
        "observed": {
            "core_retained": retained,
            "disposition": disposition,
            "continues": continues,
            "expected_behaviour": expected,
            "integration_rows": [row.as_event() for row in view.rows],
            "consumer_loop": loop["observed"],
            **observed_lease,
        },
        "not_driven": {k: v for k, v in NOT_DRIVEN.items()
                       if not (edge and k == "evaluation_outcomes")
                       and not (lease is not None and k == "enforcement_lease_records")},
    }


def capture_replays(
    scenarios: list[dict],
    *,
    clock: Callable[[], int] = time.monotonic_ns,
    edge_core: Path | None = None,
    lease_netns: bool = False,
) -> dict:
    """Measure each real adapter invocation; arbitrary runners are unsupported.

    `edge_core` executes that Edge binary in every run, on the pinned clock.
    `lease_netns` also runs it enforcing in a harness network namespace; it
    needs `edge_core`, and a host that cannot provide the namespace refuses.
    """
    if lease_netns and edge_core is None:
        raise so06_edge.EdgeUnavailable("--lease-netns needs --edge-core")
    with tempfile.TemporaryDirectory(prefix="azso06s-") as temporary:
        edge = None
        if edge_core is not None:
            edge = (edge_core, so06_edge.build_shim(Path(temporary)), lease_netns)
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
              "evidence_source": (LEASE_EVIDENCE_SOURCE if edge and edge[2]
                                  else EDGE_EVIDENCE_SOURCE if edge else EVIDENCE_SOURCE),
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
    parser.add_argument("--lease-netns", action="store_true",
                        help="also run that binary enforcing inside a network namespace this "
                             "harness creates, to drive enforcement_lease_records (test "
                             "tooling only; root, CAP_NET_ADMIN, ip and nft)")
    args = parser.parse_args(argv)
    try:
        source = json.loads(args.inputs.read_text())
        record = replay(
            capture_replays(source["scenarios"], edge_core=args.edge_core,
                            lease_netns=args.lease_netns),
            commit=args.commit,
            product_configuration=args.configuration,
        )
        args.output.write_bytes(canonical_event_bytes(record) + b"\n")
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        parser.exit(2, f"replay refused: {exc}\n")
    return 0 if record["execution_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
