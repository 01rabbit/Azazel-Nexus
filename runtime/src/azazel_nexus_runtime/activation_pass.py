"""The observe-baseline inputs of one activation pass (#206 phases P4 and P5).

`docs/activation-observe-baseline.md` §3.6. After the controller's preflight
remask, this collects, in order: full commissioning evidence; the
independent context (declared node cross-checked against the administrator
deployment declaration, the activation policy, the high-water floors and
clock, the current generation verified as an observe-baseline tree against
the unit files **as installed now**, the evidence binding and the declared
epoch); the v2 approval verified against that context; and node health.

Each producer is a fixed reader passed in as a callable so that tests can
substitute in-memory fixtures; production uses `production_producers()`.
Every failure is a fixed status label: no exception text, identity or digest
leaves this module. The result is all-or-nothing: unless **every** producer
verified, the pass gets `lease=None` and `healthy=False`, exactly as before
P4. A complete result is still only an input; the library decides per unit,
and a lease can only narrow.

Phase P4 wired SUPPORTING. Phase P5 admits `azazel-edge-core.service`
(EDGE_BASELINE) into the same pass, but never into the all-or-nothing set:
Edge evidence only decides whether the library may launch the Edge package,
so a failure there withholds edge-core (`edge_not_ready`) and leaves the
SUPPORTING units to the rest of the decision. Two things bind it:

* **the package the operator signed.** When the policy names edge-core, the
  generation's `edge_pin.package_digest` is compared with the installed
  package digest this pass derives (`edge_package.installed_package_digest`:
  the on-disk package checks), and `edge_pin.components` with the extracted
  binary and redirect policy the unit actually uses, re-measured now
  (`edge_package.measure_extracted_components`). Readable and different -- a
  self-consistent package other than the signed one, or an extracted file
  rewritten after publication -- means the signed baseline no longer
  describes this node, and the generation is refused like a changed unit
  file: everything is withheld. Unreadable (a failing package check, an
  absent, linked or unprotected component) binds nothing; the tree is then
  verified against its own pin, so the SUPPORTING units can still be
  granted, and edge-core is withheld;
* **this boot's health.** `edge_package.installed_baseline_state` reads the
  boot preflight's probe result (contract v2), which supplies health only
  when it names this boot, is within its TTL and describes the installed
  package. `running` is not required to launch. The probe's package digest
  must also equal the signed pin; otherwise `digest_matches` is reported
  False here and the library withholds edge-core.

Neither half adds an authority: the lease, the policy scope and node health
still decide every grant; Edge evidence can only narrow it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from azazel_nexus.activation import ActivationLease, EdgeBaselineState
from azazel_nexus.activation_approval_v2 import (
    ActivationApprovalPolicy,
    ObserveBaselineApproval,
    ObserveBaselineContext,
)
from azazel_nexus.activation_policy import ActivationPolicy
from azazel_nexus.bootstrap_approval import parse_bootstrap_time
from azazel_nexus.bootstrap_deployment import BootstrapDeployment, declared_node_binding
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.edge_package import bound_to_signed_package, nothing_established
from azazel_nexus.generation import Generation
from azazel_nexus.observe_baseline import (
    EDGE_CORE_UNIT,
    OBSERVE_BASELINE_FILE,
    decode_observe_baseline,
    evidence_commissioning_digest,
    verify_observe_baseline,
)

from .activation_high_water import HighWater
from .activation_markers import GRANTABLE_UNITS
from .node_config import DeclaredNode

__all__ = [
    "ALWAYS_MISSING",
    "EDGE_EVIDENCE",
    "PRODUCERS",
    "UNIT_SCOPE",
    "PassInputs",
    "PassProducers",
    "collect_pass_inputs",
    "production_producers",
    "raised_high_water",
    "staged_inputs",
]

#: The units a pass may grant: the five SUPPORTING loop units (§6.2, P4) and
#: edge-core (P5). The same object as the tripwire's and the marker writer's.
UNIT_SCOPE = GRANTABLE_UNITS

#: The producers this pass runs, as named in `missing_producers`.
PRODUCERS = (
    "authenticated_commissioning",
    "inventory_binding",
    "node_identity",
    "activation_policy",
    "epoch_high_water",
    "trusted_clock",
    "operational_generation_publisher",
    "systemd_loaded_units",
    "activation_approval_loader",
    "node_health",
)
#: Not required for the observe baseline (§2) or not built yet; always named.
ALWAYS_MISSING = (
    "authoritative_commissioning_admission",
    "renderer_measurement",
)
#: Named after them unless edge-core is in scope and its evidence is
#: launchable and bound to the signed package. Never part of `complete`:
#: Edge evidence withholds edge-core only, never the SUPPORTING units.
EDGE_EVIDENCE = "edge_evidence"

_TIME = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class PassProducers:
    """The fixed readers behind one pass. Production: `production_producers()`."""

    commissioning_evidence: Callable[[], CommissioningEvidence]
    declared_node: Callable[[], DeclaredNode]
    deployment: Callable[[], BootstrapDeployment]
    policy: Callable[[], ActivationPolicy]
    #: `require_high_water_for_pass`: None for a node with no floor at all.
    high_water: Callable[[], Optional[HighWater]]
    #: `measure_scoped_unit_files`: the scoped units' vendor file bytes,
    #: measured now and refused on any override or drop-in.
    unit_files: Callable[[list], dict]
    #: `activation_loaded_units.verify_grantable_units` over every grantable
    #: unit and the controller's D-Bus session: each file waits for its
    #: marker, the manager is a reviewed profile and each unit is not loaded,
    #: masked, or loaded as declared; raises otherwise.
    loaded_units: Callable[[list], None]
    #: `load_observe_baseline_approval` (keyword arguments).
    approval: Callable[..., ObserveBaselineApproval]
    #: `(policy, ledger) -> (healthy, findings)`.
    health: Callable
    #: `raise_high_water` (value, keyword `now` and `skew_seconds`).
    raise_high_water: Callable[..., HighWater]
    #: `edge_package.installed_package_digest`: the installed archive digest,
    #: only when the on-disk package checks pass; raises otherwise.
    edge_package_digest: Callable[[], str]
    #: `edge_package.installed_baseline_state` (keyword `now`): the five
    #: checks, health and running only from this boot's fresh probe result.
    edge_state: Callable[..., EdgeBaselineState]
    #: `edge_package.measure_extracted_components`: the SHA-256 of the
    #: extracted binary and redirect policy the unit uses, as they are now;
    #: raises when unreadable or unprotected.
    edge_components: Callable[[], dict]


@dataclass
class PassInputs:
    """What the pass may hand the library, plus fixed status labels."""

    evidence: Optional[CommissioningEvidence] = None
    lease: Optional[ActivationLease] = None
    healthy: bool = False
    status: dict = field(default_factory=dict)
    health_findings: tuple = ()
    approval: Optional[ObserveBaselineApproval] = None
    high_water: Optional[HighWater] = None
    generation: Optional[int] = None
    skew_seconds: Optional[int] = None
    #: The Edge state handed to the library (None: no lease was formed).
    edge: Optional[EdgeBaselineState] = None
    #: Fixed labels: `not_attempted`, `not_in_scope`, `bound` (installed
    #: digest equals the signed pin) or `package_refused` (no digest).
    edge_package_binding: str = "not_attempted"
    #: Fixed labels: `not_attempted`, `not_in_scope`, `launchable` or
    #: `not_launchable` (with the failed launch checks in `edge_missing`).
    edge_evidence: str = "not_attempted"
    edge_missing: tuple = ()

    @property
    def complete(self) -> bool:
        return all(self.status.get(name) == "verified" for name in PRODUCERS)

    def missing(self) -> list[str]:
        """Only the producers that failed (or were not collected), plus the unbuilt.

        `edge_evidence` is named unless edge-core is in scope with launchable,
        bound evidence; it never makes the pass incomplete.
        """
        failed = [name for name in PRODUCERS
                  if self.status.get(name) in ("failed", "not_collected_staged_root")]
        edge = [] if self.edge_evidence == "launchable" else [EDGE_EVIDENCE]
        return list(ALWAYS_MISSING) + edge + failed


def staged_inputs() -> PassInputs:
    """A relocated root reads no host producer; everything stays missing."""
    return PassInputs(status={name: "not_collected_staged_root" for name in PRODUCERS})


class _Refused(Exception):
    pass


def _utc(instant: datetime) -> str:
    return instant.astimezone(timezone.utc).strftime(_TIME)


def raised_high_water(inputs: PassInputs, *, now: str) -> HighWater:
    """The floors after a verified approval: each field the max, never lower.

    `time_floor` is `max(stored, now)`; with `now` from the same clock read
    the pass checked, it is at most `now + skew` by construction.
    """
    current, approval = inputs.high_water, inputs.approval
    if (type(current) is not HighWater or type(approval) is not ObserveBaselineApproval
            or type(inputs.generation) is not int):
        raise _Refused("verified approval and floors required")
    floor = max(parse_bootstrap_time(current.time_floor), parse_bootstrap_time(now))
    return HighWater(
        security_epoch=max(current.security_epoch, approval.security_epoch),
        approval_seq=max(current.approval_seq, approval.approval_seq),
        generation=max(current.generation, inputs.generation),
        time_floor=_utc(floor),
    )


def collect_pass_inputs(*, producers: PassProducers, generations, ledger, now: str) -> PassInputs:
    """Run every producer once, in §3.6 order; refuse as a whole on any failure."""
    result = PassInputs(status={name: "not_attempted" for name in PRODUCERS})
    status = result.status

    def attempt(names, operation):
        try:
            value = operation()
        except Exception:  # noqa: BLE001 - a failed producer is a fixed label
            for name in names:
                status[name] = "failed"
            return None
        for name in names:
            status[name] = "verified"
        return value

    def fail(name):
        status[name] = "failed"

    # 1. Full commissioning evidence (re-verified, current inventory bound).
    def evidence():
        value = producers.commissioning_evidence()
        if type(value) is not CommissioningEvidence:
            raise _Refused("commissioning evidence required")
        return value
    result.evidence = attempt(("authenticated_commissioning", "inventory_binding"), evidence)

    # 2. Node identity and declared epoch: the protected node label, hashed,
    #    must equal the administrator deployment declaration's digest.
    def node():
        declared, deployment = producers.declared_node(), producers.deployment()
        if type(declared) is not DeclaredNode or type(deployment) is not BootstrapDeployment:
            raise _Refused("declared node and deployment required")
        # The same function az-activation request and install use.
        return declared_node_binding(deployment, declared.node_id), deployment.security_epoch
    identity = attempt(("node_identity",), node)

    # 3. Activation policy: the five SUPPORTING units and edge-core at most.
    def policy():
        value = producers.policy()
        if type(value) is not ActivationPolicy:
            raise _Refused("activation policy required")
        if not set(value.units) <= UNIT_SCOPE:
            raise _Refused("policy scope outside the grantable units")
        return value
    active_policy = attempt(("activation_policy",), policy)
    if active_policy is not None:
        result.skew_seconds = active_policy.max_clock_skew_seconds

    # 4. High water: absent refuses (it is initialized only by the operator's
    #    install), and so does a declared epoch below its floor.
    def high_water():
        value = producers.high_water()
        if type(value) is not HighWater:
            raise _Refused("activation high water absent or refused")
        return value
    floors = attempt(("epoch_high_water",), high_water)
    result.high_water = floors
    if floors is not None and identity is not None and identity[1] < floors.security_epoch:
        fail("epoch_high_water")

    # 5. Clock: the OS clock may not be below the floor less the policy skew.
    if floors is not None and active_policy is not None:
        def clock():
            instant = parse_bootstrap_time(now)
            skew = timedelta(seconds=active_policy.max_clock_skew_seconds)
            if instant < parse_bootstrap_time(floors.time_floor) - skew:
                raise _Refused("clock below the persisted time floor")
        attempt(("trusted_clock",), clock)

    # 6. The current generation, as an observe-baseline tree over the unit
    #    files installed now (edge-core's, with its observe-only Environment=
    #    lines, among them when in scope), bound to this evidence and -- when
    #    edge-core is in scope -- to the Edge package installed now.
    generation: Optional[Generation] = None
    edge_in_scope = active_policy is not None and EDGE_CORE_UNIT in active_policy.units
    pinned: list = []
    if active_policy is not None and result.evidence is not None:
        def current_generation():
            current = generations.current()
            if current is None:
                raise _Refused("no generation")
            verified = generations.verify(current.number)
            tree = generations.read_tree(verified.number)
            scope = list(active_policy.units)
            measured = producers.unit_files(scope)
            package_digest, components, binding = None, None, "not_in_scope"
            if edge_in_scope:
                raw = dict(tree).get(OBSERVE_BASELINE_FILE)
                pin = decode_observe_baseline(raw)["edge_pin"]
                package_digest, components = pin["package_digest"], pin["components"]
                try:
                    installed = producers.edge_package_digest()
                except Exception:  # noqa: BLE001 - no digest binds nothing; edge-core withheld
                    installed = None
                try:
                    extracted = producers.edge_components()
                except Exception:  # noqa: BLE001 - unreadable binds nothing; edge-core withheld
                    extracted = None
                # Readable and different from what the operator signed: the
                # baseline no longer describes this node, like a changed unit
                # file. Unreadable: nothing is bound, and only edge-core waits.
                if installed is not None and installed != package_digest:
                    raise _Refused("installed Edge package differs from the generation")
                if extracted is not None and dict(extracted) != components:
                    raise _Refused("extracted Edge components differ from the generation")
                binding = ("bound" if installed is not None and extracted is not None
                           else "package_refused")
            verify_observe_baseline(generation=verified, files=tree, units=scope,
                                    unit_files=measured, package_digest=package_digest,
                                    package_components=components)
            if (verified.commissioning_evidence_binding != result.evidence.binding
                    or verified.commissioning_digest
                    != evidence_commissioning_digest(result.evidence)):
                raise _Refused("generation is bound to other commissioning evidence")
            # A unit file changed during measurement is a different baseline.
            if producers.unit_files(scope) != measured:
                raise _Refused("installed unit files changed during measurement")
            pinned[:] = [package_digest]
            result.edge_package_binding = binding
            return verified
        generation = attempt(("operational_generation_publisher",), current_generation)
    if generation is not None:
        result.generation = generation.number
        if floors is not None and generation.number < floors.generation:
            fail("epoch_high_water")

    # 6b. Every grantable unit, in the policy or not (#251 H-1, M-3): its
    #     file waits for its marker, the manager is a reviewed profile, and
    #     each unit is not loaded, masked, or loaded from the vendor file
    #     with no drop-in, its marker condition and the controller among its
    #     Requires/After. A unit loaded earlier in the boot runs its loaded
    #     definition, and READY releases its queued start whether or not
    #     this policy names it.
    def loaded_units():
        producers.loaded_units(sorted(UNIT_SCOPE))
    attempt(("systemd_loaded_units",), loaded_units)

    # 7. The v2 approval, verified against the context above and the floors.
    upstream = ("authenticated_commissioning", "node_identity", "activation_policy",
                "epoch_high_water", "trusted_clock", "operational_generation_publisher")
    if all(status[name] == "verified" for name in upstream):
        def approval():
            context = ObserveBaselineContext(
                node_digest=identity[0], generation=generation.number,
                generation_digest=generation.digest,
                commissioning_digest=evidence_commissioning_digest(result.evidence),
                commissioning_evidence_binding=result.evidence.binding,
                policy_digest=active_policy.policy_digest, security_epoch=identity[1],
            )
            approved = producers.approval(
                expected=context,
                policy=ActivationApprovalPolicy(
                    authorized_operators=frozenset(active_policy.operators),
                    max_lease_seconds=active_policy.max_lease_seconds,
                    unit_scope=frozenset(active_policy.units),
                ),
                now=now, security_epoch_floor=floors.security_epoch,
                approval_seq_floor=floors.approval_seq,
            )
            if (type(approved) is not ObserveBaselineApproval
                    or type(approved.lease) is not ActivationLease
                    or approved.lease.units is None
                    or not approved.lease.units <= set(active_policy.units)
                    or approved.lease.generation_digest != generation.digest
                    or approved.lease.generation_number != generation.number):
                raise _Refused("approval result refused")
            return approved
        result.approval = attempt(("activation_approval_loader",), approval)

    # 8. Node health, from the policy floors (after narrowing, read-only).
    if active_policy is not None:
        def health():
            healthy, findings = producers.health(active_policy, ledger)
            result.health_findings = tuple(
                (str(name), "ok" if verdict == "ok" else "failed") for name, verdict in findings
            )
            if healthy is not True:
                raise _Refused("node unhealthy")
        attempt(("node_health",), health)

    if result.complete and result.approval is not None:
        result.lease = result.approval.lease
        result.healthy = True
    else:
        result.lease, result.healthy = None, False

    # 9. Edge evidence (P5), read-only and never part of `complete`: the
    #    library withholds edge-core unless it is launchable; the SUPPORTING
    #    units are decided without it.
    if result.lease is not None:
        try:
            state = producers.edge_state(now=now)
        except Exception:  # noqa: BLE001 - unreadable evidence establishes nothing
            state = None
        if type(state) is not EdgeBaselineState:
            state = nothing_established()
        if not edge_in_scope:
            result.edge_evidence = "not_in_scope"
        else:
            # The signed pin only when the installed package was derived equal
            # to it; then the probe must also have observed that package.
            signed = (pinned[0] if result.edge_package_binding == "bound"
                      and len(pinned) == 1 else None)
            state = bound_to_signed_package(state, signed)
            result.edge_evidence = "launchable" if state.launchable else "not_launchable"
            result.edge_missing = state.missing_for_launch()
        result.edge = state
    return result


def production_producers(*, commissioning_evidence: Callable[[], CommissioningEvidence],
                         systemd=None) -> PassProducers:
    """The fixed host readers. Imported lazily by the controller after narrowing.

    `systemd` is the controller's own `SystemdBusSession` (the manager's
    `call`); without one the loaded-unit check refuses, so nothing is granted.
    """
    from azazel_nexus.activation_policy import load_activation_policy
    from azazel_nexus.activation_store import load_observe_baseline_approval
    from azazel_nexus.bootstrap_deployment_store import load_bootstrap_deployment
    from azazel_nexus.edge_package import (
        installed_baseline_state,
        installed_package_digest,
        measure_extracted_components,
    )

    from .activation_health import collect_node_health
    from .activation_high_water import raise_high_water, require_high_water_for_pass
    from .activation_loaded_units import verify_grantable_units
    from .activation_unit_files import measure_scoped_unit_files
    from .node_config import load_declared_node

    return PassProducers(
        commissioning_evidence=commissioning_evidence,
        declared_node=load_declared_node,
        deployment=load_bootstrap_deployment,
        policy=load_activation_policy,
        high_water=require_high_water_for_pass,
        unit_files=measure_scoped_unit_files,
        loaded_units=lambda units: verify_grantable_units(systemd, units),
        approval=load_observe_baseline_approval,
        health=lambda policy, ledger: collect_node_health(policy=policy, ledger=ledger),
        raise_high_water=raise_high_water,
        # The fixed installed paths. The boot preflight wrote the probe result
        # before this pass (`Before=`); the pass only reads it.
        edge_package_digest=installed_package_digest,
        edge_state=lambda *, now: installed_baseline_state(now=now),
        edge_components=measure_extracted_components,
    )
