"""The observe-baseline inputs of one activation pass (#206 phase P4).

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

Phase P4 wires SUPPORTING only. A policy naming `azazel-edge-core.service`
is refused as a whole here (`activation_policy` fails), so no lease or
generation in this phase can include edge-core; P5 lifts this with its own
Edge evidence ordering and probe binding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import os
import stat
from typing import Callable, Optional

from azazel_nexus.activation import ActivationLease
from azazel_nexus.activation_approval_v2 import (
    ActivationApprovalPolicy,
    ObserveBaselineApproval,
    ObserveBaselineContext,
)
from azazel_nexus.activation_policy import ActivationPolicy
from azazel_nexus.bootstrap_approval import parse_bootstrap_time
from azazel_nexus.bootstrap_deployment import BootstrapDeployment, declared_node_digest
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.generation import Generation
from azazel_nexus.observe_baseline import EDGE_CORE_UNIT, verify_observe_baseline

from .activation_high_water import HighWater
from .node_config import DeclaredNode

__all__ = [
    "ALWAYS_MISSING",
    "P4_UNIT_SCOPE",
    "PRODUCERS",
    "PassInputs",
    "PassProducers",
    "collect_pass_inputs",
    "commissioning_payload_digest",
    "production_producers",
    "raised_high_water",
    "read_installed_unit_file",
    "staged_inputs",
]

#: The units phase P4 may grant: the five SUPPORTING loop units (§6.2).
P4_UNIT_SCOPE = frozenset({
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
})

#: The producers this pass runs, as named in `missing_producers`.
PRODUCERS = (
    "authenticated_commissioning",
    "inventory_binding",
    "node_identity",
    "activation_policy",
    "epoch_high_water",
    "trusted_clock",
    "operational_generation_publisher",
    "activation_approval_loader",
    "node_health",
)
#: Not required for the SUPPORTING scope (§2) or not built yet; always named.
ALWAYS_MISSING = (
    "authoritative_commissioning_admission",
    "renderer_measurement",
    "edge_evidence",
)

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
    #: Bytes of one installed unit file, measured now.
    unit_file: Callable[[str], bytes]
    #: `load_observe_baseline_approval` (keyword arguments).
    approval: Callable[..., ObserveBaselineApproval]
    #: `(policy, ledger) -> (healthy, findings)`.
    health: Callable
    #: `raise_high_water` (value, keyword `now` and `skew_seconds`).
    raise_high_water: Callable[..., HighWater]


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

    @property
    def complete(self) -> bool:
        return all(self.status.get(name) == "verified" for name in PRODUCERS)

    def missing(self) -> list[str]:
        """Only the producers that failed (or were not collected), plus the unbuilt."""
        failed = [name for name in PRODUCERS
                  if self.status.get(name) in ("failed", "not_collected_staged_root")]
        return list(ALWAYS_MISSING) + failed


def staged_inputs() -> PassInputs:
    """A relocated root reads no host producer; everything stays missing."""
    return PassInputs(status={name: "not_collected_staged_root" for name in PRODUCERS})


class _Refused(Exception):
    pass


def commissioning_payload_digest(evidence: CommissioningEvidence) -> str:
    """The observe-baseline `commissioning_digest`: SHA-256 of the signed proposal.

    Derived from the verified evidence on every pass, so neither the
    generation metadata nor the approval can supply it. The generation
    publisher and `az-activation request` must use this same derivation.
    """
    if type(evidence) is not CommissioningEvidence:
        raise _Refused("commissioning evidence required")
    return "sha256:" + sha256(evidence.payload).hexdigest()


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
        digest = declared_node_digest(declared.node_id)
        if digest != deployment.node_digest:
            raise _Refused("declared node differs from the deployment declaration")
        return digest, deployment.security_epoch
    identity = attempt(("node_identity",), node)

    # 3. Activation policy, SUPPORTING scope only in P4.
    def policy():
        value = producers.policy()
        if type(value) is not ActivationPolicy:
            raise _Refused("activation policy required")
        if EDGE_CORE_UNIT in value.units or not set(value.units) <= P4_UNIT_SCOPE:
            raise _Refused("edge-core scope is not wired before phase P5")
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
    #    files installed now, bound to this evidence.
    generation: Optional[Generation] = None
    if active_policy is not None and result.evidence is not None:
        def current_generation():
            current = generations.current()
            if current is None:
                raise _Refused("no generation")
            verified = generations.verify(current.number)
            tree = generations.read_tree(verified.number)
            scope = list(active_policy.units)
            measured = {unit: producers.unit_file(unit) for unit in scope}
            verify_observe_baseline(generation=verified, files=tree, units=scope,
                                    unit_files=measured)
            if (verified.commissioning_evidence_binding != result.evidence.binding
                    or verified.commissioning_digest
                    != commissioning_payload_digest(result.evidence)):
                raise _Refused("generation is bound to other commissioning evidence")
            # A unit file changed during measurement is a different baseline.
            if {unit: producers.unit_file(unit) for unit in scope} != measured:
                raise _Refused("installed unit files changed during measurement")
            return verified
        generation = attempt(("operational_generation_publisher",), current_generation)
    if generation is not None:
        result.generation = generation.number
        if floors is not None and generation.number < floors.generation:
            fail("epoch_high_water")

    # 7. The v2 approval, verified against the context above and the floors.
    upstream = ("authenticated_commissioning", "node_identity", "activation_policy",
                "epoch_high_water", "trusted_clock", "operational_generation_publisher")
    if all(status[name] == "verified" for name in upstream):
        def approval():
            context = ObserveBaselineContext(
                node_digest=identity[0], generation=generation.number,
                generation_digest=generation.digest,
                commissioning_digest=commissioning_payload_digest(result.evidence),
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
    return result


# -- installed unit files ------------------------------------------------------

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_VENDOR = ("usr", "lib", "systemd", "system")
#: Higher-precedence unit directories: a file of the same name there would be
#: loaded instead of the measured one. Only the persistent mask (a symlink to
#: /dev/null, written by the preflight remask) may exist.
_SHADOWS = (("etc", "systemd", "system"), ("run", "systemd", "system"),
            ("usr", "local", "lib", "systemd", "system"))
#: Drop-in locations: any `<unit>.d` directory changes the loaded unit.
_DROP_INS = _SHADOWS + (("run", "systemd", "system.control"), _VENDOR)
_UNIT_FILE_LIMIT = 1 << 20
#: Owner of every component and of the unit file. Private test seam only.
_OWNER = 0


def _walk(root_fd: int, components) -> int | None:
    fd = os.dup(root_fd)
    try:
        for component in components:
            try:
                child = os.open(component, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                return None
            os.close(fd)
            fd = child
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


def _drop_in_names(unit: str) -> tuple[str, ...]:
    """Every drop-in directory systemd applies to `unit`.

    `<unit>.d`, the type-wide `service.d`, and the dash-prefix forms
    (`azazel-.service.d`, `azazel-mio-.service.d`, ...).
    """
    stem = unit[: -len(".service")]
    prefixes = [stem[: index + 1] for index, char in enumerate(stem) if char == "-"]
    return (unit + ".d", "service.d", *(prefix + ".service.d" for prefix in prefixes))


def _read_unit_file_at(root_fd: int, unit: str) -> bytes:
    """Private descriptor seam: measure `usr/lib/systemd/system/<unit>` under root_fd."""
    if (type(unit) is not str or unit not in P4_UNIT_SCOPE | {EDGE_CORE_UNIT}):
        raise _Refused("unit outside the activation scope")
    for components in _SHADOWS:
        directory = _walk(root_fd, components)
        if directory is None:
            continue
        try:
            try:
                info = os.stat(unit, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISLNK(info.st_mode) or os.readlink(unit, dir_fd=directory) != "/dev/null":
                raise _Refused("an installed unit file is shadowed")
        finally:
            os.close(directory)
    for components in _DROP_INS:
        directory = _walk(root_fd, components)
        if directory is None:
            continue
        try:
            for name in _drop_in_names(unit):
                try:
                    os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise _Refused("a drop-in changes the installed unit")
        finally:
            os.close(directory)
    directory = os.dup(root_fd)
    try:
        for component in _VENDOR:
            info = os.fstat(directory)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER
                    or info.st_mode & 0o022):
                raise _Refused("unit directory protection refused")
            child = os.open(component, _DIR_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER or info.st_mode & 0o022:
            raise _Refused("unit directory protection refused")
        fd = os.open(unit, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != _OWNER
                    or before.st_nlink != 1 or before.st_mode & 0o022
                    or not 0 < before.st_size <= _UNIT_FILE_LIMIT):
                raise _Refused("installed unit file protection refused")
            chunks = bytearray()
            while len(chunks) <= _UNIT_FILE_LIMIT:
                part = os.read(fd, _UNIT_FILE_LIMIT + 1 - len(chunks))
                if not part:
                    break
                chunks.extend(part)
            after = os.fstat(fd)
            if ((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or len(chunks) != before.st_size):
                raise _Refused("installed unit file changed while reading")
            return bytes(chunks)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def read_installed_unit_file(unit: str) -> bytes:
    """The bytes systemd loads for one scoped unit, measured now.

    Reads `/usr/lib/systemd/system/<unit>` (the Debian 13 `/lib/systemd/system`
    of the install profile, through `/usr` so no link is followed) and refuses
    when a higher-precedence directory holds anything for it but the
    persistent mask, or when any drop-in directory exists for it. It does not
    ask systemd for the loaded fragment; a generator or transient unit is
    outside this check.
    """
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return _read_unit_file_at(root, unit)
    finally:
        os.close(root)


def production_producers(*, commissioning_evidence: Callable[[], CommissioningEvidence]) -> PassProducers:
    """The fixed host readers. Imported lazily by the controller after narrowing."""
    from azazel_nexus.activation_policy import load_activation_policy
    from azazel_nexus.activation_store import load_observe_baseline_approval
    from azazel_nexus.bootstrap_deployment_store import load_bootstrap_deployment

    from .activation_health import collect_node_health
    from .activation_high_water import raise_high_water, require_high_water_for_pass
    from .node_config import load_declared_node

    return PassProducers(
        commissioning_evidence=commissioning_evidence,
        declared_node=load_declared_node,
        deployment=load_bootstrap_deployment,
        policy=load_activation_policy,
        high_water=require_high_water_for_pass,
        unit_file=read_installed_unit_file,
        approval=load_observe_baseline_approval,
        health=lambda policy, ledger: collect_node_health(policy=policy, ledger=ledger),
        raise_high_water=raise_high_water,
    )
