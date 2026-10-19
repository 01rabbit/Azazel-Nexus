"""The one component that may widen what this node runs (#28).

`docs/IMPLEMENTATION_SPEC.md` §2.3 states the rule this module exists to make
mechanical:

    Installation MUST NOT start an operational network service. Every
    operational unit is installed **preset disabled** and stays masked until
    the activation controller validates a verified generation.

and §4 names the controller as the "sole component permitted to unmask
operational units and issue generation-scoped credentials".

So the shape here is deliberately asymmetric:

*Narrowing needs no permission.* Masking a unit, fencing a failed capability,
refusing to grant -- any component may do these, and none of them takes an
authorization. A safety action that requires a permission is a safety action
that is unavailable exactly when the thing that issues permissions is the
thing that failed.

*Widening needs an authorization that only activation mints.* `unmask_and_enable`
refuses a call that does not carry an `ActivationAuthorization`, and an
authorization is bound to one unit, one generation and one digest.

**What that boundary is and is not.** Within one Python process this enforces
the *design* boundary: no operator CLI, commissioning daemon, module or M.I.O.
call path can reach `unmask_and_enable` without going through
`ActivationController.activate`, and `tests/unit/test_activation.py` scans the
package to keep it that way. It is not an enforcement boundary against hostile
code already running as root in this process -- nothing written in Python is.
That boundary is the operating system's: the unit files are root-owned, only
`azazel-activated.service` runs with the privilege to rewrite them, and every
other daemon runs under its own non-login account (§3). That half is
**hardware-unverified** and is recorded as such in `docs/hardware-gates.md`;
CI proves the design boundary and proves nothing about systemd.

*Every boot revalidates.* `activate` re-derives the digest of the current
generation on every call and never consults a cached verdict. A generation
verified once and not since describes whatever its tree has become.
"""

from __future__ import annotations

import re

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Optional, Sequence

from .audit import AuditLedger, AuditUnavailable
from .commissioning import CommissioningRecord
from .commissioning_evidence import CommissioningEvidence
from .generation import GenerationRefused, GenerationStore

__all__ = [
    "ACTIVATION_CONTROLLER_UNIT",
    "ARTIFACT_TRANSPORT",
    "LOCAL_MODEL_PROVIDER",
    "REMOTE_INFERENCE_TRANSPORT",
    "ActivationLease",
    "EdgeBaselineState",
    "CORE_UNITS",
    "ActivationAuthorization",
    "ActivationController",
    "ActivationOutcome",
    "ActivationRefused",
    "RecordingUnitController",
    "SystemdUnitController",
    "UnitController",
    "UnitDefinition",
    "UnitState",
    "UnitTier",
    "UnitVerdict",
    "Watchdog",
]


class ActivationRefused(Exception):
    """Nothing was widened, and nothing was assumed in place of a check."""


class UnmaskRefused(ActivationRefused):
    """A component that is not the activation controller tried to widen."""


class UnitState(str, Enum):
    """What the service manager would do with a unit at boot."""

    MASKED = "masked"
    DISABLED = "disabled"
    ENABLED = "enabled"


class UnitTier(str, Enum):
    """What a unit needs before it may be granted. Three answers, not one.

    Collapsing these is the failure the tiers exist to prevent: a node whose
    ledger and watchdog are running is a node that can account for itself, and
    that is **not** a node that may claim a deterministic baseline or enforce
    anything. One readiness condition covering all three would let the easiest
    of them speak for the other two.

    `SUPPORTING` is how an uncommissioned node becomes commissioned and
    accounts for itself while it is: commissioning, the ledger, the watchdog.
    Requiring a completed commissioning before the daemon that performs
    commissioning may run would leave no path from an installed node to a
    commissioned one.

    `EDGE_BASELINE` is the local Edge Core. It needs a verified Edge package
    on top of everything `SUPPORTING` needs: present, matching version and
    digest, and a healthy fixed health contract. Running is a consequence of
    starting, not an admission prerequisite. Only all five checks, including
    running, may cause `edge-baseline-ready` to be claimed.

    `ENFORCEMENT` acts on the network an operator confirmed, and needs a
    complete commissioning record on top of the rest.
    """

    SUPPORTING = "supporting"
    EDGE_BASELINE = "edge_baseline"
    ENFORCEMENT = "enforcement"


@dataclass(frozen=True)
class UnitDefinition:
    """One unit this controller governs."""

    name: str
    tier: UnitTier
    account: str
    purpose: str
    #: The capability this unit needs **wired into the build** before it may
    #: run, or `None` when it needs none.
    #:
    #: A tier says what a *node* must have established. This says what the
    #: *distribution* must contain. The two are different questions, and
    #: collapsing them is how `azazel-model-fetchd.service` came to be granted
    #: on every healthy node while its service exits immediately for having no
    #: transport: its tier was satisfied, and nothing asked whether the thing
    #: it would serve exists here at all.
    #:
    #: A unit named here is still shipped, still declared, still masked
    #: explicitly and still carries its account, socket and hardening -- the
    #: service boundary is part of the product whether or not anything is
    #: behind it yet. What it does not do is start.
    wiring: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.name.endswith(".service"):
            raise ActivationRefused(f"{self.name!r} is not a service unit name")
        if self.wiring is not None and not self.wiring.strip():
            raise ActivationRefused(
                f"{self.name} names an empty wiring capability; a requirement "
                "with no name is one nothing can ever satisfy and nobody can "
                "read"
            )
        if not self.account.strip():
            raise ActivationRefused(
                f"{self.name} names no account; a unit whose identity is "
                "unstated runs as whatever the unit file last said"
            )


#: The controller's own unit. It is installed enabled, because a controller
#: that never runs never revalidates anything -- and it starts no network
#: service, so enabling it does not breach §2.3.
#:
#: It is deliberately **not** in `CORE_UNITS`: the component that decides what
#: may be unmasked does not decide that about itself.
ACTIVATION_CONTROLLER_UNIT = "azazel-activated.service"


#: The capability `azazel-model-fetchd.service` needs wired: a Source Registry
#: that resolves at least one source symbol to an endpoint.
#:
#: A name rather than a boolean so that a withholding reason says *what* is
#: missing, and so that a second unit needing something else cannot satisfy
#: its requirement by satisfying this one.
ARTIFACT_TRANSPORT = "artifact_transport"

#: The capability `azazel-mio-locald.service` needs wired: an admitted local
#: model provider, including verified runtime and production admission evidence.
#: This build has no admission-evidence loader, so the unit is not granted.
#:
#: Separate from `ARTIFACT_TRANSPORT` and not implied by it. Fetching weights
#: and running them are different capabilities held by different accounts, and
#: a node that gained one must not be read as having gained the other.
LOCAL_MODEL_PROVIDER = "local_model_provider"

#: The capability `azazel-mio-remoted.service` needs wired: a commissioned
#: Provider Registry **and** a key holding the sanitizer role, so that a
#: provider symbol resolves and an envelope verifies.
#:
#: Separate from both others and implied by neither. Fetching weights,
#: running them, and sending what this node observed are three capabilities
#: held by three accounts; a node that gained one must not be read as having
#: gained another.
REMOTE_INFERENCE_TRANSPORT = "remote_inference_transport"


#: The governed set for the CORE slice.
#:
#: Each carries its own non-login account (#42). None of the three is root:
#: the activation controller is, and isolating the privilege there is what
#: leaves these unprivileged.
#:
#: M.I.O. entry and Knowledge Lite status are SUPPORTING services; provider
#: units remain separately wiring-gated. Enforcement, Deception Lite and
#: module-manager units belong to slices that are not built yet. `docs/roadmap.md` holds
#: what is still owed; this tuple holds what exists.
#:
#: Edge Core belongs to `EDGE_BASELINE`; its probe remains `SUPPORTING`
#: so observation does not depend on the readiness it establishes. I0 ships
#: the payload; #198 admits it on four package checks, while readiness still
#: requires the fifth check, running.
CORE_UNITS = (
    UnitDefinition(
        "azazel-commissiond.service",
        UnitTier.SUPPORTING,
        "azcommission",
        "read-only inventory, operator confirmation, commissioning record",
    ),
    UnitDefinition(
        "azazel-auditd.service",
        UnitTier.SUPPORTING,
        "azaudit",
        "hash-chain ledger; refuses chain discontinuity",
    ),
    UnitDefinition(
        "azazel-watchdog.service",
        UnitTier.SUPPORTING,
        "azwatch",
        "degradation coordinator; never restarts into a broader authority state",
    ),
    UnitDefinition(
        "azazel-edge-core.service",
        UnitTier.EDGE_BASELINE,
        "azedge",
        "verified Edge Core payload; fixed observe-only posture",
    ),
    UnitDefinition(
        "azazel-edge-intaked.service", UnitTier.SUPPORTING, "azintake",
        "receives Edge observations before Edge admission; grants no authority",
    ),
    UnitDefinition(
        "azazel-edge-probed.service",
        # SUPPORTING, and deliberately **not** EDGE_BASELINE. An
        # `EDGE_BASELINE` unit needs a verified Edge package before it may be
        # granted, and this is the unit that establishes whether one is
        # healthy and running. A probe that could only run once Edge was
        # established could never establish it.
        #
        # It belongs with commissioning and the ledger for the same reason
        # they do: it observes and records, and it grants nothing. Its result
        # cannot promote anything on its own -- the library re-derives
        # package, version and digest itself and takes only health and
        # running from it (Nexus#72).
        UnitTier.SUPPORTING,
        "azprobe",
        "one-shot Edge health and running probe; reads, never starts",
    ),
    UnitDefinition(
        "azazel-model-fetchd.service",
        # SUPPORTING for the same reason the probe is: it observes and moves
        # bytes, and it grants nothing. A fetched artifact is not admitted,
        # not activated, and reaches the store only through the same
        # verification an offline import goes through.
        #
        # Governed like every other operational unit, which is what keeps it
        # masked after installation. The one unit permitted an internet
        # address family is the last one that should start unbidden.
        UnitTier.SUPPORTING,
        "azfetch",
        "artifact fetch service; the only unit with egress, and it admits nothing",
        # The Source Registry ships empty, so this build resolves no source
        # symbol to an endpoint and the service exits rather than listen for
        # work it cannot do. Granting it would enable a unit that fails at the
        # next boot -- and a node whose systemd reports `degraded` for a thing
        # that is working as designed is a node where the next real failure
        # looks like this one.
        #
        # A commissioned Source Registry is what wires it. That is deployment
        # data, signed and reviewed, never a change to this file.
        wiring=ARTIFACT_TRANSPORT,
    ),
    UnitDefinition(
        "azazel-mio-locald.service",
        # SUPPORTING for the same reason the others are: it decides nothing
        # the arbiter decides. A started, crashed or rolled-back model runtime
        # moves no authority -- `FULL -> LITE -> CORE` is a capability state,
        # never an authority state.
        UnitTier.SUPPORTING,
        "azmio",
        "local model runtime host; the only unit that could start a model, "
        "and it starts none",
        # A pinned runtime alone is insufficient. The unit is not granted
        # until a model is admitted; HG-05 and operator approval remain closed.
        wiring=LOCAL_MODEL_PROVIDER,
    ),
    UnitDefinition(
        "azazel-mio-remoted.service",
        # SUPPORTING like the rest: it decides nothing the arbiter decides.
        # What comes back is advice, and advice is never authority.
        UnitTier.SUPPORTING,
        "azremote",
        "remote inference transport; the only unit that could send what this "
        "node observed, and it sends nothing",
        # No Provider Registry is commissioned and no key holds the sanitizer
        # role, so no provider symbol resolves and no envelope verifies. Both
        # arrive as signed commissioning data, never as a change to this file.
        wiring=REMOTE_INFERENCE_TRANSPORT,
    ),
    UnitDefinition(
        "azazel-mio-entryd.service",
        UnitTier.SUPPORTING,
        "azmioentry",
        "M.I.O. routing and handoff ledger; no provider or wiring requirement",
    ),
    UnitDefinition(
        "azazel-knowledge-lited.service",
        UnitTier.SUPPORTING,
        "azknowledge",
        "read-only Knowledge Lite service; import and repin use existing paths",
    ),
)


def _utc_lease_time(value: str) -> datetime:
    """Canonical whole-second UTC for the authenticated-input path."""
    if type(value) is not str or len(value) != 20:
        raise ActivationRefused("lease time must be canonical UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ActivationRefused("invalid lease time") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ActivationRefused("lease time must be canonical UTC")
    return parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class ActivationLease:
    """Time-bounded permission to activate one generation.

    An authorization with no expiry is one that cannot be withdrawn by doing
    nothing, and every other way of withdrawing it needs the thing that went
    wrong to still be working.

    The lease names the generation digest it was granted against. A lease is
    not a standing permission to activate whatever is current: the operator
    approved a configuration, not a slot.
    """

    granted_by: str
    granted_at: str
    expires_at: str
    generation_digest: str
    # Signed approval inputs additionally pin the exact generation and its
    # commissioning metadata. Legacy injected/library leases leave both absent.
    generation_number: Optional[int] = None
    commissioning_digest: Optional[str] = None
    commissioning_evidence_binding: Optional[str] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.commissioning_evidence_binding is not None and (
            self.generation_number is None or type(self.commissioning_evidence_binding) is not str
            or not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", self.commissioning_evidence_binding)
        ):
            raise ActivationRefused("invalid lease evidence binding")
        if (self.generation_number is None) != (self.commissioning_digest is None):
            raise ActivationRefused("generation number and commissioning binding must be supplied together")
        if self.generation_number is not None:
            if type(self.generation_number) is not int or self.generation_number < 1:
                raise ActivationRefused("invalid lease generation number")
            if type(self.commissioning_digest) is not str or not self.commissioning_digest:
                raise ActivationRefused("invalid lease commissioning binding")
            _utc_lease_time(self.granted_at)
            _utc_lease_time(self.expires_at)
        for field_name in ("granted_by", "granted_at", "expires_at", "generation_digest"):
            if not str(getattr(self, field_name)).strip():
                raise ActivationRefused(
                    f"a lease with no {field_name} is not a lease; it is a "
                    "permission nobody can be shown to have granted"
                )
        if self.expires_at <= self.granted_at:
            raise ActivationRefused(
                f"the lease expires at {self.expires_at} and was granted at "
                f"{self.granted_at}; a lease that is over before it starts "
                "would be refused on every boot and read as a fault"
            )

    def valid_at(self, now: str) -> bool:
        """RFC3339 timestamps compare correctly as strings when zoned alike.

        The caller supplies `now`; nothing here reads a clock. A component
        that decided its own permission's expiry from a clock it read itself
        is a component whose permission depends on its own clock.
        """

        if self.generation_number is not None:
            try:
                return _utc_lease_time(self.granted_at) <= _utc_lease_time(now) < _utc_lease_time(self.expires_at)
            except ActivationRefused:
                return False
        return self.granted_at <= now < self.expires_at


EDGE_LAUNCH_CHECKS = (
    "package_present", "version_matches", "digest_matches", "health_endpoint_healthy",
)
EDGE_CHECKS = (*EDGE_LAUNCH_CHECKS, "running")


@dataclass(frozen=True)
class EdgeBaselineState:
    """Evidence derived by `edge_package` from the installed package and probe.

    Four package checks permit launch; all five establish readiness. A grant
    permits a future start and says nothing about whether Edge is running.
    Missing, stale or unreadable probe evidence supplies False, never consent.
    """

    package_present: bool
    version_matches: bool
    digest_matches: bool
    health_endpoint_healthy: bool
    running: bool
    observed_at: Optional[str] = None
    package_version: Optional[str] = None
    package_digest: Optional[str] = None

    @property
    def launchable(self) -> bool:
        """The package may start; this does not claim baseline readiness."""
        return not self.missing_for_launch()

    def missing_for_launch(self) -> tuple[str, ...]:
        """Failed package checks, excluding the consequence of starting."""
        return tuple(name for name in EDGE_LAUNCH_CHECKS if not getattr(self, name))

    @property
    def ready(self) -> bool:
        return all(
            (
                self.package_present,
                self.version_matches,
                self.digest_matches,
                self.health_endpoint_healthy,
                self.running,
            )
        )

    def missing(self) -> tuple[str, ...]:
        """Which checks failed, by name.

        "Edge is not ready" and "Edge is present, running, and its digest does
        not match what we pinned" call for different operator actions, and the
        second one is a security finding.
        """

        return tuple(name for name in EDGE_CHECKS if not getattr(self, name))

    def as_event(self) -> dict:
        """A bounded record of the checks and the probe's package binding."""
        event = {name: getattr(self, name) for name in EDGE_CHECKS}
        for name, limit in (("observed_at", 64), ("package_version", 256),
                            ("package_digest", 256)):
            value = getattr(self, name)
            if value is not None:
                event[name] = value[:limit]
        return event



#: The sentinel an authorization must carry. Held by `ActivationController`
#: and by nothing else in the package; the static scan in the tests is what
#: keeps that true as the package grows.
_MINT = object()


@dataclass(frozen=True)
class ActivationAuthorization:
    """Permission to widen exactly one unit, once, for one generation.

    Construction refuses unless the caller holds the module's mint, so the
    token cannot be produced by a component that merely imports this module
    and fills in plausible fields.
    """

    unit: str
    generation: int
    digest: str
    mint: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.mint is not _MINT:
            raise UnmaskRefused(
                f"an authorization for {self.unit!r} was constructed outside the "
                "activation controller. The controller is the only component "
                "permitted to widen what this node runs (IMPLEMENTATION_SPEC "
                "§2.3, §4)"
            )
        if not self.digest:
            raise UnmaskRefused(
                f"the authorization for {self.unit!r} names no generation "
                "digest; a grant that does not say which configuration it "
                "validated cannot be checked against one later"
            )


class UnitController:
    """The port to the service manager, with the widening guard built in.

    Subclasses implement the two verbs and never the guard: the public
    `unmask_and_enable` is defined here and checked by the tests to be
    unoverridden. A subclass that could replace it could grant itself the
    privilege this class exists to withhold.
    """

    def state(self, unit: str) -> UnitState:
        raise NotImplementedError

    def mask(self, unit: str, *, reason: str) -> None:
        """Narrow. Needs no authorization, and records why.

        The reason is required because the ledger entry beside it is the only
        thing that distinguishes "withheld because the digest did not match"
        from "withheld because nobody asked for it".
        """

        if not reason.strip():
            raise ActivationRefused(
                f"masking {unit!r} without a reason leaves an operator a "
                "stopped service and no account of why it stopped"
            )
        self._mask(unit)

    def unmask_and_enable(self, unit: str, *, authorization: object) -> None:
        """Widen. Refuses anything but a bound, controller-minted token."""

        if not isinstance(authorization, ActivationAuthorization):
            raise UnmaskRefused(
                f"{unit!r} cannot be unmasked without an authorization from the "
                "activation controller; operator interfaces, the commissioning "
                "daemon, modules and M.I.O. have no path to this verb"
            )
        if authorization.unit != unit:
            raise UnmaskRefused(
                f"the authorization names {authorization.unit!r} and was used "
                f"on {unit!r}; a grant is for one unit and is not transferable"
            )
        self._unmask_and_enable(unit)

    def _mask(self, unit: str) -> None:
        raise NotImplementedError

    def _unmask_and_enable(self, unit: str) -> None:
        raise NotImplementedError


class RecordingUnitController(UnitController):
    """An in-memory service manager that keeps the call log.

    Used by the tests and by `azctl`-style dry runs. Every unit starts masked,
    which is the state the installer leaves the host in.
    """

    def __init__(self, units: Iterable[str] = ()) -> None:
        self._states = {name: UnitState.MASKED for name in units}
        self.calls: list[tuple[str, str]] = []

    def state(self, unit: str) -> UnitState:
        return self._states.get(unit, UnitState.MASKED)

    def _mask(self, unit: str) -> None:
        self._states[unit] = UnitState.MASKED
        self.calls.append(("mask", unit))

    def _unmask_and_enable(self, unit: str) -> None:
        self._states[unit] = UnitState.ENABLED
        self.calls.append(("unmask_and_enable", unit))


class SystemdUnitController(UnitController):
    """The `systemctl` argument vectors, through a runner the caller supplies.

    The runner has **no default**, and that is deliberate rather than tidy.
    This package imports nothing that can spawn a process, reach the network
    or touch host storage; `tests/unit/test_boundary_static.py` enforces it
    against the source. A `subprocess` default here would have been the first
    operational surface in a package that has commissioned no interface, and
    it would have arrived as a convenience.

    So this class decides *what to ask systemd for* and the caller decides
    *how to ask*. Which also draws the evidence line honestly: the tests
    establish that the argument vectors are right, and nothing more. Whether
    systemd then masks anything is **hardware-unverified**
    (`docs/hardware-gates.md`, `HG-01`). A green CI run is evidence about
    Python.
    """

    def __init__(self, run: Callable[[Sequence[str]], object]) -> None:
        if not callable(run):
            raise ActivationRefused(
                "SystemdUnitController needs a runner; this package spawns no "
                "process of its own, so the caller supplies the one thing that "
                "can (see tests/unit/test_boundary_static.py)"
            )
        self._run = run

    def state(self, unit: str) -> UnitState:
        result = self._run(["systemctl", "is-enabled", unit])
        text = getattr(result, "stdout", b"")
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
        word = str(text).strip()
        if word == "masked":
            return UnitState.MASKED
        if word == "enabled":
            return UnitState.ENABLED
        return UnitState.DISABLED

    def _mask(self, unit: str) -> None:
        self._run(["systemctl", "mask", "--now", unit])

    def _unmask_and_enable(self, unit: str) -> None:
        self._run(["systemctl", "unmask", unit])
        self._run(["systemctl", "enable", unit])


@dataclass(frozen=True)
class UnitVerdict:
    """What happened to one unit in one activation, and why."""

    unit: str
    granted: bool
    reason: str


@dataclass(frozen=True)
class ActivationOutcome:
    """`granted` is admission, never readiness.

    `edge_baseline_ready` is the only readiness claim.
    """

    generation: Optional[int]
    verdicts: tuple[UnitVerdict, ...]
    #: What was established about the local Edge Core during this pass.
    #: `None` means nothing was established. A grant is not readiness evidence.
    edge: Optional["EdgeBaselineState"] = None
    #: The commissioning record this pass decided against.
    record: Optional[CommissioningRecord] = None

    @property
    def granted(self) -> tuple[str, ...]:
        return tuple(v.unit for v in self.verdicts if v.granted)

    @property
    def withheld(self) -> tuple[str, ...]:
        return tuple(v.unit for v in self.verdicts if not v.granted)

    @property
    def edge_baseline_ready(self) -> bool:
        """Derived from the Edge state, **not** from the Edge tier's verdicts.

        The difference decides the answer on a node that has no Edge units at
        all. "Every unit in this tier was granted" over an empty tier is
        vacuously true, and would make a node with no Edge Core whatsoever the
        most confident node on the network -- which is the absence of evidence
        rendered as health, in its purest form.
        """

        return self.edge is not None and self.edge.ready

    @property
    def enforcement_ready(self) -> bool:
        """Both halves: a complete commissioning **and** a granted enforcement unit.

        A record alone says an operator settled what this node is attached to.
        It does not say anything is running that could act on it.
        """

        if self.record is None or not self.record.enforcement_ready:
            return False
        return any(
            verdict.granted and verdict.unit in self._enforcement_units
            for verdict in self.verdicts
        )

    #: Filled by the controller, which knows the tiers. An outcome built by
    #: hand carries none, so `enforcement_ready` is False for it -- the safe
    #: direction for a value nobody supplied.
    _enforcement_units: frozenset[str] = frozenset()


class ActivationController:
    """Validates, records, then widens -- in that order."""

    def __init__(
        self,
        *,
        units: UnitController,
        generations: GenerationStore,
        ledger: AuditLedger,
        definitions: Sequence[UnitDefinition] = CORE_UNITS,
    ) -> None:
        for definition in definitions:
            if definition.name == ACTIVATION_CONTROLLER_UNIT:
                raise ActivationRefused(
                    f"{ACTIVATION_CONTROLLER_UNIT} cannot be one of the units it "
                    "governs; a component that may grant itself privilege is "
                    "not a privilege boundary"
                )
        names = [d.name for d in definitions]
        if len(set(names)) != len(names):
            raise ActivationRefused(
                f"the governed set repeats a unit: {sorted(names)}. Two "
                "definitions for one unit means the verdict depends on order"
            )
        self.units = units
        self.generations = generations
        self.ledger = ledger
        self.definitions = tuple(definitions)
        # Set for the duration of one pass. Initialised to the refusing values
        # so that a controller asked to decide without a pass in progress
        # withholds rather than reading whatever the last pass left.
        #: Units this controller asked to mask and could not. Read by the
        #: runtime layer, which is the half that can escalate.
        self.unmaskable: set[str] = set()
        self._now = ""
        self._lease: Optional[ActivationLease] = None
        self._edge: Optional[EdgeBaselineState] = None
        self._healthy = False
        self._commissioning_evidence: Optional[CommissioningEvidence] = None
        self._require_commissioning_evidence = False
        #: What this build has wired. Empty is the refusing value and the
        #: shipped one: a controller asked to decide without being told what
        #: exists withholds every unit that needs something.
        self._wired: frozenset = frozenset()

    def activate(
        self,
        *,
        now: str,
        actor: str,
        record: Optional[CommissioningRecord] = None,
        lease: Optional[ActivationLease] = None,
        edge: Optional[EdgeBaselineState] = None,
        healthy: bool = True,
        wired: Iterable[str] = (),
        commissioning_evidence: Optional[CommissioningEvidence] = None,
        require_commissioning_evidence: bool = False,
    ) -> ActivationOutcome:
        """Run one activation pass. Called on every boot.

        The digest is re-derived here, every time. There is no cached verdict
        to consult, because a cached verdict is a statement about the tree at
        the moment it was cached.

        Four preconditions, and the tiers differ in which they need: a
        verified generation, health, a valid lease, and -- per tier -- a
        verified Edge package or a complete commissioning record.

        On any failure to establish a verified generation, every governed unit
        is masked and nothing is granted -- the node ends in the state the
        installer left it in rather than in whatever state the previous boot
        happened to reach.
        """

        self._now = now
        self._lease = lease
        self._edge = edge
        self._healthy = healthy
        if type(require_commissioning_evidence) is not bool:
            raise ActivationRefused("explicit commissioning evidence policy required")
        self._commissioning_evidence = commissioning_evidence
        self._require_commissioning_evidence = require_commissioning_evidence
        # Default empty, and the library cannot discover this for itself: what
        # is wired is a fact about the installed distribution, which is the
        # half the library is forbidden to import. It arrives as evidence, and
        # absent evidence withholds -- the same rule every other gate here
        # follows.
        self._wired = frozenset(wired)
        if lease is not None and type(lease) is not ActivationLease:
            return self._withhold_everything(
                None, "invalid_lease_type: ordinary activation requires an ActivationLease",
                now=now, actor=actor,
            )
        try:
            current = self.generations.current()
        except GenerationRefused:
            return self._withhold_everything(
                None, "generation_unverified: current generation metadata refused",
                now=now, actor=actor,
            )
        if current is None:
            return self._withhold_everything(
                None,
                "no_generation: nothing has been promoted, so there is no "
                "configuration to validate",
                now=now,
                actor=actor,
            )

        try:
            generation = self.generations.verify(current.number)
        except GenerationRefused as exc:
            return self._withhold_everything(
                current.number,
                f"generation_unverified: {exc}",
                now=now,
                actor=actor,
            )

        if lease is not None and lease.generation_number is not None and (
            lease.generation_number != generation.number
            or lease.commissioning_digest != generation.commissioning_digest
        ):
            return self._withhold_everything(
                generation.number,
                "lease_generation_binding_mismatch: approval names another generation or commissioning record",
                now=now, actor=actor,
            )

        verdicts: list[UnitVerdict] = []
        try:
            for definition in self.definitions:
                verdicts.append(
                    self._decide(definition, generation, record, now=now, actor=actor)
                )
        except AuditUnavailable:
            self._mask_all("audit_unavailable: the ledger could not record this "
                           "activation, so the activation does not happen")
            raise
        return ActivationOutcome(
            generation.number,
            tuple(verdicts),
            edge=self._edge,
            record=record,
            _enforcement_units=frozenset(
                d.name for d in self.definitions if d.tier is UnitTier.ENFORCEMENT
            ),
        )

    def _decide(
        self,
        definition: UnitDefinition,
        generation,
        record: Optional[CommissioningRecord],
        *,
        now: str,
        actor: str,
    ) -> UnitVerdict:
        withheld_because = self._withholding_reason(
            definition, record, generation.digest, generation.commissioning_digest,
            generation.commissioning_evidence_binding,
        )
        if withheld_because is not None:
            self.units.mask(definition.name, reason=withheld_because)
            self._record(
                "activation.unit_withheld",
                definition,
                generation,
                now=now,
                actor=actor,
                reason=withheld_because,
            )
            return UnitVerdict(definition.name, False, withheld_because)

        # The ledger entry is written **before** the unit is widened. If the
        # order were reversed, a crash between the two would leave a node
        # running a service with no record that it was ever granted; this way
        # a crash leaves a record of a grant that did not take effect, which
        # the next boot's revalidation corrects. An unrecorded widening is the
        # worse of the two, because nothing afterwards can discover it.
        self._record(
            "activation.unit_granted",
            definition,
            generation,
            now=now,
            actor=actor,
            reason=(
                "package-admitted: " + ",".join(EDGE_LAUNCH_CHECKS)
                + "; running not required; readiness not claimed"
                if definition.tier is UnitTier.EDGE_BASELINE
                else "verified generation, commissioning satisfied for this tier"
            ),
        )
        try:
            self.units.unmask_and_enable(
                definition.name,
                authorization=ActivationAuthorization(
                    unit=definition.name,
                    generation=generation.number,
                    digest=generation.digest,
                    mint=_MINT,
                ),
            )
        except AuditUnavailable:  # pragma: no cover - the controller never raises it here
            raise
        except Exception as exc:
            reason = f"activation_failed: {exc}"
            self._narrow(definition.name, reason)
            self._record(
                "activation.unit_failed",
                definition,
                generation,
                now=now,
                actor=actor,
                reason=reason,
            )
            return UnitVerdict(definition.name, False, reason)
        return UnitVerdict(definition.name, True, "granted")

    def _withholding_reason(
        self, definition: UnitDefinition, record: Optional[CommissioningRecord],
        generation_digest: str,
        commissioning_digest: str,
        commissioning_evidence_binding: Optional[str] = None,
    ) -> Optional[str]:
        """Per tier, in order of what each one adds to the one before it.

        Wiring comes first, ahead of even health. Every other reason here is
        something an operator can go and fix on this node; an unwired
        capability is a property of the build they installed, and no amount of
        fixing the node changes it. Reporting a fixable reason while an
        unfixable one also holds sends them to do work that will not help, and
        then tells them the real answer afterwards.
        """

        if definition.wiring is not None and definition.wiring not in self._wired:
            return (
                f"wiring_absent: this build has no {definition.wiring}, so "
                f"{definition.name} would start and exit. The unit, its "
                "account and its hardening ship; what it would serve does not"
            )

        # Required by every tier. A node that cannot answer for its own
        # health does not get to widen on the strength of not having noticed.
        if not self._healthy:
            return (
                "health_not_established: this node did not confirm its own "
                "health, and an unchecked node is not a healthy one"
            )
        lease_refusal = self._lease_refusal(generation_digest)
        if lease_refusal is not None:
            return lease_refusal

        if definition.tier is UnitTier.SUPPORTING:
            return None

        if definition.tier is UnitTier.EDGE_BASELINE:
            if self._edge is None:
                return (
                    "edge_unknown: nothing has established anything about a "
                    "local Edge Core. Unknown is not absent and neither is "
                    "ready (Nexus#44)"
                )
            if not self._edge.launchable:
                return "edge_not_ready: " + ",".join(self._edge.missing_for_launch())
            return None

        # ENFORCEMENT adds a complete commissioning record to all of the above.
        if (self._require_commissioning_evidence or commissioning_evidence_binding is not None
                or self._lease.commissioning_evidence_binding is not None
                or self._commissioning_evidence is not None):
            evidence = self._commissioning_evidence
            if type(evidence) is not CommissioningEvidence:
                return "commissioning_evidence_absent: full authenticated evidence is required"
            if (commissioning_evidence_binding is None
                    or evidence.binding != commissioning_evidence_binding
                    or self._lease.commissioning_evidence_binding != commissioning_evidence_binding):
                return "commissioning_evidence_binding_mismatch: evidence, generation and approval differ"
        # Full evidence is an additional prerequisite, not a conversion into
        # the legacy record or a replacement for its independent admission.
        if record is None:
            return (
                "commissioning_absent: no operator has confirmed what this node "
                "is attached to"
            )
        if self._commissioning_evidence is not None and not self._commissioning_evidence.matches_record(record):
            return "commissioning_evidence_record_mismatch: compatibility view differs from signed evidence"
        missing = record.missing_profiles
        if missing:
            return "commissioning_incomplete: missing profiles " + ",".join(missing)
        if record.observe_only:
            return (
                "commissioning_observe_only: every profile is present and no "
                "interface carries a confirmed role"
            )
        if record.digest() != commissioning_digest:
            return (
                "commissioning_generation_mismatch: this record is not the "
                "commissioning from which the verified generation was rendered"
            )
        return None

    def _lease_refusal(self, generation_digest: str) -> Optional[str]:
        if self._lease is None:
            return (
                "lease_absent: no operator has granted permission to activate "
                "this generation"
            )
        if not self._lease.valid_at(self._now):
            return (
                f"lease_expired: the lease ran from {self._lease.granted_at} to "
                f"{self._lease.expires_at} and it is now {self._now}"
            )
        if self._lease.generation_digest != generation_digest:
            return (
                "lease_generation_mismatch: permission was granted for another "
                "configuration, not the verified current generation"
            )
        return None

    def _withhold_everything(
        self, generation_number: Optional[int], reason: str, *, now: str, actor: str
    ) -> ActivationOutcome:
        self._mask_all(reason)
        self.ledger.append(
            {
                "event_type": "activation.refused",
                "generation": generation_number,
                "reason": reason,
                "units": [d.name for d in self.definitions],
                "occurred_at": now,
                "actor": actor,
            }
        )
        return ActivationOutcome(
            generation_number,
            tuple(UnitVerdict(d.name, False, reason) for d in self.definitions),
        )

    def _mask_all(self, reason: str) -> None:
        for definition in self.definitions:
            self._narrow(definition.name, reason)

    def _narrow(self, unit: str, reason: str) -> bool:
        """Mask, and never let a failure to mask escape this pass.

        Found by a test that made masking fail: the exception left `activate`
        entirely, so no outcome was returned, the remaining units were never
        decided, and **the units already widened by this pass stayed widened
        with nothing left running to take them back**. An exception on the
        narrowing path was propagating as a widening.

        So a failure here is recorded and the pass continues withholding. The
        caller is told by the verdict, and a runtime layer that can escalate
        (`azazel_nexus_runtime.activated`) does.
        """

        try:
            self.units.mask(unit, reason=reason)
            return True
        except Exception as exc:  # noqa: BLE001 - recorded, then reported
            self.unmaskable.add(unit)
            try:
                self.ledger.append(
                    {
                        "event_type": "activation.unit_would_not_mask",
                        "unit": unit,
                        "reason": reason,
                        "detail": f"{type(exc).__name__}: {exc}",
                    }
                )
            except AuditUnavailable:
                # The node is already as narrow as this component can make
                # it. Refusing to continue because the ledger is unavailable
                # would leave the rest of the units undecided as well.
                pass
            return False

    def _record(
        self,
        event_type: str,
        definition: UnitDefinition,
        generation,
        *,
        now: str,
        actor: str,
        reason: str,
    ) -> None:
        self.ledger.append(
            {
                "event_type": event_type,
                "unit": definition.name,
                "tier": definition.tier.value,
                "account": definition.account,
                "generation": generation.number,
                "digest": generation.digest,
                "reason": reason,
                "occurred_at": now,
                "actor": actor,
                **({"edge": self._edge.as_event()} if (
                    event_type == "activation.unit_granted"
                    and definition.tier is UnitTier.EDGE_BASELINE
                    and self._edge is not None
                ) else {}),
            }
        )


class Watchdog:
    """Fences what failed. Never restarts into a broader authority state (§4).

    The watchdog holds no mint and has no path to `unmask_and_enable`: the
    static scan in the tests asserts that this module's only reference to the
    widening verb is the controller's. So a watchdog that decides a masked
    unit ought to be running cannot act on that opinion -- re-granting is the
    controller's, against a revalidated generation, on the next boot.
    """

    def __init__(
        self,
        *,
        units: UnitController,
        ledger: AuditLedger,
        granted: Iterable[str],
    ) -> None:
        self.units = units
        self.ledger = ledger
        self._granted = frozenset(granted)
        self._fenced: set[str] = set()

    @property
    def fenced(self) -> frozenset[str]:
        return frozenset(self._fenced)

    def fence(self, unit: str, *, reason: str, now: str) -> None:
        """Narrowing. Always available, including when everything else is not."""

        self.units.mask(unit, reason=reason)
        self._fenced.add(unit)
        self.ledger.append(
            {
                "event_type": "watchdog.fenced",
                "unit": unit,
                "reason": reason,
                "occurred_at": now,
            }
        )

    def restart(self, unit: str, *, reason: str, now: str, perform: Callable[[], None]) -> None:
        """Restart a unit that activation already granted, and nothing else.

        Two refusals, and they are the same refusal seen from two sides:

        A unit activation withheld is not restarted into service. "Recovering"
        a unit that was never granted is a widening wearing the word recovery.

        A unit this watchdog fenced is not un-fenced by this watchdog. It
        lowered the node's capability for a reason it recorded; reversing that
        on its own judgement would make the fence advisory.
        """

        if unit not in self._granted:
            raise ActivationRefused(
                f"{unit!r} was not granted by activation, so the watchdog "
                "cannot restart it; that would be a widening, and the watchdog "
                "never restarts into a broader authority state"
            )
        if unit in self._fenced:
            raise ActivationRefused(
                f"{unit!r} is fenced. Returning it to service is the activation "
                "controller's decision against a revalidated generation, not "
                "the watchdog's"
            )
        try:
            perform()
        except BaseException as exc:
            self._fenced.add(unit)
            self.units.mask(
                unit, reason=f"restart_interrupted: {type(exc).__name__}: {exc}"
            )
            self.ledger.append(
                {
                    "event_type": "watchdog.restart_interrupted",
                    "unit": unit,
                    "reason": reason,
                    "detail": f"{type(exc).__name__}: {exc}",
                    "occurred_at": now,
                }
            )
            raise
        self.ledger.append(
            {
                "event_type": "watchdog.restarted",
                "unit": unit,
                "reason": reason,
                "occurred_at": now,
            }
        )
