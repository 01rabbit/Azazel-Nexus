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

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Optional, Sequence

from .audit import AuditLedger, AuditUnavailable
from .commissioning import CommissioningRecord
from .generation import GenerationRefused, GenerationStore

__all__ = [
    "ACTIVATION_CONTROLLER_UNIT",
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
    """What a unit needs before it may be granted.

    `BOOTSTRAP` units are how an uncommissioned node becomes commissioned and
    how it accounts for itself while it is: commissioning, the ledger, the
    watchdog. Requiring a completed commissioning before the daemon that
    performs commissioning may run would leave no path from an installed node
    to a commissioned one.

    `OPERATIONAL` units act on the network the operator confirmed, and are
    granted only against a complete commissioning record.
    """

    BOOTSTRAP = "bootstrap"
    OPERATIONAL = "operational"


@dataclass(frozen=True)
class UnitDefinition:
    """One unit this controller governs."""

    name: str
    tier: UnitTier
    account: str
    purpose: str

    def __post_init__(self) -> None:
        if not self.name.endswith(".service"):
            raise ActivationRefused(f"{self.name!r} is not a service unit name")
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


#: The governed set for the CORE slice.
#:
#: The enforcement, M.I.O., Knowledge Lite, Deception Lite and module-manager
#: units are absent because they belong to slices that are not built yet --
#: **not** because they are optional to the product. `docs/roadmap.md` holds
#: what is still owed; this tuple holds what exists.
CORE_UNITS = (
    UnitDefinition(
        "azazel-commissiond.service",
        UnitTier.BOOTSTRAP,
        "root",
        "read-only inventory, operator confirmation, commissioning record",
    ),
    UnitDefinition(
        "azazel-auditd.service",
        UnitTier.BOOTSTRAP,
        "root",
        "hash-chain ledger; refuses chain discontinuity",
    ),
    UnitDefinition(
        "azazel-watchdog.service",
        UnitTier.BOOTSTRAP,
        "root",
        "degradation coordinator; never restarts into a broader authority state",
    ),
)


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
    generation: Optional[int]
    verdicts: tuple[UnitVerdict, ...]

    @property
    def granted(self) -> tuple[str, ...]:
        return tuple(v.unit for v in self.verdicts if v.granted)

    @property
    def withheld(self) -> tuple[str, ...]:
        return tuple(v.unit for v in self.verdicts if not v.granted)


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

    def activate(
        self,
        *,
        now: str,
        actor: str,
        record: Optional[CommissioningRecord] = None,
    ) -> ActivationOutcome:
        """Run one activation pass. Called on every boot.

        The digest is re-derived here, every time. There is no cached verdict
        to consult, because a cached verdict is a statement about the tree at
        the moment it was cached.

        On any failure to establish a verified generation, every governed unit
        is masked and nothing is granted -- the node ends in the state the
        installer left it in rather than in whatever state the previous boot
        happened to reach.
        """

        current = self.generations.current()
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
        return ActivationOutcome(generation.number, tuple(verdicts))

    def _decide(
        self,
        definition: UnitDefinition,
        generation,
        record: Optional[CommissioningRecord],
        *,
        now: str,
        actor: str,
    ) -> UnitVerdict:
        withheld_because = self._withholding_reason(definition, record)
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
            reason="verified generation, commissioning satisfied for this tier",
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
            self.units.mask(definition.name, reason=reason)
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

    @staticmethod
    def _withholding_reason(
        definition: UnitDefinition, record: Optional[CommissioningRecord]
    ) -> Optional[str]:
        if definition.tier is UnitTier.BOOTSTRAP:
            return None
        if record is None:
            return (
                "commissioning_absent: no operator has confirmed what this node "
                "is attached to"
            )
        missing = record.missing_profiles
        if missing:
            return "commissioning_incomplete: missing profiles " + ",".join(missing)
        if record.observe_only:
            return (
                "commissioning_observe_only: every profile is present and no "
                "interface carries a confirmed role"
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
            self.units.mask(definition.name, reason=reason)

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
