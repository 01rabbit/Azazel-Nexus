"""`az-activated`: the only component that may widen what this node runs (#39).

The decision is the library's. `azazel_nexus.activation.ActivationController`
checks the verified generation, the lease, health and the commissioning
record, and decides per tier. This daemon carries that out against a service
manager, and adds the one thing a decision cannot have: **a rollback**.

## Activation is a transaction

A pass that enables three units and fails on the fourth has left the node in a
state nobody chose. Either the whole set is granted or none of it is, so a
failure re-masks everything this pass widened -- including the units that
succeeded -- and requires a positive inactive-state observation. Masking does
not stop an already running service. Without reviewed stop authority, such a
service produces an explicit containment failure, not a successful rollback.
An inactive observation is not proof of continuing inactivity or an empty
cgroup; supervision and job/lifetime guarantees remain separate gates.

Rolling *forward* is not available. The failure means the service manager did
not do what it was asked, and a component that responds to that by asking for
more is a component that has stopped believing its own error handling.

## If the rollback itself fails

It narrows further: mask everything governed, not just what this pass
touched. The direction is the invariant. There is no failure of a rollback
that is answered by widening.

## What it does not have

No shell. No command line. No unit name, path, argument or environment from a
caller. Units are addressed by a key from `units.UNIT_NAMES`, which is a
lookup and not an interpolation.

Protected per-boot bootstrap selection routes to the supporting-only
BootstrapSupervisor under one retained transaction lock. Selection expresses
intent, not approval; invalid selection never falls back to ordinary activation.
Only confirmed absence retains the ordinary path. Public bootstrap opening and
start gates remain refusing pending their separate admission obligations.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from azazel_nexus.activation import (
    ARTIFACT_TRANSPORT,
    LOCAL_MODEL_PROVIDER,
    REMOTE_INFERENCE_TRANSPORT,
    ActivationController,
    ActivationLease,
    ActivationOutcome,
    CORE_UNITS,
    EdgeBaselineState,
    UnitController,
    UnitDefinition,
    UnitState,
)
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.commissioning import CommissioningRecord
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.generation import GenerationStore
from azazel_nexus.hil_preflight import read_boot_id
from azazel_nexus.operator_store import load_operator_trust

from azazel_nexus.model_runtime import RUNTIMES

from .mio_remoted import TRANSPORT
from .model_fetch import ENDPOINT_FOR
from .units import DbusUnitManager, UnitManager, UnitOperationFailed
from .node_config import load_declared_node
from .commissioning_input import load_commissioning_evidence

__all__ = [
    "ActivationDaemon",
    "ManagedUnitController",
    "RollbackFailed",
    "wired_capabilities",
]


# One process-local entry: retain only metadata and a boolean, never key material.
_fetch_validation_cache: tuple[tuple, bool] | None = None


def _fetch_commissioned(directory: Path) -> bool:
    from .model_fetch import FETCH_COMMISSIONING_FILES, load_fetch_commissioning

    global _fetch_validation_cache

    def snapshot():
        result = []
        for name in FETCH_COMMISSIONING_FILES:
            path = directory.absolute() / name
            # Include the link itself as well as its target: a dangling optional
            # client identity must not look like an absent one on a cache hit.
            for reader in (path.lstat, path.stat):
                try:
                    info = reader()
                    result.append((str(path), info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
                except FileNotFoundError:
                    result.append((str(path), None, None, None))
        return tuple(result)

    try:
        before = snapshot()
        cached = _fetch_validation_cache
        if cached is not None and cached[0] == before:
            return cached[1]
        valid = False
        try:
            load_fetch_commissioning(directory)
            valid = True
        except Exception:  # noqa: BLE001 - incomplete validation is not wiring evidence
            valid = False
        if snapshot() != before:
            _fetch_validation_cache = None
            return False
        _fetch_validation_cache = (before, valid)
        return valid
    except OSError:
        _fetch_validation_cache = None
        return False


def wired_capabilities() -> frozenset:
    """What this **installed distribution** can actually serve.

    The library decides whether a unit may be granted and cannot answer this:
    what is wired is a fact about the runtime distribution, which the library
    is forbidden to import. So it is read here, from the thing itself, and
    passed in as evidence.

    Artifact transport requires a nonempty legacy endpoint table or fully
    loadable fetch commissioning. Merely having a signed registry is insufficient.
    A fresh node has neither and keeps the unit withheld.
    """

    wired = set()
    from .runtime_paths import fetch_commission_dir

    commissioned = _fetch_commissioned(fetch_commission_dir())
    if ENDPOINT_FOR or commissioned:
        wired.add(ARTIFACT_TRANSPORT)
    if RUNTIMES:
        wired.add(LOCAL_MODEL_PROVIDER)
    if TRANSPORT is not None:
        wired.add(REMOTE_INFERENCE_TRANSPORT)
    return frozenset(wired)


class RollbackFailed(Exception):
    """The node could not be returned to the state it started the pass in."""


def _mask_and_confirm_inactive(manager: UnitManager, unit: str) -> None:
    """Prevent future starts; refuse to equate that with stopping a process.

    This observation grants no StartUnit/StopUnit authority and is not a
    lifetime guarantee. Unknown or transitional activity is not containment.
    """
    manager.mask(unit)
    if manager.is_inactive(unit) is not True:
        raise UnitOperationFailed("masked unit has no confirmed inactive state")


class ManagedUnitController(UnitController):
    """Bridges the library's controller to a `UnitManager`.

    The library defines `unmask_and_enable` as the guarded entry point and
    forbids a subclass from overriding it; this implements the two unguarded
    verbs beneath it and records what it widened, so a failed pass knows what
    to take back.
    """

    def __init__(self, manager: UnitManager) -> None:
        self.manager = manager
        self.widened: list[str] = []

    def state(self, unit: str) -> UnitState:
        return self.manager.state(unit)

    def _mask(self, unit: str) -> None:
        _mask_and_confirm_inactive(self.manager, unit)

    def _unmask_and_enable(self, unit: str) -> None:
        # Recorded before the call, not after. A call that fails part way
        # through has still changed something, and a rollback that only knows
        # about calls that returned cleanly would leave exactly that behind.
        self.widened.append(unit)
        self.manager.unmask_and_enable(unit)


@dataclass
class ActivationDaemon:
    """One activation pass per boot, with the rollback the decision cannot have."""

    generations: GenerationStore
    ledger: AuditLedger
    manager: UnitManager
    definitions: Sequence[UnitDefinition] = CORE_UNITS

    def activate(
        self,
        *,
        now: str,
        actor: str,
        lease: Optional[ActivationLease] = None,
        record: Optional[CommissioningRecord] = None,
        edge: Optional[EdgeBaselineState] = None,
        healthy: bool = True,
        wired: Optional[Sequence[str]] = None,
        commissioning_evidence: Optional[CommissioningEvidence] = None,
        require_commissioning_evidence: bool = False,
    ) -> ActivationOutcome:
        units = ManagedUnitController(self.manager)
        controller = ActivationController(
            units=units,
            generations=self.generations,
            ledger=self.ledger,
            definitions=self.definitions,
        )
        try:
            outcome = controller.activate(
                now=now,
                actor=actor,
                lease=lease,
                record=record,
                edge=edge,
                healthy=healthy,
                commissioning_evidence=commissioning_evidence,
                require_commissioning_evidence=require_commissioning_evidence,
                # `None` means "ask the distribution", which is what a node
                # does. A caller may pass a set to exercise a build other than
                # this one; it may not pass one to widen this one, because the
                # unit still starts nothing.
                wired=wired_capabilities() if wired is None else wired,
            )
        except AuditUnavailable:
            # The library attempts to narrow before it raises, but a failed
            # mask plus an unavailable ledger must not skip this layer's
            # broader fail-closed escalation.
            if controller.unmaskable:
                failures = self._remask_all(
                    now=now,
                    actor=actor,
                    event_type="activation.audit_failure_remasked",
                    error_type="AuditUnavailable",
                )
                if failures:
                    raise RollbackFailed(
                        "audit became unavailable while narrowing failed; these "
                        f"governed units lack confirmed containment: {sorted(failures)}"
                    )
            raise
        except Exception as exc:  # noqa: BLE001 - unexpected policy failure narrows
            failures = self._remask_all(
                now=now,
                actor=actor,
                event_type="activation.composition_failed",
                error_type=type(exc).__name__,
            )
            if failures:
                raise RollbackFailed(
                    "an unexpected activation error occurred and these governed "
                    f"units lack confirmed containment: {sorted(failures)}"
                ) from exc
            raise
        if controller.unmaskable:
            # The library could not narrow something. It recorded that and
            # kept withholding rather than letting the exception leave the
            # pass -- which is what would have stranded the units already
            # widened. Escalating is this layer's half.
            self._narrow_everything(
                now=now, actor=actor, after=sorted(controller.unmaskable)
            )
        if any(
            not verdict.granted and _is_failure(verdict) for verdict in outcome.verdicts
        ):
            self._roll_back(units, now=now, actor=actor, outcome=outcome)
        return outcome

    def _remask_all(
        self, *, now: str, actor: str, event_type: str, error_type: str
    ) -> list[str]:
        """Retry narrowing of every governed unit and record the attempt."""

        failures: list[str] = []
        for definition in self.definitions:
            try:
                _mask_and_confirm_inactive(self.manager, definition.name)
            except Exception as exc:  # noqa: BLE001 - collect all failures
                failures.append(f"{definition.name}: {type(exc).__name__}")
        self._record(
            {
                "event_type": event_type,
                "error_type": error_type,
                "remask_failures": sorted(failures),
                "occurred_at": now,
                "actor": actor,
            }
        )
        return failures

    def _roll_back(
        self,
        units: ManagedUnitController,
        *,
        now: str,
        actor: str,
        outcome: ActivationOutcome,
    ) -> None:
        """Re-mask everything this pass widened. All of it, including successes."""

        taken_back: list[str] = []
        failures: list[str] = []
        for unit in units.widened:
            try:
                _mask_and_confirm_inactive(self.manager, unit)
                taken_back.append(unit)
            except Exception as exc:  # noqa: BLE001 - recorded below, then escalated
                failures.append(f"{unit}: {exc}")

        self._record(
            {
                "event_type": "activation.rolled_back",
                "widened": sorted(units.widened),
                "masked_again": sorted(taken_back),
                "could_not_mask": sorted(failures),
                "occurred_at": now,
                "actor": actor,
            }
        )
        if failures:
            self._narrow_everything(now=now, actor=actor, after=failures)

    def _narrow_everything(self, *, now: str, actor: str, after: Sequence[str]) -> None:
        """A rollback that failed is answered by narrowing further, never less.

        Every governed unit, not only the ones this pass touched. The
        direction is the invariant: there is no failure here whose answer is
        to widen.
        """

        unreachable: list[str] = []
        for definition in self.definitions:
            try:
                _mask_and_confirm_inactive(self.manager, definition.name)
            except Exception as exc:  # noqa: BLE001
                unreachable.append(f"{definition.name}: {exc}")
        self._record(
            {
                "event_type": "activation.rollback_failed",
                "after": sorted(after),
                "still_unreachable": sorted(unreachable),
                "occurred_at": now,
                "actor": actor,
            }
        )
        raise RollbackFailed(
            "the node could not be returned to the state it started this pass "
            f"in; {sorted(after)} would not mask, and {sorted(unreachable)} "
            "did not respond to the wider narrowing either"
        )

    def _record(self, event: dict) -> None:
        try:
            self.ledger.append(event)
        except AuditUnavailable:
            # The narrowing has already happened. Refusing to narrow because
            # the ledger is unavailable would mean the node stays wide while
            # nobody can write down that it should not be.
            pass


def _is_failure(verdict) -> bool:
    """A unit that was tried and failed, as opposed to one withheld by policy.

    A withheld unit is the decision working. A failed one is the service
    manager not doing what it was asked, and only the second calls for a
    rollback.
    """

    return verdict.reason.startswith("activation_failed")


def _collect_input_status(root: Path) -> dict[str, str]:
    """Read real prerequisites without publishing identities or granting trust.

    Collection follows narrowing, so any reader failure cannot strand a
    previously enabled service. Staged-root tests never inspect host inputs.
    These observations are diagnostic, not an ActivationContext or health.
    """
    if root != Path("/"):
        return {key: "not_collected_staged_root" for key in ("operator_trust", "boot", "declared_node")}
    result = {}
    try:
        load_declared_node()
        result["declared_node"] = "protected_declaration_only"
    except Exception:  # noqa: BLE001 - no parser diagnostics or identity enter audit
        result["declared_node"] = "unavailable_or_refused"
    try:
        trust = load_operator_trust()
        result["operator_trust"] = (
            "active_keys_present" if set(trust.public_keys) - trust.revoked else "no_active_keys"
        )
    except Exception:  # noqa: BLE001 - reader failure is absent evidence, never a grant
        result["operator_trust"] = "unavailable_or_refused"
    try:
        boot_id = read_boot_id()
        result["boot"] = "observed" if type(boot_id) is str and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id
        ) else "unavailable_or_invalid"
    except Exception:  # noqa: BLE001 - never include raw reader exceptions/identity in audit
        result["boot"] = "unavailable_or_invalid"
    return result


def _run_once(
    *, manager: UnitManager, root: Path, now: str, actor: str
) -> ActivationOutcome:
    """Compose the existing decision engine with fixed persistent paths.

    Full commissioning evidence is loaded after mandatory narrowing. Production
    readers for the lease, measured health and Edge baseline are still absent.
    Those remain
    explicit absences, not guessed values or data loaded from unauthenticated
    files. ``healthy=False`` is important: the library API's test-friendly
    default is not evidence a production daemon may inherit.
    """

    state = root / "var/lib/azazel/state"
    daemon = ActivationDaemon(
        generations=GenerationStore(root / "var/lib/azazel/generations"),
        ledger=AuditLedger(state / "activation.jsonl"),
        manager=manager,
        definitions=CORE_UNITS,
    )
    failures = daemon._remask_all(now=now, actor=actor,
        event_type="activation.evidence_preflight_masked", error_type="preflight")
    if failures:
        daemon._narrow_everything(now=now, actor=actor, after=failures)
    evidence = None
    if root == Path("/"):
        try:
            evidence = load_commissioning_evidence()
        except Exception:  # noqa: BLE001 - evidence failure never bypasses the refusing pass
            evidence = None
    outcome = daemon.activate(
        now=now,
        actor=actor,
        lease=None,
        record=None,
        edge=None,
        healthy=False,
        wired=wired_capabilities(),
        commissioning_evidence=evidence,
        require_commissioning_evidence=True,
    )
    if outcome.granted:
        # Full commissioning evidence does not supply a lease or node health.
        # A grant here would mean a future change silently supplied authority.
        failures: list[str] = []
        for definition in CORE_UNITS:
            try:
                _mask_and_confirm_inactive(manager, definition.name)
            except Exception as exc:  # noqa: BLE001 - fail closed on invariant break
                failures.append(f"{definition.name}: {type(exc).__name__}")
        raise RuntimeError(
            "production activation composed without lease/health admission evidence "
            "but the decision engine granted a unit; emergency remask failures: "
            f"{sorted(failures)}"
        )
    # Do not gather optional diagnostic inputs before mandatory narrowing.
    # Merely loading an enrolled key or observing a boot is not admission.
    inputs = _collect_input_status(root)
    inputs["full_commissioning"] = "verified_current_binding" if evidence is not None else "unavailable"
    missing = [
        "authoritative_commissioning_admission", "activation_approval_loader",
        "node_identity", "activation_policy", "renderer_measurement",
        "epoch_high_water", "trusted_clock", "node_health", "edge_evidence",
    ]
    if evidence is None:
        missing.extend(("authenticated_commissioning", "inventory_binding"))
    daemon.ledger.append({
        "event_type": "activation.inputs_incomplete",
        "observed_inputs": inputs,
        "missing_producers": missing,
        "generation": outcome.generation,
        "occurred_at": now,
        "actor": actor,
    })
    return outcome


def _narrow_bootstrap_core_units():
    """Fixed broad mask/inactivity pass; no ordinary admission attempt."""
    from .systemd_bus import SystemdBusSession

    failures = []
    with SystemdBusSession.connect() as session:
        manager = DbusUnitManager(call=session)
        for definition in CORE_UNITS:
            try:
                _mask_and_confirm_inactive(manager, definition.name)
            except Exception:
                failures.append(definition.name)
    if failures:
        raise UnitOperationFailed("bootstrap initial/emergency narrowing unconfirmed")


# Reviewed static messages of the bootstrap path (see
# tests/unit/test_runtime_activated_entrypoint.py, which keeps this exactly equal
# to the literal raises in the listed modules). Only these are ever logged.
_STATIC_FAILURE_MESSAGES = frozenset({
    'additional controller command refused',
    'admitted resource thresholds required',
    'audit binding admission unconfirmed',
    'audit chain evidence unavailable',
    'audit chain not intact after containment',
    'audit start admission unconfirmed',
    'audit start controller context changed',
    'audit start transaction differs from publication',
    'auditd grant-intent receipt differs from live writer head',
    'auditd grant-intent receipt required',
    'bootstrap admission cannot be renewed',
    'bootstrap audit continuation invalid',
    'bootstrap bus session cleanup failed',
    'bootstrap bus tasks did not quiesce',
    'bootstrap bus teardown budget exhausted',
    'bootstrap capacity prerequisite refused',
    'bootstrap cgroup composition unavailable',
    'bootstrap cgroup root changed',
    'bootstrap cgroup root identity changed',
    'bootstrap cgroup root unavailable',
    'bootstrap completion unconfirmed',
    'bootstrap dependency policy refused',
    'bootstrap deployment fencing unavailable; widening refused',
    'bootstrap deployment start-job fence unavailable',
    'bootstrap elapsed clock invalid or expired',
    'bootstrap elapsed clock moved backward',
    'bootstrap elapsed deadline expired',
    'bootstrap executable, arguments or flags changed',
    'bootstrap execution metadata malformed',
    'bootstrap helper readiness lost',
    'bootstrap inactivity fence unavailable',
    'bootstrap inactivity fragment unavailable',
    'bootstrap kernel deadline release unconfirmed',
    'bootstrap kernel deadline unconfirmed',
    'bootstrap loaded closure changed',
    'bootstrap manager unit outside exact pair',
    'bootstrap mount revalidation unconfirmed',
    'bootstrap operation requires its owned idle loop',
    'bootstrap operation session cleanup failed',
    'bootstrap owned closure changed',
    'bootstrap owned grant withdrawal unavailable',
    'bootstrap owned pair grant unavailable; widening refused',
    'bootstrap owned withdrawal unconfirmed',
    'bootstrap pair grant completion unconfirmed',
    'bootstrap positive dependencies must be ordered before helper',
    'bootstrap prestart observation required',
    'bootstrap restoration cgroup identity changed',
    'bootstrap restoration journal unconfirmed',
    'bootstrap restoration owner changed',
    'bootstrap restoration reload unconfirmed',
    'bootstrap restoration unconfirmed',
    'bootstrap restore requires a fresh transaction',
    'bootstrap restored fence changed',
    'bootstrap restored masks unconfirmed',
    'bootstrap selection changed before composition',
    'bootstrap selection changed during initial narrowing',
    'bootstrap start cancelled',
    'bootstrap start completion unconfirmed',
    'bootstrap start elapsed clock invalid or expired',
    'bootstrap start unit refused',
    'bootstrap supervisor cannot restart a consumed session',
    'bootstrap transaction close was not fully recorded',
    'bootstrap transaction identity differs from admission',
    'bootstrap transaction identity required for grant withdrawal',
    'bootstrap transaction identity required for pair grant',
    'bootstrap transaction not held',
    'bootstrap transaction requires recovery',
    'bootstrap transaction validator required',
    'bootstrap unpublished baseline changed',
    'commission start admission unconfirmed',
    'commission start context changed',
    'commission start differs from publication',
    'controller ActiveState malformed',
    'controller READY admission unconfirmed',
    'controller READY barrier not confirmed',
    'controller READY completion unconfirmed',
    'controller READY context expired or changed',
    'controller READY local identity changed',
    'controller READY notification unconfirmed',
    'controller executable or arguments changed',
    'controller execution metadata malformed',
    'controller fixed ExecStartEx required',
    'controller identity changed between snapshots',
    'controller inspection requires a fresh session',
    'controller job is not idle',
    'controller job list exceeds budget',
    'controller job list malformed',
    'controller job row malformed',
    'controller observation owner changed',
    'controller one-use start condition refused',
    'controller property collection refused',
    'controller property signature refused',
    'controller property value refused',
    'controller service identity differs',
    'controller service property reply shape refused',
    'controller start job identity refused',
    'controller systemd profile changed',
    'controller unit object changed',
    'controller unit phase or identity refused',
    'controller unit property reply shape refused',
    'controller watchdog elapsed deadline refused',
    'controller watchdog notification unconfirmed',
    'controller watchdog progress not admitted',
    'current boot id refused',
    'durable bootstrap transaction unavailable',
    'durable bootstrap transaction update unconfirmed',
    'durably retained bootstrap deadline required',
    'enclosing systemd owner changed',
    'enclosing systemd owner changed before loaded inspection',
    'existing bootstrap transaction requires manual review',
    'explicit positive resource floors required',
    'fresh audit binding and checkpoint required',
    'fresh retained audit start context required',
    'fresh retained commission start context required',
    'held publication transaction required',
    'independent complete dependency projection required',
    'independently admitted bootstrap generation required',
    'invalid supervision stop observation',
    'loaded bootstrap dependencies differ',
    'loaded bootstrap object changed',
    'loaded bootstrap observation refused',
    'loaded bootstrap observation refused: dependencies',
    'loaded bootstrap observation refused: service property',
    'loaded bootstrap observation refused: service property WatchdogUSec',
    'loaded bootstrap observation refused: unit property',
    'loaded bootstrap property mismatch',
    'loaded bootstrap property unavailable',
    'loaded property collection refused',
    'loaded unit changed during inspection',
    'loaded-unit inspection outside exact pair',
    'loaded-unit inspection requires fresh session',
    'login environment policy malformed',
    'manager stop evidence unavailable',
    'only the fixed system bus socket is admitted',
    'owned bootstrap closure unavailable',
    'pinned system bus client unavailable',
    'prior boot grant identity differs from journal',
    'prior boot journal retirement unavailable',
    'protected bootstrap grant store required',
    'publication admission unconfirmed',
    'publication composition unavailable',
    'publication controller observation changed',
    'publication initial containment changed',
    'publication loaded policy changed',
    'publication local controller identity changed',
    'publication manager owner changed',
    'publication manager owner required',
    'publication prerequisite observations changed',
    'publication reload unconfirmed',
    'publication start closure changed',
    'publication systemd profile changed',
    'resource floor not met',
    'resource measurements malformed',
    'resource observations incomplete',
    'retained audit peer binding unavailable',
    'retained bootstrap deadline differs from verified approval',
    'retained commission peer binding unavailable',
    'retained controller READY context required',
    'retained controller binding changed',
    'retained controller observation changed',
    'retained owner and start checkpoint required',
    'retained publication admission changed',
    'retained publication admission unavailable',
    'retained publication controller changed',
    'retained publication manager changed',
    'retained publication policy changed',
    'retained publication prerequisites changed',
    'retained publication profile changed',
    'retained publication start closure changed',
    'retained start intent changed',
    'service timer policy malformed',
    'single fixed bootstrap command required',
    'stop root differs from admitted cgroup mount',
    'stopped audit head unavailable',
    'systemd compatibility profile was not admitted',
    'systemd did not report the governed unit as enabled',
    'systemd did not report the governed unit as masked',
    'systemd owner changed during inspection',
    'systemd returned an invalid active-state result',
    'systemd returned an invalid inactivity result',
    'systemd returned an unknown unit-file state',
    'the service manager was asked about a unit outside the fixed Nexus allowlist',
    'unreviewed system bus client version',
    'verified bootstrap admission required',
    'verified bootstrap approval required',
    'withdrawal final mask changed',
    'withdrawal loaded mask changed',
    'withdrawal manager owner changed',
    'withdrawal manager profile changed',
    'withdrawal reload unconfirmed',
})


def _failure_label(exc: BaseException) -> str:
    """Class name, plus the message only when it is a reviewed static literal.

    Exactly ApprovalRefused or UnitOperationFailed (no subclasses), one
    argument, and membership in the allowlist. Anything else (other classes,
    subclasses, interpolated or unreviewed messages) stays class-only.
    """

    from azazel_nexus.operator_trust import ApprovalRefused

    from .units import UnitOperationFailed

    name = type(exc).__name__
    if type(exc) not in (ApprovalRefused, UnitOperationFailed) or len(exc.args) != 1:
        return name
    message = exc.args[0]
    if type(message) is str and message in _STATIC_FAILURE_MESSAGES:
        return f"{name}: {message}"
    return name


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run one fail-closed activation pass against systemd's system bus.

    A zero exit status means the pass completed and its decision was recorded;
    it does **not** mean any unit was granted. Full commissioning evidence may
    be available, but lease, authoritative admission and health producers remain
    absent, so this composition cannot widen a unit.
    """

    if argv is None:
        argv = sys.argv[1:]
    if argv:
        print("az-activated accepts no command-line arguments", file=sys.stderr)
        return 2
    from .runtime_paths import ROOT

    invocation_id = os.environ.get("INVOCATION_ID", "")
    if (
        os.geteuid() != 0
        or not Path("/run/systemd/system").is_dir()
        or not re.fullmatch(r"[0-9a-fA-F]{32}", invocation_id)
        or ROOT != Path("/")
    ):
        print(
            "az-activated requires its root systemd service context and fixed "
            "host paths",
            file=sys.stderr,
        )
        return 1

    from .systemd_bus import SystemdBusSession

    now = (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    try:
        from azazel_nexus.bootstrap_selection_optional import load_optional_bootstrap_selection

        try:
            selected = load_optional_bootstrap_selection()
        except Exception as primary:
            from .bootstrap_entrypoint import narrow_invalid_selection
            narrow_invalid_selection(primary, narrow=_narrow_bootstrap_core_units)
            raise
        if selected is not None:
            from .bootstrap_entrypoint import run_selected_bootstrap
            result = run_selected_bootstrap(selected, narrow=_narrow_bootstrap_core_units)
            if getattr(result, "stopping_record", "recorded") == "absent-manager-stop":
                print("az-activated supporting bootstrap stopped by manager after "
                      "helpers; stopping record unavailable")
                return 0
            print("az-activated supporting bootstrap stopped after confirmed containment")
            return 0
        with SystemdBusSession.connect() as session:
            manager = DbusUnitManager(call=session)
            outcome = _run_once(
                manager=manager,
                root=Path("/"),
                now=now,
                actor="azazel-activated",
            )
    except Exception as exc:  # noqa: BLE001 - the service boundary fails closed
        from .bootstrap_entrypoint import EMERGENCY_UNCONFIRMED
        if EMERGENCY_UNCONFIRMED in getattr(exc, "__notes__", ()):
            print("az-activated emergency narrowing unconfirmed", file=sys.stderr)
        print(
            f"az-activated failed before completing a safe pass: {_failure_label(exc)}",
            file=sys.stderr,
        )
        return 1

    reasons = sorted({verdict.reason.split(":", 1)[0] for verdict in outcome.verdicts})
    print(
        f"az-activated completed safely: granted=0, "
        f"withheld={len(outcome.withheld)}, reasons={','.join(reasons)}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
