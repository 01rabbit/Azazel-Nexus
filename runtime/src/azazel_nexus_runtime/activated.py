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
The one exception is the Knowledge Context broker: the controller holds a
separate, fixed authority to stop that unit alone (`units.ContextdStopAuthority`,
`activation_withdraw.withdraw_contextd`), used when its grant is withdrawn.
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

import contextlib
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from azazel_nexus.activation import (
    ARTIFACT_TRANSPORT,
    CORE_UNITS,
    DECEPTION_EXPOSURE_UNITS,
    REMOTE_INFERENCE_TRANSPORT,
    ActivationController,
    ActivationLease,
    ActivationOutcome,
    EdgeBaselineState,
    UnitController,
    UnitDefinition,
    UnitState,
)
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.commissioning import CommissioningRecord
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.edge_package import (
    EDGE_UNIT as EDGE_CORE_UNIT,
    installed_baseline_state,
    nothing_established,
)
from azazel_nexus.generation import GenerationStore
from azazel_nexus.hil_preflight import COMMISSIONING_DIR, luks_backing, read_boot_id
from azazel_nexus.operator_store import load_operator_trust

from .commissioning_input import load_commissioning_evidence
from .mio_remoted import TRANSPORT
from .model_fetch import ENDPOINT_FOR
from .node_config import load_declared_node
from .activation_markers import GRANTABLE_UNITS, reset_grant_markers, write_grant_markers
from .activation_budget import PassBudgetExpired, bind_remaining, check_budget
from .activation_retire import (
    RetireRefused, read_accepted_grant, retirement_pending, write_accepted_grant,
)
from .activation_lock import PassLockBusy, PassLockRefused, acquire_pass_lock
from .activation_withdraw import (
    WithdrawalUnconfirmed,
    QueuedJobState,
    clear_contextd_job,
    contextd_already_withdrawn,
    contextd_is_running,
    contextd_start_is_queued,
    release_queued_job,
    withdraw_contextd,
)
from .units import (
    CONTEXTD_UNIT,
    ContextdStopAuthority,
    DbusUnitManager,
    UnitManager,
    UnitOperationFailed,
)

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
    A fresh node has neither and keeps the unit withheld. Local model wiring
    requires independently verified embedding evidence. Wiring never supplies
    a lease or health; those come from the pass's own producers (#206).
    """

    wired = set()
    from .runtime_paths import fetch_commission_dir

    commissioned = _fetch_commissioned(fetch_commission_dir())
    if ENDPOINT_FOR or commissioned:
        wired.add(ARTIFACT_TRANSPORT)
    from azazel_nexus.activation import LOCAL_MODEL_PROVIDER

    from .model_admission_evidence import (
        MAX_SNAPSHOT_RETRIES,
        Admitted,
        decide_embedding_admission,
        fingerprint,
    )

    for _ in range(MAX_SNAPSHOT_RETRIES):
        reading = decide_embedding_admission(now=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
        try:
            if type(reading.embedding) is not Admitted:
                break
            if reading.snapshot and fingerprint(reading.watch_paths) == reading.snapshot:
                wired.add(LOCAL_MODEL_PROVIDER)
                break
        finally:
            reading.close()
    if TRANSPORT is not None:
        wired.add(REMOTE_INFERENCE_TRANSPORT)
    return frozenset(wired)


class RollbackFailed(Exception):
    """The node could not be returned to the state it started the pass in."""


def _mask_and_confirm_inactive(manager: UnitManager, unit: str, withdrawn=None,
                               before_mask=None) -> None:
    """Prevent future starts; refuse to equate that with stopping a process.

    This observation grants no StartUnit/StopUnit authority and is not a
    lifetime guarantee. Unknown or transitional activity is not containment.
    `withdrawn` (the Knowledge Context broker only) says the unit is the one
    already-withdrawn `failed` shape, which is accepted here instead of being a
    containment failure: nothing runs and nothing can start it.
    """
    if unit == CONTEXTD_UNIT and before_mask is not None:
        # A start job the pass is still holding for the broker is replaced
        # first: the mask and the reload after it would make systemd fail it.
        before_mask()
    manager.mask(unit)
    if manager.is_inactive(unit) is not True:
        if unit == CONTEXTD_UNIT and withdrawn is not None and withdrawn():
            return
        raise UnitOperationFailed("masked unit has no confirmed inactive state")


#: Bound on a reason recorded by `_unit_failure`; longer text is not a fixed reason.
_UNIT_FAILURE_REASON_LIMIT = 120


def _unit_failure(unit: str, exc: BaseException) -> str:
    """``"<unit>: <reason>"`` for the ledger: the unit and a fixed reason only.

    The reason is the message only of an exact ``UnitOperationFailed`` whose
    one argument is a string of printable ASCII, at most
    ``_UNIT_FAILURE_REASON_LIMIT`` characters; the D-Bus client translates
    every bus failure into that class with a fixed (or method-name) message.
    Any other exception, or a message outside those bounds, is recorded by
    its class name, as ``_remask_all`` already does, so no text an exception
    happens to carry (a path, a peer's error text) reaches the activation
    ledger, and a ``__str__`` that itself raises cannot leave this narrowing
    before its record (#251 M-5).

    Ledger lines written before #251 M-5 (``still_unreachable`` of
    ``activation.rollback_failed``, ``could_not_mask`` of
    ``activation.rolled_back``) recorded ``str(exc)`` and may hold free text.
    """
    if type(exc) is UnitOperationFailed and len(exc.args) == 1:
        reason = exc.args[0]
        if (type(reason) is str and 0 < len(reason) <= _UNIT_FAILURE_REASON_LIMIT
                and all(" " <= char <= "~" for char in reason)):
            return f"{unit}: {reason}"
    return f"{unit}: {type(exc).__name__}"


class ManagedUnitController(UnitController):
    """Bridges the library's controller to a `UnitManager`.

    The library defines `unmask_and_enable` as the guarded entry point and
    forbids a subclass from overriding it; this implements the two unguarded
    verbs beneath it and records what it widened, so a failed pass knows what
    to take back.
    """

    def __init__(self, manager: UnitManager, withdrawn=None, before_mask=None) -> None:
        self.manager = manager
        self.widened: list[str] = []
        self.withdrawn = withdrawn
        self.before_mask = before_mask

    def state(self, unit: str) -> UnitState:
        return self.manager.state(unit)

    def _mask(self, unit: str) -> None:
        _mask_and_confirm_inactive(self.manager, unit, self.withdrawn, self.before_mask)

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
    #: Says the broker is in the already-withdrawn `failed` shape (see
    #: `_mask_and_confirm_inactive`); None where there is no stop authority.
    contextd_withdrawn: Optional[object] = None
    #: Replaces a start job the pass is holding for the broker, before the
    #: broker is masked (see `activation_withdraw.release_queued_job`).
    contextd_before_mask: Optional[object] = None

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
        """Apply one pass; a lease-bearing pass loads missing Edge evidence.

        Explicit Edge states remain an injection seam. With no lease, None
        stays unknown, as required by the production boot refusing pass.
        """
        units = ManagedUnitController(self.manager, self.contextd_withdrawn,
                                      self.contextd_before_mask)
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
                # The lease-bearing ordinary path consumes package/probe
                # evidence. The boot refusing pass keeps edge=None and grants
                # nothing; evidence itself supplies no lease or node health.
                edge=(
                    installed_baseline_state(now=now)
                    if edge is None and lease is not None else edge
                ),
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
        # The controller's masks, unmasks and enables are one batch of unit
        # file changes. A manager that loaded a unit earlier keeps acting on
        # the definition it has until it is reloaded (a granted unit would
        # start as `masked`; a withheld one could still be queued), so the
        # batch ends with exactly one Reload. If it fails, the grants cannot
        # be confirmed and everything is narrowed.
        reload_failure = self._reload()
        if reload_failure is not None:
            self._record({
                "event_type": "activation.reload_failed",
                "after": "grant_batch",
                "error_type": reload_failure,
                "occurred_at": now,
                "actor": actor,
            })
            self._narrow_everything(now=now, actor=actor, after=[reload_failure])
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

    def _reload(self) -> Optional[str]:
        """One Manager.Reload; a fixed failure label, or None when it succeeded."""
        try:
            self.manager.reload()
        except Exception as exc:  # noqa: BLE001 - reported as a label, never raised
            return f"manager reload: {type(exc).__name__}"
        return None

    def _remask_all(
        self, *, now: str, actor: str, event_type: str, error_type: str,
        skip: frozenset = frozenset(),
    ) -> list[str]:
        """Retry narrowing of every governed unit and record the attempt.

        `skip` names units left as they are: only the Knowledge Context
        broker's queued start job at preflight (see `_run_once`).
        """

        failures: list[str] = []
        for definition in self.definitions:
            if definition.name in skip:
                continue
            try:
                _mask_and_confirm_inactive(self.manager, definition.name, self.contextd_withdrawn,
                                           self.contextd_before_mask)
            except Exception as exc:  # noqa: BLE001 - collect all failures
                failures.append(f"{definition.name}: {type(exc).__name__}")
        reload_failure = self._reload()  # the masks above are one batch
        if reload_failure is not None:
            failures.append(reload_failure)
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
                _mask_and_confirm_inactive(self.manager, unit, self.contextd_withdrawn,
                                           self.contextd_before_mask)
                taken_back.append(unit)
            except Exception as exc:  # noqa: BLE001 - recorded below, then escalated
                failures.append(_unit_failure(unit, exc))
        reload_failure = self._reload()  # the masks above are one batch
        if reload_failure is not None:
            failures.append(reload_failure)

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
                _mask_and_confirm_inactive(self.manager, definition.name, self.contextd_withdrawn,
                                           self.contextd_before_mask)
            except Exception as exc:  # noqa: BLE001
                unreachable.append(_unit_failure(definition.name, exc))
        reload_failure = self._reload()  # the masks above are one batch
        if reload_failure is not None:
            unreachable.append(reload_failure)
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
    storage = _commissioning_storage()
    if storage is not None:
        result["commissioning_storage"] = storage
    return result


#: The only values `commissioning_storage` may take (#242 §4 "Diagnostic only").
COMMISSIONING_STORAGE_LABELS = ("luks_backed", "not_luks_backed")


def _commissioning_storage() -> Optional[str]:
    """Whether `/etc/azazel/commissioning` sits on LUKS, as one of two fixed labels.

    Diagnostic only (`docs/commissioning-storage-at-boot.md` §4): it tells a
    boot whose volume stayed locked (the directory is then the bare mount
    point on the root filesystem) from other commissioning failures, from the
    ledger alone. It is read after the decision, the markers and the high
    water, and feeds none of them; it carries no device, number or path.
    The HIL preflight's reader in its three-valued form
    (`hil_preflight.luks_backing`): a `stat` and `/sys/dev/block`, nothing
    executed. When it cannot tell -- the path or the sysfs entry unreadable,
    an anonymous device -- nothing is recorded rather than a guess or a
    third value; so is a reader that raises.
    """
    try:
        backed = luks_backing(COMMISSIONING_DIR)
    except Exception:  # noqa: BLE001 - no label is better than an invented one
        return None
    if backed is True:
        return "luks_backed"
    if backed is False:
        return "not_luks_backed"
    return None
    if backed is True:
        return "luks_backed"
    if backed is False:
        return "not_luks_backed"
    return None


#: Every producer, for a pass whose input collection itself failed.
_ALL_PRODUCERS = (
    "authoritative_commissioning_admission", "renderer_measurement", "edge_evidence",
    "authenticated_commissioning", "inventory_binding", "node_identity",
    "activation_policy", "epoch_high_water", "trusted_clock",
    "operational_generation_publisher", "systemd_loaded_units",
    "activation_approval_loader", "node_health",
)

#: One monotonic budget for a whole main pass, counted from before the bus
#: connects to the end of the narrowing a failed pass needs, in three parts:
#: the phases (37 s, `budget - ready - reserve`), then the READY window
#: (`MAIN_PASS_READY_SECONDS`: sending READY, then the barrier, at worst 1 s +
#: 1 s + the barrier's 5 s wait, so 8 s), then the reserve
#: (`MAIN_PASS_RESERVE_SECONDS`: the narrowing a failed READY or barrier needs,
#: and its record). READY and the barrier therefore cannot eat the reserve.
#: `azazel-activated.service` has `TimeoutStartSec=60s`: 37 + 8 + 8 = 53 s,
#: and 7 s of margin for the exit.
MAIN_PASS_BUDGET_SECONDS = 53.0
MAIN_PASS_READY_SECONDS = 8.0
MAIN_PASS_RESERVE_SECONDS = 8.0
_AFTER_PHASES = MAIN_PASS_READY_SECONDS + MAIN_PASS_RESERVE_SECONDS
#: How long the main pass waits for the pass lock before it narrows (inside the
#: phase budget). It is longer than the part of a recheck that is time-bounded
#: (its bus work and containment finalizer, at most 20 s), so a pass that
#: arrives during a recheck normally gets the lock. The recheck's local
#: filesystem I/O under the lock (ledger appends, retirement state, marker and
#: input reads) is not time-bounded; if it stalls this wait expires and the
#: pass changes nothing, grants nothing and fails (fail-closed).
PASS_LOCK_WAIT_SECONDS = 25.0


#: The journal line for a pass that could not take `pass.lock`. Stable text;
#: nothing is changed and no ledger record is written on that path.
NO_LOCK_NO_RECORD_MESSAGE = (
    "az-activated: the activation pass lock was not held; nothing was changed or "
    "written; failing")


def _contextd_aids(root: Path, *, now: str, actor: str, invocation_id: str,
                   until: float, clock, sleep, record: bool, hold_state=None, fresh):
    """`(withdrawn_for, clear_for, before_for)`: builders bound to a stop authority.

    `withdrawn_for(authority)` is the already-withdrawn test; `clear_for(authority)
    (manager)` the full contextd withdrawal (marker, mask, reload, stop, confirm
    quiet) run after a narrowing; `before_for(authority)()` replaces a start job the
    pass is holding for the broker, once, BEFORE anything masks the broker. They
    take the authority as an argument because a narrowing on a fresh bus session
    must use the authority of THAT session: the first one belongs to a session that
    is finished and refuses every read and stop. With `record=False` the
    withdrawal writes nothing to the ledger.
    """
    state = hold_state if hold_state is not None else QueuedJobState()

    def withdrawn_for(authority):
        if authority is None:
            return None
        return lambda: contextd_already_withdrawn(authority, root)

    def before_for(authority, target=None):
        if authority is None:
            return None

        def transport(limit: float) -> None:
            # The job operations (Job reads, StopUnit, polling) get their own
            # transport deadline, so none of them can run into the time the mask,
            # the reload and the exact-masked confirmation are reserved.
            if target is not None:
                bind_remaining(target, limit, clock)

        def before_mask() -> None:
            release_queued_job(
                state=state, authority=authority, ledger=_activation_ledger(root),
                now=now, actor=actor, invocation_id=invocation_id, deadline=until,
                reason="before_mask", clock=clock, sleep=sleep, transport=transport,
                sink=None if record else (lambda event: None))

        return before_mask

    def clear_for(authority):
        if authority is None:
            return None

        def clear_job(target) -> None:
            # The FULL withdrawal, not just a job clear: on a path where READY
            # may already have been sent, the held start job may have run and
            # the broker may be active.
            withdraw_contextd(
                reason="narrowed", manager=target, authority=authority, root=root,
                ledger=_activation_ledger(root), now=now, actor=actor,
                invocation_id=invocation_id, deadline=until, final_deadline=until,
                bind_deadline=lambda d: bind_remaining(target, d, clock),
                sink=None if record else (lambda event: None), fresh=fresh,
                clock=clock, sleep=sleep)

        return clear_job

    return withdrawn_for, clear_for, before_for


def _narrow_final(manager: UnitManager, root: Path, message: str, *, until: float,
                  clock=time.monotonic, fresh_manager=None, authority=None,
                  aids=None) -> None:
    """Narrow under the end of the whole budget, on a new session if this one is finished.

    `until` is the monotonic end of the full budget (phases plus reserve), so
    the narrowing may spend the reserve; every bus call it makes is limited to
    what is left. A session whose call timed out or was cancelled is finished
    (`SystemdBusSession.broken`): when `fresh_manager` (a context manager that
    yields `(manager, stop_authority)` on a NEW session, connecting inside the
    same deadline) is available the narrowing runs there with that session's
    manager AND authority together; the old authority would refuse everything.
    `aids` are the `_contextd_aids` builders; the full broker withdrawal runs
    after the masks, best effort, before the narrowing raises. Always raises,
    like `_emergency_narrow`.
    """
    withdrawn_for, clear_for, before_for = aids if aids is not None else (
        lambda a: None, lambda a: None, lambda a: None)

    def narrow(target, target_authority) -> None:
        bind_remaining(target, until, clock)
        withdrawn = withdrawn_for(target_authority)
        clear_job = clear_for(target_authority)
        options = {} if withdrawn is None else {"withdrawn": withdrawn}
        before = before_for(target_authority, target)
        if before is not None:
            options["before_mask"] = before
        try:
            _emergency_narrow(target, root, message, **options)
        except RuntimeError:
            if clear_job is not None:
                try:
                    clear_job(target)
                except Exception:  # noqa: BLE001 - best effort; the narrowing already raised
                    pass
            raise

    def broken(target) -> bool:
        return bool(getattr(getattr(target, "call", None), "broken", False))

    def on_fresh() -> None:
        stack = contextlib.ExitStack()
        try:
            other, other_authority = stack.enter_context(fresh_manager())
        except Exception:  # noqa: BLE001 - narrow on what there is
            stack.close()
            return
        with stack:
            narrow(other, other_authority)

    if fresh_manager is not None and broken(manager):
        on_fresh()
    try:
        narrow(manager, authority)
    except RuntimeError:
        # The session finished DURING this narrowing (a call timed out): what is
        # left of the reserve goes to a new session, not to a refusing one.
        if fresh_manager is not None and broken(manager):
            on_fresh()
        raise


def _emergency_narrow(manager: UnitManager, root: Path, message: str, *,
                      withdrawn=None, before_mask=None) -> None:
    """Remove every grant marker, mask every governed unit, then raise."""
    failures: list[str] = []
    try:
        reset_grant_markers(root)
    except Exception as exc:  # noqa: BLE001 - recorded, and the remask still runs
        failures.append(f"grant_markers: {type(exc).__name__}")
        print("az-activated could not remove grant markers during emergency narrowing",
              file=sys.stderr)
    for definition in CORE_UNITS:
        try:
            _mask_and_confirm_inactive(manager, definition.name, withdrawn, before_mask)
        except Exception as exc:  # noqa: BLE001 - fail closed on invariant break
            failures.append(f"{definition.name}: {type(exc).__name__}")
    try:
        manager.reload()  # the masks above are one batch
    except Exception as exc:  # noqa: BLE001 - recorded, then raised below
        failures.append(f"manager reload: {type(exc).__name__}")
    error = RuntimeError(f"{message}; emergency remask failures: {sorted(failures)}")
    error.narrowed = True  # a narrowing was attempted: callers do not repeat it
    raise error


def _run_once(
    *, manager: UnitManager, root: Path, now: str, actor: str, producers=None,
    stop_authority: Optional[ContextdStopAuthority] = None,
    deadline: Optional[float] = None, clock=time.monotonic, sleep=time.sleep,
    invocation_id: str = "", fresh_manager=None, hold_state=None,
) -> ActivationOutcome:
    """One observe-baseline pass (#206 §3.6): SUPPORTING (P4) and edge-core (P5).

    Order: remove this boot's grant markers; preflight remask; commissioning
    evidence; independent context (declared node, policy, high water and
    clock, the current generation verified as an observe-baseline tree over
    the unit files installed now, evidence binding, declared epoch); the v2
    approval verified against it; node health; the library decision with
    ``require_commissioning_evidence=True``. Unless every producer verified,
    the decision gets ``lease=None`` and ``healthy=False``: the library API's
    test-friendly defaults are not evidence a production daemon may inherit.

    Edge evidence (P5) comes from the pass too: edge-core is launchable only
    with the four package checks, fresh health from this boot's probe
    preflight (which ran ``Before=`` this unit and is not required by it), and
    the installed package equal to the generation's signed pin. Otherwise the
    library withholds edge-core (``edge_not_ready``) and decides the
    SUPPORTING units without it.

    After the decision is recorded: a grant outside the lease, any grant
    without lease and health, or edge-core granted without launchable bound
    evidence remasks everything and raises; otherwise the
    high-water floors are raised and the per-boot grant markers written for
    exactly the granted units. ``producers`` is a test seam; ``main`` never
    passes it, and a relocated root reads no host producer.

    The caller holds the pass lock (``_locked_pass``). ``stop_authority`` is
    the authority to stop the Knowledge Context broker alone, built by
    ``main`` from the controller's session: a broker still running at
    preflight is withdrawn (marker, mask, reload, StopUnit) before the masks
    are confirmed, and a start job queued for a broker that is not granted is
    replaced. Without it a running broker is a containment failure, as
    before. ``deadline`` is the monotonic end of the pass's phases (the budget less
    ``MAIN_PASS_RESERVE_SECONDS``).
    """
    if deadline is None:
        deadline = clock() + MAIN_PASS_BUDGET_SECONDS - _AFTER_PHASES

    def _narrow_now(narrowing_manager, narrowing_root, message):
        # Narrowing may spend the reserve held back from the phases: the bus
        # calls it makes are bounded by the end of the whole budget, not by
        # the end of the phases.
        _narrow_final(narrowing_manager, narrowing_root, message,
                      until=deadline + _AFTER_PHASES, clock=clock,
                      fresh_manager=fresh_manager, authority=stop_authority, aids=aids)

    if hold_state is None:
        hold_state = QueuedJobState()
    aids = _contextd_aids(
        root, now=now, actor=actor, invocation_id=invocation_id,
        until=deadline + _AFTER_PHASES, clock=clock, sleep=sleep, record=True,
        hold_state=hold_state, fresh=fresh_manager)
    withdrawn = aids[0](stop_authority)
    # The hook the verdict's own mask, a rollback and a wider narrowing reach runs
    # while the bus session is still bound to the end of the PHASES, so its job
    # wait is bounded by that deadline (and always leaves the mask its reserve);
    # a narrowing that rebinds to the end of the whole budget builds its own.
    phase_aids = _contextd_aids(
        root, now=now, actor=actor, invocation_id=invocation_id, until=deadline,
        clock=clock, sleep=sleep, record=True, hold_state=hold_state,
        fresh=fresh_manager)
    release_job = phase_aids[2](stop_authority, manager)
    daemon = ActivationDaemon(
        generations=GenerationStore(root / "var/lib/azazel/generations"),
        ledger=_activation_ledger(root),
        manager=manager,
        definitions=CORE_UNITS,
        contextd_withdrawn=withdrawn,
        contextd_before_mask=release_job,
    )
    # Stale markers go first, before any decision: a marker left from an
    # earlier pass in this boot must never admit a queued start.
    marker_failure = None
    try:
        reset_grant_markers(root)
    except Exception as exc:  # noqa: BLE001 - refuses below, after narrowing
        marker_failure = type(exc).__name__
    hold: frozenset = frozenset()
    if stop_authority is not None:
        # A broker that is running is stopped here, with its marker gone and
        # a mask in place, before the masks below are confirmed. A broker that
        # is inactive with a start job queued is NOT masked here: masking and
        # reloading would make systemd fail that job, and the job cannot run
        # before READY (the broker is After= and Requires= the controller).
        # It is left as it is and decided at the verdict: granted, the job
        # runs after READY. Withheld, or on any narrowing, the job is replaced
        # FIRST (StopUnit replace, no job left, `queued_job_replaced`
        # recorded: `release_queued_job`, called before whatever masks the
        # broker), and only then is the broker masked and the manager
        # reloaded; the other order lets systemd fail the job ("Failed to
        # start") with no replacement and no record. Should the pass die,
        # Requires= fails the job (fail-closed).
        if contextd_is_running(stop_authority, root):
            try:
                withdraw_contextd(
                    reason="preflight", manager=manager, authority=stop_authority,
                    root=root, ledger=daemon.ledger, now=now, actor=actor,
                    invocation_id=invocation_id, deadline=deadline,
                    final_deadline=deadline + _AFTER_PHASES,
                    bind_deadline=lambda d: bind_remaining(manager, d, clock),
                    fresh=fresh_manager, clock=clock, sleep=sleep)
            except WithdrawalUnconfirmed:
                bind_remaining(manager, deadline + _AFTER_PHASES, clock)
                _narrow_now(
                    manager, root,
                    "the Knowledge Context broker could not be withdrawn at preflight")
        elif contextd_start_is_queued(stop_authority):
            hold = frozenset({CONTEXTD_UNIT})
            hold_state.held = True
    failures = daemon._remask_all(now=now, actor=actor,
        event_type="activation.evidence_preflight_masked", error_type="preflight",
        skip=hold)
    if failures:
        daemon._narrow_everything(now=now, actor=actor, after=failures)
    if marker_failure is not None:
        daemon._record({
            "event_type": "activation.grant_markers_unclean",
            "error_type": marker_failure, "occurred_at": now, "actor": actor,
        })
        raise RuntimeError("stale activation grant markers could not be removed")

    check_budget(deadline, clock)
    inputs = None
    try:
        from .activation_pass import (
            collect_pass_inputs, production_producers, staged_inputs,
        )
        if producers is None and root == Path("/"):
            # The manager's own D-Bus session, for the loaded-unit check.
            producers = production_producers(commissioning_evidence=load_commissioning_evidence,
                                             systemd=getattr(manager, "call", None))
        if producers is None:
            inputs = staged_inputs()
        else:
            inputs = collect_pass_inputs(producers=producers, generations=daemon.generations,
                                         ledger=daemon.ledger, now=now)
    except Exception:  # noqa: BLE001 - collection failure is absent evidence
        inputs = None
    check_budget(deadline, clock)
    lease = inputs.lease if inputs is not None else None
    healthy = inputs is not None and lease is not None and inputs.healthy is True
    if not healthy:
        lease = None
    if lease is not None:
        # An approval retirement (operator revoked) that is unfinished, or an
        # accepted-grant record that is not exactly what a grant writes,
        # withholds everything: nothing is granted until the recheck has
        # finished the retirement, or the record has been looked at. The
        # record is never overwritten here.
        try:
            blocked = retirement_pending(root)
            read_accepted_grant(root)
        except RetireRefused:
            blocked = True
        if blocked:
            lease, healthy = None, False
    # The pass's own Edge evidence (P5), never the daemon's host read: a
    # lease-bearing pass without it hands the library nothing launchable.
    edge = inputs.edge if inputs is not None else None
    if lease is not None and type(edge) is not EdgeBaselineState:
        edge = nothing_established()
    outcome = daemon.activate(
        now=now,
        actor=actor,
        lease=lease,
        record=None,
        edge=edge,
        healthy=healthy,
        wired=wired_capabilities(),
        commissioning_evidence=inputs.evidence if inputs is not None else None,
        require_commissioning_evidence=True,
    )
    check_budget(deadline, clock)
    granted = set(outcome.granted)
    if granted and (lease is None or not healthy or lease.units is None
                    or not granted <= lease.units or not granted <= GRANTABLE_UNITS):
        # A grant without verified lease and health, or outside the lease's
        # scope, means a change silently supplied authority.
        _narrow_now(
            manager, root,
            "production activation granted a unit outside a verified lease and "
            "health or outside the lease scope",
        )
    if EDGE_CORE_UNIT in granted and (
            inputs is None or inputs.edge_evidence != "launchable"
            or inputs.edge_package_binding != "bound"):
        # Edge-core without launchable evidence bound to the signed package.
        _narrow_now(
            manager, root,
            "production activation granted edge-core without launchable Edge "
            "evidence bound to the signed package",
        )
    if granted & set(DECEPTION_EXPOSURE_UNITS):
        # #196 P1: this build has no isolation evidence, so a Deception Lite
        # exposure unit is never granted; one that was means a change
        # supplied authority the design does not have.
        _narrow_now(
            manager, root,
            "production activation granted a Deception Lite exposure unit "
            "without isolation evidence",
        )
    if granted:
        # The grant batch has been reloaded. What the manager now holds for
        # the guarded units is what a start job will use, so it is checked
        # again here, before any marker is written or READY is sent: a unit
        # that is not loaded as declared after the Reload is not a grant.
        from .activation_pass import UNIT_CHECK_SCOPE
        try:
            producers.loaded_units(sorted(UNIT_CHECK_SCOPE))
        except Exception:  # noqa: BLE001 - an unverifiable grant is withdrawn
            try:
                daemon._record({
                    "event_type": "activation.grant_unverified_after_reload",
                    "occurred_at": now, "actor": actor,
                })
            except Exception:  # noqa: BLE001 - narrowing below is unconditional
                pass
            _narrow_now(
                manager, root,
                "granted units were not verified as loaded after the manager reload",
            )
    if granted:
        # The approval this grant is made under, durably, before any marker
        # or READY: a later explicit revocation of its operator retires it.
        approval = inputs.approval
        try:
            write_accepted_grant(
                root, operator=lease.granted_by, approval_seq=approval.approval_seq,
                approval_id=approval.approval_id,
                payload_sha256=approval.payload_sha256, units=sorted(granted))
        except RetireRefused:
            try:
                daemon._record({
                    "event_type": "activation.accepted_grant_unwritten",
                    "occurred_at": now, "actor": actor,
                })
            except Exception:  # noqa: BLE001 - narrowing below is unconditional
                pass
            _narrow_now(manager, root, "the accepted approval could not be recorded")
    if stop_authority is not None and CONTEXTD_UNIT not in granted:
        # A broker the pass does not grant must not start: a start job the
        # manager queued for it before this pass is replaced, not left to be
        # skipped by a condition.
        release_job()  # a no-op once the job was replaced before the verdict's mask
        try:
            clear_contextd_job(
                authority=stop_authority, ledger=daemon.ledger, now=now, actor=actor,
                reason="withheld", invocation_id=invocation_id, deadline=deadline,
                clock=clock, sleep=sleep)
        except WithdrawalUnconfirmed:
            _narrow_now(
                manager, root,
                "a start job queued for the Knowledge Context broker could not be replaced")
    rolled_back = any(_is_failure(verdict) for verdict in outcome.verdicts)
    high_water = "not_attempted"
    if lease is not None and inputs.approval is not None:
        # After the decision is recorded; raise-only, bounded by now + skew.
        from .activation_pass import raised_high_water
        try:
            floor = producers.raise_high_water(raised_high_water(inputs, now=now), now=now,
                                               skew_seconds=inputs.skew_seconds)
            high_water = "raised"
            # A floor event: a node with this history refuses a missing file.
            # Nested like az-activation's floor events (`FLOOR_EVENTS`), so
            # a later install or recovery never re-initializes below it.
            daemon.ledger.append({
                "event_type": "activation.high_water_raised",
                "high_water": {
                    "security_epoch": floor.security_epoch,
                    "approval_seq": floor.approval_seq,
                    "generation": floor.generation,
                    "time_floor": floor.time_floor,
                },
                "occurred_at": now, "actor": actor,
            })
        except Exception:  # noqa: BLE001 - an unraised floor admits nothing
            # The record must never stand between this failure and the remask.
            try:
                daemon._record({
                    "event_type": "activation.high_water_unraised",
                    "occurred_at": now, "actor": actor,
                })
            except Exception:  # noqa: BLE001 - narrowing below is unconditional
                pass
            _narrow_now(manager, root, "activation high water could not be raised")
    markers: tuple[str, ...] = ()
    recorded = False
    # From the first marker to the final record, any failure (writing a
    # marker, assembling the diagnostic record, appending it) withdraws:
    # markers removed, every governed unit remasked, then it raises (#251 L-2).
    try:
        if granted and not rolled_back:
            try:
                markers = write_grant_markers(sorted(granted), root)
            except Exception:  # noqa: BLE001 - a unit without a marker never starts
                # The record must never stand between this failure and the remask.
                try:
                    daemon._record({
                        "event_type": "activation.grant_markers_unwritten",
                        "occurred_at": now, "actor": actor,
                    })
                except Exception:  # noqa: BLE001 - narrowing below is unconditional
                    pass
                raise _MarkersUnwritten() from None
        # Do not gather optional diagnostic inputs before mandatory narrowing.
        # Merely loading an enrolled key or observing a boot is not admission.
        observed = _collect_input_status(root)
        evidence = inputs.evidence if inputs is not None else None
        observed["full_commissioning"] = (
            "verified_current_binding" if evidence is not None else "unavailable")
        if inputs is None:
            missing = list(_ALL_PRODUCERS)
            observed["producers"] = "collection_failed"
        else:
            missing = inputs.missing()
            observed["producers"] = dict(inputs.status)
            observed["node_health_findings"] = dict(inputs.health_findings)
        observed["high_water"] = high_water
        if inputs is not None:
            # Fixed labels and check names only; no digest or probe text.
            observed["edge_package_binding"] = inputs.edge_package_binding
            observed["edge_evidence"] = inputs.edge_evidence
            # Two separate facts and the floor label; labels only.
            # Only where an issuer is configured or something was noted: a
            # node with no issuer anchor and nothing to report records exactly
            # what it recorded before issuer verification existed.
            if inputs.edge_issuer is not None and (
                    inputs.edge_issuer.issuer_status != "not_configured"
                    or inputs.edge_issuer.notes):
                observed["edge_issuer"] = inputs.edge_issuer.labels()
            # Only when the policy requires synchronization and the floor
            # check passed (#251 M-1): tells an unproven synchronization from
            # a clock below the floor. Absent otherwise, as before the field.
            if inputs.clock_synchronization in ("synchronized", "not_proven"):
                observed["clock_synchronization"] = inputs.clock_synchronization
            if inputs.edge_missing:
                observed["edge_missing_for_launch"] = list(inputs.edge_missing)
        daemon.ledger.append({
            "event_type": "activation.inputs_incomplete",
            "observed_inputs": observed,
            "missing_producers": missing,
            "grant_markers": list(markers),
            "generation": outcome.generation,
            "occurred_at": now,
            "actor": actor,
        })
        recorded = True
    except _MarkersUnwritten:
        _narrow_now(manager, root, "activation grant markers could not be written")
    except Exception:  # noqa: BLE001 - an unrecorded pass leaves no grant behind
        # The record is what makes this a completed pass: the markers it
        # wrote and the units it enabled are withdrawn first.
        _narrow_now(manager, root, "activation pass record could not be appended")
    if recorded and markers and EDGE_CORE_UNIT in granted and inputs is not None:
        _raise_edge_floor(daemon, inputs, now=now, actor=actor)
    return outcome


def _raise_edge_floor(daemon, inputs, *, now: str, actor: str) -> None:
    """The Edge rollback floor, after a recorded edge-core grant (`edge_issuer_floor`).

    Only here, after the pass record that completes the grant: a grant
    withdrawn because its record failed never raises it. It raises only for
    an issuer-authenticated, unrevoked package bound to the launch evidence,
    so it never moves on any node without an issuer anchor. Neither the raise
    nor its record can grant or withdraw anything, so a failure of either is
    left at that -- visibly: a raise or record that fails prints a fixed label
    to the journal. Nothing escapes this function.

    A crash between the pass record and this raise leaves the floor where it
    was until the next recorded authenticated pass raises it. That is safe:
    the floor only narrows, and an un-raised floor admits nothing the checks
    did not already admit.
    """
    try:
        from .edge_issuer_floor import raise_floor_after_grant
        label = raise_floor_after_grant(
            inputs.edge_issuer,
            launched_digest=inputs.edge.package_digest if inputs.edge else None)
    except Exception:  # noqa: BLE001 - the floor is not a grant; nothing to withdraw
        label = "failed"
    if label == "not_authenticated":
        # Every node without an issuer anchor: nothing was attempted, and the
        # ledger stays exactly as it was before this floor existed.
        return
    try:
        daemon.ledger.append({
            "event_type": "activation.edge_issuer_floor",
            "edge_issuer_floor": label,
            "occurred_at": now, "actor": actor,
        })
    except Exception:  # noqa: BLE001 - the floor is not a grant; nothing to withdraw
        print(f"az-activated edge issuer floor {label}; its ledger record was not appended",
              file=sys.stderr)
        return
    if label in ("failed", "refused", "uncertain"):
        print(f"az-activated edge issuer floor {label}", file=sys.stderr)


class _MarkersUnwritten(Exception):
    """Private: a grant marker could not be written (already recorded)."""


def _activation_ledger(root: Path) -> AuditLedger:
    return AuditLedger(root / "var/lib/azazel/state/activation.jsonl")


def _narrow_bootstrap_core_units():
    """Fixed broad mask/inactivity pass; no ordinary admission attempt.

    Like ``_emergency_narrow``, it removes every grant marker first (#251
    L-7); a marker that cannot be removed fails the narrowing after the
    remask still runs.
    """
    from .systemd_bus import SystemdBusSession

    failures = []
    try:
        reset_grant_markers(Path("/"))
    except Exception:  # noqa: BLE001 - recorded, and the remask still runs
        failures.append("grant_markers")
        print("az-activated could not remove grant markers during bootstrap narrowing",
              file=sys.stderr)
    global _bootstrap_shared_end
    began = time.monotonic()
    if _bootstrap_shared_end is None:
        # Called without `main` (a direct caller): count from this call.
        _bootstrap_shared_end = began + _BOOTSTRAP_PROCESS_SECONDS
    shared_end = _bootstrap_shared_end
    end = min(shared_end, began + _BOOTSTRAP_NARROWING_SECONDS)

    def left() -> float:
        return end - time.monotonic()

    terminal = []

    def say(withdrew: bool) -> None:
        # Journal only (option b): this stage holds no pass.lock and documents no
        # ledger writer, so no activation-ledger record is appended here. The two
        # strings are fixed, one terminal message per invocation, and nothing from
        # an event is interpolated.
        if terminal:
            return
        terminal.append(withdrew)
        print("az-activated bootstrap narrowing withdrew the Knowledge Context broker"
              if withdrew else
              "az-activated bootstrap narrowing could not confirm the withdrawal of "
              "the Knowledge Context broker", file=sys.stderr)

    def journal(event: dict) -> None:
        # Only the outcome is kept here; the terminal message is printed once, when the
        # withdrawal ends (a job-stage "unconfirmed" followed by a withdrawn broker is
        # a withdrawn broker). The queued-job records are not outcomes.
        pass

    @contextlib.contextmanager
    def fresh_session():
        with SystemdBusSession.connect(left) as other:
            replacement = DbusUnitManager(call=other)
            # Bound to the governing end at once (never a fresh allowance per exchange).
            bind_remaining(replacement, end, time.monotonic)
            yield replacement, ContextdStopAuthority.from_session(other)

    if left() <= 0:
        say(False)  # the shared time is gone: a message exists before anything is killed
        raise UnitOperationFailed("bootstrap initial/emergency narrowing unconfirmed")
    try:
        connection = SystemdBusSession.connect(left)
        session_context = connection.__enter__()
    except Exception:  # noqa: BLE001 - setup failed: say so at once, then fail closed
        say(False)
        raise UnitOperationFailed("bootstrap initial/emergency narrowing unconfirmed") from None
    with contextlib.ExitStack() as stack:
        session = stack.enter_context(contextlib.nullcontext(session_context))
        stack.callback(connection.__exit__, None, None, None)
        manager = DbusUnitManager(call=session)
        # The broker first, through the one withdrawal (marker, held-job settlement,
        # mask, reload, stop, exact masked-and-quiet confirmation, a fresh session per
        # step when one finishes), with the contextd-only stop authority.
        try:
            withdraw_contextd(
                reason="bootstrap_narrowing", manager=manager,
                authority=ContextdStopAuthority.from_session(session), root=Path("/"),
                ledger=_activation_ledger(Path("/")),
                now=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                actor="azazel-activated", invocation_id="",
                deadline=max(began, end - 10.0), final_deadline=end,
                bind_deadline=lambda d: bind_remaining(manager, d, time.monotonic),
                sink=journal, fresh=fresh_session)
        except Exception:  # noqa: BLE001 - the other units are still narrowed
            failures.append(CONTEXTD_UNIT)
            say(False)
        else:
            say(True)
        # The other units: the session is bound to the final deadline again (the
        # withdrawal may have left it on its own, shorter one), and a session that
        # finished is replaced, unit by unit, inside the same deadline.
        current = {"manager": manager, "session": session}
        sub = contextlib.ExitStack()
        stack.callback(sub.close)
        bind_remaining(manager, end, time.monotonic)
        for definition in CORE_UNITS:
            if definition.name == CONTEXTD_UNIT:
                continue
            if getattr(current["session"], "broken", False) and left() > 0:
                try:
                    other_manager, _authority = sub.enter_context(fresh_session())
                    current["manager"], current["session"] = other_manager, other_manager.call
                except Exception:  # noqa: BLE001
                    pass
            try:
                _mask_and_confirm_inactive(current["manager"], definition.name)
            except Exception:  # noqa: BLE001
                failures.append(definition.name)
    if failures:
        raise UnitOperationFailed("bootstrap initial/emergency narrowing unconfirmed")


#: Time one bootstrap-stage narrowing may use (bus connection included).
_BOOTSTRAP_NARROWING_SECONDS = 25.0
#: The shared absolute end, counted from the entry of `main` (before the selection, the
#: transaction, the marker reset and the claim), for every bootstrap narrowing of the
#: process together (60 s TimeoutStartSec - 10 s; the start before `main` and the exit
#: after the end are the margin, to be measured on the clone).
_BOOTSTRAP_PROCESS_SECONDS = 50.0
_bootstrap_shared_end = None


# Reviewed static messages of the bootstrap path, including the library's
# bootstrap selection modules (see tests/unit/test_runtime_activated_entrypoint.py,
# which pins literal raises plus the closed selection-read reason set).
# Only these are ever logged.
_STATIC_FAILURE_MESSAGES = frozenset({
    'protected bootstrap selection refused: deployment unreadable or verification refused',
    'protected bootstrap selection refused: current boot unreadable',
    'protected bootstrap selection refused: selection unreadable or protection refused',
    'protected bootstrap selection refused: selection format refused',
    'protected bootstrap selection refused: boot binding differs from the current boot',
    'protected bootstrap selection refused: deployment binding differs',
    'protected bootstrap selection refused: selection or source changed during read',
    'protected bootstrap selection refused: required bootstrap input missing',
    'additional controller command refused',
    'a stop authority needs its four verbs',
    'systemd returned an invalid unit-file state result',
    'manager reload failed',
    'systemd returned an invalid job result',
    'systemd returned an invalid stop result',
    'the service manager adapter cannot reload',
    'the stop authority was asked about a unit outside its scope',
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
    'bootstrap selection absence changed',
    'bootstrap selection appeared during observation',
    'bootstrap selection binding differs',
    'bootstrap selection binding inputs required',
    'bootstrap selection changed',
    'bootstrap selection changed before composition',
    'bootstrap selection changed during initial narrowing',
    'bootstrap selection digest refused',
    'bootstrap selection directory changed',
    'bootstrap selection encoding refused',
    'bootstrap selection generation refused',
    'bootstrap selection identity refused',
    'bootstrap selection publication unfinished',
    'bootstrap selection refused',
    'bootstrap selection required',
    'bootstrap selection source changed',
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
    'bounded bootstrap selection required',
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
    'deployment changed during selection publication',
    'durable bootstrap transaction unavailable',
    'durable bootstrap transaction update unconfirmed',
    'durably retained bootstrap deadline required',
    'enclosing systemd owner changed',
    'enclosing systemd owner changed before loaded inspection',
    'existing bootstrap transaction requires manual review',
    'existing selection cannot be replaced',
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
    'noncanonical bootstrap selection refused',
    'only the fixed system bus socket is admitted',
    'optional protected bootstrap selection refused',
    'owned bootstrap closure unavailable',
    'pinned system bus client unavailable',
    'prior boot grant identity differs from journal',
    'prior boot journal retirement unavailable',
    'prior boot journal retirement record unconfirmed',
    "prior boot journal was not this boot's fence",
    'protected bootstrap grant store required',
    'protected bootstrap selection refused',
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
    'retained selection differs',
    'retained start intent changed',
    'selection directory changed',
    'selection publication refused; inspect retained state',
    'separate digest and exact operation confirmation required',
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
    # Owned-overlay withdrawal, restoration and prior boot journal retirement
    # (bootstrap_withdrawal, bootstrap_withdraw_files, bootstrap_restore_files).
    'exact grant transaction required',
    'fresh containment check failed',
    'fresh containment unconfirmed',
    'fresh restoration evidence required',
    'held guard and fresh containment check required',
    'held restoration guard required',
    'held withdrawal guard required',
    'overlay entry remains after withdrawal',
    'owned closing journal required',
    'owned mask missing before withdrawal intent',
    'prior boot journal audit record refused',
    'prior boot journal belongs to current boot',
    'prior boot journal changed during retirement',
    'prior boot journal current boot id refused',
    'prior boot journal differs from expected',
    "prior boot journal not bound by this boot's containment",
    'prior boot journal or paths changed',
    'prior boot journal phase refused',
    'prior boot journal reset not confirmed',
    'prior boot journal retirement arguments refused',
    'prior boot journal retirement masks changed',
    'prior boot journal retirement pair entry present',
    'prior boot overlay entry present',
    'restored mask has a higher-priority competitor',
    'restored paths or ownership journal changed',
    'resumed closure phase refused',
    'retained closure journal required',
    'retained withdrawal journal disappeared',
    'retained withdrawal journal required',
    'unowned withdrawal candidate present',
    'unowned withdrawal entry',
    'withdrawal candidate is not an empty mask',
    'withdrawal does not own retained overlay intent',
    'withdrawal entry missing before intent',
    'withdrawal identity or paths changed',
    'withdrawal journal or paths changed',
    'withdrawal mask not empty',
    'withdrawal observation changed',
    'withdrawal precedence directories alias',
    'withdrawal requires explicit grant selection',
    'withdrawal transaction not bound',
    'withdrawn masks still present',
    # Shared protected-file helpers the deadline store reads through
    # (activation_store._private_directory/_read_file_at, operator_store._protected).
    'activation approval directory is not private',
    'activation approval file permissions or size refused',
    'activation approval file changed while reading',
    'operator trust storage is not protected',
    'operator trust file must have one link',
    # Retained deadline and grant stores, and the first-admission wrapper
    # (Nexus#324): the reason a prior-boot record was not archived is visible.
    'archived prior boot deadline changed',
    'archived prior boot grant changed',
    'bootstrap archive is not on the state filesystem',
    'bootstrap archive unavailable',
    'bootstrap checkpoint publication changed',
    'bootstrap deadline was already initialized',
    'bootstrap state changed during transaction',
    'bootstrap state directory replaced',
    'bootstrap state has an unfinished transaction',
    'bootstrap transaction already exists',
    'bootstrap transaction boot binding differs',
    'bootstrap transaction candidate changed',
    'bootstrap transaction changed during update',
    'bootstrap transaction changed while reading',
    'bootstrap transaction compare value required',
    'bootstrap transaction compare-and-swap refused',
    'bootstrap transaction directory changed',
    'bootstrap transaction file attributes refused',
    'bootstrap transaction file refused',
    'bootstrap transaction publication changed',
    'bootstrap transaction publication refused; inspect retained state',
    'bootstrap transaction replacement changed',
    'bootstrap transaction store busy',
    'bootstrap transaction store closed',
    'bootstrap transaction store configuration refused',
    'bootstrap transaction store unavailable',
    'bootstrap transaction unavailable',
    'bootstrap transaction update refused; inspect retained state',
    'canonical bootstrap boot identity required',
    'freshly verified bootstrap approval required',
    'held bootstrap transaction guard required',
    'initial bootstrap state changed during publication',
    'initial deadline must be its admission observation',
    'invalid retained deadline fields',
    'original bootstrap deadline changed',
    'prepared bootstrap transaction required',
    'prior boot deadline changed before archive',
    'prior boot deadline has the same approval',
    'prior boot deadline is incomplete',
    'prior boot deadline is not canonical',
    'prior boot deadline records differ',
    'prior boot deadline retirement record unconfirmed',
    'prior boot grant archive composition unavailable',
    'prior boot grant archive record required',
    'prior boot grant archive record unconfirmed',
    'prior boot grant archive refused',
    'prior boot grant changed before archive',
    'prior boot record already archived',
    'protected bootstrap runtime inputs refused',
    'protected bootstrap state refused',
    'retained deadline binding or canonical form changed',
    'retained deadline exceeds bound',
    'retained deadline value required',
    'unfinished bootstrap transaction requires review',
})


_FAILURE_CHAIN_LIMIT = 4


def _failure_label(exc: BaseException) -> str:
    """Class name, plus the message only when it is a reviewed static literal.

    Exactly ApprovalRefused, SelectionReadRefused or UnitOperationFailed, one
    argument, and membership in the allowlist. Anything else (other classes,
    subclasses, interpolated or unreviewed messages) stays class-only.
    """

    from azazel_nexus.operator_trust import ApprovalRefused
    from azazel_nexus.bootstrap_selection_store import SelectionReadRefused

    from .units import UnitOperationFailed

    def one(error: BaseException) -> str | None:
        if type(error) not in (ApprovalRefused, SelectionReadRefused, UnitOperationFailed) or len(error.args) != 1:
            return None
        message = error.args[0]
        if type(message) is str and message in _STATIC_FAILURE_MESSAGES:
            return message
        return None

    name = type(exc).__name__
    first = one(exc)
    if first is None:
        return name
    # Follow the cause chain (also a suppressed context: only reviewed literals
    # are ever printed) so the root reason is visible, e.g. a selection bound to
    # an earlier boot. Bounded; stops at the first unreviewed link.
    reasons = [first]
    seen = {id(exc)}
    error = exc
    while len(reasons) < _FAILURE_CHAIN_LIMIT:
        error = error.__cause__ if error.__cause__ is not None else error.__context__
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        reason = one(error)
        if reason is None:
            break
        if reason != reasons[-1]:
            reasons.append(reason)
    return f"{name}: " + " <- ".join(reasons)


def _locked_pass(
    *, manager: UnitManager, root: Path, now: str, actor: str,
    stop_authority: Optional[ContextdStopAuthority], invocation_id: str,
    clock=time.monotonic, sleep=time.sleep, producers=None,
    budget_seconds: float = MAIN_PASS_BUDGET_SECONDS,
    reserve_seconds: float = MAIN_PASS_RESERVE_SECONDS,
    ready_seconds: float = MAIN_PASS_READY_SECONDS,
    started: Optional[float] = None, fresh_manager=None,
) -> ActivationOutcome:
    """The main pass under the pass lock, from the lock to READY's barrier.

    The lock is taken with a bounded wait; if it cannot be, the pass changes
    nothing (no marker, mask, reload, stop, ledger record or READY), prints a
    stable journal line and fails: the holder owns the state. Nothing before
    the acquisition mutates. The recheck holds the same lock while it
    evaluates, so the two never change markers and unit state at once.

    One budget covers everything from `started` (taken by `main` before the
    bus connects) to the end of any narrowing. It is kept cooperatively: the
    phases end `reserve_seconds` before it and are checked between each other,
    and every bus call is limited to the time that remains (`bind_remaining`).
    Nothing is interrupted asynchronously, so a ledger append or a high-water
    commit always completes. Every way out that narrows (an expired budget, a
    failed READY or barrier, an emergency narrowing in the pass, a finished
    bus session) does so under the lock and under the end of the whole budget, so the
    reserve is really available to it. A bus session whose call timed out is
    finished and never reused: the narrowing runs on `fresh_manager()` (a new
    session, connected inside the same deadline) with that session's manager
    and stop authority.
    """
    begin = clock() if started is None else started
    final = begin + budget_seconds
    work = final - reserve_seconds - ready_seconds

    hold_state = QueuedJobState()

    def narrow(message: str) -> None:
        # Only ever called while pass.lock is held: the holder owns the state.
        aids = _contextd_aids(
            root, now=now, actor=actor, invocation_id=invocation_id,
            until=final, clock=clock, sleep=sleep, record=True, hold_state=hold_state,
            fresh=fresh_manager)
        _narrow_final(manager, root, message, until=final, clock=clock,
                      fresh_manager=fresh_manager, authority=stop_authority, aids=aids)

    def not_the_holder(why: str) -> None:
        # A pass that does not own pass.lock changes NOTHING: no marker removal,
        # no mask, reload or stop, no ledger record, no READY. The holder (the
        # recheck, or another pass) owns the state and the ledger head, and
        # touching either could race its transaction. The journal line and the
        # non-zero exit are the whole report. This pass never sent READY, so a
        # start job that pulled it in fails through Requires= (fail-closed); a
        # running broker is the holder's or the recheck's to handle.
        print(NO_LOCK_NO_RECORD_MESSAGE, file=sys.stderr)
        error = RuntimeError(f"{why}; nothing was changed")
        error.narrowed = True  # nothing to narrow again
        raise error

    bind_remaining(manager, work, clock)
    try:
        wait = max(0.0, min(PASS_LOCK_WAIT_SECONDS, work - clock()))
        try:
            lock = acquire_pass_lock(root, wait_seconds=wait, clock=clock, sleep=sleep)
        except (PassLockBusy, PassLockRefused):
            not_the_holder("the activation pass lock could not be taken")
        expired = False
        with lock:
            try:
                outcome = _run_once(
                    manager=manager, root=root, now=now, actor=actor, producers=producers,
                    stop_authority=stop_authority, deadline=work, clock=clock,
                    sleep=sleep, invocation_id=invocation_id,
                    fresh_manager=fresh_manager, hold_state=hold_state)
                check_budget(work, clock)
                # Type=notify: without READY the controller's start fails and
                # every unit with Requires=/After= on it fails as a dependency.
                # READY is sent only after the pass, its markers and its
                # record are complete, and the lock is kept until its barrier
                # has returned.
                _notify_ready_or_withdraw(manager, root, now=now, actor=actor,
                                          until=final, clock=clock,
                                          fresh_manager=fresh_manager,
                                          stop_authority=stop_authority,
                                          invocation_id=invocation_id, sleep=sleep,
                                          hold_state=hold_state)
            except PassBudgetExpired:
                expired = True
            except Exception as error:
                # Any error that did not already come out of a narrowing is narrowed
                # here, still under the lock, whatever it is (a ledger that is
                # unavailable or whose chain is broken, a state file, a finished
                # bus session, a spent time budget) and whether or not a start job
                # is being held: the held job is replaced before the broker is
                # masked, then the units are masked, the manager reloaded and the
                # broker withdrawn. The original error is then raised again; a
                # failure of the narrowing is chained to it, never replacing it.
                # (SIGTERM ends the process by Python's default and raises
                # nothing, so no exception is involved there.)
                if not getattr(error, "narrowed", False):
                    # One reason, one call. A finished session or spent time is named
                    # as such; anything else is "unexpected".
                    reason = (
                        "the bus session finished or the time ended during the activation pass"
                        if (clock() >= work or (
                            fresh_manager is not None
                            and getattr(getattr(manager, "call", None), "broken", False)))
                        else "the activation pass failed unexpectedly")
                    try:
                        narrow(reason)
                    except Exception as narrowing:  # noqa: BLE001 - chained, then the original
                        # `narrow` raises its own error (it always does); the original
                        # object is the one that comes out, with the narrowing chained
                        # to it, marked narrowed so no outer layer contains it again.
                        error.narrowed = True
                        print("az-activated the narrowing after an unexpected error failed "
                              f"({type(narrowing).__name__})", file=sys.stderr)
                        raise error from narrowing
                raise
            if expired:
                # Every ledger append of the pass happens while pass.lock is
                # held, so a new holder cannot extend the same head.
                try:
                    _activation_ledger(root).append({
                        "event_type": "activation.pass_budget_expired",
                        "occurred_at": now, "actor": actor,
                    })
                except Exception:  # noqa: BLE001 - narrowing below is unconditional
                    pass
                narrow("the activation pass used its whole time budget")
    except PassBudgetExpired:
        # Before the lock was held (nothing there checks the budget; a safety net).
        not_the_holder("the activation pass budget ended before the lock was held")
    return outcome


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run one fail-closed activation pass against systemd's system bus.

    A zero exit status means the pass completed and its decision was recorded;
    it does **not** mean any unit was granted. Since #206 P4 a pass may grant
    the SUPPORTING loop units named by a verified v2 approval on a healthy
    node; a grant enables a unit for a later boot and writes its per-boot
    marker, and never starts it.
    """

    entered = time.monotonic()  # the anchor of the bootstrap path's absolute end
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

    global _bootstrap_shared_end
    # ONE absolute end for every bootstrap narrowing of this process, counted from
    # the entry of main (not from the first narrowing: the selection, the
    # transaction, the marker reset and the claim come first).
    _bootstrap_shared_end = entered + _BOOTSTRAP_PROCESS_SECONDS
    now = (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    try:
        from azazel_nexus.bootstrap_selection_optional import (
            load_optional_bootstrap_selection,
        )

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
        # The budget starts here, so that connecting to the bus counts.
        started = time.monotonic()

        def work_left(begin=started) -> float:
            return begin + MAIN_PASS_BUDGET_SECONDS - _AFTER_PHASES - time.monotonic()

        @contextlib.contextmanager
        def fresh_manager():
            # A new session for a narrowing after a call timed out. Its connect
            # is bounded by what is left of the whole budget.
            with SystemdBusSession.connect(
                    lambda: started + MAIN_PASS_BUDGET_SECONDS - time.monotonic()) as other:
                yield DbusUnitManager(call=other), ContextdStopAuthority.from_session(other)

        with SystemdBusSession.connect(work_left) as session:
            manager = DbusUnitManager(call=session)
            # READY is sent only after the pass, its markers and its record
            # are complete. The process exits right after READY, so it waits
            # (bounded) for systemd to process it first (BARRIER=1).
            outcome = _locked_pass(
                manager=manager,
                root=Path("/"),
                now=now,
                actor="azazel-activated",
                stop_authority=ContextdStopAuthority.from_session(session),
                invocation_id=invocation_id,
                started=started,
                fresh_manager=fresh_manager,
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

    # Only after READY and its barrier: "completed" names a start systemd saw.
    reasons = sorted({verdict.reason.split(":", 1)[0] for verdict in outcome.verdicts})
    print(
        f"az-activated completed safely: granted={len(outcome.granted)}, "
        f"withheld={len(outcome.withheld)}, reasons={','.join(reasons)}"
    )
    return 0


def _notify_ready_or_withdraw(manager: UnitManager, root: Path, *, now: str,
                              actor: str, until: Optional[float] = None,
                              clock=time.monotonic, fresh_manager=None,
                              stop_authority=None, invocation_id: str = "",
                              sleep=time.sleep, hold_state=None) -> None:
    """Send READY and wait for its barrier; on any failure withdraw, then raise.

    A refused READY, or a barrier that fails or times out, leaves it unknown
    whether systemd counted this start as successful (#251 L-2). The safe side
    is the state of a failed pass: every grant marker removed and every
    governed unit masked (``_emergency_narrow``), then a non-zero exit.

    Best effort, not a guarantee: if systemd had already processed READY, the
    dependents' ``ConditionPathExists=`` may be evaluated concurrently with
    this withdrawal. A start job evaluated after the marker is gone is
    skipped; a unit that started inside that window is not stopped (the stop
    authority covers the Knowledge Context broker alone), and its remask fails
    with "masked unit has no confirmed inactive state", which still exits
    non-zero.

    The failure is recorded as ``activation.readiness_unconfirmed`` when the
    ledger can be written; a record that fails never stands between this
    failure and the withdrawal (as for ``activation.grant_markers_unwritten``).
    """
    try:
        from . import systemd_notify

        systemd_notify.notify_ready()
        systemd_notify.notify_barrier()
    except Exception:  # noqa: BLE001 - withdrawn below; nothing widens
        print("az-activated readiness notification unavailable; withdrawing grants",
              file=sys.stderr)
        try:
            _activation_ledger(root).append({
                "event_type": "activation.readiness_unconfirmed",
                "occurred_at": now, "actor": actor,
            })
        except Exception:  # noqa: BLE001 - narrowing below is unconditional
            pass
        if until is not None:
            aids = _contextd_aids(
                root, now=now, actor=actor, invocation_id=invocation_id,
                until=until, clock=clock, sleep=sleep, record=True, hold_state=hold_state,
                fresh=fresh_manager)
            _narrow_final(manager, root, "activation readiness notification unavailable",
                          until=until, clock=clock, fresh_manager=fresh_manager,
                          authority=stop_authority, aids=aids)
        _emergency_narrow(manager, root, "activation readiness notification unavailable")


if __name__ == "__main__":  # pragma: no cover - the entry point
    raise SystemExit(main())
