"""Synchronous narrowing adapter for the bootstrap supervisor.

Each operation owns and closes its dedicated system-bus session. Widening
remains refused: no reviewed persistent-mask/lifetime/reboot grant backend is
installed. Merely constructing this adapter neither connects nor operates.
"""

import asyncio
from contextlib import contextmanager
import math
import os
import time

from azazel_nexus.bootstrap_grant_transaction import GrantTransaction, advance_transaction
from azazel_nexus.bootstrap_approval import VerifiedBootstrapApproval
from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.bootstrap_overlay_journal import overlay_journal_store_in_transaction

from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .bootstrap_start import BootstrapStartJobs
from .bootstrap_start_bridge import _StartCheckpointBridge
from .bootstrap_audit_identity import BootstrapAuditIdentityInspector
from .bootstrap_audit_peer import AuditPeerBinding
from .bootstrap_audit_client import BootstrapAuditClient
from .bootstrap_commission_identity import BootstrapCommissionIdentityInspector
from .bootstrap_commission_peer import CommissionPeerBinding
from .bootstrap_commission_client import BootstrapCommissionClient
from .bootstrap_loaded import BootstrapLoadedUnitInspector, LoadedBootstrapUnit
from .bootstrap_loaded_policy import load_loaded_bootstrap_policy
from .bootstrap_prerequisites import BootstrapPrerequisiteInspector
from .bootstrap_start_closure import BootstrapStartClosureInspector
from .bootstrap_controller import BootstrapControllerInspector, BootstrapControllerNotReady
from .bootstrap_controller_identity import current_bootstrap_controller_identity
from .bootstrap_overlay_files import (
    _mask_paths, _publish_verified_approval_at, _check_published_pair_at,
)
from .bootstrap_masked import BootstrapMaskedPairInspector, MaskedBootstrapPair, _observe_profile
from .bootstrap_job_drain import BootstrapJobDrain
from .bootstrap_close import BootstrapCloseSequence
from .bootstrap_close_files import BootstrapClosedOverlayFiles
from .bootstrap_restore import BootstrapRestoreSequence
from .bootstrap_withdrawal import BootstrapWithdrawalFiles
from .bootstrap_stopped import BootstrapStoppedPairInspector, StoppedBootstrapPair
from .bootstrap_cgroup import validate_cgroup_root
from .bootstrap_cgroup_mount import BootstrapCgroupMount, open_bootstrap_cgroup_mount
from .bootstrap_directory_paths import open_bootstrap_overlay_directories
from .bootstrap_systemd_profile import (
    SystemdBootstrapProfile,
    observe_bootstrap_systemd_profile,
    bootstrap_systemd_profile_digest,
)
from .systemd_bus import SystemdBusSession
from .units import DbusUnitManager, UNIT_NAMES, UnitKey, UnitOperationFailed, UnitState

_PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
_LOAD_ROOTS = frozenset(UNIT_NAMES[unit] for unit in _PAIR)


@contextmanager
def bootstrap_narrowing_manager_in_transaction(guard, *, job_timeout_seconds):
    """Own fixed filesystem/cgroup dependencies for the supervisor's held lock.

    This prepares only narrowing. It neither acquires another lock nor calls
    systemd, publishes a journal, creates directories, or enables starts.
    Entry-point composition must retain this context for the entire supervisor
    transaction, including cleanup. Missing deployment prerequisites refuse.
    """
    if type(guard) is not BootstrapTransactionGuard:
        raise ValueError("held bootstrap transaction required")
    guard()
    with open_bootstrap_overlay_directories() as directories, \
            overlay_journal_store_in_transaction(guard) as store, \
            open_bootstrap_cgroup_mount() as mount:
        directories.check()
        guard()
        manager = BootstrapNarrowingManager(
            job_timeout_seconds=job_timeout_seconds,
            closed_overlay_files=directories.closed_files(journal_store=store, guard=guard),
            withdrawal_files=directories.withdrawal_files(journal_store=store, guard=guard),
            cgroup_mount=mount,
        )
        manager._publication_inputs = (directories, store, guard)
        yield manager


def _name(unit):
    if type(unit) is not UnitKey or unit not in _PAIR:
        raise UnitOperationFailed("bootstrap manager unit outside exact pair")
    return UNIT_NAMES[unit]


def _require_profile(session):
    profile = session.bootstrap_profile()
    if type(profile) is not SystemdBootstrapProfile:
        raise UnitOperationFailed("systemd compatibility profile was not admitted")
    recognized = observe_bootstrap_systemd_profile(
        version=profile.version, unit_path=list(profile.unit_path),
    )
    if recognized != profile:
        raise UnitOperationFailed("systemd compatibility profile was not admitted")


# Grant phases before any pair publication can have been attempted. A closing
# grant qualifies only through the fresh unjournaled-baseline observation.
_UNPUBLISHED_PHASES = frozenset({"prepared", "pair_grant_intent", "closing"})


class BootstrapNarrowingManager:
    """Trusted composition dependency, not a CLI/RPC or general unit API.

    The factory is a private composition/testing seam, not a caller-selected bus
    address. Production must use the fixed system-bus factory and an independently
    admitted closure. This class cannot turn a bootstrap approval into a start.

    cgroup_root_fd is BORROWED, like the file backend's descriptors and held
    transaction guard. Composition must keep it open and must not reuse its
    number for the lifetime of this manager. The constructor pins its identity;
    each observation validates then owns a duplicate until session teardown.
    The manager never closes the borrowed original. Early caller close/reuse
    refuses; it is not repaired by opening a path or choosing another mount.
    """

    def __init__(
        self, *, job_timeout_seconds: float, session_factory=SystemdBusSession.connect,
        closed_overlay_files=None,
        cgroup_root_fd=None, cgroup_owner_uid=None,
        withdrawal_files=None,
        cgroup_mount=None,
    ):
        if (
            type(job_timeout_seconds) not in (int, float)
            or not math.isfinite(job_timeout_seconds)
            or job_timeout_seconds <= 0
        ):
            raise ValueError("explicit finite positive job timeout required")
        self._timeout = job_timeout_seconds
        self._factory = session_factory
        if (closed_overlay_files is not None
                and type(closed_overlay_files) is not BootstrapClosedOverlayFiles):
            raise ValueError("trusted owned-overlay closure required")
        self._closed_overlay_files = closed_overlay_files
        if withdrawal_files is not None and type(withdrawal_files) is not BootstrapWithdrawalFiles:
            raise ValueError("trusted owned-overlay withdrawal required")
        self._withdrawal_files = withdrawal_files
        self._containment_files = closed_overlay_files
        self._closed_observation = None
        self._withdrawal_kind = None
        self._publication_inputs = None
        self._publication_check = None
        self._controller_binding = None
        self._controller_grant = None
        self._controller_notification_sent = False
        self._controller_ready_confirmed = False
        self._audit_peer_binding = None
        self._commission_peer_binding = None
        self._authenticated_audit_client = BootstrapAuditClient(
            binding_source=self._audit_binding_source,
        )
        self._authenticated_commission_client = BootstrapCommissionClient(
            binding_source=self._commission_binding_source,
        )
        if cgroup_mount is not None:
            if (type(cgroup_mount) is not BootstrapCgroupMount
                    or cgroup_root_fd is not None or cgroup_owner_uid is not None):
                raise ValueError("exclusive admitted cgroup mount required")
            cgroup_root_fd = cgroup_mount.fileno()
            cgroup_owner_uid = 0
        self._cgroup_mount = cgroup_mount
        self._cgroup_root_fd = cgroup_root_fd
        self._cgroup_owner_uid = cgroup_owner_uid
        self._cgroup_root_identity = None
        if cgroup_root_fd is not None:
            info = validate_cgroup_root(cgroup_root_fd, cgroup_owner_uid)
            self._cgroup_root_identity = (info.st_dev, info.st_ino)
        elif cgroup_owner_uid is not None:
            raise ValueError("cgroup owner without root descriptor")

    @contextmanager
    def _session(self):
        session = self._factory()
        failed = False
        try:
            yield session
        except BaseException:
            failed = True
            raise
        finally:
            try:
                session.close()
            except Exception:
                if not failed:
                    raise UnitOperationFailed(
                        "bootstrap bus session cleanup failed"
                    ) from None

    def mask(self, unit: UnitKey) -> None:
        name = _name(unit)
        with self._session() as session:
            DbusUnitManager(session).mask(name)

    def close_starts(self) -> None:
        self._publication_check = None
        self._closed_observation = None
        self._audit_peer_binding = None
        self._commission_peer_binding = None
        self._controller_binding = None
        self._controller_grant = None
        self._controller_ready_confirmed = False
        self._containment_files = self._closed_overlay_files
        if self._withdrawal_files is not None and self._withdrawal_files.resume_closure():
            self._containment_files = self._withdrawal_files
        # Refusing our own Start calls does not fence jobs submitted elsewhere
        # or before this process. Do not report a deployment guarantee from a
        # process-local boolean or from persistent masks alone.
        if self._containment_files is None:
            raise UnitOperationFailed(
                "bootstrap deployment start-job fence unavailable"
            )

        def operation(session):
            return BootstrapCloseSequence(
                bus=session._bus, message_factory=session._message_factory,
                message_type=session._message_type, timeout_seconds=self._timeout,
                files=self._containment_files,
            ).close()

        self._closed_observation = self._run_owned(operation)

    def confirm_empty_pair(self) -> None:
        """Fresh observations, not a cached successful close or inactive flag."""
        self._check_cgroup_mount()
        masked = self._closed_observation
        if (masked is None or self._containment_files is None
                or self._cgroup_root_identity is None):
            raise UnitOperationFailed("bootstrap cgroup composition unavailable")
        info = validate_cgroup_root(self._cgroup_root_fd, self._cgroup_owner_uid)
        if (info.st_dev, info.st_ino) != self._cgroup_root_identity:
            raise UnitOperationFailed("bootstrap cgroup root identity changed")
        try:
            root = os.dup(self._cgroup_root_fd)
        except OSError:
            raise UnitOperationFailed("bootstrap cgroup root unavailable") from None

        def operation(session):
            arguments = dict(bus=session._bus, message_factory=session._message_factory,
                             message_type=session._message_type, timeout_seconds=self._timeout)

            async def check_closed():
                self._check_cgroup_mount()
                if self._containment_files.check() != masked.fragments:
                    raise UnitOperationFailed("bootstrap owned closure changed")
                current = await BootstrapMaskedPairInspector(
                    **arguments, expected_owner=masked.owner,
                    expected_fragments=masked.fragments,
                ).inspect()
                if (not current.same_closure(masked)
                        or self._containment_files.check() != masked.fragments):
                    raise UnitOperationFailed("bootstrap loaded closure changed")
                self._check_cgroup_mount()

            return BootstrapStoppedPairInspector(
                **arguments, expected_owner=masked.owner, cgroup_root_fd=root,
                owner_uid=self._cgroup_owner_uid, check_closed=check_closed,
            ).inspect()

        try:
            held = validate_cgroup_root(root, self._cgroup_owner_uid)
            if (held.st_dev, held.st_ino) != self._cgroup_root_identity:
                raise UnitOperationFailed("bootstrap cgroup root changed")
            self._run_owned(operation)
            self._check_cgroup_mount()
        finally:
            os.close(root)

    def stop_closed_pair(self, *, cgroup_root_fd: int, owner_uid: int) -> StoppedBootstrapPair:
        """Close, stop and observe the fixed pair on one owned bus session.

        The root is a trusted composition descriptor, never CLI/RPC input.
        Production must independently admit the cgroup-v2 mount and unit
        no-escape hardening. This does not withdraw files or create a grant.
        """
        self._check_cgroup_mount()
        if self._closed_overlay_files is None:
            raise UnitOperationFailed("owned bootstrap closure unavailable")
        original = validate_cgroup_root(cgroup_root_fd, owner_uid)
        if self._cgroup_mount is not None and (
            (original.st_dev, original.st_ino) != self._cgroup_root_identity or owner_uid != 0
        ):
            raise UnitOperationFailed("stop root differs from admitted cgroup mount")
        try:
            held_root = os.dup(self._cgroup_mount.fileno()
                               if self._cgroup_mount is not None else cgroup_root_fd)
        except OSError:
            raise UnitOperationFailed("bootstrap cgroup root unavailable") from None

        def operation(session):
            arguments = dict(bus=session._bus, message_factory=session._message_factory,
                             message_type=session._message_type, timeout_seconds=self._timeout)
            budget = BootstrapStopJobs(**arguments)

            async def transaction():
                masked = await BootstrapCloseSequence(
                    **arguments, files=self._closed_overlay_files,
                ).close()

                async def check_closed():
                    self._check_cgroup_mount()
                    if self._closed_overlay_files.check() != masked.fragments:
                        raise UnitOperationFailed("bootstrap owned closure changed")
                    current = await BootstrapMaskedPairInspector(
                        **arguments, expected_owner=masked.owner,
                        expected_fragments=masked.fragments,
                    ).inspect()
                    if (not current.same_closure(masked)
                            or self._closed_overlay_files.check() != masked.fragments):
                        raise UnitOperationFailed("bootstrap loaded closure changed")
                    self._check_cgroup_mount()

                for unit in reversed(_PAIR):
                    await check_closed()
                    await BootstrapStopJobs(
                        **arguments, expected_owner=masked.owner,
                    ).stop_and_wait(unit)
                    await check_closed()
                return await BootstrapStoppedPairInspector(
                    **arguments, expected_owner=masked.owner,
                    cgroup_root_fd=held_root, owner_uid=owner_uid,
                    check_closed=check_closed,
                ).inspect()

            return budget._bounded(transaction())

        try:
            held = validate_cgroup_root(held_root, owner_uid)
            if (held.st_dev, held.st_ino) != (original.st_dev, original.st_ino):
                raise UnitOperationFailed("bootstrap cgroup root changed")
            return self._run_owned(operation)
        finally:
            os.close(held_root)

    def drain_pending_jobs(self, *, check_closed, expected_owner=None) -> None:
        """Cancel only pair jobs under a separately established start fence.

        Trusted composition supplies the async fence revalidator; no RPC/CLI
        input chooses units, jobs or a bus. This is only the queue-drain step,
        not close_starts, proof of stopped helpers, or grant authorization.
        """
        if not callable(check_closed):
            raise ValueError("independent closed-start fence revalidator required")
        _validate_expected_owner(expected_owner)

        def operation(session):
            return BootstrapJobDrain(
                bus=session._bus,
                message_factory=session._message_factory,
                message_type=session._message_type,
                timeout_seconds=self._timeout,
                check_closed=check_closed,
                expected_owner=expected_owner,
            ).drain()

        self._run_owned(operation)

    def is_masked(self, unit: UnitKey) -> bool:
        name = _name(unit)
        with self._session() as session:
            return DbusUnitManager(session).state(name) is UnitState.MASKED

    def inspect_masked_pair(self, *, expected_owner=None) -> MaskedBootstrapPair:
        """Read both loaded masks on a dedicated connection.

        Unlike GetUnitFileState, this checks the manager's loaded projection.
        It neither reloads the manager nor proves file ownership, stopped jobs,
        process containment, or a continuing start fence.
        """
        _validate_expected_owner(expected_owner)

        def operation(session):
            _require_profile(session)
            return BootstrapMaskedPairInspector(
                bus=session._bus,
                message_factory=session._message_factory,
                message_type=session._message_type,
                timeout_seconds=self._timeout,
                expected_owner=expected_owner,
            ).inspect()

        return self._run_owned(operation)

    def is_inactive(self, unit: UnitKey) -> bool:
        name = _name(unit)
        masked = self._closed_observation
        if masked is None:
            with self._session() as session:
                return DbusUnitManager(session).is_inactive(name)
        # Under a confirmed fence the unit's mask may be the owned empty
        # overlay ("masked-runtime"), which the generic unloaded-unit read
        # refuses; observe it against the fence's attested fragment instead.
        if type(masked) is not MaskedBootstrapPair:
            raise UnitOperationFailed("bootstrap inactivity fence unavailable")
        fragment = dict(masked.fragments).get(unit)
        if type(fragment) is not str:
            raise UnitOperationFailed("bootstrap inactivity fragment unavailable")

        def operation(session):
            return BootstrapStopJobs(
                bus=session._bus, message_factory=session._message_factory,
                message_type=session._message_type, timeout_seconds=self._timeout,
                expected_owner=masked.owner,
            ).observe_inactive(unit, fragment=fragment)

        return self._run_owned(operation) is True

    def stop_and_wait(self, unit: UnitKey) -> None:
        _name(unit)

        def operation(session):
            client = BootstrapStopJobs(
                bus=session._bus,
                message_factory=session._message_factory,
                message_type=session._message_type,
                timeout_seconds=self._timeout,
                expected_owner=(self._closed_observation.owner
                                if self._closed_observation is not None else None),
            )
            return client.stop_and_wait(unit)

        self._run_owned(operation)

    def inspect_loaded(
        self, unit: UnitKey, *, expected_dependencies, expected_service_settings,
        expected_owner,
    ) -> LoadedBootstrapUnit:
        """Observe a fixed helper through an owned read-only bus transaction.

        Expectations belong to trusted composition, never an RPC caller or the
        observed manager. The result is a projection, not startup authorization
        or complete semantic admission. The host must also match an explicitly
        reviewed systemd compatibility profile. Widening stays unavailable.
        """
        _name(unit)
        if _validate_expected_owner(expected_owner) is None:
            raise ValueError("enclosing systemd owner required for loaded inspection")

        def operation(session):
            _require_profile(session)
            client = BootstrapLoadedUnitInspector(
                bus=session._bus,
                message_factory=session._message_factory,
                message_type=session._message_type,
                timeout_seconds=self._timeout,
                expected_service_settings=expected_service_settings,
                expected_owner=expected_owner,
            )
            return client.inspect(unit, expected_dependencies=expected_dependencies)

        return self._run_owned(operation)

    def _run_owned(self, operation):
        with self._owned_loop() as session:
            return session._loop.run_until_complete(operation(session))

    async def _drain_owned_tasks(self):
        """Cancel descendants too, without restarting the teardown budget."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._timeout
        current = asyncio.current_task()
        cancelled = set()
        while True:
            # Cancellation/finalizers can create cleanup tasks after the first
            # snapshot. Yield before enumerating, and rescan within one budget.
            await asyncio.sleep(0)
            pending = asyncio.all_tasks(loop) - {current}
            if not pending:
                if loop.time() >= deadline:
                    raise UnitOperationFailed("bootstrap bus teardown budget exhausted")
                return
            for task in pending - cancelled:
                task.cancel()
                cancelled.add(task)
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise UnitOperationFailed("bootstrap bus tasks did not quiesce")
            done, _pending = await asyncio.wait(pending, timeout=min(remaining, 0.01))
            for task in done:
                try:
                    task.result()
                except BaseException:
                    pass  # Preserve the operation's failure, not cancellation noise.

    @contextmanager
    def _owned_loop(self):
        with self._session() as session:
            loop = session._loop
            if loop.is_closed() or loop.is_running():
                raise UnitOperationFailed("bootstrap operation requires its owned idle loop")
            failed = False
            try:
                yield session
            except BaseException:
                failed = True
                raise
            finally:
                # Disconnect before draining: a lost/late reply cannot escape
                # this dedicated session into the next supervisor operation.
                try:
                    try:
                        session._bus.disconnect()
                    finally:
                        loop.run_until_complete(self._drain_owned_tasks())
                except Exception:
                    if not failed:
                        raise UnitOperationFailed(
                            "bootstrap operation session cleanup failed"
                        ) from None

    def _run_owned_start(self, unit: UnitKey, *, expected_owner, check_start):
        """Private job composition; not reachable from production start API."""
        _name(unit)
        if not self._controller_ready_confirmed:
            raise UnitOperationFailed("controller READY barrier not confirmed")
        if _validate_expected_owner(expected_owner) is None or not callable(check_start):
            raise UnitOperationFailed("retained owner and start checkpoint required")
        with self._owned_loop() as session:
            client = BootstrapStartJobs(
                bus=session._bus, message_factory=session._message_factory,
                message_type=session._message_type, timeout_seconds=self._timeout,
                expected_owner=expected_owner, check_start=check_start,
                load_first=True,
            )
            bridge = _StartCheckpointBridge(session._loop, client._observer)
            return bridge.run(
                client._start_with_checkpoint(unit, bridge.checkpoint), check_start,
            )

    def _start_bound_audit(self, transaction, *, check_start):
        """Compose the audit job and peer capture; public widening stays closed."""
        binding = self._controller_binding
        grant = self._controller_grant
        if (not self._controller_ready_confirmed or binding is None
                or type(grant) is not GrantTransaction
                or type(transaction) is not GrantTransaction
                or self._audit_peer_binding is not None or not callable(check_start)):
            raise UnitOperationFailed("fresh retained audit start context required")
        opened = advance_transaction(grant, "pair_grant_opened")
        if transaction != advance_transaction(opened, "auditd_start_intent"):
            raise UnitOperationFailed("audit start transaction differs from publication")
        _identity, owner, profile_digest = binding

        def checkpoint():
            self._check_retained_publication()
            if (not self._controller_ready_confirmed
                    or self._controller_binding != binding or self._controller_grant != grant):
                raise UnitOperationFailed("audit start controller context changed")
            if check_start() is not None:
                raise UnitOperationFailed("audit start admission unconfirmed")
            self._check_retained_publication()
            if (not self._controller_ready_confirmed
                    or self._controller_binding != binding or self._controller_grant != grant):
                raise UnitOperationFailed("audit start controller context changed")

        checkpoint()
        self._run_owned_start(UnitKey.AUDITD, expected_owner=owner, check_start=checkpoint)
        checkpoint()
        self._capture_audit_peer_binding(
            expected_owner=owner, systemd_profile_digest=profile_digest,
            check_start=checkpoint,
        )

    def _observe_audit_identity(self, *, expected_owner, systemd_profile_digest):
        self._check_cgroup_mount()

        def operation(session):
            return BootstrapAuditIdentityInspector(
                bus=session._bus, message_factory=session._message_factory,
                message_type=session._message_type, timeout_seconds=self._timeout,
                expected_owner=expected_owner,
                systemd_profile_digest=systemd_profile_digest,
            ).inspect()

        identity = self._run_owned(operation)
        self._check_cgroup_mount()
        return identity

    def _observe_commission_identity(self, *, expected_owner, systemd_profile_digest):
        self._check_cgroup_mount()

        def operation(session):
            return BootstrapCommissionIdentityInspector(
                bus=session._bus, message_factory=session._message_factory,
                message_type=session._message_type, timeout_seconds=self._timeout,
                expected_owner=expected_owner,
                systemd_profile_digest=systemd_profile_digest,
            ).inspect()

        identity = self._run_owned(operation)
        self._check_cgroup_mount()
        return identity

    def _commission_binding_source(self):
        if type(self._commission_peer_binding) is not CommissionPeerBinding:
            raise UnitOperationFailed("retained commission peer binding unavailable")
        return self._commission_peer_binding

    def _start_bound_commission(self, transaction, *, check_start):
        """Private fixed second-helper composition, with supervisor receipt checks."""
        binding = self._controller_binding
        grant = self._controller_grant
        audit = self._audit_binding_source()
        if (not self._controller_ready_confirmed or binding is None
                or type(grant) is not GrantTransaction
                or type(transaction) is not GrantTransaction
                or transaction.phase != "commissiond_start_intent"
                or self._commission_peer_binding is not None or not callable(check_start)):
            raise UnitOperationFailed("fresh retained commission start context required")
        expected = grant
        for phase in ("pair_grant_opened", "auditd_start_intent", "auditd_ready"):
            expected = advance_transaction(expected, phase)
        expected = advance_transaction(
            expected, "audit_intent_recorded", evidence_digest=transaction.audit_receipt_digest,
        )
        if transaction != advance_transaction(expected, "commissiond_start_intent"):
            raise UnitOperationFailed("commission start differs from publication")
        _identity, owner, profile_digest = binding

        def checkpoint():
            def retained():
                if (not self._controller_ready_confirmed
                        or self._controller_binding != binding or self._controller_grant != grant
                        or self._audit_peer_binding is not audit):
                    raise UnitOperationFailed("commission start context changed")
            retained()
            self._check_retained_publication()
            # This trusted supervisor callback verifies the exact durable intent,
            # receipt-bearing transaction and fresh authenticated audit readiness.
            # A caller-supplied digest alone is not receipt provenance.
            if check_start() is not None:
                raise UnitOperationFailed("commission start admission unconfirmed")
            self._check_retained_publication()
            retained()

        checkpoint()
        self._run_owned_start(UnitKey.COMMISSIOND, expected_owner=owner, check_start=checkpoint)
        checkpoint()
        identity = self._observe_commission_identity(
            expected_owner=owner, systemd_profile_digest=profile_digest,
        )
        checkpoint()

        def revalidate():
            return self._observe_commission_identity(
                expected_owner=owner, systemd_profile_digest=profile_digest,
            )

        self._commission_peer_binding = CommissionPeerBinding(identity, revalidate)

    def _bound_helper_ready(self, unit):
        """Private live readiness; public widening remains unavailable."""
        _name(unit)
        if unit is UnitKey.AUDITD:
            self._authenticated_audit_client.observe_head()
        else:
            self._authenticated_commission_client.observe_inventory()
        return True

    def _capture_audit_peer_binding(self, *, expected_owner, systemd_profile_digest,
                                    check_start):
        """Post-start private composition; never adopt a replacement process."""
        if self._audit_peer_binding is not None or not callable(check_start):
            raise UnitOperationFailed("fresh audit binding and checkpoint required")
        if check_start() is not None:
            raise UnitOperationFailed("audit binding admission unconfirmed")
        identity = self._observe_audit_identity(
            expected_owner=expected_owner, systemd_profile_digest=systemd_profile_digest,
        )
        if check_start() is not None:
            raise UnitOperationFailed("audit binding admission unconfirmed")

        def revalidate():
            return self._observe_audit_identity(
                expected_owner=identity.owner, systemd_profile_digest=identity.profile_digest,
            )

        self._audit_peer_binding = AuditPeerBinding(identity, revalidate)

    def _audit_binding_source(self):
        if type(self._audit_peer_binding) is not AuditPeerBinding:
            raise UnitOperationFailed("retained audit peer binding unavailable")
        return self._audit_peer_binding

    def _bootstrap_audit_client(self):
        """Use this same client for append receipts and live-head reads."""
        return self._authenticated_audit_client

    def unmask(self, unit: UnitKey) -> None:
        _name(unit)
        raise UnitOperationFailed(
            "bootstrap deployment fencing unavailable; widening refused"
        )

    def _check_retained_publication(self):
        check = self._publication_check
        if not callable(check):
            raise UnitOperationFailed("retained publication admission unavailable")
        if check() is not None or self._publication_check is not check:
            raise UnitOperationFailed("retained publication admission changed")

    def _publish_and_inspect_pair(self, transaction, *, approval, check_publish):
        """Integrated preparation only; not complete closure/lifetime admission.

        Publishing/reloading is a widening mutation even without StartUnit.
        There is intentionally no production caller while open_pair's remaining
        admission obligations are unmet. Tests use ordinary files/fake systemd.
        Retained resources belong to the enclosing transaction factory.
        """
        self._publication_check = None
        if (self._publication_inputs is None
                or type(transaction) is not GrantTransaction
                or transaction.phase != "pair_grant_intent"
                or type(approval) is not VerifiedBootstrapApproval
                or not callable(check_publish)
                or type(self._closed_observation) is not MaskedBootstrapPair):
            raise UnitOperationFailed("publication composition unavailable")
        directories, store, guard = self._publication_inputs
        if type(guard) is not BootstrapTransactionGuard:
            raise UnitOperationFailed("held publication transaction required")
        closed = self._closed_observation
        owner = _validate_expected_owner(closed.owner)
        if owner is None:
            raise UnitOperationFailed("publication manager owner required")

        def checkpoint():
            guard()
            directories.check()
            if check_publish() is not None:
                raise UnitOperationFailed("publication admission unconfirmed")

        checkpoint()
        self._check_cgroup_mount()
        controller_identity = current_bootstrap_controller_identity()
        policy = load_loaded_bootstrap_policy(expected=approval.context)
        if self.confirm_empty_pair() is not None or self._closed_observation != closed:
            raise UnitOperationFailed("publication initial containment changed")
        paths = {name: directories.arguments[name] for name in (
            "overlay_fd", "masks_fd", "higher_priority_fd",
        )}
        paths["owner_uid"] = directories.owner_uid
        directories.check()
        masks = _mask_paths(**paths)
        checkpoint()
        # The initial absent/closed observation ceases to be a current fence
        # as soon as publication may begin, including partial failure.
        self._closed_observation = None
        published = _publish_verified_approval_at(
            **paths, journal_store=store, guard=guard, approval=approval,
            transaction=transaction, check_publish=checkpoint,
        )

        def check_files():
            directories.check()
            _check_published_pair_at(
                **paths, journal_store=store, guard=guard, expected=published,
                retained_mask_stamps=masks,
            )
            directories.check()

        check_files()
        checkpoint()  # Never call this synchronous admission path inside a loop.

        def operation(session):
            arguments = dict(bus=session._bus, message_factory=session._message_factory,
                             message_type=session._message_type, timeout_seconds=self._timeout)
            reader = BootstrapStopJobs(**arguments, expected_owner=owner)

            async def check_manager():
                check_files()
                if await reader._owner() != owner:
                    raise UnitOperationFailed("publication manager owner changed")
                reader._manager_owner = owner
                profile = await _observe_profile(reader)
                if bootstrap_systemd_profile_digest(profile) != policy.systemd_profile_digest:
                    raise UnitOperationFailed("publication systemd profile changed")
                if await reader._owner() != owner:
                    raise UnitOperationFailed("publication manager owner changed")
                check_files()

            async def inspect():
                await check_manager()
                controller = await BootstrapControllerInspector(
                    **arguments, expected_owner=owner,
                    systemd_profile_digest=policy.systemd_profile_digest,
                    identity=controller_identity, phase="pre-ready",
                ).inspect()
                await check_manager()
                if await reader._call("Reload", "", [], "") != []:
                    raise UnitOperationFailed("publication reload unconfirmed")
                await check_manager()
                closure = await BootstrapStartClosureInspector(
                    **arguments, expected_owner=owner,
                    systemd_profile_digest=policy.systemd_profile_digest,
                    load_roots=_LOAD_ROOTS,
                ).inspect()
                prerequisites = await BootstrapPrerequisiteInspector(
                    **arguments, expected_owner=owner, policy=policy,
                ).inspect()
                await check_manager()
                observations = []
                for unit in _PAIR:
                    expected = policy.units[unit]
                    observations.append(await BootstrapLoadedUnitInspector(
                        **arguments, expected_owner=owner, load_first=True,
                        expected_service_settings=expected.service_settings,
                    ).inspect(unit, expected_dependencies=expected.dependencies))
                    await check_manager()
                if await BootstrapPrerequisiteInspector(
                    **arguments, expected_owner=owner, policy=policy,
                ).inspect() != prerequisites:
                    raise UnitOperationFailed("publication prerequisite observations changed")
                if await BootstrapStartClosureInspector(
                    **arguments, expected_owner=owner,
                    systemd_profile_digest=policy.systemd_profile_digest,
                    load_roots=_LOAD_ROOTS,
                ).inspect() != closure:
                    raise UnitOperationFailed("publication start closure changed")
                await check_manager()
                if await BootstrapControllerInspector(
                    **arguments, expected_owner=owner,
                    systemd_profile_digest=policy.systemd_profile_digest,
                    identity=controller_identity, phase="pre-ready",
                ).inspect() != controller:
                    raise UnitOperationFailed("publication controller observation changed")
                await check_manager()
                return tuple(observations)

            return reader._bounded(inspect())

        observations = self._run_owned(operation)
        self._check_cgroup_mount()
        if current_bootstrap_controller_identity() != controller_identity:
            raise UnitOperationFailed("publication local controller identity changed")
        if load_loaded_bootstrap_policy(expected=approval.context) != policy:
            raise UnitOperationFailed("publication loaded policy changed")
        check_files()
        checkpoint()
        self._controller_binding = (controller_identity, owner, policy.systemd_profile_digest)
        self._controller_grant = transaction

        def retained_check():
            # The original publication callback binds an earlier transaction
            # phase. Start admission supplies a fresh phase-specific callback;
            # retain only the immutable publication and independent policy here.
            ready = self._controller_ready_confirmed
            phase = "ready" if ready else "pre-ready"

            def local_check():
                guard()
                check_files()
                self._check_cgroup_mount()
                if (self._controller_ready_confirmed is not ready
                        or self._controller_binding != (
                            controller_identity, owner, policy.systemd_profile_digest)
                        or self._controller_grant != transaction):
                    raise UnitOperationFailed("retained controller binding changed")
                if load_loaded_bootstrap_policy(expected=approval.context) != policy:
                    raise UnitOperationFailed("retained publication policy changed")
                if current_bootstrap_controller_identity() != controller_identity:
                    raise UnitOperationFailed("retained publication controller changed")

            local_check()

            def observe(session):
                arguments = dict(bus=session._bus, message_factory=session._message_factory,
                                 message_type=session._message_type, timeout_seconds=self._timeout)
                reader = BootstrapStopJobs(**arguments, expected_owner=owner)

                async def inspect():
                    if await reader._owner() != owner:
                        raise UnitOperationFailed("retained publication manager changed")
                    reader._manager_owner = owner
                    if bootstrap_systemd_profile_digest(await _observe_profile(reader)) != policy.systemd_profile_digest:
                        raise UnitOperationFailed("retained publication profile changed")
                    controller = await BootstrapControllerInspector(
                        **arguments, expected_owner=owner,
                        systemd_profile_digest=policy.systemd_profile_digest,
                        identity=controller_identity, phase=phase,
                    ).inspect()
                    closure = await BootstrapStartClosureInspector(
                        **arguments, expected_owner=owner,
                        systemd_profile_digest=policy.systemd_profile_digest,
                        load_roots=_LOAD_ROOTS,
                    ).inspect()
                    before = await BootstrapPrerequisiteInspector(
                        **arguments, expected_owner=owner, policy=policy,
                    ).inspect()
                    for unit in _PAIR:
                        expected = policy.units[unit]
                        # Validate against the same independent policy, not the
                        # pre-start fingerprint: ExecStartEx execution metadata
                        # legitimately changes after auditd starts.
                        await BootstrapLoadedUnitInspector(
                            **arguments, expected_owner=owner, load_first=True,
                            expected_service_settings=expected.service_settings,
                        ).inspect(unit, expected_dependencies=expected.dependencies)
                    if await BootstrapPrerequisiteInspector(
                        **arguments, expected_owner=owner, policy=policy,
                    ).inspect() != before or await reader._owner() != owner:
                        raise UnitOperationFailed("retained publication prerequisites changed")
                    if await BootstrapStartClosureInspector(
                        **arguments, expected_owner=owner,
                        systemd_profile_digest=policy.systemd_profile_digest,
                        load_roots=_LOAD_ROOTS,
                    ).inspect() != closure:
                        raise UnitOperationFailed("retained publication start closure changed")
                    if await BootstrapControllerInspector(
                        **arguments, expected_owner=owner,
                        systemd_profile_digest=policy.systemd_profile_digest,
                        identity=controller_identity, phase=phase,
                    ).inspect() != controller:
                        raise UnitOperationFailed("retained controller observation changed")
                    if bootstrap_systemd_profile_digest(await _observe_profile(reader)) != policy.systemd_profile_digest:
                        raise UnitOperationFailed("retained publication profile changed")

                    if await reader._owner() != owner:
                        raise UnitOperationFailed("retained publication manager changed")

                return reader._bounded(inspect())

            self._run_owned(observe)
            local_check()

        self._publication_check = retained_check
        return published, observations

    def confirm_controller_ready(self, transaction, *, check_ready, notify):
        """Notify once and confirm the retained controller, not a replacement."""
        binding = self._controller_binding
        grant = self._controller_grant
        if (binding is None or type(grant) is not GrantTransaction
                or type(transaction) is not GrantTransaction
                or transaction != advance_transaction(grant, "pair_grant_opened")
                or self._controller_notification_sent
                or not callable(check_ready) or not callable(notify)):
            raise UnitOperationFailed("retained controller READY context required")
        identity, owner, profile_digest = binding
        deadline = time.monotonic() + self._timeout

        def checkpoint():
            if (self._controller_binding != binding or self._controller_grant != grant
                    or time.monotonic() >= deadline):
                raise UnitOperationFailed("controller READY context expired or changed")
            self._check_cgroup_mount()
            if current_bootstrap_controller_identity() != identity:
                raise UnitOperationFailed("controller READY local identity changed")
            if check_ready() is not None:
                raise UnitOperationFailed("controller READY admission unconfirmed")
            if (self._controller_binding != binding or self._controller_grant != grant
                    or time.monotonic() >= deadline):
                raise UnitOperationFailed("controller READY context expired or changed")

        checkpoint()
        self._controller_notification_sent = True  # uncertain sends are never retried
        if notify() is not None:
            raise UnitOperationFailed("controller READY notification unconfirmed")
        checkpoint()
        with self._owned_loop() as session:
            while True:
                checkpoint()  # synchronous admission must run outside asyncio
                inspector = BootstrapControllerInspector(
                    bus=session._bus, message_factory=session._message_factory,
                    message_type=session._message_type,
                    timeout_seconds=deadline - time.monotonic(),
                    expected_owner=owner, systemd_profile_digest=profile_digest,
                    identity=identity, phase="ready",
                )
                try:
                    session._loop.run_until_complete(inspector.inspect())
                except BootstrapControllerNotReady:
                    checkpoint()
                    session._loop.run_until_complete(
                        asyncio.sleep(min(0.01, deadline - time.monotonic()))
                    )
                    continue
                checkpoint()
                break
        checkpoint()
        self._controller_ready_confirmed = True

    def open_pair(self, transaction: GrantTransaction, *, approval, check_publish) -> None:
        if type(transaction) is not GrantTransaction:
            raise UnitOperationFailed(
                "bootstrap transaction identity required for pair grant"
            )
        raise UnitOperationFailed(
            "bootstrap owned pair grant unavailable; widening refused"
        )

    def withdraw_pair(self, transaction: GrantTransaction) -> None:
        if type(transaction) is not GrantTransaction:
            raise UnitOperationFailed(
                "bootstrap transaction identity required for grant withdrawal"
            )
        self._withdrawal_kind = None
        baseline = self._closed_overlay_files
        if (baseline is not None and self._containment_files is baseline
                and baseline.initial_baseline()):
            self._confirm_unpublished_withdrawal(transaction, baseline)
            self._withdrawal_kind = "unpublished-baseline"
            return
        files = self._withdrawal_files
        masked = self._closed_observation
        if files is None or masked is None or self._cgroup_root_identity is None:
            raise UnitOperationFailed("bootstrap owned grant withdrawal unavailable")
        owner = masked.owner
        self._closed_observation = None
        root = None
        try:
            self._check_cgroup_mount()
            # No filesystem mutation or bus request before exact retained ownership.
            files.bind(transaction)
            info = validate_cgroup_root(self._cgroup_root_fd, self._cgroup_owner_uid)
            if (info.st_dev, info.st_ino) != self._cgroup_root_identity:
                raise UnitOperationFailed("bootstrap cgroup root identity changed")
            root = os.dup(self._cgroup_root_fd)
            held = validate_cgroup_root(root, self._cgroup_owner_uid)
            if (held.st_dev, held.st_ino) != self._cgroup_root_identity:
                raise UnitOperationFailed("bootstrap cgroup root changed")

            def containment():
                self._observe_withdrawal_fence(files, owner, root)

            containment()
            restored = files.withdraw(containment)

            def restore(session):
                return BootstrapRestoreSequence(
                    bus=session._bus, message_factory=session._message_factory,
                    message_type=session._message_type, timeout_seconds=self._timeout,
                    files=restored, expected_owner=owner, cgroup_root_fd=root,
                    owner_uid=self._cgroup_owner_uid, check_mount=self._check_cgroup_mount,
                ).restore()

            self._run_owned(restore)
            final = self._observe_withdrawal_fence(restored, owner, root)
            self._containment_files = restored
            self._closed_observation = final
            self._withdrawal_kind = "withdrawn"
        except Exception:
            # No success cache survives uncertainty; durable intent is retained.
            self._closed_observation = None
            raise UnitOperationFailed("bootstrap owned withdrawal unconfirmed") from None
        finally:
            if root is not None:
                os.close(root)

    @property
    def withdrawal_kind(self) -> str | None:
        """Descriptive evidence label of the last confirmed withdrawal only.

        Never consulted for a decision: it distinguishes "nothing was
        published" from "owned files were withdrawn" in close evidence.
        """
        return self._withdrawal_kind

    def _confirm_unpublished_withdrawal(self, transaction, baseline) -> None:
        """Nothing to withdraw: the latest fence is the unjournaled mask baseline.

        Only a grant that never reached pair_grant_opened qualifies. The fresh
        loaded-mask observation must match the close_starts() fence and the
        baseline must still show no journal and no overlay entry for the pair.
        This removes no file and grants nothing; a journal or overlay entry
        that appears refuses as before.
        """
        masked = self._closed_observation
        self._closed_observation = None
        if (masked is None or self._cgroup_root_identity is None
                or transaction.phase not in _UNPUBLISHED_PHASES):
            raise UnitOperationFailed("bootstrap owned withdrawal unconfirmed")

        def operation(session):
            arguments = dict(bus=session._bus, message_factory=session._message_factory,
                             message_type=session._message_type, timeout_seconds=self._timeout)

            async def observe():
                if baseline.check() != masked.fragments:
                    raise UnitOperationFailed("bootstrap unpublished baseline changed")
                current = await BootstrapMaskedPairInspector(
                    **arguments, expected_owner=masked.owner,
                    expected_fragments=masked.fragments,
                ).inspect()
                if (not current.same_closure(masked)
                        or baseline.check() != masked.fragments):
                    raise UnitOperationFailed("bootstrap unpublished baseline changed")

            return observe()

        try:
            self._check_cgroup_mount()
            self._run_owned(operation)
            self._check_cgroup_mount()
            if not baseline.initial_baseline() or self._containment_files is not baseline:
                raise UnitOperationFailed("bootstrap unpublished baseline changed")
        except Exception:
            raise UnitOperationFailed("bootstrap owned withdrawal unconfirmed") from None
        self._closed_observation = masked

    def _observe_withdrawal_fence(self, files, owner, root):
        """Phase-aware fresh observation, including mixed absent/present masks.

        Called synchronously between owned file mutations, never from an active
        event loop. Each call owns its bus session and retains the original pin.
        Reload is needed after unlink to stop trusting stale FragmentPath data.
        """
        def operation(session):
            arguments = dict(bus=session._bus, message_factory=session._message_factory,
                             message_type=session._message_type, timeout_seconds=self._timeout)
            reader = BootstrapStopJobs(**arguments, expected_owner=owner)

            async def observe():
                self._check_cgroup_mount()
                if await reader._owner() != owner:
                    raise UnitOperationFailed("withdrawal manager owner changed")
                reader._manager_owner = owner
                profile = await _observe_profile(reader)
                fragments = files.check()
                if await reader._owner() != owner:
                    raise UnitOperationFailed("withdrawal manager owner changed")
                if await reader._call("Reload", "", [], "") != []:
                    raise UnitOperationFailed("withdrawal reload unconfirmed")

                async def check_closed():
                    self._check_cgroup_mount()
                    if await _observe_profile(reader) != profile:
                        raise UnitOperationFailed("withdrawal manager profile changed")
                    current = await BootstrapMaskedPairInspector(
                        **arguments, expected_owner=owner,
                        expected_fragments=fragments,
                    ).inspect()
                    if (current.fragments != fragments or files.check() != fragments
                            or await _observe_profile(reader) != profile
                            or await reader._owner() != owner):
                        raise UnitOperationFailed("withdrawal loaded mask changed")
                    self._check_cgroup_mount()

                await check_closed()
                await BootstrapJobDrain(
                    **arguments, expected_owner=owner, check_closed=check_closed,
                ).drain()
                await BootstrapStoppedPairInspector(
                    **arguments, expected_owner=owner, check_closed=check_closed,
                    cgroup_root_fd=root, owner_uid=self._cgroup_owner_uid,
                ).inspect()
                await check_closed()
                result = await BootstrapMaskedPairInspector(
                    **arguments, expected_owner=owner,
                    expected_fragments=fragments,
                ).inspect()
                if (result.fragments != fragments or files.check() != fragments
                        or await _observe_profile(reader) != profile
                        or await reader._owner() != owner):
                    raise UnitOperationFailed("withdrawal final mask changed")
                self._check_cgroup_mount()
                return result

            return reader._bounded(observe())

        return self._run_owned(operation)

    def _check_cgroup_mount(self):
        if self._cgroup_mount is not None:
            self._cgroup_mount.check()

    def start_and_wait(self, unit: UnitKey, *, transaction, check_start) -> None:
        _name(unit)
        raise UnitOperationFailed(
            "bootstrap deployment fencing unavailable; widening refused"
        )

    def is_ready(self, unit: UnitKey) -> bool:
        _name(unit)
        # ActiveState alone is not authenticated helper readiness. A future
        # reviewed widening backend must provide that independent observation.
        return False


class _PrototypeBootstrapManager(BootstrapNarrowingManager):
    """Private protocol composition for regular-file/fake-transport qualification.

    Not selected by the production factory, CLI, environment, or an approval
    flag. Native system-manager qualification and a separately reviewed factory
    change remain necessary before real service opening. All transaction,
    publication and authenticated-peer state stays in the retained base manager;
    this adapter adds no second backend or grant authority. Individual unmask
    remains refused by the base implementation.
    """

    def open_pair(self, transaction: GrantTransaction, *, approval, check_publish) -> None:
        self._publish_and_inspect_pair(
            transaction, approval=approval, check_publish=check_publish,
        )

    def start_and_wait(self, unit: UnitKey, *, transaction, check_start) -> None:
        _name(unit)
        if unit is UnitKey.AUDITD:
            self._start_bound_audit(transaction, check_start=check_start)
        else:
            self._start_bound_commission(transaction, check_start=check_start)

    def is_ready(self, unit: UnitKey) -> bool:
        _name(unit)
        # Peer identity alone does not prove that the retained publication,
        # controller policy and loaded dependency closure still hold. Reuse the
        # same observation as starts on both sides of the authenticated exchange.
        self._check_retained_publication()
        ready = self._bound_helper_ready(unit)
        self._check_retained_publication()
        return ready
