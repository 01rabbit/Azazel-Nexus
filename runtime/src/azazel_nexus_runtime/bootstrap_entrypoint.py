"""Fixed selected-bootstrap composition; no widening-gate bypass.

This is an operational attempt, not a preview: protected transaction/deadline
records and narrowing may change. Public manager opening/start still refuse
until their remaining admission obligations are implemented and reviewed.
"""

from contextlib import contextmanager

from azazel_nexus.bootstrap_lock import bootstrap_transaction
from azazel_nexus.bootstrap_controller_once import bootstrap_controller_once
from azazel_nexus.bootstrap_selection_store import load_bootstrap_selection
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap import BootstrapSupervisor, BootstrapResult
from .bootstrap_inputs import protected_bootstrap_inputs, protected_bootstrap_generation_admission
from .bootstrap_lifetime import BootstrapProcessLifetime
from .bootstrap_manager import bootstrap_narrowing_manager_in_transaction
from .systemd_notify import notify_ready, notify_watchdog

# Per-operation transport budget, not a claim about native service stop bounds.
_JOB_TIMEOUT_SECONDS = 10.0
_POLL_SECONDS = 10.0
EMERGENCY_UNCONFIRMED = "bootstrap emergency narrowing unconfirmed"


def _attempt_emergency_narrow(guard, narrow, primary):
    try:
        guard()
        narrow()
    except Exception:
        primary.add_note(EMERGENCY_UNCONFIRMED)


def narrow_invalid_selection(primary, *, narrow):
    """Preserve mandatory narrowing on invalid intent, without ordinary fallback."""
    with bootstrap_transaction() as guard:
        _attempt_emergency_narrow(guard, narrow, primary)


@contextmanager
def _retained_transaction(guard):
    """Borrow the already-held lock; never acquire or release a second one."""
    guard()
    try:
        yield guard
    except BaseException:
        try:
            guard()
        except Exception:
            pass  # retain the original supervisor/containment failure
        raise
    else:
        guard()


def run_selected_bootstrap(selection, *, narrow):
    """Use administrator selection only as intent, never as approval/admission.

    ``narrow`` is the fixed activation entrypoint's broad narrowing callback,
    not an RPC, environment or command-line selected function.
    """
    if not callable(narrow):
        raise ValueError("fixed initial/emergency narrowing callback required")
    # A lock-acquisition failure must not narrow another cooperating session.
    with bootstrap_transaction() as guard:
        try:
            with bootstrap_controller_once(guard) as retained_guard:
                return _run_selected_locked(selection, narrow=narrow, guard=retained_guard)
        except BaseException as primary:
            # Construction may fail before the supervisor owns containment.
            # This attempt is still inside the lock and never converts failure
            # into successful startup or ordinary-mode fallback.
            _attempt_emergency_narrow(guard, narrow, primary)
            raise


def _run_selected_locked(selection, *, narrow, guard):
    guard()
    if load_bootstrap_selection() != selection:
        raise ApprovalRefused("bootstrap selection changed before composition")
    narrow()
    guard()
    if load_bootstrap_selection() != selection:
        raise ApprovalRefused("bootstrap selection changed during initial narrowing")
    with bootstrap_narrowing_manager_in_transaction(
        guard, job_timeout_seconds=_JOB_TIMEOUT_SECONDS,
    ) as manager:
        with BootstrapProcessLifetime() as lifetime:
            client = manager._bootstrap_audit_client()
            supervisor = BootstrapSupervisor(
                manager=manager,
                refresh=protected_bootstrap_inputs(),
                admit_generation=protected_bootstrap_generation_admission(),
                deadline_guard=lifetime.deadline_guard,
                record=client, audit_head_reader=client,
                controller_ready=notify_ready, controller_watchdog=notify_watchdog,
                transaction=lambda: _retained_transaction(guard),
                emergency_narrow=narrow, stopped=lifetime.stopped,
                wait=lifetime.wait, poll_seconds=_POLL_SECONDS,
            )
            result = supervisor.run()
            if type(result) is not BootstrapResult or result.state != "stopped":
                raise ApprovalRefused("bootstrap completion unconfirmed")
            return result
