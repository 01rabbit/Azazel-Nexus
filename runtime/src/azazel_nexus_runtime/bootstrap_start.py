"""Guarded job completion observation, not an installed widening backend.

Start completion/ActiveState are not independently authenticated readiness.
The caller must retain the supervisor transaction and contain on every failure,
including timeouts/cancellation: a submitted job may still take effect.
"""

from .bootstrap_stop import BootstrapStopJobs, _validate_expected_owner
from .units import UnitKey, UnitOperationFailed


class BootstrapStartJobs:
    """Private composition only; no unit strings, path, bus or guard from RPC.

    check_start must synchronously revalidate independent admission, retained
    deadline, exact installed notify-unit/dependency closure, controller lifetime
    and the deployment's persistent-mask/reboot fence. Missing evidence raises.
    It must be bounded and return None on success, not a truthy permission flag.
    This class supplies none of those facts. The factory-selected manager
    builds it for supervised test-VM qualification; every start still
    requires fresh checks.
    Dedicated connection ownership/teardown is the enclosing manager's duty.
    expected_owner must be retained from the enclosing grant admission, not
    learned afresh from this connection. A newly authenticated manager does not
    inherit the previous manager's grant observations.
    """

    def __init__(self, *, bus, message_factory, message_type,
                 timeout_seconds: float, check_start, expected_owner,
                 load_first=False):
        if _validate_expected_owner(expected_owner) is None:
            raise ValueError("enclosing systemd unique owner required")
        if not callable(check_start):
            raise ValueError("independent start guard required")
        self._check = check_start
        self._observer = BootstrapStopJobs(
            bus=bus, message_factory=message_factory, message_type=message_type,
            timeout_seconds=timeout_seconds,
            expected_owner=expected_owner, load_first=load_first,
        )

    async def start_and_wait(self, unit: UnitKey) -> None:
        try:
            await self._observer._job(unit, _start_check=self._check)
        except Exception:
            raise UnitOperationFailed("bootstrap start completion unconfirmed") from None

    async def _start_with_checkpoint(self, unit: UnitKey, checkpoint) -> None:
        """Private owned-loop bridge; never run a synchronous guard here."""
        try:
            await self._observer._job(unit, _start_checkpoint=checkpoint)
        except Exception:
            raise UnitOperationFailed("bootstrap start completion unconfirmed") from None
