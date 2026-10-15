"""One kernel-owned absolute self-deadline, not a helper or a start grant."""

import os
from importlib.machinery import ExtensionFileLoader

from azazel_nexus.bootstrap_deadline import BootstrapDeadline
from azazel_nexus.operator_trust import ApprovalRefused


def _load_backend():
    from . import _bootstrap_deadline

    if type(_bootstrap_deadline.__loader__) is not ExtensionFileLoader:
        raise ImportError("compiled Linux deadline backend required")
    return _bootstrap_deadline


class BootstrapKernelDeadline:
    """Retain the native timer until the supervisor confirms containment.

    There is intentionally no destructor, atexit or context-exit disarm. A
    failed attempt is not retryable. No caller chooses a PID, clock or signal.
    Kernel timers do not survive exec; selected supervision must not exec.
    This does not wake a suspended machine or prove helper-stop latency.
    """

    def __init__(self):
        self._owner = os.getpid()
        self._identity = None
        self._backend = None
        self._handle = None
        self._attempted = False
        self._failed = False
        self._released = False

    def __call__(self, deadline):
        try:
            if (os.getpid() != self._owner or self._released or self._failed
                    or type(deadline) is not BootstrapDeadline
                    or type(deadline.deadline_boottime_ns) is not int
                    or not 0 < deadline.deadline_boottime_ns <= (1 << 63) - 1):
                raise ValueError("fresh owned kernel deadline required")
            identity = (
                deadline.approval.context, deadline.approval.payload_digest,
                deadline.admitted_at, deadline.admitted_boottime_ns,
                deadline.deadline_boottime_ns,
            )
            if self._identity is not None and self._identity != identity:
                raise ValueError("kernel deadline cannot be renewed")
            if self._identity is None:
                self._identity = identity
                self._attempted = True
                self._backend = _load_backend()
                self._handle = self._backend.arm(deadline.deadline_boottime_ns)
                if self._handle is None:
                    raise ValueError("kernel deadline handle unavailable")
            if self._backend.check(self._handle) is not None:
                raise ValueError("kernel deadline unconfirmed")
        except BaseException as error:
            self._failed = True
            if not isinstance(error, Exception):
                raise
            raise ApprovalRefused("bootstrap kernel deadline refused") from None

    def release_after_stop(self):
        """Trusted supervisor calls this only after confirmed full cleanup."""
        try:
            if os.getpid() != self._owner:
                raise ValueError("kernel deadline owner changed")
            if self._released:
                return
            if self._attempted:
                if self._handle is None or self._backend.release(self._handle) is not None:
                    raise ValueError("kernel deadline release unconfirmed")
            self._released = True
        except Exception:
            raise ApprovalRefused("bootstrap kernel deadline release refused") from None
