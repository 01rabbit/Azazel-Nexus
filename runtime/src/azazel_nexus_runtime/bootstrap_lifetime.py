"""Fixed process-lifetime signal adapter for bootstrap supervision."""

from __future__ import annotations

import math
import signal
import threading
from contextlib import AbstractContextManager
from types import FrameType
from typing import Self

from .bootstrap_kernel_deadline import BootstrapKernelDeadline

_MAX_WAIT_SECONDS = 60.0
_SIGNALS = (signal.SIGTERM, signal.SIGINT)


class BootstrapProcessLifetime(AbstractContextManager["BootstrapProcessLifetime"]):
    """Install fixed termination handlers and expose supervisor callbacks.

    Signal dispositions are process-global, so installation and restoration
    are restricted to Python's main thread. The handlers only set an Event;
    ``wait`` therefore wakes without polling when termination is requested.
    """

    def __init__(self) -> None:
        self.deadline_guard = BootstrapKernelDeadline()
        self._stopping = threading.Event()
        self._previous: dict[signal.Signals, signal.Handlers] | None = None
        self._used = False

    def __enter__(self) -> Self:
        self._require_main_thread()
        if self._used:
            raise RuntimeError("bootstrap lifetime object is single-use")

        previous = {signum: signal.getsignal(signum) for signum in _SIGNALS}
        installed: list[signal.Signals] = []
        try:
            for signum in _SIGNALS:
                signal.signal(signum, self._handle_signal)
                installed.append(signum)
        except BaseException:
            for signum in reversed(installed):
                signal.signal(signum, previous[signum])
            raise

        self._previous = previous
        self._used = True
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self._require_main_thread()
        if self._previous is None:
            raise RuntimeError("bootstrap lifetime is not installed")

        previous = self._previous
        self._previous = None
        for signum in reversed(_SIGNALS):
            signal.signal(signum, previous[signum])
        return False

    def stopped(self) -> bool:
        """Return the Event state as an exact ``bool``."""
        self._require_installed()
        result = self._stopping.is_set()
        if type(result) is not bool:  # defensive contract for supervisor API
            raise RuntimeError("lifetime event returned a non-bool state")
        return result

    def wait(self, timeout: float) -> None:
        """Wait up to a finite bounded duration, returning promptly on signal."""
        self._require_installed()
        if type(timeout) not in (int, float) or timeout < 0:
            raise ValueError("wait timeout must be a finite non-negative number")
        if type(timeout) is int:
            bounded = min(timeout, int(_MAX_WAIT_SECONDS))
        else:
            if not math.isfinite(timeout):
                raise ValueError("wait timeout must be a finite non-negative number")
            bounded = min(timeout, _MAX_WAIT_SECONDS)
        self._stopping.wait(float(bounded))

    def _handle_signal(self, signum: int, frame: FrameType | None) -> None:
        del signum, frame
        self._stopping.set()

    @staticmethod
    def _require_main_thread() -> None:
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("signal handlers may only be managed on the main thread")

    def _require_installed(self) -> None:
        if self._previous is None:
            raise RuntimeError("bootstrap lifetime is not installed")
