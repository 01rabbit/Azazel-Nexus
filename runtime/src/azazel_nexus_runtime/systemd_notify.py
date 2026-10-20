"""Fixed main-process startup notification, not admission or a unit-control API.

Only the packaged system-manager socket is supported. Other manager namespaces
refuse; no path/message/PID can be supplied through this public boundary.
Successful send is not an acknowledgement or proof of installed readiness.
"""

import os
from pathlib import Path
import re
import socket

from .runtime_paths import ROOT
from .units import UnitOperationFailed

_ADDRESS = "/run/systemd/notify"
_PAYLOAD = b"READY=1"
_WATCHDOG_PAYLOAD = b"WATCHDOG=1"
_TIMEOUT = 1.0


def _send(payload, address):
    """Private ordinary-socket sender; public callers use fixed constants."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
            connection.settimeout(_TIMEOUT)
            if connection.sendto(payload, address) != len(payload):
                raise UnitOperationFailed("systemd notification incomplete")
    except Exception:
        raise UnitOperationFailed("systemd notification refused") from None


def _send_ready(address):
    """Private ordinary-socket test seam; production always supplies _ADDRESS."""
    _send(_PAYLOAD, address)


def _require_fixed_context() -> None:
    if (
        ROOT != Path("/")
        or not Path("/run/systemd/system").is_dir()
        or re.fullmatch(r"[0-9a-fA-F]{32}", os.environ.get("INVOCATION_ID", "")) is None
        or os.environ.get("NOTIFY_SOCKET") != _ADDRESS
    ):
        raise UnitOperationFailed("fixed systemd notification context required")


def notify_ready() -> None:
    """Notify from the service's main process after its own preparation.

    Environment checks prevent accidental use by the relocated user harness;
    they are not authentication. systemd owns sender attribution under
    NotifyAccess=main. This sends no status text, identifiers or credentials.
    """
    _require_fixed_context()
    _send_ready(_ADDRESS)


_BARRIER_PAYLOAD = b"BARRIER=1"
_BARRIER_TIMEOUT = 5.0


def _barrier(address, timeout):
    """Private ordinary-socket seam: sd_notify_barrier(3) on `address`.

    Sends `BARRIER=1` with the write end of a fresh pipe (SCM_RIGHTS), closes
    our copy, and waits for EOF on the read end: systemd closes its copy only
    after it has processed every earlier notification from this process.
    """
    import array
    import select

    read_fd, write_fd = os.pipe()
    try:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as connection:
                connection.settimeout(_TIMEOUT)
                fds = array.array("i", [write_fd])
                sent = connection.sendmsg([_BARRIER_PAYLOAD],
                                          [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)],
                                          0, address)
                if sent != len(_BARRIER_PAYLOAD):
                    raise UnitOperationFailed("systemd notification incomplete")
        finally:
            os.close(write_fd)
        poller = select.poll()
        poller.register(read_fd, select.POLLIN | select.POLLHUP)
        if not poller.poll(int(timeout * 1000)):
            raise UnitOperationFailed("systemd notification barrier timed out")
        if os.read(read_fd, 1) != b"":
            raise UnitOperationFailed("systemd notification barrier refused")
    except UnitOperationFailed:
        raise
    except Exception:
        raise UnitOperationFailed("systemd notification barrier refused") from None
    finally:
        os.close(read_fd)


def notify_barrier() -> None:
    """Wait (bounded) until systemd has processed this process's notifications.

    For a main process that exits right after READY: without the barrier the
    exit can be seen before READY, and the start is then a failure.
    """
    _require_fixed_context()
    _barrier(_ADDRESS, _BARRIER_TIMEOUT)


def notify_watchdog() -> None:
    """Send the fixed watchdog ping from the same guarded main-process context."""
    _require_fixed_context()
    _send(_WATCHDOG_PAYLOAD, _ADDRESS)


def runtime_ready_callback():
    """Host deployment must notify; relocated synthetic harness does not.

    AZAZEL_ROOT is the existing import-time harness boundary, not permission
    to report real systemd startup. Relocated harnesses emit no notification.
    """
    return notify_ready if ROOT == Path("/") else None
