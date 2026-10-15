"""Bound the pinned dbus-next constructor's synchronous Unix connect.

Private mixin for dbus-next 0.2.3's socket setup seam. Only the fixed local
system socket is supported; no TCP, abstract sockets or fallback addresses.
No process-global socket default timeout and no abandoned worker thread.
"""

import socket
from importlib.metadata import PackageNotFoundError, version

from .units import UnitOperationFailed

SYSTEM_BUS_SOCKET = "/run/dbus/system_bus_socket"
SYSTEM_BUS_ADDRESS = "unix:path=" + SYSTEM_BUS_SOCKET
_SOCKET_TIMEOUT_SECONDS = 10.0


def require_supported_dbus_next():
    try:
        if version("dbus-next") != "0.2.3":
            raise UnitOperationFailed("unreviewed system bus client version")
    except PackageNotFoundError:
        raise UnitOperationFailed("pinned system bus client unavailable") from None


class FixedSystemBusSocket:
    def __init__(self, *args, **kwargs):
        try:
            super().__init__(*args, **kwargs)
        except BaseException:
            # The parent can fail after setup but before construction returns,
            # when the caller does not yet have a bus object to disconnect.
            self._close_fixed_socket()
            raise

    def _close_fixed_socket(self):
        """Release both references after owned-loop teardown, not on GC."""
        try:
            stream = getattr(self, "_stream", None)
            if stream is not None:
                stream.close()
        finally:
            sock = getattr(self, "_sock", None)
            if sock is not None:
                sock.close()

    def _setup_socket(self):
        if self._bus_address != [("unix", {"path": SYSTEM_BUS_SOCKET})]:
            raise UnitOperationFailed("only the fixed system bus socket is admitted")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(_SOCKET_TIMEOUT_SECONDS)
            sock.connect(SYSTEM_BUS_SOCKET)
            sock.setblocking(False)
            stream = sock.makefile("rwb")
        except BaseException:
            sock.close()
            raise
        self._sock = sock
        self._stream = stream
        self._fd = sock.fileno()
