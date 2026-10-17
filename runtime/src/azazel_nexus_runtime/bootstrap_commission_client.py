"""Fixed read-only commissioning readiness exchange, never role admission."""

import json
import math
import socket
import time

from .bootstrap_audit_client import (
    _pairs, _read_exact, _remaining, _set_remaining_timeout,
)
from .bootstrap_commission_inventory import validate_inventory_response
from .bootstrap_commission_peer import CommissionPeerBinding
from .transport import MAX_FRAME_BYTES, _HEADER
from .units import UnitOperationFailed


class BootstrapCommissionClient:
    """Authenticate the retained server before sending and accepting inventory.

    The digest is an opaque snapshot reference, not recomputed host evidence.
    Blocking identity checks are deadline-checked, not forcibly preempted.
    """

    def __init__(self, *, binding_source, timeout_seconds=5.0):
        if (not callable(binding_source) or type(timeout_seconds) not in (int, float)
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 30):
            raise ValueError("retained commission binding and bounded timeout required")
        self._binding_source = binding_source
        self._timeout = timeout_seconds

    @staticmethod
    def _connect(deadline, *, path):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            _set_remaining_timeout(connection, deadline)
            connection.connect(path)
            _remaining(deadline)
        except BaseException:
            connection.close()
            raise
        return connection

    def observe_inventory(self):
        try:
            deadline = time.monotonic() + self._timeout
            binding = self._binding_source()
            if type(binding) is not CommissionPeerBinding:
                raise UnitOperationFailed("retained commission binding unavailable")
            request = b'{"verb":"commission.inventory","arguments":{}}'
            with binding.proof(deadline) as proof:
                with self._connect(deadline, path=proof.path) as connection:
                    proof.check(connection)
                    _set_remaining_timeout(connection, deadline)
                    connection.sendall(_HEADER.pack(len(request)) + request)
                    _set_remaining_timeout(connection, deadline)
                    connection.shutdown(socket.SHUT_WR)
                    (size,) = _HEADER.unpack(_read_exact(connection, _HEADER.size, deadline))
                    if not 0 < size <= MAX_FRAME_BYTES:
                        raise ValueError("commission inventory frame refused")
                    raw = _read_exact(connection, size, deadline)
                    _set_remaining_timeout(connection, deadline)
                    if connection.recv(1):
                        raise ValueError("commission inventory trailing data")
                    _remaining(deadline)
                    response = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
                    proof.check(connection)
                    digest = validate_inventory_response(response)
                    _remaining(deadline)
            _remaining(deadline)
            return digest
        except Exception as error:
            raise UnitOperationFailed("authenticated commission inventory unavailable") from error
