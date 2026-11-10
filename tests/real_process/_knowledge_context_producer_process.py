"""Test-only wrapper around Knowledge's real mTLS producer process.

Knowledge's own test server draws a new signing key and a new ephemeral port on
every start. A restart-across-replay acceptance test needs both held fixed (and
needs to be able to change only the key), so this wrapper substitutes the
signer seed and the bind port from the command line and then runs Knowledge's
unmodified `main`. Everything else (the app, the mTLS listener, the signing
and envelope code, the clock) is Knowledge's own.

Usage: _knowledge_context_producer_process.py <root> <pki> <seed_hex> <port>
"""
from __future__ import annotations

import dataclasses
import hashlib
import sys
from pathlib import Path

root, pki, seed_hex, port = sys.argv[1:]
import _knowledge_context_mtls_server as server  # noqa: E402  (PYTHONPATH set by the test)
from nacl.signing import SigningKey  # noqa: E402


class _FixedSigner:
    def __init__(self) -> None:
        self.key = SigningKey(bytes.fromhex(seed_hex))
        self.public_key = bytes(self.key.verify_key)
        self.key_id = "sha256:" + hashlib.sha256(self.public_key).hexdigest()

    def sign(self, message: bytes) -> bytes:
        return self.key.sign(message).signature


_original_config = server.MtlsListenerConfig


def _config(**kwargs):
    return _original_config(**{**kwargs, "bind_port": int(port)})


import socket  # noqa: E402
import azazel_knowledge.api.knowledge_context_mtls as _mtls  # noqa: E402

_original_bind = _mtls._Server.server_bind


def _bind_reusable(self):
    # Only so a restarted producer can rebind its previous port immediately
    # (TIME_WAIT); Knowledge's listener otherwise leaves SO_REUSEADDR off.
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _original_bind(self)


_mtls._Server.server_bind = _bind_reusable
server._Signer = _FixedSigner
server.MtlsListenerConfig = _config
sys.exit(server.main(Path(root), Path(pki)))
