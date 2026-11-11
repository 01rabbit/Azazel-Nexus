#!/usr/bin/env python3
"""Read-only pre-check of a Knowledge Context commissioning bundle (#395).

Runs the shipped loader's own verification (`load_commissioning_from`, the same
code path as `load_commissioning`) on a bundle directory and reports the
loader's fixed reason code. Nothing is written, enabled, granted or sent: no
socket is opened and the bundle is only read. It is not an activation step and
a pass is not a grant.

Beyond the loader it checks two things the loader does not look at:
  * client.pem notAfter is later than --now;
  * max_ttl_seconds against 30, the Knowledge-side ceiling. Nexus needs its
    value to be >= Knowledge's, so a value above 30 is only a warning that the
    two sides may disagree; the value is never changed.

Secrets and exact values are not printed: identifiers and the pin appear as a
short sha256 digest or "present".

  --pin CERT   print the Nexus pin (SPKI sha256:<hex>, goes in the registry
               `certificate_pin` of the *server* certificate) next to the
               Knowledge value (sha256 of the whole DER of the *client*
               certificate, goes in Knowledge's allow list). They differ in
               direction and form; use the one that belongs to the certificate.

Exit status: 0 commissioned, 1 refused, 2 usage. AZAZEL_ROOT is not honoured
here (it would replace the trust base), so the tool refuses to run with it set.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus import spki  # noqa: E402
from azazel_nexus_runtime import knowledge_context_config as cfg  # noqa: E402
from azazel_nexus_runtime import runtime_paths  # noqa: E402

KNOWLEDGE_TTL_CEILING = 30  # Knowledge 41cad719 knowledge_context_transport.py:54
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()[:12]


def certificate_der(raw: bytes) -> bytes:
    """First certificate of a PEM file, or the bytes themselves if DER."""
    match = _PEM.search(raw)
    if match:
        return base64.b64decode(b"".join(match.group(1).split()), validate=True)
    return raw


def not_after(der: bytes) -> datetime:
    """Validity.notAfter, via spki's DER walk (private helpers, same module family)."""
    tbs = spki._first_child(spki._value(der, expect=0x30), expect=0x30)
    items = list(spki._children(tbs))
    offset = 1 if items and items[0][0] == 0xA0 else 0
    _tag, validity = items[offset + 3]  # serial, signature, issuer, validity
    times = list(spki._children(validity))
    tag, value = times[1]
    text = value.decode("ascii")
    if tag == 0x17:
        year = int(text[:2])
        text = ("19" if year >= 50 else "20") + text
    elif tag != 0x18:
        raise ValueError("unexpected time type")
    return datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)


def print_pins(path: Path) -> int:
    try:
        der = certificate_der(path.read_bytes())
        nexus = spki.spki_pin(der)
    except (OSError, ValueError, spki.CertificateRefused):
        print("refused: certificate_unreadable")
        return 1
    print(f"nexus_server_pin (registry certificate_pin, SPKI): {nexus}")
    print(f"knowledge_client_pin (DER sha256 hex, Knowledge allow list): "
          f"{hashlib.sha256(der).hexdigest()}")
    print("use the first for the Knowledge server certificate, the second for the "
          "Nexus client certificate")
    return 0


def check_bundle(directory: Path, now: datetime) -> int:
    result = cfg.load_commissioning_from(directory, now=now.isoformat())
    if result.status != "commissioned":
        print(f"refused: {result.reason_code or result.status}")
        return 1
    # The guarded client wraps the real one; read-only access to its fields.
    inner = result.client._inner
    peer = inner.registry.peers[inner.peer_id]
    ttl = inner.knowledge_context_max_ttl_seconds
    print("commissioned")
    print(f"registry_version: {result.registry_version}")
    print(f"peer_id: {_digest(inner.peer_id)}")
    print(f"client_identity: {_digest(peer.endpoint.client_identity)}")
    print(f"server_pin: present ({_digest(peer.endpoint.certificate_pin)})")
    print(f"max_ttl_seconds: {ttl}")
    status = 0
    try:
        expiry = not_after(certificate_der((directory / "client.pem").read_bytes()))
    except (OSError, ValueError, IndexError, spki.CertificateRefused):
        print("refused: client_cert_unparsable")
        return 1
    print(f"client_cert_not_after: {expiry.isoformat()}")
    if expiry <= now:
        print("refused: client_cert_expired")
        status = 1
    if ttl > KNOWLEDGE_TTL_CEILING:
        print(f"warning: ttl_above_knowledge_ceiling (max_ttl_seconds {ttl} > "
              f"{KNOWLEDGE_TTL_CEILING}); may not match the Knowledge-side setting")
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory", nargs="?", help="bundle directory (default: shipped path)")
    parser.add_argument("--now", help="ISO 8601 timestamp with offset (default: now)")
    parser.add_argument("--pin", metavar="CERT", help="print both pin forms for a PEM/DER certificate")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    if args.pin:
        if args.directory or args.now:
            print("usage: --pin takes no directory or --now", file=sys.stderr)
            return 2
        return print_pins(Path(args.pin))
    if os.environ.get("AZAZEL_ROOT"):
        print("usage: AZAZEL_ROOT must not be set for this check", file=sys.stderr)
        return 2
    try:
        now = datetime.fromisoformat(args.now) if args.now else datetime.now(UTC)
    except ValueError:
        print("usage: --now must be ISO 8601", file=sys.stderr)
        return 2
    if now.tzinfo is None:
        print("usage: --now needs a UTC offset", file=sys.stderr)
        return 2
    directory = (Path(os.path.abspath(args.directory)) if args.directory
                 else runtime_paths.knowledge_context_commission_dir())
    return check_bundle(directory, now)


if __name__ == "__main__":
    sys.exit(main())
