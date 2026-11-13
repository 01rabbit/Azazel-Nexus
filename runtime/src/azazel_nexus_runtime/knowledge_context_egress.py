"""The one destination the Knowledge Context broker may reach (U49).

`IPAddressDeny=any` stays in the broker's unit. This module derives the single
`IPAddressAllow=` the unit may carry, from the same verified registry peer the
client connects to (`knowledge_egress.egress_address`: `addresses[0]`, no DNS):

* `derive_allowance()` loads the commissioning bundle (signature, freshness,
  peer, identity and privacy class are checked by `knowledge_context_config`)
  and returns an `EgressAllowance`, or None when there is nothing to allow
  (no bundle, refused, disabled, expired, or an address the unit would refuse).
* the allowance digest covers peer id, host, port, certificate pin, address,
  registry version and the registry's commissioning digest. It is written into
  the unit as a header comment, so it is part of the generation-hashed bytes:
  a different host, pin or version at the same IP changes the unit, the
  generation and so requires a new approval.

Read-only; no network I/O. The pass compares what is installed against this
derivation; the CLI is the only writer (`knowledge_context_egress_cli`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .hardening import contextd_egress_line
from .knowledge_egress import egress_address

__all__ = ["EGRESS_SCHEMA", "EgressAllowance", "allowance_from_result", "derive_allowance",
           "expected_loaded_allow"]

EGRESS_SCHEMA = "azazel.knowledge-context.egress-allow/1"


@dataclass(frozen=True)
class EgressAllowance:
    peer_id: str
    host: str
    port: int
    certificate_pin: str
    address: str
    registry_version: int
    commissioning_digest: str
    digest: str

    @property
    def line(self) -> str:
        return contextd_egress_line(self.address)


def _digest(fields: dict) -> str:
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def allowance_from_result(result) -> EgressAllowance | None:
    """The allowance for a `CommissioningResult`, or None (zero Allow lines)."""
    if getattr(result, "status", None) != "commissioned":
        return None
    peer = result.peer
    version = result.registry_version
    digest_in = result.commissioning_digest
    try:
        endpoint = peer.endpoint
        address = egress_address(peer)
        contextd_egress_line(address)
        if (type(version) is not int or type(digest_in) is not str
                or type(endpoint.port) is not int):
            return None
        fields = {
            "schema": EGRESS_SCHEMA, "peer_id": endpoint.provider_id,
            "host": endpoint.host, "port": endpoint.port,
            "certificate_pin": endpoint.certificate_pin, "address": address,
            "registry_version": version, "commissioning_digest": digest_in,
        }
        return EgressAllowance(
            peer_id=fields["peer_id"], host=fields["host"], port=fields["port"],
            certificate_pin=fields["certificate_pin"], address=address,
            registry_version=version, commissioning_digest=digest_in,
            digest=_digest(fields))
    except (AttributeError, ValueError, TypeError, IndexError):
        return None


def derive_allowance(*, now: str | None = None) -> EgressAllowance | None:
    """Verify the installed bundle and derive the allowance; None means no Allow."""
    from .knowledge_context_config import load_egress_peer

    return allowance_from_result(load_egress_peer(now=now))


def expected_loaded_allow(allowance: EgressAllowance | None) -> list[tuple[int, bytes, int]]:
    """The manager's `IPAddressAllow` for the allowance, canonical and sorted."""
    if allowance is None:
        return []
    import ipaddress

    ip = ipaddress.ip_address(allowance.address)
    return [(2 if ip.version == 4 else 10, ip.packed, ip.max_prefixlen)]
