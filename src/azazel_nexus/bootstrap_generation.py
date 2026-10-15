"""Pure integrity/shape verification for a proposed bootstrap-only tree.

This format is Nexus-local preparation, not an adopted deployment protocol.
It is deliberately not a Generation or publisher, and supplies no admission,
commissioning, installed closure measurement, health or start authority.
"""

from dataclasses import dataclass
import json
from typing import Mapping

from .bootstrap_approval import BOOTSTRAP_UNITS, BootstrapContext, _utc
from .generation import GenerationRefused, tree_digest
from .operator_trust import ApprovalRefused

_VARIANT = "bootstrap/uncommissioned"
_SCHEMA = "azazel-nexus/bootstrap-generation/v1"
_CONFIG = "bootstrap.json"
_LIMIT = 65536


def _canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class VerifiedBootstrapGeneration:
    """Shape and byte integrity only; distinct from operational Generation."""

    number: int
    digest: str
    created_at: str


def verify_bootstrap_generation(*, metadata: bytes, files: Mapping[str, bytes],
                                 expected: BootstrapContext) -> VerifiedBootstrapGeneration:
    """Compare one bounded declarative file with independently admitted inputs.

    There are no executable/network/provider files in this variant. The named
    installed package/unit closure must still be independently measured and
    admitted; a matching declared digest cannot establish those observations.
    No normal commissioning digest or operational renderer claim is invented.
    """
    if type(expected) is not BootstrapContext:
        raise GenerationRefused("independent bootstrap context required")
    if type(metadata) is not bytes or not 0 < len(metadata) <= _LIMIT:
        raise GenerationRefused("bootstrap metadata must be bounded bytes")
    snapshot = dict(files)
    if set(snapshot) != {_CONFIG} or type(snapshot[_CONFIG]) is not bytes or not 0 < len(snapshot[_CONFIG]) <= _LIMIT:
        raise GenerationRefused("bootstrap tree must contain only its bounded declarative config")
    canonical_config = _canonical({
        "schema": "azazel-nexus/bootstrap-config/v1", "variant": _VARIANT,
        "units": BOOTSTRAP_UNITS, "policy_digest": expected.policy_digest,
        "package_digest": expected.package_digest,
        "unit_closure_digest": expected.unit_closure_digest,
    })
    if snapshot[_CONFIG] != canonical_config:
        raise GenerationRefused("bootstrap content scope or independent measurements differ")
    actual = tree_digest(snapshot)
    if actual != expected.generation_digest:
        raise GenerationRefused("bootstrap tree digest differs from expected input")
    try:
        document = json.loads(metadata)
        if type(document) is not dict or set(document) != {
            "schema", "variant", "number", "digest", "created_at"
        }:
            raise GenerationRefused("bootstrap metadata fields refused")
        _utc(document["created_at"])
        canonical_metadata = _canonical({
            "schema": _SCHEMA, "variant": _VARIANT, "number": expected.generation,
            "digest": actual, "created_at": document["created_at"],
        })
        if metadata != canonical_metadata:
            raise GenerationRefused("bootstrap metadata is not its exact expected representation")
    except (ValueError, UnicodeError, RecursionError, ApprovalRefused):
        raise GenerationRefused("bootstrap metadata malformed") from None
    return VerifiedBootstrapGeneration(expected.generation, actual, document["created_at"])
