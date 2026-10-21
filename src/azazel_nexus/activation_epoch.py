"""Operator-signed raise of the declared security epoch (#251).

`docs/activation-observe-baseline.md` §11. The payload
`azazel-nexus/activation-epoch-raise/v1` names the operator, the declared node
digest, the digest of the whole current administrator deployment declaration
and the current and new epoch. It is signed off-host under its own purpose,
`ApprovalPurpose.ACTIVATION_EPOCH_RAISE`, so neither an activation approval nor
any other operator signature can stand in for it, and it cannot stand in for
them.

The payload only raises: `to_epoch` must be above `from_epoch`, and
`from_epoch` must be the epoch declared now, so a signature applies to one
declaration state once. Nothing here reads files, writes a declaration, a
floor or a ledger, or grants anything; `az-activation epoch-raise` does that
after this check.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .bootstrap_deployment import BootstrapDeployment, encode_bootstrap_deployment
from .operator_store import _unique_object
from .operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust

SCHEMA = "azazel-nexus/activation-epoch-raise/v1"
_FIELDS = frozenset(("schema", "operator", "node_digest", "deployment_digest",
                     "from_epoch", "to_epoch"))
_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
#: The high-water counters' bound (`activation_high_water`), below the
#: declaration's own `2**64`, so a raised epoch always fits the floor.
EPOCH_LIMIT = 2**63


@dataclass(frozen=True)
class EpochRaise:
    operator: str
    node_digest: str
    deployment_digest: str
    from_epoch: int
    to_epoch: int

    def __post_init__(self):
        if type(self.operator) is not str or not _OPERATOR.fullmatch(self.operator):
            raise ApprovalRefused("epoch raise operator refused")
        for value in (self.node_digest, self.deployment_digest):
            if type(value) is not str or not _DIGEST.fullmatch(value):
                raise ApprovalRefused("epoch raise digest refused")
        for value in (self.from_epoch, self.to_epoch):
            if type(value) is not int or not 0 <= value < EPOCH_LIMIT:
                raise ApprovalRefused("epoch raise epoch refused")
        if self.to_epoch <= self.from_epoch:
            raise ApprovalRefused("an epoch raise must raise the epoch")


def deployment_digest(deployment: BootstrapDeployment) -> str:
    """SHA-256 of the canonical declaration bytes (the published file itself)."""
    return "sha256:" + hashlib.sha256(encode_bootstrap_deployment(deployment)).hexdigest()


def epoch_raise_request(deployment: BootstrapDeployment, *, operator: str,
                        to_epoch: int) -> EpochRaise:
    """What raising `deployment` to `to_epoch` means, bound to that declaration."""
    if type(deployment) is not BootstrapDeployment:
        raise ApprovalRefused("administrator deployment declaration required")
    return EpochRaise(operator=operator, node_digest=deployment.node_digest,
                      deployment_digest=deployment_digest(deployment),
                      from_epoch=deployment.security_epoch, to_epoch=to_epoch)


def encode_epoch_raise(value: EpochRaise) -> bytes:
    if type(value) is not EpochRaise:
        raise ApprovalRefused("epoch raise required")
    return json.dumps({
        "schema": SCHEMA, "operator": value.operator, "node_digest": value.node_digest,
        "deployment_digest": value.deployment_digest, "from_epoch": value.from_epoch,
        "to_epoch": value.to_epoch,
    }, sort_keys=True, separators=(",", ":")).encode("ascii")


def decode_epoch_raise(raw: bytes) -> EpochRaise:
    """The canonical payload or a refusal; nothing is normalized."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise ApprovalRefused("bounded epoch raise required")
        document = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
        if (type(document) is not dict or set(document) != _FIELDS
                or document.pop("schema") != SCHEMA):
            raise ApprovalRefused("epoch raise fields refused")
        value = EpochRaise(**document)
        if encode_epoch_raise(value) != raw:
            raise ApprovalRefused("noncanonical epoch raise refused")
        return value
    except Exception:
        raise ApprovalRefused("epoch raise payload refused") from None


def verify_epoch_raise(*, trust: OperatorTrust, payload: bytes, signature: bytes,
                       deployment: BootstrapDeployment,
                       authorized_operators: frozenset) -> EpochRaise:
    """Attribution, authorization and the exact current declaration, or a refusal.

    `authorized_operators` is the activation policy's operator set: whoever
    may approve activation may also end every approval of the current epoch.
    """
    value = decode_epoch_raise(payload)
    if type(trust) is not OperatorTrust:
        raise ApprovalRefused("operator trust required")
    trust.verify(operator=value.operator, purpose=ApprovalPurpose.ACTIVATION_EPOCH_RAISE,
                 payload=payload, signature=signature)
    if value.operator not in authorized_operators:
        raise ApprovalRefused("operator is not authorized by the activation policy")
    try:
        expected = epoch_raise_request(deployment, operator=value.operator,
                                       to_epoch=value.to_epoch)
    except ApprovalRefused:
        raise ApprovalRefused("epoch raise does not match the current declaration") from None
    if expected != value:
        raise ApprovalRefused("epoch raise does not match the current declaration")
    return value
