"""Portable administrator declarations; neither observations nor start grants.

No VM/architecture/network values, boot state or secrets belong in this record.
The policy digests reference independently admitted policies, not this record's
own hash. Protected publication, freshness and semantic admission are separate.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
import re

from .bootstrap_approval import BootstrapContext
from .operator_store import _unique_object
from .operator_trust import ApprovalRefused

_SCHEMA = "azazel-nexus/bootstrap-deployment/v1"
_FIELDS = frozenset(("node_digest", "security_epoch", "revocation_digest",
                     "policy_digest", "approval_policy_digest", "operator"))


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def declared_node_digest(node_id: str) -> str:
    """Hash an explicitly declared label; no hostname/hardware fallback.

    This digest is an identity binding, not anonymity or proof of enrollment.
    """
    if (type(node_id) is not str or not 0 < len(node_id) <= 128
            or not node_id.isascii()
            or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in node_id)):
        raise ApprovalRefused("declared node identity refused")
    raw = _canonical({"schema": "azazel-nexus/declared-node/v1", "node_id": node_id})
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, repr=False)
class BootstrapDeployment:
    node_digest: str
    security_epoch: int
    revocation_digest: str
    policy_digest: str
    approval_policy_digest: str
    operator: str

    def __post_init__(self):
        for name in _FIELDS - {"security_epoch", "operator"}:
            value = getattr(self, name)
            if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                raise ApprovalRefused("deployment digest refused")
        if type(self.security_epoch) is not int or not 0 <= self.security_epoch < 2**64:
            raise ApprovalRefused("deployment security epoch refused")
        if (type(self.operator) is not str
                or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", self.operator) is None):
            raise ApprovalRefused("deployment operator refused")


def encode_bootstrap_deployment(value: BootstrapDeployment) -> bytes:
    if type(value) is not BootstrapDeployment:
        raise ApprovalRefused("administrator deployment declaration required")
    return _canonical({"schema": _SCHEMA, **asdict(value)})


def decode_bootstrap_deployment(raw: bytes) -> BootstrapDeployment:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise ApprovalRefused("bounded deployment record required")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (type(document) is not dict or set(document) != _FIELDS | {"schema"}
                or document.pop("schema") != _SCHEMA):
            raise ApprovalRefused("deployment record fields/version refused")
        result = BootstrapDeployment(**document)
        if encode_bootstrap_deployment(result) != raw:
            raise ApprovalRefused("noncanonical deployment record refused")
        return result
    except Exception:
        raise ApprovalRefused("bootstrap deployment declaration refused") from None


def bind_bootstrap_deployment(deployment: BootstrapDeployment, *, context: BootstrapContext,
                              node_id: str, operator: str) -> None:
    """Compare protected declarations with independent current context.

    This does not validate current time, boot, installed closure, audit, policy
    semantics or rollback protection. It must not be used as sole admission.
    """
    if type(deployment) is not BootstrapDeployment or type(context) is not BootstrapContext:
        raise ApprovalRefused("independent deployment and context required")
    if (type(operator) is not str or operator != deployment.operator
            or declared_node_digest(node_id) != deployment.node_digest
            or any(getattr(context, name) != getattr(deployment, name)
                   for name in _FIELDS - {"operator"})):
        raise ApprovalRefused("bootstrap deployment binding differs")
