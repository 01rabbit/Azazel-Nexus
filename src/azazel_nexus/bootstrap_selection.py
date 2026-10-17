"""Local per-boot selection of an administrator-approved bootstrap target.

This record is intent only. It is not an approval, admission result, or service
start grant, and this module performs no filesystem or network operations.
"""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re

from .bootstrap_deployment import BootstrapDeployment, encode_bootstrap_deployment
from .operator_store import _unique_object
from .operator_trust import ApprovalRefused

_SCHEMA = "azazel-nexus/bootstrap-selection/v1"
_FIELDS = frozenset(("deployment_digest", "boot_id", "approval_id", "generation",
                     "generation_digest"))
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True, repr=False)
class BootstrapSelection:
    """Administrator-selected deployment target for one boot; not admission."""

    deployment_digest: str
    boot_id: str
    approval_id: str
    generation: int
    generation_digest: str

    def __post_init__(self):
        for name in ("deployment_digest", "generation_digest"):
            value = getattr(self, name)
            if type(value) is not str or _DIGEST.fullmatch(value) is None:
                raise ApprovalRefused("bootstrap selection digest refused")
        for name in ("boot_id", "approval_id"):
            value = getattr(self, name)
            if type(value) is not str or _UUID.fullmatch(value) is None:
                raise ApprovalRefused("bootstrap selection identity refused")
        if type(self.generation) is not int or not 1 <= self.generation < 2**63:
            raise ApprovalRefused("bootstrap selection generation refused")


def encode_bootstrap_selection(selection: BootstrapSelection) -> bytes:
    """Encode exact canonical administrator selection bytes."""
    if type(selection) is not BootstrapSelection:
        raise ApprovalRefused("bootstrap selection required")
    try:
        return _canonical({"schema": _SCHEMA, **asdict(selection)})
    except Exception:
        raise ApprovalRefused("bootstrap selection encoding refused") from None


def decode_bootstrap_selection(raw: bytes) -> BootstrapSelection:
    """Decode one bounded canonical selection, rejecting duplicate keys."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise ApprovalRefused("bounded bootstrap selection required")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (type(document) is not dict or set(document) != _FIELDS | {"schema"}
                or document.pop("schema") != _SCHEMA):
            raise ApprovalRefused("bootstrap selection fields/version refused")
        selection = BootstrapSelection(**document)
        if encode_bootstrap_selection(selection) != raw:
            raise ApprovalRefused("noncanonical bootstrap selection refused")
        return selection
    except Exception:
        raise ApprovalRefused("bootstrap selection refused") from None


def bind_bootstrap_selection(selection: BootstrapSelection, *,
                             deployment: BootstrapDeployment, boot_id: str) -> None:
    """Bind selection intent to the current boot and exact deployment bytes."""
    if (type(selection) is not BootstrapSelection
            or type(deployment) is not BootstrapDeployment
            or type(boot_id) is not str or _UUID.fullmatch(boot_id) is None):
        raise ApprovalRefused("bootstrap selection binding inputs required")
    deployment_digest = "sha256:" + sha256(encode_bootstrap_deployment(deployment)).hexdigest()
    if selection.boot_id != boot_id or selection.deployment_digest != deployment_digest:
        raise ApprovalRefused("bootstrap selection binding differs")
