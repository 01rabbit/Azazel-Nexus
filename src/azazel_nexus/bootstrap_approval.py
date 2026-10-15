"""Pure verification of the proposed two-helper bootstrap approval.

Not an activation lease, service admission, protected-state reader or signer.
Expected context and policy must be independently supplied from protected
deployment state. No production bootstrap path consumes this evidence yet.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import re

from .operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust

BOOTSTRAP_UNITS = ("azazel-auditd.service", "azazel-commissiond.service")
_SCHEMA = "azazel-nexus/supporting-bootstrap-approval/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")


def _canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc(value: str) -> datetime:
    if type(value) is not str or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise ApprovalRefused("bootstrap time must be whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ApprovalRefused("invalid bootstrap time") from exc


def parse_bootstrap_time(value: str) -> datetime:
    """Validate canonical whole-second UTC from an independent time producer.

    This public runtime boundary retains all syntax/date checks. Parsing alone
    neither establishes clock trust nor authorizes an approval or deadline.
    """
    return _utc(value)


@dataclass(frozen=True)
class BootstrapApprovalPolicy:
    """Independent approval policy, not bootstrap health/admission policy.

    Enrollment alone does not confer this purpose. No default operator or
    duration is supplied. Provisioning and protected loading remain separate.
    """

    operators: frozenset[str]
    max_seconds: int

    def __post_init__(self):
        if type(self.operators) is not frozenset or not self.operators or any(
            type(item) is not str or not _OPERATOR.fullmatch(item) for item in self.operators
        ):
            raise ApprovalRefused("explicit bootstrap operator policy required")
        if type(self.max_seconds) is not int or self.max_seconds <= 0:
            raise ApprovalRefused("explicit positive bootstrap duration policy required")

    def digest(self) -> str:
        raw = _canonical({
            "schema": "azazel-nexus/bootstrap-approval-policy/v1",
            "operators": sorted(self.operators), "max_seconds": self.max_seconds,
            "units": BOOTSTRAP_UNITS,
        })
        return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class BootstrapContext:
    """Independent context bindings; no commissioning digest is fabricated.

    ``unit_closure_digest`` is the pin for the canonical selected-installed-
    files manifest consumed by the bootstrap admission adapter. It is not a
    digest of the measured bytes or proof of complete runtime/unit closure.
    """

    approval_id: str
    node_digest: str
    boot_id: str
    generation: int
    generation_digest: str
    package_digest: str
    unit_closure_digest: str
    policy_digest: str
    approval_policy_digest: str
    security_epoch: int
    revocation_digest: str

    def __post_init__(self):
        for name, value in asdict(self).items():
            if name.endswith("_digest") and (type(value) is not str or not _DIGEST.fullmatch(value)):
                raise ApprovalRefused("invalid bootstrap context digest")
        for value in (self.approval_id, self.boot_id):
            if type(value) is not str or not _UUID.fullmatch(value):
                raise ApprovalRefused("invalid bootstrap approval or boot identity")
        if type(self.generation) is not int or self.generation < 1:
            raise ApprovalRefused("invalid bootstrap generation")
        if type(self.security_epoch) is not int or self.security_epoch < 0:
            raise ApprovalRefused("invalid bootstrap security epoch")


@dataclass(frozen=True)
class VerifiedBootstrapApproval:
    """Attribution/context evidence only, never a normal ActivationLease.

    Replay protection, retained deadlines, freshness, semantic generation
    admission and process lifetime are not established by this pure result.
    """

    context: BootstrapContext
    operator: str
    granted_at: str
    expires_at: str
    payload_digest: str


def bootstrap_payload(*, context: BootstrapContext, operator: str,
                      granted_at: str, expires_at: str) -> bytes:
    """Canonical unsigned bytes; this function does not create any key."""
    if type(context) is not BootstrapContext:
        raise ApprovalRefused("independent bootstrap context required")
    if type(operator) is not str or not _OPERATOR.fullmatch(operator):
        raise ApprovalRefused("invalid bootstrap operator")
    if _utc(expires_at) <= _utc(granted_at):
        raise ApprovalRefused("bootstrap expiry must follow grant")
    return _canonical({
        "schema": _SCHEMA, "purpose": ApprovalPurpose.SUPPORTING_BOOTSTRAP.value,
        "context": asdict(context), "operator": operator, "units": BOOTSTRAP_UNITS,
        "granted_at": granted_at, "expires_at": expires_at,
    })


def verify_bootstrap_approval(*, trust: OperatorTrust, expected: BootstrapContext,
                             policy: BootstrapApprovalPolicy, operator: str,
                             payload: bytes, signature: bytes, now: str) -> VerifiedBootstrapApproval:
    """Verify the new purpose without granting or converting normal authority."""
    if type(expected) is not BootstrapContext or type(policy) is not BootstrapApprovalPolicy:
        raise ApprovalRefused("independent bootstrap context and policy required")
    if type(operator) is not str or operator not in policy.operators:
        raise ApprovalRefused("operator not authorized for bootstrap purpose")
    if expected.approval_policy_digest != policy.digest():
        raise ApprovalRefused("bootstrap approval policy binding mismatch")
    trust.verify(operator=operator, purpose=ApprovalPurpose.SUPPORTING_BOOTSTRAP,
                 payload=payload, signature=signature)
    try:
        document = json.loads(payload)
        if type(document) is not dict or set(document) != {
            "schema", "purpose", "context", "operator", "units", "granted_at", "expires_at"
        }:
            raise ApprovalRefused("invalid bootstrap approval fields")
        canonical = bootstrap_payload(
            context=expected, operator=operator, granted_at=document["granted_at"],
            expires_at=document["expires_at"],
        )
        if payload != canonical:
            raise ApprovalRefused("bootstrap approval does not match exact expected inputs")
        start, end, instant = _utc(document["granted_at"]), _utc(document["expires_at"]), _utc(now)
        if not start <= instant < end or (end - start).total_seconds() > policy.max_seconds:
            raise ApprovalRefused("bootstrap approval outside local time policy")
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ApprovalRefused("bootstrap document refused") from exc
    return VerifiedBootstrapApproval(expected, operator, document["granted_at"],
                                     document["expires_at"], "sha256:" + hashlib.sha256(payload).hexdigest())
