"""Pure, purpose-bound local embedding approval verification. No authority is granted."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from uuid import UUID

from .operator_trust import (
    MAX_APPROVAL_BYTES,
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
)

LOCAL_MODEL_ADMISSION_ENABLED = False
MAX_VALIDITY_SECONDS = 7 * 24 * 60 * 60
EMBEDDING_CTX = 2048
EMBEDDING_THREADS = 2
EMBEDDING_MAX_TOKENS = 256
SCHEMA = "azazel-nexus/local-model-admission/v1"
FILE_SCHEMA = "azazel-nexus/local-model-admission-file/v1"
POLICY_SCHEMA = "azazel-nexus/model-admission-policy/v1"
_ADMISSION_SEAL = object()
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FIELDS = {
    "approval_key": {"fingerprint": str, "security_epoch": int},
    "node": {"node_digest": str, "commissioning_digest": str, "hardware_class": str,
             "profile": str, "dut_fingerprint": str},
    "catalog": {"document_digest": str, "schema": str, "version": int,
                "signer_key_id": str, "signer_key_fingerprint": str},
    "model": {"model_id": str, "role": str, "format": str, "digest": str,
              "size_bytes": int, "runtime_abi": str, "license": str},
    "generation": {"number": int, "generation_id": str, "previous_generation_id": str},
    "runtime": {"runtime_id": str, "version": str, "architecture": str,
                "binary_digest": str, "executable": str},
    "settings": {"argv_digest": str},
    "compatibility": {"tuple_digest": str},
    "reserve": {"campaign_record_digest": str, "run_id": str, "attestation_ref": str,
                "manifest_digest": str, "attestation_key_fingerprint": str,
                "reserve_mib": int, "harness_version": str},
    "runtime_evidence": {"peak_rss_mib": int},
    "resources": {"memory_need_mib": int, "envelope_floor_mib": int},
}


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def utc(value: str) -> datetime:
    if type(value) is not str or not re.fullmatch(r"[0-9]{4}-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z", value):
        raise ApprovalRefused("MALFORMED")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ApprovalRefused("MALFORMED") from exc


def decode(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ApprovalRefused("MALFORMED")
            result[key] = value
        return result
    try:
        doc = json.loads(raw, object_pairs_hook=unique)
        if type(doc) is not dict or canonical(doc) != raw:
            raise ApprovalRefused("MALFORMED")
        return doc
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ApprovalRefused("MALFORMED") from exc


@dataclass(frozen=True)
class AdmissionPolicy:
    operators: frozenset[str]
    max_seconds: int
    roles: tuple[str, ...]

    def __post_init__(self):
        if (type(self.max_seconds) is not int or not 0 < self.max_seconds <= MAX_VALIDITY_SECONDS
                or self.roles != ("embedding",) or not self.operators
                or any(type(op) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", op)
                       for op in self.operators)):
            raise ApprovalRefused("POLICY_REFUSED")
        object.__setattr__(self, "operators", frozenset(self.operators))

    @classmethod
    def from_bytes(cls, raw):
        doc = decode(raw)
        if (set(doc) != {"schema", "operators", "max_seconds", "roles"}
                or doc["schema"] != POLICY_SCHEMA or type(doc["operators"]) is not list
                or type(doc["roles"]) is not list
                or any(type(op) is not str for op in doc["operators"])
                or len(set(doc["operators"])) != len(doc["operators"])):
            raise ApprovalRefused("POLICY_REFUSED")
        return cls(frozenset(doc["operators"]), doc["max_seconds"], tuple(doc["roles"]))


@dataclass(frozen=True)
class AdmissionContext:
    """Independently collected observations. Nested values are immutable snapshots."""
    bindings: object

    def __post_init__(self):
        doc = dict(self.bindings)
        if set(doc) != set(_FIELDS):
            raise ApprovalRefused("MALFORMED")
        frozen = {}
        for name, fields in _FIELDS.items():
            section = dict(doc[name])
            if set(section) != set(fields):
                raise ApprovalRefused("MALFORMED")
            for key, kind in fields.items():
                value = section[key]
                if type(value) is not kind or (kind is int and value < 0):
                    raise ApprovalRefused("MALFORMED")
                if kind is str and (not value and key != "previous_generation_id"):
                    raise ApprovalRefused("MALFORMED")
                if ((key.endswith(("digest", "key_fingerprint"))
                     or key == "fingerprint" or key in ("generation_id", "previous_generation_id"))
                        and value and not _DIGEST.fullmatch(value)):
                    raise ApprovalRefused("MALFORMED")
            frozen[name] = MappingProxyType(section)
        if not re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", frozen["node"]["dut_fingerprint"]):
            raise ApprovalRefused("MALFORMED")
        if frozen["model"]["role"] != "embedding":
            raise ApprovalRefused("ROLE_MISMATCH")
        if frozen["model"]["license"] not in ("acknowledged", "not-required"):
            raise ApprovalRefused("MALFORMED")
        if (not 0 < frozen["resources"]["memory_need_mib"] <= 3840
                or not 0 < frozen["runtime_evidence"]["peak_rss_mib"]
                <= frozen["resources"]["memory_need_mib"]
                or frozen["resources"]["envelope_floor_mib"] < 1):
            raise ApprovalRefused("RESOURCE_FIT")
        object.__setattr__(self, "bindings", MappingProxyType(frozen))

    def as_document(self):
        return {key: dict(value) for key, value in self.bindings.items()}


def admission_payload(*, context: AdmissionContext, operator: str, approval_id: str,
                      issued_at: str, expires_at: str) -> bytes:
    if type(context) is not AdmissionContext:
        raise ApprovalRefused("MALFORMED")
    try:
        identity = UUID(approval_id)
        if identity.version != 4 or str(identity) != approval_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise ApprovalRefused("MALFORMED") from exc
    if type(operator) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", operator):
        raise ApprovalRefused("MALFORMED")
    if not 0 < (utc(expires_at) - utc(issued_at)).total_seconds() <= MAX_VALIDITY_SECONDS:
        raise ApprovalRefused("VALIDITY_EXCEEDS_POLICY")
    payload = canonical({"schema": SCHEMA, "purpose": ApprovalPurpose.LOCAL_MODEL_ADMISSION.value,
                      "approval_id": approval_id, "operator": operator, **context.as_document(),
                      "issued_at": issued_at, "expires_at": expires_at})
    if not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise ApprovalRefused("MALFORMED")
    return payload


@dataclass(frozen=True)
class VerifiedModelAdmission:
    context: AdmissionContext
    payload_digest: str
    approval_id: str
    issued_at: str
    expires_at: str
    descriptors: object = field(repr=False)
    _seal: object = field(repr=False)

    def __post_init__(self):
        if self._seal is not _ADMISSION_SEAL:
            raise ApprovalRefused("verified model admission required")


def is_verified(value) -> bool:
    return type(value) is VerifiedModelAdmission and getattr(value, "_seal", None) is _ADMISSION_SEAL


def verify_local_model_admission(*, trust: OperatorTrust, policy: AdmissionPolicy,
                                 expected: AdmissionContext, role: str, operator: str,
                                 payload: bytes, signature: bytes, now: str,
                                 descriptors=None) -> VerifiedModelAdmission:
    if type(trust) is not OperatorTrust or type(policy) is not AdmissionPolicy or type(expected) is not AdmissionContext:
        raise ApprovalRefused("MALFORMED")
    if role != "embedding":
        raise ApprovalRefused("ROLE_MISMATCH")
    if operator not in policy.operators:
        raise ApprovalRefused("POLICY_REFUSED")
    try:
        trust.verify(operator=operator, purpose=ApprovalPurpose.LOCAL_MODEL_ADMISSION,
                     payload=payload, signature=signature)
    except ApprovalRefused as exc:
        raise ApprovalRefused("SIGNATURE_REFUSED") from exc
    doc = decode(payload)
    if set(doc) != {*_FIELDS, "schema", "purpose", "approval_id", "operator", "issued_at", "expires_at"}:
        raise ApprovalRefused("MALFORMED")
    if any(type(doc[name]) is not dict for name in _FIELDS):
        raise ApprovalRefused("MALFORMED")
    if doc["model"].get("role") != role:
        raise ApprovalRefused("ROLE_MISMATCH")
    start, end, instant = utc(doc["issued_at"]), utc(doc["expires_at"]), utc(now)
    if instant < start:
        raise ApprovalRefused("NOT_YET_VALID")
    if instant >= end:
        raise ApprovalRefused("EXPIRED")
    if not 0 < (end - start).total_seconds() <= policy.max_seconds:
        raise ApprovalRefused("VALIDITY_EXCEEDS_POLICY")
    key = expected.bindings["approval_key"]
    if (key["fingerprint"] != digest(trust.public_keys[operator])
            or doc["approval_key"].get("fingerprint") != key["fingerprint"]):
        raise ApprovalRefused("KEY_ROTATED")
    attester = expected.bindings["reserve"]["attestation_key_fingerprint"]
    if attester == key["fingerprint"]:
        raise ApprovalRefused("ATTESTER_IS_APPROVER")
    if attester not in {digest(k) for op, k in trust.public_keys.items() if op not in trust.revoked}:
        raise ApprovalRefused("RESERVE_UNATTESTED")
    canonical_payload = admission_payload(context=expected, operator=operator,
                                          approval_id=doc["approval_id"],
                                          issued_at=doc["issued_at"], expires_at=doc["expires_at"])
    if payload != canonical_payload:
        # Compare bindings without trusting their types or accepting bool as int.
        reasons = {"approval_key": "EPOCH_MISMATCH", "node": "NODE_MISMATCH",
                   "catalog": "CATALOG_MISMATCH", "model": "CATALOG_MISMATCH",
                   "generation": "GENERATION_MISMATCH", "runtime": "RUNTIME_MISMATCH",
                   "settings": "SETTINGS_MISMATCH", "compatibility": "TUPLE_MISMATCH",
                   "reserve": "RESERVE_MISMATCH", "runtime_evidence": "RUNTIME_EVIDENCE_MISSING",
                   "resources": "RESOURCE_FIT"}
        for name, value in expected.as_document().items():
            if canonical(doc[name]) != canonical(value):
                raise ApprovalRefused(reasons[name])
        raise ApprovalRefused("MALFORMED")
    return VerifiedModelAdmission(expected, digest(payload), doc["approval_id"],
                                  doc["issued_at"], doc["expires_at"], descriptors, _ADMISSION_SEAL)
