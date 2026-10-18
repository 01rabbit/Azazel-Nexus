"""Nexus-local data routing and exposure assurance. No adapter transport.

Manifest/record arguments come from the commissioned admission store, never
from a connector. Edge keys are the commissioned Edge-role keys only (not
adapter, catalog or registry keys). No function here accepts an executor,
credential resolver, state store or callback from a payload.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..commissioning import CommissioningRecord
from ..knowledge_peer import KnowledgeRefused, canonical, fresh, instant
from ..lite_cache import Freshness
from ..sanitizer import PrivacyClass, Redaction, SanitizerPolicy, sanitize
from ..signature import SignatureRefused, verify_detached
from .manifest import AdapterManifest
from .states import AdapterRecord, BrokerState

EDGE_LEASE_DOMAIN = b"azazel-nexus/edge-lease/v1\0"
EDGE_LEASE_SCHEMA = "azazel-nexus/edge-lease/1"
MAX_PROPOSAL_BYTES = 65536
MAX_LEASE_BYTES = 8192
MANAGEMENT_HEALTH_MAX_AGE = timedelta(seconds=60)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass(frozen=True)
class GateRefusal:
    reason: str


@dataclass(frozen=True)
class DataRecord:
    """Knowledge input or operator/M.I.O. context, never a command.

    `frame` is the existing sanitizer's immutable JSON data envelope. Keeping
    those bytes avoids mutable payload aliases and inventing a Knowledge wire
    contract. The caller may hand this record to Knowledge as data only.
    """

    adapter_id: str
    manifest_digest: str
    observed_at: str
    expires_at: str
    evaluated_at: str
    privacy_class: PrivacyClass
    frame: bytes
    redaction: Redaction
    destination: str
    freshness: Freshness = Freshness.CURRENT
    trust: str = "untrusted data"


def _adapter_refusal(
    record: AdapterRecord,
    manifest: AdapterManifest,
    capability: str,
    *,
    exposure: bool = False,
) -> GateRefusal | None:
    if record.adapter_id != manifest.adapter_id or not record.adapter_id:
        return GateRefusal("adapter identity mismatch")
    if not isinstance(record.manifest_digest, str) or not _DIGEST.fullmatch(
        record.manifest_digest
    ):
        return GateRefusal("missing admitted manifest digest")
    state = record.state
    allowed = {BrokerState.ADMITTED, BrokerState.ACTIVE_BOUNDED}
    if not exposure:
        allowed.add(BrokerState.OBSERVE_ONLY)
    if state not in allowed:
        return GateRefusal("adapter state does not permit routing")
    capabilities = frozenset(manifest.capability_set)
    if capability not in capabilities:
        return GateRefusal("adapter lacks " + capability)
    if "exposure_change" in capabilities and capabilities & {
        "telemetry_read",
        "advisory_read",
    }:
        return GateRefusal("read and exposure capabilities require separate adapters")
    return None


def _route(
    payload: Mapping,
    *,
    adapter_record: AdapterRecord,
    manifest: AdapterManifest,
    observed_at: str,
    expires_at: str,
    now: str,
    policy: SanitizerPolicy,
    mission: str,
    alias_key: bytes,
    capability: str,
    destination: str,
) -> DataRecord | GateRefusal:
    refusal = _adapter_refusal(adapter_record, manifest, capability)
    if refusal:
        return refusal
    try:
        fresh({"issued_at": observed_at, "expires_at": expires_at}, now)
        privacy = PrivacyClass(manifest.privacy_class)
        encoded = canonical(dict(payload))
        if len(encoded) > MAX_PROPOSAL_BYTES:
            return GateRefusal("data payload size exceeded")
        payload = json.loads(encoded)
    except (KnowledgeRefused, ValueError):
        return GateRefusal("invalid privacy class or stale observation")
    except (TypeError, UnicodeError, RecursionError):
        return GateRefusal("invalid data payload")
    decision = sanitize(
        payload,
        privacy_class=privacy,
        policy=policy,
        mission=mission,
        alias_key=alias_key,
    )
    if not decision.allowed:
        return GateRefusal("sanitizer refused: " + decision.reason)
    return DataRecord(
        adapter_record.adapter_id,
        adapter_record.manifest_digest,
        observed_at,
        expires_at,
        now,
        privacy,
        decision.frame,
        decision.redaction,
        destination,
    )


def route_telemetry(
    payload: Mapping,
    *,
    adapter_record: AdapterRecord,
    manifest: AdapterManifest,
    observed_at: str,
    expires_at: str,
    now: str,
    policy: SanitizerPolicy,
    mission: str,
    alias_key: bytes,
) -> DataRecord | GateRefusal:
    return _route(
        payload,
        adapter_record=adapter_record,
        manifest=manifest,
        observed_at=observed_at,
        expires_at=expires_at,
        now=now,
        policy=policy,
        mission=mission,
        alias_key=alias_key,
        capability="telemetry_read",
        destination="knowledge",
    )


def route_advisory(
    payload: Mapping,
    *,
    adapter_record: AdapterRecord,
    manifest: AdapterManifest,
    observed_at: str,
    expires_at: str,
    now: str,
    policy: SanitizerPolicy,
    mission: str,
    alias_key: bytes,
) -> DataRecord | GateRefusal:
    return _route(
        payload,
        adapter_record=adapter_record,
        manifest=manifest,
        observed_at=observed_at,
        expires_at=expires_at,
        now=now,
        policy=policy,
        mission=mission,
        alias_key=alias_key,
        capability="advisory_read",
        destination="operator/mio",
    )


@dataclass(frozen=True)
class ExposureChangeProposal:
    """Opaque proposal bytes; no provider command schema is defined here."""

    adapter_id: str
    payload: bytes

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True)
class EdgeLease:
    """Detached signature (64 bytes) followed by canonical Nexus-local JSON.

    Construction confers no authority: verification happens at every gate
    evaluation, including expiry, adapter/proposal and commissioning binding.
    """

    signed: bytes
    _approval: tuple[str, datetime] | None = field(default=None, init=False, repr=False)

    @property
    def verified(self) -> bool:
        return self._approval is not None

    @property
    def adapter_id(self) -> str:
        return self._approval[0] if self._approval else ""

    @property
    def expires_at(self) -> datetime:
        if self._approval is None:
            raise KnowledgeRefused("unverified Edge lease")
        return self._approval[1]

    def bind(self, **verification) -> EdgeLease:
        """Return this same lease type carrying a freshly verified Approval."""
        doc, _ = self.verify(**verification)
        bound = EdgeLease(self.signed)
        object.__setattr__(bound, "_approval", (doc["adapter_id"], instant(doc["expires_at"])))
        return bound

    def verify(
        self,
        *,
        trusted_keys: Mapping[str, bytes],
        commissioning_digest: str,
        adapter_id: str,
        proposal_digest: str,
        now: str,
    ) -> tuple[dict, str]:
        if (
            not isinstance(self.signed, bytes)
            or not 64 < len(self.signed) <= MAX_LEASE_BYTES
        ):
            raise KnowledgeRefused("invalid Edge lease size")
        signature, payload = self.signed[:64], self.signed[64:]
        signer = None
        for key_id, key in sorted(trusted_keys.items()):
            try:
                if verify_detached(
                    public_key=key,
                    message=EDGE_LEASE_DOMAIN + payload,
                    signature=signature,
                ):
                    signer = key_id
                    break
            except SignatureRefused:
                continue
        if signer is None:
            raise KnowledgeRefused("invalid Edge lease signature")
        try:
            doc = json.loads(payload)
            if (
                not isinstance(doc, dict)
                or canonical(doc) != payload
                or set(doc)
                != {
                    "schema",
                    "adapter_id",
                    "proposal_digest",
                    "commissioning_digest",
                    "issued_at",
                    "expires_at",
                }
            ):
                raise ValueError
            if (
                doc["schema"] != EDGE_LEASE_SCHEMA
                or doc["adapter_id"] != adapter_id
                or doc["proposal_digest"] != proposal_digest
                or not commissioning_digest
                or doc["commissioning_digest"] != commissioning_digest
            ):
                raise ValueError
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise KnowledgeRefused("invalid Edge lease binding or schema") from exc
        fresh(doc, now)
        return doc, signer


@dataclass(frozen=True)
class ManagementFailsafe:
    """Local commissioning declaration and health evidence, not proposal fields.

    The named path must match the health check; its commissioning digest must
    match the topology record. The probe/commissioning store owns these facts.
    """

    commissioning_digest: str
    management_path: str
    checked_path: str
    checked_at: str
    healthy: bool


@dataclass(frozen=True)
class DispatchIntent:
    """Audit record only. Deliberately contains neither payload nor executor."""

    adapter_id: str
    manifest_digest: str
    proposal_digest: str
    commissioning_digest: str
    edge_signer: str
    expires_at: str
    dry_run: bool
    human_confirmed: bool


def gate_exposure_proposal(
    proposal: ExposureChangeProposal,
    *,
    adapter_record: AdapterRecord,
    manifest: AdapterManifest,
    edge_lease: EdgeLease,
    failsafe: ManagementFailsafe,
    topology: CommissioningRecord,
    edge_keys: Mapping[str, bytes],
    now: str,
    dry_run: bool = False,
    human_confirmed: bool = False,
) -> DispatchIntent | GateRefusal:
    """Only commissioned local inputs can authorize an intent; delivery refuses."""
    if not topology.enforcement_ready:
        return GateRefusal("topology ineligible: OBSERVE_ONLY")
    refusal = _adapter_refusal(
        adapter_record, manifest, "exposure_change", exposure=True
    )
    if refusal:
        return refusal
    if dry_run is not True or human_confirmed is not True:
        return GateRefusal("dry-run and human confirmation required")
    if (
        proposal.adapter_id != adapter_record.adapter_id
        or not isinstance(proposal.payload, bytes)
        or not 0 < len(proposal.payload) <= MAX_PROPOSAL_BYTES
    ):
        return GateRefusal("invalid proposal identity or size")
    commissioning_digest = topology.digest()
    if (
        failsafe.commissioning_digest != commissioning_digest
        or not failsafe.management_path.strip()
        or failsafe.management_path != failsafe.checked_path
        or failsafe.healthy is not True
    ):
        return GateRefusal("commissioned management path and healthy check required")
    try:
        age = instant(now) - instant(failsafe.checked_at)
        if not timedelta(0) <= age <= MANAGEMENT_HEALTH_MAX_AGE:
            return GateRefusal("management health check is not recent")
        doc, signer = edge_lease.verify(
            trusted_keys=edge_keys,
            commissioning_digest=commissioning_digest,
            adapter_id=proposal.adapter_id,
            proposal_digest=proposal.digest,
            now=now,
        )
    except KnowledgeRefused as exc:
        return GateRefusal(str(exc))
    return DispatchIntent(
        proposal.adapter_id,
        adapter_record.manifest_digest,
        proposal.digest,
        commissioning_digest,
        signer,
        doc["expires_at"],
        dry_run,
        human_confirmed,
    )


def deliver(intent: object) -> GateRefusal:
    """No transport is commissioned, even for a valid or hand-built intent."""
    return GateRefusal("transport unavailable: Fabric#25")
