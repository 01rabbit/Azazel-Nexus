"""Local broker persistence and assurance. Never executes or delivers an intent.

One broker-owned leaf holds an append-only ledger and atomic numbered snapshots.
A write-ahead checkpoint binds each snapshot to the ledger. An interrupted or
stale publication is refused on read, never recovered as a healthy adapter.
Only public signed declarations and bounded local metadata are persisted.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ..audit import AuditLedger
from ..commissioning import CommissioningRecord
from ..knowledge_peer import canonical, instant
from ..lite_import import _atomic_write
from . import states
from .confinement import AdapterCommissioning, render_adapter_unit
from .manifest import Capability, ManifestRefused, is_safe_symbol, read_manifest
from .routing import (
    ConsumedLeaseStore,
    DataRecord,
    DispatchIntent,
    EdgeLease,
    GateRefusal,
    deliver,
    gate_exposure_proposal,
    route_advisory,
    route_telemetry,
)
from .states import BrokerState


class BrokerRefused(ValueError):
    """Local state is unavailable; no readiness can be inferred."""


class Broker:
    """A commissioned local control plane; content only enters route/gate.

    Trust maps and topology must come from commissioning, never a data payload.
    No unit manager, activation controller, credential accessor or transport is
    accepted. Withdrawal records local intent cancellation; it cannot roll back
    a device because no adapter operation can be delivered in this release.
    """

    def __init__(self, root: Path, *, trusted_keys=None, topology: CommissioningRecord | None = None,
                 sibling_keys=None, edge_keys=None):
        self.root = Path(root)
        self.trusted_keys = dict(trusted_keys or {})
        self.topology = topology
        self.edge_keys = dict(edge_keys or {})
        if (set(self.edge_keys) & set(self.trusted_keys)
                or set(self.edge_keys.values()) & set(self.trusted_keys.values())):
            raise BrokerRefused("shared_edge_adapter_key")
        self.sibling_keys = dict(sibling_keys or {})
        for role in self.sibling_keys.values():
            keys = role.values() if isinstance(role, dict) else role
            if (set(self.edge_keys.values()) & set(keys)
                    or (isinstance(role, dict) and set(self.edge_keys) & set(role))):
                raise BrokerRefused("shared_edge_signing_key")
        self.ledger = AuditLedger(self.root / "audit" / "ledger.jsonl")

    def _load(self):
        self.ledger.verify()
        try:
            number = int((self.root / "current").read_text())
        except FileNotFoundError:
            if any(e.event.get("event_type") in {"broker.checkpoint", "broker.transaction"}
                   for e in self.ledger):
                raise BrokerRefused("unfinished_publication") from None
            return {"generation": 0, "adapters": {}}
        doc = json.loads((self.root / "generations" / f"{number}.json").read_bytes())
        checkpoints = [e for e in self.ledger if e.event.get("event_type") == "broker.checkpoint"]
        transactions = [e for e in self.ledger if e.event.get("event_type") == "broker.transaction"]
        if transactions and (not checkpoints or transactions[-1].sequence > checkpoints[-1].sequence):
            raise BrokerRefused("unfinished_publication")
        digest = "sha256:" + hashlib.sha256(canonical(doc)).hexdigest()
        if (doc["generation"] != number or not checkpoints
                or checkpoints[-1].event.get("snapshot_digest") != digest):
            raise BrokerRefused("unfinished_publication")
        for adapter, entry in doc["adapters"].items():
            record = self._record(entry)
            if adapter != record.adapter_id or not is_safe_symbol(entry["reason"]):
                raise BrokerRefused("invalid_record")
        return doc

    @contextmanager
    def _write(self):
        self.root.mkdir(parents=True, exist_ok=True)
        with (self.root / "writer.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            doc = self._load()
            self._event("transaction", generation=doc["generation"] + 1)
            yield doc
            doc["generation"] += 1
            payload = canonical(doc)
            self._event("checkpoint", snapshot_digest="sha256:" + hashlib.sha256(payload).hexdigest())
            _atomic_write(self.root / "generations" / f"{doc['generation']}.json", payload)
            _atomic_write(self.root / "current", str(doc["generation"]).encode())

    def _event(self, kind, **metadata):
        self.ledger.verify()
        self.ledger.append({"event_type": "broker." + kind, **metadata})

    @staticmethod
    def _record(entry, approval=None, now=None):
        return states.restore_record(entry["adapter_id"], BrokerState(entry["state"]),
                                     entry["manifest_digest"], instant(entry["since"]),
                                     now=instant(now) if now else datetime.now(UTC), lease=approval,
                                     lease_id=entry.get("lease_id"),
                                     lease_expires_at=instant(entry["lease_until"]) if entry.get("lease_until") else None)

    def _manifest(self, entry):
        if self.topology is None:
            raise BrokerRefused("commissioning_required")
        manifest = read_manifest(bytes.fromhex(entry["signed"]), trusted_keys=self.trusted_keys,
                                 commissioning_digest=self.topology.digest(),
                                 wider_egress_allowlist=tuple(tuple(v) for v in entry.get("wider_egress_allowlist", [])),
                                 management_prefixes=entry.get("management_prefixes", ()), **self.sibling_keys)
        if manifest.manifest_digest != entry["manifest_digest"] or manifest.adapter_id != entry["adapter_id"]:
            raise BrokerRefused("manifest_record_mismatch")
        return manifest

    def _admitted(self, entry, now):
        if instant(entry["credential_expires_at"]) <= instant(now):
            raise BrokerRefused("credential_expired")
        return self._manifest(entry)

    def _move(self, entry, to, *, reason, now, approval=None):
        record, event = states.transition(self._record(entry, approval, now), to, reason=reason,
                                          now=instant(now), approval=approval)
        self.ledger.append(event.as_event())
        entry.update(state=record.state.value, since=record.since.isoformat(), reason=event.reason,
                     lease_id=record.lease_id,
                     lease_until=record.lease_expires_at.isoformat() if record.lease_expires_at else None)

    def review(self, raw: bytes, *, commissioning: AdapterCommissioning, now: str):
        """Pure dry-run: verifies commissioned trust and renders, writes nothing."""
        if self.topology is None:
            raise BrokerRefused("commissioning_required")
        manifest = read_manifest(raw, trusted_keys=self.trusted_keys,
                                 commissioning_digest=self.topology.digest(),
                                 wider_egress_allowlist=commissioning.wider_egress_allowlist,
                                 management_prefixes=commissioning.management_prefixes, **self.sibling_keys)
        unit = render_adapter_unit(manifest, commissioning=commissioning, now=instant(now))
        return manifest, unit

    def admit(self, raw: bytes, *, commissioning: AdapterCommissioning, now: str):
        """Explicit library commissioning action. Never installs the rendered unit."""
        try:
            if commissioning.reviewed_at != instant(now):
                raise BrokerRefused("current_credential_review_required")
            manifest, unit = self.review(raw, commissioning=commissioning, now=now)
        except (ManifestRefused, ValueError):
            with self._write() as doc:
                self._event("schema_trust", decision="refused", occurred_at=now)
                self._withdraw(doc, reason="admission_refused", now=now)
            raise
        with self._write() as doc:
            self._event("schema_trust", decision="verified", adapter_id=manifest.adapter_id, occurred_at=now)
            prior = doc["adapters"].get(manifest.adapter_id)
            if prior and (self._record(prior).state is not BrokerState.DISABLED
                          or instant(now) < instant(prior["since"])):
                raise BrokerRefused("adapter_already_known")
            entry = {"adapter_id": manifest.adapter_id, "state": BrokerState.DISABLED.value,
                     "manifest_digest": manifest.manifest_digest, "signed": raw.hex(),
                     "since": instant(now).isoformat(), "reason": "admission", "healthy_until": None,
                     "credential_expires_at": commissioning.credential.expires_at.isoformat(),
                     "lease_until": None, "lease_id": None,
                     "wider_egress_allowlist": commissioning.wider_egress_allowlist,
                     "management_prefixes": commissioning.management_prefixes}
            for state in (BrokerState.DISCOVERED, BrokerState.STAGED, BrokerState.ADMITTED):
                self._move(entry, state, reason="admission", now=now)
            if Capability.EXPOSURE_CHANGE not in manifest.capability_set or not self.topology.enforcement_ready:
                self._move(entry, BrokerState.OBSERVE_ONLY, reason="observe_only", now=now)
            doc["adapters"][manifest.adapter_id] = entry
            self._event("admission", adapter_id=manifest.adapter_id,
                        manifest_digest=manifest.manifest_digest, occurred_at=now)
        return unit

    def route(self, adapter_id, payload, *, advisory=False, **context):
        """Payload enters the sanitizer only; neither payload nor frame is stored."""
        with self._write() as doc:
            entry = doc["adapters"][adapter_id]
            try:
                manifest = self._admitted(entry, context["now"])
            except (ManifestRefused, BrokerRefused):
                self._event("schema_trust", decision="refused", adapter_id=adapter_id, occurred_at=context["now"])
                self._withdraw(doc, reason="trust_revoked", now=context["now"])
                return GateRefusal("manifest trust refused")
            self._event("schema_trust", decision="verified", adapter_id=adapter_id, occurred_at=context["now"])
            route = route_advisory if advisory else route_telemetry
            result = route(payload, adapter_record=self._record(entry), manifest=manifest, **context)
            allowed = isinstance(result, DataRecord)
            self._event("privacy_sanitization", adapter_id=adapter_id, allowed=allowed, occurred_at=context["now"])
            self._event("routing", adapter_id=adapter_id, allowed=allowed,
                        destination="operator/mio" if advisory else "knowledge", occurred_at=context["now"])
            entry["healthy_until"] = result.expires_at if allowed else None
            self._event("postcondition_observation", adapter_id=adapter_id, healthy=allowed, occurred_at=context["now"])
            if not allowed:
                self._withdraw(doc, reason="privacy_or_health", now=context["now"])
            return result

    def gate(self, proposal, *, edge_lease: EdgeLease | None, now: str, **context):
        with self._write() as doc:
            entry = doc["adapters"][proposal.adapter_id]
            try:
                manifest = self._admitted(entry, now)
            except (ManifestRefused, BrokerRefused):
                self._event("schema_trust", decision="refused", adapter_id=proposal.adapter_id, occurred_at=now)
                self._withdraw(doc, reason="trust_revoked", now=now)
                return GateRefusal("manifest trust refused")
            self._event("schema_trust", decision="verified", adapter_id=proposal.adapter_id, occurred_at=now)
            if entry["lease_until"] and instant(entry["lease_until"]) <= instant(now):
                self._withdraw(doc, reason="lease_expired", now=now)
                return GateRefusal("Edge lease expired; withdrawn")
            result = gate_exposure_proposal(
                proposal, adapter_record=self._record(entry), manifest=manifest,
                edge_lease=edge_lease or EdgeLease(b""), topology=self.topology, now=now,
                edge_keys=self.edge_keys,
                consumed_leases=ConsumedLeaseStore(doc.setdefault("consumed_leases", [])), **context)
            self._event("lease_binding", adapter_id=proposal.adapter_id,
                        allowed=isinstance(result, DispatchIntent), occurred_at=now)
            self._event("routing", adapter_id=proposal.adapter_id,
                        allowed=isinstance(result, DispatchIntent), destination="intent_only", occurred_at=now)
            if isinstance(result, GateRefusal) and self._record(entry).state is BrokerState.ACTIVE_BOUNDED:
                self._withdraw(doc, reason="lease_or_gate_refused", now=now)
            if isinstance(result, DispatchIntent) and self._record(entry).state is BrokerState.ADMITTED:
                approval = edge_lease.bind(
                    trusted_keys=self.edge_keys, commissioning_digest=self.topology.digest(),
                    adapter_id=proposal.adapter_id, proposal_digest=proposal.digest,
                    manifest_digest=manifest.manifest_digest, now=now)
                for state in (BrokerState.OBSERVE_ONLY, BrokerState.APPROVAL_PENDING, BrokerState.ACTIVE_BOUNDED):
                    self._move(entry, state, reason="lease_bound", now=now, approval=approval)
                entry["lease_until"] = result.expires_at
            return result

    def expire(self, *, now: str):
        """Explicit local watchdog tick; no background thread or device I/O."""
        with self._write() as doc:
            if any((entry["lease_until"] and instant(entry["lease_until"]) <= instant(now))
                   or (entry["healthy_until"] and instant(entry["healthy_until"]) <= instant(now))
                   or instant(entry["credential_expires_at"]) <= instant(now)
                   for entry in doc["adapters"].values()):
                self._withdraw(doc, reason="lease_or_credential_expired", now=now)

    def deliver(self, intent: DispatchIntent, *, now: str):
        result = deliver(intent)
        with self._write() as doc:
            self._event("postcondition_observation", adapter_id=intent.adapter_id,
                        healthy=False, reason="transport_unavailable", occurred_at=now)
            self._withdraw(doc, reason="transport_unavailable", now=now)
        return result

    def _withdraw(self, doc, *, reason, now):
        if not is_safe_symbol(reason):
            reason = "reason_invalid"
        for entry in doc["adapters"].values():
            if self._record(entry).state is not BrokerState.DISABLED:
                if self._record(entry).state is not BrokerState.WITHDRAWING:
                    self._move(entry, BrokerState.WITHDRAWING, reason=reason, now=now)
                self._move(entry, BrokerState.DISABLED, reason=reason, now=now)
            entry["healthy_until"] = None
            entry["lease_until"] = None
        self._event("rollback", reason=reason, core="deterministic", occurred_at=now)
        self._event("withdrawal", reason=reason, core="deterministic", occurred_at=now)

    def withdraw_all(self, *, reason: str, now: str):
        with self._write() as doc:
            self._withdraw(doc, reason=reason, now=now)

    def status(self, *, now: str):
        doc = self._load()
        rows = []
        for adapter, entry in sorted(doc["adapters"].items()):
            healthy = False
            reason = entry["reason"]
            try:
                manifest = self._manifest(entry)
                healthy = (Capability.EXPOSURE_CHANGE not in manifest.capability_set
                           and self._record(entry).state in {BrokerState.ADMITTED, BrokerState.OBSERVE_ONLY}
                           and entry["healthy_until"] is not None
                           and instant(entry["healthy_until"]) > instant(now)
                           and instant(entry["credential_expires_at"]) > instant(now))
            except (ManifestRefused, BrokerRefused):
                reason = "trust_unverified"
            rows.append({"adapter_id": adapter, "state": self._record(entry).state.value, "reason": reason,
                         "healthy": healthy, "manifest_digest": entry["manifest_digest"]})
        return {"status_level": "LITE" if any(row["healthy"] for row in rows) else "CORE",
                "adapters": rows, "core": "deterministic", "enforcement_ready": False,
                "transport": "transport unavailable: Fabric#25"}

    def status_level(self, *, now: str | None = None):
        """LITE = fresh healthy read-only data; FULL reserved for future transport.

        CORE includes no adapters, all withdrawn, expired or unverified health.
        This adapter summary never changes the six product axes or Edge state.
        """
        if now is None:
            now = datetime.now(UTC).isoformat()
        return self.status(now=now)["status_level"]
