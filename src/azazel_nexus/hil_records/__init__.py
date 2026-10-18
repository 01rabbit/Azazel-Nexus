"""Versioned HIL evidence contracts; no acquisition, signing or admission wiring.

Inputs are JSON-compatible dictionaries. Verification is supplied by a trusted
caller, never read from a record's own ``status``. A verifier must authenticate
the *complete* dictionary (including referenced artifact digests) using an
out-of-band operator key and the evidence bundle's domain. This package does
not implement a second signature protocol. A supplied Status is an equivalent
out-of-band result for this exact record, not a claim copied from its JSON.

``attested`` establishes attribution and validated observations, not physics.
Only attested results are admissible; shape_only is a diagnostic state. No
record constructors or hardware measurements are shipped here. All field
errors are reported by name, without echoing potentially confidential values.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.core_reserve import ReserveRefused, parse_record
from azazel_nexus.core_reserve import validate as validate_reserve

CAMPAIGN_SCHEMA = "azazel-nexus/core-reserve-campaign/v1"
GATE_SCHEMA = "azazel-nexus/hil-gate/v1"
BEHAVIOUR_SCHEMA = "azazel-nexus/hil-on-host/v1"
DRILL_SCHEMA = "azazel-nexus/hil-degraded-drill/v1"
SCHEMAS = (CAMPAIGN_SCHEMA, GATE_SCHEMA, BEHAVIOUR_SCHEMA, DRILL_SCHEMA)
GATES = ("HG-01", "HG-02", "HG-04", "HG-06", "HG-07")
BEHAVIOURS = (
    "local_inference",
    "remote_fallback",
    "network_loss",
    "model_crash",
    "resource_pressure",
    "revocation",
)
DRILLS = (
    "local_model_loss",
    "remote_loss",
    "knowledge_full_node_loss",
    "deception_loss",
    "invalid_mission_pack",
    "storage_pressure",
    "service_restart",
    "stale_provider_response",
    "topology_drift",
    "cold_boot",
    "restart",
    "disk_pressure",
    "certificate_revocation",
    "audit_write_pressure",
    "uncommissioned",
    "topology_ineligible",
)
# Explicit class rather than profile alone: 32 and 64 GiB both select standard.
CLASS_PROFILES = {
    "8GiB": "core",
    "16GiB": "lite",
    "32GiB": "standard",
    "64GiB": "standard",
}
HMAC = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
ANONYMOUS_ID = re.compile(r"dut-[0-9a-f]{32}\Z")
MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
CISCO_MAC = re.compile(r"(?i)\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b")
SERIAL = re.compile(
    r"(?i)\b(?:serial(?:[ _-]?(?:number|no))?|s/n|asset[ _-]?(?:id|tag|number))\s*[:=#]\s*\S+"
)
RAW_KEYS = {
    "mac",
    "permanent_mac",
    "mac_address",
    "serial",
    "serial_number",
    "asset_id",
    "asset_tag",
}


class Status(str, Enum):
    REFUSED = "refused"
    SHAPE_ONLY = "shape_only"
    ATTESTED = "attested"


@dataclass(frozen=True)
class Validation:
    status: Status
    reasons: tuple[str, ...] = ()
    reserve_mib: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, Status):
            raise TypeError("explicit Status required")
        if (self.status is Status.REFUSED) != bool(self.reasons):
            raise ValueError("only refused results carry refusal reasons")
        if self.reserve_mib is not None and self.status is not Status.ATTESTED:
            raise ValueError("only attested campaigns yield a reserve")

    @property
    def admissible(self) -> bool:
        return self.status is Status.ATTESTED


Attestation = Status | Callable[[dict], Status]


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _matches(pattern: re.Pattern, value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _privacy(value: object, reasons: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[ -]+", "_", str(key).lower())
            if (
                (normalized == "synthetic" and child is not False)
                or (normalized == "physical_hardware" and child is not True)
                or (normalized == "provenance" and child != "measured")
                or (
                    normalized == "status"
                    and child in ("fixture", "synthetic", "shape_only")
                )
            ):
                reasons.append("nested fixture/synthetic/shape_only evidence refused")
            if normalized in RAW_KEYS:
                reasons.append("raw identifier field refused")
            _privacy(str(key), reasons)
            _privacy(child, reasons)
    elif isinstance(value, list):
        for child in value:
            _privacy(child, reasons)
    elif isinstance(value, str) and (
        MAC.search(value) or CISCO_MAC.search(value) or SERIAL.search(value)
    ):
        reasons.append("raw MAC/serial/asset pattern refused")


def _common(record: dict, reasons: list[str]) -> None:
    for key, expected in {
        "class": "hardware-only",
        "synthetic": False,
        "physical_hardware": True,
        "platform": "rugged-x86_64-linux",
        "provenance": "measured",
    }.items():
        if type(record.get(key)) is not type(expected) or record.get(key) != expected:
            reasons.append(
                f"{key}: hardware measurement required; fixture/synthetic refused"
            )
    if record.get("status") in ("fixture", "synthetic", "shape_only"):
        reasons.append("record-declared fixture/synthetic/shape_only refused")
    if not _matches(ANONYMOUS_ID, record.get("dut_id")):
        reasons.append("dut_id: anonymous dut- plus 32 lowercase hex required")
    if not _matches(HMAC, record.get("dut_fingerprint")):
        reasons.append("dut_fingerprint: key-protected HMAC-SHA256 required")
    for key in ("capture_method", "operator_attestation_ref", "workload_notes"):
        if not _text(record.get(key)):
            reasons.append(f"{key}: nonempty reference/description required")
    if record.get("hardware_class") not in CLASS_PROFILES:
        reasons.append("hardware_class: explicit GiB class required")


def _verification(
    record: dict, attestation: Attestation | None, reasons: list[str]
) -> Status:
    try:
        status = attestation(record) if callable(attestation) else attestation
    except (ValueError, TypeError, RuntimeError, OSError):
        reasons.append("operator attestation verification failed")
        return Status.REFUSED
    if status is None or status is Status.SHAPE_ONLY:
        return Status.SHAPE_ONLY
    if status is not Status.ATTESTED:
        reasons.append(
            "operator attestation refused (explicit external Status required)"
        )
        return Status.REFUSED
    return Status.ATTESTED


def _expected(observations: dict, fields: dict, reasons: list[str]) -> None:
    for key, expected in fields.items():
        if (
            type(observations.get(key)) is not type(expected)
            or observations.get(key) != expected
        ):
            reasons.append(f"observations.{key}: required outcome absent or failed")


def _descriptions(
    observations: dict, fields: tuple[str, ...], reasons: list[str]
) -> None:
    for key in fields:
        if not _text(observations.get(key)):
            reasons.append(f"observations.{key}: capture/reference required")


def _gate(record: dict, reasons: list[str]) -> None:
    gate = record.get("gate_id")
    observations = record.get("observations")
    if gate not in GATES or not isinstance(observations, dict):
        reasons.append("known gate_id and observations object required")
        return
    if gate == "HG-01":
        _descriptions(
            observations,
            (
                "systemd_version",
                "unit_inventory_ref",
                "unit_states_ref",
                "interface_counts_ref",
            ),
            reasons,
        )
        _expected(
            observations,
            {
                "all_governed_units_masked": True,
                "all_governed_units_inactive": True,
                "transmitted_frames": 0,
            },
            reasons,
        )
    elif gate == "HG-02":
        _expected(
            observations,
            {"package_created_accounts": True, "controller_only_unmask": True},
            reasons,
        )
        _descriptions(
            observations, ("account_inventory_ref", "unmask_attempts_ref"), reasons
        )
        attempts = observations.get("attempts")
        if not isinstance(attempts, list) or not attempts:
            reasons.append("observations.attempts: daemon account attempts required")
        else:
            expected_accounts = {unit.name: unit.account for unit in CORE_UNITS}
            seen = set()
            for attempt in attempts:
                if not isinstance(attempt, dict):
                    reasons.append("observations.attempts: object required")
                    continue
                _descriptions(attempt, ("daemon", "account", "capture_ref"), reasons)
                _expected(attempt, {"unmask_refused": True}, reasons)
                daemon = attempt.get("daemon")
                if isinstance(daemon, str):
                    seen.add(daemon)
                    if attempt.get("account") != expected_accounts.get(daemon):
                        reasons.append(
                            "observations.attempts: package daemon account mismatch"
                        )
            if seen != set(expected_accounts) or len(attempts) != len(seen):
                reasons.append(
                    "observations.attempts: each governed daemon required exactly once"
                )
    elif gate == "HG-04":
        _descriptions(
            observations,
            ("kernel_ref", "driver_ref", "commissioning_ref", "role_nic_inventory_ref"),
            reasons,
        )
        _expected(
            observations,
            {
                "own_account": True,
                "all_role_nics_perm_address": True,
                "renamed_after_reboot": True,
                "identities_survived": True,
            },
            reasons,
        )
    elif gate == "HG-06":
        _expected(
            observations,
            {
                "bridge": "az-decoy0",
                "namespace_capture": True,
                "on_boot": True,
                "before_exposure": True,
                "failure_removes_eligibility": True,
            },
            reasons,
        )
        _descriptions(
            observations, ("container_ref", "capture_ref", "exposure_ref"), reasons
        )
        paths = observations.get("denied_paths")
        if not isinstance(paths, dict) or set(paths) != {
            "protected",
            "management",
            "control_plane",
            "internet",
        }:
            reasons.append("observations.denied_paths: all four zones required")
        else:
            _expected(paths, dict.fromkeys(paths, True), reasons)
    else:
        _descriptions(
            observations,
            ("edge_build_ref", "installed_package_ref", "probe_ref", "status_ref"),
            reasons,
        )
        _expected(
            observations,
            dict.fromkeys(
                (
                    "real_packager",
                    "fixed_install_location",
                    "real_binary_health",
                    "real_dbus",
                    "presence",
                    "version",
                    "digest",
                    "health",
                    "running",
                    "edge_baseline_ready",
                ),
                True,
            ),
            reasons,
        )


def _behaviour(record: dict, reasons: list[str]) -> None:
    behaviour = record.get("behaviour")
    observations = record.get("observations")
    if behaviour not in BEHAVIOURS or not isinstance(observations, dict):
        reasons.append("known behaviour and observations object required")
        return
    _expected(
        observations,
        {
            "provider_admitted_after_reserve": True,
            "edge_authority_unchanged": True,
            "activation_lease_unchanged": True,
            "enforcement_unchanged": True,
        },
        reasons,
    )
    _descriptions(
        observations,
        ("admission_ref", "request_ref", "capture_ref", "invariants_ref"),
        reasons,
    )
    expected = {
        "local_inference": {"local_answered": True},
        "remote_fallback": {
            "local_failed": True,
            "remote_attempts": 1,
            "remote_answered": True,
        },
        "network_loss": {
            "network_lost": True,
            "remote_excluded": True,
            "local_answered": True,
            "deterministic_continues": True,
        },
        "model_crash": {
            "crash_observed": True,
            "deterministic_continues": True,
            "quarantined": True,
            "restart_authority_unchanged": True,
        },
        "resource_pressure": {
            "shed_order": ["remote", "optional_model", "local_model"],
            "capture_retained": True,
            "evidence_retained": True,
            "audit_retained": True,
            "lease_expiry_retained": True,
        },
        "revocation": {"in_flight": True, "completed_on_revoked_route": False},
    }[behaviour]
    _expected(observations, expected, reasons)
    if behaviour == "revocation" and observations.get("disposition") not in (
        "local_fallback",
        "refused",
    ):
        reasons.append("observations.disposition: local_fallback or refused required")


def _drill(record: dict, reasons: list[str]) -> None:
    observations = record.get("observations")
    if record.get("drill") not in DRILLS or not isinstance(observations, dict):
        reasons.append("known drill and observations object required")
        return
    _descriptions(
        observations,
        (
            "configuration_ref",
            "hardware_inventory_ref",
            "software_asset_generations_ref",
            "os_kernel_driver_ref",
            "model_runtime_quantization_ref",
            "replay_corpus_ref",
            "topology_ref",
            "latency_ref",
            "rss_swap_ref",
            "disk_growth_ref",
            "queue_backpressure_ref",
            "voice_operator_responsiveness_ref",
            "restart_recovery_ref",
            "rollback_ref",
            "watchdog_ref",
            "audit_continuity_ref",
            "lease_expiry_ref",
            "key_protection_ref",
            "safe_rejoin_ref",
            "transition_reasons_ref",
        ),
        reasons,
    )
    _expected(
        observations,
        {
            "core_available": True,
            "edge_authority_unchanged": True,
            "activation_lease_unchanged": True,
            "enforcement_unchanged": True,
            "capability_display_matches": True,
            "resource_topology_independent": True,
            "x86_specific": True,
            "pi_equivalence_claimed": False,
        },
        reasons,
    )
    if (
        type(observations.get("repeat_count")) is not int
        or observations["repeat_count"] < 1
    ):
        reasons.append("observations.repeat_count: positive integer required")
    transitions = observations.get("transitions")
    if (
        not isinstance(transitions, list)
        or not transitions
        or any(t not in ("FULL", "LITE", "CORE") for t in transitions)
    ):
        reasons.append(
            "observations.transitions: FULL/LITE/CORE state sequence required"
        )
    if record.get("drill") in (
        "uncommissioned",
        "topology_ineligible",
        "topology_drift",
    ):
        _expected(observations, {"observe_only": True}, reasons)


def _campaign(
    record: dict, attestation: Attestation | None, reasons: list[str]
) -> int | None:
    runs = record.get("runs")
    if not isinstance(runs, list) or len(runs) < 3:
        reasons.append("runs: at least three per-boot records required")
        return None
    boots: set[str] = set()
    maxima: list[int] = []
    for index, run in enumerate(runs):
        errors: list[str] = []
        if not isinstance(run, dict):
            reasons.append(f"runs[{index}]: object required")
            continue
        _common(run, errors)
        for key in ("hardware_class", "dut_id", "dut_fingerprint", "harness_version"):
            if run.get(key) != record.get(key):
                errors.append(f"{key}: campaign/run mismatch")
        boot = run.get("boot_fingerprint")
        if not _matches(HMAC, boot):
            errors.append("boot_fingerprint: HMAC-SHA256 required")
        else:
            boots.add(boot)
        measurement = run.get("measurement")
        try:
            parsed = parse_record(json.dumps(measurement, allow_nan=False))
            errors.extend(validate_reserve(parsed).refusals)
            if parsed.profile.value != CLASS_PROFILES.get(record.get("hardware_class")):
                errors.append("measurement profile differs from campaign class")
            if parsed.harness_version != record.get("harness_version"):
                errors.append("measurement harness differs from campaign")
            if parsed.host_digest != record.get("dut_fingerprint"):
                errors.append("measurement host differs from campaign DUT HMAC")
            # v2 carries its own boot identity; v1 requires the attested envelope.
            if (
                isinstance(measurement, dict)
                and "boot_fingerprint" in measurement
                and measurement["boot_fingerprint"] != boot
            ):
                errors.append("measurement boot differs from run")
            if parsed.observed_maximum_mib is not None:
                maxima.append(parsed.observed_maximum_mib)
        except (ReserveRefused, ValueError, TypeError):
            errors.append("measurement: malformed or unsupported core-reserve record")
        if _verification(run, attestation, errors) is not Status.ATTESTED:
            errors.append(
                "every campaign run must be externally attested; shape_only refused"
            )
        reasons.extend(f"runs[{index}]: {error}" for error in errors)
    if len(boots) < 3:
        reasons.append("runs: at least three distinct boot fingerprints required")
    return max(maxima, default=None)


def validate_record(
    record: object, *, attestation: Attestation | None = None
) -> Validation:
    """Validate one contract. Never trust an in-record attestation status.

    Missing verification yields diagnostic shape_only, never admissibility.
    Campaign runs must each be attested; a shape-only run refuses the campaign.
    A campaign also requires verification of the aggregate and workload notes.
    The callable is invoked independently on each run and the aggregate.
    """
    reasons: list[str] = []
    if not isinstance(record, dict):
        return Validation(Status.REFUSED, ("record: object required",))
    try:
        # Enforce a plain, bounded JSON value, not arbitrary Python objects.
        encoded = json.dumps(record, allow_nan=False)
        if len(encoded.encode("utf-8")) > 4 * 1024 * 1024:
            return Validation(Status.REFUSED, ("record exceeds 4 MiB",))
        record = json.loads(encoded)
        _privacy(record, reasons)
        _common(record, reasons)
        schema = record.get("schema")
        maximum = None
        if schema == CAMPAIGN_SCHEMA:
            if not _text(record.get("harness_version")):
                reasons.append("harness_version required")
            maximum = _campaign(record, attestation, reasons)
        elif schema == GATE_SCHEMA:
            _gate(record, reasons)
        elif schema == BEHAVIOUR_SCHEMA:
            _behaviour(record, reasons)
        elif schema == DRILL_SCHEMA:
            _drill(record, reasons)
        else:
            reasons.append("unsupported versioned HIL record schema")
        status = _verification(record, attestation, reasons)
    except (ValueError, TypeError, RecursionError):
        return Validation(Status.REFUSED, ("record: malformed JSON fields",))
    if reasons:
        return Validation(Status.REFUSED, tuple(dict.fromkeys(reasons)))
    return Validation(
        status, reserve_mib=maximum if status is Status.ATTESTED else None
    )
