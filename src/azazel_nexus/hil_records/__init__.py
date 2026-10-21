"""Versioned HIL evidence contracts; no acquisition, signing or admission wiring.

Attestation is established only by verifying a bundle with an out-of-band
operator public key and matching the record's canonical artifact digest.

``attested`` establishes attribution and validated observations, not physics.
Only attested results are admissible; shape_only is a diagnostic state. No
record constructors or hardware measurements are shipped here. All field
errors are reported by name, without echoing potentially confidential values.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from azazel_nexus.activation import CORE_UNITS
from azazel_nexus.core_reserve import ReserveRefused, parse_record
from azazel_nexus.core_reserve import validate as validate_reserve

from .confidentiality import ConfidentialityRefused, lint_text
from .contracts import ANONYMOUS_ID, HMAC
from .evidence import record_in_manifest, verified_manifest

MIO_CAMPAIGN_SCHEMA = "azazel-nexus/hil-mio-campaign/v1"
CAMPAIGN_SCHEMA = "azazel-nexus/core-reserve-campaign/v1"
GATE_SCHEMA = "azazel-nexus/hil-gate/v1"
BEHAVIOUR_SCHEMA = "azazel-nexus/hil-on-host/v1"
DRILL_SCHEMA = "azazel-nexus/hil-degraded-drill/v1"
SCHEMAS = (CAMPAIGN_SCHEMA, MIO_CAMPAIGN_SCHEMA, GATE_SCHEMA, BEHAVIOUR_SCHEMA, DRILL_SCHEMA)
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
    elif isinstance(value, str):
        try:
            lint_text(value.encode("utf-8"))
        except ConfidentialityRefused:
            reasons.append("raw MAC/serial/asset pattern refused; confidentiality violation")


def _common(record: dict, reasons: list[str]) -> None:
    from azazel_nexus.virtualization import virtualization_not_observed

    if (record.get("virtualization_not_observed") is not True
            or not virtualization_not_observed(record.get("virtualization_observations"))):
        reasons.append("RESERVE_VIRTUALIZATION_OBSERVED")
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


def _verification(record: dict, manifest: dict | None, reasons: list[str]) -> Status:
    if manifest is None:
        return Status.SHAPE_ONLY
    if not record_in_manifest(manifest, record):
        reasons.append("record is not a canonical artifact in the verified bundle")
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
    if "acquisition" in record:
        acquisition = record["acquisition"]
        if validate_acquisition(acquisition).status is Status.REFUSED:
            reasons.append("acquisition: invalid acquisition shape")
        elif any(acquisition.get(key) != record.get(key) for key in
                 ("gate_id", "dut_id", "dut_fingerprint")):
            reasons.append("acquisition: gate/DUT identity mismatch")
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
            # Package-created (non-root) daemon accounts only: the runbook
            # never runs the experiment as root, and the one root governed
            # unit (the decoy network helper, #196 P1) is kept from the
            # manager by its sandbox, not by its account. A record captured
            # before #196 P1 lacks azdecoy and must be recaptured.
            expected_accounts = {unit.name: unit.account for unit in CORE_UNITS
                                 if unit.account != "root"}
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
            "protected_zone",
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


CAPTURE_SCHEMAS = {
    "HG-01": "azazel-nexus/hil-capture/hg-01/1",
    "HG-04": "azazel-nexus/hil-capture/hg-04/1",
}


def validate_acquisition(record: object) -> Validation:
    """Check automatic capture/probe syntax, never hardware or attestation.

    These are inputs to gate/campaign envelopes, not alternative admission
    contracts. Even a complete acquisition can return only SHAPE_ONLY.
    Probe v2 is embedded unchanged as a campaign run's ``measurement``.
    """
    from azazel_nexus.core_reserve import RESERVE_SCHEMA_V2, RESERVE_SCHEMA_V3

    from .confidentiality import lint_text
    from .contracts import anonymous_dut

    reasons: list[str] = []
    try:
        if not isinstance(record, dict):
            raise TypeError("acquisition object required")
        encoded = json.dumps(record, allow_nan=False).encode("utf-8")
        if len(encoded) > 4 * 1024 * 1024:
            raise ValueError("acquisition exceeds 4 MiB")
        lint_text(encoded)
        if record.get("schema") in (RESERVE_SCHEMA_V2, RESERVE_SCHEMA_V3):
            # parse_record checks sample types, profile and all v2 metadata.
            # Provenance, duration, count and workload checks remain mandatory
            # in _campaign/validate_reserve, independently of this shape check.
            parse_record(encoded.decode("utf-8"))
        else:
            gate = record.get("gate_id")
            if not isinstance(gate, str) or record.get("schema") != CAPTURE_SCHEMAS.get(gate):
                raise ValueError("unsupported gate acquisition schema")
            if gate not in CAPTURE_SCHEMAS:
                raise ValueError("unsupported gate acquisition")
            if not _matches(HMAC, record.get("dut_fingerprint")):
                raise ValueError("dut_fingerprint: protected HMAC required")
            if record.get("dut_id") != anonymous_dut(record["dut_fingerprint"]):
                raise ValueError("dut_id: must match protected host fingerprint")
            if not _matches(HMAC, record.get("boot_fingerprint")):
                raise ValueError("boot_fingerprint: protected HMAC required")
            if not _matches(re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})"), record.get("build_commit")):
                raise ValueError("build_commit: full commit required")
            if not _text(record.get("kernel_release")):
                raise ValueError("kernel_release required")
            if gate == "HG-01":
                if record.get("capture_method") != "systemd-system-bus-read-only":
                    raise ValueError("capture_method mismatch")
                if not _text(record.get("systemd_version")):
                    raise ValueError("systemd_version required")
                files, units = record.get("unit_files"), record.get("units")
                if not isinstance(files, dict) or not isinstance(units, dict) or not units:
                    raise ValueError("unit_files and units objects required")
                if any(not _text(name) or not _text(state) for name, state in files.items()):
                    raise ValueError("unit file state required")
                for state in units.values():
                    if not isinstance(state, dict) or any(
                        not _text(state.get(key)) for key in ("active_state", "sub_state")
                    ):
                        raise ValueError("unit active/sub state required")
            else:
                if record.get("capture_method") != "RTM_GETLINK/IFLA_PERM_ADDRESS":
                    raise ValueError("capture_method mismatch")
                interfaces = record.get("interfaces")
                if not isinstance(interfaces, list):
                    raise ValueError("interfaces list required")
                for interface in interfaces:
                    if not isinstance(interface, dict):
                        raise TypeError("interface object required")
                    if not _matches(HMAC, interface.get("nic_fingerprint")):
                        raise ValueError("nic_fingerprint: protected HMAC required")
                    present = interface.get("ifla_perm_address_present")
                    usable = interface.get("permanent_address_usable")
                    fingerprint = interface.get("permanent_address_fingerprint")
                    if present is not None and type(present) is not bool:
                        raise ValueError("permanent address presence must be bool or null")
                    if type(usable) is not bool:
                        raise ValueError("permanent address usability must be bool")
                    if usable:
                        if present is not True or not _matches(HMAC, fingerprint):
                            raise ValueError("usable address requires presence and protected HMAC")
                    elif fingerprint is not None:
                        raise ValueError("unusable address cannot carry a fingerprint")
    except (ValueError, TypeError, RecursionError):
        # No field values or platform replies in diagnostics.
        reasons.append("acquisition: malformed, confidential or unsupported fields")
    return Validation(Status.REFUSED, tuple(reasons)) if reasons else Validation(Status.SHAPE_ONLY)


def _campaign(
    record: dict, manifest: dict | None, reasons: list[str]
) -> int | None:
    runs = record.get("runs")
    if not isinstance(runs, list) or len(runs) < 3:
        reasons.append("runs: at least three per-boot records required")
        return None
    boots: set[str] = set()
    maxima: list[int] = []
    sequences: set[int] = set()
    payloads: set[str] = set()
    environment = None
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
        from azazel_nexus.core_reserve import RESERVE_SCHEMA_V2, RESERVE_SCHEMA_V3

        required_schema = (RESERVE_SCHEMA_V3 if record.get("schema") == MIO_CAMPAIGN_SCHEMA
                           else RESERVE_SCHEMA_V2)
        if not isinstance(measurement, dict) or measurement.get("schema") != required_schema:
            errors.append("measurement: " + required_schema.removeprefix("azazel-nexus/")
                          + " required for campaign runs")
        if validate_acquisition(measurement).status is Status.REFUSED:
            errors.append("measurement: invalid probe acquisition shape")
        if isinstance(measurement, dict):
            payload = json.dumps(measurement, sort_keys=True)
            if payload in payloads:
                errors.append("identical measurement payload across runs refused")
            payloads.add(payload)
            sequence = measurement.get("run_sequence")
            if type(sequence) is not int or sequence < 1 or sequence in sequences:
                errors.append("distinct positive run_sequence required")
            else:
                sequences.add(sequence)
            current = tuple(measurement.get(k) for k in
                            ("build_commit", "kernel_release", "harness_version"))
            if environment is not None and current != environment:
                errors.append("measurement build_commit/kernel_release/harness must be consistent")
            environment = current
            if measurement.get("boot_fingerprint") != boot:
                errors.append("measurement boot differs from run")
        try:
            parsed = parse_record(json.dumps(measurement, allow_nan=False))
            errors.extend(validate_reserve(parsed).refusals)
            if parsed.profile.value != CLASS_PROFILES.get(record.get("hardware_class")):
                errors.append("measurement profile differs from campaign class")
            if parsed.harness_version != record.get("harness_version"):
                errors.append("measurement harness differs from campaign")
            if parsed.host_digest != record.get("dut_fingerprint"):
                errors.append("measurement host differs from campaign DUT HMAC")
            if parsed.observed_maximum_mib is not None:
                maxima.append(parsed.observed_maximum_mib)
        except (ReserveRefused, ValueError, TypeError):
            errors.append("measurement: malformed or unsupported core-reserve record")
        if _verification(run, manifest, errors) is not Status.ATTESTED:
            errors.append(
                "every campaign run must be externally attested; shape_only refused"
            )
        reasons.extend(f"runs[{index}]: {error}" for error in errors)
    if len(boots) < 3:
        reasons.append("runs: at least three distinct boot fingerprints required")
    return max(maxima, default=None)


def validate_record(
    record: object, *, bundle_directory: Path | None = None, operator_key: Path | None = None,
    bundle_files: dict | None = None, public_key: bytes | None = None
) -> Validation:
    """Validate one contract. Never trust an in-record attestation status.

    Missing verification yields diagnostic shape_only, never admissibility.
    Campaign runs must each be attested; a shape-only run refuses the campaign.
    A campaign also requires verification of the aggregate and workload notes.
    Each run and aggregate must have its canonical SHA-256 in the signed bundle.
    """
    reasons: list[str] = []
    manifest = None
    if bundle_files is not None or public_key is not None:
        from .evidence import verified_manifest_bytes

        try:
            if bundle_directory is not None or operator_key is not None:
                raise ValueError("ambiguous attestation inputs")
            manifest = verified_manifest_bytes(bundle_files, public_key=public_key)
        except (ValueError, TypeError, KeyError, OSError, RuntimeError):
            return Validation(Status.REFUSED, ("operator attestation verification failed",))
    elif bundle_directory is not None:
        try:
            checked = verified_manifest(Path(bundle_directory), operator_key=operator_key)
            if operator_key is not None:
                manifest = checked
        except (ValueError, TypeError, OSError, RuntimeError):
            return Validation(Status.REFUSED, ("operator attestation verification failed",))
    elif operator_key is not None:
        return Validation(Status.REFUSED, ("bundle directory required",))
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
        if schema in (CAMPAIGN_SCHEMA, MIO_CAMPAIGN_SCHEMA):
            if not _text(record.get("harness_version")):
                reasons.append("harness_version required")
            maximum = _campaign(record, manifest, reasons)
            if schema == MIO_CAMPAIGN_SCHEMA:
                _mio_campaign(record, reasons)
        elif schema == GATE_SCHEMA:
            _gate(record, reasons)
        elif schema == BEHAVIOUR_SCHEMA:
            _behaviour(record, reasons)
        elif schema == DRILL_SCHEMA:
            _drill(record, reasons)
        else:
            reasons.append("unsupported versioned HIL record schema")
        status = _verification(record, manifest, reasons)
    except (ValueError, TypeError, RecursionError):
        return Validation(Status.REFUSED, ("record: malformed JSON fields",))
    if reasons:
        return Validation(Status.REFUSED, tuple(dict.fromkeys(reasons)))
    return Validation(
        status, reserve_mib=maximum if status is Status.ATTESTED else None
    )


def _mio_campaign(record, reasons):
    runtime = record.get("embedding_runtime")
    fields = {"peak_rss_mib", "startup_ms", "retrieval_p50_ms", "retrieval_p95_ms",
              "runtime_binary_digest", "model_digest", "argv_digest"}
    if type(runtime) is not dict or set(runtime) != fields:
        reasons.append("embedding runtime measurement required")
        return
    for key in fields:
        value = runtime[key]
        if key.endswith("digest"):
            if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                reasons.append("runtime digest required")
        elif type(value) is not int or value < 1:
            reasons.append("positive whole runtime measurements required")
    if (type(runtime.get("retrieval_p50_ms")) is int
            and type(runtime.get("retrieval_p95_ms")) is int
            and runtime["retrieval_p50_ms"] > runtime["retrieval_p95_ms"]):
        reasons.append("runtime percentiles reversed")
