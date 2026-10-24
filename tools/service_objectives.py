"""Versioned Issue #17 records; validation never supplies hardware evidence."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.degradation import FailureMode
from azazel_nexus.signature import SignatureRefused, parse_public_key, verify_detached

SCHEMA = "azazel-nexus/service-objective/v1"
PATHS = (
    "evidence_records",
    "evaluation_outcomes",
    "enforcement_lease_records",
    "audit_chain",
)
DEPENDENCIES = (
    "knowledge_node_absent",
    "deception_node_absent",
    "remote_path_unreachable",
)
CASES = ("healthy",) + tuple(
    f"{d}/{m.value}" for d in DEPENDENCIES for m in FailureMode
)
EXCLUSIONS = ("advisory_reason_entries", "advisory_source_generation")
RULES = {
    "SO-01": "every elapsed_ns <= 120000000000; report maximum",
    "SO-06": "zero divergence and zero dropped records across all four paths",
    "SO-10": "every attributed_frames == 0 over at least 600000000000 ns",
}


class RecordRefused(ValueError):
    """Malformed or unsupported evidence is never a pass."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordRefused(message)


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def integer(value: Any) -> bool:
    return type(value) is int and value >= 0


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_event_bytes(value)).hexdigest()


def artifact(value: Any) -> None:
    require(isinstance(value, dict), "capture artifact required")
    require(nonempty(value.get("path")), "capture artifact path required")
    require(
        bool(re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", "")))),
        "capture artifact sha256 required",
    )


def compare_paths(healthy: dict, degraded: dict) -> dict:
    """Only two explicitly named fields on each stream record may differ."""
    result = {}
    for name in PATHS:
        normalized = []
        counts = []
        for run in (healthy, degraded):
            require(
                isinstance(run, dict) and set(run) == set(PATHS),
                "all four paths required",
            )
            records = run[name]
            require(isinstance(records, list), "path records must be lists")
            require(
                bool(records) or run is degraded or name != "audit_chain",
                "healthy audit must contain records",
            )
            require(
                all(isinstance(item, dict) for item in records),
                "path records must be objects",
            )
            counts.append(len(records))
            normalized.append(
                [
                    {k: v for k, v in item.items() if k not in EXCLUSIONS}
                    for item in records
                ]
            )
        result[name] = {
            "healthy_count": counts[0],
            "fault_count": counts[1],
            "dropped_records": max(0, counts[0] - counts[1]),
            "healthy_sha256": digest(normalized[0]),
            "fault_sha256": digest(normalized[1]),
            "byte_identical": canonical_event_bytes(normalized[0])
            == canonical_event_bytes(normalized[1]),
        }
    return result


ATTESTATION_DOMAIN = b"azazel-nexus/service-objective-attestation/v1\0"


def attestation_bytes(record: dict) -> bytes:
    """Domain + canonical complete record, excluding only detached attestation."""
    return ATTESTATION_DOMAIN + canonical_event_bytes(
        {k: v for k, v in record.items() if k != "operator_attestation"}
    )


def referenced_artifacts(record: dict):
    """Check every named artifact reference, including optional/extra captures."""
    names = {
        "manifest",
        "capture_artifact",
        "durable_audit_artifact",
        "commissioning_artifact",
    }

    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in names:
                    artifact(child)
                    yield child
                else:
                    yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)

    yield from walk(record)


def replay_samples(bundle: dict) -> list[dict]:
    """Evaluate captured observations; acquisition is in the in-repo adapter."""
    require(
        bundle.get("schema") == "azazel-nexus/so06-input/v3",
        "unsupported replay schema",
    )
    require(nonempty(bundle.get("evidence_source")), "evidence source required")
    scenarios = bundle["scenarios"]
    require(isinstance(scenarios, list) and bool(scenarios), "scenarios required")
    samples = []
    seen = set()
    for scenario in scenarios:
        require(
            nonempty(scenario["id"]) and scenario["id"] not in seen,
            "unique scenario id required",
        )
        seen.add(scenario["id"])
        require(bool(scenario["inputs"]), "fixed inputs required")
        runs = scenario["runs"]
        require(set(runs) == set(CASES), "healthy plus all 15 fault runs required")
        undriven = runs["healthy"]["not_driven"]
        require(
            isinstance(undriven, dict)
            and set(undriven) <= set(PATHS) - {"audit_chain"},
            "only Edge-dependent paths may be not_driven; audit is always driven",
        )
        for name in PATHS:
            if name not in undriven:
                require(
                    bool(runs["healthy"]["paths"][name]),
                    "a driven path must carry records in the healthy run",
                )
        for run in runs.values():
            require(
                run["not_driven"] == undriven
                and all(nonempty(reason) for reason in run["not_driven"].values()),
                "every run must declare the same not_driven paths, with reasons",
            )
            require(
                all(run["paths"][name] == [] for name in undriven),
                "a not_driven path carries no records",
            )
            require(
                run["inputs_sha256"] == digest(scenario["inputs"]),
                "input digest differs",
            )
            require(
                integer(run["start_ns"])
                and integer(run["end_ns"])
                and run["end_ns"] >= run["start_ns"],
                "invalid replay interval",
            )
        for case in CASES[1:]:
            run = runs[case]
            paths = compare_paths(runs["healthy"]["paths"], run["paths"])
            observed = run["observed"]
            samples.append(
                {
                    "scenario": scenario["id"],
                    "case": case,
                    "start_ns": run["start_ns"],
                    "end_ns": run["end_ns"],
                    "healthy_start_ns": runs["healthy"]["start_ns"],
                    "healthy_end_ns": runs["healthy"]["end_ns"],
                    "inputs_sha256": digest(scenario["inputs"]),
                    "paths": paths,
                    "core_retained": observed["core_retained"],
                    "disposition": observed["disposition"],
                    "expected_behaviour": observed["expected_behaviour"],
                    "continues": observed["continues"],
                    "not_driven": run["not_driven"],
                    "passed": not run["not_driven"]
                    and observed["expected_behaviour"]
                    and all(
                        p["byte_identical"] and p["dropped_records"] == 0
                        for p in paths.values()
                    ),
                }
            )
    return samples


def validate_record(
    record: dict,
    *,
    operator_key: Path | None = None,
    artifact_root: Path | None = None,
) -> Literal["shape_only", "attested"]:
    """Shape is never authority. Attestation proves attribution, not physics.

    Software records are shape-only too unless operator-attested. The replay
    harness reports an execution result separately, never a shape-only verdict.
    """
    try:
        _validate(record)
        if operator_key is None:
            return "shape_only"
        try:
            signature = bytes.fromhex(record["operator_attestation"]["signature"])
        except ValueError as exc:
            raise RecordRefused("malformed attestation signature") from exc
        key = parse_public_key(operator_key.read_text().strip())
        require(
            verify_detached(
                public_key=key, message=attestation_bytes(record), signature=signature
            ),
            "operator attestation refused",
        )
        if record["objective_id"] != "SO-06":
            root = artifact_root or Path.cwd()
            for reference in referenced_artifacts(record):
                path = root / reference["path"]
                require(
                    path.resolve().is_relative_to(root.resolve()),
                    f"artifact path leaves the artifact root: {reference['path']}",
                )
                require(path.is_file(), f"artifact missing: {path}")
                require(
                    hashlib.sha256(path.read_bytes()).hexdigest()
                    == reference["sha256"],
                    f"artifact digest differs: {path}",
                )
        return "attested"
    except (KeyError, TypeError, AttributeError, SignatureRefused, OSError) as exc:
        raise RecordRefused(f"missing or malformed record field: {exc}") from exc


def _validate(record: dict) -> None:
    require(
        isinstance(record, dict) and record.get("schema") == SCHEMA,
        "unsupported record schema",
    )
    objective = record.get("objective_id")
    require(objective in RULES, "unknown objective")
    require(record.get("owner_repository") == "Azazel-Nexus", "wrong owner")
    require(
        bool(
            re.fullmatch(
                r"[0-9a-f]{40}|[0-9a-f]{64}", str(record.get("owner_commit", ""))
            )
        ),
        "full owning commit required",
    )
    require(record.get("pass_rule") == RULES[objective], "target/pass rule changed")
    config = record["configuration"]
    require(
        isinstance(config, dict) and nonempty(config.get("product_configuration")),
        "configuration required",
    )
    samples = record["samples"]
    require(isinstance(samples, list) and bool(samples), "samples required")
    if objective == "SO-06":
        require(
            record.get("class") == "software"
            and record.get("clock") == "CLOCK_MONOTONIC",
            "SO-06 is a replay property",
        )
        require(
            config.get("scope") == "nexus-in-repo-adapter",
            "consumer scope required",
        )
        expected = replay_samples(config["replay_inputs"])
        require(
            canonical_event_bytes(samples) == canonical_event_bytes(expected),
            "replay results do not reproduce",
        )
        passed = all(sample["passed"] for sample in expected)
        summary = {
            "comparisons": len(expected),
            "failed_comparisons": sum(not s["passed"] for s in expected),
        }
    else:
        require(
            record.get("class") == "hardware-only" and record.get("synthetic") is False,
            "hardware-only: synthetic/software evidence refused",
        )
        require(
            record.get("clock") == "CLOCK_MONOTONIC",
            "hardware monotonic clock required",
        )
        for key in (
            "hardware_class",
            "dut_id",
            "os",
            "driver",
            "operator",
            "exercise_id",
        ):
            require(nonempty(config.get(key)), f"hardware capture field {key} required")
        require(config.get("physical_hardware") is True, "physical hardware required")
        capture = record["hardware_capture"]
        require(capture.get("synthetic") is False, "synthetic hardware capture refused")
        artifact(capture["manifest"])
        required_count = 10 if objective == "SO-01" else 3
        require(
            len(samples) == required_count,
            f"exactly {required_count} samples per hardware class required",
        )
        durations = []
        for index, sample in enumerate(samples, 1):
            require(
                type(sample["sequence"]) is int and sample["sequence"] == index,
                "consecutive samples required",
            )
            require(
                integer(sample["start_ns"])
                and integer(sample["end_ns"])
                and sample["end_ns"] >= sample["start_ns"],
                "invalid monotonic interval",
            )
            durations.append(sample["end_ns"] - sample["start_ns"])
            artifact(sample["capture_artifact"])
        if objective == "SO-01":
            require(
                capture.get("clock_host") == config["dut_id"],
                "SO-01 clock must be on DUT",
            )
            require(
                nonempty(config.get("coldest_cache_state")),
                "coldest cache state required",
            )
            for sample in samples:
                require(sample.get("cold_boot") is True, "cold boot required")
                require(
                    sample.get("start_event") == "unlock-unit-active-volume-usable"
                    and sample.get("end_event") == "probe-decision-and-audit-durable",
                    "SO-01 event definitions required",
                )
                require(
                    nonempty(sample.get("boot_id"))
                    and nonempty(sample.get("probe_decision_id")),
                    "boot/probe correlation required",
                )
                artifact(sample["durable_audit_artifact"])
            require(
                len({s["boot_id"] for s in samples}) == 10,
                "distinct cold boots required",
            )
            passed = all(d <= 120_000_000_000 for d in durations)
            summary = {"maximum_elapsed_ns": max(durations)}
        else:
            identity = config["commissioned_composite_identifier"]
            require(
                set(identity)
                <= {"bus_path", "permanent_mac", "pci_id", "usb_id", "serial"},
                "kernel names are not composite identities",
            )
            for key in ("bus_path", "permanent_mac"):
                require(nonempty(identity.get(key)), f"composite {key} required")
            require(
                bool(
                    re.fullmatch(
                        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
                        identity["permanent_mac"],
                    )
                ),
                "permanent MAC required",
            )
            require(
                any(nonempty(identity.get(k)) for k in ("pci_id", "usb_id", "serial")),
                "PCI/USB identity or serial required",
            )
            require(
                config.get("commissioned_role") == "observation",
                "commissioned observation role required",
            )
            artifact(config["commissioning_artifact"])
            require(
                nonempty(capture.get("device_id"))
                and capture["device_id"] != config["dut_id"],
                "independent capture device required; DUT measurements prove nothing",
            )
            require(
                capture.get("clock_host") == capture["device_id"]
                and capture.get("same_physical_segment") is True,
                "independent same-segment capture clock required",
            )
            require(
                capture.get("method") in ("second-host", "tap", "switch-mirror"),
                "physical capture method required",
            )
            counts = []
            for sample, duration in zip(samples, durations):
                require(
                    duration >= 600_000_000_000, "full ten-minute interval required"
                )
                require(
                    sample.get("start_event") == "independent-capture-stress-start"
                    and sample.get("end_event") == "independent-capture-stress-stop",
                    "SO-10 capture events required",
                )
                require(
                    sample.get("stress")
                    == {
                        "link_up_down": True,
                        "ipv6_ra": True,
                        "dhcp_offer_request": True,
                        "suspend_resume": True,
                    },
                    "all stress operations required",
                )
                require(
                    integer(sample["attributed_frames"]),
                    "nonnegative frame count required",
                )
                counts.append(sample["attributed_frames"])
            passed = all(count == 0 for count in counts)
            summary = {"attributed_frames": counts}
    require(record.get("evaluation") == summary, "evaluated pass rule summary differs")
    if objective == "SO-06":
        require(
            record.get("execution_result") == ("PASS" if passed else "FAIL"),
            "execution result differs",
        )
        require("verdict" not in record, "unattested software verdict refused")
    else:
        require(
            record.get("claimed_verdict") == ("passed" if passed else "failed"),
            "verdict differs from evaluated pass rule",
        )
        require(
            "verdict" not in record, "use claimed_verdict until attested validation"
        )


def main(argv: list[str] | None = None) -> int:
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("--operator-key", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args(argv)
    try:
        record = json.loads(args.record.read_text())
        status = validate_record(
            record,
            operator_key=args.operator_key,
            artifact_root=args.artifact_root or args.record.parent,
        )
        result = {"status": status}
        if status == "attested":
            result["verdict"] = record.get(
                "claimed_verdict", record.get("execution_result")
            )
        print(json.dumps(result))
    except (ValueError, OSError) as exc:
        parser.exit(2, f"record refused: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
