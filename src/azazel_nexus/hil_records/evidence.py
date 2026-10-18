"""Shared HIL bundle integrity, confidentiality and signature verification."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Literal

from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.signature import SignatureRefused, parse_public_key, verify_detached

from .confidentiality import ConfidentialityRefused
from .confidentiality import lint_text as lint_export
from .contracts import ANONYMOUS_ID


class RecordRefused(ValueError):
    """Malformed or unauthenticated evidence."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordRefused(message)


SCHEMA = "azazel-nexus/hil-evidence/v1"
DOMAIN = b"azazel-nexus/hil-evidence/v1\0"
SAFE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")


def lint_text(payload: bytes) -> None:
    """Use the same export boundary as on-device capture."""
    try:
        lint_export(payload)
    except ConfidentialityRefused as exc:
        raise RecordRefused(str(exc)) from exc


def attestation_bytes(manifest: dict) -> bytes:
    """Sign the entire manifest, without embedded key or signature fields."""
    return DOMAIN + canonical_event_bytes(manifest)


def _json(payload: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key refused")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=unique)
        require(isinstance(value, dict), "JSON object required")
        # Reject non-JSON floating point constants before canonicalization.
        json.dumps(value, allow_nan=False)
        canonical_event_bytes(value)
        return value
    except (ValueError, UnicodeError) as exc:
        raise RecordRefused("invalid JSON object") from exc


def _shape(manifest: dict) -> None:
    require(set(manifest) == {"schema", "run_id", "attestation_ref", "gate_ids", "dut_id", "A", "B"},
            "unsupported manifest fields")
    require(manifest["schema"] == SCHEMA, "unsupported manifest schema")
    require(isinstance(manifest["run_id"], str)
            and SAFE_NAME.fullmatch(manifest["run_id"]) is not None, "invalid run id")
    require(manifest["attestation_ref"] == "hil-evidence:" + manifest["run_id"],
            "attestation reference must identify the signed run")
    gates = manifest["gate_ids"]
    require(isinstance(gates, list) and bool(gates)
            and all(isinstance(g, str) and re.fullmatch(r"(?:HG|SO)-[0-9]{2}", g)
                    for g in gates), "gate ids required")
    require(len(set(gates)) == len(gates), "duplicate gate id")
    require(isinstance(manifest["dut_id"], str)
            and ANONYMOUS_ID.fullmatch(manifest["dut_id"]) is not None,
            "anonymous dut id required")
    require(isinstance(manifest["B"], dict), "operator block B must be an object")
    automatic = manifest["A"]
    require(isinstance(automatic, dict) and set(automatic) == {"artifacts"},
            "automatic block A must contain only artifacts")
    refs = automatic["artifacts"]
    require(isinstance(refs, dict) and bool(refs), "named artifacts required")
    for name, reference in refs.items():
        require(isinstance(name, str) and SAFE_NAME.fullmatch(name) is not None,
                "invalid artifact name")
        require(isinstance(reference, dict), "artifact object required")
        require(isinstance(reference.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is not None,
                "artifact sha256 required")
        require(set(reference) == {"path", "sha256"}
                and reference["path"] == f"artifacts/{name}", "unsafe artifact path")


def _external_key(root: Path, key: Path) -> None:
    require(not key.resolve().is_relative_to(root.resolve()), "key must be outside bundle")


def lint(root: Path) -> dict:
    """Validate layout, lint every file, and recompute every artifact digest."""
    require(root.is_dir() and not root.is_symlink(), "bundle directory required")
    require(not (root / "manifest.json").is_symlink(), "symlink refused")
    manifest = _json((root / "manifest.json").read_bytes())
    _shape(manifest)
    # Inspect semantic strings, not hashes or a signature's random bytes.
    metadata = {k: v for k, v in manifest.items() if k != "A"}
    lint_text(canonical_event_bytes(metadata))
    refs = manifest["A"]["artifacts"]
    expected = {"manifest.json", "artifacts"}
    if (root / "manifest.sig").exists():
        expected.add("manifest.sig")
    require({p.name for p in root.iterdir()} == expected, "unlisted bundle entry")
    directory = root / "artifacts"
    require(directory.is_dir() and not directory.is_symlink(), "artifact directory required")
    require({p.name for p in directory.iterdir()} == set(refs), "unlisted or missing artifact")
    for name, reference in refs.items():
        path = root / reference["path"]
        require(path.is_file() and not path.is_symlink(), "regular artifact required")
        lint_text(name.encode())
        payload = path.read_bytes()
        lint_text(payload)
        require(hashlib.sha256(payload).hexdigest() == reference["sha256"],
                "artifact digest differs")
    signature = root / "manifest.sig"
    if signature.exists():
        require(signature.is_file() and not signature.is_symlink(), "regular signature required")
        require(re.fullmatch(rb"[0-9a-f]{128}\n?", signature.read_bytes()) is not None,
                "malformed detached signature")
    return manifest



def verified_manifest(root: Path, *, operator_key: Path | None = None) -> dict:
    """Check all artifacts and authenticate this manifest with an external key."""
    manifest = lint(root)
    if operator_key is None:
        return manifest
    _external_key(root, operator_key)
    try:
        key = parse_public_key(operator_key.read_text().strip())
        signature = bytes.fromhex((root / "manifest.sig").read_text().strip())
        require(verify_detached(public_key=key, message=attestation_bytes(manifest),
                                signature=signature), "operator attestation refused")
    except (SignatureRefused, ValueError, OSError) as exc:
        raise RecordRefused("operator attestation refused") from exc
    return manifest


def verify(root: Path, *, operator_key: Path | None = None) -> Literal["shape_only", "attested"]:
    verified_manifest(root, operator_key=operator_key)
    return "shape_only" if operator_key is None else "attested"


def record_in_manifest(manifest: dict, record: dict) -> bool:
    """Require the exact canonical bytes as a listed artifact, plus identity binding."""
    digest = hashlib.sha256(canonical_event_bytes(record)).hexdigest()
    return (record.get("operator_attestation_ref") == manifest["attestation_ref"]
            and record.get("dut_id") == manifest["dut_id"]
            and any(ref["sha256"] == digest for ref in manifest["A"]["artifacts"].values()))


def verified_manifest_bytes(files, *, public_key: bytes) -> dict:
    """Verify a bounded bundle snapshot using an independently enrolled key.

    The runtime supplies bytes from held, protected directory descriptors;
    this interface never opens a key path or trusts a key in the bundle.
    """
    require(type(public_key) is bytes and len(public_key) == 32, "public key required")
    require(isinstance(files, dict) and len(files) <= 128, "bounded bundle required")
    require(all(type(v) is bytes and len(v) <= 4 * 1024 * 1024 for v in files.values()),
            "bounded bundle files required")
    require(sum(map(len, files.values())) <= 16 * 1024 * 1024, "bundle too large")
    manifest = _json(files["manifest.json"])
    _shape(manifest)
    require(set(files) == {"manifest.json", "manifest.sig"} | {
        ref["path"] for ref in manifest["A"]["artifacts"].values()}, "bundle entries differ")
    lint_text(canonical_event_bytes({k: v for k, v in manifest.items() if k != "A"}))
    for name, ref in manifest["A"]["artifacts"].items():
        lint_text(name.encode())
        payload = files[ref["path"]]
        lint_text(payload)
        require(hashlib.sha256(payload).hexdigest() == ref["sha256"], "artifact digest differs")
    raw_signature = files["manifest.sig"]
    require(re.fullmatch(rb"[0-9a-f]{128}\n?", raw_signature) is not None,
            "malformed detached signature")
    require(verify_detached(public_key=public_key, message=attestation_bytes(manifest),
                            signature=bytes.fromhex(raw_signature.decode().strip())),
            "operator attestation refused")
    return manifest
