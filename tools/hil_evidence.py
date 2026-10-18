"""Collect, lint and attest one HIL run; never generate measurements.

Policy v1 refuses ALL raw IPv4/IPv6 (including private, loopback and RFC test
ranges), MACs, serial/asset labels and serial-like uppercase mixed tokens,
FQDNs with alphabetic suffixes, and labelled bare hostnames.
Known artifact extensions and systemd unit suffixes are treated as filenames,
not hostnames; use anonymous names for those files too. Opaque binary
artifacts are refused: only UTF-8 text can be inspected. Anonymous DUT IDs use
``dut-`` plus 32 lowercase hex digits; fingerprints use hmac-sha256:<64 lowercase hex>.
This conservative pattern lint is not proof that arbitrary prose is anonymous:
operators must review it, especially unlabelled bare hostnames/identifiers.
Refusals never echo offending content. No redaction or private-range exemption.

Manifest block A is automatic (named artifacts and hashes); block B is the
operator-supplied JSON object. Signatures attest attribution/integrity, never a
hardware verdict. The detached manifest.sig covers DOMAIN + canonical manifest
bytes, following service_objectives.attestation_bytes with a separate domain.
Keys are external: sign accepts a 32-byte Ed25519 seed in lowercase hex, verify
accepts the existing public-key format. PyNaCl is needed only to sign. Neither
key is copied into the bundle. Use ``python -m tools.hil_evidence --help``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Literal

from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.hil_records.confidentiality import ConfidentialityRefused
from azazel_nexus.hil_records.confidentiality import lint_text as lint_export
from azazel_nexus.hil_records.contracts import ANONYMOUS_ID
from azazel_nexus.signature import SignatureRefused, parse_public_key, verify_detached
from tools.service_objectives import RecordRefused, artifact, require

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
        artifact(reference)
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


def bundle(destination: Path, *, run_id: str, gate_ids: list[str], dut_id: str,
           artifacts: dict[str, Path], operator_input: dict) -> dict:
    """Stage inspected copies, then promote into a new directory; never overwrite."""
    require(not destination.exists(), "destination already exists")
    manifest = {"schema": SCHEMA, "run_id": run_id, "gate_ids": gate_ids,
                "attestation_ref": "hil-evidence:" + run_id, "dut_id": dut_id, "A": {"artifacts": {}}, "B": operator_input}
    # Validate names before using them as filesystem paths.
    for name in artifacts:
        require(SAFE_NAME.fullmatch(name) is not None and name not in {".", ".."},
                "invalid artifact name")
        manifest["A"]["artifacts"][name] = {
            "path": f"artifacts/{name}", "sha256": "0" * 64,
        }
    _shape(manifest)
    with tempfile.TemporaryDirectory(prefix=".hil-evidence-", dir=destination.parent) as temporary:
        stage = Path(temporary) / "bundle"
        (stage / "artifacts").mkdir(parents=True)
        for name, source in artifacts.items():
            require(source.is_file() and not source.is_symlink(), "regular source required")
            payload = source.read_bytes()
            lint_text(payload)
            (stage / "artifacts" / name).write_bytes(payload)
            manifest["A"]["artifacts"][name]["sha256"] = hashlib.sha256(payload).hexdigest()
        (stage / "manifest.json").write_bytes(canonical_event_bytes(manifest))
        lint(stage)
        require(not destination.exists(), "destination already exists")
        stage.rename(destination)
    return manifest


def sign(root: Path, *, key_file: Path) -> None:
    """Write only a detached signature; operator supplies an external seed file."""
    from nacl.signing import SigningKey

    _external_key(root, key_file)
    manifest = lint(root)
    require(not (root / "manifest.sig").exists(), "signature already exists")
    seed = key_file.read_text().strip()
    require(re.fullmatch(r"[0-9a-f]{64}", seed) is not None, "invalid signing seed")
    signature = SigningKey(bytes.fromhex(seed)).sign(attestation_bytes(manifest)).signature
    with (root / "manifest.sig").open("x", encoding="ascii") as output:
        output.write(signature.hex() + "\n")


def verify(root: Path, *, operator_key: Path | None = None) -> Literal["shape_only", "attested"]:
    """Integrity without an external trust anchor is always shape_only."""
    manifest = lint(root)
    if operator_key is None:
        return "shape_only"
    _external_key(root, operator_key)
    try:
        key = parse_public_key(operator_key.read_text().strip())
        signature = bytes.fromhex((root / "manifest.sig").read_text().strip())
        require(verify_detached(public_key=key, message=attestation_bytes(manifest),
                                signature=signature), "operator attestation refused")
    except (SignatureRefused, ValueError, OSError) as exc:
        raise RecordRefused("operator attestation refused") from exc
    return "attested"


def record_attestation(root: Path, record: dict, *, operator_key: Path | None = None):
    """Bind C's external verification to an exact signed artifact, never a claim.

    Use a closure for validate_record's attestation callback. Each run and the
    aggregate must be present as a complete JSON artifact. Reference and DUT
    checks alone do not authenticate a record. No key means SHAPE_ONLY.
    """
    from azazel_nexus.hil_records import Status

    manifest = lint(root)
    if (record.get("operator_attestation_ref") != manifest["attestation_ref"]
            or record.get("dut_id") != manifest["dut_id"]):
        return Status.REFUSED
    expected = canonical_event_bytes(record)
    for reference in manifest["A"]["artifacts"].values():
        try:
            candidate = _json((root / reference["path"]).read_bytes())
        except ValueError:
            continue
        if canonical_event_bytes(candidate) == expected:
            return Status(verify(root, operator_key=operator_key))
    return Status.REFUSED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collect = commands.add_parser("bundle")
    collect.add_argument("directory", type=Path)
    collect.add_argument("--run-id", required=True)
    collect.add_argument("--gate-id", action="append", required=True)
    collect.add_argument("--dut-id", required=True)
    collect.add_argument("--artifact", action="append", required=True, metavar="NAME=PATH")
    collect.add_argument("--operator-input", type=Path, required=True, help="block B JSON object")
    for command in ("lint", "sign", "verify"):
        sub = commands.add_parser(command)
        sub.add_argument("directory", type=Path)
        if command == "sign":
            sub.add_argument("--key-file", type=Path, required=True)
        elif command == "verify":
            sub.add_argument("--operator-key", type=Path)
    args = parser.parse_args(argv)
    try:
        status = "shape_only"
        if args.command == "bundle":
            artifacts = {}
            for item in args.artifact:
                name, separator, path = item.partition("=")
                require(bool(separator) and bool(path) and name not in artifacts,
                        "unique NAME=PATH artifacts required")
                artifacts[name] = Path(path)
            bundle(args.directory, run_id=args.run_id, gate_ids=args.gate_id,
                   dut_id=args.dut_id, artifacts=artifacts,
                   operator_input=_json(args.operator_input.read_bytes()))
        elif args.command == "lint":
            lint(args.directory)
        elif args.command == "sign":
            sign(args.directory, key_file=args.key_file)
        else:
            status = verify(args.directory, operator_key=args.operator_key)
        print(json.dumps({"status": status}))
    except (ValueError, OSError, ImportError) as exc:
        # Avoid leaking input, source paths or key material through diagnostics.
        parser.exit(2, f"evidence refused ({type(exc).__name__})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
