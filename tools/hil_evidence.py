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

from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.hil_records.evidence import (
    DOMAIN,
    SAFE_NAME,
    SCHEMA,
    RecordRefused,
    _external_key,
    _json,
    _shape,
    attestation_bytes,
    lint,
    lint_text,
    record_in_manifest,
    require,
    verified_manifest,
    verify,
)

__all__ = [
    "DOMAIN", "RecordRefused", "attestation_bytes", "bundle", "lint",
    "lint_text", "main", "record_attestation", "sign", "verify",
]


def record_attestation(root: Path, record: dict, *, operator_key: Path | None = None):
    """Diagnostic convenience; validate_record verifies bundles directly."""
    from azazel_nexus.hil_records import Status

    manifest = verified_manifest(root, operator_key=operator_key)
    if not record_in_manifest(manifest, record):
        return Status.REFUSED
    return Status.SHAPE_ONLY if operator_key is None else Status.ATTESTED


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
        # Avoid leaking input, source paths or key material through diagnostics:
        # only a reason this package wrote as a fixed literal is printed.
        reason = getattr(exc, "fixed_reason", None)
        detail = f": {reason}" if isinstance(exc, RecordRefused) and isinstance(reason, str) else ""
        parser.exit(2, f"evidence refused ({type(exc).__name__}{detail})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
