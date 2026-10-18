"""Off-host helper for the M.I.O. embedding admission runbook.

Signs nothing, reads no private key or seed, writes nothing and grants nothing.
Run it from a reviewed checkout with ``azazel_nexus`` importable, for example
``PYTHONPATH=src python3 -m tools.mio_admission_helper --help``.

``argv``          print the exact embedding argv the admission loader derives for
                  a catalogued model digest, its ``argv_digest`` and the x86_64
                  runtime pin, so the HIL measurement and the campaign record use
                  the same values the loader will recompute.
``check-wrapper`` check an ``embedding.approval`` wrapper exactly as the loader
                  decodes it (canonical JSON, canonical base64 and lowercase
                  signature hex) and verify its Ed25519 signature over the
                  operator-approval transcript with the approver's enrolled
                  public key (64 lowercase hex). It prints the payload and
                  message SHA-256 for comparison with the request output.

A wrapper that passes here can still be refused on the node: every node
binding is recomputed there. See docs/hil-runbooks/mio-admission.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from dataclasses import replace
from pathlib import Path

from azazel_nexus import model_admission as admission
from azazel_nexus.model_runtime import (
    LLAMA_RUNTIME_DIGESTS,
    LLAMA_RUNTIME_ID,
    RUNTIMES,
    llama_server_record,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    approval_message,
)
from azazel_nexus.signature import SignatureRefused, parse_public_key, verify_detached

#: The fixed paths the admission loader binds into the approved argv
#: (runtime/src/azazel_nexus_runtime/model_admission_evidence.py).
MODEL_STORE = Path("/var/lib/azazel/models/store")
EMBEDDING_SOCKET = Path("/var/lib/azazel/mio/embedding.sock")
ARCHITECTURE = "x86_64"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def embedding_argv(model_digest: str) -> list[str]:
    """The exact argv bound by ``settings.argv_digest`` for this model digest."""
    if type(model_digest) is not str or _DIGEST.fullmatch(model_digest) is None:
        raise ApprovalRefused("MALFORMED")
    binary = replace(RUNTIMES[LLAMA_RUNTIME_ID], digest=LLAMA_RUNTIME_DIGESTS[ARCHITECTURE])
    record = llama_server_record(
        binary,
        # artifact_filename(): digest hex plus the entry format; embedding is gguf.
        model_path=MODEL_STORE / (model_digest.removeprefix("sha256:") + ".gguf"),
        socket_path=EMBEDDING_SOCKET,
        ctx=admission.EMBEDDING_CTX,
        threads=admission.EMBEDDING_THREADS,
        max_tokens=admission.EMBEDDING_MAX_TOKENS,
        embedding=True,
    )
    return list(record.argv)


def argv_summary(model_digest: str) -> dict:
    argv = embedding_argv(model_digest)
    return {
        "argv": argv,
        "argv_digest": admission.digest(admission.canonical(argv)),
        "runtime_binary_digest": LLAMA_RUNTIME_DIGESTS[ARCHITECTURE],
        "model_digest": model_digest,
    }


def check_wrapper(raw: bytes, *, public_key_hex: str) -> dict:
    """Mirror the loader's wrapper decoding, then verify the signature."""
    wrapper = admission.decode(raw)
    if (set(wrapper) != {"schema", "payload_b64", "signature_hex"}
            or wrapper["schema"] != admission.FILE_SCHEMA
            or type(wrapper["payload_b64"]) is not str
            or type(wrapper["signature_hex"]) is not str):
        raise ApprovalRefused("MALFORMED")
    try:
        payload = base64.b64decode(wrapper["payload_b64"], validate=True)
        signature = bytes.fromhex(wrapper["signature_hex"])
    except ValueError as exc:
        raise ApprovalRefused("MALFORMED") from exc
    if (base64.b64encode(payload).decode() != wrapper["payload_b64"]
            or signature.hex() != wrapper["signature_hex"] or len(signature) != 64):
        raise ApprovalRefused("MALFORMED")
    doc = admission.decode(payload)
    if doc.get("schema") != admission.SCHEMA or doc.get("purpose") != (
            ApprovalPurpose.LOCAL_MODEL_ADMISSION.value):
        raise ApprovalRefused("MALFORMED")
    try:
        public_key = parse_public_key(public_key_hex)
    except SignatureRefused as exc:
        raise ApprovalRefused("MALFORMED") from exc
    message = approval_message(ApprovalPurpose.LOCAL_MODEL_ADMISSION, payload)
    if not verify_detached(public_key=public_key, message=message, signature=signature):
        raise ApprovalRefused("SIGNATURE_REFUSED")
    approver = admission.digest(public_key)
    key, reserve = doc.get("approval_key", {}), doc.get("reserve", {})
    if type(key) is not dict or key.get("fingerprint") != approver:
        raise ApprovalRefused("KEY_ROTATED")
    if type(reserve) is not dict or reserve.get("attestation_key_fingerprint") == approver:
        raise ApprovalRefused("ATTESTER_IS_APPROVER")
    return {
        "payload_sha256": admission.digest(payload),
        "message_sha256": admission.digest(message),
        "approval_key_fingerprint": approver,
        "approval_id": doc.get("approval_id"),
        "operator": doc.get("operator"),
        "issued_at": doc.get("issued_at"),
        "expires_at": doc.get("expires_at"),
        "signature": "verified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mio_admission_helper", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    exact = commands.add_parser("argv", help="exact embedding argv and digests; runs nothing")
    exact.add_argument("--model-digest", required=True, help="sha256:<64 lowercase hex>")
    check = commands.add_parser("check-wrapper", help="verify an embedding.approval wrapper")
    check.add_argument("wrapper", type=Path)
    check.add_argument("--public-key", required=True,
                       help="approver's enrolled Ed25519 public key, 64 lowercase hex")
    args = parser.parse_args(argv)
    try:
        if args.command == "argv":
            result = argv_summary(args.model_digest)
        else:
            raw = args.wrapper.read_bytes()
            if len(raw) > 100000:
                raise ApprovalRefused("MALFORMED")
            result = check_wrapper(raw, public_key_hex=args.public_key)
    except ApprovalRefused as error:
        symbol = str(error) if re.fullmatch(r"[A-Z][A-Z0-9_]*", str(error)) else "REFUSED"
        print("refused: " + symbol)
        return 2
    except (OSError, ValueError):
        print("refused: UNREADABLE")
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    print("signs nothing, authorizes nothing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
