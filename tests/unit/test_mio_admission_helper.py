"""The off-host runbook helper mirrors the loader and signs nothing.

Keys here are generated per test with PyNaCl and discarded; nothing is a real
operator key and nothing is hardware evidence.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from azazel_nexus import model_admission as admission
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    approval_message,
)
from tools import mio_admission_helper as helper

REPO = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "ab" * 32


def test_argv_uses_the_loader_paths_and_fixed_settings():
    loader = (REPO / "runtime/src/azazel_nexus_runtime/model_admission_evidence.py").read_text()
    assert f'"{helper.MODEL_STORE}' in loader
    assert f'Path("{helper.EMBEDDING_SOCKET}")' in loader
    for setting in ("ctx=admission.EMBEDDING_CTX", "threads=admission.EMBEDDING_THREADS",
                    "max_tokens=admission.EMBEDDING_MAX_TOKENS", "embedding=True"):
        assert setting in loader
    argv = helper.embedding_argv(DIGEST)
    assert argv[:3] == ["/usr/libexec/azazel/llama-server", "-m",
                        "/var/lib/azazel/models/store/" + "ab" * 32 + ".gguf"]
    assert argv[argv.index("-c") + 1] == "2048" and argv[argv.index("-t") + 1] == "2"
    assert "--embedding" in argv
    summary = helper.argv_summary(DIGEST)
    assert summary["argv_digest"] == admission.digest(admission.canonical(argv))
    assert summary["runtime_binary_digest"].startswith("sha256:")


@pytest.mark.parametrize("value", ["", "sha256:AB", "md5:" + "a" * 32, None])
def test_argv_refuses_a_malformed_digest(value):
    with pytest.raises(ApprovalRefused, match="MALFORMED"):
        helper.embedding_argv(value)


def _wrapper(signer, *, attester_fingerprint=None, payload_doc=None):
    approver = admission.digest(bytes(signer.verify_key))
    doc = payload_doc or {
        "schema": admission.SCHEMA, "purpose": "local-model-admission",
        "approval_key": {"fingerprint": approver, "security_epoch": 1},
        "reserve": {"attestation_key_fingerprint": attester_fingerprint or "sha256:" + "c" * 64},
        "approval_id": "test-only", "operator": "approver",
        "issued_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-02T00:00:00Z"}
    payload = admission.canonical(doc)
    signature = signer.sign(approval_message(ApprovalPurpose.LOCAL_MODEL_ADMISSION, payload)).signature
    return admission.canonical({"schema": admission.FILE_SCHEMA,
                                "payload_b64": base64.b64encode(payload).decode(),
                                "signature_hex": signature.hex()}), payload


def test_check_wrapper_verifies_and_reports_the_request_hashes():
    from nacl.signing import SigningKey

    signer = SigningKey.generate()
    raw, payload = _wrapper(signer)
    result = helper.check_wrapper(raw, public_key_hex=bytes(signer.verify_key).hex())
    assert result["signature"] == "verified"
    assert result["payload_sha256"] == admission.digest(payload)
    assert result["message_sha256"] == admission.digest(
        approval_message(ApprovalPurpose.LOCAL_MODEL_ADMISSION, payload))


def test_check_wrapper_refusals():
    from nacl.signing import SigningKey

    signer, other = SigningKey.generate(), SigningKey.generate()
    public = bytes(signer.verify_key).hex()
    raw, _ = _wrapper(signer)
    with pytest.raises(ApprovalRefused, match="MALFORMED"):
        helper.check_wrapper(raw + b"\n", public_key_hex=public)
    doc = json.loads(raw)
    with pytest.raises(ApprovalRefused, match="MALFORMED"):
        helper.check_wrapper(admission.canonical({**doc, "signature_hex": doc["signature_hex"].upper()}),
                             public_key_hex=public)
    with pytest.raises(ApprovalRefused, match="SIGNATURE_REFUSED"):
        helper.check_wrapper(raw, public_key_hex=bytes(other.verify_key).hex())
    same, _ = _wrapper(signer, attester_fingerprint=admission.digest(bytes(signer.verify_key)))
    with pytest.raises(ApprovalRefused, match="ATTESTER_IS_APPROVER"):
        helper.check_wrapper(same, public_key_hex=public)
    rotated, _ = _wrapper(other)
    with pytest.raises(ApprovalRefused, match="SIGNATURE_REFUSED"):
        helper.check_wrapper(rotated, public_key_hex=public)


def test_main_prints_symbols_only(tmp_path, capsys):
    path = tmp_path / "embedding.approval"
    path.write_bytes(b"{}")
    assert helper.main(["check-wrapper", str(path), "--public-key", "00" * 32]) == 2
    assert capsys.readouterr().out == "refused: MALFORMED\n"
    assert helper.main(["argv", "--model-digest", DIGEST]) == 0
    assert "signs nothing, authorizes nothing" in capsys.readouterr().out


def test_the_helper_cannot_sign_or_read_keys():
    source = (REPO / "tools" / "mio_admission_helper.py").read_text()
    for forbidden in ("nacl", "SigningKey", "pkeyutl", "open(", "write_", ".seed"):
        assert forbidden not in source, forbidden
