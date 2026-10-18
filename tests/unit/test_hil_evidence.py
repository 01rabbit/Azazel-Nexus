"""Synthetic text only: these tests assert confidentiality and integrity, not HIL results."""

import hashlib
import json
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from azazel_nexus.audit import canonical_event_bytes
from tools.hil_evidence import (
    DOMAIN,
    RecordRefused,
    attestation_bytes,
    bundle,
    lint,
    lint_text,
    main,
    sign,
    verify,
)


@pytest.fixture
def evidence(tmp_path):
    source = tmp_path / "synthetic-input"
    source.write_text("SYNTHETIC TEST ONLY; no measurements\n")
    root = tmp_path / "bundle"
    bundle(root, run_id="test-only", gate_ids=["HG-01", "SO-01"],
           dut_id="dut-" + "a" * 32, artifacts={"capture": source},
           operator_input={"notes": "SYNTHETIC TEST ONLY"})
    return root


@pytest.fixture
def keys(tmp_path):
    signing = SigningKey.generate()
    seed = tmp_path / "test-seed"
    public = tmp_path / "test-public"
    seed.write_text(signing.encode().hex())
    public.write_text(signing.verify_key.encode().hex())
    return signing, seed, public


def test_collect_separates_blocks_and_never_copies_sources_or_keys(evidence, keys):
    manifest = lint(evidence)
    assert manifest["B"] == {"notes": "SYNTHETIC TEST ONLY"}
    assert set(manifest["A"]) == {"artifacts"}
    reference = manifest["A"]["artifacts"]["capture"]
    assert reference == {
        "path": "artifacts/capture",
        "sha256": hashlib.sha256((evidence / "artifacts/capture").read_bytes()).hexdigest(),
    }
    assert verify(evidence) == "shape_only"
    sign(evidence, key_file=keys[1])
    assert verify(evidence) == "shape_only"
    assert verify(evidence, operator_key=keys[2]) == "attested"
    assert {p.name for p in evidence.iterdir()} == {"manifest.json", "manifest.sig", "artifacts"}
    assert not any(keys[1].read_bytes() in p.read_bytes()
                   for p in evidence.rglob("*") if p.is_file())
    assert attestation_bytes(manifest) == DOMAIN + canonical_event_bytes(manifest)


@pytest.mark.parametrize("text", [
    "02:00:00:00:00:01", "02-00-00-00-00-01", "0200.0000.0001",
    "serial: test-only", '{"serial_number": "test-only"}',
    "asset-tag=TEST-ONLY", "SN12345678", "sn12345678", "AB12CD34EF56",
    "192.0.2.1", "10.0.0.1", "127.0.0.1", "8.8.8.8",
    "2001:db8::1", "fd00::1", "address:192.0.2.1", "address:fd00::1", "fe80::1%test", "::1", "::ffff:192.0.2.1",
    "test-only.local", "test-only.example", "hostname=test-only",
    '{"note": "02\\u003a00\\u003a00\\u003a00\\u003a00\\u003a01"}',
    '{"note": "192\\u002e0\\u002e2\\u002e1"}',
    b"\xff\xfe", b"binary\0payload",
])
def test_lint_refuses_without_echoing_confidential_content(text):
    with pytest.raises(RecordRefused, match="confidentiality"):
        lint_text(text if isinstance(text, bytes) else text.encode())


def test_lint_accepts_anonymous_and_fingerprint_text():
    lint_text(json.dumps({"dut_id": "dut-" + "a" * 32,
                          "boot_fingerprint": "hmac-sha256:" + "b" * 64,
                          "notes": "SYNTHETIC TEST ONLY"}).encode())
    lint_text(b"capture.json azazel-arbiter.service azazel.slice")


@pytest.mark.parametrize("with_key", [False, True])
@pytest.mark.parametrize("mutation", ["changed", "missing", "extra", "symlink", "escape"])
def test_verify_checks_all_artifacts_even_without_trust(evidence, keys, with_key, mutation):
    sign(evidence, key_file=keys[1])
    capture = evidence / "artifacts/capture"
    if mutation == "changed":
        capture.write_text("SYNTHETIC corruption")
    elif mutation == "missing":
        capture.unlink()
    elif mutation == "extra":
        (evidence / "unlisted").write_text("SYNTHETIC")
    elif mutation == "symlink":
        capture.unlink()
        capture.symlink_to(keys[1])
    else:
        manifest = json.loads((evidence / "manifest.json").read_text())
        manifest["A"]["artifacts"]["capture"]["path"] = "../test-seed"
        (evidence / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(RecordRefused):
        verify(evidence, operator_key=keys[2] if with_key else None)


@pytest.mark.parametrize("mutation", ["wrong_key", "domain", "manifest", "signature", "missing"])
def test_signature_requires_external_trust_correct_domain_and_complete_manifest(
        evidence, keys, mutation):
    signing, seed, public = keys
    sign(evidence, key_file=seed)
    signature = evidence / "manifest.sig"
    if mutation == "wrong_key":
        public.write_text(SigningKey.generate().verify_key.encode().hex())
    elif mutation == "domain":
        signature.write_text(signing.sign(canonical_event_bytes(lint(evidence))).signature.hex())
    elif mutation == "manifest":
        manifest = lint(evidence)
        manifest["B"]["notes"] = "SYNTHETIC changed input"
        (evidence / "manifest.json").write_text(json.dumps(manifest))
    elif mutation == "signature":
        signature.write_text("00" * 64)
    else:
        signature.unlink()
    with pytest.raises((RecordRefused, OSError)):
        verify(evidence, operator_key=public)


def test_internal_key_is_never_trusted_or_used(evidence, keys):
    # Reject the resolved path too, including a link from outside the bundle.
    sign(evidence, key_file=keys[1])
    with pytest.raises(RecordRefused, match="outside bundle"):
        sign(evidence, key_file=evidence / "manifest.json")
    with pytest.raises(RecordRefused, match="outside bundle"):
        verify(evidence, operator_key=evidence / "manifest.json")


@pytest.mark.parametrize("location", ["artifact", "B", "run_id", "name"])
def test_lint_applies_to_all_inputs_and_failed_bundle_is_not_promoted(tmp_path, location):
    source = tmp_path / "source"
    source.write_text("192.0.2.1" if location == "artifact" else "SYNTHETIC")
    destination = tmp_path / "bundle"
    with pytest.raises(RecordRefused):
        bundle(destination, run_id="192.0.2.1" if location == "run_id" else "test-only",
               gate_ids=["HG-01"], dut_id="dut-" + "a" * 32,
               artifacts={"test.local" if location == "name" else "capture": source},
               operator_input={"notes": "192.0.2.1"} if location == "B" else {})
    assert not destination.exists()
    assert list(tmp_path.glob(".hil-evidence-*")) == []


def test_bundle_never_overwrites_or_traverses(evidence, tmp_path):
    for destination, name in [(evidence, "capture"), (tmp_path / "new", "../escape")]:
        with pytest.raises(RecordRefused):
            bundle(destination, run_id="test-only", gate_ids=["HG-01"],
                   dut_id="dut-" + "a" * 32, artifacts={name: tmp_path / "synthetic-input"},
                   operator_input={})
    assert not (tmp_path / "escape").exists()


def test_duplicate_json_and_unknown_manifest_fields_refused(evidence):
    manifest = evidence / "manifest.json"
    original = manifest.read_text()
    manifest.write_text(original.replace('"schema":', '"schema":"duplicate","schema":'))
    with pytest.raises(RecordRefused):
        lint(evidence)
    value = json.loads(original)
    value["operator_public_key"] = "a" * 64
    manifest.write_text(json.dumps(value))
    with pytest.raises(RecordRefused):
        lint(evidence)


def test_cli_all_commands_and_no_hardware_verdict(tmp_path, keys, capsys):
    source = tmp_path / "source"
    source.write_text("SYNTHETIC TEST ONLY")
    operator = tmp_path / "input"
    operator.write_text('{"notes":"SYNTHETIC TEST ONLY"}')
    root = tmp_path / "bundle"
    assert main(["bundle", str(root), "--run-id", "test-only", "--gate-id", "HG-01",
                 "--dut-id", "dut-" + "a" * 32, "--artifact", f"capture={source}",
                 "--operator-input", str(operator)]) == 0
    assert main(["lint", str(root)]) == 0
    assert main(["sign", str(root), "--key-file", str(keys[1])]) == 0
    assert main(["verify", str(root), "--operator-key", str(keys[2])]) == 0
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert output == [{"status": "shape_only"}] * 3 + [{"status": "attested"}]
    source.write_text("192.0.2.1")
    with pytest.raises(SystemExit) as failure:
        main(["bundle", str(tmp_path / "refused"), "--run-id", "test-only",
              "--gate-id", "HG-01", "--dut-id", "dut-" + "a" * 32,
              "--artifact", f"capture={source}", "--operator-input", str(operator)])
    assert failure.value.code == 2
    err = capsys.readouterr().err
    assert "192.0.2.1" not in err
    assert err == "evidence refused (RecordRefused: confidentiality: raw IP address refused)\n"


@pytest.mark.parametrize("payload", ['{"notes":NaN}', '{"notes":Infinity}'])
def test_non_json_numbers_refused(evidence, payload):
    manifest = lint(evidence)
    text = json.dumps(manifest).replace(json.dumps(manifest["B"]), payload)
    (evidence / "manifest.json").write_text(text)
    with pytest.raises(RecordRefused):
        lint(evidence)


def test_manifest_key_order_does_not_change_signature(evidence, keys):
    sign(evidence, key_file=keys[1])
    manifest = lint(evidence)
    (evidence / "manifest.json").write_text(json.dumps(dict(reversed(list(manifest.items()))),
                                                     indent=4))
    assert verify(evidence, operator_key=keys[2]) == "attested"


def test_multiple_artifacts_are_checked(evidence, keys, tmp_path):
    root = tmp_path / "multiple"
    source = evidence / "artifacts/capture"
    bundle(root, run_id="test-only", gate_ids=["HG-01"], dut_id="dut-" + "a" * 32,
           artifacts={"capture.json": source, "other": source}, operator_input={})
    sign(root, key_file=keys[1])
    for capture in (root / "artifacts").iterdir():
        original = capture.read_bytes()
        capture.write_text("SYNTHETIC corruption")
        with pytest.raises(RecordRefused, match="digest differs"):
            verify(root, operator_key=keys[2])
        capture.write_bytes(original)


@pytest.mark.parametrize("dut_id,expected", [
    ("not-a-dut", "anonymous dut id required"),
    ("dut-" + "a" * 31, "anonymous dut id required"),
])
def test_cli_prints_the_fixed_reason_not_the_input(tmp_path, capsys, dut_id, expected):
    source = tmp_path / "source"
    source.write_text("SYNTHETIC TEST ONLY")
    operator = tmp_path / "input"
    operator.write_text('{"notes":"SYNTHETIC TEST ONLY"}')
    with pytest.raises(SystemExit) as failure:
        main(["bundle", str(tmp_path / "b"), "--run-id", "test-only", "--gate-id", "HG-01",
              "--dut-id", dut_id, "--artifact", f"capture={source}",
              "--operator-input", str(operator)])
    assert failure.value.code == 2
    err = capsys.readouterr().err
    assert err == f"evidence refused (RecordRefused: {expected})\n"
    assert dut_id not in err and str(tmp_path) not in err


def test_cli_never_prints_an_unfixed_message(tmp_path, capsys):
    # An OSError carries a path; only its type is shown.
    with pytest.raises(SystemExit):
        main(["lint", str(tmp_path / "private-path-name")])
    err = capsys.readouterr().err
    assert "private-path-name" not in err
    assert err.startswith("evidence refused (")


def test_fixed_reasons_come_only_from_literals():
    """Every message that can become a printed reason is a literal in source."""
    import ast

    for relative, names in (("src/azazel_nexus/hil_records/evidence.py", {"require", "refusal"}),
                            ("tools/hil_evidence.py", {"require", "refusal"}),
                            ("src/azazel_nexus/hil_records/confidentiality.py",
                             {"require", "ConfidentialityRefused"})):
        tree = ast.parse((ROOT / relative).read_text())
        # The forwarding calls inside `require` itself pass its parameter on.
        forwarding = {id(call) for function in ast.walk(tree)
                      if isinstance(function, ast.FunctionDef) and function.name == "require"
                      for call in ast.walk(function) if isinstance(call, ast.Call)}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in names) or id(node) in forwarding:
                continue
            message = node.args[-1] if node.func.id != "require" else node.args[1]
            if isinstance(message, ast.Constant):
                assert isinstance(message.value, str), (relative, node.lineno)
            elif isinstance(message, ast.JoinedStr):
                # The only formatted value is the fixed pattern label `reason`.
                assert all(isinstance(v, ast.Constant) or (
                    isinstance(v, ast.FormattedValue) and isinstance(v.value, ast.Name)
                    and v.value.id == "reason") for v in message.values), (relative, node.lineno)
            else:
                # `refusal(str(exc))` in lint_text forwards a ConfidentialityRefused,
                # whose own messages are checked above.
                assert relative.endswith("evidence.py") and ast.unparse(message) == "str(exc)", (
                    relative, node.lineno)
