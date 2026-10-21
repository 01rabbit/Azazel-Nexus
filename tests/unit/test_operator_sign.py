"""The off-host signer produces what the node verifies, or nothing."""

import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from azazel_nexus.activation_approval import (  # noqa: E402
    ActivationContext,
    approval_payload,
)
from azazel_nexus.activation_approval_v2 import (  # noqa: E402
    ActivationApprovalPolicy,
    ObserveBaselineContext,
    observe_baseline_payload,
    verify_observe_baseline_approval,
)
from azazel_nexus.operator_trust import (  # noqa: E402
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)
from tools import operator_sign  # noqa: E402

PAYLOAD = b'{"schema":"synthetic"}'

DIGEST = "sha256:" + "a" * 64
BINDING = "hmac-sha256:" + "c" * 64
START = "2026-10-20T00:00:00Z"
END = "2026-10-21T00:00:00Z"
UNITS = ("azazel-incident-explaind.service", "azazel-edge-intaked.service")
CONTEXT = ObserveBaselineContext(
    node_digest=DIGEST, generation=3, generation_digest=DIGEST,
    commissioning_digest=DIGEST, commissioning_evidence_binding=BINDING,
    policy_digest=DIGEST, security_epoch=2,
)
V2 = observe_baseline_payload(context=CONTEXT, approval_id="approval-1", operator="operator-a",
                              approval_seq=5, units=UNITS, granted_at=START, expires_at=END)
# Not a SUPPORTING or EDGE_BASELINE unit; a v2 approval cannot name it.
OUT_OF_TIER_UNIT = "azazel-not-a-core-unit.service"


@pytest.fixture
def key(tmp_path):
    signing = SigningKey.generate()
    seed = tmp_path / "seed"
    seed.write_text(bytes(signing).hex() + "\n")
    seed.chmod(0o600)
    payload = tmp_path / "payload.json"
    payload.write_bytes(PAYLOAD)
    return signing, seed, payload


def run(tmp_path, key, **overrides):
    signing, seed, payload = key
    arguments = {
        "--purpose": "commissioning-proposal",
        "--payload": str(payload),
        "--expect-payload-sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "--expect-public": bytes(signing.verify_key).hex(),
        "--seed": str(seed),
        "--out": str(tmp_path / "out.sig"),
        **overrides,
    }
    return operator_sign.main([item for pair in arguments.items() for item in pair])


@pytest.mark.parametrize("purpose,enum", [
    ("commissioning", ApprovalPurpose.COMMISSIONING),
    ("commissioning-proposal", ApprovalPurpose.COMMISSIONING_PROPOSAL),
])
def test_signature_verifies_over_the_node_transcript(tmp_path, key, purpose, enum):
    assert run(tmp_path, key, **{"--purpose": purpose}) == 0
    signature = (tmp_path / "out.sig").read_bytes()
    assert len(signature) == 64
    key[0].verify_key.verify(approval_message(enum, PAYLOAD), signature)
    assert (tmp_path / "out.sig").stat().st_mode & 0o777 == 0o600


def test_raw_seed_is_accepted(tmp_path, key):
    signing, seed, payload = key
    seed.write_bytes(bytes(signing))
    assert run(tmp_path, (signing, seed, payload)) == 0


@pytest.mark.parametrize("override", [
    {"--expect-payload-sha256": "0" * 64},
    {"--expect-public": "0" * 64},
])
def test_mismatch_writes_nothing(tmp_path, key, override):
    assert run(tmp_path, key, **override) == 1
    assert not (tmp_path / "out.sig").exists()


@pytest.mark.parametrize("purpose", ["bootstrap", "local-model-admission", "activation-v1"])
def test_other_purposes_are_not_offered(tmp_path, key, purpose):
    # Bootstrap, v1 activation and model admission have their own ceremonies.
    with pytest.raises(SystemExit):
        run(tmp_path, key, **{"--purpose": purpose})
    assert not (tmp_path / "out.sig").exists()
    assert operator_sign.PURPOSES == {
        "activation": ApprovalPurpose.ACTIVATION,
        "activation-epoch-raise": ApprovalPurpose.ACTIVATION_EPOCH_RAISE,
        "commissioning": ApprovalPurpose.COMMISSIONING,
        "commissioning-proposal": ApprovalPurpose.COMMISSIONING_PROPOSAL,
    }


def run_activation(tmp_path, key, payload_bytes, **overrides):
    key[2].write_bytes(payload_bytes)
    return run(tmp_path, key, **{
        "--purpose": "activation",
        "--expect-payload-sha256": hashlib.sha256(payload_bytes).hexdigest(),
        **overrides,
    })


def _verify(signing, signature, expected=CONTEXT):
    policy = ActivationApprovalPolicy(
        authorized_operators=frozenset({"operator-a"}), max_lease_seconds=24 * 3600,
        unit_scope=frozenset(UNITS),
    )
    return verify_observe_baseline_approval(
        trust=OperatorTrust({"operator-a": bytes(signing.verify_key)}), expected=expected,
        policy=policy, payload=V2, signature=signature, now=START,
        security_epoch_floor=2, approval_seq_floor=5,
    )


def test_activation_signature_verifies_on_the_node_path(tmp_path, key, capsys):
    signing = key[0]
    assert run_activation(tmp_path, key, V2) == 0
    signature = (tmp_path / "out.sig").read_bytes()
    assert _verify(signing, signature).lease.units == frozenset(UNITS)
    # Only for the context it names, and not reusable as a commissioning signature.
    with pytest.raises(ApprovalRefused):
        _verify(signing, signature, replace(CONTEXT, generation=4))
    with pytest.raises(BadSignatureError):
        signing.verify_key.verify(approval_message(ApprovalPurpose.COMMISSIONING, V2), signature)
    lines = capsys.readouterr().out.splitlines()
    for line in ("purpose: activation", "operator: operator-a", "approval_id: approval-1",
                 "units: " + ",".join(sorted(UNITS)), "generation: 3", "security_epoch: 2",
                 "approval_seq: 5", f"granted_at: {START}", f"expires_at: {END}",
                 "validity_seconds: 86400"):
        assert line in lines
    # The commissioning evidence binding is checked, never printed.
    assert not any("c" * 64 in line or "binding" in line for line in lines)


def _v1():
    context = ActivationContext(DIGEST, "11111111-1111-1111-1111-111111111111", 3,
                                DIGEST, DIGEST, DIGEST, DIGEST, DIGEST, 2,
                                commissioning_evidence_binding=BINDING)
    return approval_payload(context=context, operator="operator-a", granted_at=START,
                            expires_at="2026-10-20T00:10:00Z")


def _variant(**changes):
    document = json.loads(V2) | changes
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@pytest.mark.parametrize("payload_bytes", [
    pytest.param(_v1(), id="v1"),
    pytest.param(PAYLOAD, id="arbitrary-json"),
    pytest.param(b"\xff\xfe not json", id="binary"),
    pytest.param(json.dumps(json.loads(V2), sort_keys=True).encode(), id="spaced"),
    pytest.param(json.dumps(dict(reversed(json.loads(V2).items())),
                            separators=(",", ":")).encode(), id="unsorted-keys"),
    pytest.param(V2 + b"\n", id="trailing-newline"),
    pytest.param(_variant(units=sorted(UNITS, reverse=True)), id="unsorted-units"),
    pytest.param(_variant(units=[OUT_OF_TIER_UNIT]), id="out-of-tier-unit"),
    pytest.param(_variant(approval_seq=True), id="bool-seq"),
    pytest.param(_variant(schema="azazel-nexus/activation-approval/v1"), id="v1-schema"),
    pytest.param(_variant(boot_id="11111111-1111-1111-1111-111111111111"), id="extra-field"),
    pytest.param(_variant(expires_at=START), id="empty-window"),
    pytest.param(_variant(expires_at="2026-10-23T00:00:01Z"), id="over-ceiling"),
    pytest.param(V2.replace(b'"approval_seq":5', b'"approval_seq":5,"approval_seq":5'),
                 id="duplicate-field"),
])
def test_activation_refuses_anything_but_canonical_v2(tmp_path, key, payload_bytes, capsys):
    assert run_activation(tmp_path, key, payload_bytes) == 1
    assert not (tmp_path / "out.sig").exists()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "operator-a" not in captured.err and DIGEST not in captured.err


@pytest.mark.parametrize("unit", ["azazel-watchdog.service", "azazel-auditd.service",
                                  "azazel-commissiond.service", "azazel-model-fetchd.service"])
def test_activation_refuses_a_unit_outside_the_node_allowlist(tmp_path, key, unit, capsys):
    """#251 L-4: a canonical v2 payload naming a unit no node can grant is not signed."""
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    assert unit not in ACTIVATION_UNIT_ALLOWLIST
    payload_bytes = observe_baseline_payload(
        context=CONTEXT, approval_id="approval-1", operator="operator-a", approval_seq=5,
        units=sorted((*UNITS, unit)), granted_at=START, expires_at=END)
    assert run_activation(tmp_path, key, payload_bytes) == 1
    assert not (tmp_path / "out.sig").exists()
    captured = capsys.readouterr()
    assert "outside the activation allowlist" in captured.err
    assert captured.out == ""


def test_activation_signs_every_allowlisted_unit(tmp_path, key):
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    payload_bytes = observe_baseline_payload(
        context=CONTEXT, approval_id="approval-1", operator="operator-a", approval_seq=5,
        units=sorted(ACTIVATION_UNIT_ALLOWLIST), granted_at=START, expires_at=END)
    assert run_activation(tmp_path, key, payload_bytes) == 0


def test_activation_ceiling_is_inclusive(tmp_path, key):
    payload_bytes = _variant(expires_at="2026-10-23T00:00:00Z")
    assert run_activation(tmp_path, key, payload_bytes) == 0


def test_activation_wrong_sha_confirmation_refuses(tmp_path, key, capsys):
    assert run_activation(tmp_path, key, V2, **{
        "--expect-payload-sha256": hashlib.sha256(_v1()).hexdigest(),
    }) == 1
    assert not (tmp_path / "out.sig").exists()
    assert "SHA-256 does not match" in capsys.readouterr().err


def test_activation_wrong_public_key_refuses(tmp_path, key):
    other = bytes(SigningKey.generate().verify_key).hex()
    assert run_activation(tmp_path, key, V2, **{"--expect-public": other}) == 1
    assert not (tmp_path / "out.sig").exists()


def test_activation_never_writes_or_prints_seed_material(tmp_path, key, capsys):
    signing, seed, _ = key
    seed_hex = bytes(signing).hex()
    before = {path.name for path in tmp_path.iterdir()}
    assert run_activation(tmp_path, key, V2) == 0
    assert {path.name for path in tmp_path.iterdir()} == before | {"out.sig"}
    assert seed.read_text().strip() == seed_hex
    captured = capsys.readouterr()
    for text in (captured.out, captured.err):
        assert seed_hex not in text.lower()
    for path in tmp_path.iterdir():
        if path != seed:
            content = path.read_bytes()
            assert bytes(signing) not in content and seed_hex.encode() not in content


def test_existing_output_is_not_overwritten(tmp_path, key):
    (tmp_path / "out.sig").write_bytes(b"keep")
    assert run(tmp_path, key) == 1
    assert (tmp_path / "out.sig").read_bytes() == b"keep"


def test_malformed_seed_is_refused_without_echo(tmp_path, key, capsys):
    signing, seed, payload = key
    seed.write_text("not-a-seed-" + "x" * 40)
    assert run(tmp_path, (signing, seed, payload)) == 1
    assert "not-a-seed" not in capsys.readouterr().err
    assert not (tmp_path / "out.sig").exists()



@pytest.mark.parametrize("mode", [0o640, 0o604])
def test_seed_readable_by_others_is_refused(tmp_path, key, mode):
    key[1].chmod(mode)
    assert run(tmp_path, key) == 1
    assert not (tmp_path / "out.sig").exists()


def test_seed_symlink_is_refused(tmp_path, key):
    signing, seed, payload = key
    link = tmp_path / "seed-link"
    link.symlink_to(seed)
    assert run(tmp_path, (signing, link, payload)) == 1
    assert not (tmp_path / "out.sig").exists()


# -- activation-epoch-raise (#251, design §11) ---------------------------------


def _epoch_payload(to_epoch=3):
    from azazel_nexus.activation_epoch import EpochRaise, encode_epoch_raise
    return encode_epoch_raise(EpochRaise("operator-a", DIGEST, "sha256:" + "b" * 64, 2,
                                         to_epoch))


def run_epoch(tmp_path, key, payload_bytes):
    key[2].write_bytes(payload_bytes)
    return run(tmp_path, key, **{
        "--purpose": "activation-epoch-raise",
        "--expect-payload-sha256": hashlib.sha256(payload_bytes).hexdigest(),
    })


def test_epoch_raise_signature_verifies_only_under_its_own_purpose(tmp_path, key, capsys):
    from azazel_nexus.activation_epoch import decode_epoch_raise
    payload = _epoch_payload()
    assert run_epoch(tmp_path, key, payload) == 0
    signature = (tmp_path / "out.sig").read_bytes()
    key[0].verify_key.verify(approval_message(ApprovalPurpose.ACTIVATION_EPOCH_RAISE,
                                              payload), signature)
    with pytest.raises(BadSignatureError):
        key[0].verify_key.verify(approval_message(ApprovalPurpose.ACTIVATION, payload),
                                 signature)
    lines = capsys.readouterr().out.splitlines()
    for line in ("purpose: activation-epoch-raise", "operator: operator-a",
                 "security_epoch: 2 -> 3", f"node_digest: {DIGEST}"):
        assert line in lines
    assert decode_epoch_raise(payload).to_epoch == 3


@pytest.mark.parametrize("payload_bytes", [
    pytest.param(V2, id="activation-approval"),
    pytest.param(PAYLOAD, id="arbitrary-json"),
    pytest.param(_epoch_payload() + b"\n", id="trailing-newline"),
    pytest.param(_epoch_payload().replace(b'"to_epoch":3', b'"to_epoch":2'), id="no-raise"),
    pytest.param(_epoch_payload().replace(b'"to_epoch":3', b'"to_epoch":1'), id="lower"),
])
def test_epoch_raise_refuses_anything_but_a_canonical_raise(tmp_path, key, payload_bytes):
    assert run_epoch(tmp_path, key, payload_bytes) == 1
    assert not (tmp_path / "out.sig").exists()


def test_activation_purpose_refuses_an_epoch_raise_payload(tmp_path, key):
    assert run_activation(tmp_path, key, _epoch_payload()) == 1
    assert not (tmp_path / "out.sig").exists()
