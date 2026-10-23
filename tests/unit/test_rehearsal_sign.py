"""The test-only rehearsal signer of wiring §8 (`tests/support/rehearsal_sign.py`).

It makes exactly the two approvals the production signer refuses, only for
an operator label starting with `rehearsal-`, and it is outside the package
and the installed tree: nothing in the product names it and the offline
bundle excludes `tests/`.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation_approval_v2 import ObserveBaselineContext
from azazel_nexus.activation_approval_v3 import (
    ActivationApprovalPolicyV3,
    activation_approval_v3_payload,
    verify_activation_approval_v3,
)
from azazel_nexus.operator_trust import ApprovalRefused, OperatorTrust

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "support"))
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
import rehearsal_sign  # noqa: E402

D = "sha256:" + "a" * 64
CONTEXT = ObserveBaselineContext(
    node_digest=D, generation=3, generation_digest=D, commissioning_digest=D,
    commissioning_evidence_binding="hmac-sha256:" + "c" * 64, policy_digest=D,
    security_epoch=2)
UNITS = ("azazel-decoy-netd.service", "azazel-decoy-nsd.service", "azazel-decoyd.service",
         "azazel-mio-entryd.service")
SCOPE = "sha256:" + "5" * 64


def _payload(operator="rehearsal-op"):
    return activation_approval_v3_payload(
        context=CONTEXT, approval_id="approval-1", operator=operator, approval_seq=5,
        units=UNITS, granted_at="2026-10-20T00:00:00Z", expires_at="2026-10-21T00:00:00Z",
        exposure_scope_digest=SCOPE, exposure_prefix_count=1, exposure_ingress_count=1)


def _verify(key, payload, signature, operator="rehearsal-op"):
    return verify_activation_approval_v3(
        trust=OperatorTrust({operator: bytes(key.verify_key)}), expected=CONTEXT,
        policy=ActivationApprovalPolicyV3(authorized_operators=frozenset({operator}),
                                          max_lease_seconds=72 * 3600,
                                          unit_scope=frozenset(UNITS)),
        payload=payload, signature=signature, now="2026-10-20T00:00:00Z",
        security_epoch_floor=0, approval_seq_floor=0)


def test_v3_under_activation_is_refused_by_the_node():
    key = SigningKey.generate()
    payload, signature = rehearsal_sign.rehearsal_sign(
        kind="v3-under-activation", payload=_payload(), seed=bytes(key),
        expect_public=bytes(key.verify_key).hex())
    assert payload == _payload()
    with pytest.raises(ApprovalRefused, match="approval_v3_signature_refused"):
        _verify(key, payload, signature)


def test_v3_other_scope_verifies_and_names_another_digest():
    key = SigningKey.generate()
    payload, signature = rehearsal_sign.rehearsal_sign(
        kind="v3-other-scope", payload=_payload(), seed=bytes(key),
        expect_public=bytes(key.verify_key).hex())
    approved = _verify(key, payload, signature)
    assert approved.exposure_scope_digest != SCOPE
    assert json.loads(payload)["exposure_scope_digest"] == approved.exposure_scope_digest


@pytest.mark.parametrize("operator", ["operator-a", "rehearsal", "xrehearsal-op"])
def test_it_refuses_an_operator_outside_the_rehearsal(operator):
    key = SigningKey.generate()
    with pytest.raises(rehearsal_sign.RehearsalSignRefused, match="rehearsal"):
        rehearsal_sign.rehearsal_sign(kind="v3-other-scope", payload=_payload(operator),
                                      seed=bytes(key), expect_public=bytes(key.verify_key).hex())


def test_it_refuses_anything_but_canonical_v3_and_another_key():
    key = SigningKey.generate()
    for payload in (b'{"schema":"x"}', _payload().replace(b'"units"', b'"units" ')):
        with pytest.raises(rehearsal_sign.RehearsalSignRefused, match="canonical v3"):
            rehearsal_sign.rehearsal_sign(kind="v3-under-activation", payload=payload,
                                          seed=bytes(key),
                                          expect_public=bytes(key.verify_key).hex())
    with pytest.raises(rehearsal_sign.RehearsalSignRefused, match="public key"):
        rehearsal_sign.rehearsal_sign(kind="v3-under-activation", payload=_payload(),
                                      seed=bytes(key), expect_public="0" * 64)


def test_the_command_writes_create_only_files(tmp_path, capsys):
    key = SigningKey.generate()
    seed = tmp_path / "seed"
    seed.write_text(bytes(key).hex())
    seed.chmod(0o600)
    request = tmp_path / "request.json"
    request.write_bytes(_payload())
    args = ["--kind", "v3-other-scope", "--payload", str(request), "--seed", str(seed),
            "--expect-public", bytes(key.verify_key).hex(),
            "--out", str(tmp_path / "other.sig"), "--out-payload", str(tmp_path / "other.json")]
    assert rehearsal_sign.main(args) == 0
    other = (tmp_path / "other.json").read_bytes()
    assert f"payload_sha256: {hashlib.sha256(other).hexdigest()}" in capsys.readouterr().out
    _verify(key, other, (tmp_path / "other.sig").read_bytes())
    assert rehearsal_sign.main(args) == 1  # create-only


def test_it_is_outside_the_product_and_the_bundle():
    from tools.build_offline_bundle import EXCLUDED_PARTS

    assert "tests" in EXCLUDED_PARTS
    for base in (REPO / "src", REPO / "runtime" / "src", REPO / "tools", REPO / "packaging"):
        for path in base.rglob("*"):
            if path.is_file():
                assert "rehearsal_sign" not in path.read_text(encoding="utf-8",
                                                              errors="replace"), path
