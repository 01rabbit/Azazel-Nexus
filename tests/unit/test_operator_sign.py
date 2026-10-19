"""The off-host commissioning signer produces what the node verifies, or nothing."""

import hashlib
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from azazel_nexus.operator_trust import ApprovalPurpose, approval_message  # noqa: E402
from tools import operator_sign  # noqa: E402

PAYLOAD = b'{"schema":"synthetic"}'


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


def test_other_purposes_are_not_offered(tmp_path, key):
    # Activation, bootstrap and model admission have their own ceremonies.
    with pytest.raises(SystemExit):
        run(tmp_path, key, **{"--purpose": "activation"})
    assert not (tmp_path / "out.sig").exists()
    assert set(operator_sign.PURPOSES) == {"commissioning", "commissioning-proposal"}


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

