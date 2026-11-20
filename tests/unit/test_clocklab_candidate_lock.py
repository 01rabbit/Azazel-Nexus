"""The lab clock candidate is pinned by wheel hash in its own file (ADR-0011)."""
import hashlib
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "packaging/offline/lab"
HASH = "9f9926bcb03ec50ae6feac2185041c07cb4b83a1cb28df7e68ff5fb102317e6e"


def test_the_lab_lock_pins_one_wheel_by_hash():
    text = (LAB / "requirements-clocklab-candidate.lock").read_text(encoding="utf-8")
    assert re.findall(r"(?m)^azazel-fabric==([^ ]+) \\$", text) == ["0.10.1.dev0"]
    assert re.findall(r"--hash=sha256:([0-9a-f]{64})", text) == [HASH]
    assert "a4fa5535d3d0a0c9ed2694ea15b4b474ed587aa1" in text


def test_the_candidate_is_absent_from_every_stable_path():
    stable = [ROOT / "pyproject.toml", ROOT / "uv.lock", ROOT / "tools/build_wheelhouse.py",
              ROOT / "packaging/offline/requirements-aarch64-cp313.lock",
              ROOT / "packaging/offline/requirements-x86_64-cp313.lock"]
    for path in stable:
        text = path.read_text(encoding="utf-8")
        assert HASH not in text and "a4fa553" not in text and "0.10.1.dev0" not in text, path


def test_the_installer_refuses_a_wheel_with_another_hash(tmp_path):
    (tmp_path / "azazel_fabric-0.10.1.dev0-py3-none-any.whl").write_bytes(b"not the candidate")
    assert hashlib.sha256(b"not the candidate").hexdigest() != HASH
    result = subprocess.run([str(LAB / "install-clocklab-candidate.sh"), str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode == 1 and "refused" in result.stderr
