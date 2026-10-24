"""The first-enrollment procedure in the consumer document runs against the code (#93).

docs/knowledge-lite-consumer.md §11 gives the order a fresh node takes to reach
Knowledge Lite `available`, with the exact library calls for the two steps that
have no shipped entrypoint. These tests take the calls, the anchor documents
and the paths from the document itself and run them, in order, on a temporary
root. A document that drifts from the code fails here rather than on a node.

Owners and modes are not checked: these tests run as one user. The repin step
goes through the production `RepinConfirmation` and `production_repin` with the
runtime root relocated, as `test_runtime_repin_integration.py` does; the
socket, the CLI's terminal and systemd are not exercised.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import sys
import tarfile
from pathlib import Path

import pytest
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.repin_confirmation import (
    ANCHOR_FILENAME,
    REASONS,
    RepinConfirmation,
)
from nacl.signing import SigningKey

from azazel_nexus.layout import create_layout, spec_for
from azazel_nexus.lite_import import CommissionedLite, status_summary

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "knowledge-lite-consumer.md"
CONTRACT = ROOT / "contract" / "azazel-knowledge-lite"
AS_OF = "2026-09-21T00:00:00Z"
DIGEST = "sha256:" + "c" * 64
PRINCIPAL = PrincipalPolicy(operator_gid=123, service_uids=frozenset()).classify(0, 0, 42)
LITE_TRUST = "/var/lib/azazel/lite-trust"
KNOWLEDGE = "/var/lib/azazel/knowledge"


def _section() -> str:
    text = DOC.read_text(encoding="utf-8")
    start = text.index("## 11. First enrollment")
    return text[start:text.index("\n## ", start + 1)]


def _steps() -> dict[int, str]:
    parts = re.split(r"^### Step (\d+):", _section(), flags=re.M)
    return {int(number): body for number, body in zip(parts[1::2], parts[2::2])}


def _blocks(text: str, language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", text, flags=re.S)


def _python(step: str) -> str:
    """The program a documented `python -I -c '...'` runs."""

    (program,) = re.findall(r"python -I -c '\n(.*?)\n'", step, flags=re.S)
    return program


def _relocate(text: str, root: Path) -> str:
    return text.replace("/var/lib/azazel/", f"{root}/var/lib/azazel/")


def _run(program: str, root: Path, *argv: str) -> int:
    saved = sys.argv
    sys.argv = ["-c", *argv]
    try:
        exec(compile(_relocate(program, root), "<doc>", "exec"), {"__name__": "__main__"})
    except SystemExit as exit_:
        return int(exit_.code or 0)
    finally:
        sys.argv = saved
    return 0


def _bundle(key: SigningKey, key_id: str) -> bytes:
    """The producer's pinned fixture, re-signed under a key made for this test."""

    with tarfile.open(CONTRACT / "lite.tar.gz", "r:gz") as archive:
        members = {e.name: archive.extractfile(e).read() for e in archive if e.isfile()}
    signature = key.sign(members["manifest.json"]).signature.hex()
    members["manifest.sig"] = f"{key_id}:{signature}\n".encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _reason(root: Path) -> str:
    return status_summary(root=root / KNOWLEDGE.lstrip("/"),
                          trust_root=root / LITE_TRUST.lstrip("/"),
                          query_as_of=AS_OF)["reason_code"]


def test_the_steps_are_the_eight_in_the_table() -> None:
    assert sorted(_steps()) == list(range(1, 9))
    table = re.findall(r"^\| (\d) \|", _section(), flags=re.M)
    assert table == [str(n) for n in range(1, 9)]


def test_the_documented_sequence_reaches_available(tmp_path, monkeypatch) -> None:
    steps = _steps()
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    create_layout(tmp_path)
    bundle_key, revoker = SigningKey.generate(), SigningKey.generate()
    bundle_hex = bytes(bundle_key.verify_key).hex()
    revoker_hex = bytes(revoker.verify_key).hex()
    reasons = [_reason(tmp_path)]

    # Step 2: one anchors.toml, written at both roots the document names.
    (anchors,) = _blocks(steps[2], "toml")
    anchors = anchors.replace("<bundle public key hex>", bundle_hex)
    key_id = re.search(r'^"([^"]+)" = ', anchors, flags=re.M).group(1)
    targets = re.findall(r"anchors\.toml (/\S+/trust/anchors\.toml)", steps[2])
    assert targets == [f"{LITE_TRUST}/trust/anchors.toml", f"{KNOWLEDGE}/trust/anchors.toml"]
    for target in targets:
        path = Path(_relocate(target, tmp_path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(anchors)
    assert str(CommissionedLite(Path(KNOWLEDGE)).anchors_path) == targets[1]

    # Step 3: the root-run pin, exactly as printed.
    assert _run(_python(steps[3]), tmp_path, bundle_hex, DIGEST, AS_OF) == 0
    trust_json = tmp_path / LITE_TRUST.lstrip("/") / "trust.json"
    assert trust_json.is_file()

    # Step 4: the mode the document sets (owners need root and are not checked).
    (mode,) = re.findall(r"chmod (0\d{3}) " + re.escape(f"{LITE_TRUST}/trust.json"), steps[4])
    trust_json.chmod(int(mode, 8))
    reasons.append(_reason(tmp_path))

    # Step 5: the documented anchor document, through the production repin path.
    (document,) = _blocks(steps[5], "json")
    document = (document.replace("<bundle public key hex>", bundle_hex)
                .replace("<revocation public key hex>", revoker_hex))
    (target,) = re.findall(r"repin-anchor\.json (/etc/azazel/commissioning/\S+)", steps[5])
    assert Path(target).name == ANCHOR_FILENAME
    anchor = tmp_path / target.lstrip("/")
    anchor.write_text(document)
    (reason,) = re.findall(r"az-nexus-commission trust-repin --reason (\w+)", steps[5])
    assert reason in REASONS
    confirmation = RepinConfirmation(commissioning_dir=anchor.parent,
                                     snapshot_dir=runtime_paths.state_dir() / "commission",
                                     now=lambda: AS_OF)
    challenge = confirmation.challenge(PRINCIPAL, reason, ANCHOR_FILENAME)
    outcome = confirmation.confirm(PRINCIPAL, challenge["nonce"], challenge["confirmation_words"])
    assert outcome == {"promoted": True, "generation": 1}
    trust_root = tmp_path / LITE_TRUST.lstrip("/")
    for name in ("trust-current", "trust-generations/1.json", "trust-generations/1.revocation.json"):
        assert f"`{name}`" in steps[5]
        assert (trust_root / name).is_file()
    reasons.append(_reason(tmp_path))

    # Step 6: the inbox the document names, and the entry id is the file's SHA-256.
    (destination,) = re.findall(r"site-lite\.tar\.gz (/\S+)", steps[6])
    assert Path(destination).parent == CommissionedLite(Path(KNOWLEDGE)).inbox
    placed = Path(_relocate(destination, tmp_path))
    placed.parent.mkdir(parents=True, exist_ok=True)
    placed.write_bytes(_bundle(bundle_key, key_id))
    entry_id = hashlib.sha256(placed.read_bytes()).hexdigest()

    # Step 7: the store-owner import, exactly as printed.
    assert _run(_python(steps[7]), tmp_path, entry_id, AS_OF) == 0
    reasons.append(_reason(tmp_path))

    documented = re.search(
        r"reason `(\w+)` on a fresh install, `(\w+)`\s+after step 4, `(\w+)` after step 5"
        r" and `(\w+)` after step 7", _section())
    assert documented is not None
    assert reasons == list(documented.groups()) == [
        "trust_unreadable", "unverified", "no_bundle", "available"]


def test_the_installer_modes_the_document_states_are_the_declared_ones() -> None:
    step = _steps()[1]
    for path, owner, group, mode in (
        (LITE_TRUST, "azcommission", "azknowledge", 0o2750),
        (KNOWLEDGE, "azknowledge", "azazel-operator", 0o2750),
        ("/etc/azazel/commissioning", "root", "azcommission", 0o750),
    ):
        spec = spec_for(path)
        assert (spec.owner, spec.group, spec.mode) == (owner, group, mode)
        assert f"`{path}` as `{owner}:{group}` `{mode:04o}`" in _flat(step)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _calls(name: str, *, roots: tuple[str, ...]) -> list[Path]:
    """Files under `roots` that call an attribute or function named `name`."""

    found = []
    for root in roots:
        for path in sorted((ROOT / root).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                    if called == name:
                        found.append(path.relative_to(ROOT))
                        break
    return found


PRODUCTION = ("src", "runtime/src")


def test_no_shipped_code_pins_trust_or_imports_a_lite_bundle() -> None:
    """The two steps the document runs by hand have no shipped caller."""

    assert _calls("pin", roots=PRODUCTION) == []
    # ModelImport has its own `import_entry`; no LiteImport caller exists.
    lite_users = set(_calls("LiteImport", roots=PRODUCTION))
    importers = set(_calls("import_entry", roots=PRODUCTION))
    assert not lite_users & importers
    assert "No command calls `TrustStore.pin`" in _steps()[3]
    assert "No shipped command calls `import_entry`" in _steps()[7]


def test_commission_policy_has_no_production_caller() -> None:
    """revocation.md and §11 say only test roots use it."""

    assert _calls("commission_policy", roots=PRODUCTION) == []
    assert _calls("commission_policy", roots=("lab/src", "tools"))
    revocation = (ROOT / "docs" / "revocation.md").read_text(encoding="utf-8")
    assert "production introduction and recovery use repin exclusively" in revocation
    assert "No production code calls it" in _flat(revocation)
    assert "`revocation_policy.commission_policy` is not part of this procedure" in _steps()[5]


def test_repin_document_points_at_the_procedure() -> None:
    for name in ("trust-repin.md", "revocation.md", "knowledge-lite-trust.md"):
        text = (ROOT / "docs" / name).read_text(encoding="utf-8")
        assert "knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available" in text


@pytest.mark.parametrize("step", [3, 7])
def test_documented_programs_compile(step) -> None:
    compile(_python(_steps()[step]), "<doc>", "exec")


def test_the_fixture_key_is_not_the_documented_anchor() -> None:
    """The document uses placeholders, never the published fixture key."""

    fixture = (CONTRACT / "anchors.toml").read_text(encoding="utf-8")
    key = re.search(r'= "([0-9a-f]{64})"', fixture).group(1)
    assert key not in _section()
