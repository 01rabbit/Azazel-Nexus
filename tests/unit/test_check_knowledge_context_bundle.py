"""tools/check_knowledge_context_bundle.py: read-only pre-check; synthetic material only."""

import hashlib
import importlib.util
import os
import socket
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "src"))
sys.path.insert(0, str(ROOT / "tests" / "real_process"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from _knowledge_context_bundle_fixture import DEFECTS, build_bundle  # noqa: E402
from azazel_nexus_runtime import knowledge_context_config as cfg, runtime_paths  # noqa: E402
from tls.pins import PINS  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "check_knowledge_context_bundle", ROOT / "tools" / "check_knowledge_context_bundle.py")
tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tool)

TLS = ROOT / "tests" / "fixtures" / "tls"
NOW = "2026-11-10T00:00:00+00:00"


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)
    monkeypatch.setattr(socket.socket, "connect",
                        lambda *a, **k: pytest.fail("pre-check communicated"))
    return tmp_path


def build(root, **kw):
    return build_bundle(
        root / "etc/azazel/knowledge-context/commissioning", peer_id="az04-test",
        peer_address="192.0.2.10", peer_host="fetch.azazel.test", peer_port=443,
        certificate_pin=PINS["server-fetch"],
        peer_signing_key=SigningKey(bytes(range(32, 64))),
        registry_signing_key=SigningKey(bytes(range(32))),
        ca=TLS / "trusted-ca.crt", client_cert=TLS / "client.crt",
        client_key=TLS / "client.key", **kw)


def run(directory, capsys, *extra):
    code = tool.main([str(directory), *extra])
    return code, capsys.readouterr().out


def test_valid_bundle_commissioned_and_values_not_printed(root, capsys):
    d = build(root)
    code, out = run(d, capsys, "--now", NOW)
    assert code == 0 and out.startswith("commissioned")
    assert "registry_version: 1" in out and "max_ttl_seconds: 60" in out
    assert "client_cert_not_after: 2126-08-28T10:15:54+00:00" in out
    assert "warning: ttl_above_knowledge_ceiling" in out
    for secret in ("az04-test", "knowledge-context-client", PINS["server-fetch"][7:]):
        assert secret not in out


def test_ttl_at_ceiling_has_no_warning(root, capsys):
    code, out = run(build(root, max_ttl_seconds=30), capsys, "--now", NOW)
    assert code == 0 and "warning" not in out


@pytest.mark.parametrize("defect,word", [
    ("enabled_false", "enabled_not_true"), ("bad_signature", "registry_signature"),
    ("expired_registry", "registry_expired"), ("bad_ttl", "ttl_invalid"),
    ("short_alias", "alias_short"), ("wrong_identity", "identity_mismatch"),
    ("missing_value", "manifest_schema"),
])
def test_loader_refusals_are_reported_with_fixed_words(root, capsys, defect, word):
    assert defect in DEFECTS
    code, out = run(build(root, defect=defect), capsys, "--now", NOW)
    assert (code, out.strip()) == (1, f"refused: {word}")


def test_structural_refusals(root, capsys):
    d = build(root)
    os.chmod(d / "alias.key", 0o604)
    assert run(d, capsys, "--now", NOW) == (1, "refused: perm_unsafe\n")
    os.chmod(d / "alias.key", 0o600)
    (d / "stray").write_text("x")
    assert run(d, capsys, "--now", NOW) == (1, "refused: bundle_unexpected\n")
    (d / "stray").unlink()
    (d / "ca.pem").unlink()
    assert run(d, capsys, "--now", NOW) == (1, "refused: bundle_incomplete\n")


def test_absent_directory_is_refused(root, capsys):
    assert run(root / "etc/azazel/none", capsys) == (1, "refused: absent\n")


def test_expired_client_certificate_refused(root, capsys):
    code, out = run(build(root), capsys, "--now", "2127-01-01T00:00:00+00:00")
    # the registry (2099) expires first; the loader code wins
    assert (code, out.strip()) == (1, "refused: registry_expired")
    d = build(root, expires_at="2200-01-01T00:00:00+00:00")
    code, out = run(d, capsys, "--now", "2127-01-01T00:00:00+00:00")
    assert code == 1 and "refused: client_cert_expired" in out


def test_usage_errors(root, capsys, monkeypatch):
    assert tool.main(["--now", "yesterday"]) == 2
    assert tool.main(["--now", "2026-11-10T00:00:00"]) == 2
    assert tool.main(["--bogus"]) == 2
    assert tool.main(["--pin", "x", "--now", NOW]) == 2
    monkeypatch.setenv("AZAZEL_ROOT", "")
    assert tool.main([str(root)]) == 2


def test_root_caller_is_refused(root, capsys, monkeypatch):
    d = build(root)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert tool.main([str(d), "--now", NOW]) == 2
    assert "not root" in capsys.readouterr().err


def test_pin_shows_both_forms_matching_independent_values(root, capsys):
    code, out = (tool.main(["--pin", str(TLS / "client.crt")]), capsys.readouterr().out)
    der = tool.certificate_der((TLS / "client.crt").read_bytes())
    assert code == 0
    assert PINS["client"] in out
    assert hashlib.sha256(der).hexdigest() in out
    assert tool.main(["--pin", str(TLS / "server-fetch.crt")]) == 0
    assert PINS["server-fetch"] in capsys.readouterr().out
    assert tool.main(["--pin", str(root / "missing")]) == 1


def test_default_loader_signature_unchanged():
    import inspect
    assert str(inspect.signature(cfg.load_commissioning)) == "(*, now: 'str | None' = None) -> 'CommissioningResult'"


def test_test_only_examples_are_marked_and_use_documentation_addresses():
    import json
    import re
    d = ROOT / "docs" / "examples" / "knowledge-context-test-only"
    assert "Test-only, not for production" in (d / "README.md").read_text()
    manifest = json.loads((d / "manifest.json").read_text())
    assert manifest["enabled"] is False and set(manifest) == cfg._MANIFEST_KEYS
    assert json.loads((d / "observation-query.json").read_text())["rule"] == "technique-set/1"
    registry = json.loads((d / "registry.skeleton.json").read_text())
    assert registry["peers"][0]["endpoint"]["provider_id"] == manifest["peer_id"]
    assert not list(d.glob("*.conf"))
    texts = "".join(p.read_text() for p in d.iterdir())
    for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", texts):
        assert ip.startswith("192.0.2."), ip


def test_usage_errors_do_not_echo_arguments(root, capsys):
    mark = "MARKER-SHOULD-NOT-APPEAR"
    for argv in (["/a", f"/{mark}"], [f"--{mark}"], ["--now"], ["--pin", "x", f"/{mark}"]):
        assert tool.main(argv) == 2
        seen = capsys.readouterr()
        assert mark not in seen.out + seen.err
