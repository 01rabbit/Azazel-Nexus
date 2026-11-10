"""Commissioning bundle loader and main() wiring; synthetic material only."""

import os
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "src"))
sys.path.insert(0, str(ROOT / "tests" / "real_process"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from _knowledge_context_bundle_fixture import DEFECTS, build_bundle  # noqa: E402
from azazel_nexus_runtime import (  # noqa: E402
    knowledge_context_config as cfg, knowledge_contextd, runtime_paths,
)
from tls.pins import PINS  # noqa: E402

TLS = ROOT / "tests" / "fixtures" / "tls"
NOW = "2026-11-10T00:00:00+00:00"


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    return tmp_path


def bundle_dir(root):
    return root / "etc/azazel/knowledge-context/commissioning"


def build(root, **kw):
    return build_bundle(
        bundle_dir(root), peer_id="az04-test", peer_address="127.0.0.1",
        peer_host="fetch.azazel.test", peer_port=443,
        certificate_pin=PINS["server-fetch"],
        peer_signing_key=SigningKey(bytes(range(32, 64))),
        registry_signing_key=SigningKey(bytes(range(32))),
        ca=TLS / "trusted-ca.crt", client_cert=TLS / "client.crt",
        client_key=TLS / "client.key", **kw)


def test_absent_bundle_is_closed(root):
    result = cfg.load_commissioning(now=NOW)
    assert result.status == "absent" and result.client is None


def test_valid_bundle_commissions_without_communication(root, monkeypatch):
    import socket
    monkeypatch.setattr(socket.socket, "connect",
                        lambda *a, **k: pytest.fail("loader communicated"))
    build(root)
    result = cfg.load_commissioning(now=NOW)
    assert result.status == "commissioned", result.reason_code
    assert result.client.knowledge_context_enabled is True
    assert result.client.knowledge_context_max_ttl_seconds == 60
    assert len(result.alias_key) >= 32 and result.mission == "synthetic-mission"
    assert "AAAA" not in repr(result)


@pytest.mark.parametrize("defect,code", [
    ("enabled_false", "enabled_not_true"), ("enabled_string", "manifest_schema"),
    ("missing_value", "manifest_schema"), ("bad_signature", "registry_signature"),
    ("expired_registry", "registry_expired"), ("bad_ttl", "ttl_invalid"),
    ("short_alias", "alias_short"), ("wrong_identity", "identity_mismatch"),
])
def test_defective_bundle_is_refused_with_fixed_code(root, defect, code):
    assert defect in DEFECTS
    build(root, defect=defect)
    result = cfg.load_commissioning(now=NOW)
    assert (result.status, result.reason_code) == ("refused", code)
    assert result.client is None


def test_missing_manifest_and_extra_file_refused(root):
    build(root)
    (bundle_dir(root) / "stray.txt").write_text("x")
    assert cfg.load_commissioning(now=NOW).reason_code == "bundle_unexpected"
    (bundle_dir(root) / "stray.txt").unlink()
    (bundle_dir(root) / "manifest.json").unlink()
    assert cfg.load_commissioning(now=NOW).reason_code == "manifest_missing"


def test_unsafe_paths_and_permissions_refused(root):
    build(root)
    d = bundle_dir(root)
    os.chmod(d / "alias.key", 0o604)
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"
    os.chmod(d / "alias.key", 0o600)
    os.chmod(d / "registry.signed", 0o666)
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"
    os.chmod(d / "registry.signed", 0o644)
    os.link(d / "ca.pem", root / "hard")
    assert cfg.load_commissioning(now=NOW).reason_code == "path_unsafe"
    os.unlink(root / "hard")
    (d / "ca.pem").rename(root / "ca.real")
    (d / "ca.pem").symlink_to(root / "ca.real")
    assert cfg.load_commissioning(now=NOW).reason_code == "path_unsafe"


def test_symlinked_bundle_directory_and_wrong_owner_refused(root, monkeypatch):
    build(root)
    d = bundle_dir(root)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid() + 1)
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    d.rename(root / "moved")
    d.symlink_to(root / "moved")
    assert cfg.load_commissioning(now=NOW).reason_code == "path_unsafe"


def _request(client):
    return client.request_context(frame={}, privacy_class=None, policy=None,
                                  mission="m", alias_key=b"x" * 32, deadline_s=1)


def test_removed_manifest_latches_client_closed(root):
    build(root)
    result = cfg.load_commissioning(now=NOW)
    manifest = bundle_dir(root) / "manifest.json"
    # Before removal the guard passes and the call reaches the inner client,
    # which refuses for its own (different) reason.
    with pytest.raises(Exception) as before:
        _request(result.client)
    assert str(before.value) != "commissioning bundle changed"
    saved = manifest.read_bytes()
    manifest.unlink()
    with pytest.raises(cfg.KnowledgeRefused, match="^commissioning bundle changed$"):
        _request(result.client)
    manifest.write_bytes(saved)
    with pytest.raises(cfg.KnowledgeRefused, match="^commissioning bundle changed$"):
        _request(result.client)


def test_secret_group_read_limited_to_service_group(root):
    build(root, secret_mode=0o640)
    d = bundle_dir(root)
    assert cfg.load_commissioning(now=NOW).status == "commissioned"  # own egid
    other = next((g for g in os.getgroups() if g != os.getegid()), None)
    if other is None:
        pytest.skip("no supplementary group available to act as an unrelated group")
    os.chown(d / "client.key", -1, other)
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"
    os.chown(d / "client.key", -1, os.getegid())
    os.chown(d / "alias.key", -1, other)
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"


def test_secret_group_check_uses_effective_gid(root, monkeypatch):
    build(root, secret_mode=0o640)
    fake = os.getegid() + 12345
    monkeypatch.setattr(cfg.os, "getegid", lambda: fake)
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"


def test_unexpected_registry_error_is_registry_invalid(root, monkeypatch):
    build(root)
    def boom(*a, **k):
        raise RuntimeError("internal")
    monkeypatch.setattr(cfg, "load_registry", boom)
    assert cfg.load_commissioning(now=NOW).reason_code == "registry_invalid"


def _run_main(monkeypatch, root):
    captured = {}
    monkeypatch.setattr(knowledge_contextd, "serve_forever",
                        lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(knowledge_contextd.PrincipalPolicy, "resolve",
                        classmethod(lambda cls, **kw: None))
    state = runtime_paths.knowledge_context_state_dir()
    state.mkdir(parents=True)
    assert knowledge_contextd.main([]) == 0
    events = [__import__("json").loads(line)["event"]
              for line in (state / "context.jsonl").read_text().splitlines()]
    return captured, events


def test_main_without_bundle_stays_closed(root, monkeypatch):
    captured, events = _run_main(monkeypatch, root)
    assert captured["handler"].__self__._ready is False
    assert events[0]["event_type"] == "knowledge.context.commissioning"
    assert events[0]["outcome"] == "absent"


def test_main_with_valid_bundle_is_ready_and_audited(root, monkeypatch):
    build(root)
    captured, events = _run_main(monkeypatch, root)
    assert captured["handler"].__self__._ready is True
    assert events[0]["outcome"] == "commissioned" and events[0]["registry_version"] == 1


def test_main_with_defective_bundle_stays_closed_with_reason(root, monkeypatch):
    build(root, defect="enabled_false")
    captured, events = _run_main(monkeypatch, root)
    assert captured["handler"].__self__._ready is False
    assert (events[0]["outcome"], events[0]["reason_code"]) == ("refused", "enabled_not_true")
