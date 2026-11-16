"""tools/build_commissioning_bundle.py: offline signer/assembler (B1, U59).

Synthetic material only. Tests marked `root` run only as uid 0 (isolated
container, see lanes-20261117-u59/b1/run-b1.sh) because the real loader
requires uid-0 owners; `_OWNER` is never patched.
"""

import hashlib
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey, VerifyKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "src"))
sys.path.insert(0, str(ROOT / "tests" / "real_process"))

_spec = importlib.util.spec_from_file_location(
    "build_commissioning_bundle", ROOT / "tools" / "build_commissioning_bundle.py")
tool = importlib.util.module_from_spec(_spec)
sys.modules["build_commissioning_bundle"] = tool
_spec.loader.exec_module(tool)

TLS = ROOT / "tests" / "fixtures" / "tls"
NOW = "2026-11-10T00:00:00+00:00"
SEED = bytes(range(32))
PEER_SEED = bytes(range(32, 64))
PIN = "sha256:1ece01f6b21c26b7252f06938bea9d2e38b317beb3a7264936aa2e261a5d29c3"
needs_root = pytest.mark.skipif(os.geteuid() != 0, reason="loader pass needs uid 0")

# Golden values fixed at main d86a7fff from the test fixture, written out
# literally so neither the product code nor the fixture is the oracle.
DOMAIN_LITERAL = b"azazel-nexus/knowledge-registry/v1\x00"
REGISTRY_PUBLIC = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
PEER_PUBLIC = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
GOLDEN_REGISTRY_SHA256 = "1127f57b7d8946333d71e8ecc601f7617c8787b991660d5f919dcf9433951d91"
GOLDEN_MANIFEST_SHA256 = "f8a12f88156d98765fba9c67ce9778ac8de65f4a0b32221bc9e0d1e9a813b446"
GOLDEN_DOCUMENT = (
    '{"commissioning_digest":"synthetic-commissioning","expires_at":"2099-01-01T00:00:00+00:00",'
    '"issued_at":"2026-01-01T00:00:00+00:00","peers":[{"addresses":["192.0.2.10"],'
    '"endpoint":{"allowed_privacy_classes":["P0-public"],"certificate_pin":"' + PIN + '",'
    '"client_identity":"knowledge-context-client","deadline_seconds":5,"host":"fetch.azazel.test",'
    '"max_request_bytes":4096,"max_response_bytes":65536,"model_id":"knowledge-v1",'
    '"path_template":"/knowledge/v1","port":443,"provider_id":"az04-test"},"max_inflight":1,'
    '"public_key":"' + PEER_PUBLIC + '"}],"schema":"azazel-nexus/knowledge-peer/1","version":1}'
).encode()
POLICY = {"version": "synthetic-context-1", "remote_default": "deny",
          "classes": {"P0-public": {"remote": "allow", "fields": ["question"]}},
          "limits": {"max_bytes": 4096}}


@pytest.fixture(autouse=True)
def closed_world(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("network, DNS or key generation attempted")
    for obj, attr in ((socket.socket, "connect"), (socket.socket, "connect_ex"),
                      (socket, "create_connection"), (socket, "getaddrinfo"),
                      (socket, "gethostbyname"), (os, "urandom"),
                      (SigningKey, "generate")):
        monkeypatch.setattr(obj, attr, refuse)
    import secrets
    monkeypatch.setattr(secrets, "token_bytes", refuse)
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)


def put(path, data, mode):
    path.write_bytes(data)
    path.chmod(mode)
    return path


@pytest.fixture
def work(tmp_path):
    w = tmp_path / "in"
    w.mkdir()
    w.chmod(0o700)
    if os.geteuid() == 0:  # the loader pass needs a root-owned, non-writable parent chain
        out = _stage_dir("w")
    else:
        out = tmp_path / "out"
        out.mkdir()
    out.chmod(0o755)
    put(w / "seed", SEED.hex().encode(), 0o600)
    put(w / "peer.pub", PEER_PUBLIC.encode(), 0o644)
    put(w / "ca.pem", (TLS / "trusted-ca.crt").read_bytes(), 0o644)
    put(w / "client.pem", (TLS / "client.crt").read_bytes(), 0o644)
    put(w / "server.pem", (TLS / "server-fetch.crt").read_bytes(), 0o644)
    put(w / "client.key", (TLS / "client.key").read_bytes(), 0o600)
    put(w / "alias.key", bytes(range(100, 132)), 0o600)
    put(w / "policy.json", json.dumps(POLICY).encode(), 0o600)
    return w, out


def inputs(work, **kw):
    w, out = work
    base = dict(
        registry_seed=w / "seed", expect_registry_public=REGISTRY_PUBLIC,
        peer_public_key=w / "peer.pub", ca=w / "ca.pem", client_cert=w / "client.pem",
        client_key=w / "client.key", server_cert=w / "server.pem", alias_key=w / "alias.key",
        policy=w / "policy.json", peer_id="az04-test", client_identity="knowledge-context-client",
        peer_host="fetch.azazel.test", peer_port=443, peer_address="192.0.2.10",
        commissioning_digest="synthetic-commissioning", mission="synthetic-mission",
        expires_at="2099-01-01T00:00:00+00:00", out=out / "bundle", max_ttl_seconds=60,
        issued_at="2026-01-01T00:00:00+00:00", now=NOW, allow_unverified_staging=True)
    base.update(kw)
    return tool.Inputs(**base)


def refused(inp):
    with pytest.raises(tool.Refused) as info:
        tool.build(inp)
    return info.value.code


def no_leftovers(out):
    assert [p.name for p in out.iterdir()] == [] or all(
        not p.name.startswith(".") for p in out.iterdir())


# ------------------------------------------------------------ golden / oracle

def test_golden_bytes_and_independent_verification(work):
    state, _ = tool.build(inputs(work))
    d = work[1] / "bundle"
    assert state == ("loader_verified" if os.geteuid() == 0 else "staging_only")
    reg = (d / "registry.signed").read_bytes()
    assert reg[64:] == GOLDEN_DOCUMENT
    assert hashlib.sha256(reg).hexdigest() == GOLDEN_REGISTRY_SHA256
    assert hashlib.sha256((d / "manifest.json").read_bytes()).hexdigest() == GOLDEN_MANIFEST_SHA256
    # independent verification: literal domain, PyNaCl directly, no product code
    VerifyKey(bytes.fromhex(REGISTRY_PUBLIC)).verify(DOMAIN_LITERAL + reg[64:], reg[:64])
    assert json.loads((d / "registry-keys.json").read_text()) == {"knowledge-registry": REGISTRY_PUBLIC}


def test_matches_existing_fixture_output(work, tmp_path):
    from _knowledge_context_bundle_fixture import build_bundle
    tool.build(inputs(work))
    ref = build_bundle(
        tmp_path / "ref", peer_id="az04-test", peer_address="192.0.2.10",
        peer_host="fetch.azazel.test", peer_port=443, certificate_pin=PIN,
        peer_signing_key=SigningKey(PEER_SEED), registry_signing_key=SigningKey(SEED),
        ca=TLS / "trusted-ca.crt", client_cert=TLS / "client.crt", client_key=TLS / "client.key",
        commissioning_digest="synthetic-commissioning", max_ttl_seconds=60,
        alias_key=bytes(range(100, 132)))
    for name in ("registry.signed", "registry-keys.json", "manifest.json", "ca.pem", "client.pem",
                 "client.key", "alias.key"):
        assert (work[1] / "bundle" / name).read_bytes() == (ref / name).read_bytes(), name


def test_file_set_and_modes(work):
    tool.build(inputs(work))
    d = work[1] / "bundle"
    assert sorted(p.name for p in d.iterdir()) == sorted(tool.cfg._FILES)
    for p in d.iterdir():
        mode = p.stat().st_mode & 0o777
        assert mode == (0o640 if p.name in ("client.key", "alias.key") else 0o644)
    assert d.stat().st_mode & 0o777 == 0o755
    no_leftovers(work[1])


# ------------------------------------------------------------ input validation (B1-2)

def test_wrong_seed_and_wrong_expected_key(work):
    assert refused(inputs(work, expect_registry_public=PEER_PUBLIC)) == "registry_key_mismatch"
    put(work[0] / "seed", bytes(range(1, 33)).hex().encode(), 0o600)
    assert refused(inputs(work)) == "registry_key_mismatch"


@pytest.mark.parametrize("kw,code", [
    (dict(expires_at="2026-11-09T00:00:00+00:00"), "registry_validity"),
    (dict(expires_at="2099-01-01T00:00:00"), "expires_invalid"),
    (dict(issued_at="2026-12-01T00:00:00+00:00"), "registry_validity"),
    (dict(peer_address="192.0.2.10,192.0.2.11"), "address_invalid"),
    (dict(peer_address="192.0.2.10 192.0.2.11"), "address_invalid"),
    (dict(peer_address="fetch.azazel.test"), "address_invalid"),
    (dict(peer_host="192.0.2.10"), "server_cert_chain_or_name"),
    (dict(peer_host="not-localhost.test.invalid"), "server_cert_chain_or_name"),
    (dict(peer_id="Bad Id"), "symbol_invalid"),
    (dict(client_identity="x" * 65), "symbol_invalid"),
    (dict(max_ttl_seconds=0), "ttl_invalid"),
    (dict(registry_version=0), "version_invalid"),
    (dict(commissioning_digest=""), "value_empty"),
    (dict(peer_port=70000), "registry_rejected_by_loader"),
])
def test_invalid_values_refused(work, kw, code):
    assert refused(inputs(work, **kw)) == code
    assert not (work[1] / "bundle").exists()
    no_leftovers(work[1])


@pytest.mark.parametrize("address", [
    "127.0.0.1", "127.1.2.3", "0.0.0.0", "169.254.1.1", "224.0.0.1", "239.255.255.250",
    "255.255.255.255", "240.0.0.1", "::1", "::", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
    "::ffff:169.254.0.1", "::ffff:0.0.0.0", "2002:7f00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"])
def test_address_policy(work, address):
    assert refused(inputs(work, peer_address=address)) in ("address_policy", "address_invalid")
    assert not (work[1] / "bundle").exists()


def test_valid_ipv6_and_private_addresses_accepted(work):
    for address in ("192.0.2.10", "10.1.2.3", "2001:db8::10"):
        out = work[1] / ("b" + address.replace(":", "_").replace(".", "_"))
        tool.build(inputs(work, peer_address=address, out=out))


def test_tls_credential_defects(work):
    w = work[0]
    put(w / "server.pem", (TLS / "server-wrong-name.crt").read_bytes(), 0o644)
    assert refused(inputs(work)) == "server_cert_chain_or_name"
    put(w / "server.pem", (TLS / "server-untrusted-ca.crt").read_bytes(), 0o644)
    assert refused(inputs(work)) == "server_cert_chain_or_name"
    put(w / "server.pem", (TLS / "server-expired.crt").read_bytes(), 0o644)
    assert refused(inputs(work)) == "server_cert_chain_or_name"
    put(w / "server.pem", (TLS / "server-fetch.crt").read_bytes(), 0o644)
    put(w / "client.pem", (TLS / "client-untrusted.crt").read_bytes(), 0o644)  # key does not match
    assert refused(inputs(work)) == "tls_credentials_invalid"
    put(w / "client.pem", (TLS / "client.crt").read_bytes(), 0o644)
    put(w / "ca.pem", b"not a certificate", 0o644)
    assert refused(inputs(work)) == "tls_credentials_invalid"
    assert not (work[1] / "bundle").exists()


def test_certificate_expiring_before_registry_is_refused(work):
    # fixture certificates end in 2126
    assert refused(inputs(work, expires_at="2130-01-01T00:00:00+00:00")) == "cert_expires_before_registry"


def test_key_reuse_and_purpose_separation(work):
    w = work[0]
    put(w / "peer.pub", REGISTRY_PUBLIC.encode(), 0o644)
    assert refused(inputs(work)) == "key_reuse"
    put(w / "peer.pub", PEER_PUBLIC.encode(), 0o644)
    put(w / "alias.key", SEED + b"x" * 8, 0o600)
    assert refused(inputs(work)) == "key_reuse"
    put(w / "alias.key", (TLS / "client.key").read_bytes(), 0o600)
    assert refused(inputs(work)) == "key_reuse"
    put(w / "alias.key", bytes(range(100, 131)), 0o600)
    assert refused(inputs(work)) == "alias_short"


def test_policy_must_be_valid(work):
    put(work[0] / "policy.json", b'{"version": 1}', 0o600)
    assert refused(inputs(work)) == "policy_invalid"
    put(work[0] / "policy.json", b"[]", 0o600)
    assert refused(inputs(work)) == "policy_invalid"


def test_missing_key_inputs_are_not_generated(work):
    (work[0] / "alias.key").unlink()
    assert refused(inputs(work)) == "input_unreadable_alias"
    (work[0] / "seed").unlink()
    assert refused(inputs(work)) in ("input_unsafe_seed", "input_unreadable_alias")


# ------------------------------------------------------------ safety (B1-3)

@pytest.mark.parametrize("name,code", [
    ("seed", "input_unsafe_seed"), ("client.key", "input_permission_client_key"),
    ("alias.key", "input_permission_alias")])
def test_dangerous_input_permissions(work, name, code):
    (work[0] / name).chmod(0o644)
    assert refused(inputs(work)) == code
    (work[0] / name).chmod(0o640)
    assert refused(inputs(work)) == code


def test_symlink_and_special_inputs(work):
    w = work[0]
    real = w / "alias.real"
    (w / "alias.key").rename(real)
    (w / "alias.key").symlink_to(real)
    assert refused(inputs(work)) == "input_unreadable_alias"
    (w / "alias.key").unlink()
    os.link(real, w / "alias.key")  # nlink 2
    assert refused(inputs(work)) == "input_unsafe_alias"
    (w / "alias.key").unlink()
    real.rename(w / "alias.key")
    (w / "seed").unlink()
    os.mkfifo(w / "seed", 0o600)
    assert refused(inputs(work)) == "input_unsafe_seed"


def test_output_location_checks(work, tmp_path):
    w, out = work
    # symlinked parent
    link = tmp_path / "link"
    link.symlink_to(out)
    assert refused(inputs(work, out=link / "b")) == "output_parent_symlink"
    # symlink as the output name
    (out / "sym").symlink_to(tmp_path)
    assert refused(inputs(work, out=out / "sym")) == "output_exists"
    # group/other writable parent
    out.chmod(0o775)
    assert refused(inputs(work)) == "output_parent_permission"
    out.chmod(0o777)
    assert refused(inputs(work)) == "output_parent_permission"
    out.chmod(0o755)
    # missing parent, bad names
    assert refused(inputs(work, out=out / "x" / "y")) in ("output_parent_unusable", "output_parent_symlink")
    assert refused(inputs(work, out=out / "..")) == "output_name_invalid"


def test_existing_output_is_never_overwritten(work):
    w, out = work
    existing = out / "bundle"
    existing.mkdir()
    (existing / "marker").write_text("keep")
    assert refused(inputs(work)) == "output_exists"
    assert [p.name for p in existing.iterdir()] == ["marker"]
    shutil.rmtree(existing)
    existing.write_text("a file")
    assert refused(inputs(work)) == "output_exists"
    assert existing.read_text() == "a file"
    no_leftovers(out)


def test_race_after_check_is_not_overwritten(work, monkeypatch):
    w, out = work
    real = tool._rename_noreplace

    def racing(pfd, old, new):
        (out / "bundle").mkdir()
        (out / "bundle" / "marker").write_text("theirs")
        real(pfd, old, new)
    monkeypatch.setattr(tool, "_rename_noreplace", racing)
    assert refused(inputs(work)) == "output_exists"
    assert [p.name for p in (out / "bundle").iterdir()] == ["marker"]
    assert not any(p.name.startswith(".") for p in out.iterdir())


def test_refuses_where_exclusive_rename_is_unavailable(work, monkeypatch):
    monkeypatch.setattr(tool.sys, "platform", "freebsd13")
    assert refused(inputs(work)) == "exclusive_rename_unavailable"
    assert not (work[1] / "bundle").exists()
    assert not any(p.name.startswith(".") for p in work[1].iterdir())


@pytest.mark.parametrize("stage", ["write", "mkdir", "rename"])
def test_midway_failure_leaves_nothing(work, monkeypatch, stage):
    out = work[1]
    if stage == "write":
        calls = []
        real = os.fchmod

        def flaky(fd, mode):
            calls.append(1)
            if len(calls) == 3:
                raise OSError("injected")
            return real(fd, mode)
        monkeypatch.setattr(os, "fchmod", flaky)
    elif stage == "mkdir":
        real_write = os.write
        count = []

        def flaky_write(fd, data):
            count.append(1)
            if len(count) == 5:
                raise OSError("injected")
            return real_write(fd, data)
        monkeypatch.setattr(os, "write", flaky_write)
    else:
        def boom(*a):
            raise tool.Refused("publish_failed")
        monkeypatch.setattr(tool, "_rename_noreplace", boom)
    assert refused(inputs(work)) == "publish_failed"
    assert list(out.iterdir()) == []


def test_cli_exit_codes_and_no_secret_in_output(work, capsys):
    w, out = work
    argv = ["--enabled", "--allow-unverified-staging", "--registry-seed", str(w / "seed"),
            "--expect-registry-public", REGISTRY_PUBLIC, "--peer-public-key", str(w / "peer.pub"),
            "--ca", str(w / "ca.pem"), "--client-cert", str(w / "client.pem"),
            "--client-key", str(w / "client.key"), "--server-cert", str(w / "server.pem"),
            "--alias-key", str(w / "alias.key"), "--policy", str(w / "policy.json"),
            "--peer-id", "az04-test", "--client-identity", "knowledge-context-client",
            "--peer-host", "fetch.azazel.test", "--peer-port", "443",
            "--peer-address", "192.0.2.10", "--commissioning-digest", "synthetic-commissioning",
            "--mission", "synthetic-mission", "--expires-at", "2099-01-01T00:00:00+00:00",
            "--now", NOW, "--out", str(out / "bundle")]
    assert tool.main(argv) == 0
    seen = capsys.readouterr()
    text = seen.out + seen.err
    secrets_ = [SEED.hex(), SEED, bytes(range(100, 132)), (TLS / "client.key").read_bytes()]
    for secret in secrets_:
        blob = secret if isinstance(secret, bytes) else secret.encode()
        assert blob not in text.encode()
    for line in (TLS / "client.key").read_text().splitlines()[1:3]:
        assert line not in text
    # no digest of the secret files, only presence and a size band
    for name in ("client.key", "alias.key"):
        digest = hashlib.sha256((out / "bundle" / name).read_bytes()).hexdigest()
        assert digest[:12] not in text and digest not in text
        assert f"{name}: present (" in text
    assert "synthetic-mission" not in text and str(w) not in text
    # a refusal prints only the fixed code
    assert tool.main(argv) == 1
    err = capsys.readouterr()
    assert err.err.strip() == "refused: output_exists" and err.out == ""
    # --enabled is mandatory; arguments are not echoed on usage errors
    assert tool.main([a for a in argv if a != "--enabled"]) == 2
    usage = capsys.readouterr().err
    assert str(w) not in usage and "usage:" in usage
    assert tool.main(["--enabled", "--seed-value", SEED.hex()]) == 2
    assert SEED.hex() not in capsys.readouterr().err


def test_not_root_requires_explicit_staging_flag(work):
    if os.geteuid() == 0:
        pytest.skip("root path verifies with the loader")
    assert refused(inputs(work, allow_unverified_staging=False)) == "loader_pass_needs_root"


def test_azazel_root_env_refused(work, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", "/nonexistent")
    assert refused(inputs(work)) == "azazel_root_set"


def test_input_swapped_after_read_changes_neither_verification_nor_output(work, monkeypatch):
    """Verification runs on copies of the bytes already read; sources are not reopened."""
    w, out = work
    originals = {n: (w / n).read_bytes() for n in ("ca.pem", "client.pem", "server.pem", "client.key")}
    sources = {str(w / n) for n in originals}
    seen = []

    def swap():
        put(w / "server.pem", (TLS / "server-wrong-name.crt").read_bytes(), 0o644)
        put(w / "ca.pem", (TLS / "untrusted-ca.crt").read_bytes(), 0o644)
        put(w / "client.pem", (TLS / "client-untrusted.crt").read_bytes(), 0o644)
        put(w / "client.key", (TLS / "client-untrusted.key").read_bytes(), 0o600)

    real_ctx, real_run = tool.knowledge_egress.tls_context, tool.subprocess.run

    def ctx(**kw):
        seen.extend(kw.values())
        swap()
        return real_ctx(**kw)

    def run(command, **kw):
        seen.extend(command)
        swap()
        return real_run(command, **kw)
    monkeypatch.setattr(tool.knowledge_egress, "tls_context", ctx)
    monkeypatch.setattr(tool.subprocess, "run", run)
    tool.build(inputs(work))
    assert not sources & set(map(str, seen))
    d = out / "bundle"
    for name, final in (("ca.pem", "ca.pem"), ("client.pem", "client.pem"),
                        ("server.pem", None), ("client.key", "client.key")):
        if final:
            assert (d / final).read_bytes() == originals[name]
    assert not any(p.name.startswith(".") for p in out.iterdir())


def test_secrets_are_never_hashed(work, monkeypatch):
    import hashlib as h
    secrets_ = [SEED, SEED.hex().encode(), bytes(range(100, 132)), (TLS / "client.key").read_bytes()]
    fed = []
    real = h.sha256

    def spy(data=b"", *a, **k):
        fed.append(bytes(data))
        return real(data, *a, **k)
    monkeypatch.setattr(h, "sha256", spy)
    monkeypatch.setattr(h, "new", lambda *a, **k: pytest.fail("hashlib.new used"))
    tool.build(inputs(work))
    assert fed  # public digests are still computed
    for blob in fed:
        for secret in secrets_:
            assert secret not in blob and blob not in secrets_


def test_intermediate_symlink_and_writable_ancestor(work, tmp_path):
    w, out = work
    real = tmp_path / "real"
    (real / "sub").mkdir(parents=True)
    (real / "sub").chmod(0o755)
    (tmp_path / "lnk").symlink_to(real)
    assert refused(inputs(work, out=tmp_path / "lnk" / "sub" / "b")) == "output_parent_symlink"
    # swapped in after a string check is moot: the walk never follows a link
    anc = tmp_path / "anc"
    (anc / "mid").mkdir(parents=True)
    (anc / "mid").chmod(0o755)
    anc.chmod(0o777)
    assert refused(inputs(work, out=anc / "mid" / "b")) == "output_parent_permission"
    anc.chmod(0o775)
    assert refused(inputs(work, out=anc / "mid" / "b")) == "output_parent_permission"
    anc.chmod(0o755)
    if os.geteuid() != 0:  # as root the loader rule rejects /tmp-based parents
        tool.build(inputs(work, out=anc / "mid" / "b"))
        assert (anc / "mid" / "b" / "registry.signed").exists()


# ------------------------------------------------------------ root: real loader, service account (B1-4)

_seq = [0]


def _stage_dir(tag):
    _seq[0] += 1
    d = Path("/stage") / f"{tag}-{os.getpid()}-{_seq[0]}"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    return d


def check_as_service(directory, *extra, user=1001):
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / "check_knowledge_context_bundle.py"),
         str(directory), "--now", NOW, *extra],
        capture_output=True, text=True, user=user, group=user, env=env, umask=0o022)


def install(directory, gid=1001):
    """What the deployment step does: root:<service group>, secrets 0640."""
    os.chown(directory, 0, 0)
    for p in directory.iterdir():
        os.chown(p, 0, gid if p.name in ("client.key", "alias.key") else 0)


@needs_root
def test_root_loader_verifies_candidate_and_service_account_precheck(work):
    out = _stage_dir("ok")
    state, _ = tool.build(inputs(work, out=out / "bundle", allow_unverified_staging=False))
    assert state == "loader_verified"
    d = out / "bundle"
    install(d)
    done = check_as_service(d)
    assert done.returncode == 0 and done.stdout.startswith("commissioned"), done.stdout + done.stderr
    # the root caller is refused by the pre-check (it would read what the service cannot)
    assert subprocess.run([sys.executable, str(ROOT / "tools" / "check_knowledge_context_bundle.py"),
                           str(d)], capture_output=True).returncode == 2


@needs_root
def test_root_known_good_and_tampered_negatives_agree_between_signer_and_verifier(work):
    out = _stage_dir("neg")
    tool.build(inputs(work, out=out / "good", allow_unverified_staging=False))
    good = out / "good"
    cases = {}
    for label in ("sig", "expired", "perm", "identity", "enabled"):
        d = out / label
        shutil.copytree(good, d)
        cases[label] = d
    reg = cases["sig"] / "registry.signed"
    raw = reg.read_bytes()
    reg.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    manifest = json.loads((cases["identity"] / "manifest.json").read_text())
    manifest["client_identity"] = "other-identity"
    (cases["identity"] / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    manifest = json.loads((cases["enabled"] / "manifest.json").read_text())
    manifest["enabled"] = False
    (cases["enabled"] / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
    (cases["perm"] / "client.key").chmod(0o644)
    for label, d in cases.items():
        install(d)
    (cases["perm"] / "client.key").chmod(0o644)
    expect = {"sig": "registry_signature", "identity": "identity_mismatch",
              "enabled": "enabled_not_true", "perm": "perm_unsafe"}
    for label, code in expect.items():
        done = check_as_service(cases[label])
        assert done.returncode == 1 and code in done.stdout, (label, done.stdout)
    # expired registry: same good bundle checked after its expiry
    install(cases["expired"])
    done = check_as_service(cases["expired"], "--now" if False else "--now", "2100-01-01T00:00:00+00:00")
    assert done.returncode == 1 and "registry_expired" in done.stdout
    # signer output verified by an independent check on the untouched good bundle
    install(good)
    assert check_as_service(good).returncode == 0


@needs_root
def test_root_loader_refusal_publishes_nothing(work, monkeypatch):
    out = _stage_dir("refuse")
    real_plan = tool.plan

    def bad_plan(inp, scratch):
        built = real_plan(inp, scratch)
        data, mode = built.files["manifest.json"]
        manifest = json.loads(data)
        manifest["enabled"] = False
        built.files["manifest.json"] = (json.dumps(manifest, sort_keys=True).encode(), mode)
        return built
    monkeypatch.setattr(tool, "plan", bad_plan)
    assert refused(inputs(work, out=out / "bundle", allow_unverified_staging=False)) == "loader_enabled_not_true"
    assert list(out.iterdir()) == []


@needs_root
def test_root_unsafe_parent_chain_is_refused_by_loader_rule(work):
    # /tmp is 1777: the loader's own rule rejects it, and the tool must not publish
    import tempfile
    out = Path(tempfile.mkdtemp(dir="/tmp"))
    out.chmod(0o755)
    assert refused(inputs(work, out=out / "bundle", allow_unverified_staging=False)).startswith("loader_")
    assert list(out.iterdir()) == []
