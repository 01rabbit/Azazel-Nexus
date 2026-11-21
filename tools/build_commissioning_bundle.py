#!/usr/bin/env python3
"""Build and sign a Knowledge Context commissioning bundle, offline (B1, U59).

Product counterpart of the test-only fixture. It writes the exact flat 7-file
directory that `knowledge_context_config.load_commissioning` reads and signs
only what the existing contract signs: `registry.signed` =
Ed25519(REGISTRY_DOMAIN + canonical(document)) || canonical(document). No new
signing format, no new key type.

It never connects (no socket is opened), never generates a key (seed, TLS key
and alias key are inputs; a missing one is a refusal), never overwrites
(publication is an exclusive rename) and never takes key material on the
command line (every key is a separate file). Standard output has fixed words
only: no path, no seed, and no digest of client.key or alias.key.

Result states:
  loader_verified  run as root: the candidate itself, before publication, was
                   read by the real `load_commissioning_from` (uid-0 owner
                   rules, no patching). The output is still pre-deployment
                   staging until it is installed under the fixed path with the
                   service group (chown root:<service group>); then run
                   tools/check_knowledge_context_bundle.py as the service account.
  staging_only     not root, `--allow-unverified-staging` given: everything
                   except the owner-dependent loader pass was checked.

The output directory's whole parent chain must be root-owned and not group/other
writable when the loader pass runs (the loader's own rule).

Exit status: 0 built, 1 refused (fixed code on stderr), 2 usage.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "runtime" / "src", ROOT / "src", ROOT):
    sys.path.insert(0, str(_p))

from nacl.signing import SigningKey  # noqa: E402

from azazel_nexus import spki  # noqa: E402
from azazel_nexus.knowledge_peer import (  # noqa: E402
    REGISTRY_DOMAIN, SCHEMA, KnowledgeRefused, canonical, instant, load_registry)
from azazel_nexus.sanitizer import SanitizerPolicy  # noqa: E402
from azazel_nexus_runtime import knowledge_context_config as cfg  # noqa: E402
from azazel_nexus_runtime import knowledge_egress  # noqa: E402
from tools.check_knowledge_context_bundle import (  # noqa: E402
    KNOWLEDGE_TTL_CEILING, certificate_der, not_after)
from tools.operator_sign import SignRefused, read_seed  # noqa: E402

MANIFEST_SCHEMA = cfg.MANIFEST_SCHEMA
PUBLIC_MODE, SECRET_MODE, DIR_MODE = 0o644, 0o640, 0o755
_LIMITS = {"ca": 64 * 1024, "client_cert": 64 * 1024, "server_cert": 64 * 1024,
           "client_key": 64 * 1024, "alias": 4096, "peer_public": 256,
           "policy": 64 * 1024}
_SECRET_INPUTS = {"client_key", "alias", "seed"}
_SYMBOL = re.compile(r"[A-Za-z0-9._@:+-]{1,64}\Z")


class Refused(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class Inputs:
    registry_seed: Path
    expect_registry_public: str
    peer_public_key: Path
    ca: Path
    client_cert: Path
    client_key: Path
    server_cert: Path
    alias_key: Path
    policy: Path
    peer_id: str
    client_identity: str
    peer_host: str
    peer_port: int
    peer_address: str
    commissioning_digest: str
    mission: str
    expires_at: str
    out: Path
    max_ttl_seconds: int = KNOWLEDGE_TTL_CEILING
    registry_version: int = 1
    issued_at: str | None = None
    now: str | None = None
    allow_unverified_staging: bool = False
    clock_proposal: Path | None = None


# ---------------------------------------------------------------- inputs

def read_input(path, name: str) -> bytes:
    """Regular, single-link, no symlink, bounded; secrets owner-only."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refused(f"input_unreadable_{name}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refused(f"input_unsafe_{name}")
        if name in _SECRET_INPUTS and info.st_mode & 0o077:
            raise Refused(f"input_permission_{name}")
        limit = _LIMITS.get(name, 65)
        if not 0 < info.st_size <= limit:
            raise Refused(f"input_size_{name}")
        data = os.read(fd, limit + 1)
        if len(data) != info.st_size:
            raise Refused(f"input_unsafe_{name}")
        return data
    except OSError:
        raise Refused(f"input_unreadable_{name}") from None
    finally:
        os.close(fd)


def _utc_instant(text: str, code: str):
    try:
        return instant(text)
    except KnowledgeRefused:
        raise Refused(code) from None


def check_address(text: str) -> str:
    """Operational policy of this tool (narrower than the loader's contract)."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise Refused("address_invalid") from None
    for candidate in (address, getattr(address, "ipv4_mapped", None)):
        if candidate is None:
            continue
        if (candidate.is_loopback or candidate.is_unspecified
                or candidate.is_link_local or candidate.is_multicast
                or candidate.is_reserved):
            raise Refused("address_policy")
    if address.version == 6 and (address.sixtofour or address.teredo):
        raise Refused("address_policy")
    return str(address)


def verify_server_chain(ca, server, host: str, now: datetime) -> None:
    """Chain to the commissioned CA only, name for `host`, validity at `now`.

    `openssl verify` runs the same libssl verification the client context uses
    (CERT_REQUIRED + check_hostname, commissioned CA only). No network.
    """
    command = ["openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", str(ca),
               "-purpose", "sslserver", "-verify_hostname", host,
               "-attime", str(int(now.timestamp())), str(server)]
    try:
        done = subprocess.run(command, capture_output=True, timeout=30, check=False,
                              env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        raise Refused("server_cert_check_unavailable") from None
    if done.returncode != 0:
        raise Refused("server_cert_chain_or_name")


# ---------------------------------------------------------------- plan

@dataclass
class Plan:
    files: dict  # name -> (bytes, mode)
    facts: dict
    now: str


@dataclass
class Scratch:
    """Private 0700 directory (beside the output) for the copies that get verified."""
    fd: int
    path: str

    def write(self, name: str, data: bytes) -> str:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            if os.write(fd, data) != len(data):
                raise OSError
        finally:
            os.close(fd)
        return f"{self.path}/{name}"


def plan(inp: Inputs, scratch: Scratch) -> Plan:
    now_text = inp.now or datetime.now(UTC).isoformat()
    now = _utc_instant(now_text, "now_invalid")
    issued = inp.issued_at or now_text
    issued_dt = _utc_instant(issued, "issued_invalid")
    expires_dt = _utc_instant(inp.expires_at, "expires_invalid")
    if not issued_dt <= now < expires_dt:
        raise Refused("registry_validity")
    for value in (inp.peer_id, inp.client_identity):
        if not _SYMBOL.fullmatch(value):
            raise Refused("symbol_invalid")
    for value in (inp.commissioning_digest, inp.mission):
        if not value or not value.strip():
            raise Refused("value_empty")
    if type(inp.max_ttl_seconds) is not int or inp.max_ttl_seconds < 1:
        raise Refused("ttl_invalid")
    if type(inp.registry_version) is not int or inp.registry_version < 1:
        raise Refused("version_invalid")
    address = check_address(inp.peer_address)

    try:
        seed = read_seed(inp.registry_seed)
    except (SignRefused, OSError):
        raise Refused("input_unsafe_seed") from None
    signing = SigningKey(seed)
    registry_public = bytes(signing.verify_key).hex()
    if registry_public != inp.expect_registry_public.strip().lower():
        raise Refused("registry_key_mismatch")
    peer_text = read_input(inp.peer_public_key, "peer_public").decode("ascii", "replace").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", peer_text):
        raise Refused("peer_public_invalid")
    peer_public = peer_text.lower()
    if peer_public == registry_public:
        raise Refused("key_reuse")

    ca = read_input(inp.ca, "ca")
    client_cert = read_input(inp.client_cert, "client_cert")
    server_cert = read_input(inp.server_cert, "server_cert")
    client_key = read_input(inp.client_key, "client_key")
    alias = read_input(inp.alias_key, "alias")
    if len(alias) < 32:
        raise Refused("alias_short")
    # purposes must not share bytes: seed, client key, alias key, peer public key
    # Direct constant-time comparison; secrets are never hashed, not even internally.
    blobs = (seed, client_key, alias, bytes.fromhex(peer_public))
    for i, left in enumerate(blobs):
        for right in blobs[i + 1:]:
            if hmac.compare_digest(left, right):
                raise Refused("key_reuse")
    if hmac.compare_digest(alias[:32], seed):
        raise Refused("key_reuse")
    policy_raw = read_input(inp.policy, "policy")
    try:
        policy = json.loads(policy_raw.decode("utf-8"))
        if type(policy) is not dict:
            raise ValueError
        SanitizerPolicy.from_mapping(policy)
    except Exception:
        raise Refused("policy_invalid") from None

    # TLS: same context construction as the client (CA loads, client cert/key pair).
    # Verified: copies of the very bytes read above (written from them, 0600, in the
    # private directory). The source paths are never reopened, and the bytes that
    # are published are these same bytes.
    try:
        ca_copy = scratch.write("ca.pem", ca)
        cert_copy = scratch.write("client.pem", client_cert)
        key_copy = scratch.write("client.key", client_key)
        server_copy = scratch.write("server.pem", server_cert)
    except OSError:
        raise Refused("publish_failed") from None
    try:
        knowledge_egress.tls_context(ca_certificate=ca_copy, client_certificate=cert_copy,
                                     client_key=key_copy)
    except Exception:
        raise Refused("tls_credentials_invalid") from None
    verify_server_chain(ca_copy, server_copy, inp.peer_host, now)
    try:
        pin = spki.spki_pin(certificate_der(server_cert))
        client_expiry = not_after(certificate_der(client_cert))
        server_expiry = not_after(certificate_der(server_cert))
    except Exception:
        raise Refused("certificate_unreadable") from None
    if client_expiry <= now:
        raise Refused("client_cert_expired")
    if client_expiry < expires_dt or server_expiry < expires_dt:
        raise Refused("cert_expires_before_registry")

    clock_policy = None
    if inp.clock_proposal is not None:
        from azazel_fabric.knowledge_context_clocklab import ClockContract
        raw_proposal = read_input(inp.clock_proposal, "policy")
        proposal = json.loads(raw_proposal)
        if (proposal.get("schema") != "azazel-nexus/commissioning-proposal/v4"
                or "sha256:" + hashlib.sha256(raw_proposal).hexdigest() != inp.commissioning_digest):
            raise Refused("clock_proposal_binding")
        clock_policy = ClockContract.from_dict(proposal["clock_policy"], consumer_revision=2).as_dict()
    document = {
        "schema": SCHEMA, "commissioning_digest": inp.commissioning_digest,
        "issued_at": issued, "expires_at": inp.expires_at, "version": inp.registry_version,
        "peers": [{
            "endpoint": {
                "provider_id": inp.peer_id, "host": inp.peer_host, "port": inp.peer_port,
                "path_template": "/knowledge/v1", "model_id": "knowledge-v1",
                "certificate_pin": pin, "client_identity": inp.client_identity,
                "max_request_bytes": 4096, "max_response_bytes": 65536,
                "deadline_seconds": 5, "allowed_privacy_classes": ["P0-public"],
            },
            "addresses": [address], "public_key": peer_public, "max_inflight": 1,
        }],
    }
    body = canonical(document)
    registry = signing.sign(REGISTRY_DOMAIN + body).signature + body
    try:  # the shipped registry loader, exactly as the service will call it
        load_registry(registry, keys={"knowledge-registry": bytes.fromhex(registry_public)},
                      commissioning_digest=inp.commissioning_digest, now=now_text)
    except Exception:
        raise Refused("registry_rejected_by_loader") from None
    manifest = {
        "schema": MANIFEST_SCHEMA, "enabled": True, "peer_id": inp.peer_id,
        "client_identity": inp.client_identity,
        "commissioning_digest": inp.commissioning_digest,
        "max_ttl_seconds": inp.max_ttl_seconds, "mission": inp.mission,
        "sanitizer_policy": policy,
    }
    if clock_policy is not None:
        manifest["schema"] = cfg.MANIFEST_SCHEMA_V2
        manifest["clock_policy"] = clock_policy
    files = {
        "manifest.json": (json.dumps(manifest, sort_keys=True).encode(), PUBLIC_MODE),
        "registry-keys.json": (json.dumps(
            {"knowledge-registry": registry_public}).encode(), PUBLIC_MODE),
        "registry.signed": (registry, PUBLIC_MODE),
        "ca.pem": (ca, PUBLIC_MODE),
        "client.pem": (client_cert, PUBLIC_MODE),
        "client.key": (client_key, SECRET_MODE),
        "alias.key": (alias, SECRET_MODE),
    }
    if set(files) != set(cfg._FILES):
        raise Refused("file_set_mismatch")
    facts = {"registry_version": inp.registry_version, "max_ttl_seconds": inp.max_ttl_seconds,
             "registry_public_key": registry_public[:12], "server_pin": pin[:19],
             "client_cert_not_after": client_expiry.isoformat()}
    if inp.max_ttl_seconds > KNOWLEDGE_TTL_CEILING:
        facts["warning"] = "ttl_above_knowledge_ceiling"
    return Plan(files, facts, now_text)


# ---------------------------------------------------------------- publish

def _rename_noreplace(pfd: int, old: str, new: str) -> None:
    """Exclusive, non-replacing rename; refuse where unavailable (fail safe)."""
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        if sys.platform.startswith("linux"):
            func, flag = libc.renameat2, 1  # RENAME_NOREPLACE
        elif sys.platform == "darwin":
            func, flag = libc.renameatx_np, 4  # RENAME_EXCL
        else:
            raise Refused("exclusive_rename_unavailable")
    except AttributeError:
        raise Refused("exclusive_rename_unavailable") from None
    if func(pfd, old.encode(), pfd, new.encode(), flag) != 0:
        err = ctypes.get_errno()
        if err in (17, 39):  # EEXIST, ENOTEMPTY
            raise Refused("output_exists")
        raise Refused("exclusive_rename_unavailable" if err in (22, 38, 45) else "publish_failed")


def _remove_tree(pfd: int, name: str) -> bool:
    try:
        dfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=pfd)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    try:
        for entry in os.listdir(dfd):
            os.unlink(entry, dir_fd=dfd)
    except OSError:
        return False
    finally:
        os.close(dfd)
    try:
        os.rmdir(name, dir_fd=pfd)
    except OSError:
        return False
    return True


def _open_parent(out: Path) -> tuple[int, str, str]:
    """Walk from "/" one component at a time (O_NOFOLLOW), checking every level.

    Every directory must be owned by root or the caller and not group/other
    writable; a root-owned sticky directory (/tmp) is tolerated as an ancestor
    only. The final parent must be the caller's own and strictly private from
    others' writes. Returns (parent fd, output name, parent path string).
    """
    name = Path(out).name  # before normalisation: '..' must not collapse away
    if not name or name in (".", "..") or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name):
        raise Refused("output_name_invalid")
    parts = Path(os.path.abspath(out)).parent.parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    euid = os.geteuid()
    fd = os.open("/", flags)
    try:
        for index in range(len(parts) + 1):
            info = os.fstat(fd)
            last = index == len(parts)
            writable = bool(info.st_mode & 0o022)
            sticky_root = info.st_uid == 0 and info.st_mode & 0o1000
            if last:
                if info.st_uid != euid or writable:
                    raise Refused("output_parent_permission")
            elif info.st_uid not in (0, euid) or (writable and not sticky_root):
                raise Refused("output_parent_permission")
            if last:
                break
            try:
                child = os.open(parts[index], flags, dir_fd=fd)
            except OSError as exc:
                import errno
                raise Refused("output_parent_symlink" if exc.errno in (errno.ELOOP, errno.ENOTDIR)
                              else "output_parent_unusable") from None
            os.close(fd)
            fd = child
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return fd, name, "/" + "/".join(parts)
        except OSError:
            raise Refused("output_parent_unusable") from None
        raise Refused("output_exists")
    except BaseException:
        os.close(fd)
        raise


def publish(built: Plan, out: Path, pfd: int, name: str, parent: str, *,
            verify_loader: bool) -> str:
    tmp = f".{name}.tmp-{os.getpid()}-{_counter()}"
    created = False
    try:
        os.mkdir(tmp, 0o700, dir_fd=pfd)
        created = True
        dfd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=pfd)
        try:
            for fname, (data, mode) in built.files.items():
                fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | os.O_CLOEXEC, 0o600, dir_fd=dfd)
                try:
                    if os.write(fd, data) != len(data):
                        raise OSError
                    os.fchmod(fd, mode)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fchmod(dfd, DIR_MODE)
            os.fsync(dfd)
        finally:
            os.close(dfd)
        state = "staging_only"
        if verify_loader:
            candidate = Path(parent) / tmp
            result = cfg.load_commissioning_from(candidate, now=built.now)
            if result.status != "commissioned":
                raise Refused(f"loader_{result.reason_code or result.status}")
            state = "loader_verified"
        os.fsync(pfd)
        _rename_noreplace(pfd, tmp, name)
        created = False
        os.fsync(pfd)
        return state
    except Refused:
        raise
    except OSError:
        raise Refused("publish_failed") from None
    finally:
        if created and not _remove_tree(pfd, tmp):
            print("warning: staging_directory_not_removed", file=sys.stderr)


_n = [0]


def _counter() -> int:
    _n[0] += 1
    return _n[0] + (int(datetime.now(UTC).timestamp() * 1e6) & 0xFFFFFF)


def _size_band(n: int) -> str:
    return "<1KiB" if n < 1024 else "1-4KiB" if n < 4096 else "4-64KiB"


def build(inp: Inputs) -> tuple[str, Plan]:
    if "AZAZEL_ROOT" in os.environ:
        raise Refused("azazel_root_set")
    verify = os.geteuid() == 0
    if not verify and not inp.allow_unverified_staging:
        raise Refused("loader_pass_needs_root")
    pfd, name, parent = _open_parent(inp.out)
    scratch_name = f".{name}.vfy-{os.getpid()}-{_counter()}"
    made = False
    try:
        os.mkdir(scratch_name, 0o700, dir_fd=pfd)
        made = True
        sfd = os.open(scratch_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                      dir_fd=pfd)
        try:
            built = plan(inp, Scratch(sfd, f"{parent}/{scratch_name}"))
        finally:
            os.close(sfd)
        return publish(built, inp.out, pfd, name, parent, verify_loader=verify), built
    except OSError:
        raise Refused("publish_failed") from None
    finally:
        if made and not _remove_tree(pfd, scratch_name):
            print("warning: staging_directory_not_removed", file=sys.stderr)
        os.close(pfd)


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # noqa: ARG002 - never echo arguments
        print("usage: build_commissioning_bundle.py --enabled --out DIR ... (arguments are "
              "not echoed; see the module docstring)", file=sys.stderr)
        raise SystemExit(2)


def main(argv=None) -> int:
    p = _Parser(description=__doc__.split("\n\n")[0])
    p.add_argument("--enabled", action="store_true", required=True,
                   help="required: the tool builds only bundles the loader accepts")
    for flag in ("registry-seed", "peer-public-key", "ca", "client-cert", "client-key",
                 "server-cert", "alias-key", "policy", "out"):
        p.add_argument(f"--{flag}", required=True, type=Path)
    for flag in ("expect-registry-public", "peer-id", "client-identity", "peer-host",
                 "peer-address", "commissioning-digest", "mission", "expires-at"):
        p.add_argument(f"--{flag}", required=True)
    p.add_argument("--peer-port", required=True, type=int)
    p.add_argument("--clock-proposal", type=Path, help="explicit signed-proposal v4 body, lab only")
    p.add_argument("--max-ttl-seconds", type=int, default=KNOWLEDGE_TTL_CEILING)
    p.add_argument("--registry-version", type=int, default=1)
    p.add_argument("--issued-at")
    p.add_argument("--now")
    p.add_argument("--allow-unverified-staging", action="store_true")
    try:
        a = p.parse_args(argv)
    except SystemExit as exc:
        return 2 if exc.code else 0
    inp = Inputs(
        registry_seed=a.registry_seed, expect_registry_public=a.expect_registry_public,
        peer_public_key=a.peer_public_key, ca=a.ca, client_cert=a.client_cert,
        client_key=a.client_key, server_cert=a.server_cert, alias_key=a.alias_key,
        policy=a.policy, peer_id=a.peer_id, client_identity=a.client_identity,
        peer_host=a.peer_host, peer_port=a.peer_port, peer_address=a.peer_address,
        commissioning_digest=a.commissioning_digest, mission=a.mission, clock_proposal=a.clock_proposal,
        expires_at=a.expires_at, out=a.out, max_ttl_seconds=a.max_ttl_seconds,
        registry_version=a.registry_version, issued_at=a.issued_at, now=a.now,
        allow_unverified_staging=a.allow_unverified_staging)
    try:
        state, built = build(inp)
    except Refused as exc:
        print(f"refused: {exc.code}", file=sys.stderr)
        return 1
    except Exception:  # never echo exception text or causes
        print("refused: internal_error", file=sys.stderr)
        return 1
    print("built")
    print(f"state: {state} (pre-deployment staging until installed and chowned; "
          "then run check_knowledge_context_bundle.py as the service account)")
    for key, value in built.facts.items():
        print(f"{key}: {value}")
    for name, (data, _mode) in built.files.items():
        if name in ("client.key", "alias.key"):
            print(f"{name}: present ({_size_band(len(data))})")
        else:
            print(f"{name}: sha256:{hashlib.sha256(data).hexdigest()[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
