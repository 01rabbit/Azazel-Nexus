"""Knowledge Lite trust operations with real accounts and processes (ADR 0007).

Two stages of `tools/e2e.py`, root only, on a root of their own (a second,
fresh `install.sh --without-service-manager`, because the earlier Lite
stages pin trust by hand on the harness root and an enrollment needs an
empty one):

1. **enrollment**: `az-auditd` runs as `azaudit` and `az-knowledge-lited` as
   `azknowledge`, as their units would. An enrollment is killed at its
   commit point -- a real process, `become_commissioner()`, dying inside the
   `trust.json` rename's predecessor -- and leaves residue the reader does not
   trust. The production transaction (`lite_trust_ops.run_enroll`, forking a
   child that becomes `azcommission`) then completes it. The real CLI entry
   (`az-nexus-commission trust-enroll` on a pseudo-terminal) refuses on this
   node, which has no verified commissioning evidence, and records why.
2. **import, repin, revocation, audit stop**: the real CLI imports a bundle
   through the daemon, `trust-repin` rotates the key and its anchor together,
   `knowledge-revocation-accept` revokes the new generation, and with auditd
   stopped an import is refused before any change and succeeds once auditd
   is back. A second auditd is refused while the first holds the chain.

Only two things are supplied by the stage: the commissioning digest (the
harness has no signed full commissioning; `production_evidence_digest` is
exercised by the pseudo-terminal run instead) and the human typing the
confirmation words, which the transactions receive as a callable. Keys are
generated here and never written to disk; only public keys are.

This is a container rehearsal of real processes, not of systemd: the units'
sandbox and the activation grant of `azazel-auditd-loop.service` are covered
by `tests/unit/test_runtime_activation_pass.py` and the systemd checks in
ADR 0007's verification record, not here.
"""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pty
import pwd
import select
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from tools.e2e_harness import Daemon, Harness, NotExecuted, request

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "7" * 64


def _fresh(harness: Harness) -> Harness:
    if os.geteuid() != 0:
        raise NotExecuted("service accounts and the commissioning identity need root")
    root = Path(tempfile.mkdtemp(prefix="az-lt-", dir="/tmp"))
    root.chmod(0o711)
    result = subprocess.run(
        ["sh", str(ROOT / "packaging" / "install.sh"), "--without-service-manager"],
        env={**harness.env, "DESTDIR": str(root), "PYTHON": sys.executable},
        capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"install.sh exited {result.returncode}: {result.stderr.strip()[:300]}")
    fresh = Harness(root)
    from nacl.signing import SigningKey

    fresh.keys = {"bundle": SigningKey.generate(), "next": SigningKey.generate(),
                  "revoker": SigningKey.generate()}
    harness.lite_trust = fresh  # type: ignore[attr-defined]
    return fresh


def _public(key) -> str:
    return key.verify_key.encode().hex()


def _place(fresh: Harness, name: str, data: bytes, *, group: str = "azcommission") -> None:
    path = fresh.root / "etc/azazel/commissioning" / name
    path.write_bytes(data)
    os.chown(path, 0, grp.getgrnam(group).gr_gid)
    path.chmod(0o640)


def _python(fresh: Harness, program: str, *args: str, timeout: float = 20) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", program, *args], env=fresh.env,
                          capture_output=True, text=True, timeout=timeout)


def _status(fresh: Harness) -> str:
    path = fresh.root / "var/lib/azazel/run/knowledge/knowledge.sock"
    reply = request(path, {"verb": "knowledge.status", "arguments": {}})
    assert reply["ok"] is True, reply
    return reply["result"]["reason_code"]


def _chain(fresh: Harness) -> list[str]:
    from azazel_nexus_runtime.auditd import SegmentedLedger

    ledger = SegmentedLedger(fresh.root / "var/lib/azazel/state/audit")
    ledger.verify()
    return [entry.event["event_type"] for entry in ledger]


def _request_document(fresh: Harness) -> bytes:
    return json.dumps({
        "schema": "azazel-nexus/lite-enrollment/v1",
        "commissioning_digest": DIGEST,
        "keys": {"site-bundle": _public(fresh.keys["bundle"])},
        "threshold": 1,
        "minimum_security_epoch": 0,
        "revocation_policy": {
            "keys": {"site-revoker": _public(fresh.keys["revoker"])},
            "key_roles": {"site-revoker": "revocation-signing"},
            "threshold": 1, "generation": 1,
        },
    }, sort_keys=True).encode()


_CRASH_AT_COMMIT = """
import os, sys
from pathlib import Path
from azazel_nexus_runtime import lite_trust_ops, runtime_paths
from azazel_nexus import lite_enrollment
raw = (runtime_paths.ROOT / "etc/azazel/commissioning/lite-enrollment.json").read_bytes()
lite_trust_ops.become_commissioner()
real = lite_enrollment._write
def write(path, data):
    if path.name == "trust.json":
        os._exit(9)   # the process dies at the commit point
    real(path, data)
lite_enrollment._write = write
lite_enrollment.enroll(runtime_paths.lite_trust_root(), lite_enrollment.decode_enrollment(raw),
                       commissioning_digest=sys.argv[1], enrolled_at="2026-10-30T00:00:00Z",
                       actor="root")
"""

_ENROLL = """
import sys
from azazel_nexus_runtime import lite_trust_ops
raise SystemExit(lite_trust_ops.run_enroll(evidence=lambda: sys.argv[1], confirm=lambda lines: True))
"""


def _pty_enroll(fresh: Harness) -> tuple[int, str]:
    """The real `az-nexus-commission trust-enroll`, typed on a terminal."""

    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover - the child
        os.execve(sys.executable, [sys.executable, "-m", "azazel_nexus_runtime.commission_cli",
                                   "trust-enroll"], fresh.env)
    output = b""
    answered = False
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            text = output.decode(errors="replace")
            if not answered and "Confirmation: " in text:
                words = next(word for word in text.split() if word.startswith("ENROLL-TRUST-"))
                os.write(fd, words.encode() + b"\n")
                answered = True
    _, status = os.waitpid(pid, 0)
    os.close(fd)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


def enrollment(harness: Harness) -> str:
    fresh = _fresh(harness)
    trust = fresh.root / "var/lib/azazel/lite-trust"
    raw = _request_document(fresh)
    _place(fresh, "lite-enrollment.json", raw)
    with Daemon(fresh, "auditd", "audit", account="azaudit"), \
            Daemon(fresh, "knowledge_lited", "knowledge", account="azknowledge"):
        assert _status(fresh) == "trust_unreadable"
        # The real entry on a terminal: no verified commissioning evidence on
        # this node, so the binding cannot be checked and nothing is written.
        code, text = _pty_enroll(fresh)
        assert code == 1, text
        assert "cannot be checked: no verified commissioning evidence" in text, text
        assert '"code": "evidence_unavailable"' in text, text
        assert list(trust.iterdir()) == []
        # A real process, narrowed to azcommission, dies at the commit point.
        crashed = _python(fresh, _CRASH_AT_COMMIT, DIGEST)
        assert crashed.returncode == 9, crashed.stderr[-300:]
        residue = sorted(path.name for path in trust.iterdir())
        assert residue == ["revocation-policy.json", "trust"], residue
        assert _status(fresh) == "trust_unreadable"
        # The production transaction completes the same request.
        done = _python(fresh, _ENROLL, DIGEST)
        assert done.returncode == 0, done.stdout + done.stderr[-300:]
        result = json.loads(done.stdout.strip().splitlines()[-1])
        assert result["enrolled"] is True and result["audit_complete"] is True
        assert _status(fresh) == "no_bundle"
        owner = pwd.getpwnam("azcommission").pw_uid
        group = grp.getgrnam("azknowledge").gr_gid
        for path in [trust / "trust", *trust.rglob("*")]:
            info = path.stat()
            assert (info.st_uid, info.st_gid) == (owner, group), path
            assert info.st_mode & 0o7777 == (0o2750 if path.is_dir() else 0o640), path
        # A second enrollment of an enrolled root is refused and recorded.
        again = _python(fresh, _ENROLL, DIGEST)
        assert again.returncode == 1 and '"already_enrolled"' in again.stdout
    kinds = _chain(fresh)
    assert kinds == [
        "knowledge.lite.trust_enroll_requested", "knowledge.lite.trust_enroll_refused",
        "knowledge.lite.trust_enroll_requested", "knowledge.lite.trust_enrolled",
        "knowledge.lite.trust_enroll_requested", "knowledge.lite.trust_enroll_refused",
    ], kinds
    return ("real auditd and knowledge-lited; the terminal entry refused without commissioning "
            "evidence and recorded it; a commissioning-account process killed at the commit "
            "point left untrusted residue; the transaction (child as azcommission) completed "
            "it, files azcommission:azknowledge 0640/2750; a second enrollment refused")


def _bundle(key, key_id: str, version: int) -> bytes:
    contract = ROOT / "contract" / "azazel-knowledge-lite"
    with tarfile.open(contract / "lite.tar.gz", "r:gz") as archive:
        members = {e.name: archive.extractfile(e).read() for e in archive if e.isfile()}
    manifest = json.loads(members["manifest.json"])
    manifest["bundle_version"] = version
    members["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()
    members["manifest.sig"] = (f"{key_id}:"
                               f"{key.sign(members['manifest.json']).signature.hex()}\n").encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _import(fresh: Harness, blob: bytes) -> tuple[int, dict | None]:
    inbox = fresh.root / "var/lib/azazel/knowledge/inbox"
    if not inbox.exists():
        inbox.mkdir(mode=0o2750)
        os.chown(inbox, pwd.getpwnam("azknowledge").pw_uid, grp.getgrnam("azazel-operator").gr_gid)
        inbox.chmod(0o2750)
    for old in inbox.iterdir():
        old.unlink()
    entry = hashlib.sha256(blob).hexdigest()
    path = inbox / f"{entry[:12]}.tar.gz"
    path.write_bytes(blob)
    os.chown(path, pwd.getpwnam("azknowledge").pw_uid, grp.getgrnam("azazel-operator").gr_gid)
    path.chmod(0o640)
    result = subprocess.run([sys.executable, "-m", "azazel_nexus_runtime.commission_cli",
                             "knowledge-import", "--entry", entry], env=fresh.env,
                            capture_output=True, text=True, timeout=60)
    lines = result.stdout.strip().splitlines()
    return result.returncode, (json.loads(lines[-1]) if lines else None)


_REPIN = """
from azazel_nexus_runtime import lite_trust_ops
raise SystemExit(lite_trust_ops.run_repin("rotation", ask=lambda c: c["confirmation_words"]))
"""

_REVOKE = """
from azazel_nexus_runtime import lite_trust_ops
raise SystemExit(lite_trust_ops.run_revocation_accept())
"""


def operations(harness: Harness) -> str:
    fresh = getattr(harness, "lite_trust", None)
    if fresh is None:
        raise NotExecuted("the enrollment stage did not leave an enrolled root")
    from azazel_nexus.revocation import RevocationList

    store = fresh.root / "var/lib/azazel/knowledge"
    try:
        with Daemon(fresh, "knowledge_lited", "knowledge", account="azknowledge"):
            with Daemon(fresh, "auditd", "audit", account="azaudit"):
                # One writer: a second auditd refuses before binding anything.
                try:
                    with Daemon(fresh, "auditd", "audit-submit", account="azaudit",
                                ready_path=fresh.root / "never-ready"):
                        raise AssertionError("a second auditd started")
                except RuntimeError as refused:
                    assert "another audit writer holds the chain" in str(refused), refused
                code, result = _import(fresh, _bundle(fresh.keys["bundle"], "site-bundle", 5))
                assert code == 0 and result["outcome"] == "admitted", result
                assert _status(fresh) == "available"
                # Rotation: the pin and its anchor, together.
                _place(fresh, "repin-anchor.json", json.dumps({
                    "keys": [_public(fresh.keys["next"])],
                    "anchors": {"keys": {"site-bundle-2": _public(fresh.keys["next"])},
                                "threshold": 1},
                }).encode())
                repinned = _python(fresh, _REPIN)
                assert repinned.returncode == 0, repinned.stdout + repinned.stderr[-300:]
                assert "Trust anchors replaced; generation 1." in repinned.stdout
                assert _status(fresh) != "available"
                code, result = _import(fresh, _bundle(fresh.keys["next"], "site-bundle-2", 6))
                assert code == 0 and result["bundle_version"] == 6, result
                assert _status(fresh) == "available"
                # Revocation of generation 6 by the enrolled authority.
                statement = RevocationList(sequence=1, issued_at="2026-10-30T00:00:00Z",
                                           revoked_generations=frozenset({6}))
                _place(fresh, "lite-revocations.signed",
                       fresh.keys["revoker"].sign(statement.signature_target()).signature
                       + statement.as_payload())
                revoked = _python(fresh, _REVOKE)
                assert revoked.returncode == 0, revoked.stdout + revoked.stderr[-300:]
                assert _status(fresh) == "revoked"
            # auditd stopped: an import is refused before any change.
            before = {p: p.read_bytes() for p in store.rglob("*")
                      if p.is_file() and "inbox" not in p.parts}
            replacement = _bundle(fresh.keys["next"], "site-bundle-2", 7)
            code, result = _import(fresh, replacement)
            assert code == 1 and (result["outcome"], result["refused"]) == (
                "refused", "audit_unavailable"), result
            assert {p: p.read_bytes() for p in store.rglob("*")
                    if p.is_file() and "inbox" not in p.parts} == before
            assert _status(fresh) == "revoked"
            # So is a trust change.
            assert _python(fresh, _REVOKE).returncode == 1
            with Daemon(fresh, "auditd", "audit", account="azaudit"):
                code, result = _import(fresh, replacement)
                assert code == 0 and result["bundle_version"] == 7, result
                assert _status(fresh) == "available"
        kinds = _chain(fresh)
        for earlier, later in (
                ("knowledge.lite.trust_repin_requested", "knowledge.lite.trust_repin_promoted"),
                ("knowledge.lite.revocation_requested", "knowledge.lite.revocation_accepted")):
            assert kinds.index(earlier) < kinds.index(later), kinds
        assert kinds.count("knowledge.lite.import_admitted") == 3, kinds
    finally:
        shutil.rmtree(fresh.root, ignore_errors=True)
    return ("import, key rotation with its anchor, revocation and recovery through the real "
            "CLI and daemons; with auditd stopped an import and a trust change were refused "
            "before any change; a second auditd refused the chain; the chain verifies")
