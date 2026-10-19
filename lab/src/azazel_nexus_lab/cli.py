"""Owner-visible VM demonstration. All terminal output is explicitly labelled."""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from azazel_nexus.audit import AuditLedger
from azazel_nexus.lab_host import LAB_HOST_MARKER

from . import services
from .artifacts import BANNER, canonical, create_key, envelope, output, shred_keys
from .provision import provision

BASE = Path("/var/lib/azazel-lab")


def lab_root(identifier):
    if not re.fullmatch(r"[a-z0-9]{1,12}", identifier):
        raise ValueError("lab id must be 1-12 lowercase ASCII letters/digits")
    if BASE.is_symlink() or BASE.resolve() != BASE:
        raise ValueError("lab base must not contain symlinks")
    root = BASE / identifier
    if root.is_symlink() or root.resolve() != root:
        raise ValueError("lab root must not contain symlinks")
    return root


def secure_directory(path, mode):
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("unsafe lab directory")


def mark_host():
    secure_directory(LAB_HOST_MARKER.parent, 0o755)
    fd = os.open(LAB_HOST_MARKER, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o644)
    with os.fdopen(fd, "wb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise ValueError("unsafe lab marker")
        os.fchmod(stream.fileno(), 0o644)
        stream.write((BANNER + "\n").encode())
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def worker(root, operation, *args):
    process = subprocess.run(
        [sys.executable, "-m", "azazel_nexus_lab.worker", operation, *map(str, args)],
        env={**os.environ, "AZAZEL_ROOT": str(root), "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True, text=True, timeout=30, check=False,
    )
    return {"exit_code": process.returncode, "stdout": process.stdout, "stderr": process.stderr}


def masked_snapshot():
    from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT, CORE_UNITS

    names = {ACTIVATION_CONTROLLER_UNIT, *(item.name for item in CORE_UNITS),
             *(name + ".service" for name in services.UNITS)}
    snapshot = {name: services.show(name, ("ActiveState", "UnitFileState")) for name in sorted(names)}
    if any(row.get("ActiveState") not in {"inactive", "failed"}
           or row.get("UnitFileState") not in {"masked", "masked-runtime"}
           for row in snapshot.values()):
        raise ValueError("all production units must already be masked and stopped")
    # The only lease surface read is the fixed activation approval store. No
    # live authority transport is implemented in this build; never invent one.
    approval = Path("/etc/azazel/activation")
    metadata = {}
    for name in ("approval.json", "approval.sig"):
        path = approval / name
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            metadata[name] = None
            continue
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                raise ValueError("unsafe activation approval snapshot")
            metadata[name] = hashlib.sha256(stream.read(65537)).hexdigest()
    return {"production_units": snapshot, "activation_approval_sha256": metadata,
            "live_edge_authority": "unobserved (no live authority transport)",
            "live_lease": "unobserved (no live authority transport)"}


def fix_fixture_permissions(root):
    knowledge_uid = pwd.getpwnam("azknowledge").pw_uid
    knowledge_gid = grp.getgrnam("azknowledge").gr_gid
    for relative in ("var/lib/azazel/knowledge", "var/lib/azazel/lite-trust"):
        directory = root / relative
        for path in [directory, *directory.rglob("*")]:
            os.chown(path, knowledge_uid if relative.endswith("knowledge") else 0, knowledge_gid)
            path.chmod(0o750 if path.is_dir() else 0o640)


def up(root):
    if platform.system() != "Linux":
        raise ValueError("Debian 13 root test VM required")
    release = platform.freedesktop_os_release()
    if (release.get("ID"), release.get("VERSION_ID")) != ("debian", "13"):
        raise ValueError("Debian 13 root test VM required")
    before = masked_snapshot()
    if root.exists():
        raise ValueError("lab id already exists; use down first")
    secure_directory(BASE, 0o755)
    root.mkdir(mode=0o755)
    mark_host()
    attempted = False
    try:
        props = services.prepare(root)
        key = create_key(root / "keys")
        fixture = provision(root, key)
        fix_fixture_permissions(root)
        # This is a real CLI refusal, retained verbatim inside a lab transcript.
        # A lab namespace/domain must never be accepted as a production pack.
        pack = worker(root, "pack-inspect")
        if pack["exit_code"] == 0:
            raise ValueError("production CLI unexpectedly accepted a lab pack")
        attempted = True
        units = services.start(root, props)
        after = masked_snapshot()
        if after != before:
            raise ValueError("production authority/lease snapshot changed")
        result = output(state="degraded", root=str(root), fixture=fixture, units=units,
                        pack_cli=pack, unchanged_edge_snapshot=after,
                        limitation="Mission Pack fixture promotion requires a design decision; "
                        "production resource/encryption/architecture gates were not bypassed")
        (root / "session.lab-signed").write_bytes(envelope(canonical(result), key, "session"))
        (root / "session.json").write_bytes(canonical(result))
        return result
    except Exception:
        if attempted:
            services.stop(root)
        shred_keys(root / "keys")
        shutil.rmtree(root)
        raise


def audit(root):
    chains = {}
    for name, relative in {
        "route": "var/lib/azazel/state/mio/route.jsonl",
        "local": "var/lib/azazel/mio/local.jsonl", "lite-import": "lite-import.jsonl",
    }.items():
        path = root / relative
        if not path.is_file():
            chains[name] = {"state": "absent"}
            continue
        ledger = AuditLedger(path)
        ledger.verify()
        chains[name] = {"state": "verified", "head": ledger.head()}
    # knowledge_lited emits per-daemon events, not AuditLedger chain entries.
    # Check JSON framing without presenting it as a verified hash chain.
    events = root / "var/lib/azazel/state/knowledge/refusals.jsonl"
    rows = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
    chains["knowledge"] = {"state": "unhashed-event-log", "events": len(rows)}
    return output(ledgers=chains)


def break_target(root, target):
    before = masked_snapshot()
    detail = "applied"
    try:
        if target == "knowledge-trust":
            (root / "var/lib/azazel/lite-trust/trust.json").write_text("{}\n")
        elif target == "locald":
            services.run(["systemctl", "stop", services.prefix(root) + "azazel-mio-locald.service"])
        elif target == "pack-expire":
            # No active pack was admitted. Never manufacture a native signed
            # admission record to make this break appear successful.
            detail = "unavailable: no active lab pack selection"
        else:
            with (root / "var/lib/azazel/state/mio/route.jsonl").open("a") as stream:
                stream.write('{"tampered":true}\n')
    finally:
        after = masked_snapshot()
        print(json.dumps(output(unchanged_edge_snapshot=after, unchanged=before == after),
                         ensure_ascii=False, sort_keys=True))
    if after != before:
        raise ValueError("production authority/lease snapshot changed")
    return output(target=target, result=detail)


def down(root):
    if not root.exists():
        return output(state="down", marker_retained=True)
    services.stop(root)
    shred_keys(root / "keys")
    shutil.rmtree(root)
    return output(state="down", marker_retained=True)


def main(argv=None):
    print(BANNER, flush=True)
    parser = argparse.ArgumentParser(prog="az-nexus-lab", description=__doc__)
    parser.add_argument("--id", default="demo")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "status", "audit", "down"):
        commands.add_parser(name)
    commands.add_parser("knowledge").add_argument("technique")
    commands.add_parser("ask").add_argument("scenario", type=Path)
    commands.add_parser("break").add_argument("target", choices=(
        "knowledge-trust", "locald", "pack-expire", "audit-tamper"))
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ValueError("root required")
        root = lab_root(args.id)
        if args.command not in {"up", "down"} and not (root / "session.json").is_file():
            raise ValueError("lab is not up")
        if args.command == "up":
            result = up(root)
        elif args.command == "down":
            result = down(root)
        elif args.command == "status":
            result = output(status=worker(root, "status"), setup=worker(root, "setup"))
        elif args.command == "audit":
            result = audit(root)
        elif args.command == "break":
            result = break_target(root, args.target)
        else:
            argument = args.scenario.resolve() if args.command == "ask" else args.technique
            result = output(**{args.command: worker(root, args.command, argument)})
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 1 if result.get("state") == "degraded" else 0
    except Exception as error:  # noqa: BLE001 - no untrusted payload or key in diagnostics
        print(json.dumps(output(state="refused", error_type=type(error).__name__), sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
