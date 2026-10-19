"""Opt-in Debian 13 root smoke of parsed service properties; never a CI test."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import platform
import pwd
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from azazel_nexus_runtime.unit_relocation import (
    assert_write_isolation,
    build_command,
    create_scratch_tree,
    parse_service,
    relocate,
    require_strict,
)

UNITS = {
    "azazel-mio-entryd": ("mio-entry", "azmioentry", "mio.route",
                          {"privacy_class": "P0-public", "deadline_ms": 1000}),
    "azazel-knowledge-lited": ("knowledge", "azknowledge", "knowledge.status", {}),
}
# Preserve the smoke tool's public seams while sharing verification with lab.
from azazel_nexus_runtime import unit_sandbox as sandbox
from azazel_nexus_runtime.unit_sandbox import (
    SHOW,
    expected_properties,
    native_unknown_syscalls,
)

DANGEROUS_SYSCALL_GROUPS = sandbox.DANGEROUS_SYSCALL_GROUPS
SYSCALL_DIFFERENCE_LIMIT = sandbox.SYSCALL_DIFFERENCE_LIMIT
ctypes = sandbox.ctypes


def expand_syscall_groups(properties, observed):
    return sandbox.expand_syscall_groups(properties, observed, runner=run)


def compare_syscall_filter(properties, shown, groups):
    return sandbox.compare_syscall_filter(properties, shown, groups,
                                          native_resolver=native_unknown_syscalls)


def compare_properties(properties, observed, syscall_groups=None, evidence=None):
    if syscall_groups is None and any(key == "SystemCallFilter" for key, _ in properties):
        syscall_groups = expand_syscall_groups(properties, observed)
    return sandbox.compare_properties(properties, observed, syscall_groups, evidence,
                                      native_resolver=native_unknown_syscalls)


# Snapshot every real state surface, including absent roots and directory metadata.
REAL_DIRECTORIES = tuple(map(Path, (
    "/var/lib/azazel/state/mio", "/var/lib/azazel/state/knowledge",
    "/var/lib/azazel/run", "/var/lib/azazel/knowledge",
    "/var/lib/azazel/lite-trust", "/run/azazel",
    "/data/azazel/mission-packs", "/etc/azazel/mission-pack.json",
)))
HASH_LIMIT = 8 * 1024 * 1024


def snapshot_directories(roots: tuple[Path, ...] = REAL_DIRECTORIES) -> dict:
    """lstat recursively without following symlinks or reading special files.

    Hash regular files up to HASH_LIMIT; larger files retain all metadata.
    Concurrent removal or mutation during traversal/hashing fails closed.
    """
    snapshot = {}

    def signature(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def visit(path, info):
        record = {"path": str(path), "inode": info.st_ino, "mode": info.st_mode,
                  "uid": info.st_uid, "gid": info.st_gid, "size": info.st_size,
                  "mtime_ns": info.st_mtime_ns}
        snapshot[str(path)] = record
        if stat.S_ISLNK(info.st_mode):
            record["symlink_target"] = os.readlink(path)
        elif stat.S_ISREG(info.st_mode) and info.st_size <= HASH_LIMIT:
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
                if signature(os.fstat(stream.fileno())) != signature(info):
                    raise ValueError("file changed during snapshot: " + str(path))
                data = stream.read(HASH_LIMIT + 1)
                if len(data) != info.st_size:
                    raise ValueError("file changed during snapshot: " + str(path))
                record["sha256"] = hashlib.sha256(data).hexdigest()
                if signature(os.fstat(stream.fileno())) != signature(info):
                    raise ValueError("file changed during snapshot: " + str(path))
        elif stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child, child.lstat())
        if signature(path.lstat()) != signature(info):
            raise ValueError("path changed during snapshot: " + str(path))

    for root in roots:
        try:
            info = root.lstat()
        except FileNotFoundError:
            snapshot[str(root)] = None
        else:
            visit(root, info)
    return snapshot


def snapshot_diff(before: dict, after: dict) -> dict[str, list[str]]:
    differences = {}
    for path in sorted(before.keys() | after.keys()):
        if path not in before or path not in after:
            differences[path] = ["added" if path in after else "removed"]
        elif before[path] != after[path]:
            old, new = before[path], after[path]
            differences[path] = (["created" if old is None else "deleted"]
                                 if old is None or new is None else
                                 sorted(key for key in old.keys() | new.keys()
                                        if old.get(key) != new.get(key)))
    return differences


class SmokeFailure(ValueError):
    def __init__(self, evidence):
        super().__init__("smoke failed; see evidence")
        self.evidence = evidence


def installed_unit(name: str) -> Path:
    for base in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        path = Path(base) / (name + ".service")
        if path.is_file():  # skips the normal /dev/null mask
            return path
    raise ValueError("installed unit file missing; install the reviewed build first")


def run(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=20).stdout


def show(unit: str, fields: tuple[str, ...]) -> dict[str, str]:
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=LoadState",
         *["--property=" + key for key in fields]],
        check=False, capture_output=True, text=True, timeout=20,
    )
    observed = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode and observed.get("LoadState") != "not-found":
        raise ValueError("systemctl show failed")
    return observed


def smoke(name: str) -> dict:
    if os.geteuid() != 0 or os.environ.get("CI") or os.environ.get("AZAZEL_ROOT"):
        raise ValueError("requires root on the test VM, outside CI, without AZAZEL_ROOT")
    if platform.system() != "Linux":
        raise ValueError("requires Debian 13")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "debian" or release.get("VERSION_ID") != "13":
        raise ValueError("requires Debian 13")
    path = installed_unit(name)
    # A base file alone cannot faithfully reproduce drop-in overrides.
    if show(name + ".service", ("DropInPaths",)).get("DropInPaths"):
        raise ValueError("installed drop-ins present; reconcile the base unit before smoke")
    from azazel_nexus_runtime.startup_wrapper import parse_wrapper

    leaf, account, verb, arguments = UNITS[name]
    properties = parse_service(path.read_text())
    if dict(properties)["User"] != account:
        raise ValueError("installed service account differs from the contract")
    transient = "azazel-smoke-" + name + ".service"
    if show(transient, ("ActiveState",)).get("ActiveState") not in {"inactive", "failed"}:
        raise ValueError("transient already active or transitioning")
    private_runtime = Path("/run") / transient.removesuffix(".service")
    if private_runtime.exists():
        raise ValueError("private runtime directory already present")
    real_units = tuple(unit + ".service" for unit in (*UNITS, "azazel-activated"))
    before = {unit: show(unit, ("ActiveState",)).get("ActiveState") for unit in real_units}
    require_strict(properties)
    snapshot_before = snapshot_directories()
    evidence = {"unit": name, "transient": transient, "source": str(path),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "service_directives": properties, "real_units_before": before,
                "real_paths_before": snapshot_before, "snapshot_hash_limit": HASH_LIMIT,
                "relocation_reason": "isolate sockets, store, trust and M.I.O. ledger; no activation",
                "activation_dependencies_applied": False,
                "startup_override": "Type=exec: AZAZEL_ROOT suppresses READY notification"}
    scratch = None
    socket_path = None
    primary = None
    cleanup_errors = []
    attempted_start = False
    try:
        target = "azazel_nexus_runtime." + ("mio_entryd" if leaf == "mio-entry" else "knowledge_lited")
        command = shlex.split(dict(properties)["ExecStart"])
        if len(command) != 1:
            raise ValueError("only canonical installed wrappers supported")
        interpreter, roots = parse_wrapper(Path(command[0]).read_bytes(), target=target + ":main")
        # /run is visible with PrivateTmp=yes; use a fresh root outside /run/azazel.
        scratch = Path(tempfile.mkdtemp(prefix="azsm-", dir="/run"))
        evidence["scratch_root"] = str(scratch)
        create_scratch_tree(scratch, properties)
        relocated = relocate(properties, scratch, name)
        expected = expected_properties(relocated)
        evidence["relocated_directives"] = relocated
        socket_path = scratch / "var/lib/azazel/run" / leaf / (leaf + ".sock")
        if len(os.fsencode(socket_path)) >= 108:
            raise ValueError("scratch socket exceeds Linux AF_UNIX limit")
        attempted_start = True
        run(build_command(name, relocated))
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            if time.monotonic() >= deadline:
                raise ValueError("socket startup deadline expired")
            time.sleep(0.05)
        observed = show(transient, tuple({*SHOW, *expected}))
        evidence["observed"] = observed
        assert_write_isolation(observed, scratch, private_runtime)
        evidence["write_isolation_verified"] = True
        evidence["property_mismatches"] = compare_properties(
            relocated, observed, evidence=evidence)
        if evidence["property_mismatches"]:
            raise ValueError("effective service properties differ")
        # A child gets a fresh import-time ROOT, even if this process imported
        # runtime_paths earlier. The existing bounded client verifies credentials.
        client = f"import sys; sys.path = {list(roots)!r}; sys.dont_write_bytecode = True\n" + """import json, os, sys
os.setegid(int(sys.argv[1]))
from azazel_nexus_runtime.mio_socket_client import _exchange
print(json.dumps(_exchange(sys.argv[2], sys.argv[3], sys.argv[4], json.loads(sys.argv[5]))))
"""
        operator_gid = grp.getgrnam("azazel-operator").gr_gid
        reply = json.loads(subprocess.run(
            [interpreter, "-IS", "-c", client, str(operator_gid), leaf, account, verb,
             json.dumps(arguments)], check=True, capture_output=True, text=True, timeout=20,
            env={**os.environ, "AZAZEL_ROOT": str(scratch), "PYTHONDONTWRITEBYTECODE": "1"},
        ).stdout)
        validate_reply(name, reply)
        pid = int(observed["MainPID"])
        expected_uid = pwd.getpwnam(account).pw_uid
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        if observed["ActiveState"] != "active" or set(map(int, uid_line.split()[1:])) != {expected_uid}:
            raise ValueError("daemon is not active under the declared account")
        evidence.update(reply=reply, main_pid_uid=expected_uid,
                        client_uid=os.geteuid(), client_gid=operator_gid)
    except Exception as error:  # noqa: BLE001 - preserve the first failure through cleanup
        primary = error
    finally:
        if attempted_start:
            for action in ("stop", "reset-failed"):
                try:
                    run(["systemctl", action, transient])
                except Exception as error:  # noqa: BLE001
                    try:
                        collected = show(transient, ("ActiveState",)).get("LoadState") == "not-found"
                    except Exception:  # noqa: BLE001 - cleanup must never replace the primary error
                        collected = False
                    if not collected:
                        cleanup_errors.append(action + ":" + type(error).__name__)
        try:
            after = {unit: show(unit, ("ActiveState",)).get("ActiveState") for unit in real_units}
            evidence["real_units_after"] = after
            if before != after:
                cleanup_errors.append("verify:real_unit_state_changed")
        except Exception as error:  # noqa: BLE001
            cleanup_errors.append("real_units:" + type(error).__name__)
        try:
            evidence["real_paths_after"] = snapshot_directories()
            evidence["real_path_differences"] = snapshot_diff(
                snapshot_before, evidence["real_paths_after"])
            if evidence["real_path_differences"]:
                cleanup_errors.append("verify:real_paths_changed")
        except Exception as error:  # noqa: BLE001
            cleanup_errors.append("snapshot:" + type(error).__name__)
        evidence["leftover_unit"] = "unknown"
        evidence["leftover_runtime_directory"] = "unknown"
        try:
            remaining = show(transient, ("ActiveState",))
            deadline = time.monotonic() + 2
            while attempted_start and remaining.get("LoadState") != "not-found" and time.monotonic() < deadline:
                time.sleep(0.05)
                remaining = show(transient, ("ActiveState",))
            evidence["leftover_unit"] = remaining.get("LoadState") != "not-found"
            evidence["socket_before_scratch_cleanup"] = bool(socket_path and socket_path.exists())
            evidence["leftover_runtime_directory"] = private_runtime.exists()
        except Exception as error:  # noqa: BLE001
            cleanup_errors.append("verify:" + type(error).__name__)
        if scratch and (not attempted_start or not evidence.get("leftover_unit", True)):
            try:
                shutil.rmtree(scratch)
            except OSError as error:
                cleanup_errors.append("scratch:" + type(error).__name__)
        for key, candidate in (("scratch_leftover", scratch), ("leftover_socket", socket_path)):
            try:
                exists = bool(candidate and candidate.exists())
                evidence[key] = str(candidate) if key == "scratch_leftover" and exists else exists
            except Exception as error:  # noqa: BLE001
                evidence[key] = "unknown"
                cleanup_errors.append(key + ":" + type(error).__name__)
        evidence["cleanup_errors"] = cleanup_errors
    if primary:
        evidence["error_type"] = type(primary).__name__
        raise SmokeFailure(evidence) from primary
    if (cleanup_errors or evidence.get("leftover_unit") or evidence.get("leftover_socket")
            or evidence.get("leftover_runtime_directory") or evidence.get("scratch_leftover")):
        evidence["error_type"] = "CleanupFailure"
        raise SmokeFailure(evidence)
    return evidence


def validate_reply(name: str, reply: dict) -> None:
    if name == "azazel-mio-entryd":
        if (set(reply) != {"route", "outcome", "reason", "ledger_seq"}
                or reply["route"] != "deterministic handoff" or reply["outcome"] != "refused"
                or not isinstance(reply["reason"], str) or not 0 < len(reply["reason"]) <= 4096
                or type(reply["ledger_seq"]) is not int or reply["ledger_seq"] < 1):
            raise ValueError("unexpected route response")
    elif (set(reply) != {"state", "reason_code", "generation", "freshness"}
          or reply["state"] not in {"available", "stale", "unavailable", "quarantined"}
          or not isinstance(reply["reason_code"], str) or not 0 < len(reply["reason_code"]) <= 64
          or reply["freshness"] not in {"current", "stale", "absent"}
          or (reply["generation"] is not None and (type(reply["generation"]) is not int
                                                   or not 0 <= reply["generation"] < 2**63))):
        raise ValueError("unexpected Knowledge response")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unit", choices=UNITS)
    args = parser.parse_args()
    try:
        evidence = smoke(args.unit)
    except SmokeFailure as error:
        print(json.dumps({"ok": False, **error.evidence}, sort_keys=True))
        return 1
    except Exception as error:  # noqa: BLE001 - never disclose local configuration or reply text
        print(json.dumps({"unit": args.unit, "ok": False, "error_type": type(error).__name__}))
        return 1
    print(json.dumps({"ok": True, **evidence}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
