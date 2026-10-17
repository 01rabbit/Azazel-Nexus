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

UNITS = {
    "azazel-mio-entryd": ("mio-entry", "azmioentry", "mio.route",
                          {"privacy_class": "P0-public", "deadline_ms": 1000}),
    "azazel-knowledge-lited": ("knowledge", "azknowledge", "knowledge.status", {}),
}
SHOW = (
    "ActiveState", "SubState", "MainPID", "User", "Group", "SupplementaryGroups",
    "RestrictAddressFamilies", "ReadWritePaths", "ReadOnlyPaths", "CapabilityBoundingSet",
    "AmbientCapabilities", "NoNewPrivileges", "ProtectSystem", "ProtectHome",
    "PrivateNetwork", "IPAddressDeny", "RuntimeDirectory", "RuntimeDirectoryMode",
    "RuntimeDirectoryPreserve", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectControlGroups", "RestrictNamespaces",
    "RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute",
    "SystemCallArchitectures", "SystemCallFilter", "UMask",
)


# Occurrences stay ordered: systemd-run applies each assignment, including resets.
Properties = list[tuple[str, str]]
PATH_KEYS = {"ReadWritePaths", "ReadOnlyPaths"}
SET_KEYS = {"SupplementaryGroups", "RestrictAddressFamilies", "CapabilityBoundingSet",
            "AmbientCapabilities", "SystemCallArchitectures", "RuntimeDirectory"}
BOOL_KEYS = {key for key in SHOW if key.startswith(("Private", "Protect", "Restrict"))} | {
    "NoNewPrivileges", "LockPersonality", "MemoryDenyWriteExecute"}


def parse_service(text: str) -> Properties:
    """Preserve assignments verbatim; refuse executable hooks and specifiers."""
    properties = []
    section = pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line, pending = pending + line, ""
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        # Reject even Unit/Install specifiers rather than hiding a semantic delta.
        if "%" in value:
            raise ValueError("unit specifiers are unsupported")
        if section != "Service":
            continue
        if not separator or not key or not key.isalnum():
            raise ValueError("malformed Service directive")
        if key.startswith("Exec") and key != "ExecStart":
            raise ValueError("Exec hooks are unsupported")
        properties.append((key, value))
    if (pending or len([v for k, v in properties if k == "ExecStart"]) != 1
            or not dict(properties).get("ExecStart") or not dict(properties).get("User")):
        raise ValueError("incomplete or ambiguous Service section")
    return properties


def relocate(properties: Properties, scratch: Path, name: str) -> Properties:
    """Only state paths, the private runtime directory and startup protocol differ."""
    from azazel_nexus.layout import spec_for

    result = []
    for key, value in properties:
        if key in PATH_KEYS:
            paths = []
            for token in shlex.split(value):
                prefix = token[:len(token) - len(token.lstrip("-+"))]
                path = token[len(prefix):]
                if not spec_for(path) or not path.startswith("/var/lib/azazel/"):
                    raise ValueError("path is outside the installer layout")
                paths.append(prefix + str(scratch / path.lstrip("/")))
            value = " ".join(paths)
        elif key == "RuntimeDirectory":
            value = "azazel-smoke-" + name
        elif key == "Type":
            # runtime_ready_callback deliberately emits no READY under AZAZEL_ROOT.
            if value != "notify":
                raise ValueError("unexpected service startup protocol")
            value = "exec"
        elif key in {"Environment", "EnvironmentFile", "PassEnvironment", "UnsetEnvironment",
                     "RootDirectory", "RootImage", "WorkingDirectory", "StateDirectory",
                     "CacheDirectory", "LogsDirectory", "ConfigurationDirectory",
                     "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem",
                     "StandardOutput", "StandardError", "PIDFile"}:
            raise ValueError("unreviewed path or environment directive")
        result.append((key, value))
    if not dict(result).get("RuntimeDirectory"):
        raise ValueError("RuntimeDirectory required")
    result.append(("Environment", "AZAZEL_ROOT=" + str(scratch)))
    return result


def build_command(name: str, properties: Properties) -> list[str]:
    if name not in UNITS:
        raise ValueError("unknown smoke unit")
    # Validate again for callers that did not use parse_service.
    properties = parse_service("[Service]\n" + "\n".join(f"{k}={v}" for k, v in properties))
    command = shlex.split(dict(properties)["ExecStart"])
    if (not command or not command[0].startswith("/")
            or command[0].startswith(("-", "+", "!", "@", ":"))):
        raise ValueError("ExecStart must be a literal absolute command")
    argv = ["systemd-run", "--unit=azazel-smoke-" + name, "--no-block", "--collect"]
    return [*argv, *[f"--property={k}={v}" for k, v in properties if k != "ExecStart"],
            "--", *command]


def normalise(key: str, value: str, syscall_groups: dict | None = None):
    """Normalise show's encodings, without erasing list inversion or path flags."""
    if key == "UMask" or key.endswith("DirectoryMode"):
        return int(value, 8)
    if key in BOOL_KEYS and value in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
        return value in {"1", "true", "yes", "on"}
    if key == "IPAddressDeny":
        return frozenset({"0.0.0.0/0", "::/0"} if value == "any" else value.split())
    if key in SET_KEYS or key in PATH_KEYS or key == "SystemCallFilter":
        inverted = value.startswith("~")
        words = shlex.split(value[1:] if inverted else value)
        if key == "SystemCallFilter" and syscall_groups is not None:
            words = [syscall for word in words for syscall in syscall_groups.get(word, {word})]
        if key == "SystemCallArchitectures":
            native = {"x86_64": "x86-64", "aarch64": "arm64", "arm64": "arm64"}.get(
                platform.machine(), platform.machine())
            words = [native if word == "native" else word for word in words]
        if key in PATH_KEYS:
            paths = []
            for word in words:
                path = word.lstrip("-+")
                flags = word[:len(word) - len(path)]
                paths.append("".join(sorted(set(flags))) + str(Path(path)))
            words = paths
        if key in {"CapabilityBoundingSet", "AmbientCapabilities"}:
            words = [word.lower() for word in words]
        return inverted, frozenset(words)
    return value


def expected_properties(properties: Properties) -> dict[str, str]:
    result = {}
    for key, value in properties:
        if key == "ExecStart":
            continue
        if key in SET_KEYS | PATH_KEYS | {"SystemCallFilter", "IPAddressDeny", "Environment"}:
            if not value:
                result[key] = ""
            elif key in {"CapabilityBoundingSet", "RestrictAddressFamilies", "SystemCallFilter"}:
                # Mixed positive/inverse repetitions require systemd's algebra.
                # Refuse rather than guess the resulting sandbox.
                old = result.get(key, "")
                if old and old.startswith("~") != value.startswith("~"):
                    raise ValueError("mixed inverted assignments require review")
                result[key] = ("~" if value.startswith("~") else "") + " ".join(
                    part.lstrip("~") for part in (old, value) if part)
            else:
                result[key] = " ".join(part for part in (result.get(key, ""), value) if part)
        else:
            result[key] = value
    return result


def compare_properties(properties: Properties, observed: dict[str, str],
                       syscall_groups: dict | None = None) -> list[str]:
    return [key for key, value in expected_properties(properties).items()
            if key not in observed or normalise(key, value, syscall_groups)
            != normalise(key, observed[key], syscall_groups)]


def expand_syscall_groups(properties: Properties, observed: dict[str, str]) -> dict:
    """Use this host's systemd definitions, including recursively nested groups."""
    groups = {}
    pending = set()

    def expand(group):
        if group in pending:
            raise ValueError("recursive syscall group")
        if group in groups:
            return groups[group]
        pending.add(group)
        lines = run(["systemd-analyze", "syscall-filter", group]).splitlines()
        names = set()
        for line in lines:
            word = line.strip()
            if not word or word.startswith("#") or word == group:
                continue
            if len(word.split()) != 1:
                raise ValueError("unrecognised syscall-filter representation")
            names.update(expand(word) if word.startswith("@") else {word})
        if not names:
            raise ValueError("empty syscall group expansion")
        pending.remove(group)
        groups[group] = names
        return names

    values = [value for key, value in properties if key == "SystemCallFilter"]
    for value in [*values, observed.get("SystemCallFilter", "")]:
        for word in value.lstrip("~").split():
            if word.startswith("@"):
                expand(word)
    return groups


def create_scratch_tree(scratch: Path, properties: Properties) -> None:
    from azazel_nexus.layout import LAYOUT

    leaves = {token.lstrip("-+") for key, value in properties if key in PATH_KEYS
              for token in shlex.split(value)}
    specs = [spec for spec in LAYOUT
             if any(leaf == spec.path or leaf.startswith(spec.path + "/") for leaf in leaves)]
    scratch.chmod(0o755)  # system accounts must traverse the unique root
    # The installer relies on the OS-owned /var and /var/lib ancestors. Their
    # scratch equivalents must not inherit the invoking root shell's umask.
    for relative in ("var", "var/lib"):
        parent = scratch / relative
        parent.mkdir(exist_ok=True)
        os.chown(parent, 0, 0)
        parent.chmod(0o755)
    for spec in sorted(specs, key=lambda item: item.path.count("/")):
        target = scratch / spec.path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)
        os.chown(target, pwd.getpwnam(spec.owner).pw_uid, grp.getgrnam(spec.group).gr_gid)
        target.chmod(spec.mode)  # chown can clear setgid


# Snapshot every real state surface, including absent roots and directory metadata.
REAL_DIRECTORIES = tuple(map(Path, (
    "/var/lib/azazel/state/mio", "/var/lib/azazel/state/knowledge",
    "/var/lib/azazel/run", "/var/lib/azazel/knowledge",
    "/var/lib/azazel/lite-trust", "/run/azazel",
)))
HASH_LIMIT = 8 * 1024 * 1024


def require_strict(properties: Properties) -> None:
    # full leaves /var writable; only strict provides the required default deny.
    if expected_properties(properties).get("ProtectSystem") != "strict":
        raise ValueError("ProtectSystem=strict required")


def assert_write_isolation(observed: dict[str, str], scratch: Path,
                           private_runtime: Path) -> None:
    """Check effective mount exceptions, separately from property equality."""
    if observed.get("ProtectSystem") != "strict":
        raise ValueError("effective ProtectSystem=strict required")
    if "ReadWritePaths" not in observed:
        raise ValueError("effective ReadWritePaths missing")
    if shlex.split(observed.get("RuntimeDirectory", "")) != [private_runtime.name]:
        raise ValueError("effective RuntimeDirectory is not private")
    for token in shlex.split(observed["ReadWritePaths"]):
        path = Path(token.lstrip("-+"))
        if (not path.is_absolute() or ".." in path.parts
                or not (path.resolve().is_relative_to(scratch.resolve())
                        or path == private_runtime and path.resolve() == private_runtime)):
            raise ValueError("effective ReadWritePaths outside scratch/private runtime: " + token)


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
            relocated, observed, expand_syscall_groups(relocated, observed))
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
