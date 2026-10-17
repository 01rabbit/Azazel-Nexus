"""Opt-in Debian 13 root smoke of parsed service properties; never a CI test."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import shlex
import subprocess
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


def parse_service(text: str) -> dict[str, str]:
    """Retain every Service directive, joining repeated lists and honoring resets.

    Unknown directives are passed through: systemd-run must reject unsupported
    transient properties, rather than silently dropping a sandbox restriction.
    """
    properties = {}
    section = ""
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        line = pending + line
        pending = ""
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section != "Service":
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key:
            raise ValueError("malformed Service directive")
        if key == "ExecStart" and properties.get(key) and value:
            raise ValueError("multiple ExecStart commands are unsupported")
        properties[key] = (properties[key] + " " + value
                           if value and properties.get(key) else value)
    if pending or not properties.get("ExecStart") or not properties.get("User"):
        raise ValueError("incomplete Service section")
    return properties


def build_command(name: str, properties: dict[str, str]) -> list[str]:
    if name not in UNITS:
        raise ValueError("unknown smoke unit")
    command = shlex.split(properties["ExecStart"])
    if not command or not command[0].startswith("/") or any("%" in s for s in command):
        raise ValueError("ExecStart must be a literal absolute command")
    argv = ["systemd-run", "--unit=azazel-smoke-" + name, "--no-block"]
    for key, value in properties.items():
        if key != "ExecStart":
            argv.append(f"--property={key}={value}")
    # The installed services share /run/azazel. A smoke stop must retain it.
    argv.append("--property=RuntimeDirectoryPreserve=yes")
    return [*argv, "--", *command]


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
    import platform
    if platform.system() != "Linux":
        raise ValueError("requires Debian 13")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "debian" or release.get("VERSION_ID") != "13":
        raise ValueError("requires Debian 13")
    path = installed_unit(name)
    # A base file alone cannot faithfully reproduce drop-in overrides.
    if show(name + ".service", ("DropInPaths",)).get("DropInPaths"):
        raise ValueError("installed drop-ins present; reconcile the base unit before smoke")
    leaf, account, verb, arguments = UNITS[name]
    properties = parse_service(path.read_text())
    if properties["User"] != account:
        raise ValueError("installed service account differs from the contract")
    socket_path = Path("/var/lib/azazel/run") / leaf / (leaf + ".sock")
    transient = "azazel-smoke-" + name + ".service"
    for unit in (name + ".service", transient):
        state = show(unit, ("ActiveState",)).get("ActiveState")
        if state not in {"inactive", "failed"}:
            raise ValueError("unit already active or transitioning")
    if socket_path.exists():
        raise ValueError("socket already present; inspect it before smoke")
    evidence = {"unit": name, "transient": transient, "source": str(path),
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "service_directives": sorted(properties),
                "runtime_directory_preserve_override": "yes"}
    try:
        run(build_command(name, properties))
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            if time.monotonic() >= deadline:
                raise ValueError("socket startup deadline expired")
            time.sleep(0.05)
        # Existing client bounds framing, verifies socket owner/group and SO_PEERCRED.
        from azazel_nexus_runtime.mio_socket_client import _exchange
        # UID stays root; the verbs admit OPERATOR, not ROOT by itself.
        original_gid = os.getegid()
        operator_gid = grp.getgrnam("azazel-operator").gr_gid
        try:
            os.setegid(operator_gid)
            reply = _exchange(leaf, account, verb, arguments)
        finally:
            os.setegid(original_gid)
        validate_reply(name, reply)
        observed = show(transient, SHOW)
        pid = int(observed["MainPID"])
        expected_uid = pwd.getpwnam(account).pw_uid
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        if observed["ActiveState"] != "active" or set(map(int, uid_line.split()[1:])) != {expected_uid}:
            raise ValueError("daemon is not active under the declared account")
        evidence.update(reply=reply, observed=observed, main_pid_uid=expected_uid,
                        client_uid=os.geteuid(), client_gid=operator_gid)
    finally:
        run(["systemctl", "stop", transient])
    evidence["stopped"] = show(transient, ("ActiveState",)).get("ActiveState") == "inactive"
    if not evidence["stopped"]:
        raise ValueError("transient stop did not reach inactive")
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
    except Exception as error:  # noqa: BLE001 - never disclose local configuration or reply text
        print(json.dumps({"unit": args.unit, "ok": False, "error_type": type(error).__name__}))
        return 1
    print(json.dumps({"ok": True, **evidence}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
