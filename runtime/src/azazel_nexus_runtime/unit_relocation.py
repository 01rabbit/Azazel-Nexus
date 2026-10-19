"""Relocate parsed service sandboxes without applying production dependencies.

Used by the opt-in smoke tool and the separately installed lab distribution.
No lab package is imported by the runtime.
"""
from __future__ import annotations

import grp
import os
import pwd
import re
import shlex
from pathlib import Path

Properties = list[tuple[str, str]]
PATH_KEYS = {"ReadWritePaths", "ReadOnlyPaths"}


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
        if "%" in value and not (section == "Service" and key == "CPUQuota"
                                 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?%", value)):
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


def relocate(properties: Properties, scratch: Path, name: str, *, prefix="azazel-smoke-") -> Properties:
    """Only state paths, the private runtime directory and startup protocol differ."""
    from azazel_nexus.layout import spec_for

    if not scratch.is_absolute() or ".." in scratch.parts or scratch.resolve() == Path("/"):
        raise ValueError("private absolute relocation root required")
    result = []
    for key, value in properties:
        if key in PATH_KEYS:
            paths = []
            for token in shlex.split(value):
                flags = token[:len(token) - len(token.lstrip("-+"))]
                path = token[len(flags):]
                if ((not spec_for(path) and not (key == "ReadOnlyPaths" and path in {
                        "/etc/azazel/mission-pack.json", "/data/azazel/mission-packs",
                        "/etc/azazel/operator-trust"}))
                        or ".." in Path(path).parts
                        or not path.startswith(("/var/lib/azazel/", "/etc/azazel/",
                                                "/data/azazel/"))):
                    raise ValueError("path is outside the installer layout")
                paths.append(flags + str(scratch / path.lstrip("/")))
            value = " ".join(paths)
        elif key == "RuntimeDirectory":
            value = prefix + name
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


def build_command(name: str, properties: Properties, *, prefix="azazel-smoke-") -> list[str]:
    if name not in {"azazel-mio-entryd", "azazel-knowledge-lited", "azazel-mio-locald"}:
        raise ValueError("unknown smoke unit")
    # Validate again for callers that did not use parse_service.
    properties = parse_service("[Service]\n" + "\n".join(f"{k}={v}" for k, v in properties))
    command = shlex.split(dict(properties)["ExecStart"])
    if (not command or not command[0].startswith("/")
            or command[0].startswith(("-", "+", "!", "@", ":"))):
        raise ValueError("ExecStart must be a literal absolute command")
    argv = ["systemd-run", "--unit=" + prefix + name, "--no-block", "--collect"]
    return [*argv, *[f"--property={k}={v}" for k, v in properties if k != "ExecStart"],
            "--", *command]


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
        parent.mkdir(parents=True, exist_ok=True)
        os.chown(parent, 0, 0)
        parent.chmod(0o755)
    for spec in sorted(specs, key=lambda item: item.path.count("/")):
        target = scratch / spec.path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)
        os.chown(target, pwd.getpwnam(spec.owner).pw_uid, grp.getgrnam(spec.group).gr_gid)
        target.chmod(spec.mode)  # chown can clear setgid


def require_strict(properties: Properties) -> None:
    # full leaves /var writable; only strict provides the required default deny.
    if dict(properties).get("ProtectSystem") != "strict":
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


