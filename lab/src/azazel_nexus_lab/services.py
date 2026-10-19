"""Real installed daemon wrappers in independently named transient units."""
from __future__ import annotations

import os
import shlex
import subprocess
import time
from pathlib import Path

from .unit_relocation import (
    assert_write_isolation,
    build_command,
    create_scratch_tree,
    parse_service,
    relocate,
    require_strict,
)
from .unit_sandbox import (
    SHOW,
    compare_properties,
    expected_properties,
)

UNITS = ("azazel-knowledge-lited", "azazel-mio-locald", "azazel-mio-entryd")
LEAVES = ("knowledge", "mio", "mio-entry")


def run(argv, *, env=None):
    return subprocess.run(argv, env=env, check=True, capture_output=True,
                          text=True, timeout=30).stdout


def show(unit, fields):
    raw = run(["systemctl", "show", unit, *["--property=" + key for key in fields]])
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def prefix(root):
    return "azazel-lab-" + root.name + "-"


def installed_unit(name):
    for base in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        path = Path(base) / (name + ".service")
        if path.is_file():
            return path
    raise ValueError("installed service file missing")


def properties(name):
    if show(name + ".service", ("DropInPaths",)).get("DropInPaths"):
        raise ValueError("unreviewed installed drop-ins")
    text = installed_unit(name).read_text()
    if name == "azazel-mio-locald":
        # This hook provisions the production model identity. No model may be
        # admitted in this lab; it must never run against the host.
        hook = "ExecStartPre=+/usr/libexec/azazel/az-mio-identity\n"
        if text.count(hook) != 1:
            raise ValueError("unknown model identity hook")
        text = text.replace(hook, "")
    props = parse_service(text)
    require_strict(props)
    # Execute only the canonical installed wrapper, never unit-supplied args.
    wrapper = "/usr/libexec/azazel/az-" + name.removeprefix("azazel-")
    if shlex.split(dict(props)["ExecStart"]) != [wrapper]:
        raise ValueError("noncanonical installed executable")
    return props


def prepare(root):
    all_properties = {name: properties(name) for name in UNITS}
    for props in all_properties.values():
        create_scratch_tree(root, props)
    return all_properties


def start(root, all_properties):
    evidence = []
    for name, leaf in zip(UNITS, LEAVES, strict=True):
        props = relocate(all_properties[name], root, name, prefix=prefix(root))
        unit = prefix(root) + name + ".service"
        began = time.perf_counter()
        run(build_command(name, props, prefix=prefix(root)))
        socket = root / "var/lib/azazel/run" / leaf / (leaf + ".sock")
        if len(os.fsencode(socket)) >= 108:
            raise ValueError("lab socket exceeds AF_UNIX length")
        deadline = time.monotonic() + 15
        active_ms = None
        socket_ms = None
        while active_ms is None or socket_ms is None:
            elapsed = (time.perf_counter() - began) * 1000
            if socket.is_socket() and socket_ms is None:
                socket_ms = elapsed
            if show(unit, ("ActiveState",)).get("ActiveState") == "active" and active_ms is None:
                active_ms = elapsed
            if time.monotonic() >= deadline:
                raise ValueError("lab daemon socket startup timeout")
            time.sleep(0.05)
        observed = show(unit, tuple({*SHOW, *expected_properties(props)}))
        assert_write_isolation(observed, root, Path("/run") / unit.removesuffix(".service"))
        # The lab imposes a tighter RWP assertion than the general smoke tool.
        if any(not Path(word.lstrip("-+")).resolve().is_relative_to(root.resolve())
               for word in shlex.split(observed["ReadWritePaths"])):
            raise ValueError("effective lab ReadWritePaths escape")
        if observed["ActiveState"] != "active" or compare_properties(props, observed):
            raise ValueError("effective lab service sandbox differs")
        evidence.append({"unit": unit, "observed": observed,
                         "active_ms": active_ms, "socket_ready_ms": socket_ms})
    return evidence


def stop(root):
    # Missing/collected units are harmless; a live unit must be stopped before
    # key erasure or root removal. Never use wildcards or production names.
    for name in reversed(UNITS):
        unit = prefix(root) + name + ".service"
        state = show(unit, ("LoadState", "ActiveState"))
        if state.get("LoadState") == "not-found":
            continue
        run(["systemctl", "stop", unit])
        if show(unit, ("ActiveState",)).get("ActiveState") not in {"inactive", "failed", ""}:
            raise ValueError("lab unit did not stop")
