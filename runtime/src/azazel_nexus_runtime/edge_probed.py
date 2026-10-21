"""`az-edge-probed`: the one-shot probe the status command is not allowed to be (#72).

Azazel-Nexus's library half verifies the Edge package on disk and cannot run
anything -- `tests/unit/test_boundary_static.py` refuses `subprocess` across
`src/azazel_nexus`. Two of the five checks
[#44](https://github.com/01rabbit/Azazel-Nexus/issues/44) needs cannot be
answered without running something, so they are answered **here**, in the
runtime distribution, by a service that runs once and exits.

`azazel-nexus status` remains read-only. It starts nothing, stops nothing,
retries nothing, and probes nothing: it reads the state file this writes, or
reports `not-checked` when there is none.

## Everything this touches is fixed in code

| what | where it comes from |
| --- | --- |
| the package directory | `edge_package.EDGE_PACKAGE_ROOT` |
| the pinned version and digest | `edge_package.PIN` and the manifest beside the package |
| the health command | `edge_package.HEALTH_ARGV` |
| the unit whose state is read | `edge_package.EDGE_UNIT` |
| where the result is written | `edge_package.PROBE_STATE_PATH` |

There is **no argument by which any of them can be changed**. `main` takes no
path, no unit, no command and no extra argument, and a static scan in
`tests/unit/test_edge_probed.py` asserts it. A probe that accepted a unit name
would be a probe that could be pointed at any unit on the host; one that
accepted a command would be a general execution primitive wearing a probe's
clothes.

**The health command is the one fixed in code, not the one the manifest
declares.** The manifest declares the same argv and this checks that they
agree -- but agreement is a *verification*, not a source. A manifest is
exactly the file an adversary who can reach the package can rewrite, and
running its copy would be executing a command supplied as data.

## It starts nothing, and it does not build a command line to find out

Running state is read over **D-Bus**, through an injected `call(method, unit)`
exactly as `units.DbusUnitManager` does it -- no `systemctl`, no `PATH`
lookup, no argument splitting, no environment to inherit. The methods are an
allowlist of two, both read-only; `StartUnit` and its siblings are not absent
by convention but by not being in the table.

`tests/unit/test_runtime_activated.py` scans this distribution for anything
that can execute, and this module is the **one** exception to it -- contained
the way `fabric_boundary.py` contains the Fabric import. The exception is
narrow and its narrowness is tested: one `subprocess.run`, an argv assembled
only from module constants, no shell, a fixed `PATH`, and a deadline.

`main` supplies `systemd_bus.EdgeUnitStateReader`: the fixed system-bus
transport the controller uses, narrowed to that one read of that one unit.
When the bus cannot be reached -- a container, a host without systemd, a
permission refusal -- `running` is `not-checked` with that as the reason,
never `failed`. An operator sent to fix an Edge Core that is fine is an
operator doing harm on our word.

## What it verifies before it runs anything

The package must be present, the pinned version must match, the archive
digest must re-derive, **and the unpacked binary about to be executed must
match the digest the manifest records for it**. The last one is the point: an
intact archive says nothing about the file next to it that is actually going
to run.

## The result is bounded, atomic, and cannot promote anything

It carries the version and digest observed, so a reader can tell whether it is
about the package that reader is looking at. It carries a TTL, so an old
answer about a running process expires rather than lingering. It is written to
a temporary file in the same directory and moved into place, so a reader never
sees half of one.

Nothing it can say makes a node ready on its own: the library re-derives
package, version and digest itself on every read and only takes health and
running from here.

## The result names the boot it was observed in (contract v2, #206 P5)

`main` reads this boot's id from `/proc/sys/kernel/random/boot_id` with the
library's protected reader (`edge_package.read_current_boot_id`) **before**
probing, and `write_result` refuses an outcome that does not carry a canonical
one. When the id cannot be read nothing is written: a result that cannot say
which boot it is from is one a reader could not use anyway.

## A run that writes nothing leaves nothing behind (#258 item 7)

The boot id is **not** a per-start value. `systemctl soft-reboot` restarts
every unit but keeps the kernel, so the boot id -- and the result the previous
userspace wrote -- survive it. A preflight that then failed before writing
would leave that older result to be read as this boot's, valid until its TTL.

So the first thing `main` does, before it reads the boot id or probes
anything, is remove the previous result (`clear_previous_result`): one fixed
name, unlinked relative to its directory opened with `O_NOFOLLOW`, never a
path built from input. If it cannot be removed, nothing is probed or written
and the run fails. Every later failure therefore leaves no result at all,
which a reader takes as `not-checked` -- Edge withheld, never granted on an
older answer.

The same binary runs twice per boot: once as
`azazel-edge-probe-preflight.service`, ungoverned, before the activation
controller (so the pass sees fresh health, while `running` is still `failed`
because edge-core has not started), and once as the governed
`azazel-edge-probed.service` after it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from azazel_nexus.edge_package import (
    DEFAULT_TTL_SECONDS,
    EDGE_PACKAGE_ROOT,
    EDGE_UNIT,
    HEALTH_ARGV,
    HEALTHY_STATUS,
    PIN,
    PROBE_CONTRACT,
    PROBE_STATE_PATH,
    EdgePackageRefused,
    Evidence,
    is_boot_id,
    read_current_boot_id,
)

from .systemd_bus import EdgeUnitStateReader

__all__ = [
    "PROBE_ENV",
    "PROBE_TIMEOUT_SECONDS",
    "ProbeOutcome",
    "READ_ONLY_METHODS",
    "clear_previous_result",
    "main",
    "no_unit_reader",
    "probe",
    "write_result",
]

#: The systemd methods this may invoke. Both read. `StartUnit`, `StopUnit`,
#: `RestartUnit` and `EnableUnitFiles` are not absent by convention -- they
#: are absent from the table, which is the only way in.
READ_ONLY_METHODS = ("GetUnit", "GetUnitProperties")

#: The environment the health contract is given. Fixed, and small: an
#: inherited environment is an input nobody declared.
PROBE_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}

#: A ceiling on every subprocess. A probe with no deadline is a probe that can
#: be held open by the thing it is probing.
PROBE_TIMEOUT_SECONDS = 15

#: The most stdout this will read from the health contract. The report is a
#: small JSON object; anything larger is not one.
MAX_HEALTH_BYTES = 65536

#: The unit states that mean the payload is up. Listed rather than inferred:
#: "not failed" is not "running".
RUNNING_ACTIVE_STATES = ("active",)
RUNNING_SUB_STATES = ("running",)


@dataclass(frozen=True)
class ProbeOutcome:
    """One run's findings, in the shape the state file records."""

    observed_at: str
    package_version: str
    package_digest: str
    health: Evidence
    health_reason: str
    running: Evidence
    running_reason: str
    health_security: bool = False
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    #: The boot this run observed. Empty when none was supplied, and an
    #: outcome without a canonical one is never written.
    boot_id: str = ""

    def as_document(self) -> dict:
        return {
            "contract": PROBE_CONTRACT,
            "boot_id": self.boot_id,
            "observed_at": self.observed_at,
            "ttl_seconds": self.ttl_seconds,
            "package_version": self.package_version,
            "package_digest": self.package_digest,
            "health": self.health.value,
            "health_reason": self.health_reason,
            "health_security": self.health_security,
            "running": self.running.value,
            "running_reason": self.running_reason,
        }


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _now() -> str:
    from datetime import datetime, timezone

    stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    tail = "+00:00"
    return stamp[: -len(tail)] + "Z" if stamp.endswith(tail) else stamp


def no_unit_reader(method: str, unit: str):
    """The default. No service manager connection was supplied.

    Returns `None`, which reads as `not-checked` with the reason -- not as
    `failed`. A host with no systemd is not a host whose Edge Core is down.
    """

    return None


def probe(
    root: Path = EDGE_PACKAGE_ROOT,
    *,
    clock: Callable[[], str] = _now,
    runner: Optional[Callable[[Sequence[str], Optional[Path]], object]] = None,
    unit_reader: Callable[[str, str], object] = no_unit_reader,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    boot_id: str = "",
) -> ProbeOutcome:
    """Run once. Never raises for anything the node could be doing wrong.

    `runner` and `unit_reader` are seams. `main` supplies only the reader --
    `systemd_bus.EdgeUnitStateReader`, which can read one unit's state and
    nothing else -- so a deployment gets the fixed spawn and a read-only bus,
    and a test gets to drive both without a systemd or an Edge Core.

    `boot_id` is recorded, not checked here: `write_result` refuses an
    outcome without a canonical one, and `main` reads it before probing.
    """

    run = runner if runner is not None else _run
    observed_at = clock()
    manifest_path = root / PIN.manifest_name
    artifact_path = root / PIN.artifact_name
    binary = root / HEALTH_ARGV[0]

    unusable = lambda reason: ProbeOutcome(  # noqa: E731 - one shape, four call sites
        observed_at=observed_at,
        package_version=PIN.version,
        package_digest="",
        health=Evidence.NOT_CHECKED,
        health_reason=reason,
        running=Evidence.NOT_CHECKED,
        running_reason=reason,
        ttl_seconds=ttl_seconds,
        boot_id=boot_id,
    )

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return unusable(
            f"the Edge manifest at {manifest_path} could not be read ({exc}), "
            "so nothing was run"
        )
    if not isinstance(manifest, dict) or manifest.get("version") != PIN.version:
        return unusable(
            f"the Edge manifest does not declare the pinned version "
            f"{PIN.version}, so nothing was run"
        )
    try:
        artifact_digest = _digest(artifact_path.read_bytes())
    except OSError as exc:
        return unusable(f"the Edge artifact could not be read ({exc}), so nothing was run")
    if artifact_digest != manifest.get("digest"):
        return unusable(
            "the Edge artifact does not match the digest its manifest declares, "
            "so nothing was run. This is a finding for the reader to act on, "
            "and running the payload anyway would be acting on it here"
        )

    declared = manifest.get("health", {})
    if not isinstance(declared, dict) or list(declared.get("command", ())) != list(HEALTH_ARGV):
        return _bound(
            observed_at,
            artifact_digest,
            ttl_seconds,
            boot_id=boot_id,
            health=Evidence.NOT_CHECKED,
            health_reason=(
                "the manifest declares a health command other than the one "
                f"fixed here ({list(HEALTH_ARGV)}); nothing was run, because a "
                "command taken from a manifest is a command supplied as data"
            ),
            running=_running_finding(unit_reader),
        )

    component = _component_digest(manifest, HEALTH_ARGV[0])
    try:
        binary_digest = _digest(binary.read_bytes())
    except OSError as exc:
        return _bound(
            observed_at,
            artifact_digest,
            ttl_seconds,
            boot_id=boot_id,
            health=Evidence.NOT_CHECKED,
            health_reason=(
                f"{binary} could not be read ({exc}); the package is present "
                "and its payload is not unpacked, so nothing was run"
            ),
            running=_running_finding(unit_reader),
        )
    if component is None or binary_digest != component:
        return _bound(
            observed_at,
            artifact_digest,
            ttl_seconds,
            boot_id=boot_id,
            health=Evidence.NOT_CHECKED,
            health_reason=(
                f"{binary} does not match the digest the manifest records for "
                "it; an intact archive says nothing about the file next to it "
                "that would actually run, so nothing was run"
            ),
            running=_running_finding(unit_reader),
            health_security=False,
        )

    health, health_reason, health_security = _health_finding(run, root)
    running, running_reason = _running_finding(unit_reader)
    return ProbeOutcome(
        observed_at=observed_at,
        package_version=PIN.version,
        package_digest=artifact_digest,
        health=health,
        health_reason=health_reason,
        health_security=health_security,
        running=running,
        running_reason=running_reason,
        ttl_seconds=ttl_seconds,
        boot_id=boot_id,
    )


def _bound(
    observed_at: str,
    artifact_digest: str,
    ttl_seconds: int,
    *,
    boot_id: str,
    health: Evidence,
    health_reason: str,
    running: tuple,
    health_security: bool = False,
) -> ProbeOutcome:
    running_evidence, running_reason = running
    return ProbeOutcome(
        observed_at=observed_at,
        package_version=PIN.version,
        package_digest=artifact_digest,
        health=health,
        health_reason=health_reason,
        health_security=health_security,
        running=running_evidence,
        running_reason=running_reason,
        ttl_seconds=ttl_seconds,
        boot_id=boot_id,
    )


def _component_digest(manifest: dict, path: str) -> Optional[str]:
    for component in manifest.get("components", ()):
        if isinstance(component, dict) and component.get("path") == path:
            digest = component.get("digest")
            return digest if isinstance(digest, str) else None
    return None


def _health_finding(run, root: Path) -> tuple[Evidence, str, bool]:
    """Run the fixed command and apply the four conditions, plus version."""

    try:
        completed = run([str(root / HEALTH_ARGV[0]), *HEALTH_ARGV[1:]], root)
    except (OSError, subprocess.SubprocessError) as exc:
        return (
            Evidence.NOT_CHECKED,
            f"the health contract could not be run ({exc}); nobody looked",
            False,
        )
    stdout = (completed.stdout or "")[:MAX_HEALTH_BYTES]
    if completed.returncode != 0:
        return Evidence.FAILED, f"the health contract exited {completed.returncode}", False
    try:
        report = json.loads(stdout)
    except ValueError as exc:
        return (
            Evidence.FAILED,
            f"the health contract exited 0 and its output is not JSON ({exc}); "
            "an exit code alone is not the contract",
            False,
        )
    if not isinstance(report, dict):
        return Evidence.FAILED, "the health contract printed JSON that is not an object", False
    if report.get("contract") != PIN.health_contract:
        return (
            Evidence.FAILED,
            f"the health report declares contract {report.get('contract')!r} and "
            f"this node reads {PIN.health_contract!r}",
            False,
        )
    if report.get("status") != HEALTHY_STATUS:
        return Evidence.FAILED, f"the health report says status={report.get('status')!r}", False
    if report.get("version") != PIN.version:
        return (
            Evidence.FAILED,
            f"the health report is from version {report.get('version')!r} and "
            f"this node pins {PIN.version!r}; the binary answering is not the "
            "one the manifest describes",
            True,
        )
    return (
        Evidence.PASSED,
        "the health contract exited 0, printed JSON, declared "
        f"{PIN.health_contract} and reported status={HEALTHY_STATUS!r} at "
        f"version {PIN.version}",
        False,
    )


def _running_finding(read) -> tuple[Evidence, str]:
    """Read the unit's state over D-Bus. Read-only, typed, and never a command.

    `read(method, unit)` is the same shape `units.DbusUnitManager` uses: the
    unit name is a typed parameter, not a string that becomes an argument.
    The method comes from `READ_ONLY_METHODS` and the unit from
    `edge_package.EDGE_UNIT`; neither is an input.

    `None`, an unreadable answer or an error is `not-checked`. Only an answer
    this node understood, that said the unit is not up, is `failed`.
    """

    method = READ_ONLY_METHODS[1]
    try:
        answer = read(method, EDGE_UNIT)
    except Exception as exc:  # noqa: BLE001 - a probe never raises for the node
        return (
            Evidence.NOT_CHECKED,
            f"systemd could not be asked about {EDGE_UNIT} ({exc!r}); nobody "
            "looked, which is not the same fact as the payload being down",
        )
    if answer is None:
        return (
            Evidence.NOT_CHECKED,
            "no service manager connection was supplied, so the running state "
            f"of {EDGE_UNIT} was not read. Nobody looked",
        )
    if not isinstance(answer, dict):
        return (
            Evidence.NOT_CHECKED,
            f"systemd answered about {EDGE_UNIT} with something other than a "
            "property mapping; the answer was not one this node can read",
        )
    if not {"ActiveState", "SubState"} <= set(answer):
        return (
            Evidence.NOT_CHECKED,
            "systemd answered without ActiveState and SubState; the answer was "
            "not one this node can read",
        )
    if str(answer.get("LoadState", "")) == "not-found":
        return (
            Evidence.FAILED,
            f"{EDGE_UNIT} is not installed on this host, so nothing is running it",
        )
    if str(answer.get("LoadState", "")) == "not-loaded":
        return (
            Evidence.FAILED,
            f"systemd holds no unit object for {EDGE_UNIT}, so nothing is running it",
        )
    active = str(answer["ActiveState"])
    sub = str(answer["SubState"])
    if active in RUNNING_ACTIVE_STATES and sub in RUNNING_SUB_STATES:
        return Evidence.PASSED, f"{EDGE_UNIT} is {active}/{sub}"
    return Evidence.FAILED, f"{EDGE_UNIT} is {active}/{sub}, which is not running"


def _run(argv: Sequence[str], cwd: Optional[Path]):
    """The one place in this distribution that starts a process.

    Contained the way `fabric_boundary.py` contains the Fabric import: one
    call, no shell, a fixed environment, a deadline, and an argv whose every
    element comes from a module constant or from the fixed package root.
    `tests/unit/test_edge_probed.py` asserts each of those against the source,
    and `test_runtime_activated.py` asserts that no other module in the
    distribution can execute anything at all.
    """

    return subprocess.run(
        list(argv),
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT_SECONDS,
        cwd=None if cwd is None else str(cwd),
        env=dict(PROBE_ENV),
    )


def write_result(outcome: ProbeOutcome, path: Path = PROBE_STATE_PATH) -> Path:
    """Write the state file atomically, with no window on a partial one.

    Refuses (`ValueError`, nothing written) an outcome that does not name the
    boot it was observed in: a v2 reader could not use it, and a v1-shaped
    file would read as stale anyway.
    """

    if not is_boot_id(outcome.boot_id):
        raise ValueError(
            "the probe outcome names no boot it was observed in; nothing was written"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(outcome.as_document(), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    handle, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=".edge-probe.")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return path


def clear_previous_result(path: Path = PROBE_STATE_PATH) -> None:
    """Remove the previous result before this run probes anything.

    Only the fixed file name is unlinked, relative to its directory opened with
    `O_NOFOLLOW` (`unlink` itself never follows the last component). An absent
    directory or file is already the state this wants. Any other failure
    raises `OSError`, and `main` then probes and writes nothing: a run that
    could not clear the previous answer must not proceed as if it had.
    """

    try:
        directory = os.open(
            str(path.parent),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except FileNotFoundError:
        return
    try:
        os.unlink(path.name, dir_fd=directory)
    except FileNotFoundError:
        pass
    finally:
        os.close(directory)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """One run, then exit. Takes nothing that could redirect it.

    The only flag is `--print`, which writes the result to stdout as well. It
    changes nothing about what is probed.
    """

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--print",
        action="store_true",
        dest="echo",
        help="also write the result to stdout",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    # The previous result goes first (#258 item 7): soft-reboot keeps the
    # boot id, so an older result left in place would read as this boot's if
    # this run then failed before writing. Not cleared means nothing is run.
    try:
        clear_previous_result()
    except OSError as exc:
        print(f"refused: the previous probe result could not be removed, so "
              f"nothing was probed or written: {exc}", file=sys.stderr)
        return 2

    # This boot, read before anything is probed. Unreadable means nothing is
    # run and nothing is written (contract v2): a result that cannot name its
    # boot is one no reader may use.
    try:
        boot_id = read_current_boot_id()
    except EdgePackageRefused as exc:
        print(f"refused: this boot's id could not be read, so nothing was "
              f"probed or written: {exc}", file=sys.stderr)
        return 2

    # The one systemd view the probe gets: read-only, one unit, connected on
    # first read. A refused or absent bus is `not-checked`, never `failed`,
    # and health does not wait on it (#195: without this, `running` was never
    # read on an installed node).
    reader = EdgeUnitStateReader()
    try:
        outcome = probe(unit_reader=reader, boot_id=boot_id)
    finally:
        reader.close()
    try:
        write_result(outcome)
    except (OSError, ValueError) as exc:
        print(f"refused: the probe result could not be written: {exc}", file=sys.stderr)
        return 2
    if args.echo:
        print(json.dumps(outcome.as_document(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
