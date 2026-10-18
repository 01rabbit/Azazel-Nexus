"""What it would take to run a model here, and why nothing runs one (#97).

This module is **everything around starting a model except starting one**.
Nothing here spawns a process -- `tests/unit/test_boundary_static.py` refuses
`subprocess` across this package and that is not relaxed. The service that
would spawn one is `azazel_nexus_runtime.mio_locald`, and it is a separate
distribution, account, socket and unit.

The purpose is not to run a model. It is to fix the boundary **before**
anything can, because a containment written after the thing it contains is a
containment shaped by what that thing turned out to need.

## Two names, and nothing else crosses

A caller asks for a `model_id` and a `runtime_id`. Both are symbols.

There is no parameter here, and no argument kind in `protocol.py`, that can
carry a command, a path, an environment variable, a socket address or a model
option. That is not a check performed on the way in; it is a shape a request
cannot take. A control plane that could pass an option could pass
`--load-plugin`, and every sentence below would be advisory.

The `runtime_id` resolves through `RUNTIMES`, a table **in this package**.
A runtime is a binary, and a binary is code: it arrives by a reviewed change
to this file, never as commissioned data, never as an operator setting, and
never as something discovered on the node. `RUNTIMES` is empty in this build.

## The model is data

Weights are read. They are not code, and every way this product could be
persuaded to treat them as code is refused by name in `ArtifactDisposition`:

| refused | because |
| --- | --- |
| an executable bit | a file the node may execute is a file something may arrange to have executed |
| not a regular file | a symlink, a fifo or a device is a name for something else |
| an archive's magic bytes | unpacking is the step where one file becomes many, and one of them is a script |
| a hook, plugin or tool-call declaration | a model that can name a program to run is a model that runs programs |

The archive check reads the first bytes rather than trusting the name: an
extension is a claim by whoever wrote the filename.

## Containment is declared before admission, and needs the reserve

`Containment` is memory, CPU, processes, file size, a deadline, loopback-only
and no outbound network. It is **derived from the measured Core reserve**, so
there is no containment on a node that has not measured one -- which is every
node this build runs on (`core_reserve.py`, `docs/hardware-gates.md` HG-05).

That is the point rather than a limitation. A limit chosen without a
measurement is a number somebody liked, and a cgroup set from it either
strangles the node's own work or fails to protect it. Refusing is the honest
answer, and it is the same refusal `cognition.admit_local_model` already
gives at the resource gate.

## Nothing here grants anything

No function in this module admits a provider, activates one, changes what the
Edge arbiter decides, extends a lease or enforces anything. `FULL -> LITE ->
CORE` is a capability state, not an authority state, and a local model
runtime -- started, crashed, rolled back or absent -- moves none of it.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional

from .core_reserve import CoreReserve

__all__ = [
    "ArtifactDisposition",
    "Containment",
    "DEADLINE_SECONDS",
    "MAX_MODEL_ARTIFACT_BYTES",
    "RUNTIMES",
    "RuntimeBinary",
    "RuntimeRefused",
    "ActivationReadiness",
    "archive_signatures",
    "containment_for",
    "inspect_artifact",
    "readiness",
    "resolve_runtime",
    "llama_server_record",
]


class RuntimeRefused(Exception):
    """A runtime that may not be resolved, or a model that may not be read."""


@dataclass(frozen=True)
class RuntimeBinary:
    """One entry in the package's fixed runtime allowlist.

    `argv` is the **whole** command, fixed here, with no interpolation and no
    place for a caller's value. A runtime needing a per-model flag is a
    runtime this table does not yet describe, and describing it is a reviewed
    change to this file -- which is the review a `--load-plugin` would
    otherwise not get.
    """

    runtime_id: str
    executable: str
    version: str
    digest: str
    argv: tuple[str, ...]

    def __post_init__(self) -> None:
        if (not self.executable.startswith("/usr/libexec/azazel/")
                or ".." in Path(self.executable).parts
                or "\x00" in self.executable):
            raise RuntimeRefused(
                f"{self.runtime_id!r} names {self.executable!r}, which is not "
                "under the package's own directory. A runtime resolved from "
                "elsewhere is a runtime whoever writes there chooses"
            )
        if self.argv and self.argv[0] != self.executable:
            raise RuntimeRefused(
                f"{self.runtime_id!r} has an argv whose first element is not "
                "its executable; the two would then disagree about what runs"
            )
        for argument in self.argv:
            if not isinstance(argument, str) or "\x00" in argument:
                raise RuntimeRefused("argv elements must be literal strings without NUL")
            if "{" in argument or "}" in argument or "%" in argument:
                raise RuntimeRefused(
                    f"{self.runtime_id!r} has {argument!r} in its argv, which "
                    "reads as a template. An argv with a hole is an argv "
                    "something fills"
                )


def llama_server_record(
    binary: RuntimeBinary,
    *,
    model_path: Path,
    socket_path: Path,
    ctx: int = 2048,
    threads: int = 2,
    max_tokens: int = 256,
) -> RuntimeBinary:
    """Freeze benchmark/harness inputs into a record; grant no admission.

    Paths are literal absolute paths, never templates or paths supplied by a
    control-plane request. The executable retains RuntimeBinary's package
    restriction. RUNTIMES remains empty.
    """
    for path in (model_path, socket_path):
        if not Path(path).is_absolute() or ".." in Path(path).parts:
            raise RuntimeRefused("model and socket paths must be literal absolute paths")
    if not str(socket_path).endswith(".sock"):
        raise RuntimeRefused("llama-server requires a .sock host for AF_UNIX")
    for value in (ctx, threads, max_tokens):
        if type(value) is not int or value < 1:
            raise RuntimeRefused("context, threads and token limits must be positive integers")
    return RuntimeBinary(
        runtime_id=binary.runtime_id,
        executable=binary.executable,
        version=binary.version,
        digest=binary.digest,
        argv=(binary.executable, "-m", str(model_path), "--host", str(socket_path),
              "-c", str(ctx), "-t", str(threads), "--no-webui", "-n", str(max_tokens)),
    )


#: The runtime allowlist. **Empty in this build, and that is the shipped
#: state.**
#:
#: Not empty as a disabled feature: this distribution contains no model
#: runtime, so there is no symbol to resolve and `az-mio-locald` starts
#: nothing. `activation.UnitDefinition.wiring` is what keeps its unit from
#: being granted, so the node does not carry a unit that would start and exit.
#:
#: A runtime is added here, in code, under review -- never as commissioned
#: data. The Source Registry is data because an endpoint is a deployment fact;
#: a binary is not a fact about a deployment, it is a thing that executes.
RUNTIMES: Mapping[str, RuntimeBinary] = {}

#: A model artifact larger than this is refused before it is read. The same
#: ceiling `model_import` uses, because two ceilings for one quantity is one
#: ceiling and one number nobody maintains.
MAX_MODEL_ARTIFACT_BYTES = 64 * 1024 * 1024 * 1024

#: How long one inference may take. A request with no deadline is one nobody
#: learns has stopped, and a provider that stops answering without saying so
#: is worse than one that is absent: the absent one is planned for.
DEADLINE_SECONDS = 30


def resolve_runtime(runtime_id: str) -> RuntimeBinary:
    """A symbol to the binary it names, or a refusal. No other way in.

    `runtime_id` arrives as a string because it came off a socket. It is
    **looked up**, never joined to a path, never formatted into a command.
    """

    try:
        return RUNTIMES[runtime_id]
    except (KeyError, TypeError):
        raise RuntimeRefused(
            f"{runtime_id!r} is not a runtime this build contains. The "
            "allowlist is code in this package, so a runtime that is not here "
            "is one nobody reviewed"
        ) from None


def archive_signatures() -> tuple[tuple[bytes, str], ...]:
    """Leading bytes that mean "this is many files", and what each one is.

    By content, because an extension is a claim by whoever wrote the filename.
    """

    return (
        (b"PK\x03\x04", "zip"),
        (b"PK\x05\x06", "empty zip"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"\x28\xb5\x2f\xfd", "zstd"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"ustar", "tar"),  # at offset 257; see `inspect_artifact`
        (b"!<arch>", "ar"),
        (b"\x7fELF", "ELF executable"),
        (b"#!", "script"),
    )


class ArtifactDisposition(str, Enum):
    """What a staged model artifact is. Only one of these may be read."""

    #: A regular, non-executable file that is not an archive. Weights.
    DATA = "data"
    #: It is not there.
    ABSENT = "absent"
    #: A symlink, fifo, socket, device or directory.
    NOT_A_REGULAR_FILE = "not_a_regular_file"
    #: Any of the executable bits are set.
    EXECUTABLE = "executable"
    #: Its leading bytes say it contains other files.
    ARCHIVE = "archive"
    #: Larger than `MAX_MODEL_ARTIFACT_BYTES`, or empty.
    OUT_OF_RANGE = "out_of_range"
    #: It could not be read at all.
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class ArtifactInspection:
    """What an artifact is, and -- when it is not data -- why not."""

    disposition: ArtifactDisposition
    reason: str

    @property
    def is_data(self) -> bool:
        return self.disposition is ArtifactDisposition.DATA


def inspect_artifact(path: Path) -> ArtifactInspection:
    """Decide whether this file may be handed to a runtime as **data**.

    `lstat`, so a symlink is judged as a symlink rather than as whatever it
    points at. The executable bit is checked on the file itself for the same
    reason: a link's own mode says nothing about the target's.

    Refuses rather than repairing. Clearing an executable bit here would be
    this module deciding that a file which arrived executable was meant not to
    be, and the interesting question is who made it executable.
    """

    try:
        status = os.lstat(path)
    except FileNotFoundError:
        return ArtifactInspection(
            ArtifactDisposition.ABSENT, f"{path.name} is not present"
        )
    except OSError as exc:
        return ArtifactInspection(
            ArtifactDisposition.UNREADABLE, f"{path.name} could not be read: {exc}"
        )

    if not stat.S_ISREG(status.st_mode):
        return ArtifactInspection(
            ArtifactDisposition.NOT_A_REGULAR_FILE,
            f"{path.name} is not a regular file; a symlink, a fifo or a "
            "device is a name for something else, and what it names can "
            "change after this check",
        )
    if status.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return ArtifactInspection(
            ArtifactDisposition.EXECUTABLE,
            f"{path.name} is executable ({stat.filemode(status.st_mode)}); a "
            "model is data, and a file the node may execute is a file "
            "something may arrange to have executed",
        )
    if status.st_size < 1 or status.st_size > MAX_MODEL_ARTIFACT_BYTES:
        return ArtifactInspection(
            ArtifactDisposition.OUT_OF_RANGE,
            f"{path.name} is {status.st_size} bytes, outside 1.."
            f"{MAX_MODEL_ARTIFACT_BYTES}",
        )

    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
            handle.seek(257)
            tar_magic = handle.read(5)
    except OSError as exc:
        return ArtifactInspection(
            ArtifactDisposition.UNREADABLE, f"{path.name} could not be read: {exc}"
        )

    for magic, kind in archive_signatures():
        found = tar_magic == magic if magic == b"ustar" else head.startswith(magic)
        if found:
            return ArtifactInspection(
                ArtifactDisposition.ARCHIVE,
                f"{path.name} begins as {kind}; unpacking is the step where "
                "one file becomes many, and this node unpacks nothing",
            )
    return ArtifactInspection(ArtifactDisposition.DATA, "a regular, inert file")


@dataclass(frozen=True)
class Containment:
    """The cgroup and network bounds one model process runs under.

    Every field is a ceiling, and every ceiling is derived rather than chosen.
    A limit somebody liked is a limit that either strangles the node's own
    work or fails to protect it, and which of the two it did is discovered on
    the node rather than here.
    """

    memory_max_mib: int
    cpu_quota_percent: int
    tasks_max: int
    file_size_max_bytes: int
    deadline_seconds: int
    #: Always `True`. A field rather than a sentence in a docstring, so that
    #: removing it is a diff rather than a paragraph nobody re-read.
    loopback_only: bool
    #: Always `True`. The unit carries `IPAddressDeny=any` as well; this is
    #: the same statement on the side that renders it.
    outbound_denied: bool

    def __post_init__(self) -> None:
        if self.memory_max_mib < 1:
            raise RuntimeRefused(
                "a memory ceiling of zero is not a ceiling; the provider would "
                "be killed on its first allocation and the node would call "
                "that a crash"
            )
        if not 1 <= self.cpu_quota_percent <= 100:
            raise RuntimeRefused(
                f"{self.cpu_quota_percent}% is not a share of this node. A "
                "quota above 100 lets one provider hold more than a core's "
                "worth while the deterministic path waits"
            )
        if self.tasks_max < 1:
            raise RuntimeRefused("a process ceiling of zero starts nothing")
        if self.file_size_max_bytes < 1:
            raise RuntimeRefused("a file-size ceiling of zero writes nothing")
        if self.deadline_seconds < 1:
            raise RuntimeRefused(
                "a deadline of zero has already passed, which is a refusal "
                "wearing a timeout's clothes"
            )
        if not self.loopback_only or not self.outbound_denied:
            raise RuntimeRefused(
                "a containment that permits the network is not this "
                "containment. The provider answers on a Unix socket and "
                "reaches nothing; a model that can open a connection is a "
                "model that can carry what it was shown"
            )

    def as_unit_settings(self) -> tuple[tuple[str, str], ...]:
        """The systemd names for these, in declaration order."""

        return (
            ("MemoryMax", f"{self.memory_max_mib}M"),
            ("CPUQuota", f"{self.cpu_quota_percent}%"),
            ("TasksMax", str(self.tasks_max)),
            ("LimitFSIZE", str(self.file_size_max_bytes)),
            ("RuntimeMaxSec", str(self.deadline_seconds)),
            ("IPAddressDeny", "any"),
            ("PrivateNetwork", "yes"),
        )


#: The share of one node a model provider may hold. Below a half on purpose:
#: the deterministic path is what this product is, and a provider that can
#: take most of the CPU is a provider that decides how fast the arbiter runs.
CPU_QUOTA_PERCENT = 40

#: Processes. A model runtime is one process and the threads it needs; a tree
#: is how a runtime that spawns helpers escapes a per-process limit.
TASKS_MAX = 64

#: The largest file a provider may write. It has nothing to persist: what it
#: produces goes back over the socket it was asked on.
FILE_SIZE_MAX_BYTES = 16 * 1024 * 1024


def containment_for(
    *, memory_need_mib: int, reserve: Optional[CoreReserve], envelope_mib: int
) -> Containment:
    """Bounds for one provider, or a refusal for want of a measurement.

    The memory ceiling is the **declared need**, not the envelope minus the
    reserve. The difference matters: a provider given everything the node can
    spare will use everything the node can spare, and the reserve then holds
    only because nothing else asked. A ceiling at what it said it needs is
    also what makes the declaration mean something -- a provider that exceeds
    it is one whose declaration was wrong, and the node finds that out by the
    limit rather than by running short.

    Refuses with no reserve. Choosing a number here would be inventing the
    measurement `HG-05` exists to take, and a cgroup set from an invented
    number is worse than none: it looks like protection.
    """

    if reserve is None:
        raise RuntimeRefused(
            "the Core reserve is unmeasured, so there is no envelope to place "
            "a ceiling inside. docs/hardware-gates.md HG-05 tracks taking the "
            "measurement; choosing a limit instead would be inventing it"
        )
    if memory_need_mib < 1:
        raise RuntimeRefused(
            "a provider that declares no memory need has not declared one"
        )
    if not reserve.fits(memory_need_mib=memory_need_mib, envelope_mib=envelope_mib):
        raise RuntimeRefused(
            f"{memory_need_mib} MiB does not fit {envelope_mib} MiB after a "
            f"Core reserve of {reserve.reserve_mib} MiB. Containing it at its "
            "declared need would be containing it inside the reserve"
        )
    return Containment(
        memory_max_mib=memory_need_mib,
        cpu_quota_percent=CPU_QUOTA_PERCENT,
        tasks_max=TASKS_MAX,
        file_size_max_bytes=FILE_SIZE_MAX_BYTES,
        deadline_seconds=DEADLINE_SECONDS,
        loopback_only=True,
        outbound_denied=True,
    )


class ActivationReadiness(str, Enum):
    """Whether a provider may be activated. Three answers, never two.

    `REFUSED` and `NOT_ASSESSED` are both "no" and they are not the same
    fact: one is a decision, the other is the absence of one. Collapsing them
    is how a node that never checked comes to look like a node that checked
    and was satisfied.
    """

    READY = "ready"
    REFUSED = "refused"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True)
class ActivationVerdict:
    """Whether this node may start a model, and the first reason it may not."""

    readiness: ActivationReadiness
    reason: str

    def __post_init__(self) -> None:
        if self.readiness is ActivationReadiness.READY and self.reason:
            raise RuntimeRefused(
                "a ready verdict that carries a reason is describing a "
                "different verdict"
            )
        if self.readiness is not ActivationReadiness.READY and not self.reason:
            raise RuntimeRefused(
                "a refusal an operator cannot act on is a refusal that will be "
                "worked around"
            )


def readiness(
    *,
    admitted: bool,
    runtime_id: Optional[str],
    artifact: Optional[ArtifactInspection],
    reserve: Optional[CoreReserve],
) -> ActivationVerdict:
    """Everything that must hold before a model process could be started.

    Order matters, and it is not the order of convenience. The reserve is
    checked **first and separately from admission**, because it is the one
    condition no node this build runs on satisfies -- and a node that fails it
    must not be told about a later problem it would then go and fix.

    Admission alone is not enough and is checked anyway: the two answer
    different questions. Admission asks whether this provider is one this node
    may use; readiness asks whether this node is in a state to start it. A
    provider admitted on a node that has since lost its reserve record is not
    a provider that may be started.
    """

    if reserve is None:
        return ActivationVerdict(
            ActivationReadiness.REFUSED,
            "the Core reserve is unmeasured (docs/hardware-gates.md HG-05), so "
            "no provider is activated on this node however sound the catalog, "
            "the artifact and the runtime are. 'Verified' and 'may be used' "
            "are not the same word",
        )
    if not admitted:
        return ActivationVerdict(
            ActivationReadiness.REFUSED,
            "no provider is admitted; admission is the decision and this is "
            "the check that it was taken, not a second place to take it",
        )
    if runtime_id is None:
        return ActivationVerdict(
            ActivationReadiness.NOT_ASSESSED,
            "no runtime was named, so nothing was resolved and nothing was "
            "judged. Nobody checked is not a pass",
        )
    try:
        resolve_runtime(runtime_id)
    except RuntimeRefused as exc:
        return ActivationVerdict(ActivationReadiness.REFUSED, str(exc))
    if artifact is None:
        return ActivationVerdict(
            ActivationReadiness.NOT_ASSESSED,
            "the artifact was not inspected, so whether it is data rather "
            "than something that executes is unknown",
        )
    if not artifact.is_data:
        return ActivationVerdict(ActivationReadiness.REFUSED, artifact.reason)
    return ActivationVerdict(ActivationReadiness.READY, "")
