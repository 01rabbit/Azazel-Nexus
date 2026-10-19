"""May the 8 GiB HG-05 campaign start on this node? (#115)

One question, two answers, and nothing else: `HIL_PREFLIGHT_READY` or
`HIL_PREFLIGHT_BLOCKED`. There is no `PARTIAL`, no `READY_WITH_WARNINGS` and
no `PROBABLY` -- a preflight with a middle value is a preflight somebody
proceeds from.

## What this replaces

Before this, starting a campaign meant a person transcribing twenty facts
about a machine into a conversation. Every transcription is a copy of an
identifier somewhere it does not belong, and a mistyped one is a fact nobody
can check. The node holds all twenty; it should answer for itself.

## What it does not do

It takes no sample, reboots nothing, activates no unit, admits no provider,
runs no model, and reaches no network. It reads files, asks the operator what
only an operator can decide, and says whether a campaign may begin.
`docs/core-reserve-measurement.md` §5 is the campaign; this is the gate in
front of it.

## What the command takes

**Nothing.** `azazel-nexus hil-preflight` declares no operator, no timestamp
and no identifier, because a command line is read by everyone on the host
(`/proc/<pid>/cmdline`, `ps`, the shell's history file) and is the one place
an identifier ends up without anybody deciding to put it there.

So the operator is the **local principal** the kernel reports for the process
-- its own credentials, not a name somebody typed -- and the time is the
node's clock together with its boot ID. Both go into the encrypted record and
neither is printed.

## What may be seen

Raw identity -- permanent MACs, serials, TPM identity, an asset ID, the
detailed interface inventory -- lives in the commissioning record on encrypted
storage and **nowhere else** (`docs/inventory-confidentiality.md` §3). It does
not reach the terminal, the journal, the audit or a report. What a reader gets
is the anonymous host ID, the record generation, a key-protected HMAC
fingerprint, the classification of the roles an operator approved, whether the
node is the 8 GiB class, and a runbook ID.

A blocked answer names what is missing **by classification** -- `A-4`, `B-2`
-- and shows no value. The name of the missing fact is what the operator
needs; the value of the facts that are present is not.

## Why a refusal writes nothing

If the encrypted-storage prerequisite does not hold, the raw inventory has
nowhere it may go, so it goes nowhere: the record is not written at all. A
preflight that wrote the record and then complained about the storage would
have already done the thing it was refusing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from .commissioning import CommissioningRecord, Proposal
from .inventory import InterfaceReadout
from .resource_profile import ResourceProfile, select_profile
from .wizard import Answer

__all__ = [
    "BLOCKED",
    "COMMISSIONING_DIR",
    "PROTECTION_KEY",
    "PreflightRefused",
    "OPERATOR_ITEMS",
    "OUTCOMES",
    "READONLY_ITEMS",
    "READY",
    "TARGET_PROFILE",
    "OperatorDecisions",
    "PreflightResult",
    "Protection",
    "ReadonlyInventory",
    "OPERATOR_SCREEN_FIELDS",
    "anonymous_host_id",
    "audit_event",
    "collect_readonly_inventory",
    "describe_for_screen",
    "evaluate",
    "local_principal",
    "next_generation",
    "node_clock",
    "read_boot_id",
    "fingerprint",
    "luks_backed",
    "persist_commissioning_record",
    "read_protection_key",
    "record_as_document",
    "tpm_present",
]

#: The only two answers. A caller that wants a third has to change this tuple,
#: which is a change somebody reviews.
READY = "HIL_PREFLIGHT_READY"
BLOCKED = "HIL_PREFLIGHT_BLOCKED"
OUTCOMES = (READY, BLOCKED)

#: The class this campaign is for, in the vocabulary this product already has.
#: `docs/core-reserve-measurement.md` §1: a reserve is per class, and a record
#: from one class says nothing about another.
TARGET_PROFILE = ResourceProfile.CORE

#: What the node establishes about itself. The labels are classifications, not
#: values: they are what a blocked answer is allowed to print.
READONLY_ITEMS: Mapping[str, str] = {
    "A-1": "usable RAM is the 8 GiB class",
    "A-2": "CPU architecture",
    "A-3": "Linux distribution and version",
    "A-4": "kernel version",
    "A-5": "disk capacity",
    "A-6": "free capacity",
    "A-7": "LUKS available for the commissioning record",
    "A-8": "TPM available",
    "A-9": "wired interface inventory",
    "A-10": "wireless interface inventory",
    "A-11": "network connectivity observed",
}

#: What only an operator may decide. Nothing here is inferred, defaulted or
#: ranked; an absent answer is a blocked preflight, never an assumed one.
OPERATOR_ITEMS: Mapping[str, str] = {
    "B-1": "management interface selected",
    "B-2": "observation interface selected",
    "B-3": "every remaining interface explicitly left unassigned",
    "B-4": "whether external communication is forbidden during the campaign",
    "B-5": "responsible operator",
    "B-6": "date and time",
    "B-7": "asset ID or anonymised host ID",
    "B-8": "approval for measurements that require reboots",
    "B-9": "administrative rights for units and read-only inventory",
}

#: What an operator may be shown about an interface while choosing.
#:
#: A **subset** of `commissioning.OPERATOR_VISIBLE_FIELDS`: the serial, the
#: PCI id and the USB vendor/product id are raw identity
#: (`docs/inventory-confidentiality.md` §2) and a terminal is not one of the
#: two places raw identity may go. What is left is what an operator can check
#: by looking at the machine -- the label on the port and the slot it is in.
OPERATOR_SCREEN_FIELDS = ("physical_label", "bus_path")

_LUKS_UUID_PREFIX = "CRYPT-LUKS"

#: The kernel's own identifier for this boot. Raw identity: it goes into the
#: encrypted record, and into the audit only through the HMAC.
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")

#: The platform baseline, from `docs/platform-baseline.md` (ADR-0002).
#:
#: One distribution and one architecture, because a campaign that ran on two
#: produces evidence for neither: the reserve is measured under a kernel, an
#: allocator and a service manager, and those are the distribution's.
#: `os-release` `ID` and `VERSION_ID` are matched -- never `PRETTY_NAME`,
#: which is a sentence a vendor may rewrite between point releases.
BASELINE_OS_ID = "debian"
BASELINE_OS_VERSION_ID = "13"
#: `uname -m` for what Debian calls `amd64`. The two names are the same
#: machine; this is the one the kernel reports.
BASELINE_ARCHITECTURE = "x86_64"

#: Where the record lives, from `layout.LAYOUT`. Named here so that the CLI
#: and this module cannot disagree about which directory has to be encrypted.
COMMISSIONING_DIR = Path("/etc/azazel/commissioning")

#: The commissioning secret the fingerprint is bound to. Under the root-only
#: secrets directory: a key a daemon account could read is a key the daemon
#: account's compromise reverses every fingerprint with.
PROTECTION_KEY = Path("/var/lib/azazel/secrets/commissioning.key")


# -- what the node establishes about itself -------------------------------


def _read_first_line(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip() or None
    except OSError:
        return None


def _os_release_values(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip().strip('"')
    return values


def read_os_identity(path: Path) -> tuple[Optional[str], Optional[str]]:
    """`(ID, VERSION_ID)` from `os-release`, or `(None, None)`.

    The baseline is matched on these two fields and not on the human-readable
    name: `PRETTY_NAME` is prose, and a host whose prose was edited would
    pass or fail for a reason that has nothing to do with what is installed.
    """

    values = _os_release_values(path)
    return values.get("ID") or None, values.get("VERSION_ID") or None


def read_os_release(path: Path) -> Optional[str]:
    """`PRETTY_NAME`, or `ID` and `VERSION_ID`, or nothing.

    Nothing is a valid answer and blocks the preflight at `A-3`. A
    distribution string assembled from what happened to be readable would be
    a fact nobody could check against the machine.
    """

    values = _os_release_values(path)
    if values.get("PRETTY_NAME"):
        return values["PRETTY_NAME"]
    if values.get("ID") and values.get("VERSION_ID"):
        return f"{values['ID']} {values['VERSION_ID']}"
    return None


def luks_backed(
    path: Path,
    *,
    stat: Callable[[Path], os.stat_result] = os.stat,
    sysfs_dev_block: Path = Path("/sys/dev/block"),
) -> bool:
    """True when `path` sits on a dm-crypt device opened from a LUKS header.

    Read from `dm/uuid`, which device-mapper sets to `CRYPT-LUKS...` for such
    a device. Nothing is executed: a check that shelled out to `cryptsetup`
    would report "not encrypted" on a host where the tool is merely absent,
    which is the wrong answer in the one direction that matters.
    """

    try:
        device = stat(path).st_dev
    except OSError:
        return False
    major, minor = os.major(device), os.minor(device)
    uuid = _read_first_line(sysfs_dev_block / f"{major}:{minor}" / "dm" / "uuid")
    return bool(uuid and uuid.startswith(_LUKS_UUID_PREFIX))


def tpm_present(sysfs_tpm: Path = Path("/sys/class/tpm")) -> bool:
    """True when the kernel exposes a TPM.

    Presence only. The TPM's identity is raw identity and is not read here:
    this function answers "is there one", which is the question the
    prerequisite asks.
    """

    try:
        return any(child.name.startswith("tpm") for child in sysfs_tpm.iterdir())
    except OSError:
        return False


def _link_observed(sysfs_net: Path) -> Optional[bool]:
    """Whether any interface reports a carrier, or `None` if none could say.

    Read here and **nowhere near a role**: `docs/commissioning.md` §4 forbids
    resolving a role from carrier, link state or route, and this value is
    never passed to `propose` or `confirm_roles`. It answers `A-11`, which is
    a fact about the node, not about which port does what.
    """

    seen = False
    try:
        children = sorted(sysfs_net.iterdir())
    except OSError:
        return None
    for child in children:
        carrier = _read_first_line(child / "carrier")
        if carrier is None:
            continue
        seen = True
        if carrier.strip() == "1":
            return True
    return False if seen else None


@dataclass(frozen=True)
class ReadonlyInventory:
    """`A-1` to `A-11`, as read.

    **Holds raw identity.** `interfaces` carries permanent MACs and serials,
    so this object goes to the commissioning record and to nothing else. It
    has no `__str__` worth printing and none is provided: rendering is
    `PreflightResult`'s job, and it renders classifications.
    """

    usable_mib: Optional[int] = None
    architecture: Optional[str] = None
    distribution: Optional[str] = None
    #: `ID` and `VERSION_ID` from `os-release`, matched against the baseline.
    os_id: Optional[str] = None
    os_version_id: Optional[str] = None
    kernel_release: Optional[str] = None
    storage_total_gib: Optional[int] = None
    storage_free_gib: Optional[int] = None
    luks_available: bool = False
    tpm_available: bool = False
    interfaces: tuple[InterfaceReadout, ...] = ()
    #: Whether the wireless enumeration was *performed*. A node with no
    #: wireless adapter is an answered question; an unreadable sysfs is not,
    #: and the two must not collapse into the same `False`.
    wireless_enumerated: bool = False
    link_observed: Optional[bool] = None

    @property
    def on_the_baseline_platform(self) -> bool:
        """Debian 13 on x86_64, and nothing else.

        Not a preference: `HG-05` measures a reserve under one kernel, one
        allocator and one service manager. A record from another distribution
        is a record of another platform, and this build has no way to say by
        how much.
        """

        return (
            self.os_id == BASELINE_OS_ID
            and self.os_version_id == BASELINE_OS_VERSION_ID
            and self.architecture == BASELINE_ARCHITECTURE
        )

    @property
    def eight_gib_class(self) -> bool:
        if self.usable_mib is None:
            return False
        return select_profile(self.usable_mib) is TARGET_PROFILE

    @property
    def missing(self) -> tuple[str, ...]:
        """The `A-` items this node did not establish.

        `A-9` is satisfied by an inventory that produced interfaces; `A-10` by
        the wireless enumeration having happened, whether or not the node has
        a wireless adapter. An absent adapter is an answer; an unread sysfs is
        not.
        """

        missing: list[str] = []
        if not self.eight_gib_class:
            missing.append("A-1")
        # One code per fact: an architecture that is not the baseline's is
        # `A-2`, a distribution that is not the baseline's is `A-3`. A single
        # "not the baseline" code would tell an operator to look at both.
        if self.architecture != BASELINE_ARCHITECTURE:
            missing.append("A-2")
        if self.distribution is None or (self.os_id, self.os_version_id) != (
            BASELINE_OS_ID,
            BASELINE_OS_VERSION_ID,
        ):
            missing.append("A-3")
        for code, value in (
            ("A-4", self.kernel_release),
            ("A-5", self.storage_total_gib),
            ("A-6", self.storage_free_gib),
        ):
            if value is None:
                missing.append(code)
        if not self.luks_available:
            missing.append("A-7")
        if not self.tpm_available:
            missing.append("A-8")
        if not self.interfaces:
            missing.append("A-9")
        if not self.wireless_enumerated:
            missing.append("A-10")
        if self.link_observed is None:
            missing.append("A-11")
        return tuple(dict.fromkeys(missing))


def collect_readonly_inventory(
    *,
    interfaces: Sequence[InterfaceReadout],
    sysfs_net: Path = Path("/sys/class/net"),
    meminfo: Path = Path("/proc/meminfo"),
    os_release: Path = Path("/etc/os-release"),
    record_directory: Path,
    uname: Callable[[], os.uname_result] = os.uname,
    statvfs: Callable[[Path], os.statvfs_result] = os.statvfs,
    stat: Callable[[Path], os.stat_result] = os.stat,
    sysfs_dev_block: Path = Path("/sys/dev/block"),
    sysfs_tpm: Path = Path("/sys/class/tpm"),
) -> ReadonlyInventory:
    """Read `A-1` to `A-11`. Every source is a file or a stat; nothing runs.

    `interfaces` is passed in rather than read here: `azazel_nexus.inventory`
    already owns that read, and a second enumeration would be a second
    identity policy.
    """

    from .resource_profile import UsableMemoryUnavailable, read_usable_mib

    try:
        usable_mib: Optional[int] = read_usable_mib(meminfo)
    except UsableMemoryUnavailable:
        usable_mib = None

    try:
        machine = uname().machine or None
        release = uname().release or None
    except OSError:  # pragma: no cover - uname does not fail in practice
        machine = release = None

    try:
        usage = statvfs(record_directory)
        total_gib: Optional[int] = usage.f_blocks * usage.f_frsize // (1024**3)
        free_gib: Optional[int] = usage.f_bavail * usage.f_frsize // (1024**3)
    except OSError:
        total_gib = free_gib = None

    try:
        # The enumeration, not its result: what `A-10` asks is whether this
        # node was able to say what wireless adapters it has, and "none" is
        # an answer.
        for child in sorted(sysfs_net.iterdir()):
            (child / "phy80211").exists()
        wireless_enumerated = True
    except OSError:
        wireless_enumerated = False

    os_id, os_version_id = read_os_identity(os_release)
    return ReadonlyInventory(
        usable_mib=usable_mib,
        architecture=machine,
        distribution=read_os_release(os_release),
        os_id=os_id,
        os_version_id=os_version_id,
        kernel_release=release,
        storage_total_gib=total_gib,
        storage_free_gib=free_gib,
        luks_available=luks_backed(
            record_directory, stat=stat, sysfs_dev_block=sysfs_dev_block
        ),
        tpm_available=tpm_present(sysfs_tpm),
        interfaces=tuple(interfaces),
        wireless_enumerated=wireless_enumerated,
        link_observed=_link_observed(sysfs_net),
    )


# -- who is running this, and when, without anybody typing it -------------


def local_principal(
    *,
    getuid: Callable[[], int] = os.getuid,
    getgid: Callable[[], int] = os.getgid,
) -> str:
    """Who the kernel says is running this, as credentials rather than a name.

    `uid:1000/gid:1000`. Not a username, not an email, not a person: the
    account the process is running as, which the operating system already
    knows and nobody has to type. A name typed on a command line reaches
    `ps`, `/proc/<pid>/cmdline` and the shell's history; credentials the
    kernel reports reach none of them.

    It is bound into the encrypted commissioning record and printed nowhere.
    """

    return f"uid:{getuid()}/gid:{getgid()}"


def read_boot_id(path: Path = BOOT_ID_PATH) -> Optional[str]:
    """This boot's identifier, or `None`.

    Two runs of the campaign have to be distinguishable, and
    `docs/core-reserve-measurement.md` §5 requires separate boots -- so which
    boot a record belongs to is part of the record. The value is raw identity
    and appears outside the encrypted record only inside the HMAC.
    """

    return _read_first_line(path)


def node_clock(
    *, clock: Callable[[], float] = None, boot_id_path: Path = BOOT_ID_PATH
) -> tuple[str, Optional[str]]:
    """`(timestamp, boot id)` from the node itself.

    The time is the node's, never an argument: a timestamp a caller supplies
    is a timestamp a caller can choose, and an audit whose instants were
    chosen by the thing being audited records a story rather than a sequence.
    """

    import time
    from datetime import datetime, timezone

    now = (clock or time.time)()
    stamp = (
        datetime.fromtimestamp(now, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    return stamp, read_boot_id(boot_id_path)


def describe_for_screen(readout: InterfaceReadout) -> dict[str, str]:
    """What an operator may be shown while choosing. No raw identity.

    `commissioning.describe_for_operator` is the wider set, and it carries
    the serial and the device ids -- which an operator can indeed check
    against the machine, and which are exactly what must not reach a
    terminal. What remains is the physical label and the slot.
    """

    return {
        name: value
        for name in OPERATOR_SCREEN_FIELDS
        if (value := readout.fields.get(name))
    }


# -- what only an operator may decide -------------------------------------


@dataclass(frozen=True)
class OperatorDecisions:
    """`B-1` to `B-9`. Nothing here is derived from the inventory."""

    record: Optional[CommissioningRecord] = None
    #: One answer per commissionable interface, `role=None` meaning the
    #: operator chose to leave it unassigned. An interface with no answer is
    #: not unassigned -- it is unanswered, which blocks.
    answers: tuple[Answer, ...] = ()
    external_communication_forbidden: Optional[bool] = None
    responsible: str = ""
    at: str = ""
    #: The asset ID or anonymised host ID the operator supplies. Raw identity
    #: when it is an asset ID, so it is never rendered: what a reader sees is
    #: the anonymous host ID derived from it.
    host_label: str = ""
    approval_id: str = ""
    reboot_approved: bool = False
    administrative_rights: bool = False

    def missing(self, *, commissionable: int) -> tuple[str, ...]:
        roles = {role.role for role in self.record.roles} if self.record else set()
        missing: list[str] = []
        if "management" not in roles:
            missing.append("B-1")
        if "observation" not in roles:
            missing.append("B-2")
        if len(self.answers) != commissionable or commissionable == 0:
            missing.append("B-3")
        if self.external_communication_forbidden is None:
            missing.append("B-4")
        for code, value in (
            ("B-5", self.responsible),
            ("B-6", self.at),
            ("B-7", self.host_label),
        ):
            if not str(value).strip():
                missing.append(code)
        if not self.reboot_approved:
            missing.append("B-8")
        if not self.administrative_rights:
            missing.append("B-9")
        if not str(self.approval_id).strip():
            missing.append("B-9")
        return tuple(dict.fromkeys(missing))

    @property
    def unassigned_count(self) -> int:
        return sum(1 for answer in self.answers if answer.role is None)


# -- the protected store and the derived identity -------------------------


@dataclass(frozen=True)
class Protection:
    """Whether raw identity has anywhere it may be written."""

    luks_backed: bool = False
    key_available: bool = False

    @property
    def ok(self) -> bool:
        return self.luks_backed and self.key_available


def read_protection_key(path: Path) -> Optional[bytes]:
    """The commissioning secret, or `None`.

    The bytes are returned to the caller and to no log, no event, no report
    and no exception message. Nothing in this module formats them, and
    `tests/unit/test_hil_preflight.py` drives a key through every rendered
    surface to check that none of them carries it.
    """

    try:
        material = path.read_bytes()
    except OSError:
        return None
    return material or None


def fingerprint(value: str, *, key: bytes) -> str:
    """A key-protected HMAC, not a bare hash.

    `docs/inventory-confidentiality.md` §5: an unkeyed digest of a 48-bit
    address is recovered by enumeration, so it is an encoding of the
    identifier rather than an anonymisation of it.
    """

    if not key:
        raise ValueError("a fingerprint without a key is an encoding, not a name")
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest[:32]}"


def anonymous_host_id(host_label: str, *, key: bytes) -> str:
    """The name this node is known by outside its own encrypted store."""

    return "node-" + fingerprint(host_label, key=key).split(":", 1)[1][:16]


def record_as_document(
    record: CommissioningRecord,
    *,
    generation: int = 1,
    boot_id: Optional[str] = None,
) -> Mapping[str, object]:
    """The commissioning record as stored. One format, the existing one.

    Built from the same fields `CommissioningRecord.digest` covers, so a
    stored record and its digest cannot disagree. `generation` and `boot_id`
    sit beside it rather than inside it: the digest is over what an operator
    confirmed, and which boot recorded it is not part of what they confirmed.

    `roles[].confirmed_by` is the local principal -- `uid:…/gid:…` -- and not
    a person's name. This file is the **only** place it is written.
    """

    document: dict[str, object] = {
        "created_at": record.created_at,
        "profiles_present": sorted(record.profiles_present),
        "roles": [
            {
                "composite": [list(pair) for pair in role.composite],
                "role": role.role,
                "confirmed_by": role.confirmed_by,
                "confirmed_at": role.confirmed_at,
            }
            for role in record.roles
        ],
        "digest": record.digest(),
        "generation": generation,
    }
    if boot_id is not None:
        document["boot_id"] = boot_id
    return document


def next_generation(directory: Path) -> int:
    """The generation this run would write. Read from the node, never given.

    A generation a caller supplied would be a counter the caller could reset,
    and a record that claims to be the first is a record that hides the ones
    before it.
    """

    try:
        stored = json.loads(
            (directory / "commissioning.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return 1
    previous = stored.get("generation")
    return previous + 1 if isinstance(previous, int) and previous >= 1 else 1


class PreflightRefused(Exception):
    """Raised where writing would be the thing being refused."""


def persist_commissioning_record(
    record: CommissioningRecord,
    *,
    directory: Path,
    protection: Protection,
    generation: int = 1,
    boot_id: Optional[str] = None,
) -> Path:
    """Write the record, or refuse and write nothing.

    The refusal is here rather than in the caller because this is the only
    function that writes raw identity, and a rule enforced beside the write is
    a rule the next caller cannot route around.
    """

    if not protection.ok:
        raise PreflightRefused(
            "the commissioning record holds raw identity and this node cannot "
            "protect it: encrypted storage or the protection key is missing. "
            "Nothing was written"
        )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "commissioning.json"
    path.write_text(
        json.dumps(
            record_as_document(record, generation=generation, boot_id=boot_id),
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


# -- the answer -----------------------------------------------------------


@dataclass(frozen=True)
class PreflightResult:
    """`READY` or `BLOCKED`, and only what may be shown for either."""

    outcome: str
    missing: tuple[str, ...] = ()
    anonymous_host_id: Optional[str] = None
    record_generation: Optional[int] = None
    fingerprint: Optional[str] = None
    roles: Mapping[str, int] = field(default_factory=dict)
    unassigned: Optional[int] = None
    eight_gib_class: Optional[bool] = None
    runbook_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"{self.outcome!r} is not one of {OUTCOMES}")
        if self.outcome == BLOCKED and not self.missing:
            raise ValueError(
                "a blocked preflight names what is missing; a refusal with no "
                "reason is one an operator can only guess at"
            )
        if self.outcome == READY and self.missing:
            raise ValueError("a ready preflight has nothing missing")

    @property
    def ready(self) -> bool:
        return self.outcome == READY

    def lines(self) -> tuple[str, ...]:
        """Everything a user is shown, and nothing else.

        Blocked prints classifications. Ready prints derived identity and
        classifications. Neither prints a value from the inventory.
        """

        if not self.ready:
            return (BLOCKED, *(f"missing: {code}" for code in self.missing))
        roles = ", ".join(f"{role}={count}" for role, count in sorted(self.roles.items()))
        return (
            READY,
            f"host: {self.anonymous_host_id}",
            f"record generation: {self.record_generation}",
            f"fingerprint: {self.fingerprint}",
            f"roles approved: {roles}",
            f"unassigned interfaces: {self.unassigned}",
            f"memory class: {TARGET_PROFILE.value} (8 GiB class)",
            f"runbook: {self.runbook_id}",
        )


def evaluate(
    inventory: ReadonlyInventory,
    decisions: OperatorDecisions,
    *,
    protection: Protection,
    generation: int,
    key: bytes,
    boot_id: Optional[str] = None,
    proposal: Optional[Proposal] = None,
) -> PreflightResult:
    """Decide. Two answers, and a blocked one names classifications only.

    The protection prerequisite is folded into `A-7` and `A-8` rather than
    given a code of its own: those are the facts that fail, and inventing a
    third vocabulary for the same condition is how two lists start to
    disagree.
    """

    from .lab_host import is_lab_host

    if is_lab_host():
        return PreflightResult(outcome=BLOCKED, missing=("LAB_HOST_MARKER",))

    commissionable = (
        len(proposal.commissionable)
        if proposal is not None
        else sum(1 for readout in inventory.interfaces if readout.is_commissionable)
    )
    missing = tuple(
        dict.fromkeys(
            (*inventory.missing, *decisions.missing(commissionable=commissionable))
        )
    )
    if not protection.ok:
        missing = tuple(dict.fromkeys((*missing, "A-7", "A-8")))
    if missing or decisions.record is None:
        if decisions.record is None and not missing:
            missing = ("B-1",)
        return PreflightResult(outcome=BLOCKED, missing=missing)

    digest = decisions.record.digest()
    host = anonymous_host_id(decisions.host_label, key=key)
    # The boot is inside the fingerprint rather than beside it: two runs on
    # separate boots have to be distinguishable in the audit, and the boot ID
    # itself is raw identity that may not appear there.
    print_safe = fingerprint(f"{digest}:{boot_id or ''}", key=key)
    roles: dict[str, int] = {}
    for confirmed in decisions.record.roles:
        roles[confirmed.role] = roles.get(confirmed.role, 0) + 1
    runbook = "hil-8gib-" + fingerprint(
        f"{digest}:{generation}", key=key
    ).split(":", 1)[1][:12]
    return PreflightResult(
        outcome=READY,
        anonymous_host_id=host,
        record_generation=generation,
        fingerprint=print_safe,
        roles=roles,
        unassigned=decisions.unassigned_count,
        eight_gib_class=True,
        runbook_id=runbook,
    )


def audit_event(result: PreflightResult, *, approval_id: str) -> Mapping[str, object]:
    """What the append-only audit may hold about this run.

    The closed list of `docs/inventory-confidentiality.md` §4: the anonymous
    host ID, the generation, the transition, the approval ID, the HMAC
    fingerprint, and the outcome with the classification of what blocked it.
    No value from the inventory appears, and the blocked codes are
    classifications.
    """

    event: dict[str, object] = {
        "event_type": "hil.preflight",
        "transition": "inventory_captured,inventory_verified"
        if result.ready
        else "inventory_captured",
        "outcome": result.outcome,
        "approval_id": approval_id,
    }
    if result.ready:
        event.update(
            {
                "anonymous_host_id": result.anonymous_host_id,
                "record_generation": result.record_generation,
                "fingerprint": result.fingerprint,
                "runbook_id": result.runbook_id,
            }
        )
    else:
        event["missing"] = list(result.missing)
    return event
