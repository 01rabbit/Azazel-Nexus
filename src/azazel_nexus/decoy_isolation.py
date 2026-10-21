"""The Deception Lite network's isolation evidence, as written and as read (#196 §14).

`docs/deception-redirect-prerequisites.md` §5 D1 and §14. After it has built
the host side of the decoy network, the network helper (`az-decoy-netd`)
reads back what it built with two fixed commands and records, for this boot,
one fixed result per check. The decoy (`az-decoyd`) reads that record before
it opens any socket and refuses to listen unless it is from this boot, from
the expected writer, in the exact shape below, and every check passed.

**The shape is closed.** One JSON object, exactly these keys, written in one
canonical form (`render_evidence`), and a reader refuses anything that does
not render back to the same bytes:

    {"boot_id": "<this boot>", "checked_at": "YYYY-MM-DDTHH:MM:SSZ",
     "checks": {"<check>": "pass" | "fail" | "unreadable", ...},
     "contract": "azazel-nexus/decoy-isolation/v1"}

`checks` names exactly `CHECKS`. Nothing else is recorded: no address, no
interface name besides the fixed ones the check names stand for, no command
output, no secret.

**Where it lives.** `/run/azazel-decoy-isolation/isolation.json`. The
directory is the helper's `RuntimeDirectory=` (root, `0755`), so it exists
only while the helper is active and systemd removes it when the helper
stops; `/run` is cleared at every kernel boot. The helper removes a previous
record before it builds anything, and again first thing at stop. The file is
root's, `0644`. A reader opens the directory and the file without following
a symlink, and refuses either unless it is owned by root and writable by
nobody else, and the file unless it is a regular one within `MAX_BYTES`.

**What it is not.** It is a reading of the configuration the helper made
(the nftables table and the host's links and addresses), not a packet test
of the denied paths: nothing here sends traffic, and `HG-06` stays the gate
for that. It describes the network at the moment it was read; the helper
runs once per boot and the decoy's unit requires it.

**Activation.** `installed_isolation_reading` is the producer frame a later
activation pass may consume. Nothing grants on it in this build:
`ActivationController` still withholds `DECEPTION_EXPOSURE` as
`isolation_evidence_absent` on every pass (§14 says why), and takes no
argument through which a reading could be passed.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional

from .edge_package import EdgePackageRefused, is_boot_id, read_current_boot_id

__all__ = [
    "CHECKS",
    "CLOCK_SKEW_SECONDS",
    "CONTRACT",
    "EVIDENCE_DIRECTORY",
    "EVIDENCE_NAME",
    "IsolationEvidence",
    "IsolationEvidenceRefused",
    "IsolationReading",
    "IsolationState",
    "MAX_BYTES",
    "RESULTS",
    "admission_refusal",
    "installed_isolation_reading",
    "load_evidence",
    "parse_evidence",
    "render_evidence",
    "require_isolation_for_decoy",
]

#: The contract every record names.
CONTRACT = "azazel-nexus/decoy-isolation/v1"

#: The helper's runtime directory (`RuntimeDirectory=azazel-decoy-isolation`,
#: `hardening.DECOY_ISOLATION_DIRECTORY`; a test keeps them equal).
EVIDENCE_DIRECTORY = "/run/azazel-decoy-isolation"
EVIDENCE_NAME = "isolation.json"

#: The checks, in the order the helper runs them. Each is one fixed
#: statement about the host side of the decoy network (§14):
#:
#: * `nft_table`: the `inet azazel_decoy` table, listed, is exactly the one
#:   the helper loads (its chains, rules and set definition);
#: * `approved_v4_empty`: the set `approved_v4` in that listing has no element;
#: * `bridge`: one link `az-decoy0`, a bridge, up, attached to nothing;
#: * `bridge_address`: its only IPv4 address is the bridge address of the
#:   decoy /30, and it has no IPv6 address but a link-local one;
#: * `bridge_ports`: the only link attached to it is the host end of the
#:   veth pair;
#: * `host_veth`: that end is a veth, up, attached to the bridge, with its
#:   peer in another network namespace, and has no IPv4 address;
#: * `decoy_veth_off_host`: the decoy's end is not in the host namespace;
#: * `subnet_exclusive`: no other host link holds an address in the decoy /30.
#:
#: The decoy namespace's own interfaces are not here: only a process inside
#: it can list them, and the helper cannot enter it. The decoy checks them
#: itself, from inside, before every bind (`decoy_netns`, §12).
CHECKS: tuple[str, ...] = (
    "nft_table",
    "approved_v4_empty",
    "bridge",
    "bridge_address",
    "bridge_ports",
    "host_veth",
    "decoy_veth_off_host",
    "subnet_exclusive",
)

#: The three results a check may have. `unreadable`: the command failed, was
#: killed, or printed something that could not be read; it is not a pass.
RESULTS: tuple[str, ...] = ("pass", "fail", "unreadable")

#: A record is a few hundred bytes; a reader reads no more than this.
MAX_BYTES = 4096

#: How far in the future a record's time may be before it is refused.
CLOCK_SKEW_SECONDS = 5

_KEYS = frozenset({"boot_id", "checked_at", "checks", "contract"})
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

#: Private test seams. Production uses exactly these: the fixed directory,
#: root as the only trusted owner, and the kernel's boot id.
_DIRECTORY = EVIDENCE_DIRECTORY
_OWNER = 0
_BOOT_ID_PATH: Optional[Path] = None


class IsolationEvidenceRefused(Exception):
    """The record is absent, foreign, malformed, from another boot or failing.

    The message is a fixed phrase: never an address, a path from input or the
    record's content.
    """


@dataclass(frozen=True)
class IsolationEvidence:
    """One record, exactly as `parse_evidence` accepted it."""

    boot_id: str
    checked_at: str
    #: `(check, result)` in `CHECKS` order.
    checks: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not is_boot_id(self.boot_id):
            raise IsolationEvidenceRefused("the record names no canonical boot id")
        if type(self.checked_at) is not str or not _INSTANT.match(self.checked_at):
            raise IsolationEvidenceRefused("the record's time is not a UTC second")
        try:
            _instant(self.checked_at)
        except ValueError:
            raise IsolationEvidenceRefused("the record's time is not a UTC second") from None
        if (type(self.checks) is not tuple
                or tuple(name for name, _ in self.checks) != CHECKS
                or any(type(result) is not str or result not in RESULTS
                       for _, result in self.checks)):
            raise IsolationEvidenceRefused(
                "the record does not hold exactly the fixed checks with fixed results")

    @property
    def passed(self) -> bool:
        return all(result == "pass" for _, result in self.checks)

    @property
    def not_passed(self) -> tuple[str, ...]:
        """The checks that did not pass, by fixed name."""

        return tuple(name for name, result in self.checks if result != "pass")


def _instant(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def render_evidence(boot_id: str, checked_at: str, checks: Mapping[str, str]) -> bytes:
    """The one canonical form of a record. Refuses anything outside the shape."""

    if type(checks) is not dict or set(checks) != set(CHECKS):
        raise IsolationEvidenceRefused(
            "a record holds exactly the fixed checks with fixed results")
    evidence = IsolationEvidence(boot_id, checked_at,
                                 tuple((name, checks[name]) for name in CHECKS))
    return _render(evidence)


def _render(evidence: IsolationEvidence) -> bytes:
    document = {
        "boot_id": evidence.boot_id,
        "checked_at": evidence.checked_at,
        "checks": dict(evidence.checks),
        "contract": CONTRACT,
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def parse_evidence(data: bytes) -> IsolationEvidence:
    """Read one record. Refuses rather than repairing.

    Accepted only if it renders back to exactly the same bytes, so extra
    whitespace, a reordered or duplicated key, an escape where the canonical
    form has none, or a missing newline are all refused.
    """

    if type(data) is not bytes or len(data) > MAX_BYTES:
        raise IsolationEvidenceRefused("the record is larger than a record")
    try:
        document = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise IsolationEvidenceRefused("the record is not ASCII JSON") from None
    if type(document) is not dict or set(document) != _KEYS:
        raise IsolationEvidenceRefused("the record does not have exactly the fixed keys")
    if document["contract"] != CONTRACT:
        raise IsolationEvidenceRefused("the record names another contract")
    checks = document["checks"]
    if type(checks) is not dict or list(checks) != sorted(CHECKS) or set(checks) != set(CHECKS):
        raise IsolationEvidenceRefused(
            "the record does not hold exactly the fixed checks with fixed results")
    evidence = IsolationEvidence(document["boot_id"], document["checked_at"],
                                 tuple((name, checks[name]) for name in CHECKS))
    if _render(evidence) != data:
        raise IsolationEvidenceRefused("the record is not in its canonical form")
    return evidence


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _protected(info: os.stat_result) -> bool:
    return info.st_uid == _OWNER and not info.st_mode & 0o022


def load_evidence() -> Optional[IsolationEvidence]:
    """The record at the fixed path; `None` when the directory or file is absent.

    Absent is not a refusal here: a node whose helper has not run has no
    record. Everything else that is not exactly a record raises
    `IsolationEvidenceRefused`: a symlink in place of the directory or the
    file, an owner other than root, a group- or world-writable mode, a file
    that is not a regular one or is larger than `MAX_BYTES`, or content that
    `parse_evidence` refuses.
    """

    try:
        directory = os.open(_DIRECTORY, _DIR_FLAGS)
    except FileNotFoundError:
        return None
    except OSError:
        raise IsolationEvidenceRefused(
            "the evidence directory could not be opened as a directory") from None
    try:
        if not _protected(os.fstat(directory)):
            raise IsolationEvidenceRefused(
                "the evidence directory has unsafe ownership or mode")
        try:
            fd = os.open(EVIDENCE_NAME, _FILE_FLAGS, dir_fd=directory)
        except FileNotFoundError:
            return None
        except OSError:
            raise IsolationEvidenceRefused("the record could not be opened") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not _protected(info):
                raise IsolationEvidenceRefused("the record has unsafe ownership or mode")
            if info.st_size > MAX_BYTES:
                raise IsolationEvidenceRefused("the record is larger than a record")
            data = b""
            while len(data) <= MAX_BYTES:
                chunk = os.read(fd, MAX_BYTES + 1 - len(data))
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    return parse_evidence(data)


def admission_refusal(evidence: IsolationEvidence, *, boot_id: str, now: str) -> Optional[str]:
    """Why `evidence` does not admit a decoy now, or `None` when it does.

    It must be from the boot `boot_id` names, not dated after `now` (beyond
    `CLOCK_SKEW_SECONDS`), and every check must have passed. A fixed phrase
    and fixed check names only.
    """

    if not is_boot_id(boot_id) or evidence.boot_id != boot_id:
        return "the isolation evidence is not from this boot"
    try:
        current = datetime.fromisoformat(now[:-1] + "+00:00" if now.endswith("Z") else now)
    except (TypeError, ValueError):
        return "the current time could not be read"
    if current.tzinfo is None:
        return "the current time could not be read"
    if _instant(evidence.checked_at) > current + timedelta(seconds=CLOCK_SKEW_SECONDS):
        return "the isolation evidence is dated in the future"
    if not evidence.passed:
        return "isolation checks did not pass: " + ",".join(evidence.not_passed)
    return None


def _boot_id() -> str:
    if _BOOT_ID_PATH is None:
        return read_current_boot_id()
    return read_current_boot_id(_BOOT_ID_PATH, owner_uid=os.getuid())


def require_isolation_for_decoy(*, now: str) -> IsolationEvidence:
    """The decoy's gate: this boot's passing record, or `IsolationEvidenceRefused`.

    Called by `az-decoyd` before it opens any socket. No argument, file,
    environment variable or flag skips it; an absent record refuses.
    """

    try:
        boot_id = _boot_id()
    except EdgePackageRefused:
        raise IsolationEvidenceRefused("this boot's id could not be read") from None
    evidence = load_evidence()
    if evidence is None:
        raise IsolationEvidenceRefused(
            "no isolation evidence: the network helper has not recorded one this boot")
    refusal = admission_refusal(evidence, boot_id=boot_id, now=now)
    if refusal is not None:
        raise IsolationEvidenceRefused(refusal)
    return evidence


class IsolationState(str, Enum):
    """What one reading of the record established. Only `PASSED` is a pass."""

    ABSENT = "absent"
    REFUSED = "refused"
    NOT_THIS_BOOT = "not_this_boot"
    NOT_PASSED = "not_passed"
    PASSED = "passed"


@dataclass(frozen=True)
class IsolationReading:
    """The producer frame for a later activation pass (§14). Grants nothing."""

    state: IsolationState
    #: The checks that did not pass (`NOT_PASSED` only), by fixed name.
    not_passed: tuple[str, ...] = ()
    checked_at: Optional[str] = None


def installed_isolation_reading(*, now: str) -> IsolationReading:
    """Read the fixed record for this boot. Never raises.

    Not called by the activation pass in this build: the pass runs before the
    three units start, so this boot's record cannot exist when it runs, and
    the tier is withheld whatever this returns (§14).
    """

    try:
        evidence = load_evidence()
    except IsolationEvidenceRefused:
        return IsolationReading(IsolationState.REFUSED)
    except Exception:  # noqa: BLE001 - an unreadable record establishes nothing
        return IsolationReading(IsolationState.REFUSED)
    if evidence is None:
        return IsolationReading(IsolationState.ABSENT)
    try:
        boot_id = _boot_id()
    except Exception:  # noqa: BLE001 - no boot id, no record is this boot's
        return IsolationReading(IsolationState.NOT_THIS_BOOT)
    refusal = admission_refusal(evidence, boot_id=boot_id, now=now)
    if refusal is None:
        return IsolationReading(IsolationState.PASSED, checked_at=evidence.checked_at)
    if evidence.boot_id != boot_id:
        return IsolationReading(IsolationState.NOT_THIS_BOOT)
    if not evidence.passed:
        return IsolationReading(IsolationState.NOT_PASSED, evidence.not_passed,
                                evidence.checked_at)
    return IsolationReading(IsolationState.REFUSED)
