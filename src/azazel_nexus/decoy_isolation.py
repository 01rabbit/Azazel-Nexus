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
     "contract": "azazel-nexus/decoy-isolation/v2",
     "scope_digest": "sha256:<hex>" | "none"}

`checks` names exactly `CHECKS`. `scope_digest` is the SHA-256 of the scope
file the helper built from (`azazel_nexus.decoy_scope`), or `none` when it
had no scope (run outside its unit). Nothing else is recorded: no address,
no prefix, no interface name besides the fixed ones the check names stand
for, no command output, no secret. Version 2 (#196 G1b) changed the checks
and added the digest; a version 1 record is refused.

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

**The decoy's gate and the pass's scope** (#196 G6,
`docs/deception-exposure-wiring.md` §6, owner decision Q-D = D2). The decoy
refuses a record whose `scope_digest` is `none`, and compares the record's
digest with the one the activation pass rendered: the pass writes
`/run/azazel-activation/decoy-scope.digest` beside the scope file only when
it granted the tier, and the decoy's unit loads it as the credential
`decoy-scope-digest` (`LoadCredential=`), read here from
`SCOPE_DIGEST_CREDENTIAL_PATH` only. A missing source fails the decoy's
start (closed); the decoy reads an immutable snapshot for its whole run,
and never the approved prefixes or the ingress names.

**Activation.** `installed_isolation_reading` is a producer frame the pass
does not consume: the pass runs before the three units start, so this
boot's record cannot exist when it runs (§14). The pass grants the tier on
its own evidence (`exposure_admission`), and the record gates the decoy's
listen within the boot.
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

from .boot_id import BootIdRefused, is_boot_id, read_current_boot_id

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
    "NO_SCOPE",
    "RESULTS",
    "SCOPE_DIGEST_CREDENTIAL_PATH",
    "admission_refusal",
    "installed_isolation_reading",
    "load_evidence",
    "parse_evidence",
    "render_evidence",
    "require_isolation_for_decoy",
]

#: The contract every record names.
CONTRACT = "azazel-nexus/decoy-isolation/v2"

#: `scope_digest` when the helper ran without a scope. The decoy refuses it.
NO_SCOPE = "none"

#: Where the decoy's unit receives the pass's scope digest
#: (`LoadCredential=decoy-scope-digest:/run/azazel-activation/decoy-scope.digest`,
#: `hardening.DECOY_SCOPE_DIGEST_CREDENTIAL`; a test keeps them equal). The
#: only path the decoy's digest reader opens.
SCOPE_DIGEST_CREDENTIAL_PATH = "/run/credentials/azazel-decoyd.service/decoy-scope-digest"
#: `sha256:` and 64 lowercase hex digits and a newline.
_DIGEST_FILE_BYTES = 72

#: The helper's runtime directory (`RuntimeDirectory=azazel-decoy-isolation`,
#: `hardening.DECOY_ISOLATION_DIRECTORY`; a test keeps them equal).
EVIDENCE_DIRECTORY = "/run/azazel-decoy-isolation"
EVIDENCE_NAME = "isolation.json"

#: The checks, in the order the helper runs them. Each is one fixed
#: statement about the host side of the decoy network (§14):
#:
#: * `nft_table`: the `inet azazel_decoy` table, listed as JSON (`nft -j`),
#:   is exactly the one the helper rendered from its scope and loaded (its
#:   chains, rules, set and the set's elements; handles aside);
#: * `approved_v4_matches`: the set `approved_v4` holds exactly the scope's
#:   prefixes (none without a scope);
#: * `ingress_matches`: the set of ingress names and the number of matches
#:   carrying it: every interface match other than the bridge names exactly
#:   the scope's ingress set, three times (none without a scope); where
#:   those matches sit is `nft_table`'s structural comparison;
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
    "approved_v4_matches",
    "ingress_matches",
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

_KEYS = frozenset({"boot_id", "checked_at", "checks", "contract", "scope_digest"})
_SCOPE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
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
    #: `sha256:<hex>` of the scope file, or `NO_SCOPE`.
    scope_digest: str = NO_SCOPE

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
        if type(self.scope_digest) is not str or not (
                self.scope_digest == NO_SCOPE or _SCOPE_DIGEST.match(self.scope_digest)):
            raise IsolationEvidenceRefused("the record's scope digest is not a digest")

    @property
    def passed(self) -> bool:
        return all(result == "pass" for _, result in self.checks)

    @property
    def not_passed(self) -> tuple[str, ...]:
        """The checks that did not pass, by fixed name."""

        return tuple(name for name, result in self.checks if result != "pass")


def _instant(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def render_evidence(boot_id: str, checked_at: str, checks: Mapping[str, str],
                    scope_digest: str) -> bytes:
    """The one canonical form of a record. Refuses anything outside the shape."""

    if type(checks) is not dict or set(checks) != set(CHECKS):
        raise IsolationEvidenceRefused(
            "a record holds exactly the fixed checks with fixed results")
    evidence = IsolationEvidence(boot_id, checked_at,
                                 tuple((name, checks[name]) for name in CHECKS),
                                 scope_digest)
    return _render(evidence)


def _render(evidence: IsolationEvidence) -> bytes:
    document = {
        "boot_id": evidence.boot_id,
        "checked_at": evidence.checked_at,
        "checks": dict(evidence.checks),
        "contract": CONTRACT,
        "scope_digest": evidence.scope_digest,
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
                                 tuple((name, checks[name]) for name in CHECKS),
                                 document["scope_digest"])
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


#: Private test seam: the digest credential's path. Production is exactly
#: `SCOPE_DIGEST_CREDENTIAL_PATH`.
_DIGEST_PATH = SCOPE_DIGEST_CREDENTIAL_PATH


def read_scope_digest_credential() -> str:
    """The pass's scope digest, from the decoy's credential, or refused.

    Neither the credential directory nor the file may be a link; the file
    must be a regular one with one link, owned by root or by the decoy's own
    account (systemd hands a credential to an unprivileged unit either with
    an access list on a root-owned file or by changing its owner), writable
    by nobody else, and exactly `sha256:<64 hex>` and a newline. An absent
    credential refuses: under its unit a missing source fails the start, and
    outside it the decoy has no scope to compare with.
    """

    directory_path, _, name = _DIGEST_PATH.rpartition("/")
    owners = {_OWNER, os.geteuid()}
    try:
        directory = os.open(directory_path, _DIR_FLAGS)
    except OSError:
        raise IsolationEvidenceRefused("the scope digest credential is absent") from None
    try:
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=directory)
        except OSError:
            raise IsolationEvidenceRefused("the scope digest credential is absent") from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid not in owners or info.st_mode & 0o022
                    or info.st_size != _DIGEST_FILE_BYTES):
                raise IsolationEvidenceRefused(
                    "the scope digest credential has unsafe ownership, mode or size")
            data = os.read(fd, _DIGEST_FILE_BYTES + 1)
        except OSError:
            raise IsolationEvidenceRefused(
                "the scope digest credential could not be read") from None
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise IsolationEvidenceRefused("the scope digest credential is not a digest") from None
    if not text.endswith("\n") or not _SCOPE_DIGEST.match(text[:-1]):
        raise IsolationEvidenceRefused("the scope digest credential is not a digest")
    return text[:-1]


def require_isolation_for_decoy(*, now: str) -> IsolationEvidence:
    """The decoy's gate: this boot's passing record, or `IsolationEvidenceRefused`.

    Called by `az-decoyd` before it opens any socket. No argument, file,
    environment variable or flag skips it; an absent record refuses. Since
    #196 G6 (D2) the record must also name a scope (`scope_digest` not
    `none`), and that digest must equal the one the activation pass rendered
    for this grant, read from the decoy's own credential
    (`read_scope_digest_credential`).
    """

    try:
        boot_id = _boot_id()
    except BootIdRefused:
        raise IsolationEvidenceRefused("this boot's id could not be read") from None
    evidence = load_evidence()
    if evidence is None:
        raise IsolationEvidenceRefused(
            "no isolation evidence: the network helper has not recorded one this boot")
    refusal = admission_refusal(evidence, boot_id=boot_id, now=now)
    if refusal is not None:
        raise IsolationEvidenceRefused(refusal)
    if evidence.scope_digest == NO_SCOPE:
        raise IsolationEvidenceRefused(
            "the isolation evidence names no scope: the helper ran without one")
    if evidence.scope_digest != read_scope_digest_credential():
        raise IsolationEvidenceRefused(
            "the isolation evidence's scope is not the one the activation pass rendered")
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
