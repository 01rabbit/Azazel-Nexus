"""Knowledge Lite trust maintenance while the integrated loop runs (ADR 0007).

Three fixed root operations of `az-nexus-commission`, each one audited
transaction with no path, key, policy or override argument:

* `trust-enroll`: the first registration of a trust root
  (`azazel_nexus.lite_enrollment`), from the one fixed leaf
  `/etc/azazel/commissioning/lite-enrollment.json`;
* `trust-repin --reason R`: replacing the pinned keys or revocation authority
  (`TrustStore.repin` through `RepinConfirmation`), from the fixed leaf
  `repin-anchor.json`;
* `knowledge-revocation-accept`: a signed cumulative revocation list
  (`RevocationAcceptance`), from the fixed leaf `lite-revocations.signed`.

**Why not `az-commissiond`.** Its trust verbs are only reachable while it
runs, and it runs only under the supporting-only bootstrap: on the ordinary
path it is masked and bound to the controller, which exits right after its
pass (docs/activation-observe-baseline.md §6, decisions 2 and 8). The work
itself never needed a daemon: root asks, the signed or confirmed input is the
authority, and the change is the commissioning account's. So the transaction
is root's own process, narrowed before it touches anything:

1. as root: refuse a non-root caller; for enrollment and repin, require a
   local terminal and fresh confirmation words, as the commissioning wizard
   does; for enrollment, verify the node's commissioning evidence the way the
   activation pass does and keep only its digest;
2. in a child that has **become `azcommission`** (its groups `azknowledge` and
   `azaudit-submit`, umask `0027`, `no_new_privs`, no way back to root): take
   the commissioning lock, append `..._requested` to `az-auditd` and refuse if
   that append fails (nothing is changed without its record), make the change
   with the same library code commissiond runs, append the outcome.

The audit records go to `az-auditd` over its append-only `audit-submit`
listener, which serves the integrated loop through
`azazel-auditd-loop.service` and a bootstrap boot through the helper
`azazel-auditd.service`: the same chain either way, and auditd binds every
`knowledge.lite.trust_*` and `knowledge.lite.revocation_*` record to
`azcommission`. A stopped auditd therefore refuses every one of these
operations before any change. Repin also keeps writing its own commissioning
ledger (`trust.repin.authorized` / `promoted`); the auditd record carries the
anchor file digest and the promoted generation, which the commissioning
ledger's record names too, so the two are matched by generation (owner-decisions
M11: one shared provenance key, not one merged ledger).

The commissioning lock (`state/commission/trust.lock`, held with `flock`)
serializes these transactions with each other and with commissiond's trust
verbs, which take the same lock: the library's repin reservation assumes one
commissioning request at a time.

Nothing here starts, stops, masks or unmasks a unit, and nothing reads an
environment variable.
"""

from __future__ import annotations

import ctypes
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional

from azazel_nexus.lite_enrollment import (
    ENROLLMENT_FILENAME,
    MAX_ENROLLMENT_BYTES,
    EnrollmentRefused,
    decode_enrollment,
    enroll,
)

from .principal import Principal, PrincipalPolicy

__all__ = [
    "COMMISSION_ACCOUNT",
    "COMMISSION_GROUPS",
    "LOCK_NAME",
    "TrustBusy",
    "become_commissioner",
    "enroll_transaction",
    "repin_transaction",
    "revocation_transaction",
    "run_as_commissioner",
    "run_enroll",
    "run_repin",
    "run_revocation_accept",
    "trust_lock",
]

#: The account and groups of `azazel-commissiond.service` (hardening.py):
#: the trust root's owner, the Lite reader's group, auditd's append listener.
COMMISSION_ACCOUNT = "azcommission"
COMMISSION_GROUPS = ("azknowledge", "azaudit-submit")
LOCK_NAME = "trust.lock"
_RESULT_LIMIT = 4096
_PR_SET_NO_NEW_PRIVS = 38
_WORD = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z", re.ASCII)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z", re.ASCII)


class TrustBusy(Exception):
    """Another commissioning transaction holds the lock."""


def _is_root() -> bool:
    return os.geteuid() == 0


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def root_principal() -> Principal:
    """The invoking root, as `PrincipalPolicy` classifies uid 0.

    The trust classes (`RepinConfirmation`, `RevocationAcceptance`) admit ROOT
    only; this is the caller root really is, checked by `os.geteuid()` before
    the transaction narrows itself.
    """
    return PrincipalPolicy(operator_gid=None, service_uids=frozenset()).classify(
        0, 0, os.getpid())


@contextmanager
def trust_lock(directory: Path) -> Iterator[None]:
    """Hold the commissioning lock in commissiond's private state leaf.

    Never blocks: a held lock refuses with `TrustBusy`. A lock file that is
    not a private regular file of the leaf's owner refuses with
    `PermissionError`. The kernel releases the lock when the holder ends, so
    an interrupted transaction never leaves it held.
    """

    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        owner = os.fstat(parent).st_uid
        descriptor = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise PermissionError("commissioning lock refused")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise TrustBusy("another commissioning transaction is running") from None
        yield
    finally:
        os.close(descriptor)


def _no_new_privileges() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "no_new_privs refused")


def become_commissioner() -> None:
    """Irrevocably become `azcommission` with commissiond's groups, or raise.

    Groups first, then the group ids, then the user ids (saved ids included),
    so nothing is left to regain root with; then `no_new_privs` and the unit's
    umask. The result is read back, not assumed.
    """

    entry = pwd.getpwnam(COMMISSION_ACCOUNT)
    groups = sorted({grp.getgrnam(name).gr_gid for name in COMMISSION_GROUPS})
    os.setgroups(groups)
    os.setresgid(entry.pw_gid, entry.pw_gid, entry.pw_gid)
    os.setresuid(entry.pw_uid, entry.pw_uid, entry.pw_uid)
    _no_new_privileges()
    os.umask(0o027)
    if (os.getresuid() != (entry.pw_uid,) * 3 or os.getresgid() != (entry.pw_gid,) * 3
            or set(os.getgroups()) - {entry.pw_gid} != set(groups)):
        raise PermissionError("commissioning identity not established")
    try:
        os.setresuid(0, 0, 0)
    except PermissionError:
        return
    raise PermissionError("root was still reachable")


def run_as_commissioner(work: Callable[[], Mapping]) -> dict:
    """Run `work` in a child that has become `azcommission`; return its result.

    The child inherits the terminal (repin asks there) and returns one bounded
    JSON object of fixed fields through a pipe. Anything else -- an exception,
    an identity that could not be established, a signal -- returns nothing
    and the caller reports a refusal; no exception text crosses back.
    """

    reader, writer = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - the child, exercised by the root e2e stage
        status = 1
        try:
            os.close(reader)
            become_commissioner()
            result = json.dumps(dict(work()), sort_keys=True).encode("utf-8")
            if len(result) <= _RESULT_LIMIT:
                os.write(writer, result)
                status = 0
        except BaseException:  # noqa: BLE001 - nothing but the exit status leaves
            status = 1
        finally:
            try:
                sys.stdout.flush()
            except BaseException:  # noqa: BLE001
                pass
            os._exit(status)
    os.close(writer)
    chunks = []
    try:
        while sum(map(len, chunks)) <= _RESULT_LIMIT:
            chunk = os.read(reader, _RESULT_LIMIT + 1)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(reader)
    _, status = os.waitpid(pid, 0)
    raw = b"".join(chunks)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0 or len(raw) > _RESULT_LIMIT:
        raise RuntimeError("commissioning transaction did not complete")
    result = json.loads(raw.decode("utf-8"))
    if type(result) is not dict:
        raise RuntimeError("commissioning transaction did not complete")
    return result


def _commissioning_dir() -> Path:
    from . import runtime_paths

    return runtime_paths.ROOT / "etc/azazel/commissioning"


def _lock_dir() -> Path:
    from . import runtime_paths

    return runtime_paths.state_dir() / "commission"


def _read_leaf(directory: Path, name: str, limit: int) -> bytes:
    """One bounded regular file under a fixed name, never through a link."""

    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=descriptor)
    finally:
        os.close(descriptor)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("input refused")
        content = stream.read(limit + 1)
    if not content or len(content) > limit:
        raise ValueError("input refused")
    return content


def _default_append(event: Mapping) -> None:
    from .lite_audit import append_event

    append_event(event)


# -- enrollment --------------------------------------------------------------


def enroll_transaction(*, confirmed_digest: str, commissioning_digest: Optional[str],
                       commissioning_dir: Path, trust_root: Path, lock_dir: Path,
                       append: Callable[[Mapping], None] = _default_append,
                       now: Callable[[], str] = _now, actor: str = "root") -> dict:
    """The commissioning account's half of `trust-enroll`. Fixed fields out.

    The request is the fixed leaf as it is **now**; if its digest is not the
    one root confirmed, nothing is written (`request_changed`). The request
    record is appended first; if auditd does not take it, nothing is written
    (`audit_unavailable`).
    """

    result = {"enrolled": False, "code": None, "bundle_keys": None, "threshold": None,
              "revocation_keys": None, "trust_fingerprint": None, "audit_complete": True}
    at = now()
    try:
        append({"event_type": "knowledge.lite.trust_enroll_requested",
                "request_digest": confirmed_digest, "occurred_at": at})
    except Exception:  # noqa: BLE001 - no record, no change
        return {**result, "code": "audit_unavailable", "audit_complete": False}

    def refused(code: str) -> dict:
        try:
            append({"event_type": "knowledge.lite.trust_enroll_refused",
                    "request_digest": confirmed_digest, "code": code, "occurred_at": at})
            complete = True
        except Exception:  # noqa: BLE001 - nothing changed either way
            complete = False
        return {**result, "code": code, "audit_complete": complete}

    try:
        with trust_lock(lock_dir):
            try:
                raw = _read_leaf(commissioning_dir, ENROLLMENT_FILENAME, MAX_ENROLLMENT_BYTES)
            except (OSError, ValueError):
                # Root read it; this account cannot (it must be group
                # azcommission, 0640), or it was replaced by something else.
                return refused("request_unreadable")
            if "sha256:" + hashlib.sha256(raw).hexdigest() != confirmed_digest:
                return refused("request_changed")
            try:
                request = decode_enrollment(raw)
                outcome = enroll(trust_root, request, commissioning_digest=commissioning_digest,
                                 enrolled_at=at, actor=actor)
            except EnrollmentRefused as refusal:
                return refused(refusal.code)
    except TrustBusy:
        return refused("busy")
    except OSError:
        return refused("write_failed")
    result = {**result, "enrolled": True, "bundle_keys": outcome.bundle_keys,
              "threshold": outcome.threshold, "revocation_keys": outcome.revocation_keys,
              "trust_fingerprint": outcome.trust_fingerprint}
    try:
        append({"event_type": "knowledge.lite.trust_enrolled",
                "request_digest": confirmed_digest,
                "trust_fingerprint": outcome.trust_fingerprint,
                "revocation_policy_fingerprint": outcome.revocation_policy_fingerprint,
                "bundle_keys": outcome.bundle_keys, "threshold": outcome.threshold,
                "revocation_keys": outcome.revocation_keys, "occurred_at": at})
    except Exception:  # noqa: BLE001 - the enrollment stands; the reply says so
        result["audit_complete"] = False
    return result


def production_evidence_digest() -> Optional[str]:
    """The node's verified commissioning digest, as the activation pass derives it.

    `load_commissioning_evidence` re-verifies the signed full commissioning
    proposal against the enrolled operator trust and the current hardware;
    the digest is the SHA-256 of those signed bytes
    (`observe_baseline.evidence_commissioning_digest`). None when it cannot
    verify: enrollment then writes nothing (`evidence_unavailable`).
    """

    try:
        from azazel_nexus.observe_baseline import evidence_commissioning_digest

        from .commissioning_input import load_commissioning_evidence

        return evidence_commissioning_digest(load_commissioning_evidence())
    except Exception:  # noqa: BLE001 - unavailable evidence binds nothing
        return None


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _summary(request, commissioning_digest: Optional[str]) -> list[str]:
    binding = ("matches this node's verified commissioning"
               if commissioning_digest == request.commissioning_digest
               else "does NOT match this node's verified commissioning"
               if commissioning_digest is not None
               else "cannot be checked: no verified commissioning evidence")
    lines = [
        f"Enrollment request: {request.digest}",
        f"Bundle-signing keys: {len(request.keys)} ({', '.join(sorted(request.keys))})",
        f"Signatures required: {request.threshold}"
        + (f" from role {request.required_signer_role}" if request.required_signer_role else ""),
        "Minimum security epoch: " + (str(request.minimum_security_epoch)
                                      if request.minimum_security_epoch is not None else "none"),
        "Accepted export policies: " + (str(len(request.accepted_export_policy_digests))
                                        if request.accepted_export_policy_digests else "any"),
        f"Revocation keys: {len(request.revocation.revocation_keys)}, "
        f"{request.revocation.threshold} required, generation {request.revocation.generation}",
        f"Commissioning binding: {binding}",
    ]
    return lines


def _ask_words(lines: list[str], prefix: str) -> bool:
    words = prefix + secrets.token_hex(8)
    for line in lines:
        print(line)
    print(f"Type {words} to continue.")
    try:
        answer = input("Confirmation: ")
    except (EOFError, KeyboardInterrupt):
        return False
    return _interactive() and secrets.compare_digest(answer, words)


def run_enroll(*, evidence: Optional[Callable[[], Optional[str]]] = None,
               confirm: Optional[Callable[[list[str]], bool]] = None,
               runner: Optional[Callable[[Callable[[], Mapping]], dict]] = None,
               append: Optional[Callable[[Mapping], None]] = None) -> int:
    """`az-nexus-commission trust-enroll`. Exit 0 only for an audited enrollment.

    The keyword arguments are test seams (the module's own functions when
    omitted); the CLI passes none.
    """

    from . import runtime_paths

    evidence = evidence or production_evidence_digest
    runner = runner or run_as_commissioner
    append = append or _default_append

    if not _is_root():
        print("trust-enroll runs as root.", file=sys.stderr)
        return 1
    if confirm is None:
        if not _interactive():
            print("Trust enrollment requires a local interactive terminal.", file=sys.stderr)
            return 1
        confirm = lambda lines: _ask_words(lines, "ENROLL-TRUST-")  # noqa: E731
    directory = _commissioning_dir()
    try:
        raw = _read_leaf(directory, ENROLLMENT_FILENAME, MAX_ENROLLMENT_BYTES)
    except (OSError, ValueError):
        print(f"No readable enrollment request at {directory / ENROLLMENT_FILENAME}; "
              "nothing was recorded or changed.", file=sys.stderr)
        return 1
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    commissioning_digest = evidence()
    try:
        request = decode_enrollment(raw)
    except EnrollmentRefused:
        request = None  # recorded and refused below, without asking
    if request is not None and not confirm(_summary(request, commissioning_digest)):
        print("Trust enrollment not confirmed; nothing was recorded or changed.", file=sys.stderr)
        return 1
    trust_root, lock_dir = runtime_paths.lite_trust_root(), _lock_dir()
    try:
        result = runner(lambda: enroll_transaction(
            confirmed_digest=digest, commissioning_digest=commissioning_digest,
            commissioning_dir=directory, trust_root=trust_root, lock_dir=lock_dir,
            append=append))
        if (set(result) != {"enrolled", "code", "bundle_keys", "threshold", "revocation_keys",
                            "trust_fingerprint", "audit_complete"}
                or type(result["enrolled"]) is not bool
                or type(result["audit_complete"]) is not bool
                or not (result["code"] is None or (type(result["code"]) is str
                                                   and _WORD.fullmatch(result["code"])))
                or not all(result[key] is None or type(result[key]) is int
                           for key in ("bundle_keys", "threshold", "revocation_keys"))
                or not (result["trust_fingerprint"] is None
                        or (type(result["trust_fingerprint"]) is str
                            and _DIGEST.fullmatch(result["trust_fingerprint"])))):
            raise ValueError("reply refused")
    except Exception:  # noqa: BLE001 - fixed words only
        print("Trust enrollment refused or interrupted; nothing is reported as done.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["enrolled"] and result["audit_complete"] else 1


# -- repin -------------------------------------------------------------------


def repin_transaction(reason: str, *, principal: Principal, commissioning_dir: Path,
                      snapshot_dir: Path, ask: Callable[[dict], Optional[str]],
                      append: Callable[[Mapping], None] = _default_append,
                      repin=None, now: Callable[[], str] = _now) -> dict:
    """The commissioning account's half of `trust-repin`. Fixed fields out.

    The confirmation words are asked here, inside the narrowed child, because
    the challenge lives in this process only. Once the human typed them, the
    request is recorded first; without that record the challenge is dropped
    and nothing is promoted.
    """

    from .protocol import RequestRefused
    from .repin_confirmation import ANCHOR_FILENAME, RepinConfirmation

    options = {} if repin is None else {"repin": repin}
    confirmation = RepinConfirmation(commissioning_dir=commissioning_dir,
                                     snapshot_dir=snapshot_dir, **options)
    result = {"promoted": False, "code": None, "generation": None, "audit_complete": True}
    try:
        with trust_lock(snapshot_dir):
            try:
                challenge = confirmation.challenge(principal, reason, ANCHOR_FILENAME)
            except RequestRefused:
                return {**result, "code": "anchor_refused"}
            echo = ask(challenge)
            if echo is None:
                return {**result, "code": "unconfirmed"}
            at = now()
            anchor = challenge["new_fingerprint"]
            try:
                append({"event_type": "knowledge.lite.trust_repin_requested",
                        "anchor_digest": anchor, "reason": reason, "occurred_at": at})
            except Exception:  # noqa: BLE001 - no record, no change
                return {**result, "code": "audit_unavailable", "audit_complete": False}
            try:
                outcome = confirmation.confirm(principal, challenge["nonce"], echo)
            except RequestRefused:
                try:
                    append({"event_type": "knowledge.lite.trust_repin_refused",
                            "anchor_digest": anchor, "occurred_at": at})
                except Exception:  # noqa: BLE001 - nothing promoted either way
                    result["audit_complete"] = False
                return {**result, "code": "refused"}
            result = {**result, "promoted": outcome["promoted"],
                      "generation": outcome["generation"]}
            try:
                append({"event_type": "knowledge.lite.trust_repin_promoted",
                        "anchor_digest": anchor, "generation": outcome["generation"],
                        "occurred_at": at})
            except Exception:  # noqa: BLE001 - the promotion stands; the reply says so
                result["audit_complete"] = False
            return result
    except TrustBusy:
        return {**result, "code": "busy"}


def _ask_repin(reason: str) -> Callable[[dict], Optional[str]]:
    def ask(challenge: dict) -> Optional[str]:
        words, digest = challenge.get("confirmation_words"), challenge.get("new_fingerprint")
        if (not isinstance(words, str) or re.fullmatch(r"REPIN-TRUST-[0-9a-f]{16}", words) is None
                or not isinstance(digest, str) or not _DIGEST.fullmatch(digest)):
            return None
        print(f"Reason: {reason}\nNew anchor file fingerprint: {digest}")
        print(f"Type {words} to replace the pinned trust anchors.")
        try:
            echo = input("Confirmation: ")
        except (EOFError, KeyboardInterrupt):
            return None
        if not _interactive() or not secrets.compare_digest(echo, words):
            return None
        return echo
    return ask


def run_repin(reason: str, *,
              runner: Optional[Callable[[Callable[[], Mapping]], dict]] = None,
              ask: Optional[Callable[[dict], Optional[str]]] = None,
              append: Optional[Callable[[Mapping], None]] = None, repin=None) -> int:
    """`az-nexus-commission trust-repin --reason R`. Keywords are test seams."""

    from .repin_confirmation import REASONS

    runner = runner or run_as_commissioner
    append = append or _default_append

    if reason not in REASONS:
        print("Choose rotation, recovery or compromise.", file=sys.stderr)
        return 2
    if not _is_root():
        print("trust-repin runs as root.", file=sys.stderr)
        return 1
    if ask is None:
        if not _interactive():
            print("Trust replacement requires a local interactive terminal.", file=sys.stderr)
            return 1
        ask = _ask_repin(reason)
    principal = root_principal()
    directory, snapshot_dir = _commissioning_dir(), _lock_dir()
    try:
        result = runner(lambda: repin_transaction(
            reason, principal=principal, commissioning_dir=directory,
            snapshot_dir=snapshot_dir, ask=ask, append=append, repin=repin))
        if (set(result) != {"promoted", "code", "generation", "audit_complete"}
                or type(result["promoted"]) is not bool
                or type(result["audit_complete"]) is not bool
                or not (result["code"] is None or (type(result["code"]) is str
                                                   and _WORD.fullmatch(result["code"])))
                or not (result["generation"] is None
                        or (type(result["generation"]) is int and result["generation"] >= 0))):
            raise ValueError("reply refused")
    except Exception:  # noqa: BLE001 - fixed words only
        print("Trust replacement refused or interrupted.", file=sys.stderr)
        return 1
    if result["promoted"] is not True:
        print("Trust replacement refused or interrupted.", file=sys.stderr)
        print(json.dumps(result, sort_keys=True))
        return 1
    print(f"Trust anchors replaced; generation {result['generation']}.")
    if not result["audit_complete"]:
        print("The promotion record did not reach az-auditd; the commissioning ledger "
              "holds it.", file=sys.stderr)
        return 1
    return 0


# -- revocation --------------------------------------------------------------


def revocation_transaction(*, principal: Principal, commissioning_dir: Path, lock_dir: Path,
                           acceptance=None) -> dict:
    """The commissioning account's half of `knowledge-revocation-accept`."""

    from .lite_revocation_accept import REVOCATION_INPUT, RevocationAcceptance
    from .protocol import RequestRefused

    if acceptance is None:
        acceptance = RevocationAcceptance(commissioning_dir=commissioning_dir)
    try:
        with trust_lock(lock_dir):
            return acceptance.accept(principal, REVOCATION_INPUT)
    except TrustBusy:
        return {"accepted": False, "code": "busy", "sequence": None, "audit_complete": False}
    except RequestRefused:
        return {"accepted": False, "code": "input_refused", "sequence": None,
                "audit_complete": False}


def run_revocation_accept(*, runner: Optional[Callable[[Callable[[], Mapping]], dict]] = None,
                          acceptance=None) -> int:
    """`az-nexus-commission knowledge-revocation-accept`. Keywords are test seams."""

    runner = runner or run_as_commissioner

    if not _is_root():
        print("knowledge-revocation-accept runs as root.", file=sys.stderr)
        return 1
    principal = root_principal()
    directory, lock_dir = _commissioning_dir(), _lock_dir()
    try:
        result = runner(lambda: revocation_transaction(
            principal=principal, commissioning_dir=directory, lock_dir=lock_dir,
            acceptance=acceptance))
        if (set(result) != {"accepted", "code", "sequence", "audit_complete"}
                or type(result["accepted"]) is not bool
                or not (result["code"] is None or (type(result["code"]) is str
                                                   and _WORD.fullmatch(result["code"])))
                or not (result["sequence"] is None or type(result["sequence"]) is int)
                or type(result["audit_complete"]) is not bool):
            raise ValueError("reply refused")
    except Exception:  # noqa: BLE001 - fixed words only
        print("Revocation acceptance refused or unavailable; nothing is reported as done.",
              file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["accepted"] and result["audit_complete"] else 1
