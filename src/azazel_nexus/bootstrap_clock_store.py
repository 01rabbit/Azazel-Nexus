"""Protected explicit administrator time source; never OS synchronization trust.

The local root administrator is the selected source authority. This is not
proof of authenticated network time, hardware attestation or correct calibration.
Publication requires separate explicit confirmations; readers never create records.
"""

import os
import fcntl
from hashlib import sha256

from .activation_store import _private_directory, _read_file_at
from .bootstrap_approval import BootstrapContext
from .bootstrap_clock import decode_administrator_anchor, project_administrator_window
from .bootstrap_deadline import read_boottime_ns
from .bootstrap_prestart_store import load_bootstrap_prestart_policy
from .bootstrap_store import _bootstrap_directory
from .hil_preflight import read_boot_id
from .operator_trust import ApprovalRefused

_PENDING = b"administrator time publication pending\n"


class TimeDurabilityUncertain(ApprovalRefused):
    """Record may be published but final directory durability is unknown."""


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _read_at(fd, *, owner):
    if _exists(fd, "time.pending"):
        raise ApprovalRefused("administrator time publication pending review")
    return _read_file_at(fd, "time.json", owner=owner, limit=4096)


def _write_new(fd, name, raw):
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            count = os.write(output, remaining)
            if count <= 0:
                raise OSError("administrator time short write")
            remaining = remaining[count:]
        os.fsync(output)
    finally:
        os.close(output)


def _initialize_at(fd, raw, *, owner, confirmed_sha256, confirmed_initialize,
                   validate_current):
    """Private ordinary-file seam; interrupted/existing records are never replaced."""
    decode_administrator_anchor(raw)
    if (confirmed_initialize is not True or type(confirmed_sha256) is not str
            or sha256(raw).hexdigest() != confirmed_sha256):
        raise ApprovalRefused("separate digest and publication confirmation required")
    _private_directory(fd, owner=owner)
    validate_current()
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        if any(_exists(fd, name) for name in ("time.json", "time.pending")):
            raise ApprovalRefused("existing time state requires administrator review")
        _write_new(fd, "time.pending", _PENDING)
        os.fsync(fd)
        _write_new(fd, "time.json", raw)
        if _read_file_at(fd, "time.json", owner=owner, limit=4096) != raw:
            raise ApprovalRefused("retained time differs")
        os.fsync(fd)
        # Protected readers reopen this directory with shared locks. Retain the
        # pending marker while allowing their read-only policy/path checks.
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        validate_current()
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if (_read_file_at(fd, "time.pending", owner=owner, limit=128) != _PENDING
                or _read_file_at(fd, "time.json", owner=owner, limit=4096) != raw):
            raise ApprovalRefused("retained time publication changed")
        os.unlink("time.pending", dir_fd=fd)
        try:
            os.fsync(fd)
        except OSError:
            raise TimeDurabilityUncertain("time publication durability unconfirmed") from None
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _recover_at(fd, raw, *, owner, confirmed_sha256, confirmed_recovery,
                validate_current):
    """Finish only complete confirmed pending bytes; never repair or renew."""
    decode_administrator_anchor(raw)
    if (confirmed_recovery is not True or type(confirmed_sha256) is not str
            or sha256(raw).hexdigest() != confirmed_sha256):
        raise ApprovalRefused("separate digest and recovery confirmation required")
    _private_directory(fd, owner=owner)

    def check():
        if (_read_file_at(fd, "time.pending", owner=owner, limit=128) != _PENDING
                or _read_file_at(fd, "time.json", owner=owner, limit=4096) != raw):
            raise ApprovalRefused("retained time does not match recovery confirmation")

    validate_current()
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        check()
        retained = os.open("time.json", os.O_RDONLY | os.O_NOFOLLOW
                           | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            os.fsync(retained)
        finally:
            os.close(retained)
        os.fsync(fd)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        validate_current()
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check()
        os.unlink("time.pending", dir_fd=fd)
        try:
            os.fsync(fd)
        except OSError:
            raise TimeDurabilityUncertain("time recovery durability unconfirmed") from None
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def initialize_administrator_time(raw: bytes, *, expected: BootstrapContext,
                                  confirmed_sha256: str, confirmed_initialize: bool,
                                  revalidate_selection=None):
    """Publish explicitly supplied UTC bounds, never infer them from OS wall time.

    Independent context and its protected policy are mandatory. This operation
    neither sets the system clock nor grants runtime admission. No replacement,
    renewal, implicit directory creation or automatic recovery is performed.
    Optional selection revalidation is a trusted composition callback, not RPC
    input. It must return exactly None or raise; it runs before completion.
    """
    _publish(raw, expected=expected, confirmed_sha256=confirmed_sha256,
             confirmation=confirmed_initialize, recovery=False, revalidate_selection=revalidate_selection)


def recover_administrator_time(raw: bytes, *, expected: BootstrapContext,
                               confirmed_sha256: str, confirmed_recovery: bool,
                               revalidate_selection=None):
    """Explicitly finish an exact pending anchor still valid in this boot.

    Expired, other-boot, incomplete and unknown retained state stays untouched.
    Does not renew the anchor or extend any approval or per-boot deadline.
    """
    _publish(raw, expected=expected, confirmed_sha256=confirmed_sha256,
             confirmation=confirmed_recovery, recovery=True, revalidate_selection=revalidate_selection)


def _publish(raw, *, expected, confirmed_sha256, confirmation, recovery, revalidate_selection):
    try:
        if revalidate_selection is not None and not callable(revalidate_selection):
            raise ApprovalRefused("selection revalidation callback required")
        if type(expected) is not BootstrapContext:
            raise ApprovalRefused("independent bootstrap context required")
        anchor = decode_administrator_anchor(raw)
        policy = load_bootstrap_prestart_policy(expected=expected)
        with _bootstrap_directory() as fd:
            identity = os.fstat(fd)
            previous = None

            def validate_current():
                nonlocal previous
                if revalidate_selection is not None and revalidate_selection() is not None:
                    raise ApprovalRefused("selection revalidation did not complete")
                if (read_boot_id() != expected.boot_id
                        or load_bootstrap_prestart_policy(expected=expected) != policy):
                    raise ApprovalRefused("boot or clock policy changed")
                observed = read_boottime_ns()
                if previous is not None and observed < previous:
                    raise ApprovalRefused("boot clock regressed during publication")
                project_administrator_window(anchor, expected=expected,
                                             boottime_ns=observed,
                                             limits=policy.clock_limits())
                previous = observed
                with _bootstrap_directory() as current:
                    fresh = os.fstat(current)
                    if (identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino):
                        raise ApprovalRefused("clock publication directory changed")

            if recovery:
                _recover_at(fd, raw, owner=0, confirmed_sha256=confirmed_sha256,
                            confirmed_recovery=confirmation, validate_current=validate_current)
            else:
                _initialize_at(fd, raw, owner=0, confirmed_sha256=confirmed_sha256,
                               confirmed_initialize=confirmation, validate_current=validate_current)
    except TimeDurabilityUncertain:
        raise
    except Exception:
        raise ApprovalRefused("administrator time publication refused; inspect retained state") from None


def load_administrator_time_window(*, expected: BootstrapContext):
    """Read the fixed /etc/azazel/bootstrap/time.json against independent context.

    A persisted record from another boot refuses. This function must only be used
    in the explicitly selected administrator-managed source mode. Missing files
    do not fall back to wall time, sync markers, candidate timestamps or creation.
    """
    try:
        if type(expected) is not BootstrapContext or read_boot_id() != expected.boot_id:
            raise ApprovalRefused("current independent boot required")
        with _bootstrap_directory() as fd:
            identity = os.fstat(fd)
            raw = _read_at(fd, owner=0)
            anchor = decode_administrator_anchor(raw)
            policy = load_bootstrap_prestart_policy(expected=expected)
            observed = read_boottime_ns()
            window = project_administrator_window(anchor, expected=expected, boottime_ns=observed,
                                                   limits=policy.clock_limits())
            with _bootstrap_directory() as current:
                fresh = os.fstat(current)
                if ((identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino)
                        or _read_at(current, owner=0) != raw):
                    raise ApprovalRefused("administrator clock record changed")
            if load_bootstrap_prestart_policy(expected=expected) != policy:
                raise ApprovalRefused("clock policy changed")
            if read_boot_id() != expected.boot_id:
                raise ApprovalRefused("boot changed during time observation")
            final = read_boottime_ns()
            if type(final) is not int or not observed <= final < window.valid_until_boottime_ns:
                raise ApprovalRefused("administrator time window expired during observation")
            return window
    except Exception:
        raise ApprovalRefused("protected administrator time refused") from None
