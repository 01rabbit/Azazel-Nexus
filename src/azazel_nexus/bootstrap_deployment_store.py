"""Fixed administrator declaration store; never an approval or start grant."""

import fcntl
from hashlib import sha256
import os

from .activation_store import _private_directory, _read_file_at
from .bootstrap_deployment import decode_bootstrap_deployment
from .bootstrap_store import _bootstrap_directory
from .operator_trust import ApprovalRefused

_PENDING_BYTES = b"administrator deployment publication pending\n"


class DeploymentDurabilityUncertain(ApprovalRefused):
    """Publication may be readable, but final durability was not confirmed."""


def _finish(fd):
    os.unlink("deployment.pending", dir_fd=fd)
    try:
        os.fsync(fd)
    except OSError:
        raise DeploymentDurabilityUncertain("declaration may be published; durability unconfirmed") from None


def _read_at(fd, *, owner):
    _private_directory(fd, owner=owner)
    if _exists(fd, "deployment.pending"):
        raise ApprovalRefused("deployment publication needs operator review")
    return _read_file_at(fd, "deployment.json", owner=owner, limit=4096)


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _write_new(fd, name, raw):
    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(output, remaining)
            if written <= 0:
                raise OSError("deployment short write")
            remaining = remaining[written:]
        os.fsync(output)
    finally:
        os.close(output)


def _validate_confirmation(raw, confirmed_sha256, confirmed_initialize):
    decode_bootstrap_deployment(raw)
    if (confirmed_initialize is not True or type(confirmed_sha256) is not str
            or confirmed_sha256 != sha256(raw).hexdigest()):
        raise ApprovalRefused("separate declaration digest and initialization confirmation required")


def _initialize_at(fd, raw, *, owner, confirmed_sha256, confirmed_initialize):
    """Ordinary-file test seam. Existing or interrupted state is never replaced."""
    _validate_confirmation(raw, confirmed_sha256, confirmed_initialize)
    _private_directory(fd, owner=owner)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        if any(_exists(fd, name) for name in ("deployment.json", "deployment.pending")):
            raise ApprovalRefused("deployment already exists or publication unfinished")
        _write_new(fd, "deployment.pending", _PENDING_BYTES)
        os.fsync(fd)
        _write_new(fd, "deployment.json", raw)
        if _read_file_at(fd, "deployment.json", owner=owner, limit=4096) != raw:
            raise ApprovalRefused("published declaration differs")
        os.fsync(fd)
        _finish(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def initialize_bootstrap_deployment(raw: bytes, *, confirmed_sha256: str,
                                    confirmed_initialize: bool) -> None:
    """Explicit administrator publication to an already protected fixed directory.

    Caller supplies two independent confirmations, not an admission claim.
    Never creates directories, overwrites existing state, installs services or
    retries interrupted transactions. Failure may leave files requiring review;
    pending state blocks readers. Local storage is not a rollback anchor.
    """
    try:
        _validate_confirmation(raw, confirmed_sha256, confirmed_initialize)
        with _bootstrap_directory() as fd:
            _initialize_at(fd, raw, owner=0, confirmed_sha256=confirmed_sha256,
                           confirmed_initialize=confirmed_initialize)
    except DeploymentDurabilityUncertain:
        raise
    except Exception:
        raise ApprovalRefused("deployment publication refused; inspect retained state before retry") from None


def _recover_at(fd, raw, *, owner, confirmed_sha256, confirmed_recovery):
    """Finish only an exact, complete retained publication; never repair bytes."""
    _validate_confirmation(raw, confirmed_sha256, confirmed_recovery)
    _private_directory(fd, owner=owner)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        def check():
            if (_read_file_at(fd, "deployment.pending", owner=owner, limit=128) != _PENDING_BYTES
                    or _read_file_at(fd, "deployment.json", owner=owner, limit=4096) != raw):
                raise ApprovalRefused("retained deployment does not match recovery confirmation")

        check()
        retained = os.open("deployment.json", os.O_RDONLY | os.O_NOFOLLOW
                           | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            os.fsync(retained)
        finally:
            os.close(retained)
        os.fsync(fd)
        check()
        _finish(fd)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def recover_bootstrap_deployment(raw: bytes, *, confirmed_sha256: str,
                                 confirmed_recovery: bool) -> None:
    """Explicit recovery of complete pending bytes, not repair or rollback.

    Incomplete/unknown state is left untouched. A final fsync error can leave
    readable state with uncertain durability, just as during initialization.
    """
    try:
        _validate_confirmation(raw, confirmed_sha256, confirmed_recovery)
        with _bootstrap_directory() as fd:
            _recover_at(fd, raw, owner=0, confirmed_sha256=confirmed_sha256,
                        confirmed_recovery=confirmed_recovery)
    except DeploymentDurabilityUncertain:
        raise
    except Exception:
        raise ApprovalRefused("deployment recovery refused; inspect retained state") from None


def load_bootstrap_deployment():
    """Read /etc/azazel/bootstrap/deployment.json, not approval.json.

    Cooperative reinspection does not establish independent rollback protection
    or defend hostile root. No configurable path/owner/environment override.
    """
    try:
        with _bootstrap_directory() as fd:
            before = os.fstat(fd)
            raw = _read_at(fd, owner=0)
            result = decode_bootstrap_deployment(raw)
            with _bootstrap_directory() as current_fd:
                current = os.fstat(current_fd)
                if ((before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
                        or _read_at(current_fd, owner=0) != raw):
                    raise ApprovalRefused("deployment declaration changed")
            return result
    except Exception:
        raise ApprovalRefused("protected bootstrap deployment refused") from None
