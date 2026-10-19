"""Read explicit protected per-boot selection, never from a candidate approval."""

import os
import fcntl
from hashlib import sha256

from .activation_store import _private_directory, _read_file_at
from .bootstrap_deployment_store import load_bootstrap_deployment
from .bootstrap_selection import decode_bootstrap_selection, bind_bootstrap_selection
from .bootstrap_store import _bootstrap_directory
from .hil_preflight import read_boot_id
from .operator_trust import ApprovalRefused

_PENDING = b"administrator bootstrap selection publication pending\n"


class SelectionReadRefused(ApprovalRefused):
    """Redacted read failure category; never carries boot or identity values."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__("protected bootstrap selection refused: " + reason)


class SelectionDurabilityUncertain(ApprovalRefused):
    """Selection may be readable but final directory durability is unknown."""


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
            count = os.write(output, remaining)
            if count <= 0:
                raise OSError("selection short write")
            remaining = remaining[count:]
        os.fsync(output)
    finally:
        os.close(output)


def _publish_at(fd, raw, *, owner, confirmed_sha256, confirmed_operation,
                recovery, recheck):
    """Ordinary-file seam. No overwrite, repair, renewal or new identifier."""
    decode_bootstrap_selection(raw)
    if (confirmed_operation is not True or type(confirmed_sha256) is not str
            or confirmed_sha256 != sha256(raw).hexdigest() or type(recovery) is not bool):
        raise ApprovalRefused("separate digest and exact operation confirmation required")
    _private_directory(fd, owner=owner)

    def check_retained():
        if (_read_file_at(fd, "selection.pending", owner=owner, limit=128) != _PENDING
                or _read_file_at(fd, "selection.json", owner=owner, limit=4096) != raw):
            raise ApprovalRefused("retained selection differs")

    recheck()
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        if not recovery:
            if any(_exists(fd, name) for name in ("selection.json", "selection.pending")):
                raise ApprovalRefused("existing selection cannot be replaced")
            _write_new(fd, "selection.pending", _PENDING)
            os.fsync(fd)
            _write_new(fd, "selection.json", raw)
        check_retained()
        retained = os.open("selection.json", os.O_RDONLY | os.O_NOFOLLOW
                           | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        try:
            os.fsync(retained)
        finally:
            os.close(retained)
        os.fsync(fd)
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        recheck()
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_retained()
        os.unlink("selection.pending", dir_fd=fd)
        try:
            os.fsync(fd)
        except OSError:
            raise SelectionDurabilityUncertain("selection durability unconfirmed") from None
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _publish(raw, *, confirmed_sha256, confirmation, recovery):
    try:
        selection = decode_bootstrap_selection(raw)
        declaration = load_bootstrap_deployment()
        with _bootstrap_directory() as fd:
            identity = os.fstat(fd)

            def recheck():
                bind_bootstrap_selection(selection, deployment=declaration, boot_id=read_boot_id())
                if load_bootstrap_deployment() != declaration:
                    raise ApprovalRefused("deployment changed during selection publication")
                with _bootstrap_directory() as current:
                    fresh = os.fstat(current)
                    if (identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino):
                        raise ApprovalRefused("selection directory changed")

            _publish_at(fd, raw, owner=0, confirmed_sha256=confirmed_sha256,
                        confirmed_operation=confirmation, recovery=recovery, recheck=recheck)
    except SelectionDurabilityUncertain:
        raise
    except Exception:
        raise ApprovalRefused("selection publication refused; inspect retained state") from None


def initialize_bootstrap_selection(raw: bytes, *, confirmed_sha256: str, confirmed_initialize: bool):
    """Explicit initial per-boot intent. No approval or retained deadline reset."""
    _publish(raw, confirmed_sha256=confirmed_sha256, confirmation=confirmed_initialize, recovery=False)


def recover_bootstrap_selection(raw: bytes, *, confirmed_sha256: str, confirmed_recovery: bool):
    """Complete only exact pending bytes still bound to this deployment and boot."""
    _publish(raw, confirmed_sha256=confirmed_sha256, confirmation=confirmed_recovery, recovery=True)


def _read_at(fd, *, owner):
    try:
        os.stat("selection.pending", dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return _read_file_at(fd, "selection.json", owner=owner, limit=4096)
    raise ApprovalRefused("bootstrap selection publication unfinished")


def load_bootstrap_selection():
    """Fixed protected file, current boot and complete deployment binding.

    No creation, latest-number inference, UUID generation or approval parsing.
    A local administrator record is not an independent rollback anchor.
    """
    reason = "deployment unreadable or verification refused"
    try:
        declaration = load_bootstrap_deployment()
        reason = "current boot unreadable"
        boot = read_boot_id()
        reason = "selection unreadable or protection refused"
        with _bootstrap_directory() as fd:
            identity = os.fstat(fd)
            raw = _read_at(fd, owner=0)
            reason = "selection format refused"
            selection = decode_bootstrap_selection(raw)
            if selection.boot_id != boot:
                raise SelectionReadRefused("boot binding differs from the current boot")
            reason = "deployment binding differs"
            bind_bootstrap_selection(selection, deployment=declaration, boot_id=boot)
            reason = "selection or source changed during read"
            with _bootstrap_directory() as current:
                fresh = os.fstat(current)
                if ((identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino)
                        or _read_at(current, owner=0) != raw):
                    raise ApprovalRefused("bootstrap selection changed")
            if read_boot_id() != boot or load_bootstrap_deployment() != declaration:
                raise ApprovalRefused("bootstrap selection source changed")
            return selection
    except SelectionReadRefused:
        raise
    except FileNotFoundError:
        raise SelectionReadRefused("required bootstrap input missing") from None
    except (OSError, ApprovalRefused):
        raise SelectionReadRefused(reason) from None
    except Exception:
        raise ApprovalRefused("protected bootstrap selection refused") from None
