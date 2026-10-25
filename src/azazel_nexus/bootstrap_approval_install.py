"""Place an already verified bootstrap approval pair; never sign or admit.

The caller (``az-nexus-bootstrap approval-install``) verifies the pair with the
same ``verify_bootstrap_approval`` the bootstrap admission uses and passes that
verification as ``recheck``, which runs again before the pair is renamed into
place. A pair of the current boot is never replaced; a canonical pair of a prior
boot is recorded and moved aside first. Placement is not admission: the
bootstrap entrypoint verifies the installed pair again against its own fresh
observation on every attempt.
"""

import fcntl
import json
import os

from .activation_store import _private_directory, _read_file_at
from .bootstrap_approval import BootstrapContext, bootstrap_payload
from .bootstrap_prior_boot import retire_prior_boot_records
from .bootstrap_store import _bootstrap_directory
from .operator_store import _unique_object
from .operator_trust import MAX_APPROVAL_BYTES, ApprovalRefused

_NAMES = ("approval.json", "approval.sig")
_LIMITS = (MAX_APPROVAL_BYTES, 64)
_PARTIALS = (".approval.json.partial", ".approval.sig.partial")


class ApprovalPlacementUncertain(ApprovalRefused):
    """A rename may have happened but durability or read-back is unconfirmed."""


def approval_boot_id(payload: bytes) -> str:
    """Boot of exact canonical payload bytes; no signature or time check."""
    document = json.loads(payload, object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != {
        "schema", "purpose", "context", "operator", "units", "granted_at", "expires_at"
    } or type(document["context"]) is not dict:
        raise ApprovalRefused("bootstrap approval fields refused")
    context = BootstrapContext(**document["context"])
    if bootstrap_payload(context=context, operator=document["operator"],
                         granted_at=document["granted_at"],
                         expires_at=document["expires_at"]) != payload:
        raise ApprovalRefused("noncanonical bootstrap approval refused")
    return context.boot_id


def _prior_boot(raws):
    payload, signature = raws
    if len(signature) != 64:
        raise ApprovalRefused("invalid bootstrap signature size")
    return approval_boot_id(payload)


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
        os.fchmod(output, 0o600)
        remaining = memoryview(raw)
        while remaining:
            count = os.write(output, remaining)
            if count <= 0:
                raise OSError("approval short write")
            remaining = remaining[count:]
        os.fsync(output)
    finally:
        os.close(output)


def _install_at(fd, payload, signature, *, owner, recheck, record_prior_boot):
    """Ordinary-file seam. The caller has verified; ``recheck`` verifies again."""
    current_boot = approval_boot_id(payload)
    if len(signature) != 64:
        raise ApprovalRefused("invalid bootstrap signature size")
    _private_directory(fd, owner=owner)
    # Verified again before anything changes; a refusal here leaves all as it was.
    recheck()
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        if any(_exists(fd, name) for name in _PARTIALS):
            raise ApprovalRefused("interrupted approval placement requires administrator review")
        if any(_exists(fd, name) for name in _NAMES):
            retire_prior_boot_records(
                fd, kind="approval", names=_NAMES, limits=_LIMITS, pending=(),
                owner=owner, read_file=_read_file_at, boot_of=_prior_boot,
                current_boot=current_boot, record=record_prior_boot)
        written = []
        try:
            for name, data in zip(_PARTIALS, (payload, signature)):
                written.append(name)
                _write_new(fd, name, data)
            os.fsync(fd)
            # The verifier's protected readers take shared locks on this directory.
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            recheck()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if (any(_exists(fd, name) for name in _NAMES)
                    or tuple(_read_file_at(fd, name, owner=owner, limit=limit)
                             for name, limit in zip(_PARTIALS, _LIMITS)) != (payload, signature)):
                raise ApprovalRefused("approval placement state changed")
        except BaseException:
            for name in written:
                try:
                    os.unlink(name, dir_fd=fd)
                except OSError:
                    pass
            raise
        try:
            for partial, name in zip(_PARTIALS, _NAMES):
                os.rename(partial, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
            if tuple(_read_file_at(fd, name, owner=owner, limit=limit)
                     for name, limit in zip(_NAMES, _LIMITS)) != (payload, signature):
                raise ApprovalRefused("installed approval read-back differs")
        except Exception:
            raise ApprovalPlacementUncertain("approval placement unconfirmed") from None
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def install_bootstrap_approval(payload: bytes, signature: bytes, *, recheck,
                               record_prior_boot):
    """Fixed protected directory; no path, owner or verification override."""
    try:
        if type(payload) is not bytes or type(signature) is not bytes:
            raise ApprovalRefused("approval bytes required")
        if not callable(recheck) or not callable(record_prior_boot):
            raise ApprovalRefused("verification and record callbacks required")
        with _bootstrap_directory() as fd:
            identity = os.fstat(fd)

            def checked():
                if recheck() is not None:
                    raise ApprovalRefused("approval verification did not complete")
                with _bootstrap_directory() as current:
                    fresh = os.fstat(current)
                    if (identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino):
                        raise ApprovalRefused("approval directory changed")

            _install_at(fd, payload, signature, owner=0, recheck=checked,
                        record_prior_boot=record_prior_boot)
    except ApprovalPlacementUncertain:
        raise
    except Exception:
        raise ApprovalRefused("bootstrap approval placement refused; inspect retained state") from None
