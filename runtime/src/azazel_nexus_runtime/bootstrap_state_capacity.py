"""Read-only capacity prerequisite for the actual bootstrap/audit directories.

Filesystem availability is not a reservation, quota check, encryption proof or
permission probe as the service account. Threshold authority belongs to policy.
"""

from dataclasses import dataclass
import os
import pwd

from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_audit import _protected

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class BootstrapStateFloors:
    bootstrap_bytes: int
    bootstrap_inodes: int
    audit_bytes: int
    audit_inodes: int

    def __post_init__(self):
        for value in (self.bootstrap_bytes, self.bootstrap_inodes,
                      self.audit_bytes, self.audit_inodes):
            if type(value) is not int or not 0 < value < 2**63:
                raise ApprovalRefused("explicit positive state capacity floors required")


def _open(kind, owner):
    if kind not in {"bootstrap", "audit"}:
        raise ApprovalRefused("fixed state directory required")
    fd = os.open("/", _FLAGS)
    try:
        for component in ("var", "lib", "azazel", "state", kind):
            _protected(fd, owner=0, directory=True)
            child = os.open(component, _FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
        info = _protected(fd, owner=owner, directory=True)
        if kind == "bootstrap" and info.st_mode & 0o077:
            raise ApprovalRefused("private bootstrap state required")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _sample(kind, owner):
    fd = _open(kind, owner)
    try:
        identity = os.fstat(fd)
        usage = os.fstatvfs(fd)
        values = (usage.f_frsize, usage.f_bavail, usage.f_bfree, usage.f_blocks,
                  usage.f_favail, usage.f_ffree, usage.f_files, usage.f_flag)
        if (any(type(value) is not int or value < 0 for value in values)
                or usage.f_frsize == 0 or usage.f_flag & os.ST_RDONLY
                or not usage.f_bavail <= usage.f_bfree <= usage.f_blocks
                or not usage.f_favail <= usage.f_ffree <= usage.f_files):
            raise ApprovalRefused("state filesystem capacity unavailable")
        current = _open(kind, owner)
        try:
            fresh = os.fstat(current)
            if (identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino):
                raise ApprovalRefused("state path changed")
        finally:
            os.close(current)
        return identity.st_dev, usage.f_bavail * usage.f_frsize, usage.f_favail
    finally:
        os.close(fd)


def require_bootstrap_state_capacity(floors: BootstrapStateFloors) -> None:
    """Fresh two-directory check; same-volume floors are added, not double-counted.

    No path/owner overrides, root-volume fallback, directory creation or defaults.
    The controller must separately ensure storage trust and lifecycle reserves;
    other writers may consume space immediately after this snapshot.
    """
    try:
        if type(floors) is not BootstrapStateFloors:
            raise ApprovalRefused("independently admitted state floors required")
        audit_owner = pwd.getpwnam("azaudit").pw_uid
        if type(audit_owner) is not int or audit_owner <= 0:
            raise ApprovalRefused("audit service owner unavailable")
        bootstrap = _sample("bootstrap", 0)
        audit = _sample("audit", audit_owner)
        if bootstrap[0] == audit[0]:
            enough = (min(bootstrap[1], audit[1]) >= floors.bootstrap_bytes + floors.audit_bytes
                      and min(bootstrap[2], audit[2]) >= floors.bootstrap_inodes + floors.audit_inodes)
        else:
            enough = (bootstrap[1] >= floors.bootstrap_bytes
                      and bootstrap[2] >= floors.bootstrap_inodes
                      and audit[1] >= floors.audit_bytes and audit[2] >= floors.audit_inodes)
        if not enough:
            raise ApprovalRefused("state capacity floors not met")
    except Exception:
        raise ApprovalRefused("bootstrap state capacity prerequisite refused") from None
