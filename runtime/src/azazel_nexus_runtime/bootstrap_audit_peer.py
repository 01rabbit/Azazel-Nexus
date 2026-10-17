"""Fixed audit socket/server binding for private bootstrap composition.

No RPC-selected path/account/identity. The binding is retained from the admitted
system manager, not learned from a socket response. This is not protection
against privileged process/kernel compromise or arbitrary in-process mutation.
"""

from contextlib import contextmanager, ExitStack
from dataclasses import dataclass
import grp
import os
from pathlib import Path
import pwd
import stat
import time

from .bootstrap_audit_identity import AuditServiceIdentity
from .bootstrap_cgroup_mount import _namespaces, _read_proc
from .principal import peer_credentials, REQUIRED_SOCKET_MODE
from .runtime_paths import ROOT
from .units import UnitOperationFailed

_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_GROUP = "/system.slice/azazel-auditd.service"
_PATH = "/var/lib/azazel/run/audit/audit.sock"


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise UnitOperationFailed("audit peer verification budget expired")
    return remaining


def _account():
    account = pwd.getpwnam("azaudit")
    operator = grp.getgrnam("azazel-operator")
    values = (account.pw_uid, account.pw_gid, operator.gr_gid)
    if any(type(value) is not int or not 0 < value < 2**32 for value in values):
        raise UnitOperationFailed("fixed audit service account unavailable")
    return values


def _directory_stamp(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _socket_stamp(info):
    return (*_directory_stamp(info), info.st_nlink, info.st_ctime_ns)


class _AuditSocketPath:
    """Retain descriptor/name identity, including the service-owned leaf."""

    def __init__(self, chain, accounts):
        self._chain = chain
        self._accounts = accounts
        self._socket = None
        self.check()

    def check(self):
        for parent, name, fd, expected in self._chain:
            held = _directory_stamp(os.fstat(fd))
            named = _directory_stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
            if held != expected or named != expected:
                raise UnitOperationFailed("audit socket directory binding changed")
        info = os.stat("audit.sock", dir_fd=self._chain[-1][2], follow_symlinks=False)
        uid, _primary_gid, operator_gid = self._accounts
        if (not stat.S_ISSOCK(info.st_mode)
                or stat.S_IMODE(info.st_mode) != REQUIRED_SOCKET_MODE
                or info.st_uid != uid or info.st_gid != operator_gid
                or info.st_nlink != 1):
            raise UnitOperationFailed("audit socket declaration differs")
        observed = _socket_stamp(info)
        if self._socket is not None and observed != self._socket:
            raise UnitOperationFailed("audit socket identity changed")
        self._socket = observed


@contextmanager
def _open_audit_path(accounts):
    if ROOT != Path("/") or os.geteuid() != 0:
        raise UnitOperationFailed("installed root audit context required")
    with ExitStack() as stack:
        root = os.open("/", _DIR)
        stack.callback(os.close, root)
        root_info = os.fstat(root)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                or root_info.st_mode & 0o022):
            raise UnitOperationFailed("audit path root refused")
        chain = [(None, "/", root, _directory_stamp(root_info))]
        parent = root
        for name in ("var", "lib", "azazel", "run", "audit"):
            fd = os.open(name, _DIR, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            uid, _primary_gid, operator_gid = accounts
            if name == "audit":
                valid = (info.st_uid == uid and info.st_gid == operator_gid
                         and stat.S_IMODE(info.st_mode) == 0o2710)
            else:
                valid = info.st_uid == 0 and not info.st_mode & 0o022
                if name in {"azazel", "run"}:
                    valid = valid and stat.S_IMODE(info.st_mode) == 0o711
            if not stat.S_ISDIR(info.st_mode) or not valid:
                raise UnitOperationFailed("audit path ownership or mode refused")
            chain.append((parent, name, fd, _directory_stamp(info)))
            parent = fd
        yield _AuditSocketPath(chain, accounts)


@dataclass(frozen=True)
class AuditPeerBinding:
    identity: AuditServiceIdentity
    revalidate: object

    def __post_init__(self):
        if type(self.identity) is not AuditServiceIdentity or not callable(self.revalidate):
            raise ValueError("retained audit identity and revalidator required")

    @contextmanager
    def proof(self, deadline):
        """Protect one exchange; the caller owns its socket and request framing."""
        _remaining(deadline)
        observed = self.revalidate()
        if type(observed) is not AuditServiceIdentity or observed != self.identity:
            raise UnitOperationFailed("retained audit service identity changed")
        _remaining(deadline)
        accounts = _account()
        namespaces = _namespaces()
        with _open_audit_path(accounts) as path:
            proof = _AuditPeerProof(self, path, accounts, namespaces, deadline)
            _remaining(deadline)
            yield proof


class _AuditPeerProof:
    def __init__(self, binding, path, accounts, namespaces, deadline):
        self._binding = binding
        self._path = path
        self._accounts = accounts
        self._namespaces = namespaces
        self._deadline = deadline

    @property
    def path(self):
        return _PATH

    def _local(self, connection):
        identity = self._binding.identity
        credentials = peer_credentials(connection)
        uid, primary_gid, _operator_gid = self._accounts
        if (type(credentials) is not tuple or len(credentials) != 3
                or any(type(value) is not int for value in credentials)
                or credentials != (identity.pid, uid, primary_gid)):
            raise UnitOperationFailed("audit socket peer identity differs")
        # This path is derived solely from a positive captured MainPID, never
        # from the peer's claimed path or response data.
        if _read_proc(f"/proc/{identity.pid}/cgroup", 4096) != f"0::{_GROUP}\n".encode():
            raise UnitOperationFailed("audit peer cgroup differs")
        self._path.check()
        if _account() != self._accounts or _namespaces() != self._namespaces:
            raise UnitOperationFailed("audit peer binding changed")

    def check(self, connection):
        _remaining(self._deadline)
        self._local(connection)
        observed = self._binding.revalidate()
        if type(observed) is not AuditServiceIdentity or observed != self._binding.identity:
            raise UnitOperationFailed("retained audit service identity changed")
        _remaining(self._deadline)
        # The synchronous manager read can take time. Do not accept a socket
        # replacement/ACL change that happened during that read.
        self._local(connection)
        _remaining(self._deadline)
