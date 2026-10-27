"""Who is calling, derived by the server from the operating system (#37).

The rule this module exists to make structural:

    The principal is derived from `SO_PEERCRED` and from the socket's own
    ownership. A caller's request never contributes to it.

A request that could name its own role would be making an assertion, and an
authorization that rests on an assertion is not an authorization. So there is
no field here a caller can reach: `Principal` is built from the credentials
the kernel attaches to the connection, checked against a policy read at
startup.

Two separate checks, and both are the server's:

*The socket must be what it was declared to be.* If its owner, group or mode
differ from the declaration, the server refuses to serve at all rather than
serving on a socket whose reachability it has not established. A socket left
world-writable by a packaging mistake is a socket where peer credentials
answer "who connected" correctly and "who may connect" not at all.

*The credentials must map to a class the verb admits.* Membership is decided
against the policy, not against anything in the request.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

__all__ = [
    "Principal",
    "PrincipalClass",
    "PrincipalPolicy",
    "SocketMisconfigured",
    "peer_credentials",
]


class SocketMisconfigured(Exception):
    """The socket is not what the packaging declared. Nothing is served."""


class PrincipalClass(str, Enum):
    """What a caller is, as the server determines it.

    Deliberately coarse. A finer vocabulary would tempt a verb to accept a
    role name and check it against this, which is the assertion this module
    exists to refuse.
    """

    #: uid 0.
    ROOT = "root"
    #: A member of the operator group named by the policy.
    OPERATOR = "operator"
    #: One of the node's own service accounts.
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    """The caller, as the kernel reported them.

    `classes` is derived, never supplied. There is no constructor path that
    takes a class from anywhere but `PrincipalPolicy.classify`.
    """

    uid: int
    gid: int
    pid: int
    classes: frozenset[PrincipalClass]

    def __post_init__(self) -> None:
        if self.uid < 0 or self.gid < 0 or self.pid <= 0:
            raise SocketMisconfigured(
                f"the kernel reported uid={self.uid} gid={self.gid} "
                f"pid={self.pid}, which is not a credential this server will "
                "act on"
            )

    def admits(self, allowed: Iterable[PrincipalClass]) -> bool:
        return bool(self.classes & frozenset(allowed))

    def as_audit_fields(self) -> dict:
        """Bounded fields only.

        Three integers and a sorted list of enum values. Nothing here is
        attacker-supplied text, because nothing about a principal comes from
        the caller.
        """

        return {
            "uid": self.uid,
            "gid": self.gid,
            "pid": self.pid,
            "classes": sorted(c.value for c in self.classes),
        }


#: The service accounts `IMPLEMENTATION_SPEC.md` §3 names.
#:
#: Listed rather than discovered so that an account created by something other
#: than the package does not become a service principal by existing.
SERVICE_ACCOUNTS = (
    "azobs",
    "azevidence",
    "azeval",
    "azarbiter",
    "azenforce",
    "azmio",
    "azknowledge",
    "azdecoy",
    "azmodule",
    "azvoice",
    "azui",
    "azaudit",
    "azwatch",
    "azcommission",
    "azactivate",
)

#: Every account a Nexus daemon runs as: the specification's service accounts
#: plus the ones the installer creates (`hardening.SYSTEM_ACCOUNTS`; a test
#: keeps the two in step). None of them is ever an operator, whatever groups
#: its process carries. A unit's `SupplementaryGroups=azazel-operator` lets
#: entryd reach provider sockets; it must not make entryd an operator at
#: commissiond, auditd, watchdog or the fetcher, which do not list it as a
#: service. Before `SO_PEERGROUPS` was read on Linux this could not happen,
#: because no supplementary group was ever seen.
DAEMON_ACCOUNTS = tuple(dict.fromkeys((
    *SERVICE_ACCOUNTS,
    "azprobe",
    "azintake",
    "azexplain",
    "azedge",
    "azfetch",
    "azmioentry",
    "azmioref",
    "azremote",
)))

#: Who may reach a daemon socket at all.
DEFAULT_OPERATOR_GROUP = "azazel-operator"

#: What a daemon socket's mode must be.
#:
#: Owner and group read/write, nothing for other. A socket a caller cannot
#: reach is the first authorization boundary (`IMPLEMENTATION_SPEC.md` §4),
#: and peer credentials are the second. Neither substitutes for the other.
REQUIRED_SOCKET_MODE = 0o660


@dataclass(frozen=True)
class PrincipalPolicy:
    """The mapping from credentials to classes, read at startup.

    `operator_gid` and `service_uids` are resolved once, from the host's own
    account database, before the socket is served. Resolving them per request
    would make the answer depend on when the request arrived.
    """

    operator_gid: Optional[int]
    service_uids: frozenset[int]
    #: Daemon accounts that are never classified as operators. Not services
    #: here unless also in `service_uids`.
    daemon_uids: frozenset[int] = frozenset()

    @classmethod
    def resolve(
        cls,
        *,
        operator_group: str = DEFAULT_OPERATOR_GROUP,
        service_accounts: Iterable[str] = SERVICE_ACCOUNTS,
    ) -> "PrincipalPolicy":
        try:
            operator_gid = grp.getgrnam(operator_group).gr_gid
        except KeyError:
            # Absent group means no operator principal exists on this host,
            # not that everyone is one.
            operator_gid = None
        def uids(accounts: Iterable[str]) -> frozenset[int]:
            found = set()
            for account in accounts:
                try:
                    found.add(pwd.getpwnam(account).pw_uid)
                except KeyError:
                    continue
            return frozenset(found)

        return cls(
            operator_gid=operator_gid,
            service_uids=uids(service_accounts),
            daemon_uids=uids(DAEMON_ACCOUNTS),
        )

    def classify(
        self,
        uid: int,
        gid: int,
        pid: int,
        supplementary_groups: Iterable[int] = (),
    ) -> Principal:
        groups = tuple(supplementary_groups)
        if any(type(group) is not int or group < 0 for group in groups):
            raise SocketMisconfigured("kernel supplementary groups are malformed")
        classes = set()
        if uid == 0:
            classes.add(PrincipalClass.ROOT)
        if (
            self.operator_gid is not None
            and uid not in self.service_uids
            and uid not in self.daemon_uids
            # Root's supplementary groups never make it an operator: a root unit
            # carrying SupplementaryGroups=azazel-operator (activated) stays ROOT
            # only, exactly as before supplementary groups were read.
            and (gid == self.operator_gid or (uid != 0 and self.operator_gid in groups))
        ):
            classes.add(PrincipalClass.OPERATOR)
        if uid in self.service_uids:
            classes.add(PrincipalClass.SERVICE)
        return Principal(uid=uid, gid=gid, pid=pid, classes=frozenset(classes))


def peer_credentials(connection) -> tuple[int, int, int]:
    """`(pid, uid, gid)` from `SO_PEERCRED`, as the kernel attached them.

    Not from the request, not from the environment, and not from a header. The
    kernel fills this in at connect time and a caller cannot alter it.
    """

    import socket as socket_module
    import struct

    raw = connection.getsockopt(
        socket_module.SOL_SOCKET, socket_module.SO_PEERCRED, struct.calcsize("3i")
    )
    pid, uid, gid = struct.unpack("3i", raw)
    return pid, uid, gid


#: Linux ``SO_PEERGROUPS`` (4.13+) from ``asm-generic/socket.h``. CPython does
#: not export the constant (3.12/3.13 have no ``socket.SO_PEERGROUPS``), so
#: without this value no Linux peer ever had supplementary groups and every
#: supplementary-group operator was refused. Only architectures that use the
#: generic value are listed; any other machine keeps the fail-closed ``()``.
_LINUX_SO_PEERGROUPS = 59
_GENERIC_SOCKET_MACHINES = frozenset({
    "x86_64", "aarch64", "arm64", "i386", "i486", "i586", "i686",
    "armv6l", "armv7l", "armv8l", "riscv64", "ppc64le", "ppc64", "s390x",
})
#: CPython refuses a ``getsockopt`` buffer larger than 1024 bytes ("getsockopt
#: buflen out of range"), so 256 groups is the most it can read. A peer with
#: more groups gets ERANGE from the kernel and is classified without them.
_PEERGROUPS_BUFFER = 1024


def _peergroups_option(socket_module) -> int | None:
    option = getattr(socket_module, "SO_PEERGROUPS", None)
    if option is not None:
        return option
    if sys.platform == "linux" and os.uname().machine in _GENERIC_SOCKET_MACHINES:
        return _LINUX_SO_PEERGROUPS
    return None


def peer_supplementary_groups(connection) -> tuple[int, ...]:
    """Read the peer's kernel-reported supplementary GIDs on Linux.

    On systems without ``SO_PEERGROUPS`` no supplementary principal is
    inferred; primary-GID and root/service classification still work. Linux
    operator accounts may therefore use ordinary supplementary group
    membership without changing their primary group.
    """

    import socket as socket_module
    import struct

    option = _peergroups_option(socket_module)
    if option is None:
        return ()
    try:
        raw = connection.getsockopt(
            socket_module.SOL_SOCKET, option, _PEERGROUPS_BUFFER
        )
    except OSError as exc:
        # Fail toward fewer grants, but say so: an operator with more than 256
        # groups (ERANGE) otherwise sees only a generic principal_denied.
        # Fixed text and the errno name only; nothing the peer controls.
        import errno
        import sys
        name = errno.errorcode.get(exc.errno, "unknown")
        print(f"peer supplementary groups unavailable: {name}", file=sys.stderr)
        return ()
    if len(raw) % 4:
        raise SocketMisconfigured("kernel supplementary groups are malformed")
    return tuple(group for (group,) in struct.iter_unpack("=I", raw))


def verify_socket(
    path: Path,
    *,
    expected_mode: int = REQUIRED_SOCKET_MODE,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> None:
    """Refuse to serve on a socket that is not what packaging declared.

    Checked before the first accept, not per request: a socket whose mode is
    wrong is wrong for every caller, and discovering it on the first
    connection means the first connection already happened.
    """

    try:
        info = path.stat()
    except OSError as exc:
        raise SocketMisconfigured(f"{path} could not be examined: {exc}") from exc
    if not stat.S_ISSOCK(info.st_mode):
        raise SocketMisconfigured(f"{path} is not a socket")
    mode = stat.S_IMODE(info.st_mode)
    if mode != expected_mode:
        raise SocketMisconfigured(
            f"{path} has mode {mode:04o} and the packaging declares "
            f"{expected_mode:04o}. Peer credentials answer who connected; the "
            "mode is what decides who can"
        )
    owner = expected_uid if expected_uid is not None else os.getuid()
    if info.st_uid != owner:
        raise SocketMisconfigured(
            f"{path} is owned by uid {info.st_uid} and this daemon runs as "
            f"{owner}; a socket it does not own is a socket it cannot vouch for"
        )
    if expected_gid is not None and info.st_gid != expected_gid:
        raise SocketMisconfigured(
            f"{path} has an unexpected group; the socket ACL does not match "
            "the reviewed operator group"
        )
