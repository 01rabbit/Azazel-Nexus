"""Whether this process is inside the decoy network namespace (#196 decoy body).

`az-decoyd` listens on the IPv4 wildcard of the network namespace it runs in
(`decoy_listener.open_namespace_listener`). That is the decoy namespace's own
interfaces when systemd placed it there (`NetworkNamespacePath=` in
`azazel-decoyd.service`) and **every host interface** when it did not. So the
daemon refuses to listen unless it can show where it is:

1. its own network namespace (`/proc/self/ns/net`) is **the same nsfs inode**
   as the one bound at `DECOY_NAMESPACE_PATH`, which only the root-owned
   namespace unit can create (`/run/netns` is root's);
2. it is **not** the namespace of PID 1, when PID 1's is readable. Under the
   unit's `PrivateUsers=yes` and its own account it usually is not
   (`/proc/1/ns/net` needs ptrace access); and
3. independently of both, the interfaces **this process's own** namespace
   holds (`/proc/self/net/dev`, which the kernel answers for the reader's
   network namespace) are `lo` and at most the decoy's end of the veth pair,
   `DECOY_VETH`, and nothing else. A host namespace has a physical or bridge
   interface; a fresh decoy namespace has `lo` alone until the helper moves
   the veth end in. This is what still refuses when the file at
   `DECOY_NAMESPACE_PATH` itself names the host's namespace and PID 1's
   cannot be read (review of #272). `/sys/class/net` is **not** used: it
   shows the namespace sysfs was mounted in, not the reader's.

A missing or unreadable namespace or interface file, a different inode,
PID 1's namespace, or any other interface refuses (`NotInDecoyNamespace`).
A kernel that creates its fallback tunnel devices (`sit0`, `tunl0`, ...) in
every new namespace is refused too; such a host sets
`net.core.fb_tunnels_only_for_init_net`. That is a refusal to start, never a
listener in the wrong place.

Nothing here is a parameter: the paths are constants, there is no argument,
no environment variable and no flag that skips the check. The tests move the
paths through the private module attributes below, in-process, as
`decoy_listener._SOCKET` is moved.

Reads two or three `stat` results and one `/proc` file. Opens no socket.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "DECOY_NAMESPACE_PATH",
    "DECOY_VETH",
    "DecoyNamespace",
    "NotInDecoyNamespace",
    "confirm_decoy_namespace",
]

#: Where the namespace unit binds the decoy namespace. Equal to
#: `hardening.DECOY_NAMESPACE_PATH` (a test keeps them equal); not imported
#: from there so that the decoy process does not load the unit renderer.
DECOY_NAMESPACE_PATH = "/run/netns/azazel-decoy"

#: The decoy's end of the veth pair, inside the namespace. Fixed here; the
#: namespace unit (`az-decoy-nsd`, `decoy_network`) imports it when it creates
#: the pair; at most 15 bytes (`IFNAMSIZ`), a test checks both.
DECOY_VETH = "az-decoy-ns0"

#: The only interfaces the decoy namespace may hold.
_ALLOWED_INTERFACES = frozenset({"lo", DECOY_VETH})

#: Private test seams. Production uses exactly these.
_EXPECTED = DECOY_NAMESPACE_PATH
_OWN = "/proc/self/ns/net"
_INIT = "/proc/1/ns/net"
_NET_DEV = "/proc/self/net/dev"
#: More than this many bytes of `_NET_DEV` is not a decoy namespace.
_NET_DEV_LIMIT = 64 * 1024


class NotInDecoyNamespace(Exception):
    """The process cannot show that it runs in the decoy namespace."""


def _identity(path: str) -> tuple[int, int]:
    status = os.stat(path)
    return status.st_dev, status.st_ino


def _interfaces() -> frozenset:
    """The interface names in this process's own network namespace."""

    with open(_NET_DEV, "rb") as handle:
        raw = handle.read(_NET_DEV_LIMIT + 1)
    if len(raw) > _NET_DEV_LIMIT:
        raise ValueError("too many interfaces")
    names = set()
    for line in raw.decode("ascii").splitlines()[2:]:
        name, separator, _ = line.partition(":")
        if not separator or not name.strip():
            raise ValueError("unreadable interface line")
        names.add(name.strip())
    return frozenset(names)


@dataclass(frozen=True)
class DecoyNamespace:
    """The namespace identity `confirm_decoy_namespace` found.

    Not a permission by itself: `still_current` repeats the whole check, and
    the listener calls it before every bind.
    """

    device: int
    inode: int

    def still_current(self) -> bool:
        try:
            return confirm_decoy_namespace() == self
        except NotInDecoyNamespace:
            return False


def confirm_decoy_namespace() -> DecoyNamespace:
    """This process's namespace, if it is the decoy's; refused otherwise."""

    try:
        own = _identity(_OWN)
    except OSError:
        raise NotInDecoyNamespace(
            "this process's network namespace cannot be read") from None
    try:
        expected = _identity(_EXPECTED)
    except OSError:
        raise NotInDecoyNamespace(
            f"the decoy namespace {DECOY_NAMESPACE_PATH} does not exist or cannot "
            "be read") from None
    if own != expected:
        raise NotInDecoyNamespace(
            f"this process is not in the decoy namespace {DECOY_NAMESPACE_PATH}")
    try:
        init = _identity(_INIT)
    except OSError:
        init = None
    if init == own:
        raise NotInDecoyNamespace(
            "this process is in the host's network namespace (PID 1's)")
    try:
        interfaces = _interfaces()
    except (OSError, ValueError):
        raise NotInDecoyNamespace(
            "this process's network interfaces cannot be read") from None
    if "lo" not in interfaces or not interfaces <= _ALLOWED_INTERFACES:
        # Counted, never named: the host's interface names stay out of the log.
        raise NotInDecoyNamespace(
            f"this namespace holds {len(interfaces - _ALLOWED_INTERFACES)} "
            "interface(s) besides lo and the decoy veth; a decoy namespace "
            "holds nothing else")
    return DecoyNamespace(*own)
