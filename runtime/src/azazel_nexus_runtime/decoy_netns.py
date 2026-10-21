"""Whether this process is inside the decoy network namespace (#196 decoy body).

`az-decoyd` listens on the IPv4 wildcard of the network namespace it runs in
(`decoy_listener.open_namespace_listener`). That is the decoy namespace's own
interfaces when systemd placed it there (`NetworkNamespacePath=` in
`azazel-decoyd.service`) and **every host interface** when it did not. So the
daemon refuses to listen unless it can show where it is:

1. its own network namespace (`/proc/self/ns/net`) is **the same nsfs inode**
   as the one bound at `DECOY_NAMESPACE_PATH`, which only the root-owned
   namespace unit can create (`/run/netns` is root's); and
2. it is **not** the namespace of PID 1, when PID 1's is readable. Under the
   unit's `PrivateUsers=yes` and its own account it usually is not
   (`/proc/1/ns/net` needs ptrace access); then the first check stands alone.

A missing or unreadable namespace file, a different inode, or PID 1's
namespace refuses (`NotInDecoyNamespace`). Nothing here is a parameter: the
paths are constants, there is no argument, no environment variable and no
flag that skips the check. The tests move the paths through the private
module attributes below, in-process, as `decoy_listener._SOCKET` is moved.

Reads two or three `stat` results and nothing else. Opens no socket.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = [
    "DECOY_NAMESPACE_PATH",
    "DecoyNamespace",
    "NotInDecoyNamespace",
    "confirm_decoy_namespace",
]

#: Where the namespace unit binds the decoy namespace. Equal to
#: `hardening.DECOY_NAMESPACE_PATH` (a test keeps them equal); not imported
#: from there so that the decoy process does not load the unit renderer.
DECOY_NAMESPACE_PATH = "/run/netns/azazel-decoy"

#: Private test seams. Production uses exactly these.
_EXPECTED = DECOY_NAMESPACE_PATH
_OWN = "/proc/self/ns/net"
_INIT = "/proc/1/ns/net"


class NotInDecoyNamespace(Exception):
    """The process cannot show that it runs in the decoy namespace."""


def _identity(path: str) -> tuple[int, int]:
    status = os.stat(path)
    return status.st_dev, status.st_ino


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
    return DecoyNamespace(*own)
