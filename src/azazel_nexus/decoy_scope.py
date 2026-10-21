"""The Deception Lite exposure scope: decoded, rendered and read (#196 G1a).

`docs/deception-exposure-grant.md` §4.1 to §4.3. The operator confirms which
sources may reach the decoy, and on which interfaces, in a `deception_scope`
section of the full commissioning proposal (`commissioning-proposal/v3`,
signed with it). This module holds the one decoder of that section and the
one closed file a later activation pass renders from it for the network
helper. It grants nothing, decides nothing and runs nothing; nothing in the
pass or in the helper calls it in this build.

**The section** (§4.1, §4.2), exactly three keys:

    {"approved_v4": ["10.20.0.0/24", ...],
     "bridge_prefix": "10.255.196.0/30",
     "ingress_role": "deception_bridge"}

`decode_deception_scope` refuses the whole section on any departure; there
is no partial scope. `approved_v4` holds 1 to `MAX_PREFIXES` strict IPv4
networks, each in canonical form, sorted, with no duplicate, overlap or
adjacency, each inside RFC 1918 and none touching `RESERVED_HEADROOM`.
`bridge_prefix` is confirmed, not chosen: it must equal `BRIDGE_PREFIX`.
Interfaces are named by role only: the interfaces the same proposal confirms
as `deception_bridge`, 1 to `MAX_INGRESS` of them, none holding a second
role. A re-rendering of the decoded section must equal the section given.

**The rendered file** (§4.3 H2/H3), one line, keys sorted, no spaces, ASCII,
a newline, at most `MAX_SCOPE_BYTES`:

    {"approved_v4":[...],"contract":"azazel-nexus/decoy-scope/v1","ingress":[...]}

`ingress` holds this boot's kernel names of the `deception_bridge`
interfaces, each `[A-Za-z0-9_.-]{1,15}` and not beginning with `az-decoy`.
`read_scope_file` reads it from the helper's fixed credential path only,
without following a link, root's and writable by nobody else, a regular file
within the bound, rendered back to the same bytes and re-validated with the
rules above. It returns the scope and `scope_digest` (SHA-256 of the file).

**No content in messages.** Every refusal is a fixed phrase. No prefix,
interface name or file content appears in an exception, a record or a log
line; a caller that reports a scope reports `scope_digest` and the counts.

**A leaf.** It imports the standard library only, so that the helper may
later read the file without loading the proposal, operator trust, Ed25519 or
Fabric (#276 F3, #278), and it obeys the helper's boundary rules
(`tests/unit/test_runtime_boundary.py`; `tests/unit/test_decoy_scope.py`
checks both).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from typing import Sequence

__all__ = [
    "BRIDGE_PREFIX",
    "CONTRACT",
    "DecoyScopeRefused",
    "DeceptionScope",
    "INGRESS_ROLE",
    "MAX_INGRESS",
    "MAX_PREFIXES",
    "MAX_SCOPE_BYTES",
    "PRIVATE_V4",
    "RESERVED_HEADROOM",
    "SCOPE_CREDENTIAL_PATH",
    "ScopeFile",
    "decode_deception_scope",
    "parse_scope_file",
    "read_scope_file",
    "render_deception_scope",
    "render_scope_file",
]

#: The rendered file's contract.
CONTRACT = "azazel-nexus/decoy-scope/v1"

#: The only role whose interfaces may carry traffic to the decoy.
INGRESS_ROLE = "deception_bridge"

#: The decoy network. Equal to `azazel_nexus_runtime.decoy_addresses.DECOY_SUBNET`
#: (a test keeps them equal; the library does not import the runtime).
BRIDGE_PREFIX = "10.255.196.0/30"

#: Kept free of approved sources, for a later commissioned bridge prefix.
RESERVED_HEADROOM = "10.255.196.0/24"

#: The only blocks an approved source may come from (RFC 1918).
PRIVATE_V4: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

MAX_PREFIXES = 16
MAX_INGRESS = 4
MAX_SCOPE_BYTES = 2048

#: Where the helper's unit will receive the rendered file
#: (`LoadCredential=decoy-scope:...`, G1b). The only path the reader opens.
SCOPE_CREDENTIAL_PATH = "/run/credentials/azazel-decoy-netd.service/decoy-scope"

_SECTION_KEYS = frozenset({"approved_v4", "bridge_prefix", "ingress_role"})
_FILE_KEYS = frozenset({"approved_v4", "contract", "ingress"})
_IFNAME = re.compile(r"[A-Za-z0-9_.-]{1,15}", re.ASCII)
_RESERVED_IFNAME_PREFIX = "az-decoy"

_PRIVATE = tuple(ipaddress.IPv4Network(block) for block in PRIVATE_V4)
_BRIDGE = ipaddress.IPv4Network(BRIDGE_PREFIX)
_HEADROOM = ipaddress.IPv4Network(RESERVED_HEADROOM)

#: Private test seams. Production uses exactly these: the fixed credential
#: path and root as the only trusted owner.
_PATH = SCOPE_CREDENTIAL_PATH
_OWNER = 0


class DecoyScopeRefused(ValueError):
    """The scope or its file departs from the closed form. A fixed phrase only."""


@dataclass(frozen=True)
class DeceptionScope:
    """A decoded `deception_scope` section, exactly as the decoder accepted it."""

    approved_v4: tuple[ipaddress.IPv4Network, ...]
    #: The proposal's interface keys confirmed `deception_bridge`, sorted.
    ingress_keys: tuple[str, ...]


@dataclass(frozen=True)
class ScopeFile:
    """A rendered scope file, exactly as `parse_scope_file` accepted it."""

    approved_v4: tuple[ipaddress.IPv4Network, ...]
    ingress: tuple[str, ...]
    #: `sha256:<hex>` of the file's bytes; carries no address or name.
    scope_digest: str


def _approved(value: object) -> tuple[ipaddress.IPv4Network, ...]:
    """The §4.2 rules for `approved_v4`, shared by the section and the file."""

    if type(value) is not list or not 1 <= len(value) <= MAX_PREFIXES:
        raise DecoyScopeRefused("the approved prefixes are not a list of 1 to 16")
    networks = []
    for entry in value:
        if type(entry) is not str or not entry.isascii():
            raise DecoyScopeRefused("an approved prefix is not a string")
        try:
            network = ipaddress.IPv4Network(entry, strict=True)
        except ValueError:
            raise DecoyScopeRefused("an approved prefix is not a strict IPv4 network") from None
        if str(network) != entry:
            raise DecoyScopeRefused("an approved prefix is not in canonical form")
        if not any(network.subnet_of(block) for block in _PRIVATE):
            raise DecoyScopeRefused("an approved prefix is outside RFC 1918")
        if network.overlaps(_HEADROOM) or network.overlaps(_BRIDGE):
            raise DecoyScopeRefused("an approved prefix overlaps the decoy network's block")
        networks.append(network)
    for before, after in zip(networks, networks[1:]):
        # Strictly ascending with a gap: no duplicate, overlap or adjacency.
        if int(before.broadcast_address) + 1 >= int(after.network_address):
            raise DecoyScopeRefused(
                "the approved prefixes are not sorted, or duplicate, overlap or adjoin")
    return tuple(networks)


def _ingress_keys(assignments: object) -> tuple[str, ...]:
    if type(assignments) not in (list, tuple):
        raise DecoyScopeRefused("the role assignments could not be read")
    seen: set[str] = set()
    bridge = []
    for pair in assignments:
        if (type(pair) is not tuple or len(pair) != 2
                or type(pair[0]) is not str or type(pair[1]) is not str or not pair[0]):
            raise DecoyScopeRefused("the role assignments could not be read")
        key, role = pair
        if key in seen:
            raise DecoyScopeRefused("an interface holds more than one role")
        seen.add(key)
        if role == INGRESS_ROLE:
            bridge.append(key)
    if not 1 <= len(bridge) <= MAX_INGRESS:
        raise DecoyScopeRefused("the proposal confirms not 1 to 4 deception_bridge interfaces")
    return tuple(sorted(bridge))


def render_deception_scope(scope: DeceptionScope) -> dict:
    """The canonical section for `scope` (the form the operator signs)."""

    if type(scope) is not DeceptionScope:
        raise DecoyScopeRefused("not a decoded deception scope")
    return {
        "approved_v4": [str(network) for network in scope.approved_v4],
        "bridge_prefix": BRIDGE_PREFIX,
        "ingress_role": INGRESS_ROLE,
    }


def _canonical(document: object) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def decode_deception_scope(section: object, *,
                           assignments: Sequence[tuple[str, str]]) -> DeceptionScope:
    """Decode a proposal's `deception_scope` whole, or refuse it whole.

    `assignments` is the same proposal's `(interface_key, role)` for every
    commissioned assignment, resolved by the caller from the signed
    inventory and topology. Raises `DecoyScopeRefused`.
    """

    if type(section) is not dict or set(section) != _SECTION_KEYS:
        raise DecoyScopeRefused("the deception scope does not have exactly the fixed keys")
    if type(section["ingress_role"]) is not str or section["ingress_role"] != INGRESS_ROLE:
        raise DecoyScopeRefused("the deception scope names another ingress role")
    if type(section["bridge_prefix"]) is not str or section["bridge_prefix"] != BRIDGE_PREFIX:
        raise DecoyScopeRefused("the deception scope names another bridge prefix")
    scope = DeceptionScope(_approved(section["approved_v4"]), _ingress_keys(assignments))
    try:
        given = _canonical(section)
    except (TypeError, ValueError):
        raise DecoyScopeRefused("the deception scope is not in its canonical form") from None
    if _canonical(render_deception_scope(scope)) != given:
        raise DecoyScopeRefused("the deception scope is not in its canonical form")
    return scope


def _ingress_names(value: object) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= MAX_INGRESS:
        raise DecoyScopeRefused("the ingress interfaces are not a list of 1 to 4")
    for name in value:
        if (type(name) is not str or not _IFNAME.fullmatch(name) or name in (".", "..")
                or name.startswith(_RESERVED_IFNAME_PREFIX)):
            raise DecoyScopeRefused("an ingress interface name is not allowed")
    for before, after in zip(value, value[1:]):
        if not before < after:
            raise DecoyScopeRefused("the ingress interfaces are not sorted and distinct")
    return tuple(value)


def _render_file(approved: Sequence[ipaddress.IPv4Network], ingress: Sequence[str]) -> bytes:
    document = {
        "approved_v4": [str(network) for network in approved],
        "contract": CONTRACT,
        "ingress": list(ingress),
    }
    return _canonical(document) + b"\n"


def render_scope_file(scope: DeceptionScope, ingress: Sequence[str]) -> bytes:
    """The closed file for `scope`, with this boot's names of its ingress interfaces.

    `ingress` is the caller's resolution of `scope.ingress_keys` to kernel
    names, one per key, sorted. Refuses rather than repairing.
    """

    if type(scope) is not DeceptionScope:
        raise DecoyScopeRefused("not a decoded deception scope")
    names = _ingress_names(list(ingress) if type(ingress) is tuple else ingress)
    if len(names) != len(scope.ingress_keys):
        raise DecoyScopeRefused("the ingress names do not match the confirmed interfaces")
    approved = _approved([str(network) for network in scope.approved_v4])
    data = _render_file(approved, names)
    if len(data) > MAX_SCOPE_BYTES:
        raise DecoyScopeRefused("the scope file exceeds its bound")
    return data


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def parse_scope_file(data: bytes) -> ScopeFile:
    """Read one rendered file. Accepted only if it renders back to the same bytes."""

    if type(data) is not bytes or len(data) > MAX_SCOPE_BYTES:
        raise DecoyScopeRefused("the scope file is larger than its bound")
    try:
        document = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise DecoyScopeRefused("the scope file is not ASCII JSON") from None
    if type(document) is not dict or set(document) != _FILE_KEYS:
        raise DecoyScopeRefused("the scope file does not have exactly the fixed keys")
    if type(document["contract"]) is not str or document["contract"] != CONTRACT:
        raise DecoyScopeRefused("the scope file names another contract")
    approved = _approved(document["approved_v4"])
    ingress = _ingress_names(document["ingress"])
    if _render_file(approved, ingress) != data:
        raise DecoyScopeRefused("the scope file is not in its canonical form")
    return ScopeFile(approved, ingress, _digest(data))


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _protected(info: os.stat_result) -> bool:
    return info.st_uid == _OWNER and not info.st_mode & 0o022


def read_scope_file() -> ScopeFile:
    """The scope at the fixed credential path, or `DecoyScopeRefused`.

    An absent file refuses: the helper has no scope without one. Neither the
    directory nor the file may be a link; both must be root's and writable by
    nobody else; the file a regular one within `MAX_SCOPE_BYTES`.
    """

    directory_path, _, name = _PATH.rpartition("/")
    try:
        directory = os.open(directory_path, _DIR_FLAGS)
    except OSError:
        raise DecoyScopeRefused("the scope's directory could not be opened") from None
    try:
        if not _protected(os.fstat(directory)):
            raise DecoyScopeRefused("the scope's directory has unsafe ownership or mode")
        try:
            fd = os.open(name, _FILE_FLAGS, dir_fd=directory)
        except OSError:
            raise DecoyScopeRefused("the scope file could not be opened") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not _protected(info):
                raise DecoyScopeRefused("the scope file has unsafe ownership or mode")
            if info.st_size > MAX_SCOPE_BYTES:
                raise DecoyScopeRefused("the scope file is larger than its bound")
            data = b""
            while len(data) <= MAX_SCOPE_BYTES:
                chunk = os.read(fd, MAX_SCOPE_BYTES + 1 - len(data))
                if not chunk:
                    break
                data += chunk
        except OSError:
            raise DecoyScopeRefused("the scope file could not be read") from None
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    return parse_scope_file(data)
