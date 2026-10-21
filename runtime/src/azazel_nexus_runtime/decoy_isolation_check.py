"""The network helper's isolation check and its record (#196 §14, G1b).

`docs/deception-redirect-prerequisites.md` §14 and
`docs/deception-exposure-grant.md` §4.4 item 2. After `az-decoy-netd` has
built the host side of the decoy network, it reads back what it built with
the two fixed commands of `decoy_network.HELPER_VERIFY` and this module
turns their output into one fixed result per check
(`azazel_nexus.decoy_isolation.CHECKS`), then writes this boot's record to
`/run/azazel-decoy-isolation/isolation.json`, where the decoy reads it before
it opens any socket.

**Compared with what was rendered.** The table is read as nftables' JSON
(`nft -j list table`) and compared, structure for structure and without the
kernel's handles, with `decoy_network.Ruleset.expected`, which the helper's
one renderer produced from the same scope as the table it loaded. The set's
elements and the interfaces the rules name are also checked on their own
(`approved_v4_matches`, `ingress_matches`), so that a record says which
part departed.

**Fixed, and read only.** The checks compare the output with values that are
constants here or in `decoy_addresses`, or that the helper rendered: nothing
is taken from an argument, a file, the environment or a socket, and nothing
here starts a process (the commands are run by `decoy_network.capture_fixed`;
this module never imports it). The record holds results and the scope's
digest only, never the output, an address, a prefix or a name.

**Written the protected way.** The directory (the helper's
`RuntimeDirectory=`, root, `0755`) is opened without following a symlink and
refused unless root's and writable by nobody else. The record is written
under a fixed temporary name (`O_CREAT | O_EXCL | O_NOFOLLOW`), synced, made
`0644` (the unit's `UMask=0027` would leave it unreadable to the decoy) and
renamed over the fixed name within that directory. The previous record is
removed before anything is built (`prepare`) and first thing at stop
(`withdraw`).
"""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import sys
import time
from typing import Callable, Optional, Protocol

from azazel_nexus.boot_id import BootIdRefused, read_current_boot_id
from azazel_nexus.decoy_isolation import (
    CHECKS,
    EVIDENCE_DIRECTORY,
    EVIDENCE_NAME,
    NO_SCOPE,
    IsolationEvidenceRefused,
    render_evidence,
)

from .decoy_addresses import (
    BRIDGE,
    BRIDGE_ADDRESS,
    DECOY_SUBNET,
    HOST_VETH,
    PREFIX_LENGTH,
)
from .decoy_netns import DECOY_VETH

__all__ = [
    "Expected",
    "Recorder",
    "evaluate",
]


class Expected(Protocol):
    """What the check reads of `decoy_network.Ruleset` (never imported here)."""

    expected: str
    approved_v4: tuple[str, ...]
    ingress: tuple[str, ...]
    scope_digest: Optional[str]


#: The named set of approved sources (`decoy_network.APPROVED_SET`).
_APPROVED_SET = "approved_v4"

#: The checks that read the table listing.
_TABLE_CHECKS = ("nft_table", "approved_v4_matches", "ingress_matches")

#: What `nft -j` prints first is the listing's own description; only its
#: JSON schema version is compared (`1` in nftables 1.1.3, Debian 13). A
#: release that changes it reads as `unreadable`, which refuses the decoy.
_JSON_SCHEMA_VERSION = 1

#: The match keys that name an interface.
_INTERFACE_KEYS = ("iifname", "oifname")

_SUBNET = ipaddress.ip_network(DECOY_SUBNET)


def _scalar_set(value: object) -> bool:
    return (type(value) is list and value != []
            and (all(type(item) is str for item in value)
                 or all(type(item) is int for item in value)))


def _normalised(value: object) -> object:
    """Anonymous sets of names or ports in a rule, in one order.

    nftables lists an anonymous set's elements in an order of its own (the
    ingress names come back reordered; container-checked, nftables 1.1.3),
    so their order says nothing. The named set's `elem` is not touched.
    """

    if type(value) is dict:
        if set(value) == {"set"} and _scalar_set(value["set"]):
            return {"set": sorted(value["set"])}
        return {key: _normalised(item) for key, item in value.items()}
    if type(value) is list:
        return [_normalised(item) for item in value]
    return value


def _table(output: bytes) -> Optional[list[tuple[str, dict]]]:
    """`nft -j list table` as `(kind, body)` objects without handles, or `None`.

    `None` is output this module does not recognise: not ASCII JSON, not one
    `nftables` list, no leading `metainfo` of the known JSON schema, or an
    object that is not exactly one kind holding a dict. Never partly read.
    Any kind is kept (a map or a counter added by hand fails `nft_table`).
    """

    try:
        document = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(document) is not dict or set(document) != {"nftables"}:
        return None
    objects = document["nftables"]
    if type(objects) is not list or not objects:
        return None
    meta = objects[0]
    if (type(meta) is not dict or set(meta) != {"metainfo"}
            or type(meta["metainfo"]) is not dict
            or meta["metainfo"].get("json_schema_version") != _JSON_SCHEMA_VERSION
            or type(meta["metainfo"].get("json_schema_version")) is not int):
        return None
    table: list[tuple[str, dict]] = []
    for item in objects[1:]:
        if type(item) is not dict or len(item) != 1:
            return None
        [(kind, body)] = item.items()
        if type(body) is not dict:
            return None
        body = {key: value for key, value in body.items() if key != "handle"}
        if kind == "rule":
            body = _normalised(body)
        table.append((kind, body))
    return table


def _elements(table: list[tuple[str, dict]]) -> Optional[tuple[str, ...]]:
    """The set `approved_v4`'s elements as `str(IPv4Network)`, or `None`.

    `None` unless the table holds that set exactly once and every element is
    a prefix or a bare address (a /32): the only forms nftables lists an
    interval set of prefixes in (container-checked, nftables 1.1.3).
    """

    sets = [body for kind, body in table
            if kind == "set" and body.get("name") == _APPROVED_SET]
    if len(sets) != 1:
        return None
    elements = sets[0].get("elem", [])
    if type(elements) is not list:
        return None
    found = []
    for element in elements:
        if type(element) is str:
            text = f"{element}/32"
        elif (type(element) is dict and set(element) == {"prefix"}
                and type(element["prefix"]) is dict
                and set(element["prefix"]) == {"addr", "len"}
                and type(element["prefix"]["addr"]) is str
                and type(element["prefix"]["len"]) is int):
            text = f"{element['prefix']['addr']}/{element['prefix']['len']}"
        else:
            return None
        try:
            found.append(str(ipaddress.IPv4Network(text, strict=True)))
        except ValueError:
            return None
    return tuple(found)


def _ingress_holds(table: list[tuple[str, dict]], ingress: tuple[str, ...]) -> bool:
    """Every interface the rules name, other than the bridge, is the ingress.

    Each `iifname`/`oifname` match that names something other than the
    bridge alone must name exactly the scope's ingress interfaces, and there
    are exactly three such matches with a scope (the accept toward the
    decoy, the reply accept, the ingress drop) and none without one.
    """

    expected = tuple(sorted(ingress))
    places = 0
    for kind, body in table:
        if kind != "rule":
            continue
        expressions = body.get("expr")
        if type(expressions) is not list:
            return False
        for expression in expressions:
            match = expression.get("match") if type(expression) is dict else None
            left = match.get("left") if type(match) is dict else None
            meta = left.get("meta") if type(left) is dict else None
            if type(meta) is not dict or meta.get("key") not in _INTERFACE_KEYS:
                continue
            right = match.get("right")
            if type(right) is str:
                names: tuple = (right,)
            elif type(right) is dict and set(right) == {"set"} and _scalar_set(right["set"]):
                names = tuple(sorted(right["set"]))
            else:
                return False
            if names == (BRIDGE,):
                continue
            if names != expected:
                return False
            places += 1
    return places == (3 if ingress else 0)


def _links(output: bytes) -> Optional[list[dict]]:
    try:
        document = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    # `ip -j address show` prints `ifname`, `flags` and `addr_info` for every
    # link (an empty list when there is none). A link missing one, or holding
    # something else there, is output this module does not recognise: the
    # whole listing is unreadable, never partly read (review of #274).
    if type(document) is not list or not all(
            type(link) is dict and type(link.get("ifname")) is str
            and type(link.get("flags")) is list
            and type(link.get("addr_info")) is list
            and all(type(address) is dict for address in link.get("addr_info"))
            for link in document):
        return None
    return document


def _kind(link: dict) -> Optional[str]:
    info = link.get("linkinfo")
    return info.get("info_kind") if type(info) is dict else None


def _addresses(link: dict, family: str) -> list[tuple[object, object, object]]:
    return [(address.get("local"), address.get("prefixlen"), address.get("scope"))
            for address in link.get("addr_info", ()) if address.get("family") == family]


def _only_link_local_v6(link: dict) -> bool:
    return all(scope == "link" for _, _, scope in _addresses(link, "inet6"))


def _in_subnet(link: dict) -> bool:
    for local, _, _ in _addresses(link, "inet"):
        try:
            if ipaddress.ip_address(local) in _SUBNET:
                return True
        except (TypeError, ValueError):
            return True  # an address that cannot be read is not shown to be outside
    return False


def evaluate(outputs: dict[str, tuple[int, bytes]], ruleset: Expected) -> dict[str, str]:
    """One fixed result per check, from the two read-back outputs.

    `outputs` maps `decoy_network.HELPER_VERIFY`'s names to `(status,
    output)`; `ruleset` is the helper's `decoy_network.Ruleset`, rendered
    from the same scope as the table it loaded. A command that failed, or
    printed something that cannot be read, makes every check that depends on
    it `unreadable`.
    """

    results: dict[str, str] = {}

    status, output = outputs.get("nft_table", (1, b""))
    table = _table(output) if status == 0 else None
    if table is None:
        results.update({name: "unreadable" for name in _TABLE_CHECKS})
    else:
        listed = [{kind: body} for kind, body in table]
        results["nft_table"] = _verdict(_canonical(listed) == ruleset.expected)
        results["approved_v4_matches"] = _verdict(_elements(table) == ruleset.approved_v4)
        results["ingress_matches"] = _verdict(_ingress_holds(table, ruleset.ingress))

    status, output = outputs.get("host_links", (1, b""))
    links = _links(output) if status == 0 else None
    names = ("bridge", "bridge_address", "bridge_ports", "host_veth",
             "decoy_veth_off_host", "subnet_exclusive")
    if links is None:
        results.update({name: "unreadable" for name in names})
    else:
        by_name: dict[str, list[dict]] = {}
        for link in links:
            by_name.setdefault(link.get("ifname"), []).append(link)
        bridges = by_name.get(BRIDGE, [])
        veths = by_name.get(HOST_VETH, [])
        bridge = bridges[0] if len(bridges) == 1 else None
        veth = veths[0] if len(veths) == 1 else None

        results["bridge"] = _verdict(
            bridge is not None and _kind(bridge) == "bridge"
            and "UP" in bridge.get("flags", ()) and "master" not in bridge)
        results["bridge_address"] = _verdict(
            bridge is not None
            and [(local, prefix) for local, prefix, _ in _addresses(bridge, "inet")]
            == [(BRIDGE_ADDRESS, int(PREFIX_LENGTH))]
            and _only_link_local_v6(bridge))
        results["bridge_ports"] = _verdict(
            sorted(str(link.get("ifname")) for link in links if link.get("master") == BRIDGE)
            == [HOST_VETH])
        results["host_veth"] = _verdict(
            veth is not None and _kind(veth) == "veth" and "UP" in veth.get("flags", ())
            and veth.get("master") == BRIDGE
            and type(veth.get("link_netnsid")) is int
            and not _addresses(veth, "inet") and _only_link_local_v6(veth))
        results["decoy_veth_off_host"] = _verdict(DECOY_VETH not in by_name)
        results["subnet_exclusive"] = _verdict(
            not any(_in_subnet(link) for link in links if link.get("ifname") != BRIDGE))
    return {name: results[name] for name in CHECKS}


def _verdict(holds: bool) -> str:
    return "pass" if holds else "fail"


def _canonical(document: object) -> str:
    """`decoy_network.canonical_json`'s form (a test keeps the two the same)."""

    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _utc_second() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


#: The fixed temporary name a record is written under before the rename.
_TEMPORARY = ".isolation.json.new"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _say(text: str) -> None:
    print(f"az-decoy-netd: {text}", file=sys.stderr, flush=True)


class Recorder:
    """`decoy_network.Recorder` for the helper. Every method reports, never raises.

    `directory`, `owner`, `boot_id` and `clock` are private test seams;
    `az-decoy-netd` constructs it with none of them.
    """

    def __init__(self, *, directory: str = EVIDENCE_DIRECTORY, owner: int = 0,
                 boot_id: Callable[[], str] = read_current_boot_id,
                 clock: Callable[[], str] = _utc_second):
        self._directory, self._owner = directory, owner
        self._read_boot_id, self._clock = boot_id, clock
        self._boot_id: Optional[str] = None

    def _open_directory(self) -> int:
        fd = os.open(self._directory, _DIR_FLAGS)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._owner
                or info.st_mode & 0o022):
            os.close(fd)
            raise PermissionError("the evidence directory has unsafe ownership or mode")
        return fd

    def _remove(self) -> bool:
        """Remove the record and a leftover temporary file, never through a link."""

        try:
            directory = self._open_directory()
        except FileNotFoundError:
            return True
        except OSError:
            return False
        try:
            for name in (EVIDENCE_NAME, _TEMPORARY):
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass
            return True
        except OSError:
            return False
        finally:
            os.close(directory)

    def prepare(self) -> bool:
        """Before anything is built: no previous record, and this boot's id."""

        if not self._remove():
            return False
        try:
            self._boot_id = self._read_boot_id()
        except BootIdRefused:
            self._boot_id = None
            return False
        return True

    def record(self, outputs: dict[str, tuple[int, bytes]], ruleset: Expected) -> bool:
        """Evaluate against `ruleset`, write this boot's record.

        True only if every check passed and the record was written. The
        record carries the scope's digest (`NO_SCOPE` without one), never an
        address or a name; the journal line names fixed checks only.
        """

        try:
            results = evaluate(outputs, ruleset)
            digest = NO_SCOPE if ruleset.scope_digest is None else ruleset.scope_digest
        except Exception:  # noqa: BLE001 - an output this cannot evaluate passes nothing
            _say("isolation check: the read-back could not be evaluated")
            return False
        _say("isolation check: " + ", ".join(f"{name} {result}"
                                             for name, result in results.items()))
        if self._boot_id is None:
            return False
        try:
            payload = render_evidence(self._boot_id, self._clock(), results, digest)
        except IsolationEvidenceRefused:
            return False
        if not self._write(payload):
            _say("the isolation record could not be written")
            return False
        return all(result == "pass" for result in results.values())

    def _write(self, payload: bytes) -> bool:
        try:
            directory = self._open_directory()
        except OSError:
            return False
        try:
            try:
                os.unlink(_TEMPORARY, dir_fd=directory)
            except FileNotFoundError:
                pass
            fd = os.open(_TEMPORARY,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
            try:
                written = 0
                while written < len(payload):
                    written += os.write(fd, payload[written:])
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(_TEMPORARY, EVIDENCE_NAME, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            return True
        except OSError:
            try:
                os.unlink(_TEMPORARY, dir_fd=directory)
            except OSError:
                pass
            return False
        finally:
            os.close(directory)

    def withdraw(self) -> bool:
        """At stop, first: the record goes before the network does."""

        return self._remove()
