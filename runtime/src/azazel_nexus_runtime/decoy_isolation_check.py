"""The network helper's isolation check and its record (#196 §14).

`docs/deception-redirect-prerequisites.md` §14. After `az-decoy-netd` has
built the host side of the decoy network, it reads back what it built with
the two fixed commands of `decoy_network.HELPER_VERIFY` and this module
turns their output into one fixed result per check
(`azazel_nexus.decoy_isolation.CHECKS`), then writes this boot's record to
`/run/azazel-decoy-isolation/isolation.json`, where the decoy reads it before
it opens any socket.

**Fixed, and read only.** The checks compare the output with values that are
constants here or in `decoy_addresses` / `decoy_network`: nothing is taken
from an argument, a file, the environment or a socket, and nothing here
starts a process (the commands are run by `decoy_network.capture_fixed`;
this module never imports it). The record holds results only, never the
output, an address or a name from the output.

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
from typing import Callable, Optional

from azazel_nexus.decoy_isolation import (
    CHECKS,
    EVIDENCE_DIRECTORY,
    EVIDENCE_NAME,
    IsolationEvidenceRefused,
    render_evidence,
)
from azazel_nexus.edge_package import EdgePackageRefused, read_current_boot_id

from .decoy_addresses import (
    BRIDGE,
    BRIDGE_ADDRESS,
    DECOY_ADDRESS,
    DECOY_PORTS,
    DECOY_SUBNET,
    HOST_VETH,
    NFT_TABLE,
    PREFIX_LENGTH,
)
from .decoy_netns import DECOY_VETH

__all__ = [
    "EXPECTED_NFT_LISTING",
    "Recorder",
    "evaluate",
]

_PORTS = ", ".join(str(port) for port in DECOY_PORTS)

#: `nft list table inet azazel_decoy` for the table the helper loads, line by
#: line with the indentation and blank lines removed (container-checked with
#: nftables 1.1.3, Debian 13; §14). Another rendering of the same rules by
#: another nftables release reads as `fail`, which refuses the decoy: a
#: listing this module does not recognise is not one it may vouch for.
EXPECTED_NFT_LISTING: tuple[str, ...] = (
    f"table inet {NFT_TABLE} {{",
    "set approved_v4 {",
    "type ipv4_addr",
    "flags interval",
    "}",
    "chain forward {",
    "type filter hook forward priority filter; policy accept;",
    f'oifname "{BRIDGE}" ip saddr @approved_v4 ip daddr {DECOY_ADDRESS} '
    f"tcp dport {{ {_PORTS} }} accept",
    f'oifname "{BRIDGE}" drop',
    f'iifname "{BRIDGE}" ip saddr {DECOY_ADDRESS} ip daddr @approved_v4 '
    f"tcp sport {{ {_PORTS} }} ct state established accept",
    f'iifname "{BRIDGE}" drop',
    "}",
    "chain input {",
    "type filter hook input priority filter; policy accept;",
    f'iifname "{BRIDGE}" drop',
    "}",
    "chain output {",
    "type filter hook output priority filter; policy accept;",
    f'oifname "{BRIDGE}" drop',
    "}",
    "}",
)

_SUBNET = ipaddress.ip_network(DECOY_SUBNET)


def _listing(output: bytes) -> Optional[list[str]]:
    try:
        text = output.decode("ascii")
    except UnicodeDecodeError:
        return None
    return [line.strip() for line in text.splitlines() if line.strip()]


def _set_is_empty(lines: list[str]) -> bool:
    """Whether the set `approved_v4` is listed, and with no element."""

    try:
        start = lines.index("set approved_v4 {")
        end = lines.index("}", start)
    except ValueError:
        return False
    return not any(line.startswith("elements") for line in lines[start + 1:end])


def _links(output: bytes) -> Optional[list[dict]]:
    try:
        document = json.loads(output.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    if type(document) is not list or not all(
            type(link) is dict and type(link.get("ifname")) is str
            and type(link.get("flags", [])) is list
            and type(link.get("addr_info", [])) is list
            and all(type(address) is dict for address in link.get("addr_info", []))
            for link in document):
        return None
    return document


def _kind(link: dict) -> Optional[str]:
    info = link.get("linkinfo")
    return info.get("info_kind") if type(info) is dict else None


def _addresses(link: dict, family: str) -> list[tuple[object, object, object]]:
    return [(address.get("local"), address.get("prefixlen"), address.get("scope"))
            for address in link["addr_info"] if address.get("family") == family]


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


def evaluate(outputs: dict[str, tuple[int, bytes]]) -> dict[str, str]:
    """One fixed result per check, from the two read-back outputs.

    `outputs` maps `decoy_network.HELPER_VERIFY`'s names to `(status,
    output)`. A command that failed, or printed something that cannot be
    read, makes every check that depends on it `unreadable`.
    """

    results: dict[str, str] = {}

    status, output = outputs.get("nft_table", (1, b""))
    lines = _listing(output) if status == 0 else None
    if lines is None:
        results["nft_table"] = results["approved_v4_empty"] = "unreadable"
    else:
        results["nft_table"] = "pass" if tuple(lines) == EXPECTED_NFT_LISTING else "fail"
        results["approved_v4_empty"] = "pass" if _set_is_empty(lines) else "fail"

    status, output = outputs.get("host_links", (1, b""))
    links = _links(output) if status == 0 else None
    names = ("bridge", "bridge_address", "bridge_ports", "host_veth",
             "decoy_veth_off_host", "subnet_exclusive")
    if links is None:
        results.update({name: "unreadable" for name in names})
    else:
        by_name: dict[str, list[dict]] = {}
        for link in links:
            by_name.setdefault(link["ifname"], []).append(link)
        bridges = by_name.get(BRIDGE, [])
        veths = by_name.get(HOST_VETH, [])
        bridge = bridges[0] if len(bridges) == 1 else None
        veth = veths[0] if len(veths) == 1 else None

        results["bridge"] = _verdict(
            bridge is not None and _kind(bridge) == "bridge"
            and "UP" in bridge["flags"] and "master" not in bridge)
        results["bridge_address"] = _verdict(
            bridge is not None
            and [(local, prefix) for local, prefix, _ in _addresses(bridge, "inet")]
            == [(BRIDGE_ADDRESS, int(PREFIX_LENGTH))]
            and _only_link_local_v6(bridge))
        results["bridge_ports"] = _verdict(
            sorted(link["ifname"] for link in links if link.get("master") == BRIDGE)
            == [HOST_VETH])
        results["host_veth"] = _verdict(
            veth is not None and _kind(veth) == "veth" and "UP" in veth["flags"]
            and veth.get("master") == BRIDGE
            and type(veth.get("link_netnsid")) is int
            and not _addresses(veth, "inet") and _only_link_local_v6(veth))
        results["decoy_veth_off_host"] = _verdict(DECOY_VETH not in by_name)
        results["subnet_exclusive"] = _verdict(
            not any(_in_subnet(link) for link in links if link["ifname"] != BRIDGE))
    return {name: results[name] for name in CHECKS}


def _verdict(holds: bool) -> str:
    return "pass" if holds else "fail"


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
        except EdgePackageRefused:
            self._boot_id = None
            return False
        return True

    def record(self, outputs: dict[str, tuple[int, bytes]]) -> bool:
        """Evaluate, write this boot's record; True only if all passed and it was written."""

        results = evaluate(outputs)
        _say("isolation check: " + ", ".join(f"{name} {result}"
                                             for name, result in results.items()))
        if self._boot_id is None:
            return False
        try:
            payload = render_evidence(self._boot_id, self._clock(), results)
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
