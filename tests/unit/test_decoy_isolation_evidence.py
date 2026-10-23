"""#196 §14 and G1b: the decoy network's isolation evidence, written and read.

`docs/deception-redirect-prerequisites.md` §14 and
`docs/deception-exposure-grant.md` §4.4 item 2. The network helper reads
back the host side it built (`nft -j list table inet azazel_decoy`, `ip -j
-d address show`), compares the table's structure with the ruleset it
rendered from its scope, turns that into one fixed result per check, and
writes this boot's record to its runtime directory; the decoy refuses to
listen unless that record is from this boot, from root, in the exact shape
(contract v2), and every check passed. These tests pin, with fake command
output (nothing here runs `ip` or `nft` or opens a socket):

* the record's closed, canonical shape, as a golden, with the scope's
  digest and no address, and the refusal of every departure from it
  (keys, values, whitespace, order, size, a version 1 record);
* the reader's protection: no symlink for the directory or the file, root's
  only, nobody else may write, a regular file within the limit;
* this boot only, not in the future, every check passed;
* each check against the output of a real container run (the goldens, with
  and without a scope), and each mutation of that output failing exactly its
  checks: an element added by hand, an `iifname` match missing, the
  masquerade missing, and more;
* the writer: the previous record removed first, the record root's `0644`
  under the unit's umask, written by rename, never through a link;
* the decoy refusing before any socket without a passing record;
* the activation library still withholding the tier with a passing record
  in place; the producer frame's readings;
* the unit declarations and the boundary: the helper's runtime directory
  alone, only the helper loads the recorder.

The container runs are mechanism checks, not VM or hardware evidence.
"""

from __future__ import annotations

import ast
import copy
import json
import os
import socket
from pathlib import Path

import pytest

from azazel_nexus import decoy_isolation
from azazel_nexus.decoy_isolation import (
    CHECKS,
    CONTRACT,
    EVIDENCE_DIRECTORY,
    EVIDENCE_NAME,
    NO_SCOPE,
    IsolationEvidenceRefused,
    IsolationState,
    admission_refusal,
    installed_isolation_reading,
    load_evidence,
    parse_evidence,
    render_evidence,
    require_isolation_for_decoy,
)
from azazel_nexus.decoy_scope import parse_scope_file
from azazel_nexus_runtime import decoy_isolation_check, decoy_netns, decoyd
from azazel_nexus_runtime.decoy_isolation_check import Recorder, evaluate
from azazel_nexus_runtime.decoy_network import render_ruleset

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "runtime" / "src" / "azazel_nexus_runtime"

BOOT = "0f4a6d2e-7c1b-4e5a-9d3c-2b8f1a6e4c70"
OTHER_BOOT = "9b1c3e5a-2d4f-4a6b-8c0d-1e3f5a7b9c2d"
NOW = "2026-10-22T03:00:10Z"
WHEN = "2026-10-22T03:00:00Z"
ALL_PASS = {name: "pass" for name in CHECKS}

#: The scope of the container run below: three prefixes (one a /32), two
#: ingress interfaces. Test data only; no real site's network.
SCOPE_BYTES = (b'{"approved_v4":["10.20.0.0/24","10.30.0.1/32","192.168.10.0/24"],'
               b'"contract":"azazel-nexus/decoy-scope/v1","ingress":["eth9","lan0"]}\n')
SCOPE = parse_scope_file(SCOPE_BYTES)
SCOPE_DIGEST = "sha256:1abe4737f1fe4e7ef1186d54a4b37f8f5f92ff1497d8b7888f91d3d6faee05ef"
#: The helper's table for that scope, and for no scope.
RULESET = render_ruleset(SCOPE)
EMPTY_RULESET = render_ruleset(None)

#: The record for `BOOT`, `WHEN`, every check passing, `SCOPE`: byte for byte.
GOLDEN = (
    b'{"boot_id":"0f4a6d2e-7c1b-4e5a-9d3c-2b8f1a6e4c70",'
    b'"checked_at":"2026-10-22T03:00:00Z",'
    b'"checks":{"approved_v4_matches":"pass","bridge":"pass","bridge_address":"pass",'
    b'"bridge_ports":"pass","decoy_veth_off_host":"pass","host_veth":"pass",'
    b'"ingress_matches":"pass","nft_table":"pass","subnet_exclusive":"pass"},'
    b'"contract":"azazel-nexus/decoy-isolation/v2",'
    b'"scope_digest":"sha256:1abe4737f1fe4e7ef1186d54a4b37f8f5f92ff1497d8b7888f91d3d6faee05ef"}\n'
)

#: A version 1 record (#196 §14, before G1b), as the helper of that build
#: wrote it. The new reader refuses it.
GOLDEN_V1 = (
    b'{"boot_id":"0f4a6d2e-7c1b-4e5a-9d3c-2b8f1a6e4c70",'
    b'"checked_at":"2026-10-22T03:00:00Z",'
    b'"checks":{"approved_v4_empty":"pass","bridge":"pass","bridge_address":"pass",'
    b'"bridge_ports":"pass","decoy_veth_off_host":"pass","host_veth":"pass",'
    b'"nft_table":"pass","subnet_exclusive":"pass"},'
    b'"contract":"azazel-nexus/decoy-isolation/v1"}\n'
)

#: `nft -j list table inet azazel_decoy` after `nft` loaded the helper's
#: table for `SCOPE`, as printed by nftables 1.1.3 (Debian 13) in a
#: privileged container (#196 G1b; a mechanism check, not VM or hardware
#: evidence). Note what nftables does: the anonymous sets of names come back
#: in another order than written (`"lan0", "eth9"`), the /32 is a bare
#: address, the chains come before the set, and every object has a handle.
NFT_JSON = (
    '{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", '
    '"json_schema_version": 1}}, {"table": {"family": "inet", "name": "azazel_decoy", '
    '"handle": 3}}, {"chain": {"family": "inet", "table": "azazel_decoy", "name": "forward", '
    '"handle": 1, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}}, '
    '{"chain": {"family": "inet", "table": "azazel_decoy", "name": "input", "handle": 2, '
    '"type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": '
    '"inet", "table": "azazel_decoy", "name": "output", "handle": 3, "type": "filter", "hook": '
    '"output", "prio": 0, "policy": "accept"}}, {"chain": {"family": "inet", "table": '
    '"azazel_decoy", "name": "postrouting", "handle": 4, "type": "nat", "hook": "postrouting", '
    '"prio": 100, "policy": "accept"}}, {"set": {"family": "inet", "name": "approved_v4", '
    '"table": "azazel_decoy", "type": "ipv4_addr", "handle": 5, "flags": ["interval"], '
    '"elem": [{"prefix": {"addr": "10.20.0.0", "len": 24}}, "10.30.0.1", {"prefix": {"addr": '
    '"192.168.10.0", "len": 24}}]}}, {"rule": {"family": "inet", "table": "azazel_decoy", '
    '"chain": "forward", "handle": 8, "expr": [{"match": {"op": "==", "left": {"meta": {"key": '
    '"iifname"}}, "right": {"set": ["lan0", "eth9"]}}}, {"match": {"op": "==", "left": {"meta": '
    '{"key": "oifname"}}, "right": "az-decoy0"}}, {"match": {"op": "==", "left": {"payload": '
    '{"protocol": "ip", "field": "saddr"}}, "right": "@approved_v4"}}, {"match": {"op": "==", '
    '"left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "10.255.196.2"}}, '
    '{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, '
    '"right": {"set": [2222, 2323, 8080]}}}, {"accept": null}]}}, {"rule": {"family": "inet", '
    '"table": "azazel_decoy", "chain": "forward", "handle": 9, "expr": [{"match": {"op": "==", '
    '"left": {"meta": {"key": "oifname"}}, "right": "az-decoy0"}}, {"drop": null}]}}, '
    '{"rule": {"family": "inet", "table": "azazel_decoy", "chain": "forward", "handle": 12, '
    '"expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": '
    '"az-decoy0"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": '
    '{"set": ["lan0", "eth9"]}}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", '
    '"field": "saddr"}}, "right": "10.255.196.2"}}, {"match": {"op": "==", "left": {"payload": '
    '{"protocol": "ip", "field": "daddr"}}, "right": "@approved_v4"}}, {"match": {"op": "==", '
    '"left": {"payload": {"protocol": "tcp", "field": "sport"}}, "right": {"set": [2222, 2323, '
    '8080]}}}, {"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": '
    '"established"}}, {"accept": null}]}}, {"rule": {"family": "inet", "table": "azazel_decoy", '
    '"chain": "forward", "handle": 13, "expr": [{"match": {"op": "==", "left": {"meta": {"key": '
    '"iifname"}}, "right": "az-decoy0"}}, {"drop": null}]}}, {"rule": {"family": "inet", '
    '"table": "azazel_decoy", "chain": "forward", "handle": 15, "expr": [{"match": {"op": "==", '
    '"left": {"meta": {"key": "iifname"}}, "right": {"set": ["lan0", "eth9"]}}}, {"match": '
    '{"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "az-decoy0"}}, {"drop": '
    'null}]}}, {"rule": {"family": "inet", "table": "azazel_decoy", "chain": "input", "handle": '
    '16, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": '
    '"az-decoy0"}}, {"drop": null}]}}, {"rule": {"family": "inet", "table": "azazel_decoy", '
    '"chain": "output", "handle": 17, "expr": [{"match": {"op": "==", "left": {"meta": {"key": '
    '"oifname"}}, "right": "az-decoy0"}}, {"drop": null}]}}, {"rule": {"family": "inet", '
    '"table": "azazel_decoy", "chain": "postrouting", "handle": 18, "expr": [{"match": {"op": '
    '"==", "left": {"meta": {"key": "oifname"}}, "right": "az-decoy0"}}, {"match": {"op": "==", '
    '"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@approved_v4"}}, '
    '{"masquerade": null}]}}]}\n'
)

#: The same for the table without a scope (`NFT_RULESET`), from the same run.
NFT_JSON_EMPTY = (
    '{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", '
    '"json_schema_version": 1}}, {"table": {"family": "inet", "name": "azazel_decoy", '
    '"handle": 9}}, {"chain": {"family": "inet", "table": "azazel_decoy", "name": "forward", '
    '"handle": 1, "type": "filter", "hook": "forward", "prio": 0, "policy": "accept"}}, '
    '{"chain": {"family": "inet", "table": "azazel_decoy", "name": "input", "handle": 2, '
    '"type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}, {"chain": {"family": '
    '"inet", "table": "azazel_decoy", "name": "output", "handle": 3, "type": "filter", "hook": '
    '"output", "prio": 0, "policy": "accept"}}, {"set": {"family": "inet", "name": '
    '"approved_v4", "table": "azazel_decoy", "type": "ipv4_addr", "handle": 4, "flags": '
    '["interval"]}}, {"rule": {"family": "inet", "table": "azazel_decoy", "chain": "forward", '
    '"handle": 6, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, '
    '"right": "az-decoy0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", '
    '"field": "saddr"}}, "right": "@approved_v4"}}, {"match": {"op": "==", "left": {"payload": '
    '{"protocol": "ip", "field": "daddr"}}, "right": "10.255.196.2"}}, {"match": {"op": "==", '
    '"left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set": [2222, 2323, '
    '8080]}}}, {"accept": null}]}}, {"rule": {"family": "inet", "table": "azazel_decoy", '
    '"chain": "forward", "handle": 7, "expr": [{"match": {"op": "==", "left": {"meta": {"key": '
    '"oifname"}}, "right": "az-decoy0"}}, {"drop": null}]}}, {"rule": {"family": "inet", '
    '"table": "azazel_decoy", "chain": "forward", "handle": 9, "expr": [{"match": {"op": "==", '
    '"left": {"meta": {"key": "iifname"}}, "right": "az-decoy0"}}, {"match": {"op": "==", '
    '"left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.255.196.2"}}, '
    '{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, '
    '"right": "@approved_v4"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", '
    '"field": "sport"}}, "right": {"set": [2222, 2323, 8080]}}}, {"match": {"op": "in", '
    '"left": {"ct": {"key": "state"}}, "right": "established"}}, {"accept": null}]}}, '
    '{"rule": {"family": "inet", "table": "azazel_decoy", "chain": "forward", "handle": 10, '
    '"expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": '
    '"az-decoy0"}}, {"drop": null}]}}, {"rule": {"family": "inet", "table": "azazel_decoy", '
    '"chain": "input", "handle": 11, "expr": [{"match": {"op": "==", "left": {"meta": {"key": '
    '"iifname"}}, "right": "az-decoy0"}}, {"drop": null}]}}, {"rule": {"family": "inet", '
    '"table": "azazel_decoy", "chain": "output", "handle": 12, "expr": [{"match": {"op": "==", '
    '"left": {"meta": {"key": "oifname"}}, "right": "az-decoy0"}}, {"drop": null}]}}]}\n'
)

#: `ip -j -d address show` from the §14 container run, reduced to the fields the checks
#: read plus a few they ignore; the container's own interface is given a
#: documentation address.
HOST_LINKS = [
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"],
     "operstate": "UNKNOWN",
     "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
                   {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]},
    {"ifindex": 3, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "link_netnsid": 0, "linkinfo": {"info_kind": "veth"},
     "addr_info": [{"family": "inet", "local": "192.0.2.10", "prefixlen": 24,
                    "scope": "global"}]},
    {"ifindex": 4, "ifname": "az-decoy-host0",
     "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "master": "az-decoy0",
     "operstate": "UP", "link_netnsid": 1,
     "linkinfo": {"info_kind": "veth", "info_slave_kind": "bridge",
                  "info_slave_data": {"state": "forwarding"}},
     "addr_info": [{"family": "inet6", "local": "fe80::f03e:28ff:fee9:8ad0", "prefixlen": 64,
                    "scope": "link"}]},
    {"ifindex": 5, "ifname": "az-decoy0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "operstate": "UP", "linkinfo": {"info_kind": "bridge", "info_data": {"stp_state": 0}},
     "addr_info": [{"family": "inet", "local": "10.255.196.1", "prefixlen": 30,
                    "scope": "global", "label": "az-decoy0"},
                   {"family": "inet6", "local": "fe80::f03e:28ff:fee9:8ad0", "prefixlen": 64,
                    "scope": "link"}]},
]


def _outputs(nft=NFT_JSON, links=None, nft_status=0, links_status=0):
    links = HOST_LINKS if links is None else links
    if isinstance(nft, (list, dict)):
        nft = json.dumps(nft)
    return {"nft_table": (nft_status, nft.encode() if isinstance(nft, str) else nft),
            "host_links": (links_status,
                           links if isinstance(links, bytes) else json.dumps(links).encode())}


def install_evidence(tmp_path: Path, monkeypatch, *, data: bytes | None = None,
                     boot: str = BOOT) -> Path:
    """A record at a temporary evidence directory, read as root's and this boot's.

    Shared with `test_decoy_body.py`, which needs a passing record for the
    decoy to listen at all.
    """

    directory = tmp_path / "isolation"
    directory.mkdir(mode=0o755, exist_ok=True)
    os.chmod(directory, 0o755)
    boot_file = tmp_path / "boot_id"
    boot_file.write_text(boot + "\n")
    os.chmod(boot_file, 0o444)
    record = directory / EVIDENCE_NAME
    if data is None:
        data = render_evidence(BOOT, WHEN, dict(ALL_PASS), SCOPE_DIGEST)
    record.write_bytes(data)
    os.chmod(record, 0o644)
    monkeypatch.setattr(decoy_isolation, "_DIRECTORY", str(directory))
    monkeypatch.setattr(decoy_isolation, "_OWNER", os.getuid())
    monkeypatch.setattr(decoy_isolation, "_BOOT_ID_PATH", boot_file)
    # The decoy's credential (#196 G6, D2): the digest the activation pass
    # rendered for this grant, the record's own unless a test says otherwise.
    try:
        digest = parse_evidence(data).scope_digest
    except IsolationEvidenceRefused:
        digest = NO_SCOPE
    install_scope_digest(tmp_path, monkeypatch,
                         None if digest == NO_SCOPE else digest)
    return record


def install_scope_digest(tmp_path, monkeypatch, digest, *, mode=0o400, content=None):
    """The decoy's `decoy-scope-digest` credential under a temporary path."""

    directory = tmp_path / "credentials"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / "decoy-scope-digest"
    if path.exists():
        path.unlink()
    if digest is not None or content is not None:
        path.write_bytes(content if content is not None else (digest + "\n").encode())
        os.chmod(path, mode)
    monkeypatch.setattr(decoy_isolation, "_DIGEST_PATH", str(path))
    return path


# -- the record's shape --------------------------------------------------------


def test_the_record_is_the_golden():
    assert SCOPE.scope_digest == SCOPE_DIGEST
    assert render_evidence(BOOT, WHEN, dict(ALL_PASS), SCOPE_DIGEST) == GOLDEN
    evidence = parse_evidence(GOLDEN)
    assert (evidence.boot_id, evidence.checked_at) == (BOOT, WHEN)
    assert evidence.checks == tuple((name, "pass") for name in CHECKS)
    assert evidence.scope_digest == SCOPE_DIGEST
    assert evidence.passed and evidence.not_passed == ()
    assert CONTRACT == "azazel-nexus/decoy-isolation/v2"
    assert CHECKS == ("nft_table", "approved_v4_matches", "ingress_matches", "bridge",
                      "bridge_address", "bridge_ports", "host_veth", "decoy_veth_off_host",
                      "subnet_exclusive")
    assert EVIDENCE_DIRECTORY == "/run/azazel-decoy-isolation"
    assert EVIDENCE_NAME == "isolation.json"
    assert decoy_isolation.RESULTS == ("pass", "fail", "unreadable")
    # Without a scope the digest is the fixed word.
    plain = render_evidence(BOOT, WHEN, dict(ALL_PASS), NO_SCOPE)
    assert plain == GOLDEN.replace(SCOPE_DIGEST.encode(), b"none")
    assert parse_evidence(plain).scope_digest == NO_SCOPE == "none"


def test_the_record_holds_no_address_and_nothing_but_fixed_words():
    document = json.loads(GOLDEN)
    assert set(document) == {"boot_id", "checked_at", "checks", "contract", "scope_digest"}
    text = GOLDEN.decode()
    for forbidden in ("10.255.196", "192.0.2", "fe80", "az-decoy", "eth0", "elements",
                      "10.20.", "10.30.", "192.168.", "eth9", "lan0"):
        assert forbidden not in text
    assert len(GOLDEN) < decoy_isolation.MAX_BYTES


@pytest.mark.parametrize("data", [
    GOLDEN_V1,
    # A v1 record with a digest added, and a v2 record naming v1.
    GOLDEN_V1.replace(b'"}\n', b'","scope_digest":"none"}\n'),
    GOLDEN.replace(b"decoy-isolation/v2", b"decoy-isolation/v1"),
], ids=["v1", "v1-with-digest", "v2-naming-v1"])
def test_a_version_1_record_is_refused(data, tmp_path, monkeypatch):
    """#196 G1b: the checks changed, so the contract did; the reader refuses v1."""

    with pytest.raises(IsolationEvidenceRefused):
        parse_evidence(data)
    install_evidence(tmp_path, monkeypatch, data=data)
    with pytest.raises(IsolationEvidenceRefused):
        require_isolation_for_decoy(now=NOW)
    assert installed_isolation_reading(now=NOW).state is IsolationState.REFUSED


def _mutated(change):
    document = json.loads(GOLDEN)
    change(document)
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("data", [
    b"",
    b"[]\n",
    GOLDEN[:-1],                                      # no newline
    GOLDEN + b"\n",                                   # two
    GOLDEN.replace(b",", b", ", 1),                   # whitespace
    json.dumps(json.loads(GOLDEN)).encode() + b"\n",  # another layout
    GOLDEN.replace(b'"boot_id"', b'"boot_id":"x","boot_id"', 1),  # duplicate key
    GOLDEN.replace(b"pass", b"\\u0070ass", 1),        # an escape
    b" " * (decoy_isolation.MAX_BYTES + 1),
    GOLDEN.replace(b"v2", b"v3"),
    _mutated(lambda d: d.update(extra=1)),
    _mutated(lambda d: d.pop("scope_digest")),
    _mutated(lambda d: d.update(scope_digest="")),
    _mutated(lambda d: d.update(scope_digest=None)),
    _mutated(lambda d: d.update(scope_digest="None")),
    _mutated(lambda d: d.update(scope_digest="sha256:" + "A" * 64)),
    _mutated(lambda d: d.update(scope_digest="sha256:" + "a" * 63)),
    _mutated(lambda d: d.update(scope_digest="sha1:" + "a" * 40)),
    _mutated(lambda d: d.update(scope_digest="10.20.0.0/24")),
    _mutated(lambda d: d["checks"].update(approved_v4_empty="pass")),
    _mutated(lambda d: d.pop("checked_at")),
    _mutated(lambda d: d.update(boot_id=BOOT.upper())),
    _mutated(lambda d: d.update(boot_id="")),
    _mutated(lambda d: d.update(checked_at="2026-10-22T03:00:00+00:00")),
    _mutated(lambda d: d.update(checked_at="2026-10-22T03:00:00.5Z")),
    _mutated(lambda d: d.update(checked_at="2026-13-22T03:00:00Z")),
    _mutated(lambda d: d.update(checks=[])),
    _mutated(lambda d: d["checks"].pop("bridge")),
    _mutated(lambda d: d["checks"].update(peer="pass")),
    _mutated(lambda d: d["checks"].update(bridge="passed")),
    _mutated(lambda d: d["checks"].update(bridge=True)),
    _mutated(lambda d: d["checks"].update(bridge="10.255.196.1")),
    _mutated(lambda d: d.update(contract="azazel-nexus/edge-probe/v2")),
], ids=lambda data: repr(data[:24]))
def test_anything_but_the_exact_shape_is_refused(data):
    with pytest.raises(IsolationEvidenceRefused):
        parse_evidence(data)


def test_the_writer_refuses_to_render_anything_but_the_shape():
    for checks in ({}, {**ALL_PASS, "peer": "pass"}, {**ALL_PASS, "bridge": "ok"}):
        with pytest.raises(IsolationEvidenceRefused):
            render_evidence(BOOT, WHEN, checks, SCOPE_DIGEST)
    with pytest.raises(IsolationEvidenceRefused):
        render_evidence("not-a-boot", WHEN, dict(ALL_PASS), SCOPE_DIGEST)
    with pytest.raises(IsolationEvidenceRefused):
        render_evidence(BOOT, "yesterday", dict(ALL_PASS), SCOPE_DIGEST)
    for digest in (None, "", "eth9", "10.20.0.0/24", SCOPE_DIGEST + "0"):
        with pytest.raises(IsolationEvidenceRefused, match="digest"):
            render_evidence(BOOT, WHEN, dict(ALL_PASS), digest)


# -- admission ---------------------------------------------------------------


def test_only_this_boots_passing_record_admits():
    evidence = parse_evidence(GOLDEN)
    assert admission_refusal(evidence, boot_id=BOOT, now=NOW) is None
    assert "not from this boot" in admission_refusal(evidence, boot_id=OTHER_BOOT, now=NOW)
    assert "not from this boot" in admission_refusal(evidence, boot_id="", now=NOW)
    # Within the skew is fine, beyond it is refused.
    assert admission_refusal(evidence, boot_id=BOOT, now="2026-10-22T02:59:56Z") is None
    assert "future" in admission_refusal(evidence, boot_id=BOOT, now="2026-10-22T02:59:50Z")
    assert "time" in admission_refusal(evidence, boot_id=BOOT, now="now")


@pytest.mark.parametrize("name", CHECKS)
@pytest.mark.parametrize("result", ["fail", "unreadable"])
def test_any_check_not_passing_refuses_and_is_named(name, result):
    evidence = parse_evidence(
        render_evidence(BOOT, WHEN, {**ALL_PASS, name: result}, SCOPE_DIGEST))
    assert not evidence.passed
    assert admission_refusal(evidence, boot_id=BOOT, now=NOW) == (
        "isolation checks did not pass: " + name)


# -- the reader's protection -----------------------------------------------------


def test_the_decoy_gate_reads_a_passing_record(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch)
    assert require_isolation_for_decoy(now=NOW).passed


def test_an_absent_record_or_directory_refuses_the_decoy(tmp_path, monkeypatch):
    record = install_evidence(tmp_path, monkeypatch)
    record.unlink()
    assert load_evidence() is None
    with pytest.raises(IsolationEvidenceRefused, match="no isolation evidence"):
        require_isolation_for_decoy(now=NOW)
    record.parent.rmdir()
    with pytest.raises(IsolationEvidenceRefused, match="no isolation evidence"):
        require_isolation_for_decoy(now=NOW)


def test_another_boots_record_refuses_the_decoy(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch, boot=OTHER_BOOT)
    with pytest.raises(IsolationEvidenceRefused, match="not from this boot"):
        require_isolation_for_decoy(now=NOW)


def test_an_unreadable_boot_id_refuses_the_decoy(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch)
    monkeypatch.setattr(decoy_isolation, "_BOOT_ID_PATH", tmp_path / "missing")
    with pytest.raises(IsolationEvidenceRefused, match="boot's id"):
        require_isolation_for_decoy(now=NOW)


def test_a_failing_record_refuses_the_decoy(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch,
                     data=render_evidence(BOOT, WHEN, {**ALL_PASS, "approved_v4_matches": "fail"},
                                          SCOPE_DIGEST))
    with pytest.raises(IsolationEvidenceRefused, match="approved_v4_matches"):
        require_isolation_for_decoy(now=NOW)


def test_a_symlinked_record_is_refused(tmp_path, monkeypatch):
    record = install_evidence(tmp_path, monkeypatch)
    real = tmp_path / "elsewhere.json"
    real.write_bytes(record.read_bytes())
    record.unlink()
    record.symlink_to(real)
    with pytest.raises(IsolationEvidenceRefused, match="could not be opened"):
        load_evidence()


def test_a_symlinked_directory_is_refused(tmp_path, monkeypatch):
    record = install_evidence(tmp_path, monkeypatch)
    link = tmp_path / "linked"
    link.symlink_to(record.parent)
    monkeypatch.setattr(decoy_isolation, "_DIRECTORY", str(link))
    with pytest.raises(IsolationEvidenceRefused, match="directory"):
        load_evidence()


@pytest.mark.parametrize("mode", [0o664, 0o646, 0o666])
def test_a_record_others_may_write_is_refused(tmp_path, monkeypatch, mode):
    record = install_evidence(tmp_path, monkeypatch)
    os.chmod(record, mode)
    with pytest.raises(IsolationEvidenceRefused, match="unsafe"):
        load_evidence()


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o1777])
def test_a_directory_others_may_write_is_refused(tmp_path, monkeypatch, mode):
    record = install_evidence(tmp_path, monkeypatch)
    os.chmod(record.parent, mode)
    with pytest.raises(IsolationEvidenceRefused, match="directory has unsafe"):
        load_evidence()


def test_a_record_or_directory_of_another_owner_is_refused(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch)
    monkeypatch.setattr(decoy_isolation, "_OWNER", os.getuid() + 1)
    with pytest.raises(IsolationEvidenceRefused, match="unsafe"):
        load_evidence()


def test_production_trusts_root_alone():
    assert decoy_isolation._OWNER == 0
    assert decoy_isolation._DIRECTORY == EVIDENCE_DIRECTORY
    assert decoy_isolation._BOOT_ID_PATH is None


def test_a_record_that_is_not_a_regular_file_is_refused(tmp_path, monkeypatch):
    record = install_evidence(tmp_path, monkeypatch)
    record.unlink()
    record.mkdir(mode=0o755)
    with pytest.raises(IsolationEvidenceRefused):
        load_evidence()
    record.rmdir()
    os.mkfifo(record, 0o644)
    with pytest.raises(IsolationEvidenceRefused, match="unsafe ownership or mode"):
        load_evidence()


def test_an_oversized_record_is_refused_without_reading_it_all(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch,
                     data=GOLDEN + b" " * decoy_isolation.MAX_BYTES)
    with pytest.raises(IsolationEvidenceRefused, match="larger"):
        load_evidence()


@pytest.mark.parametrize("data", [
    GOLDEN.replace(b'"pass"', b'"fail"', 1),            # tampered to fail: refuses
    GOLDEN.replace(BOOT.encode(), OTHER_BOOT.encode()),  # another boot
    GOLDEN.replace(b"}\n", b',"note":"ok"}\n'),          # an extra key
])
def test_a_tampered_record_never_admits(tmp_path, monkeypatch, data):
    install_evidence(tmp_path, monkeypatch, data=data)
    with pytest.raises(IsolationEvidenceRefused):
        require_isolation_for_decoy(now=NOW)


# -- the checks ----------------------------------------------------------------


def test_the_real_output_passes_every_check():
    assert evaluate(_outputs(), RULESET) == ALL_PASS
    # And without a scope, the table of the first build.
    assert evaluate(_outputs(nft=NFT_JSON_EMPTY), EMPTY_RULESET) == ALL_PASS


def test_each_ruleset_passes_only_against_its_own_listing():
    """A scope's table is not a pass for no scope, and the reverse (G1b)."""

    table_checks = {"nft_table", "approved_v4_matches", "ingress_matches"}
    for outputs, ruleset in ((_outputs(nft=NFT_JSON_EMPTY), RULESET),
                             (_outputs(), EMPTY_RULESET)):
        results = evaluate(outputs, ruleset)
        assert {name for name, result in results.items() if result != "pass"} == table_checks
    other = render_ruleset(parse_scope_file(SCOPE_BYTES.replace(b"10.20.0.0", b"10.21.0.0")))
    assert {name for name, result in evaluate(_outputs(), other).items()
            if result != "pass"} == {"nft_table", "approved_v4_matches"}


def _links_with(change):
    links = copy.deepcopy(HOST_LINKS)
    change({link["ifname"]: link for link in links}, links)
    return links


def _table_with(change, source=NFT_JSON):
    """The container's `nft -j` output, parsed, changed, and printed again."""

    document = json.loads(source)
    objects = document["nftables"]

    def rule(chain, index):
        return [o["rule"] for o in objects if "rule" in o and o["rule"]["chain"] == chain][index]

    the_set = next(o["set"] for o in objects if "set" in o)
    change(objects, rule, the_set)
    return json.dumps(document)


def _drop_rule(objects, chain, index):
    rules = [o for o in objects if "rule" in o and o["rule"]["chain"] == chain]
    objects.remove(rules[index])


def _drop_chain(objects, chain):
    objects[:] = [o for o in objects
                  if not ("chain" in o and o["chain"]["name"] == chain)
                  and not ("rule" in o and o["rule"]["chain"] == chain)]


@pytest.mark.parametrize(("outputs", "failing"), [
    # An element added by hand (`nft add element`, container-checked form).
    (_outputs(nft=_table_with(lambda o, r, s: s["elem"].append(
        {"prefix": {"addr": "10.99.0.0", "len": 16}}))),
     {"nft_table", "approved_v4_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: s["elem"].insert(0, "10.1.1.1"))),
     {"nft_table", "approved_v4_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: s["elem"].pop())),
     {"nft_table", "approved_v4_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: s.pop("elem"))),
     {"nft_table", "approved_v4_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: s["elem"].__setitem__(
        1, {"range": ["10.30.0.1", "10.30.0.9"]}))),
     {"nft_table", "approved_v4_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: s.update(name="approved"))),
     {"nft_table", "approved_v4_matches"}),
    # An `iifname` match missing: on the accept toward the decoy, on the reply
    # (`oifname`, R3) and the ingress drop (K2) gone.
    (_outputs(nft=_table_with(lambda o, r, s: r("forward", 0)["expr"].pop(0))),
     {"nft_table", "ingress_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: r("forward", 2)["expr"].pop(1))),
     {"nft_table", "ingress_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: _drop_rule(o, "forward", 4))),
     {"nft_table", "ingress_matches"}),
    # Another interface named, or one of the two missing from a set.
    (_outputs(nft=_table_with(lambda o, r, s: r("forward", 0)["expr"][0]["match"].update(
        right={"set": ["lan0", "eth9", "mgmt0"]}))),
     {"nft_table", "ingress_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: r("forward", 4)["expr"][0]["match"].update(
        right="eth9"))),
     {"nft_table", "ingress_matches"}),
    (_outputs(nft=_table_with(lambda o, r, s: r("input", 0)["expr"][0]["match"].update(
        right="eth0"))),
     {"nft_table", "ingress_matches"}),
    # The masquerade (A3) missing, replaced, or its chain gone.
    (_outputs(nft=_table_with(lambda o, r, s: r("postrouting", 0)["expr"].pop())),
     {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: r("postrouting", 0)["expr"].__setitem__(
        2, {"accept": None}))), {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: _drop_rule(o, "postrouting", 0))),
     {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: _drop_chain(o, "postrouting"))),
     {"nft_table"}),
    # The rest of the table.
    (_outputs(nft=_table_with(lambda o, r, s: r("forward", 1)["expr"].__setitem__(
        1, {"accept": None}))), {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: _drop_rule(o, "output", 0))), {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: next(
        x["chain"] for x in o if "chain" in x).update(policy="drop"))), {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: o.append(
        {"map": {"family": "inet", "name": "m", "table": "azazel_decoy"}}))), {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: o.append(
        {"rule": {"family": "inet", "table": "azazel_decoy", "chain": "forward",
                  "expr": [{"accept": None}]}}))), {"nft_table"}),
    (_outputs(nft=_table_with(lambda o, r, s: o.insert(7, o.pop(8)))), {"nft_table"}),
    # The bridge.
    (_outputs(links=_links_with(lambda by, _: by["az-decoy0"]["flags"].remove("UP"))),
     {"bridge"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy0"].update(
        linkinfo={"info_kind": "dummy"}))), {"bridge"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy0"].update(master="eth0"))),
     {"bridge"}),
    (_outputs(links=_links_with(lambda by, links: links.remove(by["az-decoy0"]))),
     {"bridge", "bridge_address"}),
    (_outputs(links=_links_with(lambda by, links: links.append(copy.deepcopy(by["az-decoy0"])))),
     {"bridge", "bridge_address"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy0"]["addr_info"].append(
        {"family": "inet", "local": "192.0.2.77", "prefixlen": 24, "scope": "global"}))),
     {"bridge_address"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy0"]["addr_info"].__setitem__(
        0, {"family": "inet", "local": "10.255.196.1", "prefixlen": 24}))),
     {"bridge_address"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy0"]["addr_info"].append(
        {"family": "inet6", "local": "2001:db8::1", "prefixlen": 64, "scope": "global"}))),
     {"bridge_address"}),
    # Its ports.
    (_outputs(links=_links_with(lambda by, _: by["eth0"].update(master="az-decoy0"))),
     {"bridge_ports"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy-host0"].pop("master"))),
     {"bridge_ports", "host_veth"}),
    # The host end.
    (_outputs(links=_links_with(lambda by, _: by["az-decoy-host0"].pop("link_netnsid"))),
     {"host_veth"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy-host0"]["flags"].remove("UP"))),
     {"host_veth"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy-host0"]["linkinfo"].update(
        info_kind="dummy"))), {"host_veth"}),
    (_outputs(links=_links_with(lambda by, _: by["az-decoy-host0"]["addr_info"].append(
        {"family": "inet", "local": "192.0.2.5", "prefixlen": 24, "scope": "global"}))),
     {"host_veth"}),
    # The decoy's end on the host, and the subnet elsewhere.
    (_outputs(links=_links_with(lambda by, links: links.append(
        {"ifname": "az-decoy-ns0", "flags": ["UP"], "addr_info": []}))),
     {"decoy_veth_off_host"}),
    (_outputs(links=_links_with(lambda by, _: by["eth0"]["addr_info"].append(
        {"family": "inet", "local": "10.255.196.2", "prefixlen": 30, "scope": "global"}))),
     {"subnet_exclusive"}),
    (_outputs(links=_links_with(lambda by, _: by["lo"]["addr_info"].append(
        {"family": "inet", "local": "not-an-address", "prefixlen": 32}))),
     {"subnet_exclusive"}),
])
def test_each_mutation_of_the_real_output_fails_exactly_its_checks(outputs, failing):
    results = evaluate(outputs, RULESET)
    assert {name for name, result in results.items() if result != "pass"} == failing
    assert all(results[name] == "fail" for name in failing)


@pytest.mark.parametrize("change", [
    # The kernel's handles and the order of an anonymous set say nothing.
    lambda o, r, s: [next(iter(x.values())).update(handle=999) for x in o[1:]],
    lambda o, r, s: r("forward", 0)["expr"][0]["match"].update(right={"set": ["eth9", "lan0"]}),
    lambda o, r, s: r("forward", 0)["expr"][4]["match"].update(
        right={"set": [8080, 2222, 2323]}),
    lambda o, r, s: o[0]["metainfo"].update(version="1.1.4", release_name="another"),
], ids=["handles", "name-order", "port-order", "release"])
def test_what_nftables_varies_on_its_own_is_not_a_departure(change):
    assert evaluate(_outputs(nft=_table_with(change)), RULESET) == ALL_PASS


TABLE_CHECKS = {"nft_table", "approved_v4_matches", "ingress_matches"}


@pytest.mark.parametrize(("outputs", "unreadable"), [
    (_outputs(nft_status=1), TABLE_CHECKS),
    (_outputs(nft=b"\xff\xfe"), TABLE_CHECKS),
    # The text listing of the first build is not the JSON one.
    (_outputs(nft=EMPTY_RULESET.text.split("\n", 1)[1]), TABLE_CHECKS),
    (_outputs(nft=b"[]"), TABLE_CHECKS),
    (_outputs(nft=b'{"nftables": []}'), TABLE_CHECKS),
    (_outputs(nft=b'{"nftables": {}}'), TABLE_CHECKS),
    (_outputs(nft=_table_with(lambda o, r, s: o.pop(0))), TABLE_CHECKS),
    (_outputs(nft=_table_with(lambda o, r, s: o[0]["metainfo"].update(
        json_schema_version=2))), TABLE_CHECKS),
    (_outputs(nft=_table_with(lambda o, r, s: o[0]["metainfo"].update(
        json_schema_version=True))), TABLE_CHECKS),
    (_outputs(nft=_table_with(lambda o, r, s: o[1].update(chain={}))), TABLE_CHECKS),
    (_outputs(nft=_table_with(lambda o, r, s: o.append({"table": []}))), TABLE_CHECKS),
    (_outputs(nft=_table_with(lambda o, r, s: o.append("rule"))), TABLE_CHECKS),
    (_outputs(nft=b"[" * 100000), TABLE_CHECKS),
    (_outputs(links_status=124), set(CHECKS[3:])),
    (_outputs(links=b"not json"), set(CHECKS[3:])),
    (_outputs(links=b'{"ifname": "az-decoy0"}'), set(CHECKS[3:])),
    (_outputs(links=b'[{"ifname": 3}]'), set(CHECKS[3:])),
    (_outputs(links=b'[{"ifname": "x", "addr_info": [1]}]'), set(CHECKS[3:])),
    ({}, set(CHECKS)),
])
def test_output_that_cannot_be_read_is_unreadable_never_a_pass(outputs, unreadable):
    results = evaluate(outputs, RULESET)
    assert {name for name, result in results.items() if result == "unreadable"} == unreadable
    assert list(results) == list(CHECKS)


@pytest.mark.parametrize("change", [
    lambda o, r, s: r("forward", 0).update(expr="x"),
    lambda o, r, s: r("forward", 0)["expr"].append(7),
    lambda o, r, s: r("forward", 0)["expr"][0]["match"].update(right={"set": [1, "a"]}),
    lambda o, r, s: r("forward", 0)["expr"][0]["match"].update(right=None),
    lambda o, r, s: r("forward", 0)["expr"][0]["match"].update(left="x"),
    lambda o, r, s: s.update(elem="10.20.0.0/24"),
    lambda o, r, s: s["elem"].append({"prefix": {"addr": "10.1.0.1", "len": 24}}),
    lambda o, r, s: s["elem"].append({"prefix": {"addr": "10.1.0.0", "len": "24"}}),
    lambda o, r, s: s["elem"].append("not-an-address"),
])
def test_odd_values_in_the_table_fail_and_never_raise(change):
    results = evaluate(_outputs(nft=_table_with(change)), RULESET)
    assert results["nft_table"] == "fail"
    assert set(results.values()) <= {"pass", "fail"}


@pytest.mark.parametrize("key", ["ifname", "flags", "addr_info"])
@pytest.mark.parametrize("link", ["lo", "az-decoy0", "az-decoy-host0"])
def test_a_link_missing_a_key_makes_the_listing_unreadable(key, link):
    """Review of #274: a missing key used to raise KeyError in evaluate."""

    links = _links_with(lambda by, _: by[link].pop(key))
    results = evaluate(_outputs(links=links), RULESET)
    assert {name for name, result in results.items() if result == "unreadable"} == set(CHECKS[3:])
    assert results["nft_table"] == "pass"


@pytest.mark.parametrize("value", [None, "UP", {"UP": 1}])
def test_flags_of_another_type_make_the_listing_unreadable(value):
    links = _links_with(lambda by, _: by["az-decoy0"].update(flags=value))
    assert evaluate(_outputs(links=links), RULESET)["bridge"] == "unreadable"


def test_odd_values_inside_a_link_fail_their_check_and_never_raise():
    links = _links_with(lambda by, _: (
        by["az-decoy0"].update(linkinfo="bridge"),
        by["az-decoy-host0"]["addr_info"].append({"family": "inet"}),
        by["eth0"].update(master=["az-decoy0"])))
    results = evaluate(_outputs(links=links), RULESET)
    assert results["bridge"] == "fail" and results["host_veth"] == "fail"


def test_an_evaluation_error_records_nothing_and_does_not_pass(
        evidence_directory, monkeypatch, capsys):
    def broken(outputs, ruleset):
        raise KeyError("flags")

    monkeypatch.setattr(decoy_isolation_check, "evaluate", broken)
    recorder = _recorder(evidence_directory)
    assert recorder.prepare()
    assert recorder.record(_outputs(), RULESET) is False
    assert os.listdir(evidence_directory) == []
    assert "could not be evaluated" in capsys.readouterr().err


def test_the_checks_name_the_fixed_values_the_network_is_built_from():
    from azazel_nexus_runtime import decoy_network
    from azazel_nexus_runtime.decoy_addresses import BRIDGE, DECOY_SUBNET, HOST_VETH

    assert decoy_isolation_check.DECOY_VETH is decoy_netns.DECOY_VETH
    assert decoy_isolation_check._APPROVED_SET == decoy_network.APPROVED_SET
    # One JSON form on both sides.
    for document in (json.loads(RULESET.expected), {"b": [1, None], "a": "x"}):
        assert decoy_isolation_check._canonical(document) == decoy_network.canonical_json(
            document)
    assert (BRIDGE, HOST_VETH, DECOY_SUBNET) == ("az-decoy0", "az-decoy-host0", "10.255.196.0/30")


# -- the writer ------------------------------------------------------------------


@pytest.fixture
def evidence_directory(tmp_path):
    directory = tmp_path / "azazel-decoy-isolation"
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    return directory


def _recorder(directory, boot=BOOT):
    def boot_id():
        if boot is None:
            from azazel_nexus.boot_id import BootIdRefused
            raise BootIdRefused("no boot id")
        return boot

    return Recorder(directory=str(directory), owner=os.getuid(), boot_id=boot_id,
                    clock=lambda: WHEN)


def test_the_recorder_writes_the_golden_as_root_would_under_the_units_umask(
        evidence_directory, capsys):
    recorder = _recorder(evidence_directory)
    previous = os.umask(0o027)
    try:
        assert recorder.prepare()
        assert recorder.record(_outputs(), RULESET)
    finally:
        os.umask(previous)
    record = evidence_directory / EVIDENCE_NAME
    assert record.read_bytes() == GOLDEN
    assert record.stat().st_mode & 0o777 == 0o644
    assert sorted(os.listdir(evidence_directory)) == [EVIDENCE_NAME]
    err = capsys.readouterr().err
    assert "isolation check: nft_table pass" in err
    # No address, prefix, interface name or digest in the journal line.
    for forbidden in ("10.255.196", "192.0.2", "10.20.", "192.168.", "eth9", "lan0",
                      "sha256"):
        assert forbidden not in err


def test_without_a_scope_the_record_says_none(evidence_directory):
    recorder = _recorder(evidence_directory)
    assert recorder.prepare()
    assert recorder.record(_outputs(nft=NFT_JSON_EMPTY), EMPTY_RULESET)
    evidence = parse_evidence((evidence_directory / EVIDENCE_NAME).read_bytes())
    assert evidence.passed and evidence.scope_digest == NO_SCOPE


def test_a_record_with_a_failing_check_is_written_and_reported_as_not_passing(
        evidence_directory):
    recorder = _recorder(evidence_directory)
    assert recorder.prepare()
    added = _table_with(lambda o, r, s: s["elem"].append(
        {"prefix": {"addr": "10.99.0.0", "len": 16}}))
    assert not recorder.record(_outputs(nft=added), RULESET)
    evidence = parse_evidence((evidence_directory / EVIDENCE_NAME).read_bytes())
    assert evidence.not_passed == ("nft_table", "approved_v4_matches")


def test_prepare_removes_the_previous_record_and_a_leftover_temporary(evidence_directory):
    (evidence_directory / EVIDENCE_NAME).write_bytes(GOLDEN)
    (evidence_directory / ".isolation.json.new").write_bytes(b"partial")
    assert _recorder(evidence_directory).prepare()
    assert os.listdir(evidence_directory) == []


def test_without_a_boot_id_nothing_is_recorded(evidence_directory):
    recorder = _recorder(evidence_directory, boot=None)
    assert not recorder.prepare()
    assert not recorder.record(_outputs(), RULESET)
    assert os.listdir(evidence_directory) == []


def test_the_recorder_never_writes_through_a_link(evidence_directory, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    (evidence_directory / ".isolation.json.new").symlink_to(target)
    recorder = _recorder(evidence_directory)
    # The leftover link is removed (unlink does not follow it), then the record
    # is written fresh; the link's target is untouched.
    assert recorder.prepare()
    assert recorder.record(_outputs(), RULESET)
    assert target.read_bytes() == b"untouched"
    assert not (evidence_directory / EVIDENCE_NAME).is_symlink()


def test_the_recorder_refuses_a_foreign_or_open_directory(evidence_directory, tmp_path):
    os.chmod(evidence_directory, 0o777)
    recorder = _recorder(evidence_directory)
    assert not recorder.prepare()
    os.chmod(evidence_directory, 0o755)
    foreign = Recorder(directory=str(evidence_directory), owner=os.getuid() + 1,
                       boot_id=lambda: BOOT, clock=lambda: WHEN)
    assert not foreign.prepare()
    link = tmp_path / "link"
    link.symlink_to(evidence_directory)
    assert not _recorder(link).prepare()


def test_without_its_directory_the_recorder_records_nothing(tmp_path):
    recorder = _recorder(tmp_path / "absent")
    assert recorder.prepare()  # nothing to remove
    assert not recorder.record(_outputs(), RULESET)


def test_withdraw_removes_the_record(evidence_directory):
    recorder = _recorder(evidence_directory)
    recorder.prepare()
    recorder.record(_outputs(), RULESET)
    assert recorder.withdraw()
    assert os.listdir(evidence_directory) == []


def test_what_the_recorder_writes_the_decoy_admits(evidence_directory, tmp_path, monkeypatch):
    recorder = _recorder(evidence_directory)
    recorder.prepare()
    assert recorder.record(_outputs(), RULESET)
    install_evidence(tmp_path, monkeypatch,
                     data=(evidence_directory / EVIDENCE_NAME).read_bytes())
    assert require_isolation_for_decoy(now=NOW).passed


# -- the decoy -------------------------------------------------------------------


@pytest.fixture
def in_namespace(tmp_path, monkeypatch):
    own = tmp_path / "decoy-ns"
    host = tmp_path / "host-ns"
    own.write_bytes(b"")
    host.write_bytes(b"")
    dev = tmp_path / "net-dev"
    dev.write_text("Inter-|\n face |\n    lo: 0 0\n")
    monkeypatch.setattr(decoy_netns, "_OWN", str(own))
    monkeypatch.setattr(decoy_netns, "_EXPECTED", str(own))
    monkeypatch.setattr(decoy_netns, "_INIT", str(host))
    monkeypatch.setattr(decoy_netns, "_NET_DEV", str(dev))


@pytest.fixture
def no_socket(monkeypatch):
    made = []

    def refuse(*args, **kwargs):
        made.append(args)
        raise AssertionError("a socket was made")

    monkeypatch.setattr(socket, "socket", refuse)
    return made


@pytest.mark.parametrize("record", ["absent", "failing", "other-boot", "tampered", "v1"])
def test_the_decoy_refuses_before_any_socket_without_a_passing_record(
        tmp_path, monkeypatch, in_namespace, no_socket, capsys, record):
    data = {
        "failing": render_evidence(BOOT, WHEN, {**ALL_PASS, "bridge_ports": "fail"}, SCOPE_DIGEST),
        "other-boot": render_evidence(OTHER_BOOT, WHEN, dict(ALL_PASS), SCOPE_DIGEST),
        "tampered": GOLDEN.replace(b",", b", ", 1),
        # The decoy requires v2 (#196 G1b): this boot's passing v1 record refuses.
        "v1": GOLDEN_V1,
    }.get(record)
    path = install_evidence(tmp_path, monkeypatch, data=data)
    if record == "absent":
        path.unlink()
    assert decoyd.main([]) == 1
    err = capsys.readouterr().err
    assert "refusing to listen" in err
    assert no_socket == []


# -- activation: a frame, never a grant ------------------------------------------


def test_the_producer_frames_each_reading(tmp_path, monkeypatch):
    record = install_evidence(tmp_path, monkeypatch)
    reading = installed_isolation_reading(now=NOW)
    assert (reading.state, reading.checked_at) == (IsolationState.PASSED, WHEN)
    record.write_bytes(
        render_evidence(BOOT, WHEN, {**ALL_PASS, "bridge": "unreadable"}, SCOPE_DIGEST))
    reading = installed_isolation_reading(now=NOW)
    assert (reading.state, reading.not_passed) == (IsolationState.NOT_PASSED, ("bridge",))
    record.write_bytes(render_evidence(OTHER_BOOT, WHEN, dict(ALL_PASS), SCOPE_DIGEST))
    assert installed_isolation_reading(now=NOW).state is IsolationState.NOT_THIS_BOOT
    record.write_bytes(GOLDEN[:-1])
    assert installed_isolation_reading(now=NOW).state is IsolationState.REFUSED
    record.write_bytes(GOLDEN)
    assert installed_isolation_reading(now="2026-10-22T02:00:00Z").state is IsolationState.REFUSED
    record.unlink()
    assert installed_isolation_reading(now=NOW).state is IsolationState.ABSENT


def test_a_passing_record_still_grants_no_exposure_unit(tmp_path, monkeypatch):
    """The record is not the tier's evidence: the controller takes no reading
    (§14), and without the pass's exposure evidence the tier is withheld
    (`exposure_evidence_absent`, #196 G6)."""

    import inspect

    from azazel_nexus.activation import ActivationController, DECEPTION_EXPOSURE_UNITS

    install_evidence(tmp_path, monkeypatch)
    assert installed_isolation_reading(now=NOW).state is IsolationState.PASSED
    # Nothing in the controller can take a reading.
    for method in (ActivationController.__init__, ActivationController.activate):
        assert not {"isolation", "isolation_evidence", "evidence_reading"} & set(
            inspect.signature(method).parameters)
    source = (REPO / "src" / "azazel_nexus" / "activation.py").read_text(encoding="utf-8")
    assert "decoy_isolation" not in {
        node.module for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module}
    from test_decoy_namespace_unit import ACTOR, _controller, _lease
    from test_decoy_namespace_unit import NOW as PASS_NOW

    from azazel_nexus.activation import CORE_UNITS

    controller, units = _controller(tmp_path)
    outcome = controller.activate(now=PASS_NOW, actor=ACTOR,
                                  lease=_lease(frozenset(d.name for d in CORE_UNITS)))
    verdicts = [v for v in outcome.verdicts if v.unit in DECEPTION_EXPOSURE_UNITS]
    assert sorted(v.unit for v in verdicts) == sorted(DECEPTION_EXPOSURE_UNITS)
    assert all(not v.granted and v.reason.startswith("exposure_evidence_absent")
               for v in verdicts)
    assert not set(outcome.granted) & set(DECEPTION_EXPOSURE_UNITS)


# -- the decoy and the pass's scope digest (#196 G6, wiring §6, D2) --------------


def test_the_decoy_refuses_a_record_that_names_no_scope(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch,
                     data=render_evidence(BOOT, WHEN, dict(ALL_PASS), NO_SCOPE))
    install_scope_digest(tmp_path, monkeypatch, SCOPE_DIGEST)
    with pytest.raises(IsolationEvidenceRefused, match="names no scope"):
        require_isolation_for_decoy(now=NOW)


def test_the_decoy_refuses_a_record_for_another_scope(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch)
    install_scope_digest(tmp_path, monkeypatch, "sha256:" + "0" * 64)
    with pytest.raises(IsolationEvidenceRefused, match="not the one the activation pass"):
        require_isolation_for_decoy(now=NOW)


def test_the_decoy_refuses_without_its_credential(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch)
    install_scope_digest(tmp_path, monkeypatch, None)
    with pytest.raises(IsolationEvidenceRefused, match="credential is absent"):
        require_isolation_for_decoy(now=NOW)
    monkeypatch.setattr(decoy_isolation, "_DIGEST_PATH", str(tmp_path / "none" / "x"))
    with pytest.raises(IsolationEvidenceRefused, match="credential is absent"):
        require_isolation_for_decoy(now=NOW)


@pytest.mark.parametrize("content,mode", [
    (SCOPE_DIGEST.encode(), 0o400),                     # no newline
    (SCOPE_DIGEST.encode() + b"\n\n", 0o400),          # one byte more
    (SCOPE_DIGEST.upper().encode() + b"\n", 0o400),     # not the closed form
    (b"none" + b" " * 67 + b"\n", 0o400),
    (SCOPE_DIGEST.encode() + b"\n", 0o622),             # writable by others
    (SCOPE_DIGEST.encode() + b"\n", 0o460),             # writable by the group
])
def test_the_decoy_refuses_a_credential_out_of_its_closed_form(tmp_path, monkeypatch,
                                                              content, mode):
    install_evidence(tmp_path, monkeypatch)
    install_scope_digest(tmp_path, monkeypatch, None, content=content, mode=mode)
    with pytest.raises(IsolationEvidenceRefused):
        require_isolation_for_decoy(now=NOW)


def test_the_decoy_refuses_a_credential_that_is_a_link(tmp_path, monkeypatch):
    install_evidence(tmp_path, monkeypatch)
    path = install_scope_digest(tmp_path, monkeypatch, SCOPE_DIGEST)
    target = tmp_path / "elsewhere"
    target.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(IsolationEvidenceRefused):
        require_isolation_for_decoy(now=NOW)


def test_the_credential_path_is_the_units(tmp_path, monkeypatch):
    """The path the reader opens is the one the unit's `LoadCredential=` fills."""

    from azazel_nexus_runtime.hardening import DECOY_SCOPE_DIGEST_CREDENTIAL

    name, _, source = DECOY_SCOPE_DIGEST_CREDENTIAL.partition(":")
    assert decoy_isolation.SCOPE_DIGEST_CREDENTIAL_PATH == (
        f"/run/credentials/azazel-decoyd.service/{name}")
    assert source == "/run/azazel-activation/decoy-scope.digest"


def test_nothing_in_the_runtime_feeds_a_reading_to_activation():
    users = sorted(path.name for path in RUNTIME.rglob("*.py")
                   if "installed_isolation_reading" in path.read_text(encoding="utf-8"))
    assert users == []


# -- the units and the boundary ---------------------------------------------------


def test_the_record_directory_is_the_helpers_runtime_directory_alone():
    from dataclasses import replace

    from azazel_nexus_runtime.hardening import (
        DECOY_ISOLATION_DIRECTORY,
        DECOY_ISOLATION_DIRECTORY_MODE,
        PROFILES,
    )

    assert f"/run/{DECOY_ISOLATION_DIRECTORY}" == EVIDENCE_DIRECTORY
    holders = [p.unit for p in PROFILES
               if DECOY_ISOLATION_DIRECTORY in p.runtime_directory.split()]
    assert holders == ["azazel-decoy-netd.service"]
    helper = next(p for p in PROFILES if p.unit == "azazel-decoy-netd.service")
    assert (helper.runtime_directory, helper.runtime_directory_mode) == (
        DECOY_ISOLATION_DIRECTORY, DECOY_ISOLATION_DIRECTORY_MODE) == (
        "azazel-decoy-isolation", "0755")
    for change in ({"runtime_directory": ""}, {"runtime_directory": "azazel"},
                   {"runtime_directory_mode": "0777"},
                   {"runtime_directory_mode": "0750"},
                   {"read_write_paths": ("/var/lib/azazel/decoy",)}):
        with pytest.raises(ValueError):
            replace(helper, **change)
    decoy = next(p for p in PROFILES if p.unit == "azazel-decoyd.service")
    for name in (DECOY_ISOLATION_DIRECTORY, f"{DECOY_ISOLATION_DIRECTORY}/x"):
        with pytest.raises(ValueError, match="runtime directory alone"):
            replace(decoy, runtime_directory=name)
    # The decoy reads it from /run, which its ProtectSystem=strict leaves readable;
    # it declares nothing there.
    assert decoy.runtime_directory == "" and "/run" not in " ".join(decoy.read_write_paths)


def test_only_the_helper_loads_the_recorder_and_it_starts_no_process():
    importers = sorted(
        source.name for source in RUNTIME.rglob("*.py")
        if any(isinstance(node, ast.ImportFrom) and node.module
               and node.module.split(".")[-1] == "decoy_isolation_check"
               for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))))
    # The helper's executable alone: its build (the recorder) and its verify
    # (#196 G2, `decoy_watch`, which takes the judgement and never the
    # recorder: the verify writes no record).
    assert importers == ["decoy_netd.py", "decoy_watch.py"]
    watch = ast.parse((RUNTIME / "decoy_watch.py").read_text(encoding="utf-8"))
    taken = {alias.name for node in ast.walk(watch)
             if isinstance(node, ast.ImportFrom) and node.module == "decoy_isolation_check"
             for alias in node.names}
    assert taken == {"evaluate"}
    tree = ast.parse((RUNTIME / "decoy_isolation_check.py").read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not names & {"posix_spawn", "subprocess", "socket", "environ", "getenv", "system",
                        "popen", "fork", "execv", "execve", "setns", "unshare", "decoy_network",
                        "capture_fixed", "run_fixed", "chown", "symlink", "readlink"}
    imports = {node.module for node in ast.walk(tree)
               if isinstance(node, ast.ImportFrom) and node.module}
    assert "decoy_network" not in imports


def test_the_decoy_process_still_loads_exactly_its_six_modules():
    """The gate is the library's: the decoy's runtime closure is unchanged."""

    from test_runtime_boundary import DECOY_PROCESS, _decoy_closure

    assert _decoy_closure() == DECOY_PROCESS
    source = (RUNTIME / "decoyd.py").read_text(encoding="utf-8")
    assert "from azazel_nexus.decoy_isolation import" in source
