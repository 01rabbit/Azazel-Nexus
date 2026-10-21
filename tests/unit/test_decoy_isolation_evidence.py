"""#196 §14: the decoy network's isolation evidence, written and read.

`docs/deception-redirect-prerequisites.md` §14. The network helper reads
back the host side it built (`nft list table inet azazel_decoy`, `ip -j -d
address show`), turns it into one fixed result per check, and writes this
boot's record to its runtime directory; the decoy refuses to listen unless
that record is from this boot, from root, in the exact shape, and every check
passed. These tests pin, with fake command output (nothing here runs `ip` or
`nft` or opens a socket):

* the record's closed, canonical shape, as a golden, and the refusal of
  every departure from it (keys, values, whitespace, order, size);
* the reader's protection: no symlink for the directory or the file, root's
  only, nobody else may write, a regular file within the limit;
* this boot only, not in the future, every check passed;
* each check against the output of a real container run (the golden), and
  each mutation of that output failing exactly its check;
* the writer: the previous record removed first, the record root's `0644`
  under the unit's umask, written by rename, never through a link;
* the decoy refusing before any socket without a passing record;
* the activation library still withholding the tier with a passing record
  in place; the producer frame's readings;
* the unit declarations and the boundary: the helper's runtime directory
  alone, only the helper loads the recorder.

The container run in §14 is a mechanism check, not VM or hardware evidence.
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
    IsolationEvidenceRefused,
    IsolationState,
    admission_refusal,
    installed_isolation_reading,
    load_evidence,
    parse_evidence,
    render_evidence,
    require_isolation_for_decoy,
)
from azazel_nexus_runtime import decoy_isolation_check, decoy_netns, decoyd
from azazel_nexus_runtime.decoy_isolation_check import EXPECTED_NFT_LISTING, Recorder, evaluate

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "runtime" / "src" / "azazel_nexus_runtime"

BOOT = "0f4a6d2e-7c1b-4e5a-9d3c-2b8f1a6e4c70"
OTHER_BOOT = "9b1c3e5a-2d4f-4a6b-8c0d-1e3f5a7b9c2d"
NOW = "2026-10-22T03:00:10Z"
WHEN = "2026-10-22T03:00:00Z"
ALL_PASS = {name: "pass" for name in CHECKS}

#: The record for `BOOT`, `WHEN`, every check passing: byte for byte.
GOLDEN = (
    b'{"boot_id":"0f4a6d2e-7c1b-4e5a-9d3c-2b8f1a6e4c70",'
    b'"checked_at":"2026-10-22T03:00:00Z",'
    b'"checks":{"approved_v4_empty":"pass","bridge":"pass","bridge_address":"pass",'
    b'"bridge_ports":"pass","decoy_veth_off_host":"pass","host_veth":"pass",'
    b'"nft_table":"pass","subnet_exclusive":"pass"},'
    b'"contract":"azazel-nexus/decoy-isolation/v1"}\n'
)

#: `nft list table inet azazel_decoy` after the helper loaded its table, as
#: printed by nftables 1.1.3 in a privileged Debian 13 container (§14).
NFT_LISTING = (
    "table inet azazel_decoy {\n"
    "\tset approved_v4 {\n"
    "\t\ttype ipv4_addr\n"
    "\t\tflags interval\n"
    "\t}\n"
    "\n"
    "\tchain forward {\n"
    "\t\ttype filter hook forward priority filter; policy accept;\n"
    '\t\toifname "az-decoy0" ip saddr @approved_v4 ip daddr 10.255.196.2 tcp dport '
    "{ 2222, 2323, 8080 } accept\n"
    '\t\toifname "az-decoy0" drop\n'
    '\t\tiifname "az-decoy0" ip saddr 10.255.196.2 ip daddr @approved_v4 tcp sport '
    "{ 2222, 2323, 8080 } ct state established accept\n"
    '\t\tiifname "az-decoy0" drop\n'
    "\t}\n"
    "\n"
    "\tchain input {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    '\t\tiifname "az-decoy0" drop\n'
    "\t}\n"
    "\n"
    "\tchain output {\n"
    "\t\ttype filter hook output priority filter; policy accept;\n"
    '\t\toifname "az-decoy0" drop\n'
    "\t}\n"
    "}\n"
)

#: `ip -j -d address show` from the same run, reduced to the fields the checks
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


def _outputs(nft=NFT_LISTING, links=None, nft_status=0, links_status=0):
    links = HOST_LINKS if links is None else links
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
        data = render_evidence(BOOT, WHEN, dict(ALL_PASS))
    record.write_bytes(data)
    os.chmod(record, 0o644)
    monkeypatch.setattr(decoy_isolation, "_DIRECTORY", str(directory))
    monkeypatch.setattr(decoy_isolation, "_OWNER", os.getuid())
    monkeypatch.setattr(decoy_isolation, "_BOOT_ID_PATH", boot_file)
    return record


# -- the record's shape --------------------------------------------------------


def test_the_record_is_the_golden():
    assert render_evidence(BOOT, WHEN, dict(ALL_PASS)) == GOLDEN
    evidence = parse_evidence(GOLDEN)
    assert (evidence.boot_id, evidence.checked_at) == (BOOT, WHEN)
    assert evidence.checks == tuple((name, "pass") for name in CHECKS)
    assert evidence.passed and evidence.not_passed == ()
    assert CONTRACT == "azazel-nexus/decoy-isolation/v1"
    assert EVIDENCE_DIRECTORY == "/run/azazel-decoy-isolation"
    assert EVIDENCE_NAME == "isolation.json"
    assert decoy_isolation.RESULTS == ("pass", "fail", "unreadable")


def test_the_record_holds_no_address_and_nothing_but_fixed_words():
    document = json.loads(GOLDEN)
    assert set(document) == {"boot_id", "checked_at", "checks", "contract"}
    text = GOLDEN.decode()
    for forbidden in ("10.255.196", "192.0.2", "fe80", "az-decoy", "eth0", "elements"):
        assert forbidden not in text
    assert len(GOLDEN) < decoy_isolation.MAX_BYTES


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
    GOLDEN.replace(b"v1", b"v2"),
    _mutated(lambda d: d.update(extra=1)),
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
            render_evidence(BOOT, WHEN, checks)
    with pytest.raises(IsolationEvidenceRefused):
        render_evidence("not-a-boot", WHEN, dict(ALL_PASS))
    with pytest.raises(IsolationEvidenceRefused):
        render_evidence(BOOT, "yesterday", dict(ALL_PASS))


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
    evidence = parse_evidence(render_evidence(BOOT, WHEN, {**ALL_PASS, name: result}))
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
                     data=render_evidence(BOOT, WHEN, {**ALL_PASS, "approved_v4_empty": "fail"}))
    with pytest.raises(IsolationEvidenceRefused, match="approved_v4_empty"):
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


def test_the_expected_listing_is_the_container_golden():
    lines = [line.strip() for line in NFT_LISTING.splitlines() if line.strip()]
    assert tuple(lines) == EXPECTED_NFT_LISTING


def test_the_real_output_passes_every_check():
    assert evaluate(_outputs()) == ALL_PASS


def _links_with(change):
    links = copy.deepcopy(HOST_LINKS)
    change({link["ifname"]: link for link in links}, links)
    return links


def _with_element(text):
    return text.replace("\t\tflags interval\n",
                        "\t\tflags interval\n\t\telements = { 192.0.2.0/24 }\n")


@pytest.mark.parametrize(("outputs", "failing"), [
    # The table.
    (_outputs(nft=NFT_LISTING.replace(' "az-decoy0" drop\n\t}\n\n\tchain input',
                                      ' "az-decoy0" accept\n\t}\n\n\tchain input')),
     {"nft_table"}),
    (_outputs(nft=NFT_LISTING.replace("\tchain output {\n\t\ttype filter hook output priority "
                                      "filter; policy accept;\n\t\toifname \"az-decoy0\" drop\n"
                                      "\t}\n", "")), {"nft_table"}),
    (_outputs(nft=NFT_LISTING.replace("policy accept;", "policy drop;", 1)), {"nft_table"}),
    (_outputs(nft=NFT_LISTING + "table inet azazel_decoy {\n}\n"), {"nft_table"}),
    (_outputs(nft=_with_element(NFT_LISTING)), {"nft_table", "approved_v4_empty"}),
    (_outputs(nft=NFT_LISTING.replace("set approved_v4", "set approved")),
     {"nft_table", "approved_v4_empty"}),
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
    results = evaluate(outputs)
    assert {name for name, result in results.items() if result != "pass"} == failing
    assert all(results[name] == "fail" for name in failing)


@pytest.mark.parametrize(("outputs", "unreadable"), [
    (_outputs(nft_status=1), {"nft_table", "approved_v4_empty"}),
    (_outputs(nft=b"\xff\xfe"), {"nft_table", "approved_v4_empty"}),
    (_outputs(links_status=124), set(CHECKS[2:])),
    (_outputs(links=b"not json"), set(CHECKS[2:])),
    (_outputs(links=b'{"ifname": "az-decoy0"}'), set(CHECKS[2:])),
    (_outputs(links=b'[{"ifname": 3}]'), set(CHECKS[2:])),
    (_outputs(links=b'[{"ifname": "x", "addr_info": [1]}]'), set(CHECKS[2:])),
    ({}, set(CHECKS)),
])
def test_output_that_cannot_be_read_is_unreadable_never_a_pass(outputs, unreadable):
    results = evaluate(outputs)
    assert {name for name, result in results.items() if result == "unreadable"} == unreadable
    assert list(results) == list(CHECKS)


@pytest.mark.parametrize("key", ["ifname", "flags", "addr_info"])
@pytest.mark.parametrize("link", ["lo", "az-decoy0", "az-decoy-host0"])
def test_a_link_missing_a_key_makes_the_listing_unreadable(key, link):
    """Review of #274: a missing key used to raise KeyError in evaluate."""

    links = _links_with(lambda by, _: by[link].pop(key))
    results = evaluate(_outputs(links=links))
    assert {name for name, result in results.items() if result == "unreadable"} == set(CHECKS[2:])
    assert results["nft_table"] == "pass"


@pytest.mark.parametrize("value", [None, "UP", {"UP": 1}])
def test_flags_of_another_type_make_the_listing_unreadable(value):
    links = _links_with(lambda by, _: by["az-decoy0"].update(flags=value))
    assert evaluate(_outputs(links=links))["bridge"] == "unreadable"


def test_odd_values_inside_a_link_fail_their_check_and_never_raise():
    links = _links_with(lambda by, _: (
        by["az-decoy0"].update(linkinfo="bridge"),
        by["az-decoy-host0"]["addr_info"].append({"family": "inet"}),
        by["eth0"].update(master=["az-decoy0"])))
    results = evaluate(_outputs(links=links))
    assert results["bridge"] == "fail" and results["host_veth"] == "fail"


def test_an_evaluation_error_records_nothing_and_does_not_pass(
        evidence_directory, monkeypatch, capsys):
    def broken(outputs):
        raise KeyError("flags")

    monkeypatch.setattr(decoy_isolation_check, "evaluate", broken)
    recorder = _recorder(evidence_directory)
    assert recorder.prepare()
    assert recorder.record(_outputs()) is False
    assert os.listdir(evidence_directory) == []
    assert "could not be evaluated" in capsys.readouterr().err


def test_the_checks_name_the_fixed_values_the_network_is_built_from():
    from azazel_nexus_runtime import decoy_network
    from azazel_nexus_runtime.decoy_addresses import BRIDGE, DECOY_SUBNET, HOST_VETH, NFT_TABLE

    assert decoy_isolation_check.DECOY_VETH is decoy_netns.DECOY_VETH
    assert EXPECTED_NFT_LISTING[0] == f"table inet {NFT_TABLE} {{"
    # The expected listing is the loaded ruleset, minus `create table`, as nft prints it.
    loaded = [line.strip() for line in decoy_network.NFT_RULESET.splitlines()[1:] if line.strip()]
    assert tuple(loaded) == EXPECTED_NFT_LISTING
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
        assert recorder.record(_outputs())
    finally:
        os.umask(previous)
    record = evidence_directory / EVIDENCE_NAME
    assert record.read_bytes() == GOLDEN
    assert record.stat().st_mode & 0o777 == 0o644
    assert sorted(os.listdir(evidence_directory)) == [EVIDENCE_NAME]
    err = capsys.readouterr().err
    assert "isolation check: nft_table pass" in err
    assert "10.255.196" not in err and "192.0.2" not in err


def test_a_record_with_a_failing_check_is_written_and_reported_as_not_passing(
        evidence_directory):
    recorder = _recorder(evidence_directory)
    assert recorder.prepare()
    assert not recorder.record(_outputs(nft=_with_element(NFT_LISTING)))
    evidence = parse_evidence((evidence_directory / EVIDENCE_NAME).read_bytes())
    assert evidence.not_passed == ("nft_table", "approved_v4_empty")


def test_prepare_removes_the_previous_record_and_a_leftover_temporary(evidence_directory):
    (evidence_directory / EVIDENCE_NAME).write_bytes(GOLDEN)
    (evidence_directory / ".isolation.json.new").write_bytes(b"partial")
    assert _recorder(evidence_directory).prepare()
    assert os.listdir(evidence_directory) == []


def test_without_a_boot_id_nothing_is_recorded(evidence_directory):
    recorder = _recorder(evidence_directory, boot=None)
    assert not recorder.prepare()
    assert not recorder.record(_outputs())
    assert os.listdir(evidence_directory) == []


def test_the_recorder_never_writes_through_a_link(evidence_directory, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    (evidence_directory / ".isolation.json.new").symlink_to(target)
    recorder = _recorder(evidence_directory)
    # The leftover link is removed (unlink does not follow it), then the record
    # is written fresh; the link's target is untouched.
    assert recorder.prepare()
    assert recorder.record(_outputs())
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
    assert not recorder.record(_outputs())


def test_withdraw_removes_the_record(evidence_directory):
    recorder = _recorder(evidence_directory)
    recorder.prepare()
    recorder.record(_outputs())
    assert recorder.withdraw()
    assert os.listdir(evidence_directory) == []


def test_what_the_recorder_writes_the_decoy_admits(evidence_directory, tmp_path, monkeypatch):
    recorder = _recorder(evidence_directory)
    recorder.prepare()
    assert recorder.record(_outputs())
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


@pytest.mark.parametrize("record", ["absent", "failing", "other-boot", "tampered"])
def test_the_decoy_refuses_before_any_socket_without_a_passing_record(
        tmp_path, monkeypatch, in_namespace, no_socket, capsys, record):
    data = {
        "failing": render_evidence(BOOT, WHEN, {**ALL_PASS, "bridge_ports": "fail"}),
        "other-boot": render_evidence(OTHER_BOOT, WHEN, dict(ALL_PASS)),
        "tampered": GOLDEN.replace(b",", b", ", 1),
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
    record.write_bytes(render_evidence(BOOT, WHEN, {**ALL_PASS, "bridge": "unreadable"}))
    reading = installed_isolation_reading(now=NOW)
    assert (reading.state, reading.not_passed) == (IsolationState.NOT_PASSED, ("bridge",))
    record.write_bytes(render_evidence(OTHER_BOOT, WHEN, dict(ALL_PASS)))
    assert installed_isolation_reading(now=NOW).state is IsolationState.NOT_THIS_BOOT
    record.write_bytes(GOLDEN[:-1])
    assert installed_isolation_reading(now=NOW).state is IsolationState.REFUSED
    record.write_bytes(GOLDEN)
    assert installed_isolation_reading(now="2026-10-22T02:00:00Z").state is IsolationState.REFUSED
    record.unlink()
    assert installed_isolation_reading(now=NOW).state is IsolationState.ABSENT


def test_a_passing_record_still_grants_no_exposure_unit(tmp_path, monkeypatch):
    """The tier stays withheld as `isolation_evidence_absent` (§14)."""

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
    assert all(not v.granted and v.reason.startswith("isolation_evidence_absent")
               for v in verdicts)
    assert not set(outcome.granted) & set(DECEPTION_EXPOSURE_UNITS)


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
    assert importers == ["decoy_netd.py"]
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
