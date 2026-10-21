"""#196 G1b: the helper's ruleset and plan from the exposure scope.

`docs/deception-exposure-grant.md` §4.3 (H3) and §4.4 items 1 to 3, and
`docs/deception-exposure-reachability.md` R3. The network helper reads the
closed scope file from its credential (`decoy_scope.read_scope_credential`),
renders one nftables transaction from it (`decoy_network.render_ruleset`),
and runs only the plan built from it (`decoy_network.helper_plan`): the
constant argument lists and exactly the one ruleset. These tests pin, with
fake commands (nothing here runs `ip` or `nft`):

* the rendering: the set's elements, the quoted `iifname`/`oifname` sets, the
  ingress drop (K2), the masquerade (A3), with one to four ingress
  interfaces and one to sixteen prefixes, and the table of the first build
  without a scope;
* what reaches the text: only `str(IPv4Network)` and the checked names;
  anything else is refused before a plan exists;
* the expected listing against the container's `nft -j` output;
* the plan: exactly one argument list differs from the plan without a
  scope; everything outside it is refused;
* the helper: its scope read first, a refused scope changing nothing, `stop`
  needing no scope, and its record carrying the scope's digest.

The container runs are mechanism checks (nftables 1.1.3, Debian 13), not
VM or hardware evidence.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re

import pytest

from azazel_nexus import decoy_scope
from azazel_nexus.decoy_isolation import NO_SCOPE, parse_evidence
from azazel_nexus.decoy_scope import DecoyScopeRefused, parse_scope_file
from azazel_nexus_runtime import decoy_netd, decoy_network
from azazel_nexus_runtime.decoy_isolation_check import Recorder, evaluate
from azazel_nexus_runtime.decoy_network import (
    HELPER_ABSENT,
    HELPER_PLAN,
    NFT,
    NFT_RULESET,
    helper_plan,
    render_ruleset,
)
from test_decoy_isolation_evidence import (
    HOST_LINKS,
    NFT_JSON,
    NFT_JSON_EMPTY,
    RULESET,
    SCOPE,
    SCOPE_BYTES,
    SCOPE_DIGEST,
)

BOOT = "0f4a6d2e-7c1b-4e5a-9d3c-2b8f1a6e4c70"
WHEN = "2026-10-22T03:00:00Z"
CONTRACT = "azazel-nexus/decoy-scope/v1"


def _scope(approved, ingress):
    """A scope file through the real decoder (so only what it accepts)."""

    data = (json.dumps({"approved_v4": list(approved), "contract": CONTRACT,
                        "ingress": list(ingress)}, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()
    return parse_scope_file(data)


class Shaped:
    """A scope-like object the decoder would never produce, for the renderer's own check."""

    def __init__(self, approved, ingress, digest=SCOPE_DIGEST):
        self.approved_v4, self.ingress, self.scope_digest = approved, ingress, digest


#: The text the helper loads for `SCOPE` (two ingress interfaces, three
#: prefixes, one of them a /32), as one argument.
SCOPE_RULESET = """create table inet azazel_decoy
table inet azazel_decoy {
\tset approved_v4 {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 10.20.0.0/24, 10.30.0.1/32, 192.168.10.0/24 }
\t}
\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tiifname { "eth9", "lan0" } oifname "az-decoy0" ip saddr @approved_v4 ip daddr 10.255.196.2 tcp dport { 2222, 2323, 8080 } accept
\t\toifname "az-decoy0" drop
\t\tiifname "az-decoy0" oifname { "eth9", "lan0" } ip saddr 10.255.196.2 ip daddr @approved_v4 tcp sport { 2222, 2323, 8080 } ct state established accept
\t\tiifname "az-decoy0" drop
\t\tiifname { "eth9", "lan0" } oifname != "az-decoy0" drop
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy accept;
\t\tiifname "az-decoy0" drop
\t}
\tchain output {
\t\ttype filter hook output priority filter; policy accept;
\t\toifname "az-decoy0" drop
\t}
\tchain postrouting {
\t\ttype nat hook postrouting priority srcnat; policy accept;
\t\toifname "az-decoy0" ip saddr @approved_v4 masquerade
\t}
}
"""

#: `nft -j list table` for `SCOPE` with only `eth9` as ingress, from the same
#: container run: nftables lists an anonymous set of one name as the name.
NFT_JSON_ONE_INGRESS = NFT_JSON.replace('{"set": ["lan0", "eth9"]}', '"eth9"')

#: `nft -j list set inet azazel_decoy approved_v4` with sixteen /24 prefixes,
#: from the same container run (the text listing wrapped them over eight
#: lines; the JSON form does not).
SET_JSON_16 = (
    '{"nftables": [{"metainfo": {"version": "1.1.3", "release_name": "Commodore Bullmoose #4", '
    '"json_schema_version": 1}}, {"set": {"family": "inet", "name": "approved_v4", "table": '
    '"azazel_decoy", "type": "ipv4_addr", "handle": 5, "flags": ["interval"], "elem": ['
    + ", ".join(f'{{"prefix": {{"addr": "10.40.{i}.0", "len": 24}}}}' for i in range(0, 32, 2))
    + ']}}]}'
)


# -- rendering -------------------------------------------------------------------


def test_the_scope_ruleset_is_the_golden():
    assert RULESET.text == SCOPE_RULESET
    assert RULESET.approved_v4 == ("10.20.0.0/24", "10.30.0.1/32", "192.168.10.0/24")
    assert RULESET.ingress == ("eth9", "lan0")
    assert RULESET.scope_digest == SCOPE_DIGEST
    # One transaction, never replacing a table: `create table` first.
    assert RULESET.text.splitlines()[0] == "create table inet azazel_decoy"
    assert "delete" not in RULESET.text and "flush" not in RULESET.text
    assert "add element" not in RULESET.text


def test_without_a_scope_the_table_of_the_first_build_is_kept():
    empty = render_ruleset(None)
    assert empty.text == NFT_RULESET
    assert (empty.approved_v4, empty.ingress, empty.scope_digest) == ((), (), None)
    for word in ("elements", "iifname {", "oifname {", "postrouting", "masquerade", "!="):
        assert word not in empty.text
    assert HELPER_PLAN.ruleset == empty


def test_each_part_the_scope_adds_is_where_the_design_puts_it():
    lines = [line.strip() for line in RULESET.text.splitlines()]
    forward = lines[lines.index("chain forward {") + 2:lines.index("chain input {") - 1]
    # Toward the decoy: only from an ingress interface (grant §4.4 item 1).
    assert forward[0].startswith('iifname { "eth9", "lan0" } oifname "az-decoy0" ')
    assert forward[0].endswith(" accept")
    # The reply: only out of an ingress interface (reachability R3).
    assert forward[2].startswith('iifname "az-decoy0" oifname { "eth9", "lan0" } ')
    assert "ct state established accept" in forward[2]
    # From an ingress to anywhere but the bridge: dropped (K2, R3), last.
    assert forward[4] == 'iifname { "eth9", "lan0" } oifname != "az-decoy0" drop'
    assert len(forward) == 5
    # Approved traffic into the bridge, masqueraded to its address (A3).
    assert lines[lines.index("chain postrouting {") + 1] == (
        "type nat hook postrouting priority srcnat; policy accept;")
    assert lines[lines.index("chain postrouting {") + 2] == (
        'oifname "az-decoy0" ip saddr @approved_v4 masquerade')
    # Nothing accepts anything the first build did not; every chain accepts by policy only.
    accepts = [line for line in lines if line.endswith(" accept") and "policy" not in line]
    assert len(accepts) == 2 and all("@approved_v4" in line for line in accepts)


@pytest.mark.parametrize("ingress", [
    ("eth9",), ("eth0", "eth1"), ("a", "b", "c"), ("en0", "eth0.100", "wan_1", "x-y")])
def test_every_name_is_quoted_and_appears_only_in_its_three_places(ingress):
    ruleset = render_ruleset(_scope(["10.20.0.0/24"], ingress))
    quoted = "{ " + ", ".join(f'"{name}"' for name in ingress) + " }"
    assert ruleset.text.count(quoted) == 3
    for name in ingress:
        # Never bare: every occurrence sits inside quotes.
        assert len(re.findall(rf'(?<!")\b{re.escape(name)}\b(?!")', ruleset.text)) == 0
        assert ruleset.text.count(f'"{name}"') == 3


def test_four_ingress_interfaces_and_sixteen_prefixes_are_the_bounds():
    prefixes = [f"10.40.{i}.0/24" for i in range(0, 32, 2)]
    ruleset = render_ruleset(_scope(prefixes, ["a0", "b0", "c0", "d0"]))
    [elements] = [line for line in ruleset.text.splitlines() if "elements" in line]
    assert elements == "\t\telements = { " + ", ".join(prefixes) + " }"
    assert ruleset.approved_v4 == tuple(prefixes)
    assert ruleset.text.count('{ "a0", "b0", "c0", "d0" }') == 3
    # The set as the container listed it (one line of JSON, sixteen elements).
    listed = json.loads(SET_JSON_16)["nftables"][1]["set"]
    listed.pop("handle")
    expected = next(o["set"] for o in json.loads(ruleset.expected) if "set" in o)
    assert listed == expected
    # One past each bound is refused, by the renderer as by the decoder.
    networks = tuple(ipaddress.IPv4Network(f"10.41.{i}.0/24") for i in range(0, 34, 2))
    with pytest.raises(ValueError):
        render_ruleset(Shaped(networks, ("a0",)))
    with pytest.raises(ValueError):
        render_ruleset(Shaped(networks[:1], ("a0", "b0", "c0", "d0", "e0")))
    with pytest.raises(DecoyScopeRefused):
        _scope([str(n) for n in networks], ["a0"])
    with pytest.raises(DecoyScopeRefused):
        _scope(["10.20.0.0/24"], ["a0", "b0", "c0", "d0", "e0"])


def test_the_bounds_are_the_decoders():
    assert decoy_network.MAX_PREFIXES == decoy_scope.MAX_PREFIXES == 16
    assert decoy_network.MAX_INGRESS == decoy_scope.MAX_INGRESS == 4


ONE = (ipaddress.IPv4Network("10.20.0.0/24"),)


@pytest.mark.parametrize("approved,ingress,digest", [
    ((), ("eth0",), SCOPE_DIGEST),                                   # no prefix
    (["10.20.0.0/24"], ("eth0",), SCOPE_DIGEST),                     # a list, not a tuple
    (("10.20.0.0/24",), ("eth0",), SCOPE_DIGEST),                    # a string, not a network
    ((ipaddress.IPv6Network("fd00::/64"),), ("eth0",), SCOPE_DIGEST),
    ((ipaddress.IPv4Network("10.20.1.0/24"), ipaddress.IPv4Network("10.20.0.0/24")),
     ("eth0",), SCOPE_DIGEST),                                       # unsorted
    ((ipaddress.IPv4Network("10.20.0.0/24"), ipaddress.IPv4Network("10.20.1.0/24")),
     ("eth0",), SCOPE_DIGEST),                                       # adjacent
    ((ipaddress.IPv4Network("10.20.0.0/16"), ipaddress.IPv4Network("10.20.1.0/24")),
     ("eth0",), SCOPE_DIGEST),                                       # overlapping
    (ONE, (), SCOPE_DIGEST),
    (ONE, ["eth0"], SCOPE_DIGEST),
    (ONE, ('eth0" accept',), SCOPE_DIGEST),                          # a quote
    (ONE, ("eth0 }",), SCOPE_DIGEST),
    (ONE, ("eth0;flush",), SCOPE_DIGEST),
    (ONE, ("a" * 16,), SCOPE_DIGEST),
    (ONE, ("AZ-DECOY0",), SCOPE_DIGEST),
    (ONE, ("lan0", "eth0"), SCOPE_DIGEST),                           # unsorted
    (ONE, ("eth0", "eth0"), SCOPE_DIGEST),
    (ONE, (b"eth0",), SCOPE_DIGEST),
    (ONE, ("eth0",), None),
    (ONE, ("eth0",), "sha256:" + "0" * 63),
    (ONE, ("eth0",), "10.20.0.0/24"),
])
def test_the_renderer_refuses_anything_but_a_checked_scope(approved, ingress, digest):
    with pytest.raises(ValueError) as caught:
        render_ruleset(Shaped(approved, ingress, digest))
    with pytest.raises(ValueError):
        helper_plan(Shaped(approved, ingress, digest))
    # A fixed phrase: no name or prefix in the message.
    assert "eth0" not in str(caught.value) and "10.20" not in str(caught.value)


def test_only_networks_and_checked_names_reach_the_text():
    """Everything in the text is the constant ruleset's, or a scope's own value."""

    ruleset = render_ruleset(_scope(["10.20.0.0/24", "192.168.1.128/25"], ["eth0", "lan0"]))
    text = ruleset.text
    for value in ("10.20.0.0/24", "192.168.1.128/25"):
        text = text.replace(value, "")
    for name in ("eth0", "lan0"):
        text = text.replace(f'"{name}"', "")
    constant = set(re.findall(r"[A-Za-z0-9_./@-]+", NFT_RULESET)) | {
        "elements", "postrouting", "nat", "srcnat", "masquerade", "!="}
    assert set(re.findall(r"[A-Za-z0-9_./@-]+", text)) <= constant


# -- the expected listing --------------------------------------------------------


def test_the_expected_listing_is_the_containers_with_handles_removed():
    listed = json.loads(NFT_JSON)["nftables"][1:]
    for item in listed:
        next(iter(item.values())).pop("handle")
    expected = json.loads(RULESET.expected)
    # Same objects in the same order, but the anonymous sets of names, which
    # nftables printed in an order of its own.
    assert [list(o) for o in listed] == [list(o) for o in expected]
    normalised = json.loads(json.dumps(listed).replace('["lan0", "eth9"]', '["eth9", "lan0"]'))
    assert normalised == expected


def test_one_ingress_interface_is_listed_as_the_name_and_passes():
    one = _scope(["10.20.0.0/24", "10.30.0.1/32", "192.168.10.0/24"], ["eth9"])
    ruleset = render_ruleset(one)
    assert ruleset.text.count('{ "eth9" }') == 3
    outputs = {"nft_table": (0, NFT_JSON_ONE_INGRESS.encode()),
               "host_links": (0, json.dumps(HOST_LINKS).encode())}
    assert set(evaluate(outputs, ruleset).values()) == {"pass"}
    # The two-name listing is not a pass for one name, nor the reverse.
    results = evaluate({**outputs, "nft_table": (0, NFT_JSON.encode())}, ruleset)
    assert results["ingress_matches"] == "fail" and results["nft_table"] == "fail"


# -- the plan --------------------------------------------------------------------


def test_the_plan_is_the_constants_plus_exactly_one_ruleset():
    plan = helper_plan(SCOPE)
    assert plan.ruleset == RULESET
    assert plan.allowed - HELPER_PLAN.allowed == {(NFT, RULESET.text)}
    assert HELPER_PLAN.allowed - plan.allowed == {(NFT, NFT_RULESET)}
    assert plan.read_back == HELPER_PLAN.read_back
    assert plan.absent == HELPER_ABSENT
    assert plan.steps[0].argv == (NFT, RULESET.text)
    assert [s.argv for s in plan.steps[1:]] == [s.argv for s in HELPER_PLAN.steps[1:]]
    assert [s.undo for s in plan.steps] == [s.undo for s in HELPER_PLAN.steps]


def test_run_fixed_refuses_every_ruleset_but_the_runs_own(monkeypatch):
    monkeypatch.setattr(decoy_network.os, "posix_spawn", lambda *a, **k: 4242)
    monkeypatch.setattr(decoy_network.os, "waitpid", lambda pid, flags: (pid, 0))
    plan = helper_plan(SCOPE)
    other = render_ruleset(_scope(["10.21.0.0/24"], ["eth9"]))
    assert decoy_network.run_fixed((NFT, RULESET.text), plan=plan) == 0
    for argv in ((NFT, NFT_RULESET), (NFT, other.text), (NFT, RULESET.text + "\n"),
                 (NFT, "-f", "/tmp/x"), (NFT, RULESET.text.replace("drop", "accept"))):
        with pytest.raises(ValueError):
            decoy_network.run_fixed(argv, plan=plan)
    with pytest.raises(ValueError):
        decoy_network.run_fixed((NFT, RULESET.text), plan=HELPER_PLAN)


def test_a_plan_cannot_be_widened_after_it_is_built():
    plan = helper_plan(SCOPE)
    with pytest.raises(AttributeError):
        plan.allowed = frozenset({("/bin/sh",)})  # type: ignore[misc]
    assert isinstance(plan.allowed, frozenset)


# -- the helper ------------------------------------------------------------------


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv):
        self.calls.append(argv)
        return 1 if argv in HELPER_ABSENT else 0


class Capture:
    def __init__(self, nft=NFT_JSON):
        self.nft = nft

    def __call__(self, argv):
        if argv[:2] == (NFT, "-j"):
            return 0, self.nft.encode()
        return 0, json.dumps(HOST_LINKS).encode()


@pytest.fixture
def evidence(tmp_path):
    directory = tmp_path / "azazel-decoy-isolation"
    directory.mkdir(mode=0o755)
    os.chmod(directory, 0o755)
    return directory


def _recorder(directory):
    return Recorder(directory=str(directory), owner=os.getuid(), boot_id=lambda: BOOT,
                    clock=lambda: WHEN)


def test_the_helper_loads_its_scopes_table_and_records_its_digest(monkeypatch, evidence):
    monkeypatch.setattr(decoy_netd, "read_scope_credential", lambda: SCOPE)
    run = Runner()
    assert decoy_netd.main([], run=run, capture=Capture(), recorder=_recorder(evidence)) == 0
    assert run.calls[2] == (NFT, RULESET.text)
    record = parse_evidence((evidence / "isolation.json").read_bytes())
    assert record.passed and record.scope_digest == SCOPE_DIGEST


def test_a_table_that_differs_from_the_scope_undoes_the_build(monkeypatch, evidence, capsys):
    monkeypatch.setattr(decoy_netd, "read_scope_credential", lambda: SCOPE)
    run = Runner()
    capture = Capture(NFT_JSON.replace('"10.30.0.1", ', ""))
    assert decoy_netd.main([], run=run, capture=capture, recorder=_recorder(evidence)) == 1
    assert run.calls[-1] == (NFT, "delete", "table", "inet", "azazel_decoy")
    err = capsys.readouterr().err
    assert "approved_v4_matches fail" in err
    for forbidden in ("10.20", "10.30", "192.168", "eth9", "lan0", "sha256"):
        assert forbidden not in err


def test_without_a_credential_directory_the_helper_has_no_scope(monkeypatch, tmp_path, evidence):
    monkeypatch.setattr(decoy_scope, "_PATH", str(tmp_path / "absent" / "decoy-scope"))
    assert decoy_scope.read_scope_credential() is None
    run = Runner()
    capture = Capture(NFT_JSON_EMPTY)
    assert decoy_netd.main([], run=run, capture=capture, recorder=_recorder(evidence)) == 0
    assert run.calls[2] == (NFT, NFT_RULESET)
    assert parse_evidence((evidence / "isolation.json").read_bytes()).scope_digest == NO_SCOPE


def _credential(tmp_path, monkeypatch, data):
    directory = tmp_path / "azazel-decoy-netd.service"
    directory.mkdir()
    path = directory / "decoy-scope"
    if data is not None:
        path.write_bytes(data)
        os.chmod(path, 0o400)
    os.chmod(directory, 0o500)
    monkeypatch.setattr(decoy_scope, "_PATH", str(path))
    monkeypatch.setattr(decoy_scope, "_OWNER", os.getuid())
    return directory


@pytest.fixture(autouse=True)
def _restore(tmp_path):
    yield
    for path in tmp_path.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)


def test_the_credential_is_read_from_its_fixed_path(tmp_path, monkeypatch):
    _credential(tmp_path, monkeypatch, SCOPE_BYTES)
    assert decoy_scope.read_scope_credential() == SCOPE
    plan = decoy_netd._start_plan()
    assert plan.ruleset == RULESET


@pytest.mark.parametrize("data", [None, b"", SCOPE_BYTES.replace(b"10.20.0.0/24", b"10.20.0.1/24"),
                                  SCOPE_BYTES[:-1], SCOPE_BYTES.replace(b"eth9", b"az-decoy9")])
def test_a_present_but_refused_scope_changes_nothing(tmp_path, monkeypatch, capsys, data):
    _credential(tmp_path, monkeypatch, data)
    with pytest.raises(DecoyScopeRefused):
        decoy_scope.read_scope_credential()

    class Untouched:
        def prepare(self):
            raise AssertionError("prepared after a refused scope")

    run = Runner()
    assert decoy_netd.main([], run=run, recorder=Untouched()) == 1
    assert run.calls == []
    err = capsys.readouterr().err
    assert "the decoy scope could not be read; nothing was changed" in err
    assert "eth9" not in err and "10.20" not in err


def test_a_linked_credential_directory_is_refused(tmp_path, monkeypatch):
    real = _credential(tmp_path, monkeypatch, SCOPE_BYTES)
    link = tmp_path / "linked"
    link.symlink_to(real)
    monkeypatch.setattr(decoy_scope, "_PATH", str(link / "decoy-scope"))
    with pytest.raises(DecoyScopeRefused):
        decoy_scope.read_scope_credential()


def test_a_scope_the_renderer_refuses_changes_nothing(monkeypatch):
    monkeypatch.setattr(decoy_netd, "read_scope_credential",
                        lambda: Shaped(ONE, ('eth0" accept',)))
    run = Runner()
    assert decoy_netd.main([], run=run) == 1
    assert run.calls == []


def test_stop_reads_no_scope(monkeypatch, evidence):
    def refuse():
        raise AssertionError("stop read the scope")

    monkeypatch.setattr(decoy_netd, "read_scope_credential", refuse)
    run = Runner()
    assert decoy_netd.main(["stop"], run=run, recorder=_recorder(evidence)) == 0
    assert run.calls[-1] == (NFT, "delete", "table", "inet", "azazel_decoy")
