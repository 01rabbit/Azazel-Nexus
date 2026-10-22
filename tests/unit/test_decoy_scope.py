"""#196 G1a: the Deception Lite exposure scope, decoded, rendered and read.

`docs/deception-exposure-grant.md` §4.1 to §4.3. Nothing here is wired into
the activation pass or the network helper: the tier stays withheld, and
these tests pin only the library's closed forms:

* the `deception_scope` section's strict decoder (§4.2): exactly three keys,
  one role, the fixed bridge prefix, 1 to 16 canonical, sorted, separate
  RFC 1918 prefixes clear of the decoy block, 1 to 4 `deception_bridge`
  interfaces holding no other role, and the re-rendering equal to the input;
* the rendered scope file (§4.3): its golden, its bound, the interface names
  allowed, and the refusal of every departure from its canonical bytes;
* the reader: the fixed credential path, no link, root's, nobody else may
  write, a regular file within the bound, `scope_digest` and nothing else;
* the boundary: a leaf of the standard library, under the helper's rules,
  equal to the runtime's decoy subnet, and no content in any refusal.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from ipaddress import IPv4Network
from pathlib import Path

import pytest

from azazel_nexus import activation, decoy_scope
from azazel_nexus.decoy_scope import (
    BRIDGE_PREFIX,
    CONTRACT,
    MAX_INGRESS,
    MAX_PREFIXES,
    MAX_SCOPE_BYTES,
    SCOPE_CREDENTIAL_PATH,
    DeceptionScope,
    DecoyScopeRefused,
    decode_deception_scope,
    parse_scope_file,
    read_scope_file,
    render_deception_scope,
    render_scope_file,
)
from azazel_nexus_runtime import decoy_addresses
from test_runtime_boundary import _helper_offences

REPO = Path(__file__).resolve().parents[2]
MODULE = REPO / "src" / "azazel_nexus" / "decoy_scope.py"

ROLES = (("if-a", "observation"), ("if-b", "deception_bridge"))
SECTION = {
    "approved_v4": ["10.20.0.0/24", "172.16.8.0/22", "192.168.10.0/24"],
    "bridge_prefix": "10.255.196.0/30",
    "ingress_role": "deception_bridge",
}
GOLDEN = (b'{"approved_v4":["10.20.0.0/24","172.16.8.0/22","192.168.10.0/24"],'
          b'"contract":"azazel-nexus/decoy-scope/v1","ingress":["enp3s0"]}\n')


def _section(**changes):
    section = json.loads(json.dumps(SECTION))
    section.update(changes)
    return section


def _scope():
    return decode_deception_scope(_section(), assignments=ROLES)


# -- the section's decoder (§4.2) ---------------------------------------------


def test_the_section_decodes_and_renders_back_to_itself():
    scope = _scope()
    assert scope.approved_v4 == tuple(IPv4Network(p) for p in SECTION["approved_v4"])
    assert scope.ingress_keys == ("if-b",)
    assert render_deception_scope(scope) == SECTION


def test_the_bridge_prefix_is_the_runtime_decoy_subnet():
    # The library does not import the runtime; the value is duplicated and pinned.
    assert BRIDGE_PREFIX == decoy_addresses.DECOY_SUBNET
    assert decoy_scope.RESERVED_HEADROOM == "10.255.196.0/24"
    assert IPv4Network(BRIDGE_PREFIX).subnet_of(IPv4Network(decoy_scope.RESERVED_HEADROOM))


@pytest.mark.parametrize("section", [
    None, [], "x", {},
    {k: v for k, v in SECTION.items() if k != "approved_v4"},
    {k: v for k, v in SECTION.items() if k != "bridge_prefix"},
    {k: v for k, v in SECTION.items() if k != "ingress_role"},
    {**SECTION, "ingress": ["eth0"]},
    {**SECTION, "approved_v6": []},
], ids=["none", "list", "str", "empty", "no-approved", "no-bridge", "no-role",
        "extra-ingress", "extra-v6"])
def test_a_section_without_exactly_the_three_keys_is_refused(section):
    with pytest.raises(DecoyScopeRefused):
        decode_deception_scope(section, assignments=ROLES)


@pytest.mark.parametrize("role", ["management", "observation", "Deception_bridge",
                                  "deception_bridge ", "", None, ["deception_bridge"]])
def test_another_ingress_role_is_refused(role):
    with pytest.raises(DecoyScopeRefused, match="ingress role"):
        decode_deception_scope(_section(ingress_role=role), assignments=ROLES)


@pytest.mark.parametrize("prefix", ["10.255.196.0/29", "10.255.196.4/30", "10.255.196.0/30 ",
                                    "10.255.196.000/30", "10.255.196.0/255.255.255.252",
                                    "192.168.1.0/30", "", None])
def test_the_bridge_prefix_is_confirmed_not_chosen(prefix):
    with pytest.raises(DecoyScopeRefused, match="bridge prefix"):
        decode_deception_scope(_section(bridge_prefix=prefix), assignments=ROLES)


@pytest.mark.parametrize("approved,why", [
    ([], "list of 1 to 16"),
    ("10.20.0.0/24", "list of 1 to 16"),
    ([f"10.{i}.0.0/16" for i in range(1, 2 + MAX_PREFIXES)][:MAX_PREFIXES + 1], "list of 1 to 16"),
    ([1], "not a string"),
    ([None], "not a string"),
    (["10.20.0.1/24"], "strict"),          # host bits
    (["10.20.0.0/33"], "strict"),
    (["10.20.0/24"], "strict"),
    (["fd00::/8"], "strict"),               # IPv6
    (["10.20.0.0"], "canonical"),           # no prefix length: /32 implied
    (["10.20.0.0/255.255.255.0"], "canonical"),
    (["010.20.0.0/24"], "strict"),
    ([" 10.20.0.0/24"], "strict"),
    (["10.20.0.0/24\n"], "strict"),
    (["１0.20.0.0/24"], "not a string"),     # non-ASCII digit
    (["8.8.8.0/24"], "RFC 1918"),           # public
    (["127.0.0.0/8"], "RFC 1918"),          # loopback
    (["169.254.0.0/16"], "RFC 1918"),       # link-local
    (["224.0.0.0/4"], "RFC 1918"),          # multicast
    (["0.0.0.0/8"], "RFC 1918"),
    (["255.255.255.255/32"], "RFC 1918"),   # broadcast
    (["100.64.0.0/10"], "RFC 1918"),        # shared address space
    (["192.0.2.0/24"], "RFC 1918"),         # documentation
    (["198.18.0.0/15"], "RFC 1918"),        # benchmarking
    (["240.0.0.0/4"], "RFC 1918"),          # reserved
    (["172.32.0.0/16"], "RFC 1918"),        # just outside 172.16/12
    (["192.169.0.0/16"], "RFC 1918"),
    (["172.0.0.0/8"], "RFC 1918"),          # holds 172.16/12 and more
    (["10.255.196.0/30"], "decoy network"),
    (["10.255.196.128/25"], "decoy network"),
    (["10.255.0.0/16"], "decoy network"),
    (["10.0.0.0/8"], "decoy network"),
    (["10.20.0.0/24", "10.20.0.0/24"], "sorted"),     # duplicate
    (["10.30.0.0/24", "10.20.0.0/24"], "sorted"),     # unsorted
    (["10.20.0.0/16", "10.20.5.0/24"], "sorted"),     # overlap
    (["10.20.0.0/24", "10.20.1.0/24"], "sorted"),     # adjacent
    (["10.20.0.0/24", "10.20.0.128/25"], "sorted"),
], ids=lambda value: value if isinstance(value, str) else None)
def test_each_departure_in_the_approved_prefixes_refuses_the_whole_section(approved, why):
    with pytest.raises(DecoyScopeRefused, match=why):
        decode_deception_scope(_section(approved_v4=approved), assignments=ROLES)


def test_the_bounds_and_the_gaps_that_are_allowed():
    sixteen = [f"10.{i}.0.0/16" for i in range(1, 1 + 2 * MAX_PREFIXES, 2)]
    assert len(decode_deception_scope(_section(approved_v4=sixteen),
                                      assignments=ROLES).approved_v4) == MAX_PREFIXES
    # One address apart is not adjacent; the whole of 172.16/12 and 192.168/16 is allowed.
    ok = ["10.20.0.0/24", "10.20.2.0/24", "172.16.0.0/12", "192.168.0.0/16"]
    assert decode_deception_scope(_section(approved_v4=ok), assignments=ROLES)
    assert decode_deception_scope(_section(approved_v4=["10.255.195.0/24", "10.255.197.0/24"]),
                                  assignments=ROLES)


@pytest.mark.parametrize("assignments,why", [
    ((("if-a", "observation"),), "not 1 to 4"),
    ((), "not 1 to 4"),
    (tuple((f"if-{i}", "deception_bridge") for i in range(MAX_INGRESS + 1)), "not 1 to 4"),
    ((("if-b", "deception_bridge"), ("if-b", "management")), "more than one role"),
    ((("if-b", "deception_bridge"), ("if-b", "deception_bridge")), "more than one role"),
    ((("if-b", "observation"), ("if-b", "deception_bridge")), "more than one role"),
    ((("if-b",),), "could not be read"),
    ((["if-b", "deception_bridge"],), "could not be read"),
    ((("", "deception_bridge"),), "could not be read"),
    ((("if-b", None),), "could not be read"),
    ("if-b", "could not be read"),
    (None, "could not be read"),
])
def test_the_ingress_interfaces_are_one_to_four_holding_no_other_role(assignments, why):
    with pytest.raises(DecoyScopeRefused, match=why):
        decode_deception_scope(_section(), assignments=assignments)


def test_four_bridge_interfaces_are_allowed_and_sorted():
    roles = (("if-d", "deception_bridge"), ("if-a", "management"), ("if-c", "deception_bridge"),
             ("if-b", "deception_bridge"), ("if-e", "deception_bridge"))
    assert decode_deception_scope(_section(), assignments=roles).ingress_keys == (
        "if-b", "if-c", "if-d", "if-e")


def test_a_value_of_another_json_type_never_renders_equal():
    # `True == 1` in Python; the canonical bytes are compared, not values.
    with pytest.raises(DecoyScopeRefused):
        decode_deception_scope(_section(ingress_role=True), assignments=ROLES)
    with pytest.raises(DecoyScopeRefused):
        decode_deception_scope(_section(approved_v4=[True]), assignments=ROLES)
    for value in (False, float("nan"), float("inf"), 10.0, ["10.20.0.0/24"]):
        with pytest.raises(DecoyScopeRefused):
            decode_deception_scope(_section(approved_v4=[value]), assignments=ROLES)
        with pytest.raises(DecoyScopeRefused):
            decode_deception_scope(_section(approved_v4=["10.20.0.0/24", value]),
                                   assignments=ROLES)
    for key in ("bridge_prefix", "ingress_role"):
        for value in (True, float("nan")):
            with pytest.raises(DecoyScopeRefused):
                decode_deception_scope(_section(**{key: value}), assignments=ROLES)
    with pytest.raises(DecoyScopeRefused):
        decode_deception_scope(_section(), assignments=((True, "deception_bridge"),))


@pytest.mark.parametrize("data", [
    GOLDEN.replace(b'["enp3s0"]', b"[NaN]"),
    GOLDEN.replace(b'["enp3s0"]', b"[true]"),
    GOLDEN.replace(b'"10.20.0.0/24"', b"NaN"),
    GOLDEN.replace(b'"10.20.0.0/24"', b"false"),
    GOLDEN.replace(b'"10.20.0.0/24"', b"Infinity"),
    GOLDEN.replace(b'"azazel-nexus/decoy-scope/v1"', b"NaN"),
    GOLDEN.replace(b'"azazel-nexus/decoy-scope/v1"', b"true"),
], ids=["ingress-nan", "ingress-true", "prefix-nan", "prefix-false", "prefix-inf",
        "contract-nan", "contract-true"])
def test_a_bool_or_nan_in_the_file_is_refused(data):
    with pytest.raises(DecoyScopeRefused):
        parse_scope_file(data)


def test_render_takes_only_a_decoded_scope():
    for value in (SECTION, None, (IPv4Network("10.20.0.0/24"),)):
        with pytest.raises(DecoyScopeRefused):
            render_deception_scope(value)
        with pytest.raises(DecoyScopeRefused):
            render_scope_file(value, ["enp3s0"])


# -- the rendered file (§4.3) --------------------------------------------------


def test_the_scope_file_is_the_golden():
    assert render_scope_file(_scope(), ["enp3s0"]) == GOLDEN
    assert render_scope_file(_scope(), ("enp3s0",)) == GOLDEN
    parsed = parse_scope_file(GOLDEN)
    assert parsed.approved_v4 == _scope().approved_v4
    assert parsed.ingress == ("enp3s0",)
    assert parsed.scope_digest == "sha256:" + hashlib.sha256(GOLDEN).hexdigest()
    assert json.loads(GOLDEN)["contract"] == CONTRACT == "azazel-nexus/decoy-scope/v1"


@pytest.mark.parametrize("names", [
    [], ["a", "b", "c", "d", "e"], ["az-decoy0"], ["az-decoy-host0"], ["az-decoyX"],
    ["a" * 16], [""], ["eth 0"], ["eth0;"], ["eth/0"], ["eth:0"], ["ëth0"], ["eth0\n"],
    ["."], [".."], ["eth1", "eth0"], ["eth0", "eth0"], [1], [None], "eth0",
    # Reserved names, in any case (loopback; `/proc/sys/net/ipv4/conf/{all,default}`).
    ["lo"], ["LO"], ["Lo"], ["all"], ["ALL"], ["default"], ["Default"],
    # The decoy's own prefix in any case.
    ["AZ-DECOY0"], ["Az-Decoy-x"], ["az-DECOY"],
    # A leading dash (an option to `nft`/`ip`), and all digits (an interface index).
    ["-eth0"], ["-"], ["--"], ["0"], ["7"], ["123456789012345"],
    # Other JSON types.
    [True], [False], [float("nan")], [1.0], [["eth0"]], [{"eth0": 1}],
], ids=repr)
def test_an_ingress_name_outside_the_allowed_form_is_refused(names):
    roles = tuple((f"if-{i}", "deception_bridge") for i in range(max(1, min(len(names), 4))))
    if isinstance(names, list) and len(names) <= 4:
        scope = decode_deception_scope(_section(), assignments=roles)
    else:
        scope = _scope()
    with pytest.raises(DecoyScopeRefused):
        render_scope_file(scope, names)


def test_allowed_names_and_the_count_must_match_the_confirmed_interfaces():
    roles = tuple((f"if-{i}", "deception_bridge") for i in range(4))
    scope = decode_deception_scope(_section(), assignments=roles)
    names = ["a" * 15, "az-decoz", "br-lan.10", "enp3s0_1"]
    assert parse_scope_file(render_scope_file(scope, ["0eth", "all0", "eth-", "lo0"])).ingress
    assert parse_scope_file(render_scope_file(scope, ["1.2", "10_0", "a.", "lan."])).ingress
    assert parse_scope_file(render_scope_file(scope, names)).ingress == tuple(names)
    with pytest.raises(DecoyScopeRefused, match="do not match"):
        render_scope_file(scope, ["enp3s0"])
    with pytest.raises(DecoyScopeRefused, match="do not match"):
        render_scope_file(_scope(), ["enp3s0", "enp4s0"])


def test_the_largest_scope_file_fits_its_bound():
    sixteen = [f"10.{i}.0.0/16" for i in range(1, 1 + 2 * MAX_PREFIXES, 2)]
    roles = tuple((f"if-{i}", "deception_bridge") for i in range(4))
    scope = decode_deception_scope(_section(approved_v4=sixteen), assignments=roles)
    data = render_scope_file(scope, ["a" * 15, "b" * 15, "c" * 15, "d" * 15])
    assert len(data) <= MAX_SCOPE_BYTES
    assert parse_scope_file(data).ingress[0] == "a" * 15


def _mutated(**changes):
    document = json.loads(GOLDEN)
    document.update(changes)
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("data", [
    GOLDEN[:-1],                                        # no newline
    GOLDEN + b"\n",
    GOLDEN.replace(b",", b", ", 1),                     # whitespace
    b" " + GOLDEN,
    GOLDEN.replace(b'"approved_v4"', b'"\\u0061pproved_v4"'),  # escape
    (b'{"contract":"azazel-nexus/decoy-scope/v1","approved_v4":'
     b'["10.20.0.0/24","172.16.8.0/22","192.168.10.0/24"],"ingress":["enp3s0"]}\n'),  # order
    GOLDEN.replace(b'"ingress"', b'"ingress":["x"],"ingress"'),  # duplicate key
    _mutated(contract="azazel-nexus/decoy-scope/v2"),
    _mutated(contract=None),
    _mutated(extra=1),
    _mutated(ingress=[]),
    _mutated(ingress=["az-decoy0"]),
    _mutated(ingress=["enp3s0", "enp3s0"]),
    _mutated(approved_v4=[]),
    _mutated(approved_v4=["8.8.8.0/24"]),
    _mutated(approved_v4=["10.255.196.0/30"]),
    _mutated(approved_v4=["10.20.0.0/24", "10.20.1.0/24"]),
    _mutated(approved_v4=["10.20.0.1/24"]),
    b"",
    b"[]\n",
    b"null\n",
    "{}".encode() + b"\n",
    GOLDEN.replace(b"enp3s0", "enp3sé".encode()),     # not ASCII
    b"[" * 100000,
    b"x" * (MAX_SCOPE_BYTES + 1),
    "not bytes",
], ids=lambda value: None)
def test_every_departure_from_the_canonical_file_is_refused(data):
    with pytest.raises(DecoyScopeRefused):
        parse_scope_file(data)


# -- the reader ---------------------------------------------------------------


def _install(tmp_path, monkeypatch, data=GOLDEN, *, mode=0o400, directory_mode=0o500):
    directory = tmp_path / "azazel-decoy-netd.service"
    directory.mkdir()
    path = directory / "decoy-scope"
    if data is not None:
        path.write_bytes(data)
        os.chmod(path, mode)
    os.chmod(directory, directory_mode)
    monkeypatch.setattr(decoy_scope, "_PATH", str(path))
    monkeypatch.setattr(decoy_scope, "_OWNER", os.getuid())
    return directory, path


@pytest.fixture(autouse=True)
def _restore_modes(tmp_path):
    yield
    for path in tmp_path.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)


def test_the_reader_reads_the_fixed_path_and_returns_the_digest(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    scope = read_scope_file()
    assert scope.scope_digest == "sha256:" + hashlib.sha256(GOLDEN).hexdigest()
    assert scope.ingress == ("enp3s0",) and len(scope.approved_v4) == 3


def test_the_production_path_and_owner():
    assert SCOPE_CREDENTIAL_PATH == "/run/credentials/azazel-decoy-netd.service/decoy-scope"
    assert decoy_scope._PATH == SCOPE_CREDENTIAL_PATH
    assert decoy_scope._OWNER == 0
    assert read_scope_file.__code__.co_argcount == 0
    assert read_scope_file.__code__.co_kwonlyargcount == 0


def test_an_absent_scope_refuses(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch, data=None)
    with pytest.raises(DecoyScopeRefused, match="could not be opened"):
        read_scope_file()
    monkeypatch.setattr(decoy_scope, "_PATH", str(tmp_path / "absent" / "decoy-scope"))
    with pytest.raises(DecoyScopeRefused, match="directory could not be opened"):
        read_scope_file()


def test_a_symlinked_file_or_directory_refuses(tmp_path, monkeypatch):
    directory, path = _install(tmp_path, monkeypatch)
    os.chmod(directory, 0o700)
    target = tmp_path / "elsewhere"
    target.write_bytes(GOLDEN)
    os.chmod(target, 0o400)
    path.unlink()
    path.symlink_to(target)
    with pytest.raises(DecoyScopeRefused, match="could not be opened"):
        read_scope_file()
    linked = tmp_path / "linked"
    linked.symlink_to(directory)
    monkeypatch.setattr(decoy_scope, "_PATH", str(linked / "decoy-scope"))
    with pytest.raises(DecoyScopeRefused, match="directory could not be opened"):
        read_scope_file()


@pytest.mark.parametrize("mode,directory_mode,why", [
    (0o420, 0o500, "unsafe"), (0o402, 0o500, "unsafe"), (0o600, 0o500, None),
    (0o400, 0o520, "unsafe"), (0o400, 0o502, "unsafe"), (0o444, 0o555, None),
])
def test_the_file_and_directory_may_be_written_by_nobody_else(tmp_path, monkeypatch,
                                                              mode, directory_mode, why):
    _install(tmp_path, monkeypatch, mode=mode, directory_mode=directory_mode)
    if why is None:
        assert read_scope_file().scope_digest.startswith("sha256:")
    else:
        with pytest.raises(DecoyScopeRefused, match=why):
            read_scope_file()


def test_a_hard_linked_file_refuses(tmp_path, monkeypatch):
    directory, path = _install(tmp_path, monkeypatch, directory_mode=0o700)
    os.link(path, tmp_path / "second-name")
    with pytest.raises(DecoyScopeRefused, match="another link"):
        read_scope_file()


def test_an_unreadable_directory_status_is_a_refusal(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    real = os.fstat
    calls = []

    def failing(fd):
        calls.append(fd)
        if len(calls) == 1:
            raise OSError(5, "I/O error")
        return real(fd)

    monkeypatch.setattr(decoy_scope.os, "fstat", failing)
    with pytest.raises(DecoyScopeRefused, match="directory could not be read") as caught:
        read_scope_file()
    assert caught.value.__cause__ is None and calls


def test_another_owner_refuses(tmp_path, monkeypatch):
    _install(tmp_path, monkeypatch)
    monkeypatch.setattr(decoy_scope, "_OWNER", os.getuid() + 1)
    with pytest.raises(DecoyScopeRefused, match="unsafe"):
        read_scope_file()


def test_a_directory_or_fifo_in_place_of_the_file_refuses(tmp_path, monkeypatch):
    directory, path = _install(tmp_path, monkeypatch, data=None, directory_mode=0o700)
    os.mkfifo(path, 0o400)
    with pytest.raises(DecoyScopeRefused, match="unsafe"):
        read_scope_file()
    path.unlink()
    path.mkdir(mode=0o500)
    with pytest.raises(DecoyScopeRefused):
        read_scope_file()


def test_an_oversized_or_tampered_file_refuses(tmp_path, monkeypatch):
    directory, path = _install(tmp_path, monkeypatch, data=GOLDEN + b" " * MAX_SCOPE_BYTES,
                               directory_mode=0o700)
    with pytest.raises(DecoyScopeRefused, match="larger"):
        read_scope_file()
    os.chmod(path, 0o600)
    path.write_bytes(GOLDEN.replace(b'"enp3s0"]', b'"enp3s0" ]'))
    with pytest.raises(DecoyScopeRefused, match="canonical"):
        read_scope_file()


# -- no content in messages, and nothing wired ----------------------------------


def test_no_refusal_carries_a_prefix_or_a_name():
    secret_prefix, secret_name = "10.77.0.0/24", "secretlan0"
    cases = [
        lambda: decode_deception_scope(_section(approved_v4=["8.8.8.0/24", secret_prefix]),
                                       assignments=ROLES),
        lambda: decode_deception_scope(_section(approved_v4=[secret_prefix + "x"]),
                                       assignments=ROLES),
        lambda: render_scope_file(_scope(), [secret_name + "toolong!"]),
        lambda: parse_scope_file(_mutated(ingress=["az-decoy" + secret_name])),
        lambda: parse_scope_file(_mutated(approved_v4=["10.77.0.1/24"])),
    ]
    for case in cases:
        with pytest.raises(DecoyScopeRefused) as caught:
            case()
        text = str(caught.value)
        assert "10.77" not in text and "secret" not in text and "8.8.8" not in text
        assert caught.value.__cause__ is None


def test_the_scope_types_hold_no_raw_identity():
    assert set(DeceptionScope.__dataclass_fields__) == {"approved_v4", "ingress_keys"}
    assert set(decoy_scope.ScopeFile.__dataclass_fields__) == {
        "approved_v4", "ingress", "scope_digest"}


def _importers(root):
    found = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                 for alias in node.names}
        names |= {node.module or "" for node in ast.walk(tree)
                  if isinstance(node, ast.ImportFrom)}
        if any(name.split(".")[-1] == "decoy_scope" for name in names):
            found.append(path.name)
    return found


def test_only_the_helper_reads_the_scope_and_the_pass_does_not_yet():
    """G1b wired the helper and G2 the verify unit (the helper's executable,
    `decoy_watch`); the pass is G6. #196 G6 preparation A: the shared
    reachability reads take only the interface-name rule from it
    (`interface_name_allowed`), and nothing on the pass imports them."""

    runtime = REPO / "runtime" / "src" / "azazel_nexus_runtime"
    assert _importers(runtime) == ["decoy_netd.py", "decoy_reachability.py",
                                   "decoy_watch.py"]
    reachability = (runtime / "decoy_reachability.py").read_text(encoding="utf-8")
    assert ("from azazel_nexus.decoy_scope import MAX_INGRESS, interface_name_allowed"
            in reachability)
    for name in ("activation_pass.py", "activation_markers.py", "activated.py"):
        path = runtime / name
        if path.is_file():
            assert "decoy_scope" not in path.read_text(encoding="utf-8"), name
    library = REPO / "src" / "azazel_nexus"
    assert _importers(library) == ["commissioning_approval.py", "fabric_boundary.py"]
    assert "decoy_scope" not in (library / "activation.py").read_text(encoding="utf-8")
    assert activation  # the withhold itself is pinned by test_decoy_isolation_evidence


# -- the boundary ---------------------------------------------------------------


def test_the_module_is_a_standard_library_leaf():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {("." * node.level) + (node.module or "") for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom)}
    assert imported == {"__future__", "hashlib", "ipaddress", "json", "os", "re", "stat",
                        "dataclasses", "typing"}


def test_importing_it_loads_no_other_module_of_either_package():
    code = (f"import sys; sys.path[:0] = {[str(REPO / 'src'), str(REPO / 'runtime' / 'src')]!r}; "
            "import azazel_nexus.decoy_scope; "
            "print(sorted(m for m in sys.modules if m.startswith('azazel')))")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True,
                            text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    assert ast.literal_eval(result.stdout.strip()) == ["azazel_nexus", "azazel_nexus.decoy_scope"]


def test_the_module_obeys_the_helpers_boundary_rules():
    """The helper will load it (G1b); it must pass the rules every helper module does."""

    assert _helper_offences(MODULE) == []
    source = MODULE.read_text(encoding="utf-8")
    for name in ("open(", "Path(", "environ", "argv"):
        if name == "open(":
            assert source.count("os.open(") == source.count("open(")
        else:
            assert name not in source
