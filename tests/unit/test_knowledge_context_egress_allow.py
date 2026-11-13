"""The contextd egress allowance (U49): derivation, renderer, pass checks, CLI."""

import hashlib
import ipaddress
import os
import sys
from pathlib import Path

import pytest
from nacl.signing import SigningKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "src"))
sys.path.insert(0, str(ROOT / "tests" / "real_process"))
sys.path.insert(0, str(ROOT / "tests" / "fixtures"))

from _knowledge_context_bundle_fixture import build_bundle  # noqa: E402
from azazel_nexus_runtime import (  # noqa: E402
    activation_loaded_units as loaded_units,
    activation_unit_files as unit_files,
    hardening,
    knowledge_context_config as cfg,
    knowledge_context_egress as egress,
    knowledge_context_egress_cli as cli,
    knowledge_egress,
    runtime_paths,
    systemd_bus,
)
from azazel_nexus_runtime.hardening import PROFILES, contextd_egress_line, render_unit  # noqa: E402
from tls.pins import PINS  # noqa: E402

TLS = ROOT / "tests" / "fixtures" / "tls"
NOW = "2026-11-10T00:00:00+00:00"
CONTEXTD = "azazel-knowledge-contextd.service"
PROFILE = next(p for p in PROFILES if p.unit == CONTEXTD)


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid())
    monkeypatch.setattr(unit_files, "derived_egress_allowance",
                        lambda: egress.derive_allowance(now=NOW))
    return tmp_path


def build(root, address="192.0.2.10", host="fetch.azazel.test", pin="server-fetch", **kw):
    return build_bundle(
        root / "etc/azazel/knowledge-context/commissioning", peer_id="az04-test",
        peer_address=address, peer_host=host, peer_port=443,
        certificate_pin=PINS[pin],
        peer_signing_key=SigningKey(bytes(range(32, 64))),
        registry_signing_key=SigningKey(bytes(range(32))),
        ca=TLS / "trusted-ca.crt", client_cert=TLS / "client.crt",
        client_key=TLS / "client.key", **kw)


def allowance(root, **kw):
    build(root, **kw)
    return egress.derive_allowance(now=NOW)


# -- derivation --------------------------------------------------------------

def test_derivation_uses_addresses_zero_as_slash_32(root):
    a = allowance(root)
    assert a.line == "IPAddressAllow=192.0.2.10/32"
    assert a.address == knowledge_egress.egress_address(
        cfg.load_commissioning(now=NOW).peer)
    assert a.peer_id == "az04-test" and a.port == 443 and a.registry_version >= 1
    assert a.digest.startswith("sha256:") and len(a.digest) == 71


def test_ipv6_is_slash_128(root):
    assert allowance(root, address="2001:db8::10").line == "IPAddressAllow=2001:db8::10/128"


def test_digest_covers_address_pin_host_and_version(root):
    base = allowance(root)
    assert allowance(root, address="192.0.2.11").digest != base.digest
    assert allowance(root, host="other.azazel.test").digest != base.digest


@pytest.mark.parametrize("address", [
    "0.0.0.0", "127.0.0.1", "224.0.0.1", "169.254.1.1", "::", "::1", "ff02::1",
    "fe80::1", "::ffff:192.0.2.1", "240.0.0.1",
])
def test_unusable_addresses_derive_nothing(root, address):
    build(root, address=address)
    assert egress.derive_allowance(now=NOW) is None


def test_no_bundle_expired_and_disabled_derive_nothing(root):
    assert egress.derive_allowance(now=NOW) is None
    for defect in ("expired_registry", "enabled_false", "bad_signature", "wrong_identity"):
        build(root, defect=defect)
        assert egress.derive_allowance(now=NOW) is None, defect
        import shutil
        shutil.rmtree(root / "etc")


@pytest.mark.parametrize("bad", [
    "192.0.2.10/32", "192.0.2.10/24", "192.000.002.010", " 192.0.2.10", "192.0.2.10\n",
    "IPAddressAllow=1.2.3.4", "1.2.3.4 5.6.7.8", "", "any", "localhost", "::ffff:1.2.3.4",
    "2001:DB8::1", 5, None,
])
def test_line_validator_refuses(bad):
    with pytest.raises(ValueError):
        contextd_egress_line(bad)


def test_client_and_renderer_share_the_address_function():
    import inspect
    assert "egress_address(peer)" in inspect.getsource(knowledge_egress.KnowledgeClient._post_path)
    assert "egress_address" in inspect.getsource(egress)


# -- renderer ----------------------------------------------------------------

DIGEST = "sha256:" + "a" * 64


def test_default_render_has_no_allow_and_matches_packaged_file():
    text = render_unit(PROFILE)
    assert not any(l.startswith("IPAddressAllow") for l in text.split("\n")) and "IPAddressDeny=any" in text
    assert text == (ROOT / "packaging/systemd" / CONTEXTD).read_text()


def test_render_adds_exactly_one_line_after_deny_and_the_digest():
    text = render_unit(PROFILE, egress_allow="192.0.2.10", egress_digest=DIGEST)
    lines = text.split("\n")
    i = lines.index("IPAddressDeny=any")
    assert lines[i + 1] == "IPAddressAllow=192.0.2.10/32"
    assert sum(l.startswith("IPAddressAllow") for l in lines) == 1
    assert "# Egress allowance digest: " + DIGEST in lines
    base = render_unit(PROFILE).split("\n")
    added = [l for l in lines if l not in base]
    assert sorted(added) == sorted(["IPAddressAllow=192.0.2.10/32",
                                    "# Egress allowance digest: " + DIGEST])
    assert render_unit(PROFILE, egress_allow="192.0.2.10", egress_digest=DIGEST) == text


@pytest.mark.parametrize("kw", [
    {"egress_allow": "192.0.2.10"}, {"egress_digest": DIGEST},
    {"egress_allow": "192.0.2.10/32", "egress_digest": DIGEST},
    {"egress_allow": "192.0.2.10", "egress_digest": "sha256:zz"},
    {"egress_allow": "192.0.2.10\nExecStart=/bin/sh", "egress_digest": DIGEST},
])
def test_render_refuses_bad_inputs(kw):
    with pytest.raises(ValueError):
        render_unit(PROFILE, **kw)


def test_other_profiles_take_no_allowance():
    other = next(p for p in PROFILES if p.unit != CONTEXTD)
    with pytest.raises(ValueError):
        render_unit(other, egress_allow="192.0.2.10", egress_digest=DIGEST)


def test_extra_cannot_carry_ipaddressallow():
    import dataclasses
    with pytest.raises(ValueError):
        dataclasses.replace(PROFILE, extra=PROFILE.extra + (("IPAddressAllow", "1.2.3.4"),))


# -- pass: unit content ------------------------------------------------------

def _good(root):
    a = allowance(root)
    return a, unit_files.rendered_unit(CONTEXTD, allowance=a).encode()


def test_content_accepts_default_deny_and_exact_derived(root):
    a, data = _good(root)
    unit_files.require_governed_unit_content(CONTEXTD, data)
    unit_files.require_governed_unit_content(CONTEXTD, unit_files.rendered_unit(CONTEXTD).encode())


def _refused(data):
    with pytest.raises(unit_files.UnitContentRefused):
        unit_files.require_governed_unit_content(CONTEXTD, data)


def test_content_refuses_wider_or_other_allow(root):
    a, data = _good(root)
    text = data.decode()
    _refused(text.replace("192.0.2.10/32", "192.0.2.10/24").encode())
    _refused(text.replace("192.0.2.10/32", "192.0.2.11/32").encode())
    _refused(text.replace("IPAddressAllow=192.0.2.10/32\n",
                          "IPAddressAllow=192.0.2.10/32\nIPAddressAllow=any\n").encode())
    _refused(text.replace("IPAddressDeny=any\n", "IPAddressDeny=\n").encode())
    _refused(text.replace("IPAddressDeny=any\n", "IPAddressDeny=any\nIPAddressDeny=any\n").encode())
    _refused(text.replace("IPAddressDeny=any\n", "").encode())


def test_content_refuses_changed_digest_and_orphan_digest(root):
    a, data = _good(root)
    _refused(data.decode().replace(a.digest, "sha256:" + "0" * 64).encode())
    _refused(data.decode().replace("IPAddressAllow=192.0.2.10/32\n", "").encode())


def test_same_ip_new_host_pin_or_version_requires_regeneration(root):
    a, data = _good(root)
    import shutil
    shutil.rmtree(root / "etc")
    build(root, host="other.azazel.test")
    _refused(data)  # the installed unit carries the old digest
    shutil.rmtree(root / "etc")
    other = [name for name in PINS if name != "server-fetch"]
    if other:
        build(root, pin=other[0])
        _refused(data)  # a different pin at the same IP is a different digest


def test_allow_is_refused_without_a_derivation(root):
    a, data = _good(root)
    import shutil
    shutil.rmtree(root / "etc")
    _refused(data)


def test_other_units_may_not_gain_an_allow():
    other = next(p for p in PROFILES if p.unit != CONTEXTD and p.unit in unit_files.MARKER_GUARDED_UNITS
                 and p.unit not in unit_files.EXPOSURE_UNITS)
    text = render_unit(other).replace("IPAddressDeny=any\n", "IPAddressDeny=any\nIPAddressAllow=192.0.2.10/32\n")
    with pytest.raises(unit_files.UnitContentRefused):
        unit_files.require_governed_unit_content(other.unit, text.encode())


def test_generation_hash_changes_with_the_allowance(root):
    a, data = _good(root)
    default = unit_files.rendered_unit(CONTEXTD).encode()
    assert hashlib.sha256(data).digest() != hashlib.sha256(default).digest()
    build_dir_text = unit_files.rendered_unit(
        CONTEXTD, allowance=egress.EgressAllowance(**{**a.__dict__, "digest": "sha256:" + "1" * 64}))
    assert build_dir_text.encode() != data


# -- pass: loaded properties -------------------------------------------------

DENY = [(2, bytes(4), 0), (10, bytes(16), 0)]


def _loaded(allow, deny=DENY):
    return {"Id": CONTEXTD, "LoadState": "loaded",
            "FragmentPath": f"/usr/lib/systemd/system/{CONTEXTD}", "DropInPaths": [],
            "Conditions": [], "Asserts": [], "Requires": ["azazel-activated.service"],
            "After": ["azazel-activated.service"],
            "IPAddressAllow": allow, "IPAddressDeny": deny,
            "SliceChainAllow": {"system.slice": [], "-.slice": []}}


def _check(loaded, monkeypatch, file_value):
    """`file_value`: the IPAddressAllow entries of the measured unit file."""
    monkeypatch.setattr(loaded_units, "file_allow", lambda unit: file_value)
    monkeypatch.setattr(loaded_units, "expected_loaded_guards", lambda unit: ([], []))
    loaded_units._check_loaded(CONTEXTD, loaded)


IP = (2, bytes([192, 0, 2, 10]), 32)


def test_loaded_must_equal_the_file_exactly(monkeypatch):
    _check(_loaded([]), monkeypatch, [])
    _check(_loaded([IP]), monkeypatch, [IP])


@pytest.mark.parametrize("allow,file_value", [
    ([IP], []),            # file has no Allow: loaded must be empty
    ([], [IP]),            # file has the Allow: loaded must carry it
    ([(2, bytes([192, 0, 2, 10]), 24)], [IP]), ([(2, bytes([192, 0, 2, 11]), 32)], [IP]),
    ([(2, bytes(4), 0)], [IP]), ([(10, bytes(16), 0)], []),
    ([IP, (2, bytes([192, 0, 2, 11]), 32)], [IP]),
])
def test_loaded_differing_from_file_refuses(monkeypatch, allow, file_value):
    with pytest.raises(loaded_units.LoadedUnitRefused):
        _check(_loaded(allow), monkeypatch, file_value)


@pytest.mark.parametrize("chain", [
    {"system.slice": [(2, bytes(4), 0)], "-.slice": []},
    {"system.slice": [], "-.slice": [(10, bytes(16), 0)]},
    {"system.slice": [IP], "-.slice": []}, {}, None,
])
def test_loaded_parent_slice_allow_refuses(monkeypatch, chain):
    loaded = _loaded([])
    loaded["SliceChainAllow"] = chain
    with pytest.raises(loaded_units.LoadedUnitRefused):
        _check(loaded, monkeypatch, [])


@pytest.mark.parametrize("deny", [[], [(2, bytes(4), 0)], [(2, bytes(4), 8), (10, bytes(16), 0)]])
def test_loaded_weaker_deny_refuses(monkeypatch, deny):
    with pytest.raises(loaded_units.LoadedUnitRefused):
        _check(_loaded([], deny), monkeypatch, [])


def test_loaded_missing_filter_refuses(monkeypatch):
    loaded = _loaded([])
    del loaded["IPAddressAllow"]
    with pytest.raises(loaded_units.LoadedUnitRefused):
        _check(loaded, monkeypatch, [])


def test_file_allow_reads_the_measured_bytes(root, monkeypatch):
    unit_dir = root / "usr/lib/systemd/system"
    unit_dir.mkdir(parents=True)
    for p in (root, root / "usr", root / "usr/lib", root / "usr/lib/systemd", unit_dir):
        p.chmod(0o755)
    monkeypatch.setattr(unit_files, "_ROOT", root)
    monkeypatch.setattr(unit_files, "_OWNER", os.getuid())
    a = allowance(root)
    (unit_dir / CONTEXTD).write_text(unit_files.rendered_unit(CONTEXTD))
    assert loaded_units.file_allow(CONTEXTD) == []
    (unit_dir / CONTEXTD).write_text(unit_files.rendered_unit(CONTEXTD, allowance=a))
    assert loaded_units.file_allow(CONTEXTD) == [IP]


@pytest.mark.parametrize("value,ok", [
    ([[2, b"\xc0\x00\x02\x0a", 32]], True),
    ([(2, bytearray(b"\xc0\x00\x02\x0a"), 32)], True),
    ([[2, [192, 0, 2, 10], 32]], True),
    ([[2, b"\xc0\x00\x02", 32]], False), ([[2, b"\xc0\x00\x02\x0a", 33]], False),
    ([[10, b"\x00" * 16, 129]], False), ([[3, b"\x00" * 4, 0]], False),
    ([[2, b"\xc0\x00\x02\x0a"]], False), ([[2, "x", 32]], False),
    ([[True, b"\x00" * 4, 0]], False), ([[2, b"\x00" * 4, 0]] * 65, False),
])
def test_bus_decoding_is_bounded_and_canonical(value, ok):
    if ok:
        assert systemd_bus._loaded_value("a(iayu)", value, "a(iayu)") == [
            (2, b"\xc0\x00\x02\x0a", 32)]
    else:
        with pytest.raises(systemd_bus.UnitOperationFailed):
            systemd_bus._loaded_value("a(iayu)", value, "a(iayu)")


def test_bus_decoding_sorts_and_checks_signature():
    value = [[10, b"\x00" * 16, 0], [2, b"\x00" * 4, 0]]
    assert systemd_bus._loaded_value("a(iayu)", value, "a(iayu)") == DENY
    with pytest.raises(systemd_bus.UnitOperationFailed):
        systemd_bus._loaded_value("a(sbbsi)", value, "a(iayu)")
    with pytest.raises(systemd_bus.UnitOperationFailed):
        systemd_bus._loaded_value("a(iayu)", "x", "a(iayu)")


# -- CLI ---------------------------------------------------------------------

class _Auth:
    def __init__(self, state="inactive", cgroup="empty"):
        self.state, self.cgroup = state, cgroup

    def active_state(self, unit): return self.state
    def job(self, unit): return (0, "/")
    def cgroup_state(self, unit): return self.cgroup
    def file_state(self, unit): return "masked"


@pytest.fixture
def host(root, monkeypatch):
    unit_dir = root / "usr/lib/systemd/system"
    unit_dir.mkdir(parents=True)
    (unit_dir / CONTEXTD).write_text(unit_files.rendered_unit(CONTEXTD))
    for path in (root, root / "usr", root / "usr/lib", root / "usr/lib/systemd", unit_dir):
        path.chmod(0o755)
    monkeypatch.setattr(unit_files, "_ROOT", root)
    monkeypatch.setattr(unit_files, "_OWNER", os.getuid())
    monkeypatch.setattr(cli, "_ROOT", root)
    monkeypatch.setattr(cli, "_OWNER", os.getuid())
    monkeypatch.setattr(cli, "_is_root", lambda: True)
    monkeypatch.setattr(cli, "derived_egress_allowance", lambda: egress.derive_allowance(now=NOW))
    state = {"auth": _Auth(), "reloads": 0, "marker": False}

    import contextlib

    @contextlib.contextmanager
    def session():
        yield state["auth"], lambda: state.__setitem__("reloads", state["reloads"] + 1)
    monkeypatch.setattr(cli, "_session", session)
    monkeypatch.setattr(cli, "contextd_marker_present", lambda r: state["marker"])
    state["unit"] = unit_dir / CONTEXTD
    return state


class _Out:
    def __init__(self): self.text = ""
    def write(self, s): self.text += s; return len(s)
    def flush(self): pass


def _published():
    calls = []
    return calls, lambda: calls.append(1) or 0


def test_cli_apply_writes_exactly_the_rendered_unit_and_publishes(host, root):
    a = allowance(root)
    out, (calls, publish) = _Out(), _published()
    assert cli.run_apply(out=out, publish=publish) == 0, out.text
    assert host["unit"].read_text() == unit_files.rendered_unit(CONTEXTD, allowance=a)
    assert host["reloads"] == 1 and calls == [1]
    assert oct(host["unit"].stat().st_mode & 0o777) == "0o644"
    assert cli.run_check(out=_Out()) == 0
    assert [p.name for p in host["unit"].parent.iterdir()] == [CONTEXTD]


def test_cli_remove_restores_default_deny(host, root):
    allowance(root)
    calls, publish = _published()
    cli.run_apply(out=_Out(), publish=publish)
    assert cli.run_remove(out=_Out(), publish=publish) == 0
    assert host["unit"].read_text() == unit_files.rendered_unit(CONTEXTD)
    assert cli.run_check(out=_Out()) == 1  # derivation still exists: allow missing


@pytest.mark.parametrize("setup", ["marker", "running", "populated", "unknown_cgroup"])
def test_cli_refuses_unless_withdrawn_stopped_and_empty(host, root, setup):
    allowance(root)
    before = host["unit"].read_text()
    if setup == "marker":
        host["marker"] = True
    elif setup == "running":
        host["auth"] = _Auth(state="active")
    elif setup == "populated":
        host["auth"] = _Auth(cgroup="populated")
    else:
        host["auth"] = _Auth(cgroup="???")
    calls, publish = _published()
    out = _Out()
    assert cli.run_apply(out=out, publish=publish) == 1
    assert host["unit"].read_text() == before and calls == [] and host["reloads"] == 0
    assert cli.run_remove(out=_Out(), publish=publish) == 1


def test_cli_refuses_without_root_without_derivation_and_with_links(host, root, monkeypatch):
    calls, publish = _published()
    assert cli.run_apply(out=_Out(), publish=publish) == 1  # no bundle
    allowance(root)
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    assert cli.run_apply(out=_Out(), publish=publish) == 1
    monkeypatch.setattr(cli, "_is_root", lambda: True)
    host["unit"].unlink()
    host["unit"].symlink_to(root / "elsewhere")
    assert cli.run_apply(out=_Out(), publish=publish) == 1
    assert calls == []


def test_cli_refuses_drop_ins(host, root):
    allowance(root)
    d = root / "etc/systemd/system" / (CONTEXTD + ".d")
    d.mkdir(parents=True)
    (d / "x.conf").write_text("[Service]\nIPAddressAllow=any\n")
    for p in (root / "etc", root / "etc/systemd", root / "etc/systemd/system", d):
        p.chmod(0o755)
    calls, publish = _published()
    assert cli.run_apply(out=_Out(), publish=publish) == 1 and calls == []


def test_cli_show_and_check_report(host, root):
    out = _Out()
    assert cli.run_show(out=out) == 0 and "none" in out.text
    allowance(root)
    out = _Out()
    cli.run_show(out=out)
    assert "IPAddressAllow=192.0.2.10/32" in out.text and "every port" in out.text
    out = _Out()
    assert cli.run_check(out=out) == 1 and "default-deny-missing" in out.text


def test_cli_check_detects_stale_allow(host, root):
    allowance(root)
    cli.run_apply(out=_Out(), publish=lambda: 0)
    import shutil
    shutil.rmtree(root / "etc")
    assert cli.run_check(out=_Out()) == 1


# -- bus call shape ----------------------------------------------------------

def test_service_interface_getall_is_allowed_for_the_broker_alone():
    from types import SimpleNamespace
    from azazel_nexus_runtime.systemd_bus import (
        PROPERTIES_INTERFACE, SERVICE_INTERFACE, SystemdBusSession, UnitOperationFailed,
        _unit_object_path)

    class Bus:
        def __init__(self): self.messages = []
        async def call(self, message):
            self.messages.append(message)
            return SimpleNamespace(message_type=1, signature="a{sv}", body=[{}])

    class Loop:
        def run_until_complete(self, coro):
            import asyncio
            return asyncio.new_event_loop().run_until_complete(coro)

    bus = Bus()
    session = SystemdBusSession(
        bus=bus, loop=Loop(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **kw: SimpleNamespace(**kw))
    session._exchange(PROPERTIES_INTERFACE, "GetAll", "s", [SERVICE_INTERFACE],
                      path=_unit_object_path(CONTEXTD))
    assert len(bus.messages) == 1
    for unit in ("azazel-edge-intaked.service", "sshd.service"):
        with pytest.raises(UnitOperationFailed):
            session._exchange(PROPERTIES_INTERFACE, "GetAll", "s", [SERVICE_INTERFACE],
                              path=_unit_object_path(unit))
    with pytest.raises(UnitOperationFailed):
        session._exchange(PROPERTIES_INTERFACE, "GetAll", "s",
                          [SERVICE_INTERFACE, "x"], path=_unit_object_path(CONTEXTD))
    assert len(bus.messages) == 1


def _bus_session(reply_for):
    from types import SimpleNamespace
    import asyncio

    class Bus:
        def __init__(self): self.messages = []
        async def call(self, message):
            self.messages.append(message)
            return reply_for(message)

    class Loop:
        def run_until_complete(self, coro):
            return asyncio.new_event_loop().run_until_complete(coro)

    bus = Bus()
    return bus, systemd_bus.SystemdBusSession(
        bus=bus, loop=Loop(), previous_loop=None,
        message_type=SimpleNamespace(ERROR=3, METHOD_RETURN=1),
        message_factory=lambda **kw: SimpleNamespace(**kw))


def test_slice_getall_is_object_scoped():
    from types import SimpleNamespace
    bus, session = _bus_session(
        lambda m: SimpleNamespace(message_type=1, signature="a{sv}", body=[{}]))
    for name in ("system.slice", "-.slice"):
        session._exchange(systemd_bus.PROPERTIES_INTERFACE, "GetAll", "s",
                          [systemd_bus.SLICE_INTERFACE],
                          path=systemd_bus._unit_object_path(name))
    for name in ("user.slice", CONTEXTD, "sshd.service"):
        with pytest.raises(systemd_bus.UnitOperationFailed):
            session._exchange(systemd_bus.PROPERTIES_INTERFACE, "GetAll", "s",
                              [systemd_bus.SLICE_INTERFACE],
                              path=systemd_bus._unit_object_path(name))
    with pytest.raises(systemd_bus.UnitOperationFailed):  # Unit iface on a slice
        session._exchange(systemd_bus.PROPERTIES_INTERFACE, "GetAll", "s",
                          [systemd_bus.UNIT_INTERFACE],
                          path=systemd_bus._unit_object_path("system.slice"))
    assert len(bus.messages) == 2


def _chain_calls(slices):
    """SystemdUnitCalls exchange fake: slice name -> (allow, parent)."""
    from types import SimpleNamespace as NS
    path = systemd_bus._unit_object_path
    by_path = {path(n): v for n, v in slices.items()}

    def exchange(interface, member, signature, body, **kw):
        if member == "GetUnit":
            if body[0] in slices:
                return systemd_bus._Reply("o", [path(body[0])])
            return systemd_bus._Reply("", [], no_such_unit=True)
        if body == [systemd_bus.SLICE_INTERFACE]:
            allow, parent = by_path[kw["path"]]
            return systemd_bus._Reply("a{sv}", [{
                "IPAddressAllow": NS(signature="a(iayu)", value=allow),
                "Slice": NS(signature="s", value=parent)}])
        raise AssertionError(body)
    return systemd_bus.SystemdUnitCalls(exchange)


def _chain(slices, first="system.slice"):
    from types import SimpleNamespace as NS
    return _chain_calls(slices)._slice_chain_allow({"Slice": NS(signature="s", value=first)})


def test_slice_chain_is_followed_and_reports_allow():
    wide = [[2, bytes(4), 0]]
    assert _chain({"system.slice": ([], "-.slice"), "-.slice": ([], "")}) == {
        "system.slice": [], "-.slice": []}
    assert _chain({"system.slice": ([], "-.slice"), "-.slice": (wide, "")})["-.slice"] == [
        (2, bytes(4), 0)]


@pytest.mark.parametrize("slices,first", [
    ({"system.slice": ([], "user.slice")}, "system.slice"),   # outside the fixed chain
    ({"system.slice": ([], "system.slice")}, "system.slice"),  # loop
    ({}, "system.slice"),                                      # slice object missing
    ({"user.slice": ([], "")}, "user.slice"),
])
def test_slice_chain_refusals(slices, first):
    with pytest.raises(systemd_bus.UnitOperationFailed):
        _chain(slices, first)


def test_cli_write_loops_over_short_writes(host, root, monkeypatch):
    a = allowance(root)
    real = os.write

    def short(fd, data):
        return real(fd, bytes(data[:7]))
    monkeypatch.setattr(cli.os, "write", short)
    assert cli.run_apply(out=_Out(), publish=lambda: 0) == 0
    assert host["unit"].read_text() == unit_files.rendered_unit(CONTEXTD, allowance=a)


def test_cli_failed_write_leaves_the_old_unit_and_no_temp(host, root, monkeypatch):
    allowance(root)
    before = host["unit"].read_text()
    monkeypatch.setattr(cli.os, "write", lambda fd, data: 0)
    calls, publish = _published()
    assert cli.run_apply(out=_Out(), publish=publish) == 1
    assert host["unit"].read_text() == before and calls == []
    assert [p.name for p in host["unit"].parent.iterdir()] == [CONTEXTD]


def test_cli_checks_preconditions_before_deriving(host, root, monkeypatch):
    host["marker"] = True
    monkeypatch.setattr(cli, "derived_egress_allowance",
                        lambda: pytest.fail("derived before the preconditions"))
    assert cli.run_apply(out=_Out(), publish=lambda: 0) == 1


# -- D1: a root reader derives under the standard placement ------------------

def test_root_reader_derives_without_reading_secret_files(root, monkeypatch):
    """Secrets are root:<service group> 0640; egid 0 is neither, so the daemon's
    rule refuses them for a root caller. The derivation reads none."""
    build(root)
    bundle = root / "etc/azazel/knowledge-context/commissioning"
    for name in ("client.key", "alias.key"):
        (bundle / name).chmod(0o640)
    monkeypatch.setattr(cfg.os, "getegid", lambda: 4242)  # a caller outside the file's group
    assert cfg.load_commissioning(now=NOW).reason_code == "perm_unsafe"  # daemon rule unchanged
    derived = egress.derive_allowance(now=NOW)
    assert derived is not None and derived.line == "IPAddressAllow=192.0.2.10/32"


def test_derivation_still_applies_the_owner_and_mode_rules(root, monkeypatch):
    build(root)
    bundle = root / "etc/azazel/knowledge-context/commissioning"
    (bundle / "registry.signed").chmod(0o666)  # group/other writable public file
    assert egress.derive_allowance(now=NOW) is None
    (bundle / "registry.signed").chmod(0o644)
    monkeypatch.setattr(cfg, "_OWNER", os.getuid() + 1)
    assert egress.derive_allowance(now=NOW) is None


def test_derivation_applies_the_signature_expiry_and_identity_checks(root):
    import shutil
    for defect in ("expired_registry", "bad_signature", "wrong_identity", "enabled_false"):
        build(root, defect=defect)
        assert egress.derive_allowance(now=NOW) is None, defect
        shutil.rmtree(root / "etc")


# -- D2: the CLI's cgroup reader mode ----------------------------------------

def _cg_root(tmp_path, own, **kw):
    from test_runtime_contextd_cgroup import make_root
    r = make_root(tmp_path, self_cgroup=own, **kw)
    base = r / "sys/fs/cgroup"
    for part in [p for p in own[4:].strip().split("/") if p] if own and own.startswith("0::/") else []:
        base = base / part
        base.mkdir(exist_ok=True)
    return r


LOGIN = "0::/user.slice/user-0.slice/session-1.scope\n"


@pytest.mark.parametrize("own", [LOGIN, "0::/init.scope\n", "0::/\n",
                                 "0::/system.slice/run-abc.service\n"])
def test_operator_mode_reads_from_a_login_shell(tmp_path, own):
    from azazel_nexus_runtime.contextd_cgroup import read_contextd_cgroup
    r = _cg_root(tmp_path, own, events="populated 0\n")
    assert read_contextd_cgroup("inactive", root=r, caller="operator") == "empty"
    r = _cg_root(tmp_path / "p", own, events="populated 1\n")
    assert read_contextd_cgroup("active", root=r, caller="operator") == "populated"


def test_service_mode_is_unchanged_and_refuses_a_login_shell(tmp_path):
    from azazel_nexus_runtime.contextd_cgroup import read_contextd_cgroup
    r = _cg_root(tmp_path, LOGIN, events="populated 0\n")
    assert read_contextd_cgroup("inactive", root=r) == "unknown"
    assert read_contextd_cgroup("inactive", root=r, caller="bogus") == "unknown"


@pytest.mark.parametrize("kwargs", [
    dict(own="0::/docker/abc/user.slice/x.scope\n"),
    dict(own="0::/user.slice/../x\n"),
    dict(own="0::/user.slice/a\n0::/b\n"),
    dict(own="1:cpu:/user.slice/a\n"),
    dict(own="0::/user.slice/a"),
    dict(own=None),
    dict(own=LOGIN, mountinfo=None),
    dict(own=LOGIN, mountinfo="30 25 0:27 / /sys/fs/cgroup rw - cgroup cgroup rw\n"),
    dict(own=LOGIN, mountinfo="30 25 0:99999 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"),
])
def test_operator_mode_keeps_the_mount_binding_and_unknown_is_not_empty(tmp_path, kwargs):
    from azazel_nexus_runtime.contextd_cgroup import read_contextd_cgroup
    own = kwargs.pop("own")
    r = _cg_root(tmp_path, own, events="populated 0\n", **kwargs)
    assert read_contextd_cgroup("inactive", root=r, caller="operator") == "unknown"


def test_operator_mode_requires_the_own_cgroup_to_exist_under_the_mount(tmp_path):
    from test_runtime_contextd_cgroup import make_root
    from azazel_nexus_runtime.contextd_cgroup import read_contextd_cgroup
    r = make_root(tmp_path, self_cgroup=LOGIN, events="populated 0\n")  # dirs not created
    assert read_contextd_cgroup("inactive", root=r, caller="operator") == "unknown"


def test_cli_session_asks_for_operator_mode():
    import inspect
    assert 'cgroup_caller="operator"' in inspect.getsource(cli._session)


# -- D3: the slice chain is read whatever the broker's state -----------------

class _Reader:
    def __init__(self, chain, loaded=None):
        self.chain, self.loaded = chain, loaded

    def bootstrap_profile(self): return "reviewed"
    def loaded_unit(self, unit): return self.loaded
    def slice_chain_allow(self):
        if isinstance(self.chain, Exception):
            raise self.chain
        return self.chain


OK_CHAIN = {"system.slice": [], "-.slice": []}


def test_pass_accepts_an_empty_chain_with_the_broker_not_loaded(monkeypatch):
    loaded_units.verify_loaded_units(_Reader(OK_CHAIN), (CONTEXTD,))


@pytest.mark.parametrize("chain", [
    {"system.slice": [(2, bytes(4), 0)], "-.slice": []},
    {"system.slice": [], "-.slice": [(10, bytes(16), 0)]},
    {"system.slice": []}, {}, None, RuntimeError("x"),
])
@pytest.mark.parametrize("loaded", [None, {"Id": CONTEXTD, "LoadState": "masked"}])
def test_pass_refuses_a_wide_slice_even_when_the_broker_is_not_loaded_or_masked(chain, loaded):
    with pytest.raises(loaded_units.LoadedUnitRefused):
        loaded_units.verify_loaded_units(_Reader(chain, loaded), (CONTEXTD,))


def test_pass_refuses_a_reader_without_the_slice_read():
    class NoSlice:
        def bootstrap_profile(self): return "reviewed"
        def loaded_unit(self, unit): return None
    with pytest.raises(loaded_units.LoadedUnitRefused):
        loaded_units.verify_loaded_units(NoSlice(), (CONTEXTD,))


def test_bus_slice_chain_read_needs_no_broker():
    wide = [[2, bytes(4), 0]]
    calls = _chain_calls({"system.slice": ([], "-.slice"), "-.slice": (wide, "")})
    assert calls.slice_chain_allow() == {"system.slice": [], "-.slice": [(2, bytes(4), 0)]}


@pytest.mark.parametrize("change", [dict(fstype="cgroup"), dict(mount_root="/x"),
                                    dict(point="/sys/fs/cgroup/unified")])
def test_operator_mode_refuses_a_mount_that_is_not_the_cgroup2_root(tmp_path, change):
    from test_runtime_contextd_cgroup import mountinfo_for
    from azazel_nexus_runtime.contextd_cgroup import read_contextd_cgroup
    r = _cg_root(tmp_path, LOGIN, events="populated 0\n")
    (r / "proc/self/mountinfo").write_text(mountinfo_for(r / "sys/fs/cgroup", **change))
    assert read_contextd_cgroup("inactive", root=r, caller="operator") == "unknown"
