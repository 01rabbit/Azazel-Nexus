"""#196 G2: the Deception Lite watch (verify unit, timer, trip unit).

`docs/deception-exposure-grant.md` §6.1 (W4, decided as §10 Q6 and Q7) and
`docs/deception-exposure-reachability.md` §6 and §9 R4. These tests pin, with
fake commands and a fake `/proc/sys/net` (nothing here runs `ip` or `nft`,
starts a unit or reads the host's sysctls):

* the three unit files: rendered from the declaration and committed byte for
  byte; no `[Install]` section and no grant-marker condition on any of them;
  the decoy pulling in the verify unit and the timer; the trip unit holding
  only `Conflicts=` on the namespace unit;
* the verify unit's pinned declaration: the helper's executable with the one
  word `verify`, the helper's sandbox without what makes it a builder, and
  the scope credential shared by exactly the helper and the verify unit;
* the verify's plan: read-backs only, no argument list that changes state;
* `az-decoy-netd verify`: 0 when everything matches, 1 when the table
  departs, is missing, the scope is refused, or reachability R4 departs; no
  record is written or removed;
* each reason code of R4, and the reading of the sysctl tree;
* `activation_unit_files.require_watch_unit_files`.

None of this is VM or hardware evidence (grant §11, reachability §11).
"""

from __future__ import annotations

import json
import os
from dataclasses import replace

import pytest

from azazel_nexus import decoy_scope
from azazel_nexus.activation import (
    ACTIVATION_CONTROLLER_UNIT,
    DECOY_NAMESPACE_UNIT,
    DECOY_NETWORK_HELPER_UNIT,
    DECOY_UNIT,
)
from azazel_nexus.decoy_scope import DecoyScopeRefused
from azazel_nexus_runtime import (
    activation_unit_files as unit_files,
    decoy_isolation_check,
    decoy_netd,
    decoy_network,
    decoy_watch,
)
from azazel_nexus_runtime.decoy_network import (
    HELPER_PLAN,
    HELPER_VERIFY,
    IP,
    WATCH_READS,
    render_ruleset,
    run_fixed,
    verify_plan,
)
from azazel_nexus_runtime.decoy_watch import (
    DECOY_PREFIX_ROUTED,
    FORWARDING_HOST_WIDE,
    FORWARDING_INGRESS_OFF,
    FORWARDING_IPV6_ON,
    FORWARDING_OTHER_ON,
    FORWARDING_UNREADABLE,
    INGRESS_CONTAINMENT_ABSENT,
    IPV6_ABSENT,
    PROXY_ARP_ON,
    REACHABILITY_CODES,
    reachability_departures,
    read_sysctls,
)
from azazel_nexus_runtime.hardening import (
    ALL_PROFILES,
    DECOY_SCOPE_CREDENTIAL,
    DECOY_TRIP_UNIT,
    DECOY_VERIFY_SANDBOX,
    DECOY_VERIFY_TIMER,
    DECOY_VERIFY_UNIT,
    DECOY_WATCH_PROFILES,
    HOST_FIREWALL_UNITS,
    PROFILES,
    packaged_unit_files,
    render_unit,
)
from test_decoy_isolation_evidence import NFT_JSON, NFT_JSON_EMPTY, RULESET, SCOPE, _outputs

REPO = __import__("pathlib").Path(__file__).resolve().parents[2]
UNIT_DIR = REPO / "packaging" / "systemd"
WATCH = (DECOY_VERIFY_UNIT, DECOY_VERIFY_TIMER, DECOY_TRIP_UNIT)
VERIFY = next(p for p in DECOY_WATCH_PROFILES if p.unit == DECOY_VERIFY_UNIT)


def _settings(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "[")):
            continue
        key, _, value = line.partition("=")
        found.setdefault(key, []).append(value)
    return found


def _sections(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("[")]


# -- the unit files ---------------------------------------------------------------


def test_every_packaged_unit_file_is_the_rendered_one():
    rendered = dict(packaged_unit_files())
    assert sorted(rendered) == sorted(path.name for path in UNIT_DIR.iterdir())
    for name, text in rendered.items():
        assert (UNIT_DIR / name).read_text(encoding="ascii") == text, name


def test_the_watch_units_are_the_three_the_design_names():
    assert WATCH == ("azazel-decoy-verify.service", "azazel-decoy-verify.timer",
                     "azazel-decoy-trip.target")
    assert unit_files.WATCH_UNITS == WATCH


@pytest.mark.parametrize("unit", WATCH)
def test_no_watch_unit_has_an_install_section_or_a_condition(unit):
    """A marker would let systemd skip them as a success (n1); [Install] would
    let something other than the decoy start them."""

    text = (UNIT_DIR / unit).read_text(encoding="ascii")
    assert "[Install]" not in _sections(text)
    settings = _settings(text)
    for key in ("WantedBy", "RequiredBy", "Alias", "Also", "UpheldBy"):
        assert key not in settings, key
    assert not any(key.startswith("Condition") for key in settings), unit
    assert "/run/azazel-activation/granted" not in text


def test_every_other_unit_keeps_its_install_section():
    for profile in ALL_PROFILES:
        if profile.unit == DECOY_VERIFY_UNIT:
            continue
        assert _sections(render_unit(profile))[-1] == "[Install]", profile.unit
        assert _settings(render_unit(profile))["WantedBy"] == ["multi-user.target"]


def test_the_verify_unit_file():
    settings = _settings((UNIT_DIR / DECOY_VERIFY_UNIT).read_text(encoding="ascii"))
    assert settings["ExecStart"] == ["/usr/libexec/azazel/az-decoy-netd verify"]
    assert settings["Type"] == ["oneshot"]
    assert settings["User"] == ["root"]
    assert settings["After"] == [DECOY_NETWORK_HELPER_UNIT]
    assert settings["OnFailure"] == [DECOY_TRIP_UNIT]
    assert settings["CapabilityBoundingSet"] == ["CAP_NET_ADMIN"]
    assert settings["AmbientCapabilities"] == [""]
    assert settings["RestrictAddressFamilies"] == ["AF_NETLINK"]
    assert settings["LoadCredential"] == [DECOY_SCOPE_CREDENTIAL]
    assert settings["AppArmorProfile"] == ["azazel-decoy-verify"]
    assert settings["AssertSecurity"] == ["apparmor"]
    assert settings["InaccessiblePaths"] == ["-/run/dbus/system_bus_socket",
                                             "-/run/systemd/private"]
    assert settings["ProtectKernelTunables"] == ["yes"]
    assert settings["NoNewPrivileges"] == ["yes"]
    # It writes nothing and runs again every period.
    for key in ("RuntimeDirectory", "ReadWritePaths", "StateDirectory", "RemainAfterExit",
                "ExecStop", "ExecStartPre", "ExecStopPost", "Requires", "Wants",
                "Environment", "EnvironmentFile", "SetCredential", "Restart"):
        assert key not in settings, key


def test_the_timer_runs_the_verify_unit_every_ten_seconds_and_stops_with_the_decoy():
    text = (UNIT_DIR / DECOY_VERIFY_TIMER).read_text(encoding="ascii")
    assert _sections(text) == ["[Unit]", "[Timer]"]
    settings = _settings(text)
    assert settings["OnActiveSec"] == ["10s"]
    assert settings["OnUnitActiveSec"] == ["10s"]
    assert settings["AccuracySec"] == ["1s"]
    assert settings["Unit"] == [DECOY_VERIFY_UNIT]
    assert settings["PartOf"] == [DECOY_UNIT]
    assert set(settings) == {"Description", "Documentation", "PartOf", "OnActiveSec",
                             "OnUnitActiveSec", "AccuracySec", "Unit"}


def test_the_trip_unit_is_only_a_conflict_with_the_namespace_unit():
    """Stopping is the job engine's: no D-Bus, no process, no privilege."""

    text = (UNIT_DIR / DECOY_TRIP_UNIT).read_text(encoding="ascii")
    assert DECOY_TRIP_UNIT.endswith(".target")
    assert _sections(text) == ["[Unit]"]
    settings = _settings(text)
    assert settings == {
        "Description": ["Azazel-Nexus Deception Lite trip"],
        "Documentation": [
            "https://github.com/01rabbit/Azazel-Nexus/blob/main/docs/deception-exposure-grant.md"],
        "Conflicts": [DECOY_NAMESPACE_UNIT],
    }


def test_the_decoy_pulls_in_the_verify_unit_and_the_timer():
    settings = _settings((UNIT_DIR / DECOY_UNIT).read_text(encoding="ascii"))
    assert settings["Requires"] == [ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT,
                                    DECOY_VERIFY_UNIT, DECOY_VERIFY_TIMER]
    assert settings["After"] == [ACTIVATION_CONTROLLER_UNIT, DECOY_NETWORK_HELPER_UNIT,
                                 DECOY_VERIFY_UNIT]
    # The decoy's grant-marker lines and guards still pass the content check.
    unit_files.require_governed_unit_content(
        DECOY_UNIT, (UNIT_DIR / DECOY_UNIT).read_bytes())


def test_the_helper_is_after_the_three_firewall_loaders():
    settings = _settings((UNIT_DIR / DECOY_NETWORK_HELPER_UNIT).read_text(encoding="ascii"))
    assert HOST_FIREWALL_UNITS == ("nftables.service", "firewalld.service",
                                   "netfilter-persistent.service")
    assert settings["After"] == [ACTIVATION_CONTROLLER_UNIT, DECOY_NAMESPACE_UNIT,
                                 *HOST_FIREWALL_UNITS]
    for key in ("Requires", "Wants", "BindsTo", "PartOf", "Requisite", "Before"):
        for value in settings.get(key, []):
            assert value not in HOST_FIREWALL_UNITS, (key, value)


def test_the_watch_is_not_governed_granted_or_named_by_a_policy():
    from azazel_nexus.activation import CORE_UNITS, DECEPTION_EXPOSURE_UNITS
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    from azazel_nexus_runtime.activation_markers import GRANTABLE_UNITS
    from azazel_nexus_runtime.hardening import GRANT_MARKER_UNITS

    for unit in WATCH:
        assert unit not in {d.name for d in CORE_UNITS}
        assert unit not in GRANTABLE_UNITS
        assert unit not in ACTIVATION_UNIT_ALLOWLIST
        assert unit not in GRANT_MARKER_UNITS
        assert unit not in DECEPTION_EXPOSURE_UNITS
        assert unit not in {p.unit for p in PROFILES}
    preset = (REPO / "packaging" / "azazel-nexus.preset").read_text(encoding="utf-8")
    installer = (REPO / "packaging" / "install.sh").read_text(encoding="utf-8")
    for unit in WATCH:
        assert unit not in preset
        assert f"systemctl mask {unit}" not in installer
        assert f"systemctl enable {unit}" not in installer
        assert installer.count(f'install -m 0644 "$HERE"/systemd/{unit} "$UNIT_DIR"') == 1


# -- the verify unit's declaration ------------------------------------------------


def test_the_verify_unit_is_the_helpers_sandbox_without_the_builder():
    assert VERIFY.executable == "/usr/libexec/azazel/az-decoy-netd"
    assert VERIFY.arguments == ("verify",)
    assert VERIFY.on_failure == (DECOY_TRIP_UNIT,)
    assert VERIFY.wanted_by == ()
    assert VERIFY.extra == DECOY_VERIFY_SANDBOX
    helper = next(p for p in PROFILES if p.unit == DECOY_NETWORK_HELPER_UNIT)
    assert VERIFY.capability_bounding_set == helper.capability_bounding_set
    assert VERIFY.address_families == helper.address_families
    # The helper's extra minus RemainAfterExit and ExecStop; the same credential.
    assert set(VERIFY.extra) == set(helper.extra) - {
        ("RemainAfterExit", "yes"), ("ExecStop", "/usr/libexec/azazel/az-decoy-netd stop")}


@pytest.mark.parametrize("change", [
    {"arguments": ()},
    {"arguments": ("verify", "now")},
    {"arguments": ("stop",)},
    {"on_failure": ()},
    {"on_failure": ("azazel-other.target",)},
    {"wanted_by": ("multi-user.target",)},
    {"executable": "/usr/libexec/azazel/az-decoyd"},
    {"account": "azdecoy"},
    {"capability_bounding_set": ("CAP_NET_ADMIN", "CAP_SYS_ADMIN")},
    {"capability_bounding_set": ()},
    {"address_families": ("AF_UNIX", "AF_NETLINK")},
    {"runtime_directory": "azazel-decoy-verify"},
    {"read_write_paths": ("/var/lib/azazel",)},
    {"after": ()},
    {"after": (DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT)},
    {"requires": (DECOY_NETWORK_HELPER_UNIT,)},
    {"conditions": (("ConditionPathExists",
                     "/run/azazel-activation/granted/azazel-decoyd.service"),)},
    {"unit_type": "simple"},
    {"extra": DECOY_VERIFY_SANDBOX + (("RemainAfterExit", "yes"),)},
    {"extra": DECOY_VERIFY_SANDBOX[:1] + DECOY_VERIFY_SANDBOX[2:]},
    {"apparmor_profile": "azazel-decoy-netd"},
], ids=lambda change: next(iter(change)))
def test_the_verify_unit_refuses_any_other_shape(change):
    with pytest.raises(ValueError):
        replace(VERIFY, **change)


@pytest.mark.parametrize("change", [
    {"arguments": ("verify",)},
    {"on_failure": (DECOY_TRIP_UNIT,)},
    {"wanted_by": ()},
])
@pytest.mark.parametrize("unit", [DECOY_NETWORK_HELPER_UNIT, DECOY_UNIT,
                                  "azazel-edge-core.service"])
def test_no_other_unit_takes_the_verify_units_own_fields(unit, change):
    profile = next(p for p in ALL_PROFILES if p.unit == unit)
    with pytest.raises(ValueError, match="verify"):
        replace(profile, **change)


def test_the_scope_credential_is_the_helpers_and_the_verify_units_alone():
    loaders = [p.unit for p in ALL_PROFILES
               if any(key == "LoadCredential" and "decoy-scope" in value
                      for key, value in p.extra)]
    assert loaders == [DECOY_NETWORK_HELPER_UNIT, DECOY_VERIFY_UNIT]
    mio = next(p for p in ALL_PROFILES if p.unit == "azazel-mio-entryd.service")
    with pytest.raises(ValueError, match="credential alone"):
        replace(mio, extra=mio.extra + (("LoadCredential", DECOY_SCOPE_CREDENTIAL),))


def test_the_verify_credential_path_is_the_units():
    assert decoy_scope.VERIFY_SCOPE_CREDENTIAL_PATH == (
        f"/run/credentials/{DECOY_VERIFY_UNIT}/decoy-scope")
    assert DECOY_SCOPE_CREDENTIAL.split(":", 1)[0] == "decoy-scope"
    assert decoy_scope._VERIFY_PATH == decoy_scope.VERIFY_SCOPE_CREDENTIAL_PATH


def test_only_the_decoy_requires_the_watch():
    """The decoy is the only unit that requires the watch, and the trip unit
    conflicts with the namespace unit only."""

    for profile in ALL_PROFILES:
        if profile.unit != DECOY_UNIT:
            assert DECOY_VERIFY_UNIT not in profile.requires, profile.unit
            assert DECOY_VERIFY_TIMER not in profile.requires, profile.unit
        assert DECOY_TRIP_UNIT not in profile.requires + profile.after + profile.conflicts


# -- the plan ---------------------------------------------------------------------


def test_the_verify_plan_holds_only_read_backs():
    plan = verify_plan(SCOPE)
    assert plan.steps == () and plan.absent == ()
    assert plan.verify == WATCH_READS
    assert plan.allowed == plan.read_back == frozenset(cmd for _, cmd in WATCH_READS)
    assert WATCH_READS[:2] == HELPER_VERIFY
    assert WATCH_READS[2:] == (
        ("host_rules", (IP, "-j", "-4", "rule", "show")),
        ("main_routes", (IP, "-j", "-4", "route", "show", "table", "main")),
    )
    # Nothing in it writes: every command lists.
    for _, command in WATCH_READS:
        assert set(command) & {"list", "show"}, command
        assert not set(command) & {"add", "delete", "set", "flush", "create", "del"}
    assert plan.ruleset == render_ruleset(SCOPE)


def test_the_verify_plan_refuses_every_build_and_undo_command():
    plan = verify_plan(SCOPE)
    builder = decoy_network.helper_plan(SCOPE)
    for argv in builder.allowed - plan.read_back:
        with pytest.raises(ValueError):
            run_fixed(argv, plan=plan)
    for argv in HELPER_PLAN.allowed - plan.read_back:
        with pytest.raises(ValueError):
            run_fixed(argv, plan=plan)


# -- R4 ---------------------------------------------------------------------------

INGRESS = SCOPE.ingress  # ("eth9", "lan0")


def _ipv4(**changes):
    tree = {
        "all": {"forwarding": 0, "proxy_arp": 0},
        "default": {"forwarding": 0},
        "lo": {"forwarding": 0},
        "eth9": {"forwarding": 1, "proxy_arp": 0},
        "lan0": {"forwarding": 1, "proxy_arp": 0},
        "mgmt0": {"forwarding": 0},
        "az-decoy0": {"forwarding": 1},
        "az-decoy-host0": {"forwarding": 0},
    }
    for name, values in changes.items():
        if values is None:
            tree.pop(name)
        else:
            tree[name] = {**tree.get(name, {}), **values}
    return tree


def _ipv6(**changes):
    tree = {name: {"forwarding": 0}
            for name in ("all", "default", "lo", "eth9", "lan0", "mgmt0", "az-decoy0")}
    for name, value in changes.items():
        tree[name] = {"forwarding": value}
    return tree


def _rules(*extra, drop=()):
    rules = [{"priority": 0, "src": "all", "table": "local"}]
    for name in INGRESS:
        rules += [
            {"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
             "iif": name, "table": "main", "suppress_prefixlen": 29},
            {"priority": 1961, "src": "all", "iif": name, "action": "blackhole"},
        ]
    rules = [rule for index, rule in enumerate(rules) if index not in drop]
    rules += list(extra)
    rules += [{"priority": 32766, "src": "all", "table": "main"},
              {"priority": 32767, "src": "all", "table": "default"}]
    return (0, json.dumps(rules).encode())


def _routes(*extra):
    routes = [
        {"dst": "default", "gateway": "192.168.50.254", "dev": "mgmt0", "flags": []},
        {"dst": "10.255.196.0/30", "dev": "az-decoy0", "protocol": "kernel",
         "scope": "link", "prefsrc": "10.255.196.1", "flags": []},
        {"dst": "10.0.0.0/8", "gateway": "192.168.50.1", "dev": "mgmt0", "flags": []},
        {"dst": "192.168.50.0/24", "dev": "mgmt0", "protocol": "kernel", "scope": "link",
         "prefsrc": "192.168.50.2", "flags": []},
    ]
    return (0, json.dumps(routes + list(extra)).encode())


def _departures(ipv4=None, ipv6=None, rules=None, routes=None, ingress=INGRESS):
    return reachability_departures(
        _ipv4() if ipv4 is None else ipv4, _ipv6() if ipv6 is None else ipv6,
        _rules() if rules is None else rules, _routes() if routes is None else routes,
        ingress)


def test_the_codes_are_the_reachability_designs():
    assert REACHABILITY_CODES == (
        "forwarding_ingress_off", "forwarding_host_wide", "forwarding_other_on",
        "forwarding_ipv6_on", "proxy_arp_on", "ingress_containment_absent",
        "decoy_prefix_routed", "forwarding_unreadable")


def test_everything_in_place_is_no_departure():
    assert _departures() == ()
    assert _departures(ipv6=IPV6_ABSENT) == ()
    # The bridge's own forwarding is not read: off only makes it unreachable.
    assert _departures(ipv4=_ipv4(**{"az-decoy0": {"forwarding": 0}})) == ()
    # Without the connected route (the bridge is down) nothing departs either.
    routes = json.loads(_routes()[1])
    assert _departures(routes=(0, json.dumps(routes[:1] + routes[2:]).encode())) == ()


@pytest.mark.parametrize(("ipv4", "code"), [
    (_ipv4(eth9={"forwarding": 0}), FORWARDING_INGRESS_OFF),
    (_ipv4(all={"forwarding": 1}), FORWARDING_HOST_WIDE),
    (_ipv4(default={"forwarding": 1}), FORWARDING_HOST_WIDE),
    (_ipv4(mgmt0={"forwarding": 1}), FORWARDING_OTHER_ON),
    (_ipv4(lo={"forwarding": 1}), FORWARDING_OTHER_ON),
    (_ipv4(**{"az-decoy-host0": {"forwarding": 1}}), FORWARDING_OTHER_ON),
    (_ipv4(docker0={"forwarding": 1}), FORWARDING_OTHER_ON),
    (_ipv4(all={"proxy_arp": 1}), PROXY_ARP_ON),
    (_ipv4(lan0={"proxy_arp": 1}), PROXY_ARP_ON),
    (_ipv4(mgmt0={"forwarding": None}), FORWARDING_UNREADABLE),
    (_ipv4(eth9={"proxy_arp": None}), FORWARDING_UNREADABLE),
    (_ipv4(lan0=None), FORWARDING_UNREADABLE),
    (_ipv4(default=None), FORWARDING_UNREADABLE),
], ids=["ingress-off", "all-on", "default-on", "management-on", "lo-on", "veth-on",
        "other-on", "proxy-arp-all", "proxy-arp-ingress", "unreadable-value",
        "unreadable-proxy-arp", "ingress-absent", "default-absent"])
def test_each_ipv4_departure_has_its_code(ipv4, code):
    assert _departures(ipv4=ipv4) == (code,)


def test_an_unreadable_ipv4_tree_and_ipv6_departures():
    assert _departures(ipv4=None or {}) == (FORWARDING_UNREADABLE,)
    assert reachability_departures(None, _ipv6(), _rules(), _routes(), INGRESS) == (
        FORWARDING_UNREADABLE,)
    assert _departures(ipv6=_ipv6(eth9=1)) == (FORWARDING_IPV6_ON,)
    assert _departures(ipv6=_ipv6(all=1)) == (FORWARDING_IPV6_ON,)
    assert _departures(ipv6=_ipv6(**{"az-decoy0": 1})) == (FORWARDING_IPV6_ON,)
    assert _departures(ipv6=_ipv6(mgmt0=None)) == (FORWARDING_UNREADABLE,)
    assert reachability_departures(_ipv4(), None, _rules(), _routes(), INGRESS) == (
        FORWARDING_UNREADABLE,)
    ipv6 = _ipv6()
    del ipv6["default"]
    assert _departures(ipv6=ipv6) == (FORWARDING_UNREADABLE,)


@pytest.mark.parametrize("rules", [
    _rules(drop=(1,)),
    _rules(drop=(2,)),
    _rules(drop=(0,)),
    _rules({"priority": 100, "src": "all", "table": "100"}),
    _rules({"priority": 5210, "src": "all", "fwmark": "0x80000/0xff0000", "table": "main"}),
    _rules({"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
            "iif": "mgmt0", "table": "main", "suppress_prefixlen": 29}),
    _rules({"priority": 1000, "src": "all", "l3mdev": None, "table": "local"}),
], ids=["lookup-missing", "blackhole-missing", "local-missing", "extra-rule",
        "vpn-fwmark", "pair-on-other-interface", "l3mdev"])
def test_each_rule_departure_is_containment_absent(rules):
    assert _departures(rules=rules) == (INGRESS_CONTAINMENT_ABSENT,)


@pytest.mark.parametrize(("index", "field", "value"), [
    (1, "table", "100"), (1, "dst", "10.255.196.4"), (1, "dstlen", 24),
    (1, "suppress_prefixlen", 0), (1, "action", "blackhole"), (2, "action", "unreachable"),
    (2, "table", "main"), (0, "table", "main"), (0, "iif", "eth9"),
])
def test_a_k1_rule_without_its_defining_attribute_departs(index, field, value):
    rules = json.loads(_rules()[1])
    rules[index][field] = value
    assert _departures(rules=(0, json.dumps(rules).encode())) == (
        INGRESS_CONTAINMENT_ABSENT,)


def test_without_a_scope_only_the_local_rule_may_come_before_main():
    ipv4 = _ipv4(eth9={"forwarding": 0}, lan0={"forwarding": 0})
    local = (0, json.dumps([{"priority": 0, "src": "all", "table": "local"},
                            {"priority": 32766, "src": "all", "table": "main"}]).encode())
    assert reachability_departures(ipv4, _ipv6(), local, _routes(), ()) == ()
    assert reachability_departures(ipv4, _ipv6(), _rules(), _routes(), ()) == (
        INGRESS_CONTAINMENT_ABSENT,)


@pytest.mark.parametrize("route", [
    {"dst": "10.255.196.2", "gateway": "192.168.50.9", "dev": "mgmt0", "flags": []},
    {"dst": "10.255.196.0/30", "gateway": "192.168.50.9", "dev": "mgmt0", "flags": []},
    {"type": "blackhole", "dst": "10.255.196.8/30", "flags": []},
    {"dst": "10.255.196.128/25", "dev": "mgmt0", "flags": []},
    {"dst": "10.255.196.0/24", "dev": "mgmt0", "flags": []},
    {"dst": "10.255.196.0/30", "dev": "az-decoy0", "protocol": "kernel", "flags": []},
    {"dst": "10.255.196.0/30", "flags": [], "nexthops": [{"dev": "az-decoy0"}]},
], ids=["host-route", "slash30-elsewhere", "blackhole", "half", "whole-24",
        "second-connected", "multipath"])
def test_each_route_inside_the_decoy_network_departs(route):
    assert _departures(routes=_routes(route)) == (DECOY_PREFIX_ROUTED,)


def test_a_wider_route_is_suppressed_by_k1_and_does_not_depart():
    assert _departures(routes=_routes({"dst": "10.255.0.0/16", "dev": "mgmt0",
                                       "flags": []})) == ()


@pytest.mark.parametrize("output", [
    (1, b""), (0, b"not json"), (0, b"{}"), (0, b"[1]"),
    (0, json.dumps([{"src": "all"}]).encode()),
    (0, json.dumps([{"priority": "0"}]).encode()),
])
def test_an_unreadable_rule_dump_is_unreadable(output):
    assert _departures(rules=output) == (FORWARDING_UNREADABLE,)


@pytest.mark.parametrize("output", [
    (1, b""), (0, b"\xff"), (0, json.dumps([{"dev": "mgmt0"}]).encode()),
    (0, json.dumps([{"dst": "10.255.196.1/24"}]).encode()),
    (0, json.dumps([{"dst": "fe80::/64"}]).encode()),
])
def test_an_unreadable_route_dump_is_unreadable(output):
    assert _departures(routes=output) == (FORWARDING_UNREADABLE,)


def test_several_departures_are_reported_in_fixed_order():
    found = _departures(ipv4=_ipv4(all={"forwarding": 1}, eth9={"forwarding": 0}),
                        rules=_rules(drop=(1,)), routes=_routes(
                            {"dst": "10.255.196.2", "dev": "mgmt0", "flags": []}))
    assert found == (FORWARDING_INGRESS_OFF, FORWARDING_HOST_WIDE,
                     INGRESS_CONTAINMENT_ABSENT, DECOY_PREFIX_ROUTED)


# -- reading /proc/sys/net --------------------------------------------------------


def _write(path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


@pytest.fixture
def net(tmp_path, monkeypatch):
    root = tmp_path / "net"
    for family, names in (("ipv4", ("all", "default", "lo", "eth9", "mgmt0")),
                          ("ipv6", ("all", "default", "lo", "eth9", "mgmt0"))):
        for name in names:
            _write(root / family / "conf" / name / "forwarding",
                   b"1\n" if (family, name) == ("ipv4", "eth9") else b"0\n")
            if family == "ipv4":
                _write(root / family / "conf" / name / "proxy_arp", b"0\n")
    monkeypatch.setattr(decoy_watch, "_NET", str(root))
    return root


def test_the_reader_reads_forwarding_and_proxy_arp(net):
    ipv4, ipv6 = read_sysctls(("eth9",))
    assert ipv4 == {"all": {"forwarding": 0, "proxy_arp": 0}, "default": {"forwarding": 0},
                    "lo": {"forwarding": 0}, "eth9": {"forwarding": 1, "proxy_arp": 0},
                    "mgmt0": {"forwarding": 0}}
    assert ipv6 == {name: {"forwarding": 0}
                    for name in ("all", "default", "lo", "eth9", "mgmt0")}


@pytest.mark.parametrize("content", [b"", b"1", b"0\n\n", b"2\n", b" 0\n", b"0\n" * 4])
def test_a_value_not_in_its_closed_form_is_unreadable(net, content):
    (net / "ipv4" / "conf" / "mgmt0" / "forwarding").write_bytes(content)
    assert read_sysctls(("eth9",))[0]["mgmt0"] == {"forwarding": None}


def test_a_missing_value_file_is_unreadable_and_a_link_is_not_followed(net):
    (net / "ipv4" / "conf" / "mgmt0" / "forwarding").unlink()
    assert read_sysctls(("eth9",))[0]["mgmt0"] == {"forwarding": None}
    target = net / "zero"
    target.write_bytes(b"0\n")
    os.symlink(target, net / "ipv4" / "conf" / "mgmt0" / "forwarding")
    assert read_sysctls(("eth9",))[0]["mgmt0"] == {"forwarding": None}
    # An interface directory that is a link is not opened either.
    os.symlink(net / "ipv4" / "conf" / "lo", net / "ipv4" / "conf" / "link0")
    assert read_sysctls(("eth9",))[0]["link0"] == {"forwarding": None}


def test_without_ipv6_forwarding_counts_as_off(net):
    import shutil

    shutil.rmtree(net / "ipv6")
    ipv4, ipv6 = read_sysctls(("eth9",))
    assert ipv6 is IPV6_ABSENT
    # With the directory present but conf/ missing, it is unreadable.
    (net / "ipv6").mkdir()
    assert read_sysctls(("eth9",))[1] is None


def test_an_absent_ipv4_tree_is_unreadable(net):
    import shutil

    shutil.rmtree(net / "ipv4")
    assert read_sysctls(("eth9",))[0] is None


def test_the_reader_is_what_the_profile_allows():
    """`/proc/sys/net/ipv{4,6}/conf/*/` and its two files: nothing else."""

    assert decoy_watch._NET == "/proc/sys/net"
    profile = (REPO / "packaging" / "apparmor" / "azazel-decoy-verify").read_text()
    for path in ("ipv4/conf/*/forwarding", "ipv4/conf/*/proxy_arp",
                 "ipv6/conf/*/forwarding"):
        assert f"@{{PROC}}/sys/net/{path} r," in profile


# -- az-decoy-netd verify ---------------------------------------------------------


class Capture:
    def __init__(self, outputs):
        self.outputs, self.calls = outputs, []

    def __call__(self, command):
        self.calls.append(command)
        return self.outputs[command]


def _capture(nft=NFT_JSON, nft_status=0, rules=None, routes=None):
    table = _outputs(nft=nft, nft_status=nft_status)
    by_name = {**table, "host_rules": _rules() if rules is None else rules,
               "main_routes": _routes() if routes is None else routes}
    return Capture({command: by_name[name] for name, command in WATCH_READS})


@pytest.fixture
def watch(monkeypatch):
    """The verify's scope and sysctls, and a recorder that must not be touched."""

    monkeypatch.setattr(decoy_watch, "read_verify_scope_credential", lambda: SCOPE)
    monkeypatch.setattr(decoy_watch, "read_sysctls", lambda ingress: (_ipv4(), _ipv6()))

    def untouched(*_args, **_kwargs):
        raise AssertionError("the verify touched the isolation recorder")

    monkeypatch.setattr(decoy_isolation_check.Recorder, "__init__", untouched)
    monkeypatch.setattr(decoy_netd, "Recorder", untouched)


def test_a_match_exits_zero(watch, capsys):
    capture = _capture()
    assert decoy_netd.main(["verify"], capture=capture) == 0
    assert capture.calls == [command for _, command in WATCH_READS]
    err = capsys.readouterr().err
    assert "match" in err


def test_a_table_that_differs_from_the_scope_exits_one(watch, capsys):
    other = NFT_JSON.replace('"10.20.0.0"', '"10.21.0.0"')
    assert other != NFT_JSON
    assert decoy_netd.main(["verify"], capture=_capture(nft=other)) == 1
    assert "approved_v4_matches fail" in capsys.readouterr().err


def test_a_missing_or_flushed_table_exits_one(watch, capsys):
    assert decoy_netd.main(["verify"], capture=_capture(nft_status=1)) == 1
    assert "nft_table unreadable" in capsys.readouterr().err
    # The table of the first build is not the scope's table.
    assert decoy_netd.main(["verify"], capture=_capture(nft=NFT_JSON_EMPTY)) == 1


def test_a_refused_scope_exits_one_and_reads_nothing(monkeypatch, watch, capsys):
    def refused():
        raise DecoyScopeRefused("the scope file is not in its canonical form")

    monkeypatch.setattr(decoy_watch, "read_verify_scope_credential", refused)
    capture = _capture()
    assert decoy_netd.main(["verify"], capture=capture) == 1
    assert capture.calls == []
    assert "scope could not be read" in capsys.readouterr().err


@pytest.mark.parametrize(("ipv4", "rules", "routes", "code"), [
    (_ipv4(eth9={"forwarding": 0}), None, None, FORWARDING_INGRESS_OFF),
    (_ipv4(all={"forwarding": 1}), None, None, FORWARDING_HOST_WIDE),
    (None, _rules(drop=(2,)), None, INGRESS_CONTAINMENT_ABSENT),
    (None, None, _routes({"dst": "10.255.196.2", "dev": "mgmt0", "flags": []}),
     DECOY_PREFIX_ROUTED),
    (None, (1, b""), None, FORWARDING_UNREADABLE),
])
def test_a_reachability_departure_exits_one(monkeypatch, watch, capsys, ipv4, rules,
                                            routes, code):
    if ipv4 is not None:
        monkeypatch.setattr(decoy_watch, "read_sysctls", lambda ingress: (ipv4, _ipv6()))
    assert decoy_netd.main(["verify"], capture=_capture(rules=rules, routes=routes)) == 1
    assert code in capsys.readouterr().err


def test_an_error_while_evaluating_exits_one(monkeypatch, watch):
    def broken(ingress):
        raise RuntimeError("boom")

    monkeypatch.setattr(decoy_watch, "read_sysctls", broken)
    assert decoy_netd.main(["verify"], capture=_capture()) == 1


def test_the_verify_reads_the_scope_from_its_own_credential(monkeypatch, tmp_path):
    """Its directory, not the helper's: absent directory, no scope."""

    monkeypatch.setattr(decoy_scope, "_VERIFY_PATH", str(tmp_path / "absent" / "decoy-scope"))
    assert decoy_scope.read_verify_scope_credential() is None
    monkeypatch.setattr(decoy_scope, "_PATH", str(tmp_path / "helper" / "decoy-scope"))
    (tmp_path / "verify").mkdir()
    monkeypatch.setattr(decoy_scope, "_VERIFY_PATH", str(tmp_path / "verify" / "decoy-scope"))
    with pytest.raises(DecoyScopeRefused):
        decoy_scope.read_verify_scope_credential()


def test_the_verify_says_no_name_prefix_or_address(monkeypatch, watch, capsys):
    monkeypatch.setattr(decoy_watch, "read_sysctls", lambda ingress: (
        _ipv4(eth9={"forwarding": 0}, mgmt0={"forwarding": 1}), _ipv6(lan0=1)))
    routes = _routes({"dst": "10.255.196.2", "dev": "mgmt0", "flags": []})
    other = NFT_JSON.replace('"10.20.0.0"', '"10.21.0.0"')
    assert decoy_netd.main(["verify"], capture=_capture(nft=other, rules=_rules(drop=(1,)),
                                                        routes=routes)) == 1
    err = capsys.readouterr().err
    for secret in ("eth9", "lan0", "mgmt0", "10.20.", "10.21.", "10.30.", "192.168.",
                   "10.255.196.2"):
        assert secret not in err, secret


def test_other_arguments_are_still_refused():
    assert decoy_netd.main(["verify", "now"]) == 2
    assert decoy_netd.main(["--verify"]) == 2


def test_the_verify_imports_no_writer():
    """It takes the judgement from the helper's check, never the recorder."""

    import ast

    tree = ast.parse((REPO / "runtime" / "src" / "azazel_nexus_runtime" /
                      "decoy_watch.py").read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not names & {"Recorder", "run_fixed", "write", "unlink", "rename", "replace",
                        "mkdir", "chmod", "fchmod", "O_WRONLY", "O_CREAT", "O_RDWR",
                        "socket", "environ", "getenv"}


# -- the watch's unit-file check --------------------------------------------------


@pytest.fixture
def root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    vendor = root / "usr/lib/systemd/system"
    vendor.mkdir(parents=True)
    rendered = dict(packaged_unit_files())
    for unit in WATCH:
        (vendor / unit).write_text(rendered[unit])
        (vendor / unit).chmod(0o644)
    for path in [root, *root.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)
    monkeypatch.setattr(unit_files, "_ROOT", root)
    monkeypatch.setattr(unit_files, "_OWNER", os.getuid())
    return root


def _dir(root, relative):
    path = root / relative
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != root:
        current.chmod(0o755)
        current = current.parent
    return path


def test_the_watch_files_as_rendered_pass(root):
    unit_files.require_watch_unit_files()


@pytest.mark.parametrize("unit", WATCH)
def test_a_changed_watch_file_is_refused(root, unit):
    path = root / "usr/lib/systemd/system" / unit
    path.write_text(path.read_text() + "\n")
    with pytest.raises(unit_files.UnitContentRefused):
        unit_files.require_watch_unit_files()


@pytest.mark.parametrize("unit", WATCH)
def test_a_missing_watch_file_is_refused(root, unit):
    (root / "usr/lib/systemd/system" / unit).unlink()
    with pytest.raises(unit_files.UnitFilesRefused):
        unit_files.require_watch_unit_files()


@pytest.mark.parametrize("unit", WATCH)
def test_a_masked_watch_unit_is_refused(root, unit):
    """A masked trip unit would leave a failed verify starting nothing."""

    etc = _dir(root, "etc/systemd/system")
    os.symlink("/dev/null", etc / unit)
    with pytest.raises(unit_files.UnitOverrideRefused):
        unit_files.require_watch_unit_files()


@pytest.mark.parametrize("dropin", ["azazel-decoy-trip.target.d", "target.d",
                                    "azazel-decoy-verify.timer.d", "azazel-.service.d"])
def test_a_drop_in_on_a_watch_unit_is_refused(root, dropin):
    directory = _dir(root, f"run/systemd/system/{dropin}")
    (directory / "x.conf").write_text("[Unit]\n")
    with pytest.raises(unit_files.UnitOverrideRefused):
        unit_files.require_watch_unit_files()


def test_the_pass_does_not_call_the_watch_check_yet():
    """G6 wires it in with the generation's exposure section."""

    runtime = REPO / "runtime" / "src" / "azazel_nexus_runtime"
    for name in ("activation_pass.py", "activated.py", "activation_loaded_units.py",
                 "activation_cli.py"):
        assert "require_watch_unit_files" not in (runtime / name).read_text(), name


# -- review of #287 ---------------------------------------------------------------


def test_an_absent_scope_exits_one_and_reads_nothing(monkeypatch, watch, capsys):
    """F1: no credential directory is not the table of the first build."""

    monkeypatch.setattr(decoy_watch, "read_verify_scope_credential", lambda: None)
    capture = _capture()
    sysctls = []
    monkeypatch.setattr(decoy_watch, "read_sysctls",
                        lambda ingress: sysctls.append(ingress) or (_ipv4(), _ipv6()))
    assert decoy_netd.main(["verify"], capture=capture) == 1
    assert capture.calls == [] and sysctls == []
    assert "the decoy scope is absent; nothing was compared" in capsys.readouterr().err
    # Even when the host shows exactly the scope-less table and no ingress.
    outputs = {"nft_table": (0, NFT_JSON_EMPTY.encode()),
               "host_links": _outputs()["host_links"],
               "host_rules": _rules(), "main_routes": _routes()}
    empty = Capture({command: outputs[name] for name, command in WATCH_READS})
    assert decoy_watch.verify(capture=empty, read_scope=lambda: None,
                              sysctls=lambda ingress: (_ipv4(), _ipv6())) == 1
    assert empty.calls == []


@pytest.mark.parametrize("missing", [None, 7, ["None"]])
def test_a_rule_without_a_named_iif_is_never_an_ingress_rule(missing):
    """F3: an absent `iif` is a sentinel, not the text "None"."""

    ingress = ("None",)
    lookup = {"priority": 1960, "src": "all", "dst": "10.255.196.0", "dstlen": 30,
              "table": "main", "suppress_prefixlen": 29}
    blackhole = {"priority": 1961, "src": "all", "action": "blackhole"}
    if missing is not None:
        lookup["iif"] = blackhole["iif"] = missing
    rules = [{"priority": 0, "src": "all", "table": "local"}, lookup, blackhole]
    assert decoy_watch._rules_contained(rules, ingress) is False
    named = [rules[0], {**lookup, "iif": "None"}, {**blackhole, "iif": "None"}]
    assert decoy_watch._rules_contained(named, ingress) is True
    # Without iif the pair would match every interface: never containment.
    assert decoy_watch._rules_contained(rules, ()) is False


def test_the_verify_plan_cannot_start_anything_but_its_four_reads(monkeypatch):
    """No argument list that loads, deletes or changes anything is in the plan,
    and `run_fixed`/`capture_fixed` refuse any other before a process exists."""

    spawned = []

    def spawn(argv, actions):
        spawned.append(argv)
        raise AssertionError("a process was started")

    monkeypatch.setattr(decoy_network, "_spawn", spawn)
    plan = verify_plan(SCOPE)
    assert len(plan.allowed) == 4
    for argv in plan.allowed:
        assert argv[0] in (decoy_network.IP, decoy_network.NFT)
        assert argv[1] == "-j"
    writes = [(decoy_network.NFT, render_ruleset(SCOPE).text),
              (decoy_network.NFT, "flush", "ruleset"),
              (decoy_network.NFT, "delete", "table", "inet", "azazel_decoy"),
              (IP, "link", "delete", "az-decoy0"),
              (IP, "rule", "add", "priority", "1", "lookup", "main")]
    for argv in writes:
        with pytest.raises(ValueError):
            run_fixed(argv, plan=plan)
        with pytest.raises(ValueError):
            decoy_network.capture_fixed(argv, plan=plan)
    assert spawned == []


def test_without_a_scope_the_rendered_table_approves_nothing():
    """`render_ruleset(None)`: the first build's table, no element, no ingress,
    no digest; the verify refuses to compare against it (F1)."""

    ruleset = render_ruleset(None)
    assert ruleset.text == decoy_network.NFT_RULESET
    assert ruleset.approved_v4 == () and ruleset.ingress == ()
    assert ruleset.scope_digest is None
    assert "elements" not in ruleset.text and "iifname {" not in ruleset.text
    assert "masquerade" not in ruleset.text
    assert verify_plan(None).ruleset == ruleset
