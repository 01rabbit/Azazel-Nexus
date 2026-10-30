"""The NOC snapshot (U3): projection, strict reader, observer, unit and read model.

`az-noc-observe` writes `noc_status.project(noc_observe.collect(...))` into
`run/noc-status`; status and the UI read it through `read_noc_status`.
Mock evidence unless marked: the collection runs against the fake netlink
and sysfs tree of `test_noc_observe`; one test runs the observer's entry
point in a real process against this Linux container's own netlink (container
evidence, not hardware).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_nexus import noc_status
from azazel_nexus import operator_snapshots as snap
from azazel_nexus import runtime_paths as paths
from azazel_nexus import status_view
from test_noc_observe import LINUX, SECRET_STRINGS, _run, _second_read, host  # noqa: F401

REPO = Path(__file__).resolve().parents[2]
NOW = 1_800_000_000.0


def _observed(host):
    return noc_status.project(_run(host, on_sleep=_second_read(host)), NOW)


def _raw(value) -> bytes:
    return json.dumps(value).encode()


def _paths(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            yield path
            yield from _paths(item, path)
    elif isinstance(value, list):
        for item in value:
            yield prefix + "[]"
            yield from _paths(item, prefix + "[]")


# -- the projection --------------------------------------------------------------


def test_the_projection_keeps_ifindex_counts_and_codes_only(host):
    value = _observed(host)
    assert value["collection"] == "observed" and value["reason_code"] is None
    assert noc_status.read_noc_status(_raw(value)) == value
    text = json.dumps(value, sort_keys=True)
    for secret in SECRET_STRINGS:
        assert secret not in text, secret
    for leaked in ('"lo"', "corp.example", "198.51.100.53", "127.0.0.53", "/sys/class/net",
                   "evidence", "source", "reason_text"):
        assert leaked not in text, leaked
    interfaces = value["interfaces"]["value"]
    assert [item["ifindex"] for item in interfaces] == [1, 2, 3]
    eth = interfaces[1]
    assert eth["addresses"]["value"] == {"ipv4": 1, "ipv6": 2}
    assert eth["quality"]["value"]["rx_errors_delta"] == 2
    assert eth["quality"]["value"]["rx_dropped_delta"] == 1
    assert eth["counters"]["value"]["rx_bytes"] == 126_000
    assert eth["speed_mbps"]["value"] == 1000
    assert eth["dhcp"]["value"]["client"] == "systemd-networkd"
    wan = interfaces[2]
    assert (wan["speed_mbps"]["state"], wan["speed_mbps"]["reason"]) == (
        "unknown", "speed_not_reported")
    assert wan["dhcp"]["value"]["client"] == "dhclient"
    uplink = value["uplink"]
    assert uplink["ipv4"]["value"]["table_main"]["default_routes"] == 1
    assert uplink["ipv4"]["value"]["table_main"]["egress_ifindex"] == [2]
    assert uplink["ipv4"]["value"]["other_tables"]["linkdown"] is True
    assert uplink["ipv4"]["value"]["policy_rules_evaluated"] is False
    assert value["routes"]["value"]["table_main"]["ipv4"] == 2
    assert value["dns"]["resolv_conf"]["value"] == {
        "kind": "symlink_systemd_resolved_stub", "nameservers": 1,
        "loopback_nameservers": 1, "search_domains": 1}
    assert value["dns"]["systemd_resolved_upstream"]["value"] == {"nameservers": 2}


def test_what_needs_an_active_probe_is_unknown_never_down(host):
    value = _observed(host)
    for field in (value["uplink"]["reachability"], value["dns"]["resolution"]):
        assert (field["state"], field["value"], field["reason"]) == (
            "unknown", None, "active_check_not_performed")
    assert value["active_checks"] == "none"
    # The reader refuses a snapshot that claims either was observed.
    for path in (("uplink", "reachability"), ("dns", "resolution")):
        forged = json.loads(json.dumps(value))
        forged[path[0]][path[1]] = {"state": "observed", "value": False, "reason": None,
                                    "age_s": 0.0}
        assert noc_status.read_noc_status(_raw(forged)) is None
        forged[path[0]][path[1]] = {"state": "unknown", "value": None,
                                    "reason": "netlink_unavailable", "age_s": 0.0}
        assert noc_status.read_noc_status(_raw(forged)) is None


def test_a_field_the_observation_grows_does_not_reach_the_snapshot(host):
    observation = _run(host, on_sleep=_second_read(host))
    observation["interfaces"][1]["name"] = "eth9"
    observation["interfaces"][1]["mac"] = {"state": "observed", "value": "02:00:00:00:00:09"}
    observation["dns"]["resolv_conf"]["value"]["nameserver_addresses"] = ["198.51.100.53"]
    value = noc_status.project(observation, NOW)
    assert value["collection"] == "observed"
    text = json.dumps(value)
    assert "eth9" not in text and "02:00" not in text and "198.51" not in text


def test_more_interfaces_than_the_bound_are_counted_not_listed(host):
    observation = _run(host, on_sleep=_second_read(host))
    template = observation["interfaces"][1]
    observation["interfaces"] = [dict(template, ifindex=index) for index in range(1, 41)]
    value = noc_status.project(observation, NOW)
    assert len(value["interfaces"]["value"]) == noc_status.MAX_INTERFACES
    assert value["interfaces_omitted"] == 40 - noc_status.MAX_INTERFACES
    assert len(_raw(value)) < noc_status.NOC_BYTES


def test_an_unprojectable_observation_is_refused_as_a_whole(host):
    observation = _run(host, on_sleep=_second_read(host))
    observation["interfaces"][0]["operstate"]["value"] = "SECRET-state"
    value = noc_status.project(observation, NOW)
    assert (value["collection"], value["reason_code"]) == ("failed", "projection_refused")
    assert "SECRET" not in json.dumps(value)
    assert noc_status.read_noc_status(_raw(value)) == value
    assert noc_status.project({"schema": "x"}, NOW)["reason_code"] == "projection_refused"


def test_a_netlink_failure_is_carried_as_its_fixed_reason(host):
    from test_noc_observe import _factory

    def unavailable():
        raise OSError("no netlink")
    observation = _run(host, factory=unavailable)
    value = noc_status.project(observation, NOW)
    assert value["collection"] == "observed"
    assert (value["interfaces"]["state"], value["interfaces"]["reason"]) == (
        "unknown", "netlink_unavailable")
    assert value["uplink"]["ipv4"]["reason"] == "netlink_unavailable"
    assert noc_status.read_noc_status(_raw(value)) == value
    assert _factory  # the fake used elsewhere stays importable


# -- the reader --------------------------------------------------------------------


def _damaged(host, how):
    value = _observed(host)
    interface = value["interfaces"]["value"][1]
    changes = {
        "name": lambda: interface.update(name="eth9"),
        "mac": lambda: interface.update(mac="02:00:00:00:00:09"),
        "operstate": lambda: interface["operstate"].update(value="green"),
        "negative_counter": lambda: interface["counters"]["value"].update(rx_bytes=-1),
        "bool_as_int": lambda: interface["admin_up"].update(value=1),
        "reason_unregistered": lambda: interface["mtu"].update(state="unknown", value=None,
                                                               reason="SECRET"),
        "observed_with_reason": lambda: interface["mtu"].update(reason="not_reported"),
        "duplicate_ifindex": lambda: value["interfaces"]["value"].append(dict(interface)),
        "unsorted": lambda: value["interfaces"]["value"].reverse(),
        "policy_evaluated": lambda: value["uplink"]["ipv4"]["value"].update(
            policy_rules_evaluated=True),
        "egress_unsorted": lambda: value["uplink"]["ipv4"]["value"]["table_main"].update(
            egress_ifindex=[3, 2]),
        "resolver_address": lambda: value["dns"]["resolv_conf"]["value"].update(
            nameservers="198.51.100.53"),
        "resolv_kind": lambda: value["dns"]["resolv_conf"]["value"].update(kind="other"),
        "active_checks": lambda: value.update(active_checks="icmp"),
        "age_negative": lambda: interface["mtu"].update(age_s=-1),
        "failed_with_data": lambda: value.update(collection="failed",
                                                 reason_code="collection_failed"),
        "extra_top": lambda: value.update(interface_names=[]),
        "schema": lambda: value.update(schema="azazel-nexus/noc-observation-local/v1"),
    }
    changes[how]()
    return value


@pytest.mark.parametrize("how", [
    "name", "mac", "operstate", "negative_counter", "bool_as_int", "reason_unregistered",
    "observed_with_reason", "duplicate_ifindex", "unsorted", "policy_evaluated",
    "egress_unsorted", "resolver_address", "resolv_kind", "active_checks", "age_negative",
    "failed_with_data", "extra_top", "schema",
])
def test_the_reader_refuses_anything_outside_the_closed_shape(host, how):
    assert noc_status.read_noc_status(_raw(_damaged(host, how))) is None


@pytest.mark.parametrize("raw", [b"{", b"[]", b"", b"\xff", b"null"])
def test_the_reader_refuses_broken_bytes(raw):
    assert noc_status.read_noc_status(raw) is None
    assert noc_status.read_noc_status(b" " * (noc_status.NOC_BYTES + 1)) is None


def test_the_core_reasons_match_the_collector():
    from azazel_nexus_runtime import noc_observe

    assert noc_status.UNKNOWN_REASONS == frozenset(noc_observe.UNKNOWN_REASONS)
    assert noc_status.OPERSTATES == (frozenset(noc_observe._OPERSTATES.values())
                                     | {"kernel_unrecognised"})
    assert noc_status.COUNTERS == noc_observe._COUNTERS


# -- the observer ------------------------------------------------------------------


@pytest.fixture
def root(tmp_path, monkeypatch):
    from azazel_nexus_runtime import runtime_paths as runtime

    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path / "node"))
    monkeypatch.setattr(runtime, "ROOT", tmp_path / "node")
    return tmp_path / "node"


def test_the_observer_writes_the_snapshot_and_status_reads_it(root, host):
    from azazel_nexus_runtime import noc_snapshot

    collect = lambda interval: _run(host, on_sleep=_second_read(host))  # noqa: E731
    assert noc_snapshot.main([], collect=collect, clock=lambda: NOW) == 1  # no leaf yet
    paths.noc_status_path().parent.mkdir(parents=True)
    assert noc_snapshot.main([], collect=collect, clock=lambda: NOW) == 0
    section = status_view._noc(NOW + 5)
    assert (section["status"], section["freshness"]) == ("observed", "fresh") and section["source"]["writer"] == "az-noc-observe"
    assert section["snapshot"]["collection"] == "observed"
    assert section["observation"] == {"kind": "passive", "transmission": "none",
                                      "active_checks": "none",
                                      "policy_rules_evaluated": False}
    assert [(m["field"], m["status"], m["reason_code"]) for m in section["not_measured"]] == [
        ("uplink.reachability", "not_measured", "active_check_not_performed"),
        ("dns.resolution", "not_measured", "active_check_not_performed")]
    assert section["role"]["reason_code"] == "role_evidence_not_provided"
    text = json.dumps(section)
    for word in ("unreachable", "offline", "通信不能", "disconnected"):
        assert word not in text
    assert all(status_view._noc(t)["status"] != "running" for t in (NOW, NOW + 10_000, None))
    # The observer stops (its timer is disabled): the snapshot goes stale.
    stale = status_view._noc(NOW + noc_status.NOC_STALE_S + 1)
    assert (stale["status"], stale["reason_code"]) == ("stale", "snapshot_expired")
    future = status_view._noc(NOW - 10)
    assert future["reason_code"] == "snapshot_dated_in_future"
    paths.noc_status_path().unlink()
    assert status_view._noc(NOW)["status"] == "unavailable"


def test_a_failed_collection_is_a_fixed_code(root):
    from azazel_nexus_runtime import noc_snapshot

    def explode(interval):
        raise ValueError("lease line for wan7 192.0.2.10")
    paths.noc_status_path().parent.mkdir(parents=True)
    assert noc_snapshot.main([], collect=explode, clock=lambda: NOW) == 0
    raw = paths.noc_status_path().read_bytes()
    assert b"wan7" not in raw and b"192.0.2" not in raw
    section = status_view._noc(NOW)
    assert (section["status"], section["reason_code"]) == ("unknown", "collection_failed")
    with pytest.raises(SystemExit, match="takes no arguments"):
        noc_snapshot.main(["--interval", "5"], collect=explode)


@pytest.mark.parametrize("damage", ["symlink", "directory", "oversized", "broken"])
def test_a_damaged_noc_file_is_unavailable(root, damage):
    path = paths.noc_status_path()
    path.parent.mkdir(parents=True)
    if damage == "symlink":
        (root / "real.json").write_bytes(_raw(noc_status.failed(NOW)))
        path.symlink_to(root / "real.json")
    elif damage == "directory":
        path.mkdir()
    elif damage == "oversized":
        path.write_bytes(b" " * (noc_status.NOC_BYTES + 2))
    else:
        path.write_bytes(b'{"schema":"azazel-nexus/noc-status/v1"')
    section = status_view._noc(NOW)
    assert (section["status"], section["reason_code"]) == ("unavailable",
                                                           "snapshot_absent_or_refused")


@pytest.mark.real_process
@pytest.mark.skipif(not LINUX, reason="AF_NETLINK is Linux-only")
def test_container_evidence_the_observer_writes_this_containers_netlink_state(tmp_path):
    """CONTAINER EVIDENCE, NOT HARDWARE. `az-noc-observe`'s entry point in a
    real process, with every non-netlink socket family refused in that
    process, writing into a leaf under a temporary root."""

    leaf = tmp_path / "var/lib/azazel/run/noc-status"
    leaf.mkdir(parents=True)
    guard = (
        "import socket, sys\n"
        "real = socket.socket\n"
        "class G(real):\n"
        "    def __init__(self, family=-1, *a, **k):\n"
        "        if family != socket.AF_NETLINK:\n"
        "            sys.stderr.write('NON-NETLINK SOCKET\\n'); raise SystemExit(70)\n"
        "        super().__init__(family, *a, **k)\n"
        "socket.socket = G\n"
        "from azazel_nexus_runtime.noc_snapshot import main\n"
        "raise SystemExit(main([]))\n"
    )
    completed = subprocess.run([sys.executable, "-c", guard], capture_output=True, text=True,
                               timeout=60, check=False,
                               env={**os.environ, "AZAZEL_ROOT": str(tmp_path)})
    assert completed.returncode == 0, completed.stderr
    value = noc_status.read_noc_status((leaf / "status.json").read_bytes())
    assert value is not None and value["collection"] == "observed"
    loopback = [item for item in value["interfaces"]["value"]
                if item["loopback"]["value"] is True]
    assert len(loopback) == 1
    assert oct((leaf / "status.json").stat().st_mode & 0o777) == "0o640"


# -- the unit and the read model -----------------------------------------------------


def test_the_noc_unit_is_passive_unprivileged_and_required_by_nothing():
    from azazel_nexus_runtime.hardening import ALL_PROFILES, SYSTEM_ACCOUNTS, packaged_unit_files
    from azazel_nexus_runtime.principal import DAEMON_ACCOUNTS, SERVICE_ACCOUNTS

    files = dict(packaged_unit_files())
    service = files["azazel-noc-observe.service"]
    assert "User=aznoc" in service and "Type=oneshot" in service
    assert "ExecStart=/usr/libexec/azazel/az-noc-observe\n" in service
    assert "RestrictAddressFamilies=AF_NETLINK AF_UNIX\n" in service
    assert "IPAddressDeny=any" in service and "IPAddressAllow" not in service
    assert "PrivateNetwork" not in service and "CapabilityBoundingSet=\n" in service
    assert "ReadWritePaths=-/var/lib/azazel/run/noc-status\n" in service
    # And the read-only UI's copy of the same snapshot (ADR-0007), nothing else.
    assert "ReadWritePaths=-/var/lib/azazel/run/ui-read/noc\n" in service
    assert service.count("ReadWritePaths=") == 2 and "SupplementaryGroups" not in service
    assert "\n[Install]" not in service
    timer = files["azazel-noc-observe.timer"]
    assert "Unit=azazel-noc-observe.service" in timer and "OnUnitActiveSec=60s" in timer
    for name in ("azazel-noc-observe.service", "azazel-noc-observe.timer"):
        assert (REPO / "packaging/systemd" / name).read_text(encoding="utf-8") == files[name]
    # Its own account: never an operator, never a service principal anywhere.
    assert "aznoc" in SYSTEM_ACCOUNTS and "aznoc" in DAEMON_ACCOUNTS
    assert "aznoc" not in SERVICE_ACCOUNTS
    for profile in ALL_PROFILES:
        assert "azazel-noc-observe" not in " ".join(
            profile.requires + profile.binds_to + profile.after + profile.before)
        if profile.unit != "azazel-noc-observe.service":
            assert "aznoc" not in profile.supplementary_groups
    # Netlink holders: the five that held it before U3, and this observer.
    netlink = sorted(p.unit for p in ALL_PROFILES if "AF_NETLINK" in p.address_families)
    assert netlink == sorted([
        "azazel-activated.service", "azazel-commissiond.service", "azazel-decoy-nsd.service",
        "azazel-decoy-netd.service", "azazel-decoy-verify.service",
        "azazel-noc-observe.service"])


def test_the_installer_creates_the_account_and_leaf_and_enables_nothing():
    installer = (REPO / "packaging/install.sh").read_text(encoding="utf-8")
    assert re.search(r"for account in [^;]* aznoc( [a-z]+)*; do", installer)
    assert "make_owned_dir 2750 aznoc azazel-operator /var/lib/azazel/run/noc-status" in installer
    assert not re.search(r"systemctl (enable|mask|start).*noc", installer)
    assert "noc" not in (REPO / "packaging/azazel-nexus.preset").read_text(encoding="utf-8")


def test_status_json_carries_the_noc_section(root, host, monkeypatch):
    """`status --json` has the section; the text screen does not change."""
    import io
    from datetime import datetime, timezone

    from azazel_nexus.cli import main

    path = paths.noc_status_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(_raw(_observed(host)))
    monkeypatch.setattr("azazel_nexus.edge_package._probe_owner_uid", os.geteuid)
    as_of = datetime.fromtimestamp(NOW + 3, timezone.utc).isoformat().replace("+00:00", "Z")
    out = io.StringIO()
    assert main(["--as-of", as_of, "status", "--json"], out=out) == 0
    view = json.loads(out.getvalue())
    noc = view["sections"]["noc"]
    assert noc["status"] == "observed" and noc["freshness"] == "fresh"
    allowed_top = {"status", "reason_code", "freshness", "conditions", "source", "snapshot", "observation",
                   "not_measured", "role", "identity"}
    assert set(noc) == allowed_top
    assert set(noc["snapshot"]) == {"schema", "written_at", *status_view.NOC_FIELDS}
    for secret in SECRET_STRINGS:
        assert secret not in out.getvalue()
    text = io.StringIO()
    assert main(["--as-of", as_of, "status"], out=text) == 0
    # L8: the text screen names the section's word and code, and nothing of
    # the snapshot below it (no counts, no ifindex, no interface identity).
    lines = [line for line in text.getvalue().splitlines() if "noc" in line.lower()]
    assert lines == ["    passive NOC (noc-observe): observed; written 3 s before as-of"]
    for secret in SECRET_STRINGS:
        assert secret not in text.getvalue()
