"""The NOC snapshot operators read (U3): a closed projection of `az-nexus-noc`.

`azazel_nexus_runtime.noc_observe.collect` is the passive observation
(`docs/noc-observation.md`): one `AF_NETLINK` dump of links, addresses and
routes, sysfs counters, the resolver files and DHCP lease files, every field
with its evidence and a fixed `unknown` reason. `az-noc-observe` runs it once
per `azazel-noc-observe.timer` period and writes this projection into
`/var/lib/azazel/run/noc-status/status.json` (`2750 azobs:azazel-operator`),
the same way the other operator snapshots are written (`operator_snapshots`).

The projection keeps what an operator screen needs and nothing that
identifies the node's network: interfaces by kernel ifindex only (no name,
no MAC, no address), addresses and nameservers counted, routes counted per
table and family, the default routes' egress ifindexes, counters and their
deltas, DHCP lease remaining time, each field's age at observation, and the
fixed reason for anything not observed. Whether a resolver answers or a
gateway replies is never observed here -- no probe is sent -- and is always
`unknown` / `active_check_not_performed`: "not measured", never "down".

`project` builds the snapshot from `collect`'s output and `read_noc_status`
refuses anything outside it; both use the same checks.
"""

from __future__ import annotations

import json
import math
from typing import Any, Callable, Optional

from .operator_snapshots import _decode, _guard

__all__ = [
    "ACTIVE_CHECK_FIELDS",
    "MAX_INTERFACES",
    "NOC_BYTES",
    "NOC_INTERVAL_S",
    "NOC_SCHEMA",
    "NOC_STALE_S",
    "UNKNOWN_REASONS",
    "failed",
    "project",
    "read_noc_status",
]

NOC_SCHEMA = "azazel-nexus/noc-status/v1"
NOC_BYTES = 65536
#: `azazel-noc-observe.timer` runs the observer this often.
NOC_INTERVAL_S = 60
NOC_STALE_S = 300
#: More interfaces than this are counted (`interfaces_omitted`), not listed.
MAX_INTERFACES = 32
#: `noc_observe.UNKNOWN_REASONS`, by code (a test keeps the two equal).
UNKNOWN_REASONS = frozenset({
    "netlink_unavailable", "netlink_malformed", "socket_not_netlink", "not_reported",
    "file_absent", "read_failed", "file_not_regular", "file_unparsable",
    "interface_name_unsafe", "speed_not_reported", "counters_unavailable", "no_lease_file",
    "role_evidence_not_provided", "role_withheld", "role_not_in_resolved_set",
    "active_check_not_performed", "nexthop_object_not_resolved", "wall_clock_implausible",
})
#: Why a whole observation is absent.
COLLECTION_REASONS = ("collection_failed", "projection_refused")
#: Fields that only an active probe could answer; always unknown here.
ACTIVE_CHECK_FIELDS = ("uplink.reachability", "dns.resolution")
OPERSTATES = frozenset({"kernel_unknown", "notpresent", "down", "lowerlayerdown", "testing",
                        "dormant", "up", "kernel_unrecognised"})
COUNTERS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
            "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")
RESOLV_KINDS = frozenset({"regular_file", "symlink_systemd_resolved_stub",
                          "symlink_systemd_resolved_upstream", "symlink_other"})
DHCP_CLIENTS = frozenset({"systemd-networkd", "dhclient"})
_U64 = 2**64 - 1
_I64 = 2**63 - 1
_KEYS = ("schema", "written_at", "collection", "reason_code", "observed_at", "active_checks",
         "interfaces", "interfaces_omitted", "uplink", "routes", "dns")


class _Refused(ValueError):
    pass


# -- value checks (shared by the projection and the reader) -----------------


def _need(condition) -> None:
    if not condition:
        raise _Refused("shape")


def _int(value, lo=0, hi=_U64) -> None:
    _need(type(value) is int and lo <= value <= hi)


def _num(value) -> None:
    _need(type(value) in (int, float) and math.isfinite(value) and value >= 0)


def _opt(check):
    def run(value):
        if value is not None:
            check(value)
    return run


def _bool(value) -> None:
    _need(type(value) is bool)


def _exact(value, keys) -> None:
    _need(type(value) is dict and set(value) == set(keys))


def _field(value, check, *, observable=True) -> None:
    _exact(value, ("state", "value", "reason", "age_s"))
    _num(value["age_s"])
    if value["state"] == "observed":
        _need(observable and value["reason"] is None)
        check(value["value"])
    else:
        _need(value["state"] == "unknown" and value["value"] is None
              and value["reason"] in UNKNOWN_REASONS)
        if not observable:
            _need(value["reason"] == "active_check_not_performed")


def _family_counts(value) -> None:
    _exact(value, ("ipv4", "ipv6"))
    _int(value["ipv4"], hi=_I64)
    _int(value["ipv6"], hi=_I64)


def _counters(value) -> None:
    _exact(value, COUNTERS)
    for key in COUNTERS:
        _int(value[key])


_QUALITY = ("interval_s", "reset_counters", "rx_bps", "tx_bps", "rx_errors_delta",
            "tx_errors_delta", "rx_dropped_delta", "tx_dropped_delta", "tx_packets_delta",
            "rx_utilisation", "tx_utilisation")


def _quality(value) -> None:
    _exact(value, _QUALITY)
    _num(value["interval_s"])
    _need(type(value["reset_counters"]) is list
          and all(item in COUNTERS for item in value["reset_counters"])
          and value["reset_counters"] == sorted(set(value["reset_counters"])))
    for key in ("rx_bps", "tx_bps", "rx_utilisation", "tx_utilisation"):
        _opt(_num)(value[key])
    for key in ("rx_errors_delta", "tx_errors_delta", "rx_dropped_delta",
                "tx_dropped_delta", "tx_packets_delta"):
        _opt(_int)(value[key])


def _dhcp(value) -> None:
    _exact(value, ("client", "remaining_s", "expired", "expires_never"))
    _need(value["client"] in DHCP_CLIENTS)
    _opt(lambda item: _int(item, lo=-_I64, hi=_I64))(value["remaining_s"])
    _bool(value["expired"])
    _bool(value["expires_never"])
    _need((value["remaining_s"] is None) == value["expires_never"])


_INTERFACE = ("ifindex", "loopback", "admin_up", "lower_up", "operstate", "carrier", "mtu",
              "addresses", "speed_mbps", "counters", "quality", "dhcp")


def _interface(value) -> None:
    _exact(value, _INTERFACE)
    _int(value["ifindex"], lo=1, hi=2**31 - 1)
    for key in ("loopback", "admin_up", "lower_up", "carrier"):
        _field(value[key], _bool)
    _field(value["operstate"], lambda item: _need(item in OPERSTATES))
    _field(value["mtu"], lambda item: _int(item, hi=2**32 - 1))
    _field(value["addresses"], _family_counts)
    _field(value["speed_mbps"], lambda item: _int(item, lo=1, hi=2**32 - 1))
    _field(value["counters"], _counters)
    _field(value["quality"], _quality)
    _field(value["dhcp"], _dhcp)


def _interfaces(value) -> None:
    _need(type(value) is list and len(value) <= MAX_INTERFACES)
    for item in value:
        _interface(item)
    indexes = [item["ifindex"] for item in value]
    _need(indexes == sorted(set(indexes)))


_DEFAULTS = ("default_routes", "egress_ifindex", "via_gateway", "linkdown", "dead")


def _defaults(value, extra=()) -> None:
    _exact(value, _DEFAULTS + extra)
    _int(value["default_routes"], hi=_I64)
    _need(type(value["egress_ifindex"]) is list and len(value["egress_ifindex"]) <= 256)
    for index in value["egress_ifindex"]:
        _int(index, lo=0, hi=2**32 - 1)
    _need(value["egress_ifindex"] == sorted(set(value["egress_ifindex"])))
    for key in ("via_gateway", "linkdown", "dead"):
        _bool(value[key])
    if extra:
        _int(value["tables"], hi=_I64)


def _uplink_family(value) -> None:
    _exact(value, ("table_main", "other_tables", "policy_rules_evaluated"))
    _defaults(value["table_main"])
    _defaults(value["other_tables"], ("tables",))
    _need(value["policy_rules_evaluated"] is False)


def _uplink(value) -> None:
    _exact(value, ("ipv4", "ipv6", "reachability"))
    _field(value["ipv4"], _uplink_family)
    _field(value["ipv6"], _uplink_family)
    _field(value["reachability"], None, observable=False)


def _routes(value) -> None:
    _exact(value, ("table_main", "other_tables"))
    _family_counts(value["table_main"])
    _family_counts(value["other_tables"])


def _resolv(value) -> None:
    _exact(value, ("kind", "nameservers", "loopback_nameservers", "search_domains"))
    _need(value["kind"] in RESOLV_KINDS)
    for key in ("nameservers", "loopback_nameservers", "search_domains"):
        _int(value[key], hi=_I64)


def _dns(value) -> None:
    _exact(value, ("resolv_conf", "systemd_resolved_upstream", "resolution"))
    _field(value["resolv_conf"], _resolv)
    _field(value["systemd_resolved_upstream"],
           lambda item: (_exact(item, ("nameservers",)), _int(item["nameservers"], hi=_I64)))
    _field(value["resolution"], None, observable=False)


def _check(value) -> None:
    _exact(value, _KEYS)
    _need(value["active_checks"] == "none")
    if value["collection"] == "failed":
        _need(value["reason_code"] in COLLECTION_REASONS
              and all(value[key] is None for key in ("observed_at", "interfaces",
                                                     "interfaces_omitted", "uplink",
                                                     "routes", "dns")))
        return
    _need(value["collection"] == "observed" and value["reason_code"] is None)
    _num(value["observed_at"])
    _field(value["interfaces"], _interfaces)
    _int(value["interfaces_omitted"], hi=_I64)
    _uplink(value["uplink"])
    _field(value["routes"], _routes)
    _dns(value["dns"])


# -- the projection ------------------------------------------------------------


def _age(rendered) -> float:
    age = rendered["evidence"]["age_s"]
    _num(age)
    return float(age)


def _f(rendered, project: Optional[Callable[[Any], Any]]) -> dict:
    """One rendered `noc_observe` field, as `{state, value, reason, age_s}`."""

    if rendered["state"] == "observed":
        return {"state": "observed", "value": project(rendered["value"]),
                "reason": None, "age_s": _age(rendered)}
    return {"state": "unknown", "value": None, "reason": rendered["reason"],
            "age_s": _age(rendered)}


def _addresses(value) -> dict:
    return {family: sum(value.get(family, {}).values()) for family in ("ipv4", "ipv6")}


def _project_quality(value) -> dict:
    return {key: value[key] for key in _QUALITY}


def _project_dhcp(value) -> dict:
    return {"client": value["client"], "remaining_s": value["remaining_s"],
            "expired": value["expired"], "expires_never": bool(value.get("expires_never", False))}


def _project_interface(item) -> dict:
    same = lambda value: value  # noqa: E731 - checked afterwards
    return {
        "ifindex": item["ifindex"],
        **{key: _f(item[key], same) for key in ("loopback", "admin_up", "lower_up",
                                                 "operstate", "carrier", "mtu", "speed_mbps")},
        "addresses": _f(item["addresses"], _addresses),
        "counters": _f(item["counters"], lambda value: {k: value[k] for k in COUNTERS}),
        "quality": _f(item["quality"], _project_quality),
        "dhcp": _f(item["dhcp"], _project_dhcp),
    }


def _project_family(value) -> dict:
    return {"table_main": {key: value["table_main"][key] for key in _DEFAULTS},
            "other_tables": {key: value["other_tables"][key]
                             for key in (*_DEFAULTS, "tables")},
            "policy_rules_evaluated": value["policy_rules_evaluated"]}


def failed(written_at: float, reason: str = "collection_failed") -> dict:
    """The snapshot of an observation that could not be made or projected."""

    return {"schema": NOC_SCHEMA, "written_at": written_at, "collection": "failed",
            "reason_code": reason, "observed_at": None, "active_checks": "none",
            "interfaces": None, "interfaces_omitted": None, "uplink": None, "routes": None,
            "dns": None}


def project(observation: dict, written_at: float) -> dict:
    """`noc_observe.collect`'s output as `noc-status/v1`, or `failed(...)`.

    Copied field by field; nothing is passed through whole, so a field the
    observation grows does not reach operators until it is listed here.
    """

    try:
        interfaces = observation["interfaces"]
        omitted = 0
        if isinstance(interfaces, list):
            listed = sorted(interfaces, key=lambda item: item["ifindex"])
            omitted = max(0, len(listed) - MAX_INTERFACES)
            projected_interfaces = {"state": "observed", "age_s": 0.0, "reason": None,
                                    "value": [_project_interface(item)
                                              for item in listed[:MAX_INTERFACES]]}
            ages = [item["admin_up"]["evidence"]["age_s"] for item in listed]
            projected_interfaces["age_s"] = float(max(ages)) if ages else 0.0
        else:
            projected_interfaces = _f(interfaces, None)
        uplink = observation["uplink"]
        dns = observation["dns"]
        value = {
            "schema": NOC_SCHEMA, "written_at": written_at, "collection": "observed",
            "reason_code": None, "observed_at": written_at, "active_checks": "none",
            "interfaces": projected_interfaces,
            "interfaces_omitted": omitted,
            "uplink": {"ipv4": _f(uplink["ipv4"], _project_family),
                       "ipv6": _f(uplink["ipv6"], _project_family),
                       "reachability": _f(uplink["reachability"], None)},
            "routes": _f(observation["routes"], lambda item: {
                where: {family: item[where][family] for family in ("ipv4", "ipv6")}
                for where in ("table_main", "other_tables")}),
            "dns": {"resolv_conf": _f(dns["resolv_conf"], lambda item: {
                        key: item[key] for key in ("kind", "nameservers",
                                                   "loopback_nameservers", "search_domains")}),
                    "systemd_resolved_upstream": _f(dns["systemd_resolved_upstream"],
                                                    lambda item: {"nameservers":
                                                                  item["nameservers"]}),
                    "resolution": _f(dns["resolution"], None)},
        }
        _check(value)
        if len(json.dumps(value, sort_keys=True, separators=(",", ":"))) + 1 > NOC_BYTES:
            raise _Refused("size")
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        return failed(written_at, "projection_refused")


def read_noc_status(raw) -> Optional[dict]:
    """Decode the NOC snapshot, or `None` outside its closed shape."""

    def read():
        value = _decode(raw, NOC_BYTES, _KEYS, NOC_SCHEMA)
        _check(value)
        return value
    return _guard(read)
