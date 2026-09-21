"""The ordinal is not the identification; the ordinal plus the digest is (#38).

An operator picks a row from a list. The row number alone means nothing: the
kernel may enumerate differently next boot, an adapter may be unplugged
between the listing and the confirmation, and two reads of a moving table are
two tables.

So a request carries the ordinal **and the digest of the enumeration it was
chosen from**, and the daemon re-enumerates and compares. A mismatch is
refused and the operator is asked to look again -- never silently re-resolved
against the new list, which is how a confirmation for one adapter reaches
another.

The other rule this file is about: **there is no fallback to the current
MAC.** `docs/commissioning.md` §3 forbids resolving an assignment from an
address a bond, a randomisation or an attacker can change, and a quiet
fallback here would be exactly that, one layer down and harder to see.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from azazel_nexus_runtime.commissiond import (
    MAX_INTERFACES,
    REGISTRY,
    VERBS,
    CommissionService,
    Snapshot,
    build_snapshot,
)
from azazel_nexus_runtime.netlink import LinkRecord
from azazel_nexus_runtime.principal import Principal, PrincipalClass
from azazel_nexus_runtime.protocol import RequestRefused
from azazel_nexus_runtime.transport import Request

CURRENT_MAC = "02:de:ad:be:ef:01"
PERMANENT_MAC = "aa:bb:cc:dd:ee:ff"

OPERATOR = Principal(uid=1000, gid=1000, pid=42, classes=frozenset({PrincipalClass.OPERATOR}))


def _tree(tmp_path: Path, names=("enp4s0", "enp5s0")) -> Path:
    """A sysfs tree whose interfaces carry a *current* MAC.

    Present on purpose. A tree without one lets a fallback to it go
    unnoticed, which is precisely the mistake `test_inventory.py` records
    having caught once already.
    """

    root = tmp_path / "sys"
    net = root / "class" / "net"
    for index, name in enumerate(names):
        slot = f"0000:0{index + 4}:00.0"
        bus = root / "devices" / "pci0000:00" / slot
        bus.mkdir(parents=True)
        (bus / "vendor").write_text("0x8086\n")
        (bus / "device").write_text(f"0x15b{index}\n")
        (bus / "label").write_text(f"LAN{index + 1}\n")
        interface = net / name
        interface.mkdir(parents=True)
        (interface / "device").symlink_to(f"../../../devices/pci0000:00/{slot}")
        (interface / "address").write_text(CURRENT_MAC + "\n")
    return net


def _links(*pairs) -> list[LinkRecord]:
    records = []
    for index, (name, mac) in enumerate(pairs, start=1):
        if mac is None:
            records.append(
                LinkRecord(index, name, None, reason="the driver reports no permanent address")
            )
        else:
            records.append(LinkRecord(index, name, mac))
    return records


def _service(tmp_path, links, names=("enp4s0", "enp5s0")) -> CommissionService:
    net = _tree(tmp_path, names)
    return CommissionService(sysfs=net, read_links_fn=lambda: links)


def _request(verb_name: str, arguments: dict) -> Request:
    verb = REGISTRY.resolve(verb_name, OPERATOR)
    return Request(verb=verb, arguments=verb.bind(arguments), principal=OPERATOR)


# -- the verb table ------------------------------------------------------


def test_the_daemon_declares_two_verbs_and_neither_changes_anything():
    assert sorted(verb.name for verb in VERBS) == [
        "commission.inventory",
        "commission.permanent_mac",
    ]


def test_no_verb_takes_anything_but_a_digest_and_an_ordinal():
    """No path, no unit name, no interface name. Nothing a caller composes."""

    for verb in VERBS:
        for argument in verb.arguments:
            assert argument.kind.value in {"digest", "ordinal"}


# -- the snapshot binds an ordinal to an identity ------------------------


def test_a_snapshot_digests_the_composite_identities_in_order(tmp_path):
    links = _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None))
    first = build_snapshot(sysfs=_tree(tmp_path / "a"), links=links)
    second = build_snapshot(sysfs=_tree(tmp_path / "b"), links=links)
    assert first.digest == second.digest


def test_an_adapter_swapped_in_the_same_slot_changes_the_digest(tmp_path):
    """Otherwise the ordinal points at a different device saying it is the same.

    The permanent address is part of what the digest covers precisely for
    this: the bus path and the ids can be identical for a replacement.
    """

    net = _tree(tmp_path)
    before = build_snapshot(sysfs=net, links=_links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)))
    after = build_snapshot(
        sysfs=net, links=_links(("enp4s0", "12:22:33:44:55:66"), ("enp5s0", None))
    )
    assert before.digest != after.digest


def test_an_interface_appearing_changes_the_digest(tmp_path):
    two = build_snapshot(
        sysfs=_tree(tmp_path / "two"),
        links=_links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)),
    )
    three = build_snapshot(
        sysfs=_tree(tmp_path / "three", names=("enp4s0", "enp5s0", "enp6s0")),
        links=_links(("enp4s0", PERMANENT_MAC), ("enp5s0", None), ("enp6s0", None)),
    )
    assert two.digest != three.digest


def test_a_snapshot_whose_halves_disagree_cannot_be_built():
    with pytest.raises(ValueError):
        Snapshot(readouts=(), permanent_macs=(None,), digest="sha256:" + "0" * 64)


# -- what an operator sees -----------------------------------------------


def test_the_rows_never_carry_a_kernel_name(tmp_path):
    service = _service(tmp_path, _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)))
    result = service.handle(_request("commission.inventory", {}))
    rendered = repr(result)
    for name in ("enp4s0", "enp5s0"):
        assert name not in rendered


def test_the_rows_say_whether_an_address_could_be_read(tmp_path):
    """Before the operator confirms, not after.

    An operator who confirms a role against an interface whose permanent
    address cannot be read has spent the confirmation on something that will
    be refused.
    """

    service = _service(tmp_path, _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)))
    result = service.handle(_request("commission.inventory", {}))
    assert [row["permanent_mac_readable"] for row in result["interfaces"]] == [
        True,
        False,
    ]


def test_the_inventory_carries_the_digest_the_next_request_must_quote(tmp_path):
    service = _service(tmp_path, _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)))
    listing = service.handle(_request("commission.inventory", {}))
    answer = service.handle(
        _request(
            "commission.permanent_mac",
            {"snapshot": listing["snapshot"], "ordinal": 0},
        )
    )
    assert answer == {
        "readable": True,
        "permanent_mac": PERMANENT_MAC,
        "snapshot": listing["snapshot"],
    }


# -- a stale snapshot is refused, not re-resolved ------------------------


def test_a_request_quoting_a_stale_snapshot_is_refused(tmp_path):
    """The operator confirmed a row in a list that no longer describes this host."""

    links = [_links(("enp4s0", PERMANENT_MAC), ("enp5s0", None))]
    service = CommissionService(
        sysfs=_tree(tmp_path), read_links_fn=lambda: links[0]
    )
    listing = service.handle(_request("commission.inventory", {}))

    # The adapter in the first slot is replaced.
    links[0] = _links(("enp4s0", "12:22:33:44:55:66"), ("enp5s0", None))
    answer = service.handle(
        _request(
            "commission.permanent_mac",
            {"snapshot": listing["snapshot"], "ordinal": 0},
        )
    )
    assert answer["readable"] is False
    assert answer["reason"] == "inventory_changed"


def test_a_stale_request_is_not_answered_from_the_new_enumeration(tmp_path):
    """The refusal must not leak the address the ordinal now points at.

    Answering it would be applying a confirmation made about one adapter to
    whichever adapter happens to occupy that position now.
    """

    links = [_links(("enp4s0", PERMANENT_MAC), ("enp5s0", None))]
    service = CommissionService(
        sysfs=_tree(tmp_path), read_links_fn=lambda: links[0]
    )
    listing = service.handle(_request("commission.inventory", {}))
    replacement = "12:22:33:44:55:66"
    links[0] = _links(("enp4s0", replacement), ("enp5s0", None))

    answer = service.handle(
        _request(
            "commission.permanent_mac",
            {"snapshot": listing["snapshot"], "ordinal": 0},
        )
    )
    assert replacement not in repr(answer)
    assert "permanent_mac" not in answer


def test_the_refusal_carries_the_digest_to_read_against_now(tmp_path):
    links = [_links(("enp4s0", PERMANENT_MAC), ("enp5s0", None))]
    service = CommissionService(sysfs=_tree(tmp_path), read_links_fn=lambda: links[0])
    stale = "sha256:" + "0" * 64
    answer = service.handle(
        _request("commission.permanent_mac", {"snapshot": stale, "ordinal": 0})
    )
    assert answer["snapshot"] != stale
    assert "read the inventory again" in answer["detail"].lower()


# -- no fallback to the current MAC --------------------------------------


def test_an_interface_with_no_permanent_address_is_refused(tmp_path):
    service = _service(tmp_path, _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)))
    listing = service.handle(_request("commission.inventory", {}))
    answer = service.handle(
        _request(
            "commission.permanent_mac",
            {"snapshot": listing["snapshot"], "ordinal": 1},
        )
    )
    assert answer["readable"] is False
    assert answer["reason"] == "no_permanent_address"


def test_the_current_mac_appears_nowhere_in_the_answer(tmp_path):
    """The sysfs tree carries one, and it is not what a role may bind to.

    A fallback would be resolved by whatever set the address last, which on a
    bond is the bond and on a hostile network is the attacker.
    """

    service = _service(tmp_path, _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None)))
    listing = service.handle(_request("commission.inventory", {}))
    assert CURRENT_MAC not in repr(listing)

    for ordinal in (0, 1):
        answer = service.handle(
            _request(
                "commission.permanent_mac",
                {"snapshot": listing["snapshot"], "ordinal": ordinal},
            )
        )
        assert CURRENT_MAC not in repr(answer)


def test_a_host_where_nothing_reports_an_address_reports_that(tmp_path):
    """Which is the state this build leaves a real host in (`HG-04`)."""

    service = _service(tmp_path, _links(("enp4s0", None), ("enp5s0", None)))
    listing = service.handle(_request("commission.inventory", {}))
    assert not any(row["permanent_mac_readable"] for row in listing["interfaces"])


# -- the enumeration is taken fresh --------------------------------------


def test_every_request_re_enumerates(tmp_path):
    """A cached enumeration describes the host at the moment it was cached.

    And the request it would answer is the one asking whether the host still
    looks that way.
    """

    reads = []
    links = _links(("enp4s0", PERMANENT_MAC), ("enp5s0", None))

    def counting():
        reads.append(1)
        return links

    service = CommissionService(sysfs=_tree(tmp_path), read_links_fn=counting)
    service.handle(_request("commission.inventory", {}))
    service.handle(_request("commission.inventory", {}))
    assert len(reads) == 2


def test_an_ordinal_beyond_the_declared_ceiling_never_reaches_the_daemon():
    """The protocol refuses it, so the handler is not where that is decided."""

    with pytest.raises(RequestRefused):
        _request(
            "commission.permanent_mac",
            {"snapshot": "sha256:" + "0" * 64, "ordinal": MAX_INTERFACES},
        )


def test_a_netlink_failure_is_a_refusal_rather_than_an_empty_inventory(tmp_path):
    """Reporting no interfaces would be a sentence an operator acts on."""

    from azazel_nexus_runtime.netlink import NetlinkUnavailable

    def unavailable():
        raise NetlinkUnavailable("no netlink in this namespace")

    service = CommissionService(sysfs=_tree(tmp_path), read_links_fn=unavailable)
    with pytest.raises(RequestRefused):
        service.handle(_request("commission.inventory", {}))
