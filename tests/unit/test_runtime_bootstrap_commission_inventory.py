"""Exact response-shape validation using the real commissiond producer."""

from copy import deepcopy

import pytest

from azazel_nexus.inventory import InterfaceReadout
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.commissiond import MAX_INTERFACES, Snapshot
from azazel_nexus_runtime.bootstrap_commission_inventory import validate_inventory_response


DIGEST = "sha256:" + "a" * 64


def _producer_response():
    snapshot = Snapshot(
        readouts=(InterfaceReadout(
            kernel_name="synthetic0",
            fields={
                "physical_label": "Port A",
                "bus_path": "pci-0000:00:01.0",
                "pci_id": "8086:1234",
                "kernel_name": "must-not-escape",
            },
        ),),
        permanent_macs=(None,),
        digest=DIGEST,
    )
    return {"ok": True, "result": {
        "snapshot": snapshot.digest,
        "interfaces": snapshot.describe(),
    }}


def test_validates_actual_snapshot_describe_output_and_returns_its_digest():
    response = _producer_response()

    assert validate_inventory_response(response) == DIGEST
    assert response["result"]["interfaces"] == [{
        "ordinal": 0,
        "description": {
            "physical_label": "Port A",
            "bus_path": "pci-0000:00:01.0",
            "pci_id": "8086:1234",
        },
        "permanent_mac_readable": False,
    }]


@pytest.mark.parametrize("mutation", [
    "response-extra", "response-not-ok", "result-extra", "digest-uppercase",
    "digest-wrong-prefix", "interfaces-tuple", "interfaces-over-limit",
    "row-extra", "row-missing", "ordinal-bool", "ordinal-gap", "flag-int",
    "description-extra", "description-empty-value", "description-nonstring",
    "description-not-dict",
])
def test_refuses_malformed_or_widened_response(mutation):
    response = deepcopy(_producer_response())
    result = response["result"]
    row = result["interfaces"][0]
    if mutation == "response-extra":
        response["unexpected"] = None
    elif mutation == "response-not-ok":
        response["ok"] = 1
    elif mutation == "result-extra":
        result["unexpected"] = None
    elif mutation == "digest-uppercase":
        result["snapshot"] = "sha256:" + "A" * 64
    elif mutation == "digest-wrong-prefix":
        result["snapshot"] = "a" * 64
    elif mutation == "interfaces-tuple":
        result["interfaces"] = tuple(result["interfaces"])
    elif mutation == "interfaces-over-limit":
        result["interfaces"] = [row] * (MAX_INTERFACES + 1)
    elif mutation == "row-extra":
        row["kernel_name"] = "synthetic0"
    elif mutation == "row-missing":
        del row["description"]
    elif mutation == "ordinal-bool":
        row["ordinal"] = True
    elif mutation == "ordinal-gap":
        row["ordinal"] = 1
    elif mutation == "flag-int":
        row["permanent_mac_readable"] = 1
    elif mutation == "description-extra":
        row["description"]["kernel_name"] = "synthetic0"
    elif mutation == "description-empty-value":
        row["description"]["serial"] = ""
    elif mutation == "description-nonstring":
        row["description"]["serial"] = 7
    elif mutation == "description-not-dict":
        row["description"] = []

    with pytest.raises(ApprovalRefused):
        validate_inventory_response(response)


def test_accepts_empty_inventory_and_empty_producer_description():
    response = {
        "ok": True,
        "result": {"snapshot": DIGEST, "interfaces": []},
    }
    assert validate_inventory_response(response) == DIGEST

    response["result"]["interfaces"].append({
        "ordinal": 0,
        "description": {},
        "permanent_mac_readable": False,
    })
    assert validate_inventory_response(response) == DIGEST
