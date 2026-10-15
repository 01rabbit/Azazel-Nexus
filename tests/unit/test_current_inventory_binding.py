"""Complete current hardware snapshot binding to retained Fabric evidence."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from azazel_nexus import fabric_boundary as boundary

pytest.importorskip("azazel_fabric")
from azazel_fabric.provisioning_contracts import (  # noqa: E402
    HardwareInventory,
    assert_content_digest,
    content_digest,
)
from azazel_fabric.testing.provisioning import golden_hardware_inventory  # noqa: E402


def _golden_inventory() -> HardwareInventory:
    return HardwareInventory.model_validate(golden_hardware_inventory())


def _with_valid_digest(inventory: HardwareInventory) -> HardwareInventory:
    normalized = HardwareInventory.model_validate(inventory.model_dump(mode="json"))
    digested = normalized.model_copy(
        update={
            "inventory_digest": content_digest(
                normalized, digest_field="inventory_digest"
            )
        }
    )
    assert_content_digest(digested, digest_field="inventory_digest")
    return digested


def _assert_refused(retained: HardwareInventory, current: HardwareInventory) -> None:
    with pytest.raises(boundary.CommissioningRecordUnavailable):
        boundary.assert_current_inventory_matches(retained=retained, current=current)


def test_metadata_only_new_snapshot_matches_without_mutating_inputs():
    retained = _golden_inventory()
    current = retained.model_copy(
        update={
            "inventory_id": "inv-current-2",
            "collected_at": datetime(2026, 9, 2, tzinfo=timezone.utc),
        }
    )
    current = _with_valid_digest(current)
    retained_before = deepcopy(retained.model_dump(mode="json"))
    current_before = deepcopy(current.model_dump(mode="json"))

    boundary.assert_current_inventory_matches(retained=retained, current=current)

    assert retained.model_dump(mode="json") == retained_before
    assert current.model_dump(mode="json") == current_before
    assert retained.inventory_digest != current.inventory_digest


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("node_id", "node-other"),
        ("platform", "OtherVendor"),
        ("storage_devices", ()),
        ("interfaces", ()),
        ("product", "other-product"),  # inventory scope
        ("limitations", ("another-limitation",)),
    ],
)
def test_changed_inventory_content_is_refused_with_a_valid_new_digest(
    field, replacement
):
    retained = _golden_inventory()
    if field == "platform":
        replacement = retained.platform.model_copy(update={"vendor": replacement})
    current = _with_valid_digest(retained.model_copy(update={field: replacement}))
    assert current.inventory_digest != retained.inventory_digest

    _assert_refused(retained, current)


@pytest.mark.parametrize("which", ["retained", "current"])
def test_corrupted_digest_is_refused(which):
    retained = _golden_inventory()
    current = _with_valid_digest(
        retained.model_copy(
            update={
                "inventory_id": "inv-current-2",
                "collected_at": datetime(2026, 9, 2, tzinfo=timezone.utc),
            }
        )
    )
    if which == "retained":
        retained = retained.model_copy(update={"inventory_digest": "sha256:corrupt"})
    else:
        current = current.model_copy(update={"inventory_digest": "sha256:corrupt"})

    _assert_refused(retained, current)


def test_older_observation_time_is_refused():
    retained = _golden_inventory()
    current = _with_valid_digest(
        retained.model_copy(
            update={
                "inventory_id": "inv-current-older",
                "collected_at": datetime(2026, 8, 31, 23, 59, 59, tzinfo=timezone.utc),
            }
        )
    )

    _assert_refused(retained, current)


@pytest.mark.parametrize("which", ["retained", "current"])
def test_wrong_model_type_is_refused(which):
    retained = _golden_inventory()
    current = _with_valid_digest(
        retained.model_copy(
            update={
                "inventory_id": "inv-current-2",
                "collected_at": datetime(2026, 9, 2, tzinfo=timezone.utc),
            }
        )
    )
    if which == "retained":
        retained = retained.model_dump(mode="json")
    else:
        current = current.model_dump(mode="json")

    _assert_refused(retained, current)


def test_missing_fabric_is_refused(monkeypatch):
    retained = _golden_inventory()
    current = _with_valid_digest(
        retained.model_copy(
            update={
                "inventory_id": "inv-current-2",
                "collected_at": datetime(2026, 9, 2, tzinfo=timezone.utc),
            }
        )
    )
    monkeypatch.setattr(boundary, "_import_fabric", lambda: (None, "not installed"))

    _assert_refused(retained, current)
