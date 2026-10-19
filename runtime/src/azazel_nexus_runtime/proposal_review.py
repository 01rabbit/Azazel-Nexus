"""Historical detached approval review; no authoritative-record promotion."""

import json
import sys

from azazel_nexus.commissioning_approval import verify_retained_commissioning_proposal
from azazel_nexus.commissioning_draft import DraftRefused, read_proposal_review_inputs
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus.fabric_boundary import (
    CommissioningRecordUnavailable, assert_current_inventory_matches,
    project_hardware_inventory, restore_commissioning_inputs,
)

from .node_config import NodeConfigUnavailable, load_declared_node
from .hardware_inventory import HardwareUnavailable, collect_hardware_observations
from .netlink import NetlinkMalformed, NetlinkUnavailable


def run(operator: str, *, current_hardware: bool = False, addresses=None) -> int:
    """Read only fixed protected originals and a detached 64-byte signature.

    External input supplies no record, node identity or enrolled key. Recheck
    protected state before publishing the approval result. An explicit current
    hardware check recollects the whole snapshot; it does not claim an atomic
    trusted-host state or current resource/capture/isolation readiness.
    """
    from azazel_nexus.lab_host import is_lab_host

    if is_lab_host():
        print("refused: LAB_HOST_MARKER", file=sys.stderr)
        return 2
    try:
        node = load_declared_node()
        trust = load_operator_trust()
        expected, payload, signature = read_proposal_review_inputs()
        verify_retained_commissioning_proposal(
            trust=trust, payload=payload, signature=signature,
            expected_payload=expected, operator=operator, node_id=node.node_id,
        )
        if current_hardware:
            if addresses is None:
                raise HardwareUnavailable("permanent-address reader required")
            observed = collect_hardware_observations(permanent_mac_reader=addresses)
            current = project_hardware_inventory(
                readouts=observed.interfaces, platform=observed.platform,
                storage_devices=observed.storage_devices, limitations=observed.limitations,
                node_id=node.node_id, inventory_id="current-review-observation",
                collected_at=observed.collected_at,
            )
            context = restore_commissioning_inputs(json.loads(expected))
            assert_current_inventory_matches(retained=context["inventory"], current=current)
            if not addresses.unchanged():
                raise HardwareUnavailable("link snapshot changed")
            latest = collect_hardware_observations(permanent_mac_reader=addresses)
            if not all(getattr(latest, field) == getattr(observed, field) for field in (
                "interfaces", "platform", "storage_devices", "limitations", "excluded_loopbacks"
            )) or not addresses.unchanged():
                raise HardwareUnavailable("hardware snapshot changed")
        if (load_declared_node() != node or load_operator_trust() != trust
                or read_proposal_review_inputs() != (expected, payload, signature)):
            raise ApprovalRefused("protected proposal state changed")
    except (ApprovalRefused, DraftRefused, NodeConfigUnavailable, CommissioningRecordUnavailable,
            HardwareUnavailable, NetlinkMalformed, NetlinkUnavailable, OSError):
        print("Full proposal review refused. Check retained inputs and enrollment locally; nothing activated.",
              file=sys.stderr)
        return 1
    if current_hardware:
        print("Full proposal signature verified; current hardware fields match retained evidence. Resource freshness, trusted time, policy and activation remain unverified.")
    else:
        print("Full proposal signature verified against retained local expectations. Historical approval only; current hardware, freshness and activation remain unverified.")
    return 0
