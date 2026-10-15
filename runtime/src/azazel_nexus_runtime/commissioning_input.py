"""Fixed-path authenticated full evidence loader for the activation composition."""

import json

from azazel_nexus.commissioning_approval import verify_retained_commissioning_proposal
from azazel_nexus.commissioning_draft import DraftRefused, read_proposal_review_inputs
from azazel_nexus.commissioning_evidence import (
    CommissioningEvidence, load_commissioning_binding_key, verify_commissioning_evidence,
)
from azazel_nexus.fabric_boundary import CommissioningRecordUnavailable, project_hardware_inventory
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import ApprovalRefused

from .commission_cli import _PermanentAddresses
from .hardware_inventory import HardwareUnavailable, collect_hardware_observations
from .netlink import NetlinkMalformed, NetlinkUnavailable
from .node_config import NodeConfigUnavailable, load_declared_node


def load_commissioning_evidence() -> CommissioningEvidence:
    """No persistent verified flag, imported paths, key generation or admission."""
    try:
        node = load_declared_node()
        trust = load_operator_trust()
        key = load_commissioning_binding_key()
        expected, payload, signature = read_proposal_review_inputs()
        # Protected retained bytes supply only the key lookup label. The same
        # label must pass canonical reconstruction and enrolled-key verification.
        operator = json.loads(expected)["operator"]
        verify_retained_commissioning_proposal(trust=trust, expected_payload=expected,
            payload=payload, signature=signature, operator=operator, node_id=node.node_id)
        addresses = _PermanentAddresses()
        observed = collect_hardware_observations(permanent_mac_reader=addresses)
        current = project_hardware_inventory(readouts=observed.interfaces,
            platform=observed.platform, storage_devices=observed.storage_devices,
            limitations=observed.limitations, node_id=node.node_id,
            inventory_id="activation-current-observation", collected_at=observed.collected_at)
        evidence = verify_commissioning_evidence(trust=trust, expected_payload=expected,
            payload=payload, signature=signature, node_id=node.node_id,
            current_inventory=current, protection_key=key)
        if not addresses.unchanged():
            raise ApprovalRefused("link snapshot changed")
        latest = collect_hardware_observations(permanent_mac_reader=addresses)
        if not all(getattr(latest, field) == getattr(observed, field) for field in (
            "interfaces", "platform", "storage_devices", "limitations", "excluded_loopbacks"
        )) or not addresses.unchanged():
            raise ApprovalRefused("hardware snapshot changed")
        if (load_declared_node() != node or load_operator_trust() != trust
                or load_commissioning_binding_key() != key
                or read_proposal_review_inputs() != (expected, payload, signature)):
            raise ApprovalRefused("protected evidence inputs changed")
        return evidence
    except (ApprovalRefused, DraftRefused, CommissioningRecordUnavailable,
            HardwareUnavailable, NetlinkMalformed, NetlinkUnavailable,
            NodeConfigUnavailable, OSError, ValueError, TypeError, KeyError, RecursionError):
        raise ApprovalRefused("authenticated commissioning evidence unavailable") from None
