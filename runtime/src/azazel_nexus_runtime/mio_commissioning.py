"""Read a signed commissioning ceiling, without admitting any provider."""

import json

from azazel_nexus.commissioning_approval import verify_retained_commissioning_proposal
from azazel_nexus.commissioning_draft import DraftRefused, read_mio_profile_review_inputs
from azazel_nexus.fabric_boundary import CommissioningRecordUnavailable
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import ApprovalRefused

from .node_config import NodeConfigUnavailable, load_declared_node

_PROFILES = {"CORE": MioProfile.CORE, "LITE": MioProfile.LOCAL_ONLY,
             "FULL": MioProfile.FASTEST_PERMITTED}


def commissioned_profile() -> MioProfile:
    """Verify on every read so revocation and node changes narrow immediately.

    Historical confirmation suffices only for a ceiling. It proves neither
    current hardware nor admission, and a v1 proposal has no M.I.O. choice.
    The existing verifier also refuses lab hosts; no test state is promoted.
    """
    try:
        node = load_declared_node()
        trust = load_operator_trust()
        expected, payload, signature = read_mio_profile_review_inputs()
        document = json.loads(expected)
        operator = document["operator"]
        verify_retained_commissioning_proposal(
            trust=trust, payload=payload, signature=signature,
            expected_payload=expected, operator=operator, node_id=node.node_id,
        )
        if (load_declared_node() != node or load_operator_trust() != trust
                or read_mio_profile_review_inputs() != (expected, payload, signature)):
            return MioProfile.CORE
        if document["schema"] != "azazel-nexus/commissioning-proposal/v2":
            return MioProfile.CORE
        return _PROFILES[document["mio_profile"]]
    except (ApprovalRefused, DraftRefused, CommissioningRecordUnavailable,
            NodeConfigUnavailable, OSError, ValueError, TypeError, KeyError,
            AttributeError, RecursionError):
        return MioProfile.CORE
