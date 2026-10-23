"""Interactive protected full-proposal export; no signing or service admission.

**The Deception Lite exposure scope** (#196, `docs/deception-exposure-grant.md`
§4.1, S1). Only when the signed draft assigns at least one interface the
role `deception_bridge`, the export asks, after the M.I.O. ceiling, for the
approved IPv4 source prefixes. Empty keeps the v2 proposal exactly as
before. Otherwise the section (the fixed bridge prefix, confirmed and
printed, the prefixes as typed, the ingress role) is decoded whole by
`decoy_scope.decode_deception_scope` against this proposal's own roles and
refused whole on any departure; the prefixes and the number of ingress
interfaces are printed, and the operator types `EXPOSE` before `EXPORT`.
The proposal is then `commissioning-proposal/v3`, signed with the same
purpose by the same separate full-proposal signature. Nothing is granted:
the activation pass reads the scope only with a v3 approval naming the
exposure tier (G6).
"""

from datetime import datetime, timezone
import sys
from uuid import uuid4

from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.decoy_scope import (
    BRIDGE_PREFIX,
    INGRESS_ROLE,
    DecoyScopeRefused,
    decode_deception_scope,
    render_deception_scope,
)
from azazel_nexus.commissioning_draft import (
    DraftInputRefused, DraftRefused, retain_proposal_context, read_draft_review_inputs,
)
from azazel_nexus.fabric_boundary import (
    CommissioningRecordUnavailable, IdentityUnavailable, deception_scope_assignments,
    project_hardware_inventory, project_resource_profile, project_reviewed_topology,
)
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import ApprovalRefused

from .hardware_inventory import HardwareUnavailable, collect_hardware_observations
from .netlink import NetlinkMalformed, NetlinkUnavailable
from .node_config import NodeConfigUnavailable, load_declared_node
from .resource_assessment import assess_resources


def _now():
    # An assembly timestamp, not a trusted-clock or freshness attestation.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: The prompts of the exposure scope, fixed (the rehearsal drives them).
SCOPE_PROMPT = ("Deception Lite exposure: approved IPv4 source prefixes "
                "(comma-separated), or empty for none: ")
EXPOSE_PROMPT = ("Make a Deception Lite decoy reachable from these sources on the "
                 "deception_bridge interfaces once activation approves it? Type EXPOSE: ")


def _deception_scope(inventory, topology):
    """The operator's scope section, or None for none; refused whole otherwise."""
    if not any(assignment.role == INGRESS_ROLE
               for assignment in topology.commissioned_assignments):
        return None
    text = input(SCOPE_PROMPT).strip()
    if not text:
        return None
    section = {"approved_v4": [part.strip() for part in text.split(",")],
               "bridge_prefix": BRIDGE_PREFIX, "ingress_role": INGRESS_ROLE}
    try:
        scope = decode_deception_scope(section, assignments=deception_scope_assignments(
            inventory, topology))
    except (DecoyScopeRefused, IdentityUnavailable, ValueError, TypeError, AttributeError):
        raise DraftRefused("deception scope refused") from None
    print(f"Decoy bridge prefix (fixed, confirmed): {BRIDGE_PREFIX}")
    print("Approved IPv4 source prefixes: "
          + ", ".join(str(network) for network in scope.approved_v4))
    print(f"Ingress interfaces (role {INGRESS_ROLE}): {len(scope.ingress_keys)}")
    if input(EXPOSE_PROMPT) != "EXPOSE":
        raise DraftRefused("exposure declined")
    return render_deception_scope(scope)


def run(operator: str, addresses) -> int:
    """Export only locally assembled bytes after explicit consent and rechecks.

    Node labels and all raw inventory stay inside the encrypted record. IDs
    identify this proposal only, never a replacement node identity. Historical
    observations keep their own timestamps; this path does not authenticate
    them or load an externally replaced proposal as its own expected context.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Proposal export requires a local interactive terminal.", file=sys.stderr)
        return 1
    reason = "node declaration unavailable or refused"
    try:
        node = load_declared_node()
        reason = "operator trust unreadable or refused"
        trust = load_operator_trust()
        reason = "signed draft unreadable or protection refused"
        payload, signature = read_draft_review_inputs()
        reason = "hardware inventory unavailable or refused"
        observed = collect_hardware_observations(permanent_mac_reader=addresses)
        inventory = project_hardware_inventory(
            readouts=observed.interfaces, platform=observed.platform,
            storage_devices=observed.storage_devices, limitations=observed.limitations,
            node_id=node.node_id, inventory_id="inventory-" + uuid4().hex,
            collected_at=observed.collected_at,
        )
        resource = project_resource_profile(observation=assess_resources(), inventory=inventory,
                                            profile_id="resource-" + uuid4().hex)
        reason = "signed draft signature or current binding refused"
        topology = project_reviewed_topology(
            payload=payload, signature=signature, operator=operator, trust=trust,
            current=observed.commissioning_proposal(), inventory=inventory,
            profile_id="topology-" + uuid4().hex, observed_at=_now(),
        )
        reason = "M.I.O. ceiling selection invalid or export incomplete"
        profile = input("M.I.O. ceiling [CORE, LITE, FULL] (does not admit providers): ").strip()
        if profile not in {"CORE", "LITE", "FULL"}:
            raise DraftRefused("unknown M.I.O. profile")
        context = dict(
            inventory=inventory, resource_profile=resource, topology_profile=topology,
            record_id="record-" + uuid4().hex, operator=operator, confirmed_at=_now(),
            mio_profile=profile,
        )
        reason = ("Deception Lite exposure scope refused (canonical, sorted, "
                  "non-overlapping RFC 1918 IPv4 prefixes) or declined")
        scope = _deception_scope(inventory, topology)
        if scope is not None:
            context["deception_scope"] = scope
        reason = "M.I.O. ceiling selection invalid or export incomplete"
        commissioning_proposal_payload(**context)  # Validate before asking for consent.
        what = "and the Deception Lite exposure scope " if scope is not None else ""
        if input(f"Create a protected unsigned full proposal with M.I.O. {profile} {what}for separate review/signing? Type EXPORT: ") != "EXPORT":
            raise DraftRefused("export declined")
        reason = "hardware or protected inputs changed during export"
        if not addresses.unchanged():
            raise HardwareUnavailable("link snapshot changed")
        latest = collect_hardware_observations(permanent_mac_reader=addresses)
        if not all(getattr(latest, field) == getattr(observed, field) for field in (
            "interfaces", "platform", "storage_devices", "limitations", "excluded_loopbacks"
        )) or not addresses.unchanged():
            raise HardwareUnavailable("hardware snapshot changed")
        if (load_declared_node() != node or load_operator_trust() != trust
                or read_draft_review_inputs() != (payload, signature)):
            raise DraftRefused("protected inputs changed")
        reason = "proposal retention refused; inspect protected storage"
        retain_proposal_context(**context)
    except (ApprovalRefused, DraftRefused, CommissioningRecordUnavailable,
            NodeConfigUnavailable, HardwareUnavailable, NetlinkMalformed,
            NetlinkUnavailable, OSError, EOFError, KeyboardInterrupt) as error:
        if isinstance(error, DraftInputRefused):
            reason = error.reason
        print("Proposal export refused: " + reason + ". No activation attempted.",
              file=sys.stderr)
        return 1
    print("Unsigned full proposal saved in protected commissioning storage. Separate full-proposal signature required; nothing activated.")
    return 0
