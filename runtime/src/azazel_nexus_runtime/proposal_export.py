"""Interactive protected full-proposal export; no signing or service admission."""

from datetime import datetime, timezone
import sys
import json
import os
import stat
from uuid import uuid4

from azazel_nexus.commissioning_approval import commissioning_proposal_payload
from azazel_nexus.commissioning_draft import (
    DraftInputRefused, DraftRefused, retain_proposal_context, read_draft_review_inputs,
)
from azazel_nexus.fabric_boundary import (
    CommissioningRecordUnavailable, project_hardware_inventory,
    project_resource_profile, project_reviewed_topology,
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


_CLOCK_POLICY_LIMIT = 4096


def _policy_stat(info, *, directory=False):
    if ((not stat.S_ISDIR(info.st_mode) if directory else not stat.S_ISREG(info.st_mode))
            or info.st_uid != 0 or info.st_mode & 0o022
            or (not directory and (info.st_nlink != 1 or not 0 < info.st_size <= _CLOCK_POLICY_LIMIT))):
        raise DraftRefused("clock policy path refused")
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _clock_policy_input(path):
    """Read only explicit root-owned input, retaining bytes and path identity.

    Repeating this entire walk after consent detects replacement of either the
    file or an ancestor, even if the normalized policy has identical values.
    """
    try:
        if type(path) is not str or not path.startswith("/"):
            raise DraftRefused("clock policy needs an absolute path")
        parts = path.split("/")[1:]
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise DraftRefused("clock policy path refused")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open("/", flags | os.O_DIRECTORY)
        try:
            ancestry = [_policy_stat(os.fstat(directory), directory=True)]
            for part in parts[:-1]:
                child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
                try:
                    identity = _policy_stat(os.fstat(child), directory=True)
                except BaseException:
                    os.close(child)
                    raise
                os.close(directory)
                directory = child
                ancestry.append(identity)
            fd = os.open(parts[-1], flags | os.O_NONBLOCK, dir_fd=directory)
            try:
                before = _policy_stat(os.fstat(fd))
                raw = os.read(fd, _CLOCK_POLICY_LIMIT + 1)
                after = _policy_stat(os.fstat(fd))
                if before != after or len(raw) != before[6]:
                    raise DraftRefused("clock policy changed during read")
            finally:
                os.close(fd)
        finally:
            os.close(directory)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        def invalid_constant(_value):
            raise ValueError("nonfinite JSON")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=invalid_constant)
        from azazel_nexus.fabric_boundary import clock_contract_from_dict
        contract = clock_contract_from_dict(value, consumer_revision=2)
        if contract.skew_budget_us != 5000:
            raise DraftRefused("clock policy requires the explicit finite lab contract")
        return contract.as_dict(), (tuple(ancestry), before, raw)
    except (ValueError, TypeError, UnicodeError, OSError, ImportError):
        raise DraftRefused("clock policy unreadable or refused") from None


def run(operator: str, addresses, *, clock_policy_path: str | None = None) -> int:
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
        policy = policy_identity = None
        if clock_policy_path is not None:
            reason = "clock policy unreadable or refused"
            policy, policy_identity = _clock_policy_input(clock_policy_path)
        reason = "node declaration unavailable or refused"
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
        if policy is not None and profile != "FULL":
            raise DraftRefused("clock policy requires FULL")
        context = dict(
            inventory=inventory, resource_profile=resource, topology_profile=topology,
            record_id="record-" + uuid4().hex, operator=operator, confirmed_at=_now(),
            mio_profile=profile,
        )
        if policy is not None:
            context["clock_policy"] = policy
            print("Explicit clock lab policy: B=5000us, health age=5000ms; "
                  + policy["contract_id"] + ". This is not a production clock guarantee.")
        commissioning_proposal_payload(**context)  # Validate before asking for consent.
        if input(f"Create a protected unsigned full proposal with M.I.O. {profile} for separate review/signing? Type EXPORT: ") != "EXPORT":
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
        if clock_policy_path is not None:
            reason = "clock policy changed during export"
            latest_policy, latest_identity = _clock_policy_input(clock_policy_path)
            if latest_policy != policy or latest_identity != policy_identity:
                raise DraftRefused("clock policy changed during export")
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
