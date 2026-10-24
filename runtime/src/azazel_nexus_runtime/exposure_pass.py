"""Pass step 10: the exposure tier's runtime stages, P1 to P11 (#196 G6).

`docs/deception-exposure-wiring.md` §4.1, §4.3 and §4.4. After the lease is
formed and Edge evidence read (step 9), the pass asks the G6 parts, in a
fixed order, whether the conditions of grant §5 C1 that can be judged
before the three exposure units start hold on this host, and makes one
value of the answer: `azazel_nexus.exposure_admission.ExposureEvidence`. The
library consumes it (`ActivationController._withholding_reason`, L3 to L5)
and decides; nothing here grants, writes, starts, stops or masks anything.

| stage | condition (grant §5 C1) | part |
| --- | --- | --- |
| P1 | 1: the lease came from a verified v3 approval naming the three | type check |
| P2 | 6, static half | `exposure_withholding.fb_tunnels_refusal` |
| P3 | 4, first half: AppArmor on, the four profiles enforced | `decoy_apparmor.exposure_lsm_refusal` |
| P4 | 5: no ruleset loader enabled or active | `exposure_withholding.host_firewall_refusal` |
| P5 | §6.3 G6 (a): no masked running unit, no leftovers | `decoy_residue.exposure_residue_departures` |
| P6 | 3: a v3 proposal's scope, roles resolved for this boot | `decoy_scope`, `exposure_interfaces` |
| P7 | 6, forwarding half (R1, R2, R5) | `decoy_reachability.pass_reachability_departures` |
| P8 | grant §4.3: the scope file renders | `decoy_scope.render_scope_file` |
| P9 | 2: the generation's exposure section describes this node | `exposure_generation.verify_exposure_section` |
| P10 | §5.1 V2: the approval's exposure fields are this pass's | equality |
| P11 | 4, second half: loaded units' profiles, the kernel's policy | `decoy_apparmor` |

**Order.** Each stage runs only when every earlier one held, so a pass
records exactly one reason and a host that fails an early, cheap check is
not read further; each stage reads its own inputs when it is reached.

**Never raises** (review of #301, finding 3). Any exception in any stage --
a reader, a part, the construction of a value -- becomes evidence with the
fixed refusal `exposure_stage_unreadable` and the stages that held before
it. Nothing here reaches the producers' `complete` or the lease: a refusal
withholds the three exposure units and nothing else.

**What the controller reads** (§4.4). Files under `/proc/sys`,
`/sys/kernel/security`, `/run/netns` and `/etc/apparmor.d`, the unit files,
the service manager's bus (read-only, `systemd_bus`, §4.5) and route netlink
dumps (`netlink.read_links`, `exposure_route_dump`; no capability). No
process is started (B1), no nftables listing is taken (A1) and no unit is
stopped (owner decision Q-B = B0).

**No content in a reason.** Every reason is `"<code>: <phrase>"` of a part
or of `exposure_admission`; never a name, prefix, address, digest or value.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Callable, Mapping, Optional

from azazel_nexus.activation import DECEPTION_EXPOSURE_UNITS
from azazel_nexus.activation_approval_v3 import ActivationApprovalV3
from azazel_nexus.decoy_scope import (
    DecoyScopeRefused,
    decode_deception_scope,
    parse_scope_file,
    render_scope_file,
)
from azazel_nexus.exposure_admission import (
    DECEPTION_SCOPE_ABSENT,
    DECEPTION_SCOPE_REFUSED,
    DECOY_SCOPE_UNRENDERABLE,
    EXPOSURE_APPROVAL_BINDING_DIFFERS,
    EXPOSURE_APPROVAL_NOT_V3,
    EXPOSURE_FILES_UNREADABLE,
    EXPOSURE_GENERATION_ABSENT,
    EXPOSURE_GENERATION_DIFFERS,
    EXPOSURE_STAGE_UNREADABLE,
    EXPOSURE_STAGES,
    ExposureEvidence,
    admission_refusal,
)
from azazel_nexus.exposure_interfaces import (
    ROLE_EVIDENCE_UNAVAILABLE,
    ROLE_INTERFACE_PHRASES,
    RoleInterfaces,
    resolve_role_interfaces,
)
from azazel_nexus.fabric_boundary import (
    deception_scope_assignments,
    restore_commissioning_inputs,
    restore_current_inventory,
)
from azazel_nexus.generation import GenerationRefused

from .activation_unit_files import UnitContentRefused
from .decoy_apparmor import (
    LSM_PHRASES,
    LSM_POLICY_UNVERIFIABLE,
    exposure_lsm_refusal,
    loaded_unit_profile_refusal,
    policy_hash_refusal,
)
from .decoy_reachability import pass_reachability_departures, reachability_refusal
from .decoy_residue import exposure_residue_departures, residue_refusal
from .exposure_generation import expected_policy_hashes, verify_exposure_section
from .exposure_withholding import fb_tunnels_refusal, host_firewall_refusal

__all__ = [
    "ExposureReaders",
    "ExposureStageRefused",
    "collect_exposure_evidence",
    "production_exposure_readers",
    "resolve_exposure_scope",
]

#: The commissioning proposal that carries a deception scope (grant §4.1).
_PROPOSAL_V3 = "azazel-nexus/commissioning-proposal/v3"


@dataclass(frozen=True)
class ExposureReaders:
    """The fixed host readers of step 10. Production: `production_exposure_readers`.

    Each is called only when its stage is reached, and each is read-only.
    """

    #: P2: `exposure_withholding.read_fb_tunnels`.
    fb_tunnels: Callable[[], Any]
    #: P3: `decoy_apparmor.read_exposure_lsm`, `(lsm, profiles)`.
    lsm: Callable[[], tuple]
    #: P4: the bus reads of §4.5, `host_firewall_refusal`'s input.
    host_firewall: Callable[[], Any]
    #: P5: the bus reads of §4.5, `exposure_residue_departures`'s `units`.
    exposure_units: Callable[[], Any]
    #: P5: `decoy_residue.read_netns`.
    netns: Callable[[], Any]
    #: P5 and P7: `netlink.read_links` (raises when the dump fails).
    links: Callable[[], Any]
    #: P7: `decoy_reachability.read_sysctls(ingress)`.
    sysctls: Callable[[tuple], tuple]
    #: P7: `exposure_route_dump.dump_ipv4_rules` (None: not read whole).
    rules: Callable[[], Optional[list]]
    #: P7: `exposure_route_dump.dump_main_routes(links)` (None: not read whole).
    routes: Callable[[Mapping], Optional[list]]
    #: P9: `exposure_generation.measure_exposure_section_inputs`.
    section_inputs: Callable[[], tuple]
    #: P11: the bus reads of §4.5, `loaded_unit_profile_refusal`'s input.
    loaded_profiles: Callable[[], Any]
    #: P11: `decoy_apparmor.read_policy_hashes`.
    policy_hashes: Callable[[], Any]


class ExposureStageRefused(Exception):
    """A stage refused with `reason` (already `"<code>: <phrase>"`)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _check(reason: Optional[str]) -> None:
    if reason is not None:
        raise ExposureStageRefused(reason)


def _role_refusal(code: str) -> str:
    return f"{code}: {ROLE_INTERFACE_PHRASES[code]}"


def resolve_exposure_scope(evidence) -> tuple:
    """P6: the proposal's decoded scope and this boot's role names.

    `(DeceptionScope, RoleInterfaces)` from verified commissioning evidence,
    or `ExposureStageRefused`. The pass's stage P6, and what
    `az-activation generation-publish`, `request` and `install` render the
    scope file from (wiring §5.2), so the two cannot render differently.
    """

    document = json.loads(evidence.payload)
    if type(document) is not dict or document.get("schema") != _PROPOSAL_V3:
        raise ExposureStageRefused(admission_refusal(DECEPTION_SCOPE_ABSENT))
    try:
        context = restore_commissioning_inputs(document)
        scope = decode_deception_scope(
            context["deception_scope"],
            assignments=deception_scope_assignments(context["inventory"],
                                                    context["topology_profile"]))
    except Exception:  # noqa: BLE001 - any refusal of the section is the stage's code
        raise ExposureStageRefused(admission_refusal(DECEPTION_SCOPE_REFUSED)) from None
    try:
        current = restore_current_inventory(evidence.current_inventory)
    except Exception:  # noqa: BLE001 - the evidence's own bytes do not restore
        raise ExposureStageRefused(_role_refusal(ROLE_EVIDENCE_UNAVAILABLE)) from None
    roles = resolve_role_interfaces(proposal=document, current_inventory=current, scope=scope)
    if type(roles) is not RoleInterfaces:
        raise ExposureStageRefused(roles if type(roles) is str else _role_refusal(ROLE_EVIDENCE_UNAVAILABLE))
    return scope, roles


def collect_exposure_evidence(*, approval, evidence, generation_digest: str,
                              section, readers: Optional[ExposureReaders]
                              ) -> tuple[ExposureEvidence, Optional[bytes]]:
    """Run P1 to P11 in order; the first refusal ends it. Never raises.

    `approval` is the verified approval of step 7, `evidence` the verified
    commissioning evidence of step 1, `generation_digest` the verified
    generation's digest, `section` its recorded exposure section (None for a
    generation without one), `readers` the host readers. Returns
    `(evidence, scope file)`: evidence with every stage held and the rendered
    scope file's digest, and P8's bytes (the file the pass writes, §5.3); or
    evidence with the first stage's refusal and the stages that held before
    it, and None.
    """

    held: list[str] = []
    scope_digest: Optional[str] = None
    scope_file: Optional[bytes] = None
    try:
        # P1: the lease came from a verified v3 approval naming the three.
        if (type(approval) is not ActivationApprovalV3
                or approval.lease.units is None
                or not set(DECEPTION_EXPOSURE_UNITS) <= approval.lease.units):
            raise ExposureStageRefused(admission_refusal(EXPOSURE_APPROVAL_NOT_V3))
        held.append("P1")
        # P2: fallback tunnels in the initial namespace only.
        _check(fb_tunnels_refusal(readers.fb_tunnels()))
        held.append("P2")
        # P3: AppArmor on, the four profiles in enforce mode, no child.
        lsm, profiles = readers.lsm()
        _check(exposure_lsm_refusal(lsm, profiles))
        held.append("P3")
        # P4: no host firewall loader enabled or active.
        _check(host_firewall_refusal(readers.host_firewall()))
        held.append("P4")
        # P5: no definition-less running unit, no leftovers (no table, A1).
        units = readers.exposure_units()
        netns = readers.netns()
        try:
            records = tuple(readers.links())
        except Exception:  # noqa: BLE001 - a failed dump is unreadable, not empty
            records = None
        names = None if records is None else tuple(record.name for record in records)
        _check(residue_refusal(exposure_residue_departures(units, netns, names)))
        held.append("P5")
        # P6: a v3 proposal's scope, its roles resolved to this boot's names.
        scope, roles = resolve_exposure_scope(evidence)
        held.append("P6")
        # P7: forwarding, K1 and the routes, with P6's names.
        ipv4, ipv6 = readers.sysctls(roles.ingress)
        rules = readers.rules()
        routes = readers.routes({record.index: record.name for record in records})
        _check(reachability_refusal(pass_reachability_departures(
            ipv4, ipv6, rules, routes, ingress=roles.ingress,
            management=roles.management, observation=roles.observation)))
        held.append("P7")
        # P8: the scope file renders, and reads back as itself.
        try:
            rendered = render_scope_file(scope, roles.ingress)
            parsed = parse_scope_file(rendered)
        except DecoyScopeRefused:
            raise ExposureStageRefused(admission_refusal(DECOY_SCOPE_UNRENDERABLE)) from None
        scope_file, scope_digest = rendered, parsed.scope_digest
        held.append("P8")
        # P9: the generation's section describes the files and this scope.
        if section is None:
            raise ExposureStageRefused(admission_refusal(EXPOSURE_GENERATION_ABSENT))
        try:
            unit_files, watch_unit_files, apparmor_profiles = readers.section_inputs()
        except UnitContentRefused:
            # Read, and not the declaration (a watch file is compared byte
            # for byte with its rendering, a governed unit file's guards line
            # by line): a file changed after publishing, as the section would
            # say (§8 VM rehearsal, 2026-10-24).
            raise ExposureStageRefused(admission_refusal(EXPOSURE_GENERATION_DIFFERS)) from None
        except Exception:  # noqa: BLE001 - a reader's refusal is the stage's code
            raise ExposureStageRefused(admission_refusal(EXPOSURE_FILES_UNREADABLE)) from None
        try:
            verify_exposure_section(section, unit_files=unit_files,
                                    watch_unit_files=watch_unit_files,
                                    apparmor_profiles=apparmor_profiles,
                                    scope_file=scope_file)
        except GenerationRefused:
            raise ExposureStageRefused(admission_refusal(EXPOSURE_GENERATION_DIFFERS)) from None
        held.append("P9")
        # P10: the approval's exposure fields (V2) are this pass's.
        if (approval.exposure_scope_digest != scope_digest
                or section["scope_digest"] != scope_digest
                or approval.exposure_prefix_count != len(parsed.approved_v4)
                or approval.exposure_ingress_count != len(parsed.ingress)):
            raise ExposureStageRefused(admission_refusal(EXPOSURE_APPROVAL_BINDING_DIFFERS))
        held.append("P10")
        # P11: the loaded units name their profiles; the kernel's policy is
        # the compiled one the signed section records.
        _check(loaded_unit_profile_refusal(readers.loaded_profiles()))
        try:
            expected = expected_policy_hashes(section)
        except GenerationRefused:
            raise ExposureStageRefused(f"{LSM_POLICY_UNVERIFIABLE}: {LSM_PHRASES[LSM_POLICY_UNVERIFIABLE]}"
                        ) from None
        _check(policy_hash_refusal(readers.policy_hashes(), expected))
        held.append("P11")
        refusal = None
    except ExposureStageRefused as stage:
        refusal = stage.reason
    except Exception:  # noqa: BLE001 - any failure in a stage withholds the tier
        refusal = admission_refusal(EXPOSURE_STAGE_UNREADABLE)
    stages = tuple(held)
    if refusal is None and stages != EXPOSURE_STAGES:  # pragma: no cover - by construction
        refusal = admission_refusal(EXPOSURE_STAGE_UNREADABLE)
    value = ExposureEvidence(generation_digest=generation_digest, scope_digest=scope_digest,
                             refusal=refusal, stages=stages)
    return value, (scope_file if refusal is None else None)


def production_exposure_readers(systemd) -> ExposureReaders:
    """The fixed host readers. `systemd` is the controller's own bus session.

    Without a session the bus readers raise, and the stage that needs them
    withholds as `exposure_stage_unreadable`.
    """

    from .decoy_apparmor import read_exposure_lsm, read_policy_hashes
    from .decoy_reachability import read_sysctls
    from .decoy_residue import read_netns
    from .exposure_generation import measure_exposure_section_inputs
    from .exposure_route_dump import dump_ipv4_rules, dump_main_routes
    from .exposure_withholding import read_fb_tunnels
    from .netlink import read_links

    def session():
        if systemd is None:
            raise RuntimeError("no service manager session")
        return systemd

    return ExposureReaders(
        fb_tunnels=read_fb_tunnels,
        lsm=read_exposure_lsm,
        host_firewall=lambda: session().host_firewall_states(),
        exposure_units=lambda: session().exposure_unit_states(),
        netns=read_netns,
        links=read_links,
        sysctls=read_sysctls,
        rules=dump_ipv4_rules,
        routes=dump_main_routes,
        section_inputs=measure_exposure_section_inputs,
        loaded_profiles=lambda: session().decoy_profile_states(),
        policy_hashes=read_policy_hashes,
    )
