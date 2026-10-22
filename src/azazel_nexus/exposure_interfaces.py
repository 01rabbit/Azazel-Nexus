"""This boot's names of the exposure tier's role interfaces (#196 G6 prep D).

`docs/deception-exposure-grant.md` §4.3, `docs/commissioning.md` §3 and §8,
and the "Interfaces" paragraph of `docs/deception-exposure-reachability.md`
§6. The pass renders the scope file with this boot's kernel names of the
`deception_bridge` interfaces, and judges forwarding with the names of the
`management` and `observation` interfaces too. Both come from the signed
commissioning evidence and the current inventory, resolved by composite
identity: an ambiguous or missing identity withholds, and no name stands in
for a role.

`resolve_role_interfaces` is that resolution, pure. Its inputs:

* `proposal`: the signed `commissioning-proposal/v3` document, already
  verified by the caller (`commissioning_evidence`); its role assignments
  (interface key and composite identity) are restored by
  `fabric_boundary.restore_commissioning_inputs` and
  `fabric_boundary.deception_scope_assignments`;
* `current_inventory`: this boot's `HardwareInventory` (kernel names and
  identities), compared whole with the retained one by
  `fabric_boundary.assert_current_inventory_matches`, the comparison the
  commissioning evidence already makes;
* `scope`: the `decoy_scope.DeceptionScope` decoded from the same proposal.

It returns `RoleInterfaces` (`ingress` for `decoy_scope.render_scope_file`;
`management` and `observation` for the `management` and `observation`
arguments of the pass's judgement of reachability §6 in the runtime's
`decoy_reachability`; `ingress` for its `ingress` as well) or a withholding reason `"<code>: <phrase>"`.
Each assignment is resolved by Fabric's rule (`identify_interface`: exactly
one match, zero and several the same answer); a name is taken only from
the one interface an identity resolves to, never looked up by name. Refused:

* `role_evidence_unavailable`: the proposal cannot be restored, or is not
  v3 (it carries no scope);
* `role_scope_mismatch`: `scope` is not a decoded scope, does not render to
  the proposal's section, or its interfaces are not the proposal's
  `deception_bridge` interfaces;
* `role_inventory_changed`: this boot's inventory is not the retained one
  (a renamed, added, removed or changed interface included: §3 asks for
  recommissioning, not a rebinding);
* `role_interface_unresolved`: an assignment's identity matches no
  interface of this boot or several, or the one it matches has no kernel
  name;
* `role_interface_ambiguous`: one interface holds two roles, or a name
  belongs to more than one interface of this boot;
* `role_interface_name_refused`: a name fails grant §4.3
  (`decoy_scope.interface_name_allowed`).

No `management` or no `observation` role is not a refusal: an interface
that holds neither is "every other interface" to the pass's judgement,
which requires it not to forward either (reachability §6,
`forwarding_other_on`).

**No content in reasons.** Every reason is a fixed code and a fixed phrase
(`ROLE_INTERFACE_PHRASES`); never a kernel name, an interface key, a MAC, a
serial or a bus path. An argument of any shape gives a reason, never an
exception.

**Implemented, not wired.** Nothing calls this module: the pass, the
controller and the library do not import it, nothing writes
`/run/azazel-activation/decoy-scope.json`, and
`ActivationController._withholding_reason` still withholds the tier as
`isolation_evidence_absent` (`tests/unit/test_exposure_interfaces.py`).
Wiring it in is G6. It grants, writes and reads nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Union

from .decoy_scope import (
    INGRESS_ROLE,
    DecoyScopeRefused,
    DeceptionScope,
    interface_name_allowed,
    render_deception_scope,
)
from .fabric_boundary import (
    CommissioningRecordUnavailable,
    IdentityUnavailable,
    assert_current_inventory_matches,
    deception_scope_assignments,
    identify_interface,
    restore_commissioning_inputs,
)

__all__ = [
    "ROLE_EVIDENCE_UNAVAILABLE",
    "ROLE_INTERFACE_AMBIGUOUS",
    "ROLE_INTERFACE_CODES",
    "ROLE_INTERFACE_NAME_REFUSED",
    "ROLE_INTERFACE_PHRASES",
    "ROLE_INTERFACE_UNRESOLVED",
    "ROLE_INVENTORY_CHANGED",
    "ROLE_SCOPE_MISMATCH",
    "RoleInterfaces",
    "resolve_role_interfaces",
]

ROLE_EVIDENCE_UNAVAILABLE = "role_evidence_unavailable"
ROLE_SCOPE_MISMATCH = "role_scope_mismatch"
ROLE_INVENTORY_CHANGED = "role_inventory_changed"
ROLE_INTERFACE_UNRESOLVED = "role_interface_unresolved"
ROLE_INTERFACE_AMBIGUOUS = "role_interface_ambiguous"
ROLE_INTERFACE_NAME_REFUSED = "role_interface_name_refused"

#: In the order they are asked.
ROLE_INTERFACE_CODES: tuple[str, ...] = (
    ROLE_EVIDENCE_UNAVAILABLE,
    ROLE_SCOPE_MISMATCH,
    ROLE_INVENTORY_CHANGED,
    ROLE_INTERFACE_UNRESOLVED,
    ROLE_INTERFACE_AMBIGUOUS,
    ROLE_INTERFACE_NAME_REFUSED,
)

#: Each code's fixed phrase: no name, key or identity.
ROLE_INTERFACE_PHRASES: dict[str, str] = {
    ROLE_EVIDENCE_UNAVAILABLE: ("the commissioning evidence could not be restored "
                                "or carries no deception scope"),
    ROLE_SCOPE_MISMATCH: ("the deception scope is not the commissioning "
                          "evidence's own"),
    ROLE_INVENTORY_CHANGED: ("this boot's inventory is not the commissioned "
                             "inventory"),
    ROLE_INTERFACE_UNRESOLVED: ("a commissioned identity matches no interface "
                                "of this boot, several, or one without a name"),
    ROLE_INTERFACE_AMBIGUOUS: ("an interface holds more than one role, or a "
                               "name belongs to more than one interface"),
    ROLE_INTERFACE_NAME_REFUSED: "a role interface's name is not allowed",
}

#: The roles whose names the pass needs.
_MANAGEMENT = "management"
_OBSERVATION = "observation"


@dataclass(frozen=True)
class RoleInterfaces:
    """This boot's kernel names of the role interfaces, each sorted.

    `ingress` is the `deception_bridge` interfaces, in the order
    `decoy_scope.render_scope_file` takes them; `management` and
    `observation` may be empty. No name is in two places.
    """

    ingress: tuple[str, ...]
    management: tuple[str, ...]
    observation: tuple[str, ...]


def _refusal(code: str) -> str:
    return f"{code}: {ROLE_INTERFACE_PHRASES[code]}"


class _Withheld(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_UNREADABLE = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
               CommissioningRecordUnavailable, IdentityUnavailable, DecoyScopeRefused)


def _restore(proposal: Any) -> tuple[Any, Any, dict]:
    """The retained inventory, topology and scope section, or withheld."""

    try:
        context = restore_commissioning_inputs(proposal)
        return context["inventory"], context["topology_profile"], context["deception_scope"]
    except _UNREADABLE:
        raise _Withheld(ROLE_EVIDENCE_UNAVAILABLE) from None


def _resolve(proposal: Any, current_inventory: Any, scope: Any) -> RoleInterfaces:
    retained, topology, section = _restore(proposal)

    try:
        # The pairs the scope was decoded against when the proposal was
        # restored; restored again here so the given scope is bound to them.
        pairs = deception_scope_assignments(retained, topology)
        bridge = tuple(sorted(key for key, role in pairs if role == INGRESS_ROLE))
        if (type(scope) is not DeceptionScope
                or render_deception_scope(scope) != section
                or scope.ingress_keys != bridge):
            raise _Withheld(ROLE_SCOPE_MISMATCH)
    except _UNREADABLE:
        raise _Withheld(ROLE_SCOPE_MISMATCH) from None

    try:
        assert_current_inventory_matches(retained=retained, current=current_inventory)
    except _UNREADABLE:
        raise _Withheld(ROLE_INVENTORY_CHANGED) from None

    # Fabric's rule over this boot's interfaces, one assignment at a time.
    resolved = []
    try:
        for assignment, (key, role) in zip(topology.commissioned_assignments, pairs,
                                           strict=True):
            identity = identify_interface(current_inventory.interfaces, assignment.selector)
            name = identity.kernel_name_observed
            if identity.interface_key != key or type(name) is not str or not name:
                raise _Withheld(ROLE_INTERFACE_UNRESOLVED)
            resolved.append((key, role, name))
    except _UNREADABLE:
        raise _Withheld(ROLE_INTERFACE_UNRESOLVED) from None

    keys = [key for key, _, _ in resolved]
    names = [name for _, _, name in resolved]
    observed = [item.kernel_name_observed for item in current_inventory.interfaces]
    if (len(set(keys)) != len(keys) or len(set(names)) != len(names)
            or any(observed.count(name) != 1 for name in names)):
        raise _Withheld(ROLE_INTERFACE_AMBIGUOUS)

    wanted = {INGRESS_ROLE: [], _MANAGEMENT: [], _OBSERVATION: []}
    for _, role, name in resolved:
        if role in wanted:
            if not interface_name_allowed(name):
                raise _Withheld(ROLE_INTERFACE_NAME_REFUSED)
            wanted[role].append(name)
    return RoleInterfaces(*(tuple(sorted(wanted[role]))
                            for role in (INGRESS_ROLE, _MANAGEMENT, _OBSERVATION)))


def resolve_role_interfaces(*, proposal: Any, current_inventory: Any,
                            scope: Any) -> Union[RoleInterfaces, str]:
    """`RoleInterfaces` for this boot, or a withholding reason. Never raises.

    `proposal` is the verified `commissioning-proposal/v3` document (a
    `dict`), `current_inventory` this boot's Fabric `HardwareInventory`,
    `scope` the proposal's decoded `DeceptionScope`. The reason is
    `"<code>: <phrase>"` with a code of `ROLE_INTERFACE_CODES`.
    """

    try:
        return _resolve(proposal, current_inventory, scope)
    except _Withheld as withheld:
        return _refusal(withheld.code)
    except _UNREADABLE:
        return _refusal(ROLE_EVIDENCE_UNAVAILABLE)
