"""Commissioning as a conversation an operator can finish (#29).

The acceptance condition is plain: *an operator completes commissioning
without hand-editing anything.* The constraints around it are what make it
awkward, and they are not negotiable:

*Nothing is proposed.* `azazel_nexus.commissioning.propose` offers the
interfaces whose identity is unambiguous and the roles that exist. Which role
goes where is the operator's answer. This module does not rank, default,
pre-select, or order rows to hint -- every fact that would let it do so is a
fact `docs/commissioning.md` §4 forbids reading, and none of them is read.

*Nothing is applied without confirmation.* The wizard asks per interface and
then asks once more for the whole set. The second question is not ceremony:
the first answers are made one at a time with the next row still unseen, and
the set is what the record will contain.

*No kernel name reaches the operator.* Rows are identified by a handle and by
physically checkable facts. An operator confirming `enp3s0` is confirming
something they cannot check against the machine in front of them.

The prompt function is injected. A wizard that called `input()` could only be
exercised by a person, which means the path that writes the commissioning
record would be the one path never tested.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from .commissioning import (
    CommissioningRecord,
    CommissioningRefused,
    Proposal,
)
from .inventory import InterfaceReadout
from .commissioning import confirm_roles

__all__ = [
    "Answer",
    "WizardAbandoned",
    "commission",
    "render_rows",
]

#: What the wizard is allowed to do with an answer it does not understand.
#:
#: Re-ask. Not "treat as skip", which would turn a typo into an interface
#: silently left unassigned, and not "treat as yes", which needs no comment.
_MAX_REASKS = 3


def _screen_description(readout: InterfaceReadout) -> dict[str, str]:
    # hil_preflight also consumes Answer; defer the shared policy helper until
    # both modules are initialized instead of introducing an import cycle.
    from .hil_preflight import describe_for_screen

    return describe_for_screen(readout)


class WizardAbandoned(Exception):
    """The operator did not confirm. No record was written."""


@dataclass(frozen=True)
class Answer:
    """One operator answer, with the row it answers about."""

    handle: str
    role: Optional[str]


def render_rows(proposal: Proposal) -> tuple[dict[str, object], ...]:
    """The rows an operator chooses between.

    Refused interfaces are carried too, with their reasons. An operator
    looking for an adapter that was seen and discarded has no other way to
    find out what happened to it -- and an adapter that silently vanished from
    a list is the one they will spend an hour looking for behind the rack.
    """

    rows: list[dict[str, object]] = []
    for index, readout in enumerate(proposal.commissionable, start=1):
        rows.append(
            {
                "handle": f"if-{index}",
                "description": _screen_description(readout),
                "commissionable": True,
                "blocked_by": (),
            }
        )
    for _, reasons in proposal.refused:
        rows.append(
            {
                "handle": "-",
                "description": {
                    "note": "this adapter was seen and cannot be commissioned"
                },
                "commissionable": False,
                "blocked_by": reasons,
            }
        )
    return tuple(rows)


def commission(
    proposal: Proposal,
    *,
    ask: Callable[[str, Sequence[str]], str],
    confirm: Callable[[str], bool],
    operator: str,
    at: str,
    profiles_present: Sequence[str],
) -> CommissioningRecord:
    """Ask, confirm the whole set, then return an unsigned in-memory draft.

    Returns an observe-only record when the operator assigns no role. That is
    a completed choice, not an abandoned one: somebody looked and
    confirmed nothing, which is different from nobody having looked.
    This function neither persists nor signs the draft and does not establish
    measured profiles, service readiness, or activation approval.
    """

    if proposal.commissioning_required:
        raise CommissioningRefused(
            "no interface on this host carries an identity unambiguous enough "
            "to confirm a role against. "
            + ("; ".join(proposal.reasons) if proposal.reasons else "")
        )

    choices = ("skip", *proposal.offerable_roles)
    confirmations: list[tuple[InterfaceReadout, str]] = []
    answers: list[Answer] = []

    for index, readout in enumerate(proposal.commissionable, start=1):
        handle = f"if-{index}"
        role = _ask_until_understood(ask, handle, readout, choices)
        answers.append(Answer(handle, None if role == "skip" else role))
        if role != "skip":
            confirmations.append((readout, role))

    summary = _summarise(answers)
    if not confirm(summary):
        raise WizardAbandoned(
            "the operator did not confirm the set; nothing was written. The "
            "per-interface answers were given one at a time with the next row "
            "unseen, and the set is what the record would contain"
        )

    return confirm_roles(
        proposal,
        tuple(confirmations),
        operator=operator,
        at=at,
        profiles_present=tuple(profiles_present),
    )


def _ask_until_understood(
    ask: Callable[[str, Sequence[str]], str],
    handle: str,
    readout: InterfaceReadout,
    choices: Sequence[str],
) -> str:
    description = _screen_description(readout)
    facts = ", ".join(f"{k}={v}" for k, v in sorted(description.items())) or (
        "no physically checkable identifier was readable"
    )
    prompt = f"{handle} ({facts}) -- which role?"
    for _ in range(_MAX_REASKS):
        answer = ask(prompt, tuple(choices)).strip()
        if answer in choices:
            return answer
    raise CommissioningRefused(
        f"{handle} received no answer from {tuple(choices)} after "
        f"{_MAX_REASKS} attempts. An unparsed answer is not a skip: an "
        "interface left unassigned by a typo is an interface nobody decided "
        "about"
    )


def _summarise(answers: Sequence[Answer]) -> str:
    lines = ["Confirm this commissioning:"]
    for answer in answers:
        lines.append(f"  {answer.handle}: {answer.role or 'no role'}")
    assigned = [a for a in answers if a.role]
    if not assigned:
        lines.append(
            "  No interface carries a role. The node will observe and enforce "
            "nothing."
        )
    return "\n".join(lines)
