"""Recoverable removal of owned empty masks, not a completed withdrawal.

Trusted composition retains the lifetime lock and provides fresh containment
checks. This synchronous file phase has no production opener. It returns the
retained withdrawing journal, never closed: manager reload, restored loaded
masks and final containment are still required before completing the journal.
"""

import os

from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.bootstrap_overlay_journal import OverlayJournal, advance_overlay
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_overlay_files import (
    _PAIR, _closing_candidate, _directory, _mask_paths, _present,
)
from .bootstrap_directory_paths import AbsentBootstrapDirectory


class OverlayWithdrawalUncertain(ApprovalRefused):
    """Retained intent must be inspected before any further file mutation."""


def _withdraw_paths(*, overlay_fd, masks_fd, higher_priority_fd,
                    transient_fd, generator_early_fd, owner_uid):
    stamps = list(_mask_paths(overlay_fd=overlay_fd, masks_fd=masks_fd,
                             higher_priority_fd=higher_priority_fd, owner_uid=owner_uid))
    for fd in (transient_fd, generator_early_fd):
        if type(fd) is AbsentBootstrapDirectory:
            stamps.append(fd.stamp(owner_uid))
        else:
            info = _directory(fd, owner_uid=owner_uid)
            stamps.append((info.st_dev, info.st_ino, info.st_uid, info.st_mode))
        if any(_present(fd, unit) or _present(fd, unit + ".d") for unit in _PAIR):
            raise ApprovalRefused("restored mask has a higher-priority competitor")
    identities = []
    for fd in (overlay_fd, masks_fd, higher_priority_fd, transient_fd, generator_early_fd):
        if type(fd) is AbsentBootstrapDirectory:
            identities.append(fd.stamp(owner_uid))
        else:
            info = os.fstat(fd)
            identities.append((info.st_dev, info.st_ino))
    if len(set(identities)) != len(identities):
        raise ApprovalRefused("withdrawal precedence directories alias")
    return tuple(stamps)


def _withdraw_candidates_at(*, overlay_fd, masks_fd, higher_priority_fd,
                            transient_fd, generator_early_fd, journal_store,
                            guard, owner_uid, check_contained):
    if type(guard) is not BootstrapTransactionGuard or not callable(check_contained):
        raise ApprovalRefused("held guard and fresh containment check required")
    guard()
    current = journal_store.load()
    if type(current) is not OverlayJournal or current.phase not in {"closing", "withdrawing"}:
        raise ApprovalRefused("owned closing journal required")
    recovering = current.phase == "withdrawing"
    owned = {unit: (device, inode, digest)
             for unit, device, inode, digest in current.owned_files}
    path_args = dict(overlay_fd=overlay_fd, masks_fd=masks_fd,
                     higher_priority_fd=higher_priority_fd, owner_uid=owner_uid,
                     transient_fd=transient_fd, generator_early_fd=generator_early_fd)

    def paths():
        return _withdraw_paths(**path_args)

    original_paths = paths()

    def stable():
        guard()
        try:
            result = check_contained()
        except Exception:
            raise ApprovalRefused("fresh containment check failed") from None
        if result is not None:
            raise ApprovalRefused("fresh containment unconfirmed")
        if journal_store.load() != current or paths() != original_paths:
            raise ApprovalRefused("withdrawal journal or paths changed")
        if any(_present(overlay_fd, unit) for unit in _PAIR if unit not in owned):
            raise ApprovalRefused("unowned withdrawal candidate present")

    def inspect(unit, *, allow_absent):
        if not _present(overlay_fd, unit):
            if allow_absent:
                return False
            raise ApprovalRefused("owned mask missing before withdrawal intent")
        device, inode, digest = owned[unit]
        with _closing_candidate(overlay_fd, unit, (device, inode), digest,
                                owner_uid=owner_uid, allow_empty=True) as fd:
            if os.fstat(fd).st_size != 0:
                raise ApprovalRefused("withdrawal candidate is not an empty mask")
        return True

    stable()
    for unit in owned:
        inspect(unit, allow_absent=recovering)
    uncertain = recovering
    try:
        stable()
        if recovering:
            # A visible record alone does not prove its last rename was durable.
            journal_store.replace(current, current)
        else:
            withdrawing = advance_overlay(current, "begin-withdrawal")
            uncertain = True
            journal_store.replace(current, withdrawing)
            current = withdrawing
        for unit in reversed(_PAIR):
            if unit not in owned:
                continue
            stable()
            if inspect(unit, allow_absent=True):
                # The protected directories/held lock exclude untrusted writers.
                # No ownership is inferred from matching bytes or an empty file.
                stable()
                inspect(unit, allow_absent=False)
                os.unlink(unit, dir_fd=overlay_fd)
            os.fsync(overlay_fd)
            stable()
        if any(_present(overlay_fd, unit) for unit in _PAIR):
            raise ApprovalRefused("withdrawn masks still present")
        stable()
        return current
    except (ApprovalRefused, OSError):
        if uncertain:
            raise OverlayWithdrawalUncertain("owned withdrawal incomplete; intent retained") from None
        raise
