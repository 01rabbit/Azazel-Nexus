"""Retained post-unlink file observation and journal completion.

Only trusted composition supplies these borrowed directory descriptors/paths
and the lifetime guard. No opener, removal of journals, or inference
of loaded manager state is provided. Final evidence must come from the connected
same-owner restoration sequence, never from candidate data or an RPC caller.
"""

from pathlib import Path

from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard
from azazel_nexus.bootstrap_overlay_journal import (
    OverlayJournal, OverlayStopEvidence, advance_overlay,
)
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_overlay_files import _PAIR, _present
from .bootstrap_withdraw_files import _withdraw_paths
from .units import UnitKey, UNIT_NAMES
from .bootstrap_directory_paths import bind_directory_path


class BootstrapRestoredOverlayFiles:
    def __init__(self, *, overlay_fd, masks_fd, higher_priority_fd,
                 transient_fd, generator_early_fd, overlay_path, masks_path,
                 higher_priority_path, transient_path, generator_early_path,
                 journal_store, guard, owner_uid):
        if type(guard) is not BootstrapTransactionGuard:
            raise ApprovalRefused("held restoration guard required")
        self._guard = guard
        self._store = journal_store
        self._arguments = dict(overlay_fd=overlay_fd, masks_fd=masks_fd,
                               higher_priority_fd=higher_priority_fd,
                               transient_fd=transient_fd, generator_early_fd=generator_early_fd,
                               owner_uid=owner_uid)
        self._fds = (overlay_fd, masks_fd, higher_priority_fd, transient_fd, generator_early_fd)
        self._paths = tuple(Path(path) for path in (overlay_path, masks_path,
                            higher_priority_path, transient_path, generator_early_path))
        guard()
        self._journal = journal_store.load()
        if (type(self._journal) is not OverlayJournal
                or self._journal.phase not in {"withdrawing", "closed"}):
            raise ApprovalRefused("retained withdrawal journal required")
        self._stamps = _withdraw_paths(**self._arguments)
        self.check()

    def check(self):
        self._guard()
        for path, fd in zip(self._paths, self._fds, strict=True):
            bind_directory_path(path, fd)
        if (self._store.load() != self._journal
                or _withdraw_paths(**self._arguments) != self._stamps):
            raise ApprovalRefused("restored paths or ownership journal changed")
        if any(_present(self._fds[0], name) for name in _PAIR):
            raise ApprovalRefused("overlay entry remains after withdrawal")
        self._guard()
        return tuple((unit, str(self._paths[1] / UNIT_NAMES[unit]))
                     for unit in (UnitKey.AUDITD, UnitKey.COMMISSIOND))

    def finalize(self, evidence):
        if type(evidence) is not OverlayStopEvidence:
            raise ApprovalRefused("fresh restoration evidence required")
        self.check()
        current = self._journal
        closed = (advance_overlay(current, "withdraw", evidence=evidence)
                  if current.phase == "withdrawing" else current)
        # Reaffirm visible closed intent too: prior rename visibility is not
        # proof of a successful directory fsync. Never delete the journal here.
        self._store.replace(current, closed)
        self._journal = closed
        self.check()
