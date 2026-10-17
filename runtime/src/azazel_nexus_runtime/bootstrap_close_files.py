"""Held-descriptor owned-file closure for the connected narrowing sequence.

No directory opener here: trusted composition (the factory) retains descriptors and
the transaction lock for the complete sequence. Paths are independent expected
manager fragment locations, not paths learned from D-Bus or CLI inputs.
"""

import os
from pathlib import Path

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus.bootstrap_lock import BootstrapTransactionGuard

from .bootstrap_overlay_files import (
    _PAIR, _close_candidates_at, _closing_candidate, _mask_paths, _present,
)
from .units import UNIT_NAMES, UnitKey
from .bootstrap_directory_paths import bind_directory_path


class BootstrapClosedOverlayFiles:
    """Close and repeatedly recheck the retained journal-owned regular files."""

    def __init__(self, *, overlay_fd, masks_fd, higher_priority_fd,
                 overlay_path, masks_path, higher_priority_path,
                 journal_store, guard, owner_uid):
        if type(guard) is not BootstrapTransactionGuard:
            raise ApprovalRefused("held closure transaction guard required")
        self._arguments = dict(
            overlay_fd=overlay_fd, masks_fd=masks_fd,
            higher_priority_fd=higher_priority_fd, journal_store=journal_store,
            guard=guard, owner_uid=owner_uid,
        )
        self._paths = tuple(Path(path) for path in
                            (overlay_path, masks_path, higher_priority_path))
        self._fds = (overlay_fd, masks_fd, higher_priority_fd)
        self._journal = None
        self._stamps = None
        self._initial = False
        self._bind_paths()

    def _bind_paths(self):
        for path, fd in zip(self._paths, self._fds, strict=True):
            bind_directory_path(path, fd)

    def _mask_stamps(self):
        return _mask_paths(**{key: self._arguments[key] for key in
                             ("overlay_fd", "masks_fd", "higher_priority_fd", "owner_uid")})

    def close(self):
        self._bind_paths()
        current = self._arguments["journal_store"].load_optional()
        if current is None:
            if self._journal is not None:
                raise ApprovalRefused("retained overlay journal disappeared")
            self._initial = True
            self._stamps = self._mask_stamps()
            self.check()
            return
        self._initial = False
        self._journal = _close_candidates_at(**self._arguments)
        self._stamps = self._mask_stamps()
        self.check()

    def initial_baseline(self) -> bool:
        """Whether the latest close() found no journal; not a never-existed proof."""
        return self._initial is True and self._journal is None

    def check(self):
        if self._initial:
            return self._check_initial()
        if self._journal is None or self._journal.phase != "closing":
            raise ApprovalRefused("owned close has not completed")
        args = self._arguments

        def stable():
            args["guard"]()
            self._bind_paths()
            if (args["journal_store"].load() != self._journal
                    or self._mask_stamps() != self._stamps):
                raise ApprovalRefused("owned closure state changed")

        stable()
        owned = {unit: (device, inode, digest)
                 for unit, device, inode, digest in self._journal.owned_files}
        fragments = []
        for key in (UnitKey.AUDITD, UnitKey.COMMISSIOND):
            unit = UNIT_NAMES[key]
            if unit not in _PAIR:
                raise ApprovalRefused("closure pair changed")
            if unit in owned:
                device, inode, digest = owned[unit]
                with _closing_candidate(
                    args["overlay_fd"], unit, (device, inode), digest,
                    owner_uid=args["owner_uid"], allow_empty=True,
                ) as fd:
                    if os.fstat(fd).st_size != 0:
                        raise ApprovalRefused("owned closure is not empty")
                directory = self._paths[0]
            else:
                if _present(args["overlay_fd"], unit):
                    raise ApprovalRefused("unowned closure candidate exists")
                directory = self._paths[1]
            fragments.append((key, str(directory / unit)))
        stable()
        return tuple(fragments)

    def _check_initial(self):
        """No owned files or invented journal; only a persistent-mask baseline."""
        args = self._arguments

        def stable():
            args["guard"]()
            self._bind_paths()
            if (args["journal_store"].load_optional() is not None
                    or self._mask_stamps() != self._stamps):
                raise ApprovalRefused("initial bootstrap baseline changed")

        stable()
        if any(_present(args["overlay_fd"], unit) for unit in _PAIR):
            raise ApprovalRefused("unjournaled bootstrap overlay exists")
        stable()
        return tuple((key, str(self._paths[1] / UNIT_NAMES[key]))
                     for key in (UnitKey.AUDITD, UnitKey.COMMISSIOND))
