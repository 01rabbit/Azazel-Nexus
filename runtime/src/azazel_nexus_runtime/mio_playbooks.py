"""Verified reasoning playbooks for a process that holds no model.

Shared by the model-free reference service (`mio_referenced`) and the local
runtime host (`mio_locald`). Importing it loads no runtime, admission,
embedding or Knowledge code: selecting verified prose is not running a model.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus.audit import AuditUnavailable
from azazel_nexus.playbook_selection import (
    PlaybookSelection,
    active_playbooks,
    retained_paths,
    selection_context,
)
from azazel_nexus.reasoning_playbook import Library

__all__ = ["PlaybookSelectionHolder"]


class PlaybookSelectionHolder:
    """Cache verified layers; inspect only file metadata until state changes.

    Trust/config, pointer, retained bytes and selected assets invalidate the
    cache, including failures. Expiry removes references even if no files
    change; restored files or permissions invalidate failed selections.
    """

    def __init__(self, *, config: Path, root: Path, clock=None):
        self.config = config
        self.root = root
        self.clock = clock or (lambda: datetime.now(UTC).isoformat().replace('+00:00', 'Z'))
        self.selection = PlaybookSelection(None, 'no_pack')
        self._revision = None
        self._watch_paths = ()
        self._audited = False

    def _fingerprint(self, watch_paths):
        result = []
        for path in (self.config, self.root, self.root / 'generations',
                     self.root / 'current', *watch_paths):
            try:
                info = path.lstat()
                result.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                               info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid))
            except OSError as error:
                result.append((type(error).__name__, error.errno))
        return tuple(result)

    def refresh(self, *, audit: Callable[[dict], None]) -> Library | None:
        now = self.clock()
        revision = self._fingerprint(self._watch_paths)
        expired = (self.selection.expires_at is not None
                   and datetime.fromisoformat(now) >= datetime.fromisoformat(self.selection.expires_at))
        if (self._revision == revision and not expired):
            return self.selection.library
        watch_paths = ()
        before = None
        try:
            watch_paths = retained_paths(self.root)
            if not watch_paths:
                selection = PlaybookSelection(None, 'no_pack')
            else:
                context = selection_context(self.config, self.root)
                watch_paths += tuple(asset.path for key, asset in context.assets.items()
                                     if key[0] == 'reasoning_playbook')
                before = self._fingerprint(watch_paths)
                selection = active_playbooks(context, now=now)
        except PermissionError:
            selection = PlaybookSelection(None, 'store_unreadable')
        except Exception as error:
            if isinstance(error, AuditUnavailable):
                raise
            selection = PlaybookSelection(None, 'pack_degraded')
        previous = self.selection
        after = self._fingerprint(watch_paths)
        # Compare the NEW paths on both sides of verification. The old paths
        # also cover config/pointer changes during discovery or config reads.
        stable = (revision == self._fingerprint(self._watch_paths)
                  and (before is None or before == after))
        self.selection = selection
        self._watch_paths = watch_paths
        self._revision = after if stable else None
        if not self._audited or selection != previous or self._revision is None:
            audit(selection.as_event())
            self._audited = True
        return selection.library
