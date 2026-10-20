"""Bounded per-daemon refusal logs (#211).

Every socket daemon records the requests it turned away in its own
`refusals.jsonl` (`runtime_paths.audit_sink`). That file is diagnostic state,
not audit evidence: it is not hash-chained, nothing verifies it, and the
audit chain (`az-auditd`) and the M.I.O. route ledger are separate files with
their own limits. Before this module it had no bound at all: anything that
could reach a socket could grow it one line per malformed frame until
`/var/lib` was full.

Two bounds apply, and both are local to the writing daemon:

* **Aggregation.** A `runtime.request_refused` event is keyed on the caller's
  kernel-reported uid and the refusal reason. The first refusal of a key is
  written as it is. Further refusals of that key within `window_s` are only
  counted; when the window ends with a non-zero count, one
  `runtime.request_refused_summary` line carries the count and the last
  suppressed refusal's fingerprint (and verb, when it had one), and a new
  window opens. A steady flood therefore writes at most one line per key per
  window. The serve loop calls `flush_due` between connections, so the count
  is written even if the flood has stopped. At most `max_keys` keys are
  tracked; the oldest is summarized and dropped to make room.
* **Size.** Before a line would take a file past `max_bytes`, the file is
  rotated: `<name>.<keep-1>` replaces `<name>.<keep>` (the oldest is thereby
  deleted), and so on down to `<name>` becoming `<name>.1`.

Other events written through the same sink (Knowledge Lite's
`knowledge.lookup`) go to a sibling `events.jsonl` with its own rotation, so
a flood of them can never rotate a refusal line away. A daemon's refusal
records take at most `max_bytes * (keep + 1)` bytes on disk, and its other
events as much again.

A refused request did nothing, so a refusal that cannot be written is counted
in `unrecorded` (one per refusal the lost line stood for) and never raised
into the request path. Files keep the mode they always had (created `0666`
less the daemon's umask); rotation is a rename within the same directory, so
a rotated file keeps its mode and owner. Each line is one `write(2)` on an
`O_APPEND` descriptor, so a line is never interleaved or half-rotated; lines
are not fsynced (as before: this is diagnostic state, and a flood must not
become a flood of fsyncs), while a rotation's renames are made durable with a
directory fsync.
"""

from __future__ import annotations

import json
import os
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path

__all__ = [
    "EVENTS_FILE_NAME",
    "REFUSAL_EVENT",
    "REFUSAL_LOG_KEEP",
    "REFUSAL_LOG_MAX_BYTES",
    "REFUSAL_LOG_MAX_KEYS",
    "REFUSAL_LOG_WINDOW_S",
    "REFUSAL_SUMMARY_EVENT",
    "BoundedRefusalLog",
]

#: The size at which `refusals.jsonl` (and `events.jsonl`) is rotated.
REFUSAL_LOG_MAX_BYTES = 4 * 1024 * 1024
#: How many rotated files are kept (`refusals.jsonl.1` .. `.N`).
REFUSAL_LOG_KEEP = 2
#: Refusals of one (uid, reason) within this many seconds share one line.
REFUSAL_LOG_WINDOW_S = 60.0
#: How many (uid, reason) windows are tracked at once.
REFUSAL_LOG_MAX_KEYS = 1024
#: Where a daemon's events that are not refusals go, beside `refusals.jsonl`.
EVENTS_FILE_NAME = "events.jsonl"

REFUSAL_EVENT = "runtime.request_refused"
REFUSAL_SUMMARY_EVENT = "runtime.request_refused_summary"

_OPEN_FLAGS = (os.O_WRONLY | os.O_APPEND | os.O_CREAT
               | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))


class _RotatingFile:
    """One append-only file, rotated by size."""

    def __init__(self, path: Path, *, max_bytes: int, keep: int) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.keep = keep
        self.rotations = 0

    def write(self, event) -> None:
        line = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        fd = os.open(self.path, _OPEN_FLAGS, 0o666)
        try:
            size = os.fstat(fd).st_size
            if size and size + len(line) > self.max_bytes:
                os.close(fd)
                fd = -1
                self._rotate()
                fd = os.open(self.path, _OPEN_FLAGS, 0o666)
            if os.write(fd, line) != len(line):
                raise OSError("short write to refusal log")
        finally:
            if fd >= 0:
                os.close(fd)

    def _rotated(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    def _rotate(self) -> None:
        if self.keep == 0:
            self.path.unlink()
        else:
            for index in range(self.keep, 0, -1):
                source = self.path if index == 1 else self._rotated(index - 1)
                try:
                    os.replace(source, self._rotated(index))
                except FileNotFoundError:
                    continue
        self.rotations += 1
        _sync_directory(self.path.parent)


class BoundedRefusalLog:
    """A refusal sink: call it with an event; it never raises."""

    def __init__(
        self,
        path: Path,
        *,
        max_bytes: int = REFUSAL_LOG_MAX_BYTES,
        keep: int = REFUSAL_LOG_KEEP,
        window_s: float = REFUSAL_LOG_WINDOW_S,
        max_keys: int = REFUSAL_LOG_MAX_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_bytes < 1 or keep < 0 or window_s <= 0 or max_keys < 1:
            raise ValueError("refusal log bounds must be positive")
        self.path = Path(path)
        self.events_path = self.path.with_name(EVENTS_FILE_NAME)
        self.max_bytes = max_bytes
        self.keep = keep
        self.window_s = window_s
        self.max_keys = max_keys
        self._clock = clock
        self._refusals = _RotatingFile(self.path, max_bytes=max_bytes, keep=keep)
        self._events = _RotatingFile(self.events_path, max_bytes=max_bytes, keep=keep)
        # (uid, reason) -> [opened at, count since, last fingerprint, last verb]
        self._windows: OrderedDict[tuple, list] = OrderedDict()
        self.written = 0
        self.suppressed = 0
        self.unrecorded = 0

    @property
    def rotations(self) -> int:
        return self._refusals.rotations + self._events.rotations

    def counters(self) -> dict:
        """Totals since start, for a daemon's status answer."""
        return {
            "written": self.written,
            "suppressed": self.suppressed,
            "unrecorded": self.unrecorded,
            "rotations": self.rotations,
        }

    # -- the sink ----------------------------------------------------------

    def __call__(self, event: dict) -> None:
        try:
            now = self._clock()
            self._flush(now)
            if not isinstance(event, dict) or event.get("event_type") != REFUSAL_EVENT:
                self._write(self._events, event)
                return
            uid = event.get("uid")
            key = (uid if type(uid) is int else None, str(event.get("reason")))
            window = self._windows.get(key)
            if window is not None:
                # `_flush` has already closed every expired window.
                window[1] += 1
                window[2] = event.get("request_fingerprint")
                window[3] = event.get("verb")
                self.suppressed += 1
                return
            self._windows[key] = [now, 0, None, None]
            while len(self._windows) > self.max_keys:
                oldest, evicted = self._windows.popitem(last=False)
                if evicted[1]:
                    self._summarize(oldest, evicted)
            self._write(self._refusals, event)
        except Exception:  # noqa: BLE001 - a refusal log never fails the request
            self.unrecorded += 1

    def flush_due(self) -> None:
        """Write the summaries whose window has ended. Called by the serve loop."""
        try:
            self._flush(self._clock())
        except Exception:  # noqa: BLE001
            self.unrecorded += 1

    # -- internals ---------------------------------------------------------

    def _flush(self, now: float) -> None:
        # Windows are ordered by when they opened, so the expired ones are a
        # prefix: this stops at the first window still open.
        while self._windows:
            key, window = next(iter(self._windows.items()))
            if now - window[0] < self.window_s:
                return
            del self._windows[key]
            if window[1]:
                # Re-open at once so a flood that continues is still counted,
                # not written line by line.
                self._windows[key] = [now, 0, None, None]
                self._summarize(key, window)

    def _summarize(self, key: tuple, window: list) -> None:
        uid, reason = key
        _, count, fingerprint, verb = window
        summary = {
            "event_type": REFUSAL_SUMMARY_EVENT,
            "uid": uid,
            "reason": reason,
            "suppressed": count,
            "window_s": self.window_s,
            "unrecorded": self.unrecorded,
            "last_request_fingerprint": fingerprint,
        }
        if verb is not None:
            summary["last_verb"] = verb
        try:
            self._write(self._refusals, summary)
        except Exception:  # noqa: BLE001
            # Every refusal the summary stood for is now in no file.
            self.unrecorded += count

    def _write(self, target: _RotatingFile, event) -> None:
        target.write(event)
        self.written += 1


def _sync_directory(directory: Path) -> None:
    """Make the renames durable; a failure here loses nothing already written."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
