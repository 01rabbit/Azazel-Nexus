"""Bounded, read-only comparison of the live audit writer head.

The writer head is an in-memory observation made by auditd after it verifies
its chain at startup and serializes subsequent appends. It is not a fresh
disk re-verification, an independent rollback anchor, or proof against a
privileged writer outside the auditd trust boundary. This adapter only reads
that head; it does not start auditd, append records, or grant authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Protocol

from azazel_nexus.audit import GENESIS_HASH
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_audit import AuditObservation

_HASH = re.compile(r"[0-9a-f]{64}\Z")


class _HeadReader(Protocol):
    def observe_head(self) -> tuple[int, str]: ...


@dataclass(frozen=True)
class WriterHead:
    """A distinct value type for auditd's live in-memory writer head."""

    sequence: int
    digest: str

    def __post_init__(self) -> None:
        if (type(self.sequence) is not int or self.sequence < 0
                or type(self.digest) is not str or not _HASH.fullmatch(self.digest)
                or (self.sequence == 0) != (self.digest == GENESIS_HASH)):
            raise ValueError("invalid writer head")


class BootstrapLiveAuditHead:
    """Compare a live writer head to stopped-writer disk evidence.

    The first successful read must exactly match the stopped-writer
    ``AuditObservation``. Later reads may advance monotonically. Equal sequence
    numbers must retain the same digest. Any malformed, stale, or inconsistent
    result is rejected with a redacted ``ApprovalRefused``.
    """

    def __init__(self, stopped: AuditObservation, reader: _HeadReader):
        if (type(stopped) is not AuditObservation
                or not callable(getattr(reader, "observe_head", None))):
            raise ApprovalRefused("bootstrap audit head comparison unavailable")
        try:
            expected = WriterHead(stopped.sequence, stopped.digest)
        except Exception:
            raise ApprovalRefused("bootstrap audit head comparison unavailable") from None
        self._stopped = expected
        self._reader = reader
        self._last: WriterHead | None = None

    def verify_startup(self) -> WriterHead:
        """Require exact equality with the stopped-writer observation."""
        if self._last is not None:
            raise ApprovalRefused("bootstrap audit startup head already observed")
        current = self._read()
        if current != self._stopped:
            raise ApprovalRefused("bootstrap audit startup head differs")
        self._last = current
        return current

    def observe(self) -> WriterHead:
        """Accept only an unchanged or monotonically advanced live head."""
        if self._last is None:
            raise ApprovalRefused("bootstrap audit startup head not verified")
        current = self._read()
        previous = self._last
        if (current.sequence < previous.sequence
                or (current.sequence == previous.sequence
                    and current.digest != previous.digest)):
            raise ApprovalRefused("bootstrap audit live head is stale or inconsistent")
        self._last = current
        return current

    def _read(self) -> WriterHead:
        try:
            result = self._reader.observe_head()
            if type(result) is not tuple or len(result) != 2:
                raise ValueError("malformed head")
            return WriterHead(result[0], result[1])
        except Exception:
            raise ApprovalRefused("bootstrap audit live head unavailable") from None
