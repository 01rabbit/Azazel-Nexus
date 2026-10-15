"""Pure bootstrap deadline transitions, not a service or durable state store.

Callers must durably retain initial/advanced state before any widening or
continued use. Missing retained state is never replaced by revalidation.
The production clock/trust and persistence composition remain unimplemented.
"""

from dataclasses import dataclass, replace
import time

from .bootstrap_approval import VerifiedBootstrapApproval, _utc
from .operator_trust import ApprovalRefused

_NS_PER_SECOND = 1_000_000_000


def read_boottime_ns() -> int:
    """Suspend-inclusive Linux elapsed time only; no MONOTONIC fallback."""
    try:
        value = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _elapsed(value)
        return value
    except (AttributeError, OSError, ValueError):
        raise ApprovalRefused("suspend-inclusive boot clock unavailable") from None


def _elapsed(value: int) -> None:
    if type(value) is not int or value < 0:
        raise ApprovalRefused("invalid boot elapsed time")


def _observe(approval: VerifiedBootstrapApproval, *, boot_id: str,
             now: str, boottime_ns: int, clock_trusted: bool):
    if type(approval) is not VerifiedBootstrapApproval:
        raise ApprovalRefused("freshly verified bootstrap approval required")
    if clock_trusted is not True:
        raise ApprovalRefused("independent trusted clock observation required")
    if type(boot_id) is not str or boot_id != approval.context.boot_id:
        raise ApprovalRefused("bootstrap boot binding changed")
    _elapsed(boottime_ns)
    instant, start, end = _utc(now), _utc(approval.granted_at), _utc(approval.expires_at)
    if not start <= instant < end:
        raise ApprovalRefused("bootstrap UTC interval expired or not started")
    return instant, end


@dataclass(frozen=True)
class BootstrapDeadline:
    """State that a protected store must retain; not an authorization token.

    Full approval equality binds node, generation, policies, operator,
    revocation and epoch as well as its signed payload digest. Fresh signature
    verification is still required on every revalidation, not cached here.
    """

    approval: VerifiedBootstrapApproval
    admitted_at: str
    admitted_boottime_ns: int
    deadline_boottime_ns: int
    last_utc: str
    last_boottime_ns: int

    def __post_init__(self):
        if type(self.approval) is not VerifiedBootstrapApproval:
            raise ApprovalRefused("invalid retained bootstrap approval")
        for value in (self.admitted_boottime_ns, self.deadline_boottime_ns, self.last_boottime_ns):
            _elapsed(value)
        admitted, last, expiry = _utc(self.admitted_at), _utc(self.last_utc), _utc(self.approval.expires_at)
        if not _utc(self.approval.granted_at) <= admitted <= last < expiry:
            raise ApprovalRefused("invalid retained UTC interval")
        remaining_ns = int((expiry - admitted).total_seconds()) * _NS_PER_SECOND
        if self.deadline_boottime_ns != self.admitted_boottime_ns + remaining_ns:
            raise ApprovalRefused("retained deadline does not match original admission")
        if not self.admitted_boottime_ns <= self.last_boottime_ns < self.deadline_boottime_ns:
            raise ApprovalRefused("invalid retained boot-clock interval")


def begin_deadline(approval: VerifiedBootstrapApproval, *, boot_id: str,
                   now: str, boottime_ns: int, clock_trusted: bool) -> BootstrapDeadline:
    """Construct initial state only; controller must guard first admission.

    This pure function cannot discover previous admission. It must never be
    used to recover a missing record or renew a previously consumed approval.
    """
    instant, end = _observe(approval, boot_id=boot_id, now=now,
                            boottime_ns=boottime_ns, clock_trusted=clock_trusted)
    remaining_ns = int((end - instant).total_seconds()) * _NS_PER_SECOND
    return BootstrapDeadline(approval, now, boottime_ns, boottime_ns + remaining_ns,
                             now, boottime_ns)


def revalidate_deadline(retained: BootstrapDeadline, *, approval: VerifiedBootstrapApproval,
                        boot_id: str, now: str, boottime_ns: int,
                        clock_trusted: bool) -> BootstrapDeadline:
    """Advance high-water observations without changing the original deadline.

    `approval` must be freshly verified with current protected trust/context.
    A local saved high-water is not an independent anti-rollback anchor.
    """
    if type(retained) is not BootstrapDeadline:
        raise ApprovalRefused("retained bootstrap deadline required; no restart fallback")
    instant, _end = _observe(approval, boot_id=boot_id, now=now,
                             boottime_ns=boottime_ns, clock_trusted=clock_trusted)
    if approval != retained.approval:
        raise ApprovalRefused("retained bootstrap approval binding changed")
    if instant < _utc(retained.last_utc) or boottime_ns < retained.last_boottime_ns:
        raise ApprovalRefused("bootstrap clock moved backward")
    if boottime_ns >= retained.deadline_boottime_ns:
        raise ApprovalRefused("bootstrap elapsed deadline expired")
    return replace(retained, last_utc=now, last_boottime_ns=boottime_ns)
