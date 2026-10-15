"""Pure projection of an explicitly admitted, bounded administrator UTC anchor.

Construction is NOT admission. A protected producer and administrator procedure
must establish the anchor's authority and uncertainty. No OS wall-clock fallback.
"""

from dataclasses import asdict, dataclass
from datetime import timedelta
import json
import re
from typing import NamedTuple

from .bootstrap_approval import BootstrapContext, parse_bootstrap_time
from .operator_trust import ApprovalRefused
from .operator_store import _unique_object

_NS = 1_000_000_000


class ProjectedAdministratorTime(NamedTuple):
    earliest_utc: str
    latest_utc: str
    observed_boottime_ns: int
    valid_until_boottime_ns: int


@dataclass(frozen=True)
class AdministratorClockLimits:
    max_anchor_lifetime_ns: int
    max_uncertainty_ns: int
    drift_ppb: int

    def __post_init__(self):
        for value in (self.max_anchor_lifetime_ns, self.max_uncertainty_ns):
            if type(value) is not int or not 0 < value < 2**63:
                raise ApprovalRefused("explicit bounded clock limits required")
        if type(self.drift_ppb) is not int or not 0 <= self.drift_ppb < _NS:
            raise ApprovalRefused("explicit clock drift bound required")


@dataclass(frozen=True, repr=False)
class AdministratorTimeAnchor:
    node_digest: str
    policy_digest: str
    boot_id: str
    earliest_utc: str
    latest_utc: str
    boottime_ns: int
    expires_boottime_ns: int

    def __post_init__(self):
        for value in (self.node_digest, self.policy_digest):
            if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                raise ApprovalRefused("clock anchor binding refused")
        if type(self.boot_id) is not str or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", self.boot_id) is None:
            raise ApprovalRefused("clock anchor boot refused")
        if parse_bootstrap_time(self.earliest_utc) > parse_bootstrap_time(self.latest_utc):
            raise ApprovalRefused("clock anchor interval reversed")
        if (type(self.boottime_ns) is not int or type(self.expires_boottime_ns) is not int
                or not 0 <= self.boottime_ns < self.expires_boottime_ns < 2**63):
            raise ApprovalRefused("bounded clock anchor lifetime required")


def encode_administrator_anchor(anchor: AdministratorTimeAnchor) -> bytes:
    if type(anchor) is not AdministratorTimeAnchor:
        raise ApprovalRefused("explicit administrator anchor required")
    return json.dumps({"schema": "azazel-nexus/administrator-clock-anchor/v1",
                       "source": "administrator-confirmed", **asdict(anchor)},
                      sort_keys=True, separators=(",", ":")).encode()


def decode_administrator_anchor(raw: bytes) -> AdministratorTimeAnchor:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= 4096:
            raise ApprovalRefused("bounded administrator clock record required")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        document.pop("schema")
        document.pop("source")
        anchor = AdministratorTimeAnchor(**document)
        if encode_administrator_anchor(anchor) != raw:
            raise ApprovalRefused("administrator clock schema/source/canonical form refused")
        return anchor
    except Exception:
        raise ApprovalRefused("administrator clock record refused") from None


def project_administrator_time(anchor: AdministratorTimeAnchor, *, expected: BootstrapContext,
                               boottime_ns: int, limits: AdministratorClockLimits) -> ProjectedAdministratorTime:
    """Return outward-rounded UTC bounds within the explicitly admitted boot.

    Expiry is nonrenewable here. Explicit policy drift widens the admitted
    initial interval; this computation cannot establish how initial uncertainty
    or oscillator bounds were measured. Limits require independent policy binding.
    """
    try:
        if (type(anchor) is not AdministratorTimeAnchor or type(expected) is not BootstrapContext
                or type(limits) is not AdministratorClockLimits
                or (anchor.node_digest, anchor.policy_digest, anchor.boot_id)
                != (expected.node_digest, expected.policy_digest, expected.boot_id)
                or type(boottime_ns) is not int
                or not anchor.boottime_ns <= boottime_ns < anchor.expires_boottime_ns
                or anchor.expires_boottime_ns - anchor.boottime_ns > limits.max_anchor_lifetime_ns):
            raise ApprovalRefused("clock anchor unavailable for this observation")
        elapsed = boottime_ns - anchor.boottime_ns
        drift = (elapsed * limits.drift_ppb + _NS - 1) // _NS
        earliest = parse_bootstrap_time(anchor.earliest_utc) + timedelta(seconds=(elapsed - drift) // _NS)
        latest = parse_bootstrap_time(anchor.latest_utc) + timedelta(seconds=(elapsed + drift + _NS - 1) // _NS)
        width = latest - earliest
        width_ns = (width.days * 86400 + width.seconds) * _NS + width.microseconds * 1000
        if width_ns > limits.max_uncertainty_ns:
            raise ApprovalRefused("projected clock uncertainty exceeds policy")
        return ProjectedAdministratorTime(
            earliest.isoformat(timespec="seconds").replace("+00:00", "Z"),
            latest.isoformat(timespec="seconds").replace("+00:00", "Z"),
            boottime_ns, anchor.expires_boottime_ns,
        )
    except Exception:
        raise ApprovalRefused("administrator time projection refused") from None


@dataclass(frozen=True, repr=False)
class AdministratorTimeWindow:
    """UTC envelope valid throughout its half-open BOOTTIME interval, not trust."""

    node_digest: str
    policy_digest: str
    boot_id: str
    earliest_utc: str
    latest_utc: str
    observed_boottime_ns: int
    valid_until_boottime_ns: int

    def __post_init__(self):
        AdministratorTimeAnchor(self.node_digest, self.policy_digest, self.boot_id,
                                self.earliest_utc, self.latest_utc,
                                self.observed_boottime_ns, self.valid_until_boottime_ns)


def project_administrator_window(anchor: AdministratorTimeAnchor, *, expected: BootstrapContext,
                                 boottime_ns: int, limits: AdministratorClockLimits) -> AdministratorTimeWindow:
    """Find a bounded validity window without assuming verification takes no time.

    Lower UTC is fixed at the sample; upper UTC covers the final included boot
    nanosecond. Monotonic upper projections permit a bounded integer search.
    No latency default is invented: the policy uncertainty budget limits reuse.
    """
    first = project_administrator_time(anchor, expected=expected, boottime_ns=boottime_ns, limits=limits)
    low, high = boottime_ns, anchor.expires_boottime_ns - 1
    best = first
    while low < high:
        midpoint = (low + high + 1) // 2
        try:
            projected = project_administrator_time(anchor, expected=expected,
                                                    boottime_ns=midpoint, limits=limits)
            width = parse_bootstrap_time(projected.latest_utc) - parse_bootstrap_time(first.earliest_utc)
            width_ns = (width.days * 86400 + width.seconds) * _NS + width.microseconds * 1000
            fits = width_ns <= limits.max_uncertainty_ns
        except ApprovalRefused:
            fits = False
        if fits:
            low, best = midpoint, projected
        else:
            high = midpoint - 1
    return AdministratorTimeWindow(anchor.node_digest, anchor.policy_digest, anchor.boot_id,
                                   first.earliest_utc, best.latest_utc, boottime_ns, low + 1)
