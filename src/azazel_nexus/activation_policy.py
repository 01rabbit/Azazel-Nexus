"""Read the protected activation policy; an inert input, never a grant (#206).

`docs/activation-observe-baseline.md` §2 names `activation_policy` as a
required producer: the operators authorized to approve activation, the lease
cap, the exact unit scope, the health floors and the clock skew. This module
decodes and reads that one fixed file. It does not verify an approval, build a
lease, measure health or widen anything. Since phase P4 the activation pass
reads it through `azazel_nexus_runtime.activation_pass`.

Every value can only narrow what a pass may grant:

*Scope is a subset of a code-fixed allowlist.* A policy naming any unit outside
`ACTIVATION_UNIT_ALLOWLIST` is refused as a whole; a file cannot add
enforcement, commissioning, watchdog, fetch or model-host units to the loop.

*The lease cap is capped in code.* `max_lease_seconds` above 72 hours is
refused, whatever the administrator wrote.

*The shape is closed and canonical.* Unknown, missing or duplicate fields,
non-canonical bytes and unsorted lists are refused, so `policy_digest` names
exactly one policy. The file is exactly `json.dumps(..., sort_keys=True,
separators=(",", ":"))` in UTF-8 with no trailing newline; an editor that
appends one makes the policy refused, deliberately.

*One optional field (#251 M-1).* `require_clock_synchronized` may be absent,
`false` or `true`. Absent or `false` changes nothing; `true` makes the pass's
`trusted_clock` producer also require proof that the OS clock was
synchronized in this boot. The field is kept exactly as written (absent
stays absent), so an existing policy keeps its bytes and its digest. The
schema stays v1: a reader from before this field refuses any policy that
carries it (closed shape), so an older package never ignores a `true`.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from typing import Optional

from .activation_store import _approval_directory, _private_directory, _read_file_at
from .operator_store import _unique_object
from .operator_trust import _OPERATOR, ApprovalRefused

__all__ = [
    "ACTIVATION_POLICY_SCHEMA",
    "ACTIVATION_UNIT_ALLOWLIST",
    "MAX_CLOCK_SKEW_SECONDS",
    "MAX_LEASE_SECONDS_CAP",
    "ActivationPolicy",
    "decode_activation_policy",
    "encode_activation_policy",
    "load_activation_policy",
]

ACTIVATION_POLICY_SCHEMA = "azazel-nexus/activation-policy/v1"

#: The integrated loop's units (§2). The SUPPORTING units, edge-core for
#: phase P5, the model-free reference service (proposed 2026-10-28,
#: `docs/activation-observe-baseline.md` §6.2; it runs no model) and the
#: loop's audit writer `azazel-auditd-loop.service` (2026-10-30, ADR 0008:
#: without it no Knowledge Lite import or trust change can be recorded on
#: the ordinary path), and the optional Knowledge Context egress broker. The
#: broker remains uncommissioned and absent from wired capabilities by default.
#: The bootstrap helpers auditd and commissiond, watchdog,
#: fetchd, locald and remoted stay excluded (§6.2) and cannot be named by a
#: policy.
ACTIVATION_UNIT_ALLOWLIST = (
    "azazel-auditd-loop.service",
    "azazel-edge-core.service",
    "azazel-edge-intaked.service",
    "azazel-edge-probed.service",
    "azazel-incident-explaind.service",
    "azazel-knowledge-contextd.service",
    "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
    "azazel-mio-referenced.service",
)

#: §6.1: a boot-free approval lives at most 72 hours.
MAX_LEASE_SECONDS_CAP = 72 * 3600
#: The tolerated backwards step of the OS clock against the persisted floor.
MAX_CLOCK_SKEW_SECONDS = 300

_FILE = "policy.json"
_LIMIT = 8192
_STATE_FLOORS = ("audit_bytes", "audit_inodes", "bootstrap_bytes", "bootstrap_inodes")
_RESOURCE_FLOORS = (
    "min_mission_available_mib", "min_online_logical_cpus", "min_usable_memory_mib",
)
_FIELDS = {
    "schema", "operators", "max_lease_seconds", "units",
    "state_floors", "resource_floors", "max_clock_skew_seconds",
}
#: Fields a policy may omit (#251 M-1). Absent and `false` both mean "not
#: required": the pass then behaves exactly as before the field existed.
_OPTIONAL_FIELDS = {"require_clock_synchronized"}


def _positive(value) -> bool:
    return type(value) is int and 0 < value < 2**63


def _floors(document, names) -> tuple[tuple[str, int], ...]:
    if type(document) is not dict or set(document) != set(names):
        raise ApprovalRefused("activation policy floors refused")
    if not all(_positive(document[name]) for name in names):
        raise ApprovalRefused("explicit positive activation health floors required")
    return tuple((name, document[name]) for name in sorted(names))


@dataclass(frozen=True)
class ActivationPolicy:
    """The decoded policy. Expected values, not a measurement or an approval.

    `state_floors` and `resource_floors` carry the field names of the
    runtime's bootstrap capacity and resource checks, which the health
    collector reuses; they are sorted `(name, value)` pairs so the record is
    immutable and hashable.
    """

    operators: tuple[str, ...]
    max_lease_seconds: int
    units: tuple[str, ...]
    state_floors: tuple[tuple[str, int], ...]
    resource_floors: tuple[tuple[str, int], ...]
    max_clock_skew_seconds: int
    policy_digest: str
    #: None when the file omits the field. Only `True` requires the pass to
    #: prove that the clock was synchronized (`clock_synchronization_required`).
    require_clock_synchronized: Optional[bool] = None

    def __post_init__(self):
        operators, units = self.operators, self.units
        if (type(operators) is not tuple or not operators
                or any(type(name) is not str or not _OPERATOR.fullmatch(name) for name in operators)
                or list(operators) != sorted(set(operators))):
            raise ApprovalRefused("activation policy operators refused")
        if (type(units) is not tuple or not units
                or any(type(unit) is not str for unit in units)
                or list(units) != sorted(set(units))
                or not set(units) <= set(ACTIVATION_UNIT_ALLOWLIST)):
            raise ApprovalRefused("activation policy unit scope refused")
        if (type(self.max_lease_seconds) is not int
                or not 0 < self.max_lease_seconds <= MAX_LEASE_SECONDS_CAP):
            raise ApprovalRefused("activation policy lease cap refused")
        if (type(self.max_clock_skew_seconds) is not int
                or not 0 <= self.max_clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS):
            raise ApprovalRefused("activation policy clock skew refused")
        if (self.require_clock_synchronized is not None
                and type(self.require_clock_synchronized) is not bool):
            raise ApprovalRefused("activation policy clock synchronization refused")
        for floors, names in ((self.state_floors, _STATE_FLOORS),
                              (self.resource_floors, _RESOURCE_FLOORS)):
            if (type(floors) is not tuple
                    or any(type(pair) is not tuple or len(pair) != 2 for pair in floors)):
                raise ApprovalRefused("activation policy floors refused")
            _floors(dict(floors), names)
            if [name for name, _ in floors] != sorted(names):
                raise ApprovalRefused("activation policy floors refused")
        if (type(self.policy_digest) is not str
                or self.policy_digest != "sha256:" + sha256(encode_activation_policy(self)).hexdigest()):
            raise ApprovalRefused("activation policy digest refused")

    @property
    def clock_synchronization_required(self) -> bool:
        """True only for an explicit `"require_clock_synchronized":true`."""
        return self.require_clock_synchronized is True

    def state_floor_values(self) -> dict[str, int]:
        return dict(self.state_floors)

    def resource_floor_values(self) -> dict[str, int]:
        return dict(self.resource_floors)


def encode_activation_policy(policy) -> bytes:
    """The one canonical byte form; `policy_digest` is SHA-256 over it.

    An absent `require_clock_synchronized` is not written, so a policy from
    before the field encodes to exactly the bytes it always did.
    """
    document = {
        "schema": ACTIVATION_POLICY_SCHEMA,
        "operators": list(policy.operators),
        "max_lease_seconds": policy.max_lease_seconds,
        "units": list(policy.units),
        "state_floors": dict(policy.state_floors),
        "resource_floors": dict(policy.resource_floors),
        "max_clock_skew_seconds": policy.max_clock_skew_seconds,
    }
    if policy.require_clock_synchronized is not None:
        document["require_clock_synchronized"] = policy.require_clock_synchronized
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def decode_activation_policy(raw: bytes) -> ActivationPolicy:
    """Decode exactly one canonical policy document, or refuse redacted."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _LIMIT:
            raise ApprovalRefused("activation policy size refused")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (type(document) is not dict or not _FIELDS <= set(document)
                or not set(document) <= _FIELDS | _OPTIONAL_FIELDS):
            raise ApprovalRefused("activation policy fields refused")
        if document["schema"] != ACTIVATION_POLICY_SCHEMA:
            raise ApprovalRefused("unsupported activation policy schema")
        operators, units = document["operators"], document["units"]
        if type(operators) is not list or type(units) is not list:
            raise ApprovalRefused("activation policy lists refused")
        digest = "sha256:" + sha256(raw).hexdigest()
        policy = ActivationPolicy(
            operators=tuple(operators),
            max_lease_seconds=document["max_lease_seconds"],
            units=tuple(units),
            state_floors=_floors(document["state_floors"], _STATE_FLOORS),
            resource_floors=_floors(document["resource_floors"], _RESOURCE_FLOORS),
            max_clock_skew_seconds=document["max_clock_skew_seconds"],
            policy_digest=digest,
            require_clock_synchronized=document.get("require_clock_synchronized"),
        )
        if encode_activation_policy(policy) != raw:
            raise ApprovalRefused("activation policy is not canonical")
        return policy
    except Exception:
        raise ApprovalRefused("activation policy refused") from None


def _read_at(directory_fd: int, *, owner: int) -> bytes:
    """Private descriptor seam for ordinary temporary-file tests."""
    _private_directory(directory_fd, owner=owner)
    return _read_file_at(directory_fd, _FILE, owner=owner, limit=_LIMIT)


def load_activation_policy() -> ActivationPolicy:
    """Read `/etc/azazel/activation/policy.json` twice through protected descriptors.

    Same directory and protections as the activation approval: root-owned
    `0700` directory, root-owned `0600` single-link regular file, no symlink
    at any component. A file replaced or rewritten between the reads is
    refused; there is no default, no creation and no fallback.
    """
    try:
        with _approval_directory() as fd:
            identity = os.fstat(fd)
            raw = _read_at(fd, owner=0)
            policy = decode_activation_policy(raw)
            with _approval_directory() as current:
                fresh = os.fstat(current)
                if ((identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino)
                        or _read_at(current, owner=0) != raw):
                    raise ApprovalRefused("activation policy changed")
            return policy
    except Exception:
        raise ApprovalRefused("protected activation policy refused") from None
