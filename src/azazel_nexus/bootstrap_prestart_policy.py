"""Administrator pre-start policy bindings, not measured health or admission.

This policy describes existing-history bootstrap only. First-install genesis
and external rollback anchoring cannot be represented as implicit defaults.
"""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re

from .bootstrap_approval import BOOTSTRAP_UNITS, BootstrapContext
from .bootstrap_clock import AdministratorClockLimits
from .operator_store import _unique_object
from .operator_trust import ApprovalRefused


@dataclass(frozen=True, repr=False)
class BootstrapPrestartPolicy:
    """Protected expected values; not a measured health/admission report.

    ``unit_closure_digest`` pins the canonical selected-installed-files
    manifest used by bootstrap admission. The selected-file measurement is
    intentionally narrower than complete process/import/systemd closure.
    """

    package_digest: str
    unit_closure_digest: str
    systemd_profile_digest: str
    min_usable_memory_mib: int
    min_online_logical_cpus: int
    min_mission_available_mib: int
    bootstrap_bytes: int
    bootstrap_inodes: int
    audit_bytes: int
    audit_inodes: int
    audit_sequence: int
    audit_head: str
    max_audit_bytes: int
    max_audit_segments: int
    max_anchor_lifetime_ns: int
    max_uncertainty_ns: int
    drift_ppb: int
    loaded_policy_digest: str | None = None

    def __post_init__(self):
        self.clock_limits()
        for name, value in asdict(self).items():
            if name == "drift_ppb":
                continue  # Explicit zero is permitted; exact type/range checked above.
            if name == "loaded_policy_digest" and value is None:
                continue
            if name in {"package_digest", "unit_closure_digest", "systemd_profile_digest", "audit_head"}:
                pattern = r"[0-9a-f]{64}" if name == "audit_head" else r"sha256:[0-9a-f]{64}"
                if type(value) is not str or re.fullmatch(pattern, value) is None:
                    raise ApprovalRefused("prestart policy digest refused")
            elif name == "loaded_policy_digest":
                if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                    raise ApprovalRefused("prestart policy digest refused")
            elif type(value) is not int or not 0 < value < 2**63:
                raise ApprovalRefused("explicit bounded prestart policy values required")

    def clock_limits(self) -> AdministratorClockLimits:
        return AdministratorClockLimits(self.max_anchor_lifetime_ns, self.max_uncertainty_ns, self.drift_ppb)


def encode_prestart_policy(policy: BootstrapPrestartPolicy) -> bytes:
    if type(policy) is not BootstrapPrestartPolicy:
        raise ApprovalRefused("explicit prestart policy required")
    version = "v4" if policy.loaded_policy_digest is not None else "v3"
    values = asdict(policy)
    if version == "v3":
        values.pop("loaded_policy_digest")
    return json.dumps({
        "schema": f"azazel-nexus/bootstrap-prestart-policy/{version}",
        "units": BOOTSTRAP_UNITS, "audit_assurance": "LOCAL_CONTINUITY_ONLY",
        "audit_mode": "existing-history", **values,
    }, sort_keys=True, separators=(",", ":")).encode()


def decode_prestart_policy(raw: bytes, *, expected: BootstrapContext) -> BootstrapPrestartPolicy:
    """Bind the independently pinned policy to the complete expected context."""
    try:
        if type(expected) is not BootstrapContext:
            raise ApprovalRefused("independent bootstrap context required")
        policy = decode_pinned_prestart_policy(raw, expected_digest=expected.policy_digest)
        if (policy.package_digest != expected.package_digest
                or policy.unit_closure_digest != expected.unit_closure_digest):
            raise ApprovalRefused("prestart policy scope/bindings differ")
        return policy
    except Exception:
        raise ApprovalRefused("bootstrap prestart policy refused") from None


def decode_pinned_prestart_policy(raw: bytes, *, expected_digest: str) -> BootstrapPrestartPolicy:
    """Decode declared expectations before context construction, not measurements."""
    try:
        if (type(expected_digest) is not str or type(raw) is not bytes
                or not 0 < len(raw) <= 8192
                or "sha256:" + sha256(raw).hexdigest() != expected_digest):
            raise ApprovalRefused("independent full policy digest differs")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(document) is not dict:
            raise ApprovalRefused("prestart policy object required")
        schema = document.get("schema")
        has_loaded_digest = "loaded_policy_digest" in document
        if schema == "azazel-nexus/bootstrap-prestart-policy/v3":
            if has_loaded_digest:
                raise ApprovalRefused("v3 policy cannot contain loaded policy digest")
        elif schema == "azazel-nexus/bootstrap-prestart-policy/v4":
            if not has_loaded_digest or document["loaded_policy_digest"] is None:
                raise ApprovalRefused("v4 loaded policy digest required")
        else:
            raise ApprovalRefused("unsupported prestart policy schema")
        for key in ("schema", "units", "audit_assurance", "audit_mode"):
            document.pop(key)
        policy = BootstrapPrestartPolicy(**document)
        if encode_prestart_policy(policy) != raw:
            raise ApprovalRefused("prestart policy scope/bindings differ")
        return policy
    except Exception:
        raise ApprovalRefused("bootstrap prestart policy refused") from None
