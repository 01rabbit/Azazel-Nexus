"""Protected, non-widening expectations for loaded bootstrap helpers."""

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from azazel_nexus.bootstrap_prestart_store import load_bootstrap_prestart_policy
from azazel_nexus.bootstrap_store import read_bootstrap_loaded_policy
from azazel_nexus.bootstrap_prestart_policy import BootstrapPrestartPolicy
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_loaded import _DEPENDENCIES, _dependency_policy, _service_policy
from .hardening import PROFILES
from .units import UNIT_NAMES, UnitKey

_SCHEMA = "azazel-nexus/loaded-bootstrap-units/v1"
_LIMIT = 65_536
_UNITS = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
_UNIT_NAMES = tuple(UNIT_NAMES[unit] for unit in _UNITS)
_SETTINGS = (
    "TimeoutStartUSec", "TimeoutStopUSec", "RuntimeMaxUSec", "WatchdogUSec",
    "SetLoginEnvironment",
)
# The exact-pair bootstrap does not admit asynchronous handler/trigger paths
# or a unit that can keep a helper running independently of its supervisor.
# Pinning such a relationship is not semantic authorization to activate it.
_ACTIVATION_CHANNELS = frozenset({
    "Upholds", "UpheldBy", "OnFailure", "OnSuccess", "OnFailureOf",
    "OnSuccessOf", "Triggers", "TriggeredBy",
})


@dataclass(frozen=True)
class LoadedUnitPolicy:
    unit: UnitKey
    _dependencies: tuple[tuple[str, tuple[str, ...]], ...]
    _service_settings: tuple[tuple[str, int | bool], ...]

    @property
    def dependencies(self) -> dict[str, frozenset[str]]:
        return {key: frozenset(names) for key, names in self._dependencies}

    @property
    def service_settings(self) -> dict[str, int | bool]:
        return dict(self._service_settings)


@dataclass(frozen=True)
class LoadedBootstrapPolicy:
    digest: str
    systemd_profile_digest: str
    _units: tuple[LoadedUnitPolicy, ...]

    @property
    def units(self) -> dict[UnitKey, LoadedUnitPolicy]:
        return {item.unit: item for item in self._units}


def _profile_azazel_edges():
    profiles = {profile.unit: profile for profile in PROFILES}
    if any(name not in profiles for name in _UNIT_NAMES):
        raise ApprovalRefused("loaded helper profiles unavailable")
    expected = {unit: {key: set() for key in _DEPENDENCIES} for unit in _UNITS}
    direct = (("after", "After"), ("requires", "Requires"), ("binds_to", "BindsTo"))
    for unit in _UNITS:
        profile = profiles[UNIT_NAMES[unit]]
        for field, key in direct:
            for name in getattr(profile, field, ()):
                if name.startswith("azazel-"):
                    expected[unit][key].add(name)
    # In-pair inverse sets (Before/RequiredBy/BoundBy) are recorded EMPTY: systemd
    # garbage-collects an inactive peer, so a freshly loaded single unit never
    # reports them. The loaded inspector tolerates exactly commissiond in auditd's
    # three inverse sets once commissiond is loaded; any other name fails closed.
    return expected


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalRefused("duplicate loaded policy key")
        result[key] = value
    return result


def _canonical_document(raw: bytes):
    if type(raw) is not bytes or not 0 < len(raw) <= _LIMIT:
        raise ApprovalRefused("loaded policy size refused")
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if type(document) is not dict or set(document) != {
        "schema", "systemd_profile_digest", "units"
    } or document["schema"] != _SCHEMA:
        raise ApprovalRefused("loaded policy schema refused")
    if json.dumps(document, sort_keys=True, separators=(",", ":")).encode() != raw:
        raise ApprovalRefused("loaded policy must be canonical")
    return document


def decode_loaded_bootstrap_policy(raw: bytes, *, prestart_policy) -> LoadedBootstrapPolicy:
    """Decode one canonical file against protected v4 pre-start policy pins."""
    try:
        if (type(prestart_policy) is not BootstrapPrestartPolicy
                or getattr(prestart_policy, "loaded_policy_digest", None) is None):
            raise ApprovalRefused("v4 pre-start policy with loaded digest required")
        document = _canonical_document(raw)
        digest = "sha256:" + sha256(raw).hexdigest()
        profile_digest = document["systemd_profile_digest"]
        if (digest != prestart_policy.loaded_policy_digest
                or profile_digest != prestart_policy.systemd_profile_digest):
            raise ApprovalRefused("loaded policy digest or systemd profile differs")
        if (type(profile_digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", profile_digest) is None):
            raise ApprovalRefused("loaded policy profile digest malformed")
        units = document["units"]
        if type(units) is not dict or set(units) != set(_UNIT_NAMES):
            raise ApprovalRefused("exact loaded helper pair required")
        profile_edges = _profile_azazel_edges()
        decoded = []
        for unit in _UNITS:
            record = units[UNIT_NAMES[unit]]
            if type(record) is not dict or set(record) != {"dependencies", "service_settings"}:
                raise ApprovalRefused("loaded helper policy shape refused")
            dependencies = record["dependencies"]
            # JSON arrays are converted into the frozen API expected by the shared validator.
            if type(dependencies) is not dict or set(dependencies) != set(_DEPENDENCIES):
                raise ApprovalRefused("complete loaded dependency map required")
            dependency_sets = {}
            for key in _DEPENDENCIES:
                names = dependencies[key]
                if (type(names) is not list or any(type(name) is not str for name in names)
                        or names != sorted(set(names))):
                    raise ApprovalRefused("canonical dependency names required")
                dependency_sets[key] = frozenset(names)
                if key in _ACTIVATION_CHANNELS and names:
                    raise ApprovalRefused("bootstrap asynchronous activation relationship refused")
                observed_azazel = {name for name in names if name.startswith("azazel-")}
                if observed_azazel != profile_edges[unit][key]:
                    raise ApprovalRefused("loaded helper Nexus dependency differs from profile")
            _dependency_policy(unit, dependency_sets)
            settings = record["service_settings"]
            if type(settings) is not dict or set(settings) != set(_SETTINGS):
                raise ApprovalRefused("exact loaded service settings required")
            _service_policy(settings)
            decoded.append(LoadedUnitPolicy(
                unit=unit,
                _dependencies=tuple((key, tuple(dependencies[key])) for key in _DEPENDENCIES),
                _service_settings=tuple((key, settings[key]) for key in _SETTINGS),
            ))
        return LoadedBootstrapPolicy(digest, profile_digest, tuple(decoded))
    except Exception:
        raise ApprovalRefused("protected loaded bootstrap policy refused") from None


def load_loaded_bootstrap_policy(*, expected) -> LoadedBootstrapPolicy:
    """Read stable protected loaded-unit expectations; no systemd calls."""
    try:
        prestart = load_bootstrap_prestart_policy(expected=expected)
        raw = read_bootstrap_loaded_policy()
        policy = decode_loaded_bootstrap_policy(raw, prestart_policy=prestart)
        if load_bootstrap_prestart_policy(expected=expected) != prestart:
            raise ApprovalRefused("pre-start policy changed during loaded read")
        return policy
    except Exception:
        raise ApprovalRefused("protected loaded bootstrap policy refused") from None
