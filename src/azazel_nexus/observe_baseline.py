"""The observe-baseline generation tree: builder and verifier, nothing else (#206).

`docs/activation-observe-baseline.md` §3.2: an ordinary generation in
`/var/lib/azazel/generations` whose tree is exactly one canonical
`baseline.json` naming the exact unit list, the Edge pin and the SHA-256 of
each scoped unit file as installed. Its metadata is ordinary generation
metadata carrying the commissioning digest and evidence binding.

This module is pure. It does not measure installed files, publish, read the
store, verify an approval or grant anything; the measurement is supplied by
the caller, independently of the tree being checked. Since phase P4 the
activation pass calls it through `azazel_nexus_runtime.activation_pass`.

The tree is distinct from the other variants in both directions: it holds no
`bootstrap.json`, so the bootstrap verifier refuses it, and this verifier
refuses any tree that is not exactly its own single canonical file -- a
bootstrap tree, an arbitrary ordinary tree or a tree with one extra file.

**Two schemas** (#196 G6, `docs/deception-exposure-wiring.md` §5.2). v1
(`OBSERVE_BASELINE_SCHEMA`) is the generation without the Deception Lite
exposure tier, and refuses the three exposure units explicitly. v2
(`OBSERVE_BASELINE_SCHEMA_V2`) is v1's document plus one key, `exposure`,
**required exactly when** the policy scope names the three units and
forbidden otherwise. In both, the body's `units` and `unit_files` hold the
**observe scope** only (the policy's units without the exposure tier,
`activation_policy.OBSERVE_UNIT_ALLOWLIST`): the exposure unit files are
measured only by the section, never by the body, so a changed exposure unit
file never refuses the generation (which would withhold every tier) and is
judged by the pass's stage P9 alone. Here the section's closed shape is
checked (its keys, its name sets and the form of each digest); whether it
describes the files placed now is the runtime's
(`exposure_generation.verify_exposure_section`, at publication and at P9).
The section's name sets are restated below (the library imports no runtime
module; a test keeps them equal to the runtime's).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from .activation_policy import EXPOSURE_POLICY_UNITS, OBSERVE_UNIT_ALLOWLIST
from .edge_package import BOUND_COMPONENTS, PIN
from .generation import Generation, GenerationRefused, tree_digest
from .operator_store import _unique_object

__all__ = [
    "EDGE_CORE_UNIT",
    "EXPOSURE_SECTION_APPARMOR_PROFILES",
    "EXPOSURE_SECTION_KEYS",
    "EXPOSURE_SECTION_WATCH_UNITS",
    "OBSERVE_BASELINE_FILE",
    "OBSERVE_BASELINE_SCHEMA",
    "OBSERVE_BASELINE_SCHEMA_V2",
    "VerifiedObserveBaseline",
    "build_observe_baseline",
    "decode_observe_baseline",
    "edge_pin_digest",
    "evidence_commissioning_digest",
    "exposure_section_of",
    "verify_observe_baseline",
]

OBSERVE_BASELINE_SCHEMA = "azazel-nexus/observe-baseline-generation/v1"
#: v1 plus the exposure section (#196 G6, wiring §5.2).
OBSERVE_BASELINE_SCHEMA_V2 = "azazel-nexus/observe-baseline-generation/v2"
#: The section's keys (`exposure_generation.EXPOSURE_SECTION_KEYS`).
EXPOSURE_SECTION_KEYS = ("apparmor_policy_hashes", "apparmor_profiles", "scope_digest",
                         "unit_files", "watch_unit_files")
#: The watch's three unit files (`activation_unit_files.WATCH_UNITS`).
EXPOSURE_SECTION_WATCH_UNITS = ("azazel-decoy-trip.target", "azazel-decoy-verify.service",
                                "azazel-decoy-verify.timer")
#: The four AppArmor profiles (`decoy_apparmor.REQUIRED_ENFORCED_PROFILES`).
EXPOSURE_SECTION_APPARMOR_PROFILES = ("azazel-decoy-netd", "azazel-decoy-nsd",
                                      "azazel-decoy-verify", "azazel-decoyd")
_POLICY_HASH = re.compile(r"[0-9a-f]{64}\Z")
OBSERVE_BASELINE_FILE = "baseline.json"
_LIMIT = 65536
_UNIT_FILE_LIMIT = 1 << 20
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EDGE_CORE_UNIT = "azazel-edge-core.service"


def _canonical(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def edge_pin_digest() -> str:
    """SHA-256 over the canonical form of the code-fixed `edge_package.PIN`.

    The pin carries no artifact digest of its own; this names the exact pin
    record (package, version, architecture, contracts, signed flag), so a
    baseline built against a different pin is a different baseline.
    """
    return "sha256:" + sha256(_canonical(asdict(PIN))).hexdigest()


def evidence_commissioning_digest(evidence) -> str:
    """The `commissioning_digest` an observe-baseline generation and approval carry.

    The SHA-256 of the signed full commissioning proposal bytes
    (`CommissioningEvidence.payload`) that the protected evidence loader has
    just verified. The operator already holds and signed those bytes, so the
    digest discloses nothing new; raw inventory stays behind the HMAC
    `binding`. Publisher, request, install and the pass derive it the same way.
    """
    payload = getattr(evidence, "payload", None)
    if type(payload) is not bytes or not payload:
        raise GenerationRefused("verified commissioning evidence required")
    return "sha256:" + sha256(payload).hexdigest()


def _scope(units) -> list[str]:
    """The body's scope: the observe scope, never an exposure unit."""
    if (type(units) not in {list, tuple} or not units
            or any(type(unit) is not str for unit in units)
            or list(units) != sorted(set(units))
            or not set(units) <= set(OBSERVE_UNIT_ALLOWLIST)):
        raise GenerationRefused("observe-baseline unit scope refused")
    return list(units)


def _split(units) -> tuple[list[str], bool]:
    """A policy scope to `(observe scope, names the exposure tier)`.

    The exposure tier is named whole or not at all; the rest is the body's.
    """
    if type(units) not in {list, tuple} or any(type(unit) is not str for unit in units):
        raise GenerationRefused("observe-baseline unit scope refused")
    exposure = set(units) & EXPOSURE_POLICY_UNITS
    if exposure and exposure != EXPOSURE_POLICY_UNITS:
        raise GenerationRefused("observe-baseline unit scope refused")
    return [unit for unit in units if unit not in EXPOSURE_POLICY_UNITS], bool(exposure)


def _digests(value, names) -> bool:
    return (type(value) is dict and set(value) == set(names)
            and all(type(digest) is str and _DIGEST.match(digest)
                    for digest in value.values()))


def _section(value) -> dict:
    """The exposure section in its closed shape, or refused. Shape only."""
    if (type(value) is not dict or set(value) != set(EXPOSURE_SECTION_KEYS)
            or type(value["scope_digest"]) is not str
            or not _DIGEST.match(value["scope_digest"])
            or not _digests(value["unit_files"], EXPOSURE_POLICY_UNITS)
            or not _digests(value["watch_unit_files"], EXPOSURE_SECTION_WATCH_UNITS)
            or not _digests(value["apparmor_profiles"], EXPOSURE_SECTION_APPARMOR_PROFILES)
            or type(value["apparmor_policy_hashes"]) is not dict
            or set(value["apparmor_policy_hashes"]) != set(EXPOSURE_SECTION_APPARMOR_PROFILES)
            or not all(type(digest) is str and _POLICY_HASH.match(digest)
                       for digest in value["apparmor_policy_hashes"].values())):
        raise GenerationRefused("observe-baseline exposure section refused")
    return value


def _components(value) -> dict:
    if (not isinstance(value, Mapping) or set(value) != set(BOUND_COMPONENTS)
            or any(type(digest) is not str or not _DIGEST.match(digest)
                   for digest in value.values())):
        raise GenerationRefused("edge-core scope requires the extracted component digests")
    return {name: value[name] for name in sorted(value)}


def _edge_pin(scope, package_digest, package_components=None) -> dict:
    """The pin; the installed package and its extracted components exactly when
    edge-core is in scope."""
    pin = {"version": PIN.version, "contract_digest": edge_pin_digest()}
    if EDGE_CORE_UNIT in scope:
        if type(package_digest) is not str or not _DIGEST.match(package_digest):
            raise GenerationRefused("edge-core scope requires the installed package digest")
        pin["package_digest"] = package_digest
        pin["components"] = _components(package_components)
    elif package_digest is not None or package_components is not None:
        raise GenerationRefused("package digest is forbidden without edge-core in scope")
    return pin


def _document(units, unit_files: Mapping[str, bytes], package_digest,
              package_components=None, exposure=None) -> dict:
    observe, names_exposure = _split(units)
    scope = _scope(observe)
    snapshot = dict(unit_files)
    if set(snapshot) != set(scope) or any(
        type(data) is not bytes or not 0 < len(data) <= _UNIT_FILE_LIMIT
        for data in snapshot.values()
    ):
        raise GenerationRefused("observe-baseline unit files must match the scope exactly")
    document = {
        "schema": OBSERVE_BASELINE_SCHEMA_V2 if names_exposure else OBSERVE_BASELINE_SCHEMA,
        "units": scope,
        "edge_pin": _edge_pin(scope, package_digest, package_components),
        "unit_files": {unit: "sha256:" + sha256(snapshot[unit]).hexdigest() for unit in scope},
    }
    # Required exactly when the scope names the exposure tier (wiring §5.2).
    if names_exposure:
        document["exposure"] = _section(exposure)
    elif exposure is not None:
        raise GenerationRefused("an exposure section is forbidden without the exposure tier")
    return document


def build_observe_baseline(
    *, units, unit_files: Mapping[str, bytes], package_digest: str | None = None,
    package_components: Mapping[str, str] | None = None, exposure: dict | None = None,
) -> dict[str, bytes]:
    """The complete tree for `GenerationStore.create`; nothing is written here.

    `units` is the policy scope. `unit_files` maps each unit of its observe
    scope (the scope without the exposure tier) to the bytes of its installed
    unit file, measured by the caller. Exactly those units, no others.
    `exposure` is the exposure section (`exposure_generation.
    build_exposure_section`), required exactly when `units` names the three
    exposure units (then the tree is v2) and forbidden otherwise.
    `package_digest` is the installed Edge archive digest from its manifest
    (the value `edge_package` compares); required exactly when edge-core is
    in scope, so the operator's signature over the generation digest binds
    one specific Edge package. `package_components` maps each of
    `edge_package.BOUND_COMPONENTS` (the extracted binary and redirect policy
    the unit uses) to its SHA-256, under the same rule, so the signature also
    binds the files that actually run. Both are forbidden otherwise.
    """
    return {OBSERVE_BASELINE_FILE: _canonical(
        _document(units, unit_files, package_digest, package_components, exposure))}


@dataclass(frozen=True)
class VerifiedObserveBaseline:
    """Tree shape and byte integrity against supplied measurements only."""

    generation: int
    digest: str
    units: tuple[str, ...]


def decode_observe_baseline(raw: bytes) -> dict:
    """Decode one canonical baseline document without expected inputs."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= _LIMIT:
            raise GenerationRefused("observe-baseline size refused")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        keys = {"schema", "units", "edge_pin", "unit_files"}
        if type(document) is not dict or document.get("schema") not in {
                OBSERVE_BASELINE_SCHEMA, OBSERVE_BASELINE_SCHEMA_V2}:
            raise GenerationRefused("observe-baseline fields refused")
        if document["schema"] == OBSERVE_BASELINE_SCHEMA_V2:
            keys = keys | {"exposure"}
        if set(document) != keys:
            raise GenerationRefused("observe-baseline fields refused")
        if "exposure" in document:
            _section(document["exposure"])
        scope = _scope(document["units"])
        pin, files = document["edge_pin"], document["unit_files"]
        pin_fields = {"version", "contract_digest"}
        if EDGE_CORE_UNIT in scope:
            pin_fields |= {"package_digest", "components"}
        if (type(pin) is not dict or set(pin) != pin_fields
                or type(pin["version"]) is not str
                or any(type(pin[name]) is not str or not _DIGEST.match(pin[name])
                       for name in pin_fields - {"version", "components"})
                or ("components" in pin_fields
                    and _components(pin["components"]) != pin["components"])):
            raise GenerationRefused("observe-baseline edge pin refused")
        if (type(files) is not dict or set(files) != set(scope)
                or any(type(value) is not str or not _DIGEST.match(value)
                       for value in files.values())):
            raise GenerationRefused("observe-baseline unit digests refused")
        if _canonical(document) != raw:
            raise GenerationRefused("observe-baseline is not canonical")
        return document
    except Exception:
        raise GenerationRefused("observe-baseline document refused") from None


def verify_observe_baseline(
    *, generation: Generation, files: Mapping[str, bytes],
    units, unit_files: Mapping[str, bytes], package_digest: str | None = None,
    package_components: Mapping[str, str] | None = None,
) -> VerifiedObserveBaseline:
    """Compare a stored tree with independently supplied scope and measurements.

    `generation` comes from the ordinary store's verified metadata, `files` is
    its tree, `units` the policy scope, `unit_files` a fresh measurement of
    the installed unit files of its observe scope and `package_digest` the
    installed Edge archive digest (exactly when edge-core is in scope). Any
    difference refuses. A match establishes that the tree describes these
    bytes; it is not an approval or a health signal.

    When `units` names the exposure tier the tree must be v2 and carry an
    exposure section of the closed shape; the section's **content** is taken
    as recorded and compared with nothing here: it is covered by the tree
    digest (so by the operator's signature over `generation_digest`), and
    whether it describes the files placed now is the pass's stage P9, where
    a difference withholds the exposure tier alone (wiring §5.1).

    The commissioning digest and evidence binding in `generation` are not
    re-derived here: binding them to the current commissioning evidence is the
    store's and the activation controller's job, as for every ordinary
    generation. This only requires that a binding is present.
    """
    try:
        if type(generation) is not Generation:
            raise GenerationRefused("ordinary generation metadata required")
        if generation.commissioning_evidence_binding is None:
            raise GenerationRefused("observe-baseline generation needs its evidence binding")
        snapshot = dict(files)
        if set(snapshot) != {OBSERVE_BASELINE_FILE}:
            raise GenerationRefused("observe-baseline tree must hold only baseline.json")
        raw = snapshot[OBSERVE_BASELINE_FILE]
        document = decode_observe_baseline(raw)
        expected = _document(units, unit_files, package_digest, package_components,
                             document.get("exposure"))
        if document["edge_pin"] != expected["edge_pin"]:
            raise GenerationRefused("observe-baseline edge pin differs")
        if document["units"] != expected["units"]:
            raise GenerationRefused("observe-baseline unit scope differs")
        if document["unit_files"] != expected["unit_files"]:
            raise GenerationRefused("observe-baseline unit file digest differs")
        if raw != _canonical(expected):
            raise GenerationRefused("observe-baseline differs")
        if tree_digest(snapshot) != generation.digest:
            raise GenerationRefused("observe-baseline tree digest differs")
        return VerifiedObserveBaseline(generation.number, generation.digest, tuple(expected["units"]))
    except Exception:
        raise GenerationRefused("observe-baseline generation refused") from None


def exposure_section_of(raw: bytes) -> dict | None:
    """The recorded exposure section of a decoded tree's `baseline.json`, or None.

    None for a v1 document (no section). The section is checked for its
    closed shape only (`decode_observe_baseline`); the caller compares it.
    """
    document = decode_observe_baseline(raw)
    section = document.get("exposure")
    return None if section is None else json.loads(json.dumps(section))
