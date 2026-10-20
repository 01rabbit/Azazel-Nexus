"""The observe-baseline generation tree: builder and verifier, nothing else (#206).

`docs/activation-observe-baseline.md` §3.2: an ordinary generation in
`/var/lib/azazel/generations` whose tree is exactly one canonical
`baseline.json` naming the exact unit list, the Edge pin and the SHA-256 of
each scoped unit file as installed. Its metadata is ordinary generation
metadata carrying the commissioning digest and evidence binding.

This module is pure. It does not measure installed files, publish, read the
store, verify an approval or grant anything; the measurement is supplied by
the caller, independently of the tree being checked. `az-activated` does not
use it yet (phase P2).

The tree is distinct from the other variants in both directions: it holds no
`bootstrap.json`, so the bootstrap verifier refuses it, and this verifier
refuses any tree that is not exactly its own single canonical file -- a
bootstrap tree, an arbitrary ordinary tree or a tree with one extra file.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from .activation_policy import ACTIVATION_UNIT_ALLOWLIST
from .edge_package import PIN
from .generation import Generation, GenerationRefused, tree_digest
from .operator_store import _unique_object

__all__ = [
    "EDGE_CORE_UNIT",
    "OBSERVE_BASELINE_FILE",
    "OBSERVE_BASELINE_SCHEMA",
    "VerifiedObserveBaseline",
    "build_observe_baseline",
    "decode_observe_baseline",
    "edge_pin_digest",
    "evidence_commissioning_digest",
    "verify_observe_baseline",
]

OBSERVE_BASELINE_SCHEMA = "azazel-nexus/observe-baseline-generation/v1"
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
    if (type(units) not in {list, tuple} or not units
            or any(type(unit) is not str for unit in units)
            or list(units) != sorted(set(units))
            or not set(units) <= set(ACTIVATION_UNIT_ALLOWLIST)):
        raise GenerationRefused("observe-baseline unit scope refused")
    return list(units)


def _edge_pin(scope, package_digest) -> dict:
    """The pin; the installed package digest exactly when edge-core is in scope."""
    pin = {"version": PIN.version, "contract_digest": edge_pin_digest()}
    if EDGE_CORE_UNIT in scope:
        if type(package_digest) is not str or not _DIGEST.match(package_digest):
            raise GenerationRefused("edge-core scope requires the installed package digest")
        pin["package_digest"] = package_digest
    elif package_digest is not None:
        raise GenerationRefused("package digest is forbidden without edge-core in scope")
    return pin


def _document(units, unit_files: Mapping[str, bytes], package_digest) -> dict:
    scope = _scope(units)
    snapshot = dict(unit_files)
    if set(snapshot) != set(scope) or any(
        type(data) is not bytes or not 0 < len(data) <= _UNIT_FILE_LIMIT
        for data in snapshot.values()
    ):
        raise GenerationRefused("observe-baseline unit files must match the scope exactly")
    return {
        "schema": OBSERVE_BASELINE_SCHEMA,
        "units": scope,
        "edge_pin": _edge_pin(scope, package_digest),
        "unit_files": {unit: "sha256:" + sha256(snapshot[unit]).hexdigest() for unit in scope},
    }


def build_observe_baseline(
    *, units, unit_files: Mapping[str, bytes], package_digest: str | None = None,
) -> dict[str, bytes]:
    """The complete tree for `GenerationStore.create`; nothing is written here.

    `unit_files` maps each scoped unit name to the bytes of its installed unit
    file, measured by the caller. Exactly the scoped units, no others.
    `package_digest` is the installed Edge archive digest from its manifest
    (the value `edge_package` compares); required exactly when edge-core is
    in scope, so the operator's signature over the generation digest binds
    one specific Edge package. Forbidden otherwise.
    """
    return {OBSERVE_BASELINE_FILE: _canonical(_document(units, unit_files, package_digest))}


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
        if (type(document) is not dict
                or set(document) != {"schema", "units", "edge_pin", "unit_files"}
                or document["schema"] != OBSERVE_BASELINE_SCHEMA):
            raise GenerationRefused("observe-baseline fields refused")
        scope = _scope(document["units"])
        pin, files = document["edge_pin"], document["unit_files"]
        pin_fields = {"version", "contract_digest"}
        if EDGE_CORE_UNIT in scope:
            pin_fields.add("package_digest")
        if (type(pin) is not dict or set(pin) != pin_fields
                or type(pin["version"]) is not str
                or any(type(pin[name]) is not str or not _DIGEST.match(pin[name])
                       for name in pin_fields - {"version"})):
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
) -> VerifiedObserveBaseline:
    """Compare a stored tree with independently supplied scope and measurements.

    `generation` comes from the ordinary store's verified metadata, `files` is
    its tree, `units` the policy scope, `unit_files` a fresh measurement of
    the installed unit files and `package_digest` the installed Edge archive
    digest (exactly when edge-core is in scope). Any difference refuses. A match establishes that
    the tree describes these bytes; it is not an approval or a health signal.

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
        expected = _document(units, unit_files, package_digest)
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
