"""Shared test vectors: one canonical digest per decision, authorization and audit output.

ADR-0003 D6 says the core is one CPU-independent implementation, checked by
shared vectors run on both CPUs and compared byte for byte. This module is
those vectors. Each one runs the product code on fixed inputs (the vendored
fixtures, injected clocks and identifiers) and returns a JSON document; the
document's canonical bytes are hashed with SHA-256, and the digest is pinned
in `digests.json` next to this file.

`tests/unit/test_cross_arch_vectors.py` holds every digest to its pin on
whatever CPU runs the suite. `tools/cross_arch_vectors.py` runs this module on
the aarch64 and the amd64 (Rosetta) colima contexts and compares the two sets.
`docs/cross-arch-vectors.md` says what is compared, what is excluded and how
a pin is changed.

## Canonical form

``json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False)`` encoded as UTF-8 -- the form `audit.canonical_event_bytes`
and `edge_intake.canonical` already use. Non-ASCII text (the Japanese question
in an explanation frame, for one) is kept as UTF-8 rather than escaped, so the
bytes are the bytes the product writes.

Only ``dict`` (string keys), ``list``, ``str``, ``int``, ``bool`` and ``None``
are accepted. **A float is refused**, as is a tuple, a set or any other type:
a vector that wants one converts or excludes it explicitly, so nothing enters
the digest by accident. Where a product output does carry floats (the status
view's timestamps, a Lite row's confidence), `without_floats` removes them
and the vector records the removed paths, so the set of exclusions is itself
part of what is pinned.

## What is not compared

Wall clocks, random identifiers, floats, measured values (resource readings,
latency, embedding similarity), exception text from the standard library or
another package (it differs between Python versions), filesystem paths and
uids. Each vector injects or drops these; the list is in
`docs/cross-arch-vectors.md` §3.
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

ROOT = Path(__file__).resolve().parents[2]
UNIT = ROOT / "tests" / "unit"
FIXTURES = ROOT / "tests" / "fixtures"
CONTRACT = ROOT / "contract"
DIGESTS = Path(__file__).resolve().parent / "digests.json"

#: The fixed instants every vector reads. Never the wall clock.
FRESH = "2026-09-21T00:00:00Z"
LATER = "2030-01-01T00:00:00Z"
CLOCK_AT = "2026-10-28T00:00:00Z"


def _paths() -> None:
    """The test helpers and the runtime sources, as conftest puts them."""

    for path in (UNIT, ROOT / "runtime" / "src", ROOT / "src"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))


# -- canonical form --------------------------------------------------------


class NotCanonical(TypeError):
    """A value the canonical form does not admit. Never coerced."""


def _check(value, where: str = "$") -> None:
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        raise NotCanonical(f"{where}: a float is excluded, not compared")
    if type(value) is list:
        for index, item in enumerate(value):
            _check(item, f"{where}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise NotCanonical(f"{where}: a key is text")
            _check(item, f"{where}.{key}")
        return
    raise NotCanonical(f"{where}: {type(value).__name__} is not part of the canonical form")


def canonical_bytes(value) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def without_floats(value, where: str = "$"):
    """`(value without its floats, sorted paths that were removed)`.

    List indices are written ``[]`` so the path names a field, not a position.
    """

    removed: set[str] = set()

    def walk(item, path):
        if type(item) is float:
            removed.add(path)
            return _DROP
        if type(item) is dict:
            kept = {}
            for key, sub in item.items():
                result = walk(sub, f"{path}.{key}")
                if result is not _DROP:
                    kept[key] = result
            return kept
        if type(item) in (list, tuple):
            return [sub for sub in (walk(x, f"{path}[]") for x in item) if sub is not _DROP]
        return item

    return walk(value, where), sorted(removed)


_DROP = object()


def _plain(value):
    """Tuples and frozensets as lists, recursively; other types untouched."""

    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_plain(item) for item in value)
    return value


def _refusal(exc: BaseException, *attributes: str) -> dict:
    """A refusal as its type and its fixed codes. Never its text."""

    result = {"refused": type(exc).__name__}
    for name in attributes:
        attribute = getattr(exc, name)
        result[name] = getattr(attribute, "value", attribute)
    return result


# -- the context a vector runs in -----------------------------------------


@dataclass
class Context:
    """A private temporary directory and a monkeypatch, both undone afterwards."""

    tmp: Path
    mp: object  # pytest.MonkeyPatch


@contextmanager
def context() -> Iterator[Context]:
    import pytest

    _paths()
    directory = tempfile.mkdtemp(prefix="azn-vector-")
    try:
        with pytest.MonkeyPatch.context() as mp:
            yield Context(Path(directory), mp)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# -- Edge golden: intake, incident, explain ---------------------------------


#: The floats the golden observations carry: Edge's ``f64`` epochs. Each is
#: integral in the fixture, and a vector takes it as that integer, so no
#: float reaches the canonical bytes (docs/cross-arch-vectors.md §3). Any
#: other float, or a non-integral one, stops the vector.
GOLDEN_FLOAT_FIELDS = ("$.enforcement.metadata.release_due_epoch", "$.normalized.ingest_epoch")


def _integral(value, path, seen):
    if type(value) is float:
        if not value.is_integer():
            raise NotCanonical(f"{path} is not an integral float: {value!r}")
        seen.add(path)
        return int(value)
    if type(value) is dict:
        return {key: _integral(item, f"{path}.{key}", seen) for key, item in value.items()}
    if type(value) is list:
        return [_integral(item, f"{path}[]", seen) for item in value]
    return value


def _golden_lines() -> list[bytes]:
    """The golden observations, with `GOLDEN_FLOAT_FIELDS` read as integers."""

    lines = []
    for raw in (FIXTURES / "edge" / "rust_event_engine_v1.jsonl").read_bytes().splitlines():
        seen: set[str] = set()
        event = _integral(json.loads(raw), "$", seen)
        if not seen <= set(GOLDEN_FLOAT_FIELDS):
            raise NotCanonical(f"the golden observation carries another float: {sorted(seen)}")
        lines.append(json.dumps(event, sort_keys=True, separators=(",", ":")).encode())
    return lines


#: Malformed producer lines and the fixed code each one is refused with.
_EDGE_REFUSALS = (
    b"",
    b"{",
    b"[]",
    b'{"a":1,"a":2}',
    b"NaN",
    b"x" * (64 * 1024 + 1),
)


def edge_intake(ctx: Context):
    from azazel_nexus.edge_intake import EdgeEventRefused, EvidenceRecord, parse_edge_event

    events = []
    for number, line in enumerate(_golden_lines()):
        event = parse_edge_event(line)
        record = EvidenceRecord.receive(event, lambda: 1789900000 + number)
        events.append({"canonical": event.encoded.decode("utf-8"),
                       "evidence": record.as_dict()})
    refusals = []
    for raw in _EDGE_REFUSALS:
        try:
            parse_edge_event(raw)
        except EdgeEventRefused as exc:
            refusals.append({"input_sha256": hashlib.sha256(raw).hexdigest(),
                             "code": exc.code})
        else:  # pragma: no cover - a vector that stops refusing is a finding
            refusals.append({"input_sha256": hashlib.sha256(raw).hexdigest(), "code": None})
    return {"events": events, "refusals": refusals}


def _tracked_transitions():
    """The golden events through the tracker, on injected clocks."""
    from azazel_nexus.edge_intake import EvidenceRecord, IncidentTracker, parse_edge_event

    instants = iter(range(10_000, 20_000))
    tracker = IncidentTracker(lambda: 0, monotonic=lambda: next(instants))
    transitions = []
    # Two passes, 61 s apart (one update interval), then an idle close.
    for offset in (0, 61):
        for number, line in enumerate(_golden_lines()):
            record = EvidenceRecord.receive(parse_edge_event(line),
                                            lambda: 1789900000 + offset + number)
            transitions.extend(tracker.add(record))
    transitions.extend(tracker.tick(1789900000 + 61 + 901 + 6))
    return transitions, tracker


def edge_incident(ctx: Context):
    transitions, tracker = _tracked_transitions()
    return {"transitions": _plain(transitions), "open": len(tracker.incidents),
            "rate_limited": tracker.rate_limited}


def edge_explain(ctx: Context):
    from azazel_nexus.incident_explain import (
        build_frame,
        build_recent_incident,
        build_recent_incidents,
        explanation_input,
    )

    transitions, _ = _tracked_transitions()
    frames, rows, latest = [], [], {}
    for sequence, transition in enumerate(transitions, start=1):
        # What edge_intaked writes to the incident ledger for a transition.
        event = dict(transition)
        event = dict(event_type="edge.incident." + event.pop("transition"), **event)
        frames.append({"input": explanation_input(event), "frame": build_frame(event, sequence)})
        row = build_recent_incident(event, latest.get(event["incident_id"]))
        latest[event["incident_id"]] = row
        rows.append(row)
    recent = build_recent_incidents(list(latest.values()), 1789901000)
    return {"frames": _plain(frames), "rows": _plain(rows), "recent": _plain(recent)}


# -- Knowledge Lite --------------------------------------------------------

_LITE = CONTRACT / "azazel-knowledge-lite"


def _claims(accepted, as_of):
    from azazel_nexus.lite_bundle import read_claims, reading_for

    claims = read_claims(accepted, query_as_of=as_of)
    sample, floats = without_floats(_plain(list(claims.sample_served)), "$.sample_served")
    reading = reading_for(claims, query_as_of=as_of).as_event()
    return {"as_of": as_of, "served": claims.served_count, "withheld": claims.withheld_count,
            "timeless": claims.timeless_count, "next_expiry": claims.next_expiry,
            "time_bound": claims.time_bound.value,
            "static_reference": claims.static_reference.value,
            "serves_anything": claims.serves_anything,
            "sample_served": sample, "excluded_floats": floats, "reading": reading}


def knowledge_lite_verify(ctx: Context):
    """`verify_bundle` over the producer's valid and negative fixtures."""
    from azazel_nexus.lite_bundle import BundleRefused, read_anchors, refused_reading, verify_bundle

    anchors = read_anchors(_LITE / "anchors.toml")
    negative = json.loads((_LITE / "negative.json").read_text(encoding="utf-8"))
    cases = [("valid", "lite.tar.gz")] + [
        (entry["name"], entry["path"]) for entry in negative["fixtures"]]
    results = []
    for name, path in cases:
        source = _LITE / path
        if not source.exists():
            results.append({"name": name, "exists": False})
            continue
        try:
            accepted = verify_bundle(source.read_bytes(), anchors=anchors)
        except BundleRefused as exc:
            reading = refused_reading(exc).as_event()
            reading.pop("reason")  # carries the refusal's detail text
            results.append({"name": name, "exists": True,
                            **_refusal(exc, "gate", "code"), "reading": reading})
            continue
        results.append({"name": name, "exists": True, "accepted": accepted.as_event(),
                        "member_sha256": {member: hashlib.sha256(body).hexdigest()
                                          for member, body in sorted(accepted.members.items())},
                        "claims": [_claims(accepted, FRESH), _claims(accepted, LATER)]})
    return {"results": results}


def _commissioned_lite(ctx: Context):
    """A node with the producer's anchor pinned and the producer fixtures in its inbox."""
    from azazel_nexus.lite_import import CommissionedLite, LiteImport
    from azazel_nexus.lite_trust import TrustStore
    from azazel_nexus.revocation_policy import (
        REVOCATION_SIGNING,
        RevocationPolicy,
        commission_policy,
    )
    from signing_oracle import public_key_for

    ctx.mp.setenv("AZAZEL_ROOT", str(ctx.tmp))
    root = ctx.tmp / "var/lib/azazel/knowledge"
    trust = ctx.tmp / "var/lib/azazel/lite-trust"
    (root / "inbox").mkdir(parents=True)
    (root / "trust").mkdir()
    (trust / "trust").mkdir(parents=True)
    for target in (root, trust):
        shutil.copy(_LITE / "anchors.toml", target / "trust" / "anchors.toml")
    from azazel_nexus.lite_bundle import read_anchors

    keys = [key.hex() for key in read_anchors(_LITE / "anchors.toml").keys.values()]
    commissioning = "sha256:" + "c" * 64
    TrustStore(trust).pin(keys, commissioning_digest=commissioning, pinned_at=FRESH,
                          actor="vector")
    # A published test seed: this key signs nothing here; it is the authority
    # the revocation reader requires to exist.
    revoker = public_key_for(bytes(range(32)))
    commission_policy(trust, RevocationPolicy(keys={"r": revoker},
                                              key_roles={"r": REVOCATION_SIGNING},
                                              threshold=1, generation=1),
                      commissioning_digest=commissioning, anchors_key_roles={},
                      anchors_keys={})
    return root, trust, LiteImport(CommissionedLite(root))


def knowledge_lite_lookup(ctx: Context):
    """The import outcome and `lookup_context_reading` over the valid and expired fixtures."""
    from azazel_nexus.lite_import import lookup_context_reading

    outcomes = []
    lookups = []
    for name in ("lite.tar.gz", "negative/expired.tar.gz", "negative/corrupt-signature.tar.gz"):
        root, trust, importer = _commissioned_lite(ctx)
        shutil.copy(_LITE / name, root / "inbox" / Path(name).name)
        (entry,) = importer.list_inbox()
        outcome = importer.import_entry(entry.entry_id, now=FRESH)
        event = outcome.as_event()
        outcomes.append({"fixture": name, "admitted": outcome.admitted,
                         "bundle_digest": outcome.bundle_digest,
                         "refusal": None if outcome.refusal is None
                         else _refusal(outcome.refusal, "gate", "code"),
                         "event_keys": sorted(event)})
        for ids in ((), ("T1110",), ("T1110", "T1110", "T1046"), ("T9999",), ("bad",)):
            for as_of in (FRESH, LATER):
                result = lookup_context_reading(root=root, trust_root=trust,
                                                technique_ids=ids, query_as_of=as_of)
                lookups.append({"fixture": name, "ids": list(ids), "as_of": as_of,
                                "reason_code": result.reason_code,
                                "refs": [_plain(vars(ref)) for ref in result.refs]})
        shutil.rmtree(ctx.tmp / "var")
    return {"outcomes": outcomes, "lookups": lookups}


def _archive(members) -> bytes:
    """A gzip'd PAX tar of ``(name, bytes[, tar type])``, in order, mtime 0."""
    import gzip
    import tarfile

    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, body, *kind in members:
                info = tarfile.TarInfo(name=name)
                info.size, info.mtime = len(body), 0
                if kind:
                    info.type, info.size = kind[0], 0
                    archive.addfile(info)
                    continue
                archive.addfile(info, io.BytesIO(body))
    return raw.getvalue()


def knowledge_lite_refusals(ctx: Context):
    """Every `verify_bundle` gate that the producer publishes no fixture for.

    Built here with the test-only signer, as `test_lite_bundle` does. These
    are not evidence about what Knowledge emits; they fix which gate and code
    each constructed artifact is refused at, on every CPU. The archive's own
    digest is left out: it is gzip output, not a decision.
    """
    from azazel_nexus.lite_bundle import (
        TRUST_SHADOWING_FIELDS,
        BundleRefused,
        read_claims,
        verify_bundle,
    )
    from signing_oracle import sign_detached
    from test_lite_bundle import KEY_ID, SEED, _local_anchors, _manifest

    table = b'{"technique_id":"T1110","name":"Brute Force"}\n'

    def signed(manifest, tables=None, *, extra=(), files=None, key_id=KEY_ID,
               signature_text=None, signature_raw=None, manifest_bytes=None):
        tables = {"tables/a.jsonl": table} if tables is None else tables
        declared = files if files is not None else {
            path: hashlib.sha256(body).hexdigest() for path, body in sorted(tables.items())}
        body = manifest_bytes if manifest_bytes is not None else json.dumps(
            {**manifest, "files": declared}, indent=2, sort_keys=True).encode()
        sig = sign_detached(seed=SEED, message=body).hex()
        text = signature_text if signature_text is not None else f"{key_id}:{sig}\n"
        raw_sig = signature_raw if signature_raw is not None else text.encode()
        return _archive([("manifest.json", body), ("manifest.sig", raw_sig),
                         *tables.items(), *extra])

    anchors = _local_anchors()
    policy = "c" * 64
    cases = [("control", signed(_manifest()), anchors, 0)]
    for field in TRUST_SHADOWING_FIELDS:
        cases.append((f"shadows:{field}", signed(_manifest(**{field: 1})), anchors, 0))
    cases += [
        ("manifest_missing", _archive([("manifest.sig", b"x:00\n")]), anchors, 0),
        ("signature_missing", _archive([("manifest.json", b"{}")]), anchors, 0),
        ("manifest_not_json", signed({}, manifest_bytes=b"{"), anchors, 0),
        ("manifest_not_object", signed({}, manifest_bytes=b"[]"), anchors, 0),
        ("format_not_integer", signed(_manifest(bundle_format_version="1")), anchors, 0),
        ("format_unsupported", signed(_manifest(bundle_format_version=2)), anchors, 0),
        ("kind_delta", signed(_manifest(kind="delta")), anchors, 0),
        ("signature_line_malformed", signed(_manifest(), signature_text="no colon\n"),
         anchors, 0),
        ("signature_not_text", signed(_manifest(), signature_raw=b"\xff:00\n"), anchors, 0),
        ("signature_too_many_lines",
         signed(_manifest(), signature_text="".join(f"k{i}:00\n" for i in range(33))),
         anchors, 0),
        ("signer_revoked", signed(_manifest()), _local_anchors(revoked=frozenset({KEY_ID})), 0),
        ("signer_unknown", signed(_manifest(), key_id="someone-else"), anchors, 0),
        ("signer_role_missing", signed(_manifest()),
         _local_anchors(required_signer_role="bundle-signing"), 0),
        ("security_epoch_missing", signed(_manifest()),
         _local_anchors(minimum_security_epoch=3), 0),
        ("security_epoch_not_integer", signed(_manifest(security_epoch="3")),
         _local_anchors(minimum_security_epoch=3), 0),
        ("security_epoch_too_low", signed(_manifest(security_epoch=2)),
         _local_anchors(minimum_security_epoch=3), 0),
        ("security_epoch_met", signed(_manifest(security_epoch=3)),
         _local_anchors(minimum_security_epoch=3), 0),
        ("export_policy_missing", signed(_manifest()),
         _local_anchors(accepted_export_policy_digests=frozenset({policy})), 0),
        ("export_policy_not_accepted",
         signed(_manifest(profile={"selection_inputs": {"export_policy_digest": "d" * 64}})),
         _local_anchors(accepted_export_policy_digests=frozenset({policy})), 0),
        ("export_policy_accepted",
         signed(_manifest(profile={"selection_inputs": {"export_policy_digest": policy}})),
         _local_anchors(accepted_export_policy_digests=frozenset({policy})), 0),
        ("version_not_integer", signed(_manifest(bundle_version="7")), anchors, 0),
        ("version_regression_equal", signed(_manifest()), anchors, 7),
        ("version_above_watermark", signed(_manifest()), anchors, 6),
        ("files_not_a_map", signed(_manifest(), files=[]), anchors, 0),
        ("file_missing", signed(_manifest(), {}, files={"tables/a.jsonl": "0" * 64}),
         anchors, 0),
        ("member_undeclared", signed(_manifest(), extra=[("tables/b.jsonl", table)]),
         anchors, 0),
        ("file_hash_mismatch", signed(_manifest(), files={"tables/a.jsonl": "0" * 64}),
         anchors, 0),
        ("file_digest_not_text", signed(_manifest(), files={"tables/a.jsonl": 7}), anchors, 0),
        ("member_parent", signed(_manifest(), extra=[("../escape", b"x")]), anchors, 0),
        ("member_absolute", signed(_manifest(), extra=[("/abs", b"x")]), anchors, 0),
        ("member_unnormalised", signed(_manifest(), extra=[("tables//x", b"x")]), anchors, 0),
        ("member_too_deep", signed(_manifest(), extra=[("/".join("d" * 10), b"x")]),
         anchors, 0),
        ("member_name_too_long", signed(_manifest(), extra=[("n" * 201, b"x")]), anchors, 0),
        ("member_directory", signed(_manifest(), extra=[("dir", b"", b"5")]), anchors, 0),
        ("member_symlink", signed(_manifest(), extra=[("link", b"", b"2")]), anchors, 0),
        ("manifest_too_large",
         signed({}, manifest_bytes=b" " * (8 * 1024 * 1024 + 1)), anchors, 0),
        ("member_duplicate", signed(_manifest(), extra=[("tables/a.jsonl", table)]),
         anchors, 0),
        ("too_many_members", signed(_manifest(), extra=[(f"m/{i}", b"") for i in range(64)]),
         anchors, 0),
        ("not_gzip", b"this is not a gzip stream at all", anchors, 0),
        ("gzip_cut", signed(_manifest())[:60], anchors, 0),
    ]
    results = []
    for name, raw, trust, watermark in cases:
        try:
            accepted = verify_bundle(raw, anchors=trust, last_imported_version=watermark)
        except BundleRefused as exc:
            results.append({"case": name, **_refusal(exc, "gate", "code")})
            continue
        event = accepted.as_event()
        event.pop("bundle_digest")
        results.append({"case": name, "accepted": event})

    # Rows that verify but cannot be read, and expiries that cannot be parsed.
    rows = []
    for name, body in (
        ("not_utf8", b"\xff\xfe\n"),
        ("not_jsonl", b"{\n"),
        ("not_object", b"[1]\n"),
        ("line_too_long", b'{"x":"' + b"a" * (64 * 1024) + b'"}\n'),
        ("expiry_unreadable", b'{"agg_next_expiry":"soon"}\n'),
        ("expiry_naive", b'{"agg_next_expiry":"2027-01-01T00:00:00"}\n'),
        ("expiry_offset", b'{"agg_next_expiry":"2026-09-21T09:00:01+09:00"}\n'),
        ("expiry_equal", b'{"agg_next_expiry":"2026-09-21T00:00:00Z"}\n'),
    ):
        accepted = verify_bundle(signed(_manifest(), {"tables/a.jsonl": body}), anchors=anchors)
        try:
            claims = read_claims(accepted, query_as_of=FRESH)
        except BundleRefused as exc:
            rows.append({"case": name, **_refusal(exc, "gate", "code")})
            continue
        rows.append({"case": name, "served": claims.served_count,
                     "withheld": claims.withheld_count, "timeless": claims.timeless_count,
                     "next_expiry": claims.next_expiry})
    return {"bundles": results, "rows": rows}


# -- revocation ------------------------------------------------------------


def revocation(ctx: Context):
    from azazel_nexus.lite_bundle import BundleRefused, TrustAnchors, verify_bundle
    from azazel_nexus.revocation import (
        REVOCATION_DOMAIN,
        RevocationList,
        RevocationRefused,
        RevocationStore,
        encode_signed,
    )
    from azazel_nexus.revocation_policy import REVOCATION_SIGNING, RevocationPolicy
    from azazel_nexus.signature import verify_detached
    from signing_oracle import public_key_for, sign_detached

    def vector(name):
        raw = json.loads((FIXTURES / "revocation" / f"{name}.json").read_text())
        return (bytes.fromhex(raw["public_key"]), raw["payload"].encode(),
                bytes.fromhex(raw["signature"]))

    def as_bundle(payload, signature):
        import tarfile

        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            for member, body in {"manifest.json": payload,
                                 "manifest.sig": f"test:{signature.hex()}\n".encode()}.items():
                info = tarfile.TarInfo(member)
                info.size, info.mtime = len(body), 0
                archive.addfile(info, io.BytesIO(body))
        return output.getvalue()

    fixtures = []
    for index, name in enumerate(("manifest", "manifest-with-sequence", "revocation")):
        key, payload, signature = vector(name)
        authority = RevocationPolicy({"test": key}, {"test": REVOCATION_SIGNING}, 1, 1)
        store = RevocationStore(ctx.tmp / f"fixture-{index}", authority)
        entry = {"name": name,
                 "verifies_plain": verify_detached(public_key=key, message=payload,
                                                   signature=signature),
                 "verifies_revocation_domain": verify_detached(
                     public_key=key, message=REVOCATION_DOMAIN + payload, signature=signature)}
        try:
            entry["accepted_sequence"] = store.accept(signature + payload).sequence
        except RevocationRefused as exc:
            entry["store_refusal"] = str(exc)
        entry["current_sequence"] = store.current().sequence
        try:
            entry["bundle"] = verify_bundle(as_bundle(payload, signature),
                                            anchors=TrustAnchors(1, {"test": key})).as_event()
            entry["bundle"].pop("bundle_digest")  # the tar's own bytes, not the decision
        except BundleRefused as exc:
            entry["bundle"] = _refusal(exc, "gate", "code")
        fixtures.append(entry)

    # A signed sequence: accept, replay, re-enable, then the reasons it gives.
    seed = bytes(range(160, 192))
    key = public_key_for(seed)
    authority = RevocationPolicy({"k": key}, {"k": REVOCATION_SIGNING}, 1, 1)
    store = RevocationStore(ctx.tmp / "sequence", authority)
    revoked = "sha256:" + "ab" * 32
    lists = (
        RevocationList(sequence=1, issued_at=CLOCK_AT, revoked_digests=frozenset({revoked})),
        RevocationList(sequence=1, issued_at=CLOCK_AT, revoked_digests=frozenset({revoked})),
        RevocationList(sequence=2, issued_at=CLOCK_AT, revoked_generations=frozenset({4})),
        RevocationList(sequence=3, issued_at=CLOCK_AT, revoked_digests=frozenset({revoked}),
                       revoked_generations=frozenset({4, 5}),
                       revoked_keys=frozenset({"cd" * 32})),
    )
    steps = []
    for item in lists:
        blob = encode_signed(item.as_payload(),
                             [sign_detached(seed=seed, message=item.signature_target())])
        step = {"payload": item.as_payload().decode(), "blob_sha256": hashlib.sha256(blob).hexdigest()}
        try:
            step["accepted_sequence"] = store.accept(blob).sequence
        except RevocationRefused as exc:
            step["refusal"] = str(exc)
        current = store.current()
        step["in_force"] = {
            "sequence": current.sequence,
            "digest_reason": current.reason_for(digest=revoked),
            "generation_4_reason": current.reason_for(generation=4),
            "generation_5_reason": current.reason_for(generation=5),
            "other_reason": current.reason_for(digest="sha256:" + "00" * 32, generation=9),
            "revokes_key": current.revokes_key(bytes.fromhex("cd" * 32)),
        }
        steps.append(step)
    return {"fixtures": fixtures, "sequence": steps}


# -- signature (RFC 8032) ----------------------------------------------------

#: RFC 8032 §7.1 TEST 1, 2, 3 and SHA(abc): (secret seed, public key, message, signature).
RFC_8032 = (
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
     "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da08"
     "5ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18"
     "ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a21"
     "92992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909"
     "351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"),
)


def signature(ctx: Context):
    from azazel_nexus.signature import (
        _Q,
        SignatureRefused,
        parse_public_key,
        verify_detached,
    )
    from signing_oracle import public_key_for, sign_detached

    def verify(key, message, sig):
        try:
            return verify_detached(public_key=key, message=message, signature=sig)
        except SignatureRefused:
            return "refused"

    results = []
    for seed, public, message, expected in RFC_8032:
        key, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(expected)
        flipped_sig = bytearray(sig)
        flipped_sig[32] ^= 1
        flipped_msg = bytearray(msg) or bytearray(b"\x00")
        flipped_msg[0] ^= 1
        s_plus_l = sig[:32] + (int.from_bytes(sig[32:], "little") + _Q).to_bytes(32, "little")
        oracle = sign_detached(seed=bytes.fromhex(seed), message=msg)
        results.append({
            "public_key": public,
            "derived_public_key": public_key_for(bytes.fromhex(seed)).hex(),
            "oracle_signature": oracle.hex(),
            "oracle_matches_rfc": oracle == sig,
            "verifies": verify(key, msg, sig),
            "flipped_signature_bit": verify(key, msg, bytes(flipped_sig)),
            "flipped_message_bit": verify(key, bytes(flipped_msg), sig),
            "s_plus_l": verify(key, msg, s_plus_l),
            "truncated": verify(key, msg, sig[:-1]),
        })
    # Small-order and off-curve keys: refused before any signature is read.
    keys = []
    for text in ("01" + "00" * 31, "00" * 32, "ff" * 32,
                 RFC_8032[0][1].upper(), RFC_8032[0][1]):
        try:
            keys.append({"key": text, "parsed": parse_public_key(text).hex()})
        except SignatureRefused:
            keys.append({"key": text, "parsed": None})
    return {"rfc8032": results, "keys": keys}


# -- audit chain -----------------------------------------------------------

_AUDIT_EVENTS = (
    {"event_type": "edge.incident.opened", "incident_id": "inc-0000000000000001", "count": 1},
    {"event_type": "mio.route.selected", "route": "deterministic_handoff",
     "reason": "決定論的な引継ぎ", "permitted": ["deterministic_handoff"]},
    {"event_type": "lite.bundle.accepted", "bundle_version": 1, "signers": ["c561fa9f"],
     "nested": {"z": None, "a": [True, False, 0, -1, 2**63 - 1]}},
    {"event_type": "edge.incident.closed", "incident_id": "inc-0000000000000001",
     "reason": "idle", "text": "tab\tnewline\nquote\"backslash\\ é \U0001f512"},
)


def audit_chain(ctx: Context):
    from azazel_nexus.audit import GENESIS_HASH, AuditChainBroken, AuditLedger

    heads = []
    for run in ("a", "b"):
        ledger = AuditLedger(ctx.tmp / run / "ledger.jsonl")
        entries = [ledger.append(dict(event)) for event in _AUDIT_EVENTS]
        ledger.verify()
        heads.append({"head": list(ledger.head()),
                      "links": [[e.sequence, e.previous_hash, e.event_hash] for e in entries],
                      "file_sha256": hashlib.sha256(ledger.path.read_bytes()).hexdigest()})
    if heads[0] != heads[1]:
        raise AssertionError("the same events gave two chains in one process")
    # Each tamper is refused, and *where* the chain breaks is part of the
    # vector: the sequence the verifier names and its fixed message.
    import re

    tampered = []
    for change in ("edit", "splice", "truncate_hash", "sequence_gap", "sequence_repeat"):
        for position in (1, 2, 4):
            ledger = AuditLedger(ctx.tmp / f"{change}-{position}" / "ledger.jsonl")
            for event in _AUDIT_EVENTS:
                ledger.append(dict(event))
            lines = ledger.path.read_text(encoding="utf-8").splitlines()
            raw = json.loads(lines[position - 1])
            if change == "edit":
                raw["event"]["edited"] = True
            elif change == "splice":
                raw["previous_hash"] = GENESIS_HASH if position > 1 else "1" * 64
            elif change == "truncate_hash":
                raw["event_hash"] = raw["event_hash"][:-1] + (
                    "1" if raw["event_hash"][-1] == "0" else "0")
            elif change == "sequence_gap":
                raw["sequence"] += 1
            else:
                raw["sequence"] = max(1, raw["sequence"] - 1) if position > 1 else 2
            lines[position - 1] = json.dumps(raw)
            ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                ledger.verify()
            except AuditChainBroken as exc:
                message = str(exc)
                found = re.match(r"entry (\d+)|expected sequence (\d+)", message)
                tampered.append({"change": change, "position": position,
                                 "refused": "AuditChainBroken",
                                 "broken_at": int(found.group(1) or found.group(2))
                                 if found else None,
                                 "message": message})
            else:  # pragma: no cover - a tamper that verifies is a finding
                tampered.append({"change": change, "position": position, "refused": None})
    return {"genesis": GENESIS_HASH, "chain": heads[0], "tampered": tampered}


# -- status read model -------------------------------------------------------


def status_read_model(ctx: Context):
    """`azazel-nexus status --json` in each golden scene (`test_status_view`)."""
    test_status_view = importlib.import_module("test_status_view")

    views = {}
    for name in sorted(test_status_view.SCENARIOS):
        with _scene(ctx) as (tmp, mp):
            mp.setattr("azazel_nexus.edge_package._probe_owner_uid", os.geteuid)
            code, out, _ = test_status_view.run_scenario(name, tmp, mp, json_flag=True)
            if str(tmp) in out:
                raise AssertionError(f"{name}: the view carries a temporary path")
            view, floats = without_floats(json.loads(out))
            views[name] = {"exit": code, "view": view, "excluded_floats": floats}
    return {"scenes": views}


@contextmanager
def _scene(ctx: Context):
    """A fresh directory and monkeypatch per scene, so scenes cannot leak."""
    import pytest

    directory = Path(tempfile.mkdtemp(prefix="scene-", dir=ctx.tmp))
    try:
        with pytest.MonkeyPatch.context() as mp:
            yield directory, mp
    finally:
        shutil.rmtree(directory, ignore_errors=True)


# -- platform profile --------------------------------------------------------

_HOSTS = (
    ("debian", "13", "x86_64", "cpython-313-x86_64-linux-gnu"),
    ("debian", "13", "aarch64", "cpython-313-aarch64-linux-gnu"),
    ("debian", "13", "arm64", "cpython-313-aarch64-linux-gnu"),
    ("debian", "13", "amd64", "cpython-313-x86_64-linux-gnu"),
    ("debian", "13", "x86_64", "cpython-312-x86_64-linux-gnu"),
    ("debian", "13", "aarch64", "cpython-313-x86_64-linux-gnu"),
    ("debian", "12", "x86_64", "cpython-313-x86_64-linux-gnu"),
    ("ubuntu", "24.04", "aarch64", "cpython-313-aarch64-linux-gnu"),
    ("debian", "13", "riscv64", "cpython-313-riscv64-linux-gnu"),
    ("debian", "13", "X86_64", "cpython-313-x86_64-linux-gnu"),
    ("debian", "13", "", "cpython-313-x86_64-linux-gnu"),
    ("debian", "13", None, "cpython-313-x86_64-linux-gnu"),
)


def platform_profile_selection(ctx: Context):
    from azazel_nexus import platform_profile as pp

    selections = []
    for os_id, version, machine, soabi in _HOSTS:
        entry = {"os_id": os_id, "os_version_id": version, "machine": machine, "soabi": soabi}
        try:
            chosen = pp.select_profile(os_id=os_id, os_version_id=version, machine=machine,
                                       soabi=soabi)
        except pp.PlatformRefused as exc:
            entry["refused"] = exc.reason
        else:
            entry["profile_id"] = chosen.profile_id
            entry["purpose"] = chosen.purpose
            entry["uses"] = {}
            for use in sorted(pp.PRODUCTION_USES) + ["not-a-use"]:
                try:
                    pp.require_deployment_baseline(chosen, use)
                    entry["uses"][use] = "admitted"
                except pp.PlatformRefused as exc:
                    entry["uses"][use] = exc.reason
        selections.append(entry)
    names = {}
    for architecture in pp.ARCHITECTURES:
        names[architecture] = {boundary: pp.to_boundary(architecture, boundary)
                               for boundary in pp.BOUNDARIES}
    readers = {}
    for raw in ("x86_64", "aarch64", "arm64", "amd64", "x86-64", "i686", "AARCH64", ""):
        row = {}
        for reader in ("from_machine", "normalize_machine"):
            try:
                row[reader] = getattr(pp, reader)(raw)
            except pp.PlatformRefused as exc:
                row[reader] = exc.reason
        for boundary in pp.BOUNDARIES:
            try:
                row[boundary] = pp.from_boundary(boundary, raw)
            except pp.PlatformRefused as exc:
                row[boundary] = exc.reason
        readers[raw] = row
    profiles = {pid: {"purpose": p.purpose, "architecture": p.architecture, "os_id": p.os_id,
                      "os_version_id": p.os_version_id, "soabi": p.soabi,
                      "features": sorted(p.features)}
                for pid, p in pp.REVIEWED_PROFILES.items()}
    return {"selections": selections, "boundary_names": names, "readers": readers,
            "profiles": profiles}


# -- M.I.O. route decision and consent gate -----------------------------------


def _predictions(**by_route):
    from azazel_nexus.route_evidence import Observation, Outcome, SizeClass, predict
    from azazel_nexus.routing import Route

    built = {}
    for name, (elapsed, count, answered) in by_route.items():
        observations = [
            Observation(candidate=name, at="2026-09-21T11:59:00Z", elapsed_ms=elapsed + i,
                        outcome=Outcome.ANSWERED if i < answered else Outcome.FAILED,
                        request_size=SizeClass.SMALL, response_size=SizeClass.SMALL,
                        queue_depth=0, cold_start=False)
            for i in range(count)
        ]
        built[Route.LOCAL if name == "local" else Route.REMOTE] = predict(
            observations, candidate=name, as_of="2026-09-21T12:00:00Z")
    return built


def mio_route(ctx: Context):
    from azazel_nexus.edge_package import Evidence
    from azazel_nexus.mio_profile import (
        NO_OPT_IN,
        PREREQUISITES,
        MioProfile,
        RemoteOptIn,
        Withdrawal,
    )
    from azazel_nexus.remote_trust import (
        RemoteAdmission,
        RemoteTrustReading,
        TrustSignal,
        remote_admission,
        unchecked_reading,
    )
    from azazel_nexus.route_selection import (
        TerminalEvent,
        fallback_once,
        outcome_for,
        select,
    )
    from azazel_nexus.routing import Route
    from azazel_nexus.sanitizer import PrivacyClass
    from azazel_nexus_runtime.mio_router import terminal_for

    granted = RemoteOptIn(granted=frozenset(PREREQUISITES), operator="op", at=CLOCK_AT)
    withdrawn = RemoteOptIn(granted=frozenset(PREREQUISITES), operator="op", at=CLOCK_AT,
                            withdrawn=Withdrawal(operator="op", at=CLOCK_AT,
                                                 reason="policy change"))
    partial = RemoteOptIn(granted=frozenset(list(PREREQUISITES)[:2]), operator="op",
                          at=CLOCK_AT)
    passed = RemoteTrustReading(signals={s: Evidence.PASSED for s in TrustSignal},
                                reasons={s: "vector" for s in TrustSignal})
    opt_ins = {"none": NO_OPT_IN, "partial": partial, "granted": granted,
               "withdrawn": withdrawn}
    trusts = {"unchecked": unchecked_reading(), "passed": passed}

    admissions = []
    for profile in MioProfile:
        for privacy in PrivacyClass:
            for opt_name, opt_in in opt_ins.items():
                for trust_name, trust in trusts.items():
                    for sanitised in (False, True):
                        admission = remote_admission(profile=profile, opt_in=opt_in,
                                                     trust=trust, privacy_class=privacy,
                                                     sanitised=sanitised)
                        admissions.append({"profile": profile.value, "privacy": privacy.value,
                                           "opt_in": opt_name, "trust": trust_name,
                                           "sanitised": sanitised, **admission.as_event()})

    hg05 = "the Core reserve is unmeasured (HG-05), so no local provider is admitted"
    fixture_permit = RemoteAdmission(permitted=True, excluded_by=None,
                                     reason="permitted by a vector fixture")
    real = remote_admission(profile=MioProfile.FASTEST_PERMITTED, opt_in=granted, trust=passed,
                            privacy_class=PrivacyClass.P0_PUBLIC, sanitised=True)
    cases = {
        "nothing_permitted": dict(remote=real, local=False, predictions={}),
        "local_unpredictable": dict(remote=real, local=True,
                                    predictions=_predictions(local=(300, 5, 5))),
        "local_selected": dict(remote=real, local=True,
                               predictions=_predictions(local=(300, 20, 20))),
        "local_misses_deadline": dict(remote=real, local=True,
                                      predictions=_predictions(local=(1500, 20, 20))),
        "local_below_success_floor": dict(remote=real, local=True,
                                          predictions=_predictions(local=(300, 20, 17))),
        "remote_faster": dict(remote=fixture_permit, local=True,
                              predictions=_predictions(local=(600, 20, 20),
                                                       remote=(200, 20, 20))),
        "tie_to_narrower": dict(remote=fixture_permit, local=True,
                                predictions=_predictions(local=(400, 20, 20),
                                                         remote=(400, 20, 20))),
    }
    selections = {}
    for name, case in cases.items():
        selection = select(profile=MioProfile.FASTEST_PERMITTED,
                           privacy_class=PrivacyClass.P0_PUBLIC, remote=case["remote"],
                           local_admitted=case["local"], local_refusal=hg05,
                           predictions=case["predictions"], deadline_ms=1000)
        fallbacks = []
        for failed in (Route.LOCAL, Route.REMOTE):
            for spent in (False, True):
                for narrowed in ((), (Route.LOCAL,), (Route.DETERMINISTIC_HANDOFF,)):
                    fallbacks.append(fallback_once(selection=selection, failed=failed,
                                                   already_spent=spent,
                                                   still_permitted=narrowed).as_event())
        selections[name] = {
            "selection": selection.as_event(),
            "predictions": {route.value: p.as_event()
                            for route, p in sorted(case["predictions"].items(),
                                                   key=lambda kv: kv[0].value)},
            "fallbacks": fallbacks,
        }
    outcomes = {event.value: {str(available): outcome_for(event, fallback_available=available).value
                              for available in (False, True)}
                for event in TerminalEvent}
    replies = [{"outcome": "advisory"}, {"outcome": "timed_out"}, {"outcome": "tls_failed"},
               {"outcome": "not_advice"}, {"outcome": "not_sent", "refusal": "malformed_payload"},
               {"outcome": "not_sent", "refusal": "something_else"}, {"outcome": "ready"}, {}]
    terminals = [{"reply": reply, "terminal": terminal_for(reply).value} for reply in replies]
    return {"admissions": admissions, "selections": selections, "outcomes": outcomes,
            "terminals": terminals}


def mio_consent(ctx: Context):
    """The opt-in store's generations and the send gate, on an injected clock."""
    from azazel_nexus.mio_profile import PREREQUISITES
    from azazel_nexus_runtime.mio_remote_consent import (
        ConsentRefused,
        ConsentStore,
        decode_record,
        encode_record,
    )

    directory = ctx.tmp / "mio"
    directory.mkdir()
    directory.chmod(0o700)
    ticks = iter(f"2026-10-28T00:00:{second:02d}Z" for second in range(60))
    store = ConsentStore(directory, owner=os.geteuid(), clock=lambda: next(ticks),
                         monotonic=iter(range(10**6)).__next__)

    def observe(label, record=None):
        reading = store.reading()
        with store.send_gate() as gate:
            gate_view = {"status": gate.status, "generation": gate.generation,
                         "permits": gate.permits}
        return {"step": label, "status": reading.status, "generation": reading.generation,
                "permits": reading.permits, "active": reading.opt_in.active(),
                "reason": reading.opt_in.reason(), "gate": gate_view,
                "record": None if record is None else encode_record(record).decode()}

    steps = [observe("absent")]
    for prerequisite in PREREQUISITES:
        record = store.set_prerequisite(prerequisite, operator="uid:1001")
        steps.append(observe(f"set:{prerequisite.value}", record))
    record, drained = store.withdraw("operator_request", operator="uid:1001")
    steps.append({**observe("withdrawn", record), "drained": drained})
    record = store.set_prerequisite(list(PREREQUISITES)[0], operator="uid:1001")
    steps.append(observe("set_after_withdrawal", record))

    canonical = encode_record(record)
    decodes = []
    for label, raw in (("canonical", canonical),
                       ("spaced", canonical.replace(b",", b", ")),
                       ("duplicate", canonical[:-1] + b',"at":"x"}'),
                       ("empty", b""),
                       ("oversized", b" " * 4097)):
        try:
            decoded = decode_record(raw)
            decodes.append({"input": label, "generation": decoded.generation})
        except ConsentRefused:
            decodes.append({"input": label, "refused": "ConsentRefused"})
    return {"steps": steps, "decodes": decodes}


# -- the registry ------------------------------------------------------------

#: Name -> builder. The name is the key in `digests.json`.
VECTORS: dict[str, Callable[[Context], object]] = {
    "edge.intake": edge_intake,
    "edge.incident": edge_incident,
    "edge.explain": edge_explain,
    "knowledge_lite.verify": knowledge_lite_verify,
    "knowledge_lite.lookup": knowledge_lite_lookup,
    "knowledge_lite.refusals": knowledge_lite_refusals,
    "revocation": revocation,
    "signature.ed25519": signature,
    "audit.chain": audit_chain,
    "status.read_model": status_read_model,
    "platform_profile.selection": platform_profile_selection,
    "mio.route": mio_route,
    "mio.consent": mio_consent,
}


def build(name: str):
    """The document for one vector, in a fresh context."""

    with context() as ctx:
        return VECTORS[name](ctx)


def compute(names=None) -> dict[str, str]:
    return {name: digest(build(name)) for name in (names or VECTORS)}


def pinned() -> dict[str, str]:
    document = json.loads(DIGESTS.read_text(encoding="utf-8"))
    return {name: entry["sha256"] for name, entry in document["vectors"].items()}


def host() -> dict:
    """What ran the vectors. Recorded beside the digests, never compared."""
    import platform
    import sysconfig

    return {"machine": platform.machine(), "python": platform.python_version(),
            "soabi": sysconfig.get_config_var("SOABI"), "byteorder": sys.byteorder,
            "uid": os.geteuid()}


def main(argv=None) -> int:
    """``python tests/vectors/cross_arch.py [--show NAME]``: print the digests as JSON."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--show", metavar="NAME", help="print one vector's canonical document")
    args = parser.parse_args(argv)
    if args.show:
        sys.stdout.write(canonical_bytes(build(args.show)).decode("utf-8") + "\n")
        return 0
    computed = compute()
    expected = pinned()
    report = {"host": host(), "digests": computed,
              "matches_pins": {name: computed[name] == expected.get(name) for name in computed}}
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
