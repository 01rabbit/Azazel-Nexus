"""Observe-baseline generation builder and verifier (#206 P2), temp stores only."""

from dataclasses import asdict, replace
from hashlib import sha256
import json

import pytest

from azazel_nexus import observe_baseline
from azazel_nexus.bootstrap_generation import verify_bootstrap_generation
from azazel_nexus.edge_package import PIN
from azazel_nexus.generation import GenerationRefused, GenerationStore, tree_digest
from azazel_nexus.observe_baseline import (
    OBSERVE_BASELINE_SCHEMA,
    build_observe_baseline,
    decode_observe_baseline,
    edge_pin_digest,
    verify_observe_baseline,
)
from test_bootstrap_generation import _config, _context

NOW = "2026-10-20T00:00:00Z"
#: The extracted binary and redirect policy the edge-core unit uses (#206 P5).
COMPONENTS = {"bin/azazel-edge-core": "sha256:" + "e" * 64,
              "config/redirect_policy.yaml": "sha256:" + "f" * 64}
COMMISSIONING = "sha256:" + "a" * 64
BINDING = "hmac-sha256:" + "b" * 64
UNITS = [
    "azazel-edge-intaked.service", "azazel-edge-probed.service",
    "azazel-incident-explaind.service", "azazel-knowledge-lited.service",
    "azazel-mio-entryd.service",
]


def _unit_files(units=UNITS):
    return {unit: f"[Unit]\nDescription={unit}\n".encode() for unit in units}


def _publish(tmp_path, files):
    store = GenerationStore(tmp_path / "generations")
    store.create(files, created_at=NOW, commissioning_digest=COMMISSIONING,
                 commissioning_evidence_binding=BINDING)
    generation = store.verify(1)
    return store, generation


@pytest.fixture
def published(tmp_path):
    tree = build_observe_baseline(units=UNITS, unit_files=_unit_files())
    store, generation = _publish(tmp_path, tree)
    return store, generation


def _verify(generation, files, *, units=UNITS, unit_files=None, package_digest=None,
            package_components=None):
    if package_digest is not None and package_components is None:
        package_components = COMPONENTS
    return verify_observe_baseline(
        generation=generation, files=files, units=units,
        unit_files=_unit_files() if unit_files is None else unit_files,
        package_digest=package_digest, package_components=package_components,
    )


def test_built_tree_is_one_canonical_document():
    tree = build_observe_baseline(units=UNITS, unit_files=_unit_files())
    assert set(tree) == {"baseline.json"}
    document = json.loads(tree["baseline.json"])
    assert document == {
        "schema": OBSERVE_BASELINE_SCHEMA,
        "units": UNITS,
        "edge_pin": {"version": PIN.version, "contract_digest": edge_pin_digest()},
        "unit_files": {unit: "sha256:" + sha256(data).hexdigest()
                       for unit, data in _unit_files().items()},
    }
    assert tree["baseline.json"] == json.dumps(
        document, sort_keys=True, separators=(",", ":")).encode()
    assert decode_observe_baseline(tree["baseline.json"]) == document


def test_edge_pin_digest_names_the_code_fixed_pin():
    expected = sha256(json.dumps(asdict(PIN), sort_keys=True, separators=(",", ":")).encode())
    assert edge_pin_digest() == "sha256:" + expected.hexdigest()


def test_published_ordinary_generation_verifies(published):
    store, generation = published
    verified = _verify(generation, store.read_tree(1))
    assert verified.generation == 1
    assert verified.digest == generation.digest
    assert verified.units == tuple(UNITS)


EDGE_UNITS = sorted(UNITS + ["azazel-edge-core.service"])
PACKAGE = "sha256:" + "c" * 64


def test_edge_core_in_scope_is_hashed_like_any_unit(tmp_path):
    units = EDGE_UNITS
    files = _unit_files(units)
    files["azazel-edge-core.service"] += b"Environment=AZAZEL_EDGE_MODE=observe\n"
    store, generation = _publish(tmp_path, build_observe_baseline(
        units=units, unit_files=files, package_digest=PACKAGE, package_components=COMPONENTS))
    _verify(generation, store.read_tree(1), units=units, unit_files=files,
            package_digest=PACKAGE)
    files["azazel-edge-core.service"] = files["azazel-edge-core.service"].replace(
        b"observe", b"enforce")
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1), units=units, unit_files=files,
                package_digest=PACKAGE)


def test_edge_core_scope_binds_the_installed_package_digest(tmp_path):
    tree = build_observe_baseline(units=EDGE_UNITS, unit_files=_unit_files(EDGE_UNITS),
                                  package_digest=PACKAGE, package_components=COMPONENTS)
    pin = json.loads(tree["baseline.json"])["edge_pin"]
    assert pin == {"version": PIN.version, "contract_digest": edge_pin_digest(),
                   "package_digest": PACKAGE, "components": COMPONENTS}
    store, generation = _publish(tmp_path, tree)
    _verify(generation, store.read_tree(1), units=EDGE_UNITS,
            unit_files=_unit_files(EDGE_UNITS), package_digest=PACKAGE)
    for other in ("sha256:" + "d" * 64, None):
        with pytest.raises(GenerationRefused):
            _verify(generation, store.read_tree(1), units=EDGE_UNITS,
                    unit_files=_unit_files(EDGE_UNITS), package_digest=other)
    # The extracted binary or redirect policy the unit uses is bound too.
    for name in COMPONENTS:
        changed = {**COMPONENTS, name: "sha256:" + "0" * 64}
        with pytest.raises(GenerationRefused):
            _verify(generation, store.read_tree(1), units=EDGE_UNITS,
                    unit_files=_unit_files(EDGE_UNITS), package_digest=PACKAGE,
                    package_components=changed)


@pytest.mark.parametrize("components", [
    None, {}, {"bin/azazel-edge-core": "sha256:" + "e" * 64},
    {**COMPONENTS, "bin/other": "sha256:" + "e" * 64},
    {**COMPONENTS, "bin/azazel-edge-core": "sha256:" + "E" * 64},
    {**COMPONENTS, "bin/azazel-edge-core": None},
], ids=["none", "empty", "one", "extra", "uppercase", "not-a-digest"])
def test_edge_core_scope_requires_exactly_the_bound_components(components):
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=EDGE_UNITS, unit_files=_unit_files(EDGE_UNITS),
                               package_digest=PACKAGE, package_components=components)


def test_components_are_forbidden_without_edge_core():
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=UNITS, unit_files=_unit_files(),
                               package_components=COMPONENTS)


@pytest.mark.parametrize("digest", [
    None, "", "sha256:" + "C" * 64, "sha512:" + "c" * 64, "c" * 64, b"sha256:" + b"c" * 64,
])
def test_edge_core_scope_requires_a_wellformed_package_digest(digest):
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=EDGE_UNITS, unit_files=_unit_files(EDGE_UNITS),
                               package_digest=digest, package_components=COMPONENTS)


def test_package_digest_forbidden_without_edge_core(published):
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=UNITS, unit_files=_unit_files(), package_digest=PACKAGE)
    store, generation = published
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1), package_digest=PACKAGE)


def test_stored_pin_shape_must_match_the_scope():
    edge = json.loads(build_observe_baseline(
        units=EDGE_UNITS, unit_files=_unit_files(EDGE_UNITS),
        package_digest=PACKAGE, package_components=COMPONENTS)["baseline.json"])
    for field in ("package_digest", "components"):
        without = {**edge, "edge_pin": {k: v for k, v in edge["edge_pin"].items()
                                        if k != field}}
        with pytest.raises(GenerationRefused):
            decode_observe_baseline(_bytes(without))
    plain = _document()
    plain["edge_pin"] = {**plain["edge_pin"], "package_digest": PACKAGE}
    with pytest.raises(GenerationRefused):
        decode_observe_baseline(_bytes(plain))
    assert decode_observe_baseline(_bytes(edge)) == edge


@pytest.mark.parametrize("units", [
    [], ["azazel-auditd.service"], sorted(UNITS + ["azazel-watchdog.service"]),
    list(reversed(UNITS)), UNITS + UNITS[:1], "azazel-edge-intaked.service",
])
def test_builder_refuses_scope_outside_allowlist_or_not_exact(units):
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=units, unit_files=_unit_files(
            [u for u in units] if isinstance(units, list) else UNITS))


@pytest.mark.parametrize("change", ["missing", "extra", "empty", "text"])
def test_builder_refuses_unit_files_not_matching_scope(change):
    files = _unit_files()
    if change == "missing":
        files.pop(UNITS[0])
    elif change == "extra":
        files["azazel-edge-core.service"] = b"x"
    elif change == "empty":
        files[UNITS[0]] = b""
    else:
        files[UNITS[0]] = "text"
    with pytest.raises(GenerationRefused):
        build_observe_baseline(units=UNITS, unit_files=files)


def test_mismatch_installed_unit_file_bytes(published):
    store, generation = published
    files = _unit_files()
    files[UNITS[2]] += b"ExecStart=/bin/sh\n"
    with pytest.raises(GenerationRefused) as error:
        _verify(generation, store.read_tree(1), unit_files=files)
    assert str(error.value) == "observe-baseline generation refused"


def test_mismatch_policy_scope_narrower_or_wider(published):
    store, generation = published
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1), units=UNITS[1:], unit_files=_unit_files(UNITS[1:]))
    wider = sorted(UNITS + ["azazel-edge-core.service"])
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1), units=wider, unit_files=_unit_files(wider),
                package_digest="sha256:" + "c" * 64)


def test_mismatch_edge_pin(published, monkeypatch):
    store, generation = published
    monkeypatch.setattr(observe_baseline, "PIN", replace(PIN, version="0.1.1"))
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1))


def test_mismatch_generation_digest(published):
    store, generation = published
    with pytest.raises(GenerationRefused):
        _verify(replace(generation, digest="sha256:" + "0" * 64), store.read_tree(1))


def test_generation_without_evidence_binding_refused(published):
    store, generation = published
    with pytest.raises(GenerationRefused):
        _verify(replace(generation, commissioning_evidence_binding=None), store.read_tree(1))


def test_metadata_must_be_an_ordinary_generation(published):
    store, generation = published
    with pytest.raises(GenerationRefused):
        _verify(generation.__dict__, store.read_tree(1))


def _document():
    return json.loads(build_observe_baseline(units=UNITS, unit_files=_unit_files())["baseline.json"])


def _bytes(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


@pytest.mark.parametrize("raw", [
    json.dumps(_document(), sort_keys=True, indent=2).encode(),
    _bytes(_document()) + b"\n",
    _bytes({**_document(), "variant": "observe"}),
    _bytes({**_document(), "schema": "azazel-nexus/observe-baseline-generation/v2"}),
    _bytes({k: v for k, v in _document().items() if k != "edge_pin"}),
    _bytes({**_document(), "edge_pin": {"version": PIN.version}}),
    _bytes({**_document(), "edge_pin": {"version": PIN.version, "contract_digest": "md5:x"}}),
    _bytes({**_document(), "edge_pin": {"version": PIN.version, "digest": edge_pin_digest()}}),
    _bytes({**_document(), "unit_files": {}}),
    _bytes({**_document(), "unit_files": {u: "sha256:" + "z" * 64 for u in UNITS}}),
    _bytes(_document()).replace(b'"units"', b'"units":[],"units"', 1),
    b"[]",
    b"",
])
def test_closed_shape_and_canonical_bytes_refused(raw):
    with pytest.raises(GenerationRefused):
        decode_observe_baseline(raw)


def test_tree_with_any_other_shape_refused(tmp_path):
    good = build_observe_baseline(units=UNITS, unit_files=_unit_files())
    for index, files in enumerate([
        {**good, "extra.json": b"{}"},
        {"node.yaml": b"preexisting ordinary generation\n"},
        {"bootstrap.json": _config()},
        {"nested/baseline.json": good["baseline.json"]},
    ]):
        store = GenerationStore(tmp_path / f"store-{index}")
        store.create(files, created_at=NOW, commissioning_digest=COMMISSIONING,
                     commissioning_evidence_binding=BINDING)
        with pytest.raises(GenerationRefused):
            _verify(store.verify(1), store.read_tree(1))


def test_reformatted_tree_with_matching_metadata_still_refused(tmp_path):
    files = {"baseline.json": json.dumps(_document(), sort_keys=True, indent=1).encode()}
    store, generation = _publish(tmp_path, files)
    assert generation.digest == tree_digest(files)
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1))


def test_tree_altered_after_publication_refused_by_store_and_verifier(published):
    store, generation = published
    path = store.root / "1" / "tree" / "baseline.json"
    document = json.loads(path.read_bytes())
    document["units"] = UNITS[:1]
    document["unit_files"] = {UNITS[0]: document["unit_files"][UNITS[0]]}
    path.chmod(0o600)
    path.write_bytes(_bytes(document))
    with pytest.raises(GenerationRefused):
        store.verify(1)
    with pytest.raises(GenerationRefused):
        _verify(generation, store.read_tree(1))


def test_bootstrap_verifier_refuses_the_observe_baseline_tree():
    tree = build_observe_baseline(units=UNITS, unit_files=_unit_files())
    context = _context(tree)
    metadata = json.dumps({
        "schema": "azazel-nexus/bootstrap-generation/v1",
        "variant": "bootstrap/uncommissioned", "number": context.generation,
        "digest": tree_digest(tree), "created_at": NOW,
    }, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(GenerationRefused):
        verify_bootstrap_generation(metadata=metadata, files=tree, expected=context)


def test_ordinary_reader_accepts_the_metadata_and_refuses_a_bootstrap_variant(published):
    store, generation = published
    assert store.read(1) == generation
    meta = store.root / "1" / "generation.json"
    document = json.loads(meta.read_bytes())
    meta.chmod(0o600)
    meta.write_text(json.dumps({**document, "variant": "observe-baseline"}))
    with pytest.raises(GenerationRefused):
        store.read(1)


def test_commissioning_digest_is_the_verified_proposal_digest():
    from azazel_nexus.commissioning_evidence import CommissioningEvidence

    payload = b'{"schema":"synthetic-full-proposal"}'
    evidence = CommissioningEvidence(payload, b"s" * 64, b"{}", "hmac-sha256:" + "c" * 64)
    assert observe_baseline.evidence_commissioning_digest(evidence) == (
        "sha256:" + sha256(payload).hexdigest())
    for value in (None, object(), b"raw"):
        with pytest.raises(GenerationRefused):
            observe_baseline.evidence_commissioning_digest(value)
