"""What may be offered as a model, and what offering one does not mean (#94).

The distinction this file exists to defend, and the one it would be easiest
to lose:

*no catalog* ≠ *empty catalog* ≠ *declared but no artifact* ≠ *artifact
present and verified*. And none of the four is `available`, because none of
them is a model serving as a provider.

The signing oracle is a fixed, test-only key derived from a literal string.
It is shared with no production, commissioned or release key, exists only for
the run, and no key material reaches a file, a fixture, a log or an assertion.
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib

import pytest

from azazel_nexus import model_catalog
from azazel_nexus.model_catalog import (
    CATALOG_DOMAIN,
    CATALOG_FILENAME,
    CATALOG_SCHEMA,
    KNOWN_FORMATS,
    KNOWN_RUNTIME_ABIS,
    MAX_CATALOG_BYTES,
    MAX_ENTRIES,
    CatalogRefused,
    CatalogState,
    ModelEntry,
    ModelReading,
    Refusal,
    absent_reading,
    artifact_filename,
    catalog_payload,
    read_catalog,
    verify_artifact,
)
from azazel_nexus.resource_profile import ResourceProfile

nacl_signing = pytest.importorskip("nacl.signing", reason="PyNaCl is a dev dependency")

COMMISSIONING = "sha256:" + "c" * 64
OTHER_COMMISSIONING = "sha256:" + "d" * 64

#: Fixed, test-only. Never leaves this process.
_SEED = hashlib.sha256(b"azazel-nexus/test-only/model-catalog/0").digest()
_WRONG_SEED = hashlib.sha256(b"azazel-nexus/test-only/model-catalog/wrong").digest()


def _key(seed=_SEED):
    return nacl_signing.SigningKey(seed)


def trusted(seed=_SEED):
    return {"catalog-key": bytes(_key(seed).verify_key)}


def an_entry(**overrides) -> ModelEntry:
    body = b"weights, not a program"
    fields = {
        "model_id": "small-advisor",
        "format": "gguf",
        "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
        "provenance": "fixture, emitted by this test",
        "license_acknowledgement_required": False,
        "runtime_abi": "llama.cpp/1",
        "purpose": "summarise a situation frame",
        "context_limit": 4096,
        "declared_min_ram_mib": 4096,
        "declared_min_disk_mib": 2048,
        "declared_profile": ResourceProfile.LITE,
        "rollback_lineage": (),
    }
    fields.update(overrides)
    return ModelEntry(**fields)


def write_catalog(directory, entries, *, seed=_SEED, commissioning=COMMISSIONING, version=1,
                  domain=CATALOG_DOMAIN, payload=None):
    body = payload if payload is not None else catalog_payload(
        version=version, commissioning_digest=commissioning, entries=entries
    )
    signature = bytes(_key(seed).sign(domain + body).signature)
    path = directory / CATALOG_FILENAME
    path.write_bytes(signature + body)
    return path


def write_artifact(directory, entry, content=b"weights, not a program"):
    path = directory / artifact_filename(entry)
    path.write_bytes(content)
    return path


# -- the four states stay four -------------------------------------------


def test_no_catalog_is_absent(tmp_path) -> None:
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(
            tmp_path / CATALOG_FILENAME,
            trusted_keys=trusted(),
            commissioning_digest=COMMISSIONING,
        )
    assert Refusal.CATALOG_ABSENT.value in str(caught.value)
    assert absent_reading().state is CatalogState.ABSENT


def test_an_empty_catalog_is_empty_and_not_absent(tmp_path) -> None:
    """A node told "nothing is offered" differs from one told nothing."""

    path = write_catalog(tmp_path, [])
    catalog = read_catalog(
        path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    )
    assert catalog.state is CatalogState.EMPTY
    assert catalog.state is not CatalogState.ABSENT
    assert catalog.entries == ()


def test_a_declared_entry_with_no_artifact_is_declared(tmp_path) -> None:
    entry = an_entry()
    path = write_catalog(tmp_path, [entry])
    catalog = read_catalog(
        path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    )
    assert catalog.state is CatalogState.DECLARED
    reading = verify_artifact(entry, artifact_root=tmp_path)
    assert reading.state is CatalogState.DECLARED
    assert reading.refused_by is Refusal.ARTIFACT_ABSENT


def test_a_verified_artifact_is_present_and_still_not_admitted(tmp_path) -> None:
    """`PRESENT` is the furthest this module can take anything."""

    entry = an_entry()
    write_artifact(tmp_path, entry)
    reading = verify_artifact(entry, artifact_root=tmp_path)
    assert reading.state is CatalogState.PRESENT
    assert reading.refused_by is None
    assert reading.admitted is False
    assert "HG-05" in reading.reason


def test_the_four_states_are_four_and_none_is_available() -> None:
    """One word for all of them would be the word an operator fills in."""

    assert {s.value for s in CatalogState} == {"absent", "empty", "declared", "present"}
    assert "AVAILABLE" not in {s.name for s in CatalogState}
    source = pathlib.Path(model_catalog.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    members = {
        node.targets[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.isupper()
    }
    assert "AVAILABLE" not in members


def test_nothing_here_can_report_itself_admitted() -> None:
    """Admission belongs to the gates, against a measured Core reserve."""

    with pytest.raises(CatalogRefused) as caught:
        ModelReading(
            model_id="m", state=CatalogState.PRESENT, refused_by=None,
            reason="r", admitted=True,
        )
    assert "HG-05" in str(caught.value)


# -- the catalog is signed, versioned, canonical and bound ----------------


def test_an_unsigned_catalog_is_refused(tmp_path) -> None:
    body = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[])
    (tmp_path / CATALOG_FILENAME).write_bytes(b"\0" * 64 + body)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(
            tmp_path / CATALOG_FILENAME,
            trusted_keys=trusted(),
            commissioning_digest=COMMISSIONING,
        )
    assert Refusal.CATALOG_UNSIGNED.value in str(caught.value)


def test_a_catalog_signed_by_another_key_is_refused(tmp_path) -> None:
    path = write_catalog(tmp_path, [an_entry()], seed=_WRONG_SEED)
    with pytest.raises(CatalogRefused):
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)


def test_a_signature_without_the_domain_tag_does_not_verify(tmp_path) -> None:
    """Three signing targets, three roles, and no coincidence holding them apart.

    A signature made over the bare payload -- as a manifest, a revocation
    list or a runtime binary signature would be -- must not read as a
    catalog signature. That is what the tag is for, and the schemas not
    happening to overlap is not a substitute.
    """

    path = write_catalog(tmp_path, [an_entry()], domain=b"")
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert Refusal.CATALOG_UNSIGNED.value in str(caught.value)


def test_a_signature_with_another_domain_tag_does_not_verify(tmp_path) -> None:
    path = write_catalog(tmp_path, [an_entry()], domain=b"azazel-nexus/revocation/v1\x00")
    with pytest.raises(CatalogRefused):
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)


def test_the_domain_tag_is_fixed_versioned_and_fixed_length() -> None:
    assert CATALOG_DOMAIN.endswith(b"\x00")
    assert b"/v1" in CATALOG_DOMAIN
    tree = ast.parse(pathlib.Path(model_catalog.__file__).read_text(encoding="utf-8"))
    assigned = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "CATALOG_DOMAIN"
    ]
    assert len(assigned) == 1, "the tag is defined in exactly one place"


def test_a_catalog_pinned_under_another_commissioning_is_refused(tmp_path) -> None:
    path = write_catalog(tmp_path, [an_entry()], commissioning=OTHER_COMMISSIONING)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "re-commissioning" in str(caught.value)


def test_the_payload_is_canonical() -> None:
    """The signer and the verifier cannot disagree about what was signed."""

    entries = [an_entry(model_id="b"), an_entry(model_id="a")]
    once = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=entries)
    again = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=entries)
    assert once == again
    document = json.loads(once)
    assert document["schema"] == CATALOG_SCHEMA
    # Structural, not textual: a byte scan would trip over a comma inside a
    # string value. Re-serialising canonically must reproduce the payload
    # exactly, which pins both key order and separator spacing.
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert once == canonical
    # And the entries are ordered by the payload, not by the caller's list:
    # an id names one entry, so the order the builder was handed is not part
    # of what is being signed.
    assert [entry["model_id"] for entry in document["entries"]] == ["a", "b"]
    reversed_order = catalog_payload(
        version=1, commissioning_digest=COMMISSIONING, entries=list(reversed(entries))
    )
    assert reversed_order == once


def test_a_broken_key_in_the_store_does_not_make_the_catalog_unverifiable(tmp_path) -> None:
    """And the result does not depend on ordering."""

    path = write_catalog(tmp_path, [an_entry()])
    keys = {"aaa-broken": b"\x00" * 31, "zzz-good": bytes(_key().verify_key)}
    catalog = read_catalog(path, trusted_keys=keys, commissioning_digest=COMMISSIONING)
    assert catalog.signer == "zzz-good"


@pytest.mark.parametrize("order", [("aaa-good", "zzz-good"), ("zzz-good", "aaa-good")])
def test_the_reported_signer_does_not_depend_on_store_ordering(tmp_path, order) -> None:
    """Two keys, one catalog: which one is named must not be dict order.

    The same key material under two ids verifies under both, so the only
    thing deciding the answer is the iteration order of the trust store.
    An audit record whose content depends on how a mapping was built is a
    record two nodes can disagree about while both being right.
    """

    path = write_catalog(tmp_path, [an_entry()])
    material = bytes(_key().verify_key)
    keys = {key_id: material for key_id in order}
    catalog = read_catalog(path, trusted_keys=keys, commissioning_digest=COMMISSIONING)
    assert catalog.signer == "aaa-good"


def test_the_schema_names_the_shape_it_actually_has() -> None:
    """The schema moved to `/2` when `source_id` was added.

    A required field changes what the document is, so a reader that accepted
    a `/1` document under `/2` rules would be inferring a field nobody wrote.
    And the domain tag did *not* move: it says what kind of thing was signed,
    which is unchanged, while the schema says what shape it is.
    """

    assert CATALOG_SCHEMA == "azazel-nexus/model-catalog/2"
    assert CATALOG_DOMAIN == b"azazel-nexus/model-catalog/v1\x00"
    assert "source_id" in an_entry().as_document()


def test_verification_checks_the_domain_the_schema_and_the_bytes(tmp_path) -> None:
    """All three, and a catalog is accepted only when every one holds.

    They answer different questions -- what kind of thing was signed, what
    shape it is, and whether these are the bytes that were signed -- and
    checking two of the three leaves the third free to be anything.
    """

    good = write_catalog(tmp_path, [an_entry()])
    assert read_catalog(
        good, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    ).schema == CATALOG_SCHEMA

    # 1. Wrong domain: the signature is over the right payload, under the
    #    right key, with the wrong kind tag.
    wrong_domain = tmp_path / "domain"
    wrong_domain.mkdir()
    path = write_catalog(wrong_domain, [an_entry()], domain=b"azazel-nexus/other/v1\x00")
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert Refusal.CATALOG_UNSIGNED.value in str(caught.value)

    # 2. Wrong schema: correctly signed, correct domain, shape unknown.
    wrong_schema = tmp_path / "schema"
    wrong_schema.mkdir()
    document = json.loads(
        catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[])
    )
    document["schema"] = "azazel-nexus/model-catalog/77"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_catalog(wrong_schema, [], payload=payload)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "model-catalog/77" in str(caught.value)

    # 3. Wrong bytes: correct domain, correct schema, payload edited after
    #    signing.
    tampered = tmp_path / "bytes"
    tampered.mkdir()
    raw = bytearray(good.read_bytes())
    raw[-2] ^= 0xFF
    (tampered / CATALOG_FILENAME).write_bytes(bytes(raw))
    with pytest.raises(CatalogRefused):
        read_catalog(
            tampered / CATALOG_FILENAME,
            trusted_keys=trusted(),
            commissioning_digest=COMMISSIONING,
        )


def test_the_domain_moves_for_a_kind_or_a_protocol_never_for_a_field() -> None:
    """What the two version numbers mean, pinned so the rule survives.

    The domain names the *kind* of signing target and the canonical signing
    protocol. It moves when the kind changes, when canonicalisation changes,
    or when cross-protocol separation has to mean something new. It does not
    move because the payload grew a field -- `source_id` did exactly that
    (#96), and the schema moved while the domain did not.

    Bumping the domain for every shape change would make each one a new
    signing role, and a key store full of one-version roles is a store where
    nothing is reused and every rotation is a migration.
    """

    assert CATALOG_DOMAIN == b"azazel-nexus/model-catalog/v1\x00"
    assert CATALOG_SCHEMA == "azazel-nexus/model-catalog/2"
    # The kind is in the domain; the shape number is not.
    assert b"model-catalog" in CATALOG_DOMAIN
    assert b"/2" not in CATALOG_DOMAIN
    # And the rule is written down where the constant is, not only here.
    source = pathlib.Path(model_catalog.__file__).read_text(encoding="utf-8")
    # Strip the comment markers before flattening: a sentence wrapped across
    # two comment lines would otherwise read as "canonical #: signing".
    flat = " ".join(source.replace("#:", " ").split())
    assert "the *kind* of signing target" in flat
    assert "the canonical signing protocol" in flat
    assert "It does **not** move because the payload grew a field" in flat


def test_a_catalog_declaring_the_previous_schema_is_refused(tmp_path) -> None:
    """The shape it names is not the shape this reader knows."""

    body = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[])
    document = json.loads(body)
    document["schema"] = "azazel-nexus/model-catalog/1"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_catalog(tmp_path, [], payload=payload)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "model-catalog/1" in str(caught.value)


def test_a_catalog_naming_another_schema_is_refused(tmp_path) -> None:
    """Refused, not best-effort parsed. A reader that guesses is a reader
    that accepts a document nobody wrote for it."""

    body = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[])
    document = json.loads(body)
    document["schema"] = "azazel-nexus/model-catalog/99"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_catalog(tmp_path, [], payload=payload)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "model-catalog/99" in str(caught.value)


@pytest.mark.parametrize("version", [0, -1, "1", 1.0, True, None])
def test_a_catalog_without_a_positive_whole_version_is_refused(tmp_path, version) -> None:
    body = catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[])
    document = json.loads(body)
    document["version"] = version
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_catalog(tmp_path, [], payload=payload)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "positive whole number" in str(caught.value)


# -- entry refusals, each named and each independent ---------------------


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"format": "pickle"}, "not one of"),
        ({"runtime_abi": "invented/9"}, "not one of"),
        ({"digest": "not-a-digest"}, "sha256 digest"),
        ({"size_bytes": 0}, "positive whole number"),
        ({"context_limit": -1}, "positive whole number"),
        ({"provenance": "  "}, "where it came from"),
        ({"purpose": ""}, "what it is for"),
    ],
)
def test_a_malformed_entry_is_refused(overrides, expected) -> None:
    with pytest.raises(CatalogRefused) as caught:
        an_entry(**overrides)
    assert expected in str(caught.value)


@pytest.mark.parametrize(
    "model_id",
    ["../escape", "a/b", "a\\b", "/absolute", "..", "A-Upper", "", "x" * 65, "a b"],
)
def test_a_model_id_that_names_a_location_is_refused(model_id) -> None:
    """An id names an entry, never a location."""

    with pytest.raises(CatalogRefused) as caught:
        an_entry(model_id=model_id)
    assert "not a model id" in str(caught.value)


def test_an_undefined_profile_is_refused(tmp_path) -> None:
    entry = an_entry()
    document = json.loads(
        catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[entry])
    )
    document["entries"][0]["declared_profile"] = "enormous"
    body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path = write_catalog(tmp_path, [], payload=body)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert Refusal.UNDEFINED_PROFILE.value in str(caught.value)


def test_an_entry_with_an_extra_field_is_refused(tmp_path) -> None:
    """Including the ones somebody would most plausibly add."""

    for extra in ("download_url", "command", "args", "license_text", "prompt"):
        entry = an_entry()
        document = json.loads(
            catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[entry])
        )
        document["entries"][0][extra] = "x"
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        path = write_catalog(tmp_path, [], payload=body)
        with pytest.raises(CatalogRefused) as caught:
            read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
        assert extra in str(caught.value)


def test_a_catalog_larger_than_the_ceiling_is_refused_before_parsing(tmp_path) -> None:
    """The ceiling is checked on the bytes, before any of them are trusted.

    A reader that parses first and bounds afterwards has already spent the
    work the bound exists to prevent.
    """

    path = tmp_path / CATALOG_FILENAME
    path.write_bytes(b"\0" * 64 + b"{" + b" " * (MAX_CATALOG_BYTES + 1))
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert str(MAX_CATALOG_BYTES) in str(caught.value)
    # And the ceiling is a ceiling, not a floor: an ordinary catalog of the
    # same shape but under it is read.
    good = write_catalog(tmp_path, [an_entry()])
    assert read_catalog(
        good, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    ).state is CatalogState.DECLARED


def test_an_artifact_symlinked_out_of_the_root_is_refused_as_traversal(tmp_path) -> None:
    """The digest cannot escape the root, but a symlink at the destination can.

    The filename is digest-derived, so nothing *in the catalog* can steer a
    path. What can is a link an operator or an import step left in the
    artifact root: `stat` and `open` both follow it, so without resolving
    the path a file outside the root would verify as present on its
    contents alone. This is the case the check exists for.
    """

    root = tmp_path / "artifacts"
    root.mkdir()
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    entry = an_entry()
    body = b"weights, not a program"
    target = outside / "real-weights.bin"
    target.write_bytes(body)
    (root / artifact_filename(entry)).symlink_to(target)
    # The contents are exactly what the catalog declared -- size and digest
    # both match -- so only the location is wrong.
    assert hashlib.sha256(target.read_bytes()).hexdigest() == entry.digest.split(":")[1]
    reading = verify_artifact(entry, artifact_root=root)
    assert reading.refused_by is Refusal.PATH_TRAVERSAL
    assert reading.state is CatalogState.DECLARED


def test_a_catalog_offering_too_many_entries_is_refused(tmp_path) -> None:
    entries = [an_entry(model_id=f"m{i}") for i in range(MAX_ENTRIES + 1)]
    path = write_catalog(tmp_path, entries)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert str(MAX_ENTRIES) in str(caught.value)


def test_a_duplicated_model_id_is_refused(tmp_path) -> None:
    path = write_catalog(tmp_path, [an_entry(), an_entry()])
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "more than once" in str(caught.value)


# -- artifact refusals ----------------------------------------------------


def test_a_size_mismatch_is_refused_before_hashing(tmp_path) -> None:
    entry = an_entry()
    write_artifact(tmp_path, entry, content=b"shorter")
    reading = verify_artifact(entry, artifact_root=tmp_path)
    assert reading.refused_by is Refusal.SIZE_MISMATCH


def test_a_digest_mismatch_is_refused(tmp_path) -> None:
    entry = an_entry()
    write_artifact(tmp_path, entry, content=b"weights, not a progrAm")  # same length
    reading = verify_artifact(entry, artifact_root=tmp_path)
    assert reading.refused_by is Refusal.DIGEST_MISMATCH


@pytest.mark.parametrize(
    "magic, what",
    [
        (b"\x7fELF\x02\x01", "ELF"),
        (b"MZ\x90\x00", "PE"),
        (b"#!/bin/sh\n", "script"),
        (b"PK\x03\x04\x14\x00", "zip"),
        (b"\x1f\x8b\x08\x00", "gzip"),
        (b"\xfd7zXZ\x00\x00", "xz"),
        (b"BZh9AY", "bzip2"),
        (b"\x28\xb5\x2f\xfd\x00\x00", "zstd"),
    ],
)
def test_an_executable_or_archive_is_refused_as_not_weights(tmp_path, magic, what) -> None:
    """An archive unpacks and an executable runs. A model artifact does neither."""

    content = magic + b"x" * 40
    entry = an_entry(
        digest="sha256:" + hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )
    write_artifact(tmp_path, entry, content=content)
    reading = verify_artifact(entry, artifact_root=tmp_path)
    assert reading.refused_by is Refusal.NOT_WEIGHTS, what
    assert "does neither" in reading.reason


def test_plain_weights_are_not_mistaken_for_an_archive(tmp_path) -> None:
    """Otherwise the test above would pass by refusing everything."""

    entry = an_entry()
    write_artifact(tmp_path, entry)
    assert verify_artifact(entry, artifact_root=tmp_path).refused_by is None


def test_an_unacknowledged_licence_is_refused_without_reading_the_artifact(tmp_path) -> None:
    """Cheap and absolute first: a node does not hash gigabytes to find out."""

    entry = an_entry(license_acknowledgement_required=True)
    # No artifact on disk at all, and the refusal is still about the licence.
    reading = verify_artifact(entry, artifact_root=tmp_path, license_acknowledged=False)
    assert reading.refused_by is Refusal.LICENSE_NOT_ACKNOWLEDGED


def test_an_acknowledged_licence_proceeds(tmp_path) -> None:
    entry = an_entry(license_acknowledgement_required=True)
    write_artifact(tmp_path, entry)
    reading = verify_artifact(entry, artifact_root=tmp_path, license_acknowledged=True)
    assert reading.state is CatalogState.PRESENT


def test_a_stale_rollback_lineage_is_refused(tmp_path) -> None:
    entry = an_entry()
    write_artifact(tmp_path, entry)
    reading = verify_artifact(
        entry, artifact_root=tmp_path, installed_lineage=("small-advisor", "older")
    )
    assert reading.refused_by is Refusal.STALE_ROLLBACK_LINEAGE


def test_the_artifact_filename_comes_from_the_digest_not_the_name() -> None:
    """A filename built from a name is a filename the entry could steer."""

    entry = an_entry()
    name = artifact_filename(entry)
    assert entry.model_id not in name
    assert name.startswith(entry.digest.split(":")[1])
    assert "/" not in name and ".." not in name


# -- declared conditions are not admission --------------------------------


def test_declared_resource_conditions_do_not_admit_anything(tmp_path) -> None:
    """A model declaring it needs 1 MiB is still not admitted."""

    content = b"weights, not a program"
    entry = an_entry(
        declared_min_ram_mib=1,
        declared_min_disk_mib=1,
        declared_profile=ResourceProfile.DIAGNOSTIC,
    )
    write_artifact(tmp_path, entry, content=content)
    reading = verify_artifact(entry, artifact_root=tmp_path)
    assert reading.state is CatalogState.PRESENT
    assert reading.admitted is False


def test_the_module_admits_nothing_and_runs_nothing() -> None:
    """It declares. Execution belongs to a separate distribution (#97)."""

    tree = ast.parse(pathlib.Path(model_catalog.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "subprocess", "socket", "ssl", "http", "urllib", "requests", "httpx", "shutil"
    } == set()
    names = {
        node.name for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any(
        name.startswith(("run", "exec", "launch", "start", "download", "fetch", "admit"))
        for name in names
    ), sorted(names)


# -- the record carries nothing it should not -----------------------------


def test_a_reading_carries_no_prompt_evidence_secret_or_key(tmp_path) -> None:
    entry = an_entry()
    write_artifact(tmp_path, entry)
    event = verify_artifact(entry, artifact_root=tmp_path).as_event()
    flattened = repr(event).lower()
    for forbidden in ("prompt", "evidence", "secret", "token", "licence text", "license text", "private"):
        assert forbidden not in flattened, forbidden


def test_an_entry_declares_no_licence_text_and_no_location() -> None:
    """Only whether acknowledgement is required, never the text itself."""

    document = an_entry().as_document()
    assert set(document) == {
        "model_id", "format", "digest", "size_bytes", "provenance",
        "license_acknowledgement_required", "runtime_abi", "purpose",
        "context_limit", "declared_min_ram_mib", "declared_min_disk_mib",
        "declared_profile", "rollback_lineage", "source_id",
    }
    assert "url" not in " ".join(document).lower()
    assert isinstance(document["license_acknowledgement_required"], bool)


@pytest.mark.parametrize(
    "source_id",
    [
        "https://example.invalid/model.gguf",
        "example.invalid",
        "mirror/eu",
        "mirror:443",
        "../mirror",
        "MIRROR",
        "",
    ],
)
def test_a_source_that_is_spelled_like_a_location_is_refused(source_id) -> None:
    """A source is named, never located.

    If a catalog could carry an endpoint, a catalog signature would become a
    way to point a node at any host on the internet, and the signer would
    hold that power over every node their catalog reaches. The symbol
    resolves against a table fixed in the build, so the most a catalog can do
    is choose among sources this build already knows.
    """

    with pytest.raises(CatalogRefused) as caught:
        an_entry(source_id=source_id)
    assert "not a source symbol" in str(caught.value)


def test_a_symbolic_source_is_carried_and_a_null_one_means_offline_only(tmp_path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    named = write_catalog(tmp_path / "a", [an_entry(source_id="vendor-mirror")])
    catalog = read_catalog(
        named, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    )
    assert catalog.entry("small-advisor").source_id == "vendor-mirror"
    silent = write_catalog(tmp_path / "b", [an_entry()])
    quiet = read_catalog(
        silent, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    )
    assert quiet.entry("small-advisor").source_id is None


def test_an_entry_missing_source_id_is_refused_rather_than_defaulted(tmp_path) -> None:
    """"No online source" is something a catalog author states, not forgets."""

    body = catalog_payload(
        version=1, commissioning_digest=COMMISSIONING, entries=[an_entry()]
    )
    document = json.loads(body)
    del document["entries"][0]["source_id"]
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    path = write_catalog(tmp_path, [], payload=payload)
    with pytest.raises(CatalogRefused) as caught:
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert "source_id" in str(caught.value)


def test_no_catalog_or_artifact_is_committed_anywhere() -> None:
    """The repository declares a contract; it does not ship models."""

    repository = pathlib.Path(__file__).resolve().parents[2]
    found = [
        str(path.relative_to(repository))
        for path in repository.rglob(CATALOG_FILENAME)
        if ".git" not in path.parts and ".venv" not in path.parts
    ]
    assert found == [], f"{found} ship a catalog"
    weights = [
        str(path.relative_to(repository))
        for extension in KNOWN_FORMATS
        for path in repository.rglob(f"*.{extension}")
        if ".git" not in path.parts and ".venv" not in path.parts
    ]
    assert weights == [], f"{weights} ship model weights"


# -- no authority ---------------------------------------------------------


def test_no_reading_moves_the_edge_answer(tmp_path) -> None:
    from azazel_nexus.edge_package import inspect as inspect_edge

    root = pathlib.Path("/nonexistent-edge-core-for-model-catalog")

    def edge_answer():
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    assert baseline == (False, "absent", False)
    entry = an_entry()
    write_artifact(tmp_path, entry)
    for acknowledged in (True, False):
        for lineage in ((), ("small-advisor",)):
            verify_artifact(
                entry,
                artifact_root=tmp_path,
                license_acknowledged=acknowledged,
                installed_lineage=lineage,
            )
            assert edge_answer() == baseline
    absent_reading()
    assert edge_answer() == baseline
