"""Reading the Knowledge Lite bundle, against what Knowledge actually emits (#67).

Every case below runs over `contract/azazel-knowledge-lite/`, which holds the
producer's own fixtures pinned by source revision and digest. **Nothing here
forges a broken bundle.** A locally forged artifact differs from a real one in
ways nobody can enumerate, and a reader that only ever sees forgeries is a
reader nobody has tested -- the producer says so, and it is the reason those
fixtures exist.

The six cases the producer publishes are all exercised: valid,
corrupt-signature, corrupt-payload, corrupt-truncated, expired, absent. For
each one, the refusal code Nexus produces is compared against the
`expected_error_code` the producer declares, so the two repositories cannot
drift into disagreeing about what a bundle is.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from azazel_nexus.lite_bundle import (
    BundleRefused,
    Gate,
    SUPPORTED_FORMATS,
    TrustAnchors,
    read_anchors,
    read_claims,
    verify_bundle,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contract" / "azazel-knowledge-lite"

#: An instant before the valid fixture's claims expire (2027-01-01Z).
FRESH = "2026-09-21T00:00:00Z"
#: An instant after them.
LATER = "2030-01-01T00:00:00Z"


@pytest.fixture(scope="module")
def anchors() -> TrustAnchors:
    return read_anchors(CONTRACT / "anchors.toml")


def _negative() -> dict:
    return json.loads((CONTRACT / "negative.json").read_text(encoding="utf-8"))


def _fixture(name: str) -> dict:
    return next(entry for entry in _negative()["fixtures"] if entry["name"] == name)


# -- the pinned contract ---------------------------------------------------


def test_the_vendored_fixtures_are_the_ones_the_source_manifest_pins() -> None:
    """Nothing here was taken on trust from one emission."""

    import hashlib

    descriptor = json.loads((CONTRACT / "FIXTURE.json").read_text(encoding="utf-8"))
    digests = descriptor["artifact_digest"]
    assert digests, "a vacuous check: the manifest pins nothing"
    for relative, expected in sorted(digests.items()):
        actual = hashlib.sha256((CONTRACT / relative).read_bytes()).hexdigest()
        assert actual == expected, f"{relative} is not the file that was pinned"


def test_the_source_manifest_names_everything_the_contract_needs() -> None:
    descriptor = json.loads((CONTRACT / "FIXTURE.json").read_text(encoding="utf-8"))
    for field in (
        "source_repository",
        "source_revision",
        "fixture_generator_command",
        "artifact_digest",
        "knowledge_contract",
        "purpose",
    ):
        assert field in descriptor, f"the source manifest does not state {field}"
    assert len(descriptor["source_revision"]) == 40


def test_the_pinned_digests_agree_with_what_the_producer_declares() -> None:
    """Two independent statements of the same bytes, compared."""

    descriptor = json.loads((CONTRACT / "FIXTURE.json").read_text(encoding="utf-8"))
    expected = json.loads((CONTRACT / "expected.json").read_text(encoding="utf-8"))
    assert descriptor["artifact_digest"]["lite.tar.gz"] == expected["bundle_sha256"]
    for entry in _negative()["fixtures"]:
        if entry["sha256"] is None:
            continue
        assert descriptor["artifact_digest"][entry["path"]] == entry["sha256"], entry["name"]


# -- the trust anchor ------------------------------------------------------


def test_the_anchor_is_read_with_tomllib_and_nothing_else() -> None:
    import ast

    module = ROOT / "src" / "azazel_nexus" / "lite_bundle.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "tomllib" in imported


def test_the_anchor_carries_the_keys_the_producer_published(anchors: TrustAnchors) -> None:
    assert anchors.threshold == 1
    assert set(anchors.keys) == {"c561fa9f"}
    assert all(len(material) == 32 for material in anchors.keys.values())


@pytest.mark.parametrize(
    "document, fragment",
    [
        ("threshold = 0\n[keys]\n\"a\" = \"" + "00" * 32 + "\"\n", "trusts anything"),
        ("threshold = 1\n", "names no verification key"),
        ("threshold = 2\n[keys]\n\"a\" = \"" + "00" * 32 + "\"\n", "exceeds"),
        ("threshold = 1\n[keys]\n\"a\" = \"zz\"\n", "not hex"),
        ("threshold = 1\n[keys]\n\"a\" = \"00\"\n", "an ed25519 key is 32"),
        ("threshold = 1\nrequired_signer_role = \"\"\n[keys]\n\"a\" = \"" + "00" * 32 + "\"\n", "non-empty string"),
        ("threshold = 1\nminimum_security_epoch = \"3\"\n[keys]\n\"a\" = \"" + "00" * 32 + "\"\n", "must be an integer"),
        ("not toml at all = = =\n", "not valid TOML"),
    ],
)
def test_a_malformed_anchor_is_refused(tmp_path, document, fragment) -> None:
    path = tmp_path / "anchors.toml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(BundleRefused) as caught:
        read_anchors(path)
    assert caught.value.gate is Gate.ANCHORS
    assert fragment in caught.value.detail


def test_an_absent_anchor_is_refused_rather_than_defaulted(tmp_path) -> None:
    with pytest.raises(BundleRefused, match="could not be read"):
        read_anchors(tmp_path / "nothing.toml")


# -- the six cases the producer publishes ----------------------------------


def test_the_valid_bundle_is_accepted_and_yields_real_claims(anchors) -> None:
    accepted = verify_bundle((CONTRACT / "lite.tar.gz").read_bytes(), anchors=anchors)
    assert accepted.signers == ("c561fa9f",)
    assert accepted.manifest["kind"] == "full"
    assert accepted.manifest["bundle_format_version"] == 1

    claims = read_claims(accepted, query_as_of=FRESH)
    assert claims.serves_a_dated_claim
    assert claims.served, "the bundle verified and produced no claim to serve"
    # A real claim, read out of the artifact rather than counted.
    assert any("agg_next_expiry" in row for row in claims.served)


def test_the_accepted_bundle_matches_the_per_file_digests_the_producer_declares(
    anchors,
) -> None:
    import hashlib

    accepted = verify_bundle((CONTRACT / "lite.tar.gz").read_bytes(), anchors=anchors)
    expected = json.loads((CONTRACT / "expected.json").read_text(encoding="utf-8"))["files"]
    assert set(accepted.members) == set(expected)
    for path, digest in expected.items():
        assert hashlib.sha256(accepted.members[path]).hexdigest() == digest


@pytest.mark.parametrize("name", ["corrupt-signature", "corrupt-payload", "corrupt-truncated"])
def test_each_broken_fixture_is_refused_at_the_code_the_producer_declares(
    anchors, name
) -> None:
    """The cross-repository tie: one word for one refusal, on both sides."""

    entry = _fixture(name)
    with pytest.raises(BundleRefused) as caught:
        verify_bundle((CONTRACT / entry["path"]).read_bytes(), anchors=anchors)
    assert caught.value.code == entry["expected_error_code"], (
        f"{name}: Nexus says {caught.value.code} and Knowledge declares "
        f"{entry['expected_error_code']}"
    )


def test_the_truncated_fixture_is_refused_although_no_known_type_was_caught(
    anchors,
) -> None:
    """The tar decoder raises before the verifier has an opinion.

    A reader that caught only a known error type would let this through as an
    unhandled error, which is why the archive gate catches everything.
    """

    entry = _fixture("corrupt-truncated")
    with pytest.raises(BundleRefused) as caught:
        verify_bundle((CONTRACT / entry["path"]).read_bytes(), anchors=anchors)
    assert caught.value.gate is Gate.ARCHIVE
    assert "any exception" in caught.value.detail.lower() or "Caught as any" in caught.value.detail


def test_the_expired_fixture_verifies_and_then_serves_no_dated_claim(anchors) -> None:
    """Expiry is not a corruption and not a gate.

    The producer's own words: a conforming reader verifies this artifact and
    then serves NO indicator from it. The static reference material in it is
    there so that withholding the expired indicators can be told apart from
    discarding the whole artifact -- so it must not make the bundle serve.
    """

    entry = _fixture("expired")
    assert entry["verifies"] is True
    accepted = verify_bundle((CONTRACT / entry["path"]).read_bytes(), anchors=anchors)

    claims = read_claims(accepted, query_as_of=FRESH)
    assert claims.served == ()
    assert claims.serves_a_dated_claim is False
    assert claims.withheld, "nothing was withheld, so nothing was evaluated"
    assert claims.timeless, (
        "the reference material is gone; withholding the expired indicators "
        "could no longer be told apart from discarding the artifact"
    )


def test_the_absent_fixture_has_no_artifact_and_that_is_not_an_error() -> None:
    entry = _fixture("absent")
    assert entry["exists"] is False
    assert not (CONTRACT / entry["path"]).exists()


def test_every_fixture_the_producer_publishes_is_exercised_here() -> None:
    """A case nobody runs is a case nobody is testing."""

    published = {entry["name"] for entry in _negative()["fixtures"]} | {"valid"}
    source = Path(__file__).read_text(encoding="utf-8")
    for name in sorted(published):
        assert name in source, f"the producer publishes {name} and nothing here runs it"
    assert len(published) == 6


# -- the available / stale distinction -------------------------------------


def test_a_valid_bundle_goes_stale_when_its_claims_expire(anchors) -> None:
    """Same artifact, two instants, two answers -- and no clock was read."""

    accepted = verify_bundle((CONTRACT / "lite.tar.gz").read_bytes(), anchors=anchors)
    assert read_claims(accepted, query_as_of=FRESH).serves_a_dated_claim is True
    assert read_claims(accepted, query_as_of=LATER).serves_a_dated_claim is False


def test_reference_material_alone_never_makes_a_bundle_serve(anchors) -> None:
    """The mistake an earlier draft of this made, kept as a test."""

    accepted = verify_bundle(
        (CONTRACT / _fixture("expired")["path"]).read_bytes(), anchors=anchors
    )
    claims = read_claims(accepted, query_as_of=FRESH)
    assert claims.timeless and not claims.served
    assert claims.serves_a_dated_claim is False


def test_an_unreadable_expiry_is_withheld_rather_than_served() -> None:
    """An expiry nobody could parse is not a licence to serve."""

    from azazel_nexus.lite_bundle import BundleAccepted

    accepted = BundleAccepted(
        manifest={"bundle_version": 1},
        members={"tables/x.jsonl": b'{"agg_next_expiry": "whenever"}\n'},
        signers=("k",),
        bundle_digest="sha256:" + "0" * 64,
    )
    claims = read_claims(accepted, query_as_of=FRESH)
    assert claims.withheld and not claims.served


# -- what the reader will not accept ---------------------------------------


def test_the_reader_supports_one_format_and_refuses_others() -> None:
    assert SUPPORTED_FORMATS == (1, 1)


def test_nothing_is_written_to_disk_while_verifying() -> None:
    """The failure `corrupt-payload` exists to catch, made impossible.

    A reader that stages before verifying can promote what it staged. This
    one holds members in memory and has no staging directory at all, so the
    scan is for the verbs that would create one.
    """

    import ast

    module = ROOT / "src" / "azazel_nexus" / "lite_bundle.py"
    tree = ast.parse(module.read_text(encoding="utf-8"))
    forbidden = {"write_text", "write_bytes", "mkdir", "extractall", "extract", "replace", "unlink"}
    offenders = [
        f"{node.func.attr}:{node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden
    ]
    assert offenders == [], f"{offenders} would put bundle bytes on disk"
    assert forbidden, "a vacuous name set would pass over any module"


# -- gates the producer publishes no fixture for ---------------------------
#
# The six cases above use the producer's own artifacts and nothing else. The
# gates below have no published fixture, so the only way to exercise them is
# to build a minimal bundle here. That is stated rather than blurred: these
# are **not** substitutes for the six, and none of them is evidence about
# what Knowledge emits. They are evidence that a gate this reader declares is
# a gate that fires.
#
# Each of them survived a mutation before it was written -- the gate could be
# removed and every test still passed -- which is what a fixture gap looks
# like from inside.

import gzip
import hashlib
import io
import tarfile

from signing_oracle import public_key_for, sign_detached

SEED = bytes(range(32))
KEY_ID = "testonly"


def _tar(members: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name in members:
                info = tarfile.TarInfo(name=name)
                info.size = len(members[name])
                info.mtime = 0
                archive.addfile(info, io.BytesIO(members[name]))
    return raw.getvalue()


def _signed(manifest: dict, tables: dict[str, bytes] | None = None) -> bytes:
    tables = tables or {}
    manifest = {
        **manifest,
        "files": {
            path: hashlib.sha256(body).hexdigest() for path, body in sorted(tables.items())
        },
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    signature = sign_detached(seed=SEED, message=manifest_bytes)
    members = {
        "manifest.json": manifest_bytes,
        "manifest.sig": f"{KEY_ID}:{signature.hex()}\n".encode("utf-8"),
        **tables,
    }
    return _tar(members)


def _local_anchors(**overrides) -> TrustAnchors:
    fields = {
        "threshold": 1,
        "keys": {KEY_ID: public_key_for(SEED)},
        "revoked": frozenset(),
        "key_roles": {},
    }
    fields.update(overrides)
    return TrustAnchors(**fields)


def _manifest(**overrides) -> dict:
    document = {"bundle_format_version": 1, "bundle_version": 7, "kind": "full"}
    document.update(overrides)
    return document


def test_a_constructed_valid_bundle_is_accepted() -> None:
    """The control. Without it the refusals below could all be one bug."""

    accepted = verify_bundle(
        _signed(_manifest(), {"tables/a.jsonl": b"{}\n"}), anchors=_local_anchors()
    )
    assert accepted.signers == (KEY_ID,)


def test_an_undeclared_member_is_refused() -> None:
    """An unsigned member is not covered by the signature over the manifest."""

    manifest = _manifest()
    manifest_bytes = json.dumps(
        {**manifest, "files": {"tables/a.jsonl": hashlib.sha256(b"{}\n").hexdigest()}},
        indent=2,
        sort_keys=True,
    ).encode("utf-8")
    raw = _tar(
        {
            "manifest.json": manifest_bytes,
            "manifest.sig": f"{KEY_ID}:{sign_detached(seed=SEED, message=manifest_bytes).hex()}\n".encode(),
            "tables/a.jsonl": b"{}\n",
            "tables/smuggled.jsonl": b'{"anything": true}\n',
        }
    )
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(raw, anchors=_local_anchors())
    assert caught.value.code == "BUNDLE_UNDECLARED_MEMBER"


@pytest.mark.parametrize(
    "field",
    ["threshold", "keys", "required_signer_role", "minimum_security_epoch", "revoked"],
)
def test_a_manifest_that_speaks_about_trust_is_refused(field: str) -> None:
    """A bundle does not get to say what this node will accept."""

    raw = _signed(_manifest(**{field: "whatever"}), {"tables/a.jsonl": b"{}\n"})
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(raw, anchors=_local_anchors())
    assert caught.value.code == "BUNDLE_SHADOWS_TRUST_ANCHOR"
    assert field in caught.value.detail


@pytest.mark.parametrize("declared", [0, 2, 99, "1", True])
def test_a_format_outside_the_supported_range_is_refused(declared) -> None:
    """An incompatible artifact is refused for being incompatible.

    Not misread. A reader that accepted whatever arrived would have no way to
    say that a future format is one it cannot read.
    """

    raw = _signed(_manifest(bundle_format_version=declared), {"tables/a.jsonl": b"{}\n"})
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(raw, anchors=_local_anchors())
    assert caught.value.gate is Gate.FORMAT
    assert caught.value.code in ("BUNDLE_FORMAT_UNSUPPORTED", "BUNDLE_FORMAT_INVALID")


def test_a_delta_bundle_is_refused_because_lite_is_full_only() -> None:
    raw = _signed(_manifest(kind="delta"), {"tables/a.jsonl": b"{}\n"})
    with pytest.raises(BundleRefused, match="full-only"):
        verify_bundle(raw, anchors=_local_anchors())


def test_a_revoked_signer_is_refused_on_the_producers_own_bundle(anchors) -> None:
    """Revocation is this node's decision, so the real artifact can carry it.

    The anchor is ours to change; the bundle is not. Refusing the producer's
    valid bundle under an anchor that revokes its key is the whole of what
    revocation means.
    """

    revoked = TrustAnchors(
        threshold=anchors.threshold,
        keys=dict(anchors.keys),
        revoked=frozenset(anchors.keys),
    )
    with pytest.raises(BundleRefused) as caught:
        verify_bundle((CONTRACT / "lite.tar.gz").read_bytes(), anchors=revoked)
    assert caught.value.code == "BUNDLE_REVOKED_SIGNER"


def test_a_signer_without_the_required_role_is_refused() -> None:
    raw = _signed(_manifest(), {"tables/a.jsonl": b"{}\n"})
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(
            raw,
            anchors=_local_anchors(
                required_signer_role="release", key_roles={KEY_ID: "staging"}
            ),
        )
    assert caught.value.code == "BUNDLE_SIGNER_ROLE_NOT_PERMITTED"


@pytest.mark.parametrize(
    "declared, code",
    [
        (None, "BUNDLE_SECURITY_EPOCH_MISSING"),
        ("3", "BUNDLE_SECURITY_EPOCH_INVALID"),
        (2, "BUNDLE_SECURITY_EPOCH_TOO_LOW"),
    ],
)
def test_the_security_epoch_gate_fires_on_its_own(declared, code) -> None:
    """A correctly signed artifact from before a security event is still from before it."""

    overrides = {} if declared is None else {"security_epoch": declared}
    raw = _signed(_manifest(**overrides), {"tables/a.jsonl": b"{}\n"})
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(raw, anchors=_local_anchors(minimum_security_epoch=3))
    assert caught.value.code == code


@pytest.mark.parametrize(
    "policy, code",
    [(None, "BUNDLE_EXPORT_POLICY_MISSING"), ("other", "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED")],
)
def test_the_export_policy_gate_fires_on_its_own(policy, code) -> None:
    """Whether this node tolerates the privacy policy it was built under."""

    profile = {} if policy is None else {"selection_inputs": {"export_policy_digest": policy}}
    raw = _signed(_manifest(profile=profile), {"tables/a.jsonl": b"{}\n"})
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(
            raw, anchors=_local_anchors(accepted_export_policy_digests=frozenset({"mine"}))
        )
    assert caught.value.code == code


def test_an_accepted_policy_digest_passes() -> None:
    """Otherwise the two refusals above could be one unconditional failure."""

    raw = _signed(
        _manifest(profile={"selection_inputs": {"export_policy_digest": "mine"}}),
        {"tables/a.jsonl": b"{}\n"},
    )
    accepted = verify_bundle(
        raw, anchors=_local_anchors(accepted_export_policy_digests=frozenset({"mine"}))
    )
    assert accepted.export_policy_digest == "mine"


@pytest.mark.parametrize("watermark, ok", [(6, True), (7, False), (8, False)])
def test_anti_rollback_compares_against_the_watermark_this_node_holds(watermark, ok) -> None:
    """A correctly signed older artifact is still an older artifact."""

    raw = _signed(_manifest(bundle_version=7), {"tables/a.jsonl": b"{}\n"})
    if ok:
        assert verify_bundle(raw, anchors=_local_anchors(), last_imported_version=watermark)
    else:
        with pytest.raises(BundleRefused) as caught:
            verify_bundle(raw, anchors=_local_anchors(), last_imported_version=watermark)
        assert caught.value.code == "BUNDLE_VERSION_REGRESSION"


def test_an_archive_that_is_not_gzip_at_all_is_refused() -> None:
    """The catch-all, exercised by something that is not a `tarfile.ReadError`.

    A mutation narrowing the archive gate to `tarfile.ReadError` survived the
    producer's fixtures, because its truncated bundle happens to raise exactly
    that. This is the case that makes the catch-all load-bearing.
    """

    with pytest.raises(BundleRefused) as caught:
        verify_bundle(b"this is not a gzip stream at all", anchors=_local_anchors())
    assert caught.value.gate is Gate.ARCHIVE
    assert caught.value.code == "BUNDLE_ARCHIVE_UNREADABLE"


def test_a_bundle_larger_than_the_ceiling_is_refused_before_it_is_decoded() -> None:
    from azazel_nexus.lite_bundle import MAX_BUNDLE_BYTES

    with pytest.raises(BundleRefused) as caught:
        verify_bundle(b"\0" * (MAX_BUNDLE_BYTES + 1), anchors=_local_anchors())
    assert caught.value.code == "BUNDLE_TOO_LARGE"


def test_a_declared_member_that_is_absent_is_refused_and_not_a_crash() -> None:
    """Survived a mutation, and the mutation exposed how it would fail.

    With the missing-member check removed the digest loop reaches
    `members[path]` for a file that is not there and raises `KeyError` --
    which is not a `BundleRefused` and would leave the caller with an
    unhandled exception instead of a refusal. The check is what turns that
    into an answer.
    """

    manifest = {
        "bundle_format_version": 1,
        "bundle_version": 7,
        "kind": "full",
        "files": {"tables/promised.jsonl": hashlib.sha256(b"{}\n").hexdigest()},
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    raw = _tar(
        {
            "manifest.json": manifest_bytes,
            "manifest.sig": f"{KEY_ID}:{sign_detached(seed=SEED, message=manifest_bytes).hex()}\n".encode(),
        }
    )
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(raw, anchors=_local_anchors())
    assert caught.value.code == "BUNDLE_FILE_MISSING"
    assert "tables/promised.jsonl" in caught.value.detail


def test_a_gzip_stream_that_fails_mid_decompression_is_refused() -> None:
    """The case that makes the archive catch-all load-bearing.

    Narrowing the gate to `tarfile.ReadError` survives both the producer's
    truncated fixture and a run of plain garbage, because `tarfile` raises
    `ReadError` for each. Cutting a **valid** gzip stream part-way fails
    inside the decompressor instead, with an exception the tar layer never
    turns into its own -- and a reader that caught only the known type would
    let it out as an unhandled error.
    """

    intact = (CONTRACT / "lite.tar.gz").read_bytes()
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(intact[: len(intact) // 2], anchors=_local_anchors())
    assert caught.value.gate is Gate.ARCHIVE
    assert caught.value.code == "BUNDLE_ARCHIVE_UNREADABLE"
