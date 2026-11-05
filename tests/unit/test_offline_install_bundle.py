"""The offline install bundle: manifest, safe extraction, slots, offline install.

Everything here is a unit test over synthetic inputs (mock wheels, a fake Edge
package, a hand-built .deb). The pip test starts a real pip in a real venv with
``--no-index``; it is process evidence about pip's hash enforcement, not about
the target platform. The container proof is recorded separately under
docs/evidence/.
"""

from __future__ import annotations

import base64
import copy
import csv
import gzip
import hashlib
import io
import json
import lzma
import os
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from tests.unit.test_offline_bundle import _repo
from tools import build_wheelhouse, offline_bundle
from tools.build_offline_bundle import _inputs, build_install_bundle, repository_identity
from tools.offline_bundle import BundleRefused, Limits, extract_bundle, verify_extracted

ROOT = Path(__file__).resolve().parents[2]
TARGET = offline_bundle.TARGETS[build_wheelhouse.TARGET]


# -- fixtures ---------------------------------------------------------------


def _wheel(directory: Path, distribution: str, version: str, module: str) -> Path:
    """A minimal valid pure wheel that pip can install with no index."""

    stem = distribution.replace("-", "_")
    name = f"{stem}-{version}-py3-none-any.whl"
    dist_info = f"{stem}-{version}.dist-info"
    files = {
        f"{module}/__init__.py": f"MARKER = {distribution!r}\n".encode(),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {distribution}\nVersion: {version}\n"
        ).encode(),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([path, f"sha256={digest}", len(data)])
    writer.writerow([f"{dist_info}/RECORD", "", ""])
    files[f"{dist_info}/RECORD"] = record.getvalue().encode()
    path = directory / name
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in files.items():
            info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
            archive.writestr(info, data)
    return path


def _wheelhouse(directory: Path, commit: str, third_party: tuple[tuple[str, str], ...] = ()) -> Path:
    """The two Nexus wheels, plus fake third-party wheels when asked for.

    The fake third-party wheels cannot carry the hashes the real lock pins, so
    a bundle with them is refused by the reviewed-lock check unless a test
    supplies its own pins.
    """

    directory.mkdir()
    wheels = [
        (_wheel(directory, "azazel-nexus", "0.0.1.dev0", "fake_azazel_nexus"), "built:test"),
        (_wheel(directory, "azazel-nexus-runtime", "0.0.1.dev0", "fake_azazel_runtime"), "built:test"),
    ] + [
        (_wheel(directory, name, version, "fake_" + name.replace("-", "_")), "pypi:test")
        for name, version in third_party
    ]
    record = {
        "schema": build_wheelhouse.WHEELHOUSE_SCHEMA,
        "target": build_wheelhouse.TARGET,
        "repository_identity": {"commit": commit},
        "wheels": [
            {
                "file": path.name,
                "requirement": offline_bundle.canonical_name(path.name.split("-")[0])
                + "==" + path.name.split("-")[1],
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
                "source": source,
            }
            for path, source in wheels
        ],
    }
    (directory / "wheelhouse.json").write_text(json.dumps(record), encoding="utf-8")
    return directory


def _edge_package(directory: Path, *, observe_only: bool = True, cpu: str = "x86_64",
                  binary_cpu: str | None = None) -> Path:
    """An Edge package named and described for ``cpu`` (the baseline's by default),
    whose binary is an ELF header of ``binary_cpu`` (``cpu`` unless given)."""

    from azazel_nexus.edge_package import PINS
    from _edge_package_fixture import elf_stub

    PIN = PINS[cpu]
    directory.mkdir()
    components = {
        "bin/azazel-edge-core": elf_stub(binary_cpu or cpu),
        "config/redirect_policy.yaml": b"redirect: []\n",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in components.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    artifact = buffer.getvalue()
    (directory / PIN.artifact_name).write_bytes(artifact)
    manifest = {
        "contract": PIN.manifest_contract,
        "package": PIN.package,
        "version": PIN.version,
        "architecture": PIN.architecture,
        "artifact": PIN.artifact_name,
        "digest": "sha256:" + hashlib.sha256(artifact).hexdigest(),
        "signed": False,
        "health": {"contract": PIN.health_contract},
        "posture": {"observe_only": observe_only, "enforcement": not observe_only},
        "components": [
            {"path": name, "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}
            for name, data in components.items()
        ],
    }
    (directory / PIN.manifest_name).write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def _pin_edge(monkeypatch, edge: Path, cpu: str = "x86_64") -> None:
    """Stand in for an owner-reviewed pin of whatever artifact is in ``edge`` when checked."""

    from azazel_nexus.edge_package import PINS

    PIN = PINS[cpu]
    monkeypatch.setattr(offline_bundle, "reviewed_edge_digest", lambda root=None, target=None: (
        hashlib.sha256((edge / PIN.artifact_name).read_bytes()).hexdigest(), PIN.artifact_name))


def _deb(path: Path, *, package: str = "iproute2", version: str = "6.15.0-1",
         architecture: str = "amd64") -> Path:
    control = (
        f"Package: {package}\nVersion: {version}\nArchitecture: {architecture}\n"
        "Description: test\n multi-line\n"
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("./control")
        info.size = len(control)
        archive.addfile(info, io.BytesIO(control))
    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.xz", lzma.compress(buffer.getvalue())),
        ("data.tar.xz", lzma.compress(b"")),
    ]
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}".encode() + b"`\n"
        out += data + (b"\n" if len(data) % 2 else b"")
    path.write_bytes(bytes(out))
    return path


@pytest.fixture
def empty_third_party_lock(monkeypatch):
    """Default reviewed pins: the real Nexus versions and no third-party entry.

    The real lock pins wheels the fake bundles cannot reproduce, and
    ``verify`` refuses a bundle that lacks a locked wheel (ADR-0004). An
    explicit root still reads that root, as before.
    """

    real = offline_bundle.reviewed_pins

    def pins(root: Path | None = None, target: str = offline_bundle.BASELINE_TARGET):
        if root is not None:
            return real(root, target)
        return {}, real(target=target)[1]

    monkeypatch.setattr(offline_bundle, "reviewed_pins", pins)


@pytest.fixture
def built(tmp_path: Path, empty_third_party_lock):
    """A bundle of the two fake Nexus wheels."""

    root = _repo(tmp_path / "repo")
    commit = repository_identity(root)["commit"]
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", commit)
    output = tmp_path / "bundle.tar.gz"
    document = build_install_bundle(root, output, wheelhouse=wheelhouse)
    return root, wheelhouse, output, document


def _members(bundle: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    with tarfile.open(bundle, "r:gz") as archive:
        result = []
        for info in archive.getmembers():
            stream = archive.extractfile(info) if info.isreg() else None
            result.append((copy.copy(info), stream.read() if stream else None))
        return result


def _write(path: Path, members: list[tuple[tarfile.TarInfo, bytes | None]]) -> Path:
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for info, data in members:
            if data is not None:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)
    return path


def _with_manifest(members, document: dict):
    data = offline_bundle.manifest_bytes(document)
    info = copy.copy(members[0][0])
    return [(info, data)] + members[1:]


def _refused(tmp_path: Path, bundle: Path, match: str, **limits) -> None:
    destination = tmp_path / "out"
    with pytest.raises(BundleRefused, match=match):
        extract_bundle(bundle, destination, limits=Limits().tighter(**limits) if limits else Limits())
    assert not destination.exists()
    leftovers = [p.name for p in tmp_path.iterdir() if ".staging-" in p.name]
    assert leftovers == [], "a refused extraction left its staging directory behind"


# -- manifest round trip ------------------------------------------------------


def test_manifest_round_trip_lists_every_member_with_hash_size_kind_source(built, tmp_path):
    root, _wheelhouse_dir, bundle, document = built
    members = _members(bundle)
    assert members[0][0].name == offline_bundle.MANIFEST_NAME
    assert json.loads(members[0][1]) == document
    assert [info.name for info, _ in members[1:]] == [e["path"] for e in document["artifacts"]]
    for (info, data), entry in zip(members[1:], document["artifacts"]):
        assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        assert entry["size"] == len(data) == info.size
        assert entry["kind"] in offline_bundle.KIND_PREFIX and entry["source"]
    source_paths = {e["path"] for e in document["artifacts"] if e["kind"] == "source"}
    assert source_paths == {"source/" + name for _, name in _inputs(root)}
    assert document["slots"] == {k: "empty" for k in offline_bundle.SLOT_KINDS}

    extracted = extract_bundle(bundle, tmp_path / "out")
    assert extracted.manifest == document
    for entry in document["artifacts"]:
        on_disk = (tmp_path / "out" / entry["path"]).read_bytes()
        assert hashlib.sha256(on_disk).hexdigest() == entry["sha256"]
        assert oct((tmp_path / "out" / entry["path"]).stat().st_mode & 0o777) == "0o" + entry["mode"][1:]
    report = verify_extracted(extracted)
    assert report["bundle_authenticated"] is False
    assert report["signature"]["present"] is False
    assert report["counts"]["wheel"] == 2
    assert {w["pinned_by"] for w in report["wheels"]} == {"reviewed pyproject version only"}


def test_the_same_inputs_make_identical_bundle_bytes(built, tmp_path):
    root, wheelhouse, bundle, _ = built
    assert bundle.stat().st_mode & 0o777 == 0o644
    again = build_install_bundle(root, tmp_path / "again.tar.gz", wheelhouse=wheelhouse)
    assert (tmp_path / "again.tar.gz").read_bytes() == bundle.read_bytes()
    assert again == json.loads(_members(bundle)[0][1])


def test_wheel_requirements_pin_every_bundled_wheel_by_hash(built):
    document = built[3]
    lines = offline_bundle.wheel_requirements(document).splitlines()
    wheels = [e for e in document["artifacts"] if e["kind"] == "wheel"]
    assert lines == [f"{e['requirement']} --hash=sha256:{e['sha256']}" for e in wheels]


def test_a_wheelhouse_from_another_commit_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", "0" * 40)
    with pytest.raises(ValueError, match="different commit"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse)


def test_a_wheelhouse_file_that_changed_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    victim = next(wheelhouse.glob("azazel_nexus_runtime*.whl"))
    victim.write_bytes(victim.read_bytes() + b"x")
    with pytest.raises(ValueError, match="does not match wheelhouse.json"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse)


def test_the_real_source_selection_carries_the_offline_verifier():
    names = {name for _, name in _inputs(ROOT)}
    assert "tools/offline_bundle.py" in names
    assert "packaging/install.sh" in names


# -- manifest validation ------------------------------------------------------


def _valid(built) -> dict:
    return copy.deepcopy(built[3])


@pytest.mark.parametrize(
    "mutate, match",
    [
        (lambda d: d.update(schema="other@1"), "schema"),
        (lambda d: d.update(target="debian-13-riscv64-cp313"), "not a declared target"),
        (lambda d: d.update(extra=1), "unexpected"),
        (lambda d: d["artifacts"][0].update(kind="firmware"), "kind"),
        (lambda d: d["artifacts"][0].update(path="wheels/x.py"), "not under"),
        (lambda d: d["artifacts"][0].update(sha256="ab"), "sha256"),
        (lambda d: d["artifacts"][0].update(mode="4755"), "mode"),
        (lambda d: d["artifacts"][0].update(source=""), "source"),
        (lambda d: d["slots"].update(deb="filled"), "slot deb"),
        (lambda d: d["totals"].update(bytes=1), "totals"),
        (lambda d: d["artifacts"].reverse(), "path order|totals"),
    ],
)
def test_malformed_manifests_are_refused(built, mutate, match):
    document = _valid(built)
    mutate(document)
    with pytest.raises(BundleRefused, match=match):
        offline_bundle.validate_manifest(document)


def _wheel_entry(document: dict) -> dict:
    return next(e for e in document["artifacts"] if e["kind"] == "wheel")


@pytest.mark.parametrize(
    "filename, fits",
    [
        ("pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl", True),
        ("azazel_nexus_runtime-0.0.1.dev0-cp313-cp313-linux_x86_64.whl", True),
        ("dbus_next-0.2.3-py3-none-any.whl", True),
        ("pyyaml-6.0.3-cp313-cp313-manylinux2014_aarch64.manylinux_2_17_aarch64.whl", False),
        ("pyyaml-6.0.3-cp312-cp312-manylinux_2_17_x86_64.whl", False),
        ("pyyaml-6.0.3-cp313-cp313-macosx_11_0_arm64.whl", False),
        ("pyyaml-6.0.3-cp313-cp313-musllinux_1_2_x86_64.whl", False),
        ("x-1.0-cp313-cp313-manylinux_2_42_x86_64.whl", False),
    ],
)
def test_wheels_must_fit_the_declared_target(filename, fits):
    assert offline_bundle.wheel_fits_target(filename, TARGET) is fits


def test_a_wheel_that_does_not_carry_its_requirement_is_refused(built):
    document = _valid(built)
    _wheel_entry(document)["requirement"] = "pyyaml==6.0.3"
    with pytest.raises(BundleRefused, match="does not carry"):
        offline_bundle.validate_manifest(document)


def test_a_bundle_without_both_nexus_wheels_is_refused(built):
    document = _valid(built)
    document["artifacts"] = [
        e for e in document["artifacts"] if not e["path"].startswith("wheels/azazel_nexus_runtime")
    ]
    document["totals"] = {"count": len(document["artifacts"]),
                          "bytes": sum(e["size"] for e in document["artifacts"])}
    with pytest.raises(BundleRefused, match="azazel-nexus-runtime"):
        offline_bundle.validate_manifest(document)


def test_limits_can_be_lowered_but_never_raised():
    assert Limits().tighter(max_members=10).max_members == 10
    with pytest.raises(BundleRefused, match="never raised"):
        Limits().tighter(max_total_bytes=Limits().max_total_bytes + 1)


# -- safe extraction refusals -------------------------------------------------


def _extra(name: str, kind: bytes = tarfile.REGTYPE, data: bytes | None = b"x", linkname: str = ""):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info, data if kind == tarfile.REGTYPE else None


@pytest.mark.parametrize(
    "member, match",
    [
        (_extra("/etc/cron.d/evil"), "absolute"),
        (_extra("source/../../evil"), r"'\.\.'"),
        (_extra("source/evil", tarfile.SYMTYPE, linkname="/etc/passwd"), "symlink"),
        (_extra("source/evil", tarfile.SYMTYPE, linkname="../../../etc/passwd"), "symlink"),
        (_extra("source/evil", tarfile.LNKTYPE, linkname="../../etc/shadow"), "hardlink"),
        (_extra("source/evil", tarfile.CHRTYPE), "device"),
        (_extra("source/evil", tarfile.BLKTYPE), "device"),
        (_extra("source/evil", tarfile.FIFOTYPE), "FIFO"),
        (_extra("source/evil", tarfile.DIRTYPE), "directory"),
        (_extra("source/undeclared.py"), "not declared"),
    ],
)
def test_unsafe_or_undeclared_members_are_refused(built, tmp_path, member, match):
    members = _members(built[2])
    members.insert(3, member)
    _refused(tmp_path, _write(tmp_path / "evil.tar.gz", members), match)


def test_a_declared_path_written_as_a_link_is_refused(built, tmp_path):
    members = _members(built[2])
    info, _ = members[2]
    link = copy.copy(info)
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    members[2] = (link, None)
    _refused(tmp_path, _write(tmp_path / "evil.tar.gz", members), "symlink")


def test_a_missing_declared_member_is_refused(built, tmp_path):
    members = _members(built[2])
    del members[5]
    _refused(tmp_path, _write(tmp_path / "short.tar.gz", members), "missing")


def test_a_duplicated_member_is_refused(built, tmp_path):
    members = _members(built[2])
    members.insert(3, members[2])
    _refused(tmp_path, _write(tmp_path / "dup.tar.gz", members), "twice")


def test_a_hash_mismatch_of_the_same_size_is_refused(built, tmp_path):
    members = _members(built[2])
    info, data = members[4]
    flipped = bytes([data[0] ^ 1]) + data[1:]
    members[4] = (info, flipped)
    _refused(tmp_path, _write(tmp_path / "tampered.tar.gz", members), "sha256")


def test_a_size_mismatch_is_refused(built, tmp_path):
    members = _members(built[2])
    info, data = members[4]
    members[4] = (info, data + b"\n")
    _refused(tmp_path, _write(tmp_path / "grown.tar.gz", members), "bytes; the manifest declares")


def test_a_rewritten_manifest_hash_is_still_a_mismatch_for_the_unchanged_file(built, tmp_path):
    document = _valid(built)
    document["artifacts"][1]["sha256"] = "0" * 64
    members = _with_manifest(_members(built[2]), document)
    _refused(tmp_path, _write(tmp_path / "rehashed.tar.gz", members), "sha256")


def test_the_manifest_must_come_first(built, tmp_path):
    members = _members(built[2])
    members[0], members[1] = members[1], members[0]
    _refused(tmp_path, _write(tmp_path / "late.tar.gz", members), "first member")


def test_member_count_above_the_cap_is_refused(built, tmp_path):
    count = len(built[3]["artifacts"])
    _refused(tmp_path, built[2], "cap", max_members=count - 1)


def test_total_size_above_the_cap_is_refused(built, tmp_path):
    total = built[3]["totals"]["bytes"]
    _refused(tmp_path, built[2], "cap", max_total_bytes=total - 1)


def test_an_existing_destination_is_never_merged_into(built, tmp_path):
    destination = tmp_path / "out"
    destination.mkdir()
    with pytest.raises(BundleRefused, match="already exists"):
        extract_bundle(built[2], destination)
    assert list(destination.iterdir()) == []


def test_a_refusal_late_in_the_stream_leaves_no_partial_tree(built, tmp_path):
    members = _members(built[2])
    info, data = members[-1]
    members[-1] = (info, bytes([data[0] ^ 1]) + data[1:])
    bundle = _write(tmp_path / "late-tamper.tar.gz", members)
    _refused(tmp_path, bundle, "sha256")


def test_a_corrupt_archive_is_refused(built, tmp_path):
    data = built[2].read_bytes()
    corrupt = tmp_path / "corrupt.tar.gz"
    corrupt.write_bytes(data[: len(data) // 2])
    _refused(tmp_path, corrupt, "could not be read|missing|truncated|ends inside")


# -- the signing hook ---------------------------------------------------------


def test_a_present_signature_is_carried_but_authenticates_nothing(built, tmp_path):
    members = _members(built[2])
    signature = tarfile.TarInfo(offline_bundle.SIGNATURE_NAME)
    members.insert(1, (signature, b"not a real signature"))
    extracted = extract_bundle(_write(tmp_path / "signed.tar.gz", members), tmp_path / "out")
    assert extracted.signature == b"not a real signature"
    report = verify_extracted(extracted)
    assert report["bundle_authenticated"] is False
    assert report["signature"]["present"] is True
    assert "not checked" in report["signature"]["reason"]


def test_a_signature_after_payload_members_is_refused(built, tmp_path):
    members = _members(built[2])
    members.insert(3, (tarfile.TarInfo(offline_bundle.SIGNATURE_NAME), b"sig"))
    _refused(tmp_path, _write(tmp_path / "late-sig.tar.gz", members), "misplaced")


def test_the_hook_never_authenticates_today():
    for signature in (None, b"", b"x" * 64):
        verdict = offline_bundle.verify_bundle_signature(b"{}", signature)
        assert verdict.authenticated is False


# -- slots ------------------------------------------------------------------


def test_an_edge_package_slot_is_verified_with_the_edge_checks(tmp_path, monkeypatch, empty_third_party_lock):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    edge = _edge_package(tmp_path / "edge-in")
    _pin_edge(monkeypatch, edge)
    document = build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                                    edge_package=edge, edge_source="test fixture")
    assert document["slots"]["edge-package"] == "filled"
    report = verify_extracted(extract_bundle(tmp_path / "b.tar.gz", tmp_path / "out"))
    edge_report = report["slots"]["edge-package"]
    assert edge_report["admitted"] is False
    assert edge_report["checks"]["digest_matches"] == "passed"
    assert edge_report["checks"]["health_endpoint_healthy"] == "not-checked"
    assert "not authenticity" in edge_report["caveat"]
    assert report["bundle_authenticated"] is False


def test_an_edge_slot_needs_a_named_source(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    with pytest.raises(ValueError, match="edge-source"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                             edge_package=_edge_package(tmp_path / "edge-in"))


def test_an_enforcing_edge_package_is_refused(tmp_path, monkeypatch):
    edge = _edge_package(tmp_path / "edge", observe_only=False)
    _pin_edge(monkeypatch, edge)
    with pytest.raises(BundleRefused, match="package_present"):
        offline_bundle.verify_edge_slot(edge)


def test_an_edge_artifact_that_does_not_match_its_manifest_is_refused(tmp_path, monkeypatch):
    from azazel_nexus.edge_package import PINS

    PIN = PINS["x86_64"]
    edge = _edge_package(tmp_path / "edge")
    other = _edge_package(tmp_path / "other", binary_cpu="x86_64", observe_only=True)
    # A well-formed archive of the same CPU, just not the one the manifest describes.
    data = bytearray((other / PIN.artifact_name).read_bytes())
    import gzip as _gzip
    raw = bytearray(_gzip.decompress(bytes(data)))
    raw[raw.index(b"synthetic")] ^= 0x20
    (edge / PIN.artifact_name).write_bytes(_gzip.compress(bytes(raw), mtime=0))
    _pin_edge(monkeypatch, edge)
    with pytest.raises(BundleRefused, match="digest_matches"):
        offline_bundle.verify_edge_slot(edge)


def test_an_edge_slot_with_an_extra_file_is_refused(tmp_path):
    edge = _edge_package(tmp_path / "edge")
    (edge / "extra.sh").write_bytes(b"#!/bin/sh\n")
    with pytest.raises(BundleRefused, match="exactly"):
        offline_bundle.verify_edge_slot(edge)


def test_deb_slot_records_and_rechecks_control_fields(tmp_path, empty_third_party_lock):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    debs = tmp_path / "debs"
    debs.mkdir()
    _deb(debs / "iproute2_6.15.0-1_amd64.deb")
    # apt writes an epoch as %3a in the file name.
    _deb(debs / "suricata_1%3a7.0.10-1+deb13u4_amd64.deb", package="suricata",
         version="1:7.0.10-1+deb13u4")
    document = build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                                    debs=debs, deb_source="test snapshot")
    entries = [e for e in document["artifacts"] if e["kind"] == "deb"]
    assert [(e["package"], e["version"], e["architecture"]) for e in entries] == [
        ("iproute2", "6.15.0-1", "amd64"), ("suricata", "1:7.0.10-1+deb13u4", "amd64")]
    report = verify_extracted(extract_bundle(tmp_path / "b.tar.gz", tmp_path / "out"))
    assert report["slots"]["deb"]["installed"] is False
    assert [p["package"] for p in report["slots"]["deb"]["packages"]] == ["iproute2", "suricata"]


def test_a_deb_whose_control_disagrees_with_the_manifest_is_refused(tmp_path):
    _deb(tmp_path / "x.deb", version="6.15.0-2")
    document = {"artifacts": [{"kind": "deb", "path": "x.deb", "package": "iproute2",
                               "version": "6.15.0-1", "architecture": "amd64", "source": "s"}]}
    with pytest.raises(BundleRefused, match="control says"):
        offline_bundle.verify_deb_slot(tmp_path, document)


@pytest.mark.parametrize("payload, match", [
    (b"not an ar archive", "not an ar archive"),
    (b"!<arch>\n" + b"x" * 10, "malformed ar header"),
])
def test_a_file_that_is_not_a_deb_is_refused(tmp_path, payload, match):
    (tmp_path / "x.deb").write_bytes(payload)
    with pytest.raises(BundleRefused, match=match):
        offline_bundle.deb_control_fields(tmp_path / "x.deb")


def test_a_foreign_architecture_deb_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    debs = tmp_path / "debs"
    debs.mkdir()
    _deb(debs / "iproute2_6.15.0-1_arm64.deb", architecture="arm64")
    with pytest.raises(BundleRefused, match="arm64"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                             debs=debs, deb_source="test snapshot")


def test_model_and_knowledge_slots_are_carried_not_admitted(tmp_path, empty_third_party_lock):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF fake")
    knowledge = tmp_path / "lite.tar"
    knowledge.write_bytes(b"knowledge fake")
    build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                         models=[model], knowledge=[knowledge], assets_source="test fixture")
    report = verify_extracted(extract_bundle(tmp_path / "b.tar.gz", tmp_path / "out"))
    assert report["slots"]["model"] == {"state": "carried", "files": ["assets/models/model.gguf"],
                                        "admitted": False}
    assert report["slots"]["knowledge"]["admitted"] is False


# -- the lock files -----------------------------------------------------------


def test_the_wheel_lock_pins_exactly_what_the_pyproject_files_declare():
    lock = build_wheelhouse.parse_lock(ROOT / build_wheelhouse.LOCK)
    assert set(lock) == build_wheelhouse.bundled_requirements(ROOT)
    assert build_wheelhouse.declared_runtime_dependencies(ROOT) < set(lock)
    assert all(len(hashes) == 1 for hashes in lock.values())


def test_each_locked_wheel_named_in_the_lock_fits_the_target():
    text = (ROOT / build_wheelhouse.LOCK).read_text(encoding="utf-8")
    named = [line.strip("# \n") for line in text.splitlines() if line.strip().endswith(".whl")]
    assert len(named) == 9
    for filename in named:
        assert offline_bundle.wheel_fits_target(filename, TARGET), filename


def test_the_build_backend_lock_satisfies_the_declared_build_requirement():
    lock = build_wheelhouse.parse_lock(ROOT / build_wheelhouse.BACKEND_LOCK)
    (pin,) = lock
    name, _, version = pin.partition("==")
    assert name == "setuptools" and int(version.split(".")[0]) >= 68


@pytest.mark.parametrize("text, match", [
    ("PyYAML>=6.0\n", "exact pin"),
    ("PyYAML==6.0.3\n", "exact pin"),
    ("PyYAML==6.0.3 --hash=md5:abc\n", "sha256"),
    ("a==1 --hash=sha256:" + "0" * 64 + "\na==2 --hash=sha256:" + "1" * 64 + "\n", "twice"),
])
def test_a_loose_lock_is_refused(tmp_path, text, match):
    (tmp_path / "x.lock").write_text(text)
    with pytest.raises(ValueError, match=match):
        build_wheelhouse.parse_lock(tmp_path / "x.lock")


def test_the_wheelhouse_builder_refuses_a_host_that_is_not_the_target(tmp_path, monkeypatch):
    monkeypatch.setitem(offline_bundle.TARGETS[build_wheelhouse.TARGET], "python_version", (2, 7))
    with pytest.raises(ValueError, match="must be built on"):
        build_wheelhouse.build_wheelhouse(ROOT, tmp_path / "wh")
    assert not (tmp_path / "wh").exists()


# -- the hash-pinned, no-index install ----------------------------------------


@pytest.fixture
def venv_python(tmp_path) -> Path:
    """A fresh venv per test: pip skips hash checks for what is already installed."""

    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, capture_output=True)
    return venv / "bin" / "python"


@pytest.mark.real_process
def test_pip_installs_only_the_bundled_wheels_with_every_hash_required(built, tmp_path, venv_python):
    extracted = extract_bundle(built[2], tmp_path / "out")
    requirements = tmp_path / "req.txt"
    requirements.write_text(offline_bundle.wheel_requirements(extracted.manifest))
    offline_bundle.pip_install_offline(venv_python, extracted.root / "wheels", requirements)
    result = subprocess.run(
        [str(venv_python), "-I", "-c",
         "import fake_azazel_nexus, fake_azazel_runtime; print('ok')"],
        capture_output=True, text=True, check=False,
    )
    assert result.stdout.strip() == "ok", result.stderr


@pytest.mark.real_process
def test_pip_refuses_a_wheel_whose_hash_is_not_the_pinned_one(built, tmp_path, venv_python):
    extracted = extract_bundle(built[2], tmp_path / "out")
    text = offline_bundle.wheel_requirements(extracted.manifest)
    wrong = text.replace(_wheel_entry(extracted.manifest)["sha256"], "0" * 64)
    requirements = tmp_path / "req.txt"
    requirements.write_text(wrong)
    with pytest.raises(BundleRefused, match="(?i)hash"):
        offline_bundle.pip_install_offline(venv_python, extracted.root / "wheels", requirements)


@pytest.mark.real_process
def test_pip_refuses_a_requirement_without_a_hash(built, tmp_path, venv_python):
    extracted = extract_bundle(built[2], tmp_path / "out")
    lines = offline_bundle.wheel_requirements(extracted.manifest).splitlines()
    lines[0] = lines[0].split(" --hash")[0]
    requirements = tmp_path / "req.txt"
    requirements.write_text("\n".join(lines) + "\n")
    with pytest.raises(BundleRefused, match="(?i)hash"):
        offline_bundle.pip_install_offline(venv_python, extracted.root / "wheels", requirements)


@pytest.mark.real_process
def test_pip_finds_nothing_that_is_not_in_the_bundle(built, tmp_path, venv_python):
    extracted = extract_bundle(built[2], tmp_path / "out")
    requirements = tmp_path / "req.txt"
    requirements.write_text("PyYAML==6.0.3 --hash=sha256:" + "0" * 64 + "\n")
    with pytest.raises(BundleRefused, match="No matching distribution found"):
        offline_bundle.pip_install_offline(venv_python, extracted.root / "wheels", requirements)


def test_the_pip_argv_forbids_an_index_and_requires_hashes(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(offline_bundle, "_run", seen.append)
    offline_bundle.pip_install_offline(Path("/venv/bin/python"), tmp_path, tmp_path / "req.txt")
    (argv,) = seen
    for flag in ("--no-index", "--require-hashes", "--only-binary=:all:", "--find-links"):
        assert flag in argv
    assert "--index-url" not in argv and "--extra-index-url" not in argv


def test_install_refuses_an_interpreter_that_is_not_the_target(built, tmp_path, monkeypatch):
    monkeypatch.setattr(offline_bundle, "_require_root", lambda: None)
    probe = (offline_bundle.TARGETS[build_wheelhouse.TARGET]["architecture"],
             offline_bundle.TARGETS[build_wheelhouse.TARGET]["python_version"])
    import platform

    if (platform.machine(), sys.version_info[:2]) == probe:
        pytest.skip("this interpreter is the target; the refusal is not reachable here")
    with pytest.raises(BundleRefused, match="the bundle targets"):
        offline_bundle.install(built[2], tmp_path / "out", tmp_path / "venv", Path(sys.executable))
    assert not (tmp_path / "venv").exists()
    assert not (tmp_path / "out").exists(), "a refused install left its extracted tree"


def test_install_refuses_when_not_root(built, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    with pytest.raises(BundleRefused, match="install runs as root"):
        offline_bundle.install(built[2], tmp_path / "out", tmp_path / "venv", Path(sys.executable))
    assert not (tmp_path / "out").exists()


def test_install_refuses_an_installer_option_outside_the_allowlist(built, tmp_path, monkeypatch):
    monkeypatch.setattr(offline_bundle, "_require_root", lambda: None)
    with pytest.raises(BundleRefused, match="installer option"):
        offline_bundle.install(built[2], tmp_path / "out", tmp_path / "venv", Path(sys.executable),
                               run_installer=True, installer_options=("--llama-runtime",))


def test_install_refuses_an_existing_venv(built, tmp_path, monkeypatch):
    monkeypatch.setattr(offline_bundle, "_require_root", lambda: None)
    (tmp_path / "venv").mkdir()
    with pytest.raises(BundleRefused, match="fresh venv"):
        offline_bundle.install(built[2], tmp_path / "out", tmp_path / "venv", Path(sys.executable))
    assert not (tmp_path / "out").exists()


def test_the_cli_reports_unauthenticated_on_success_and_refusal(built, tmp_path, capsys):
    assert offline_bundle.main(["verify", "--bundle", str(built[2]), "--into", str(tmp_path / "a")]) == 0
    assert json.loads(capsys.readouterr().out)["bundle_authenticated"] is False
    members = _members(built[2])
    members.insert(3, _extra("source/undeclared.py"))
    evil = _write(tmp_path / "evil.tar.gz", members)
    assert offline_bundle.main(["verify", "--bundle", str(evil), "--into", str(tmp_path / "b")]) == 2
    refusal = json.loads(capsys.readouterr().err)
    assert refusal["bundle_authenticated"] is False and "not declared" in refusal["refused"]


def test_the_cli_runs_as_an_isolated_script_against_a_bundle(built, tmp_path):
    """The isolated script reads the real reviewed lock, which no fake bundle satisfies.

    So it gets as far as the completeness check (ADR-0004) and refuses there,
    in its structured form; acceptance is covered in-process above.
    """

    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools" / "offline_bundle.py"), "verify",
         "--bundle", str(built[2]), "--into", str(tmp_path / "out")],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode == 2, result.stdout
    refusal = json.loads(result.stderr)
    assert refusal["bundle_authenticated"] is False
    assert "does not carry" in refusal["refused"] and "azazel-fabric==0.10.0" in refusal["refused"]
    assert not (tmp_path / "out").exists()


def test_gzip_and_tar_noise_is_not_read_as_a_manifest(tmp_path):
    bundle = tmp_path / "noise.tar.gz"
    bundle.write_bytes(gzip.compress(os.urandom(4096)))
    _refused(tmp_path, bundle, "could not be read|first member|checksum|ustar")


# -- review follow-ups: wheels against the reviewed lock (S2) -----------------


def _bundle_with(tmp_path: Path, third_party) -> Path:
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"], third_party)
    build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse)
    return tmp_path / "b.tar.gz"


def test_a_third_party_wheel_not_in_the_reviewed_lock_is_refused_and_removed(tmp_path):
    bundle = _bundle_with(tmp_path, (("evil", "1.0"),))
    with pytest.raises(BundleRefused, match="not in the reviewed lock"):
        offline_bundle.extract_and_verify(bundle, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_a_locked_name_and_version_with_another_hash_is_refused(tmp_path):
    bundle = _bundle_with(tmp_path, (("dbus-next", "0.2.3"),))
    with pytest.raises(BundleRefused, match="sha256 the reviewed lock pins"):
        offline_bundle.extract_and_verify(bundle, tmp_path / "out")


def test_a_third_party_wheel_matching_the_lock_is_accepted(tmp_path):
    bundle = _bundle_with(tmp_path, (("dbus-next", "0.2.3"),))
    digest = hashlib.sha256(next((tmp_path / "wheelhouse").glob("dbus_next*.whl")).read_bytes()).hexdigest()
    _lock, versions = offline_bundle.reviewed_pins()
    _, report = offline_bundle.extract_and_verify(
        bundle, tmp_path / "out", pins=({"dbus-next==0.2.3": [digest]}, versions))
    assert {"requirement": "dbus-next==0.2.3",
            "pinned_by": "packaging/offline/requirements-x86_64-cp313.lock"} in report["wheels"]


def test_an_own_wheel_at_another_version_is_refused(built, tmp_path):
    lock, _versions = offline_bundle.reviewed_pins()
    pins = (lock, {"azazel-nexus": "9.9", "azazel-nexus-runtime": "9.9"})
    with pytest.raises(BundleRefused, match="reviewed checkout builds"):
        offline_bundle.extract_and_verify(built[2], tmp_path / "out", pins=pins)


def test_the_reviewed_lock_is_the_real_one():
    lock, versions = offline_bundle.reviewed_pins()
    assert set(lock) == {
        "dbus-next==0.2.3", "pyyaml==6.0.3", "azazel-fabric==0.10.0", "azazel-mio==0.1.0.dev20261105+gite639a65",
        "pydantic==2.13.5",
        "pydantic-core==2.46.5", "annotated-types==0.8.0", "typing-extensions==4.16.0",
        "typing-inspection==0.4.4",
    }
    assert versions == {"azazel-nexus": "0.0.1.dev0", "azazel-nexus-runtime": "0.0.1.dev0"}


def test_a_verifier_without_a_reviewed_lock_refuses(built, tmp_path, monkeypatch):
    real = offline_bundle.reviewed_pins
    monkeypatch.setattr(offline_bundle, "reviewed_pins", lambda target: real(tmp_path / "nowhere", target))
    with pytest.raises(BundleRefused, match="reviewed checkout"):
        offline_bundle.extract_and_verify(built[2], tmp_path / "out")


# -- the strict ustar reader (B1) ---------------------------------------------


def _raw_header(name: str, size: int, typeflag: bytes = b"0", *, magic: bytes = b"ustar\x0000",
                linkname: str = "", checksum_delta: int = 0, size_field: bytes | None = None,
                area: bytes = b"") -> bytes:
    block = bytearray(512)
    block[0:len(name)] = name.encode()
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = size_field if size_field is not None else b"%011o\0" % size
    block[136:148] = b"00000000000\0"
    block[156:157] = typeflag
    block[157:157 + len(linkname)] = linkname.encode()
    block[257:265] = magic
    block[345:345 + len(area)] = area
    block[148:156] = b" " * 8
    block[148:156] = b"%06o\0 " % (sum(block) + checksum_delta)
    return bytes(block)


def _pax(records: dict[str, str]) -> bytes:
    out = b""
    for key, value in records.items():
        body = f" {key}={value}\n".encode()
        length = len(body) + 1
        while len(str(length)) + len(body) != length:
            length = len(str(length)) + len(body)
        out += str(length).encode() + body
    return out


def _stream_bundle(path: Path, parts) -> Path:
    """Write gzip(tar) from raw blocks and (size, chunk) bodies without holding them."""

    with gzip.open(path, "wb", compresslevel=1) as stream:
        for part in parts:
            if isinstance(part, bytes):
                stream.write(part)
            else:
                size, chunk = part
                written = 0
                while written < size:
                    piece = chunk[: size - written]
                    stream.write(piece)
                    written += len(piece)
                stream.write(b"\0" * (-size % 512))
        stream.write(b"\0" * 1024)
    return path


def _padded(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 512)


def _vmhwm_extract(tmp_path: Path, bundle: Path) -> dict:
    """Extract in a child process; report its outcome and its own peak RSS (VmHWM).

    VmHWM, not ru_maxrss: Linux carries ru_maxrss across exec, so a child of a
    large pytest process would report the parent's peak.
    """

    if not Path("/proc/self/status").exists():
        pytest.skip("VmHWM needs Linux /proc")
    probe = (
        "import json, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from pathlib import Path\n"
        "from tools import offline_bundle as ob\n"
        "try:\n"
        "    ob.extract_bundle(Path(sys.argv[2]), Path(sys.argv[3]))\n"
        "    outcome = 'accepted'\n"
        "except ob.BundleRefused as exc:\n"
        "    outcome = str(exc)\n"
        "hwm = [l for l in open('/proc/self/status') if l.startswith('VmHWM:')][0]\n"
        "print(json.dumps({'outcome': outcome, 'maxrss_kib': int(hwm.split()[1])}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe, str(ROOT), str(bundle), str(tmp_path / "out")],
        capture_output=True, text=True, check=False, timeout=300,
    )
    assert result.returncode == 0, result.stderr
    assert [p.name for p in tmp_path.iterdir() if ".staging-" in p.name] == []
    return json.loads(result.stdout)


_BIG = 256 << 20


@pytest.mark.real_process
@pytest.mark.parametrize("kind", [b"L", b"x", b"K", b"g"])
def test_an_oversized_extended_header_is_refused_in_bounded_memory(tmp_path, kind):
    bomb = _stream_bundle(tmp_path / "bomb.tar.gz", [
        _raw_header("././@LongLink", _BIG, kind), (_BIG, b"9 a=bbb\n" * (1 << 17)),
    ])
    report = _vmhwm_extract(tmp_path, bomb)
    assert bomb.stat().st_size < 4 << 20  # a small file on the medium...
    assert report["maxrss_kib"] < 128 * 1024, report  # ...is never inflated in memory
    assert "only regular files are carried" in report["outcome"]


@pytest.mark.real_process
def test_a_pax_gnu_sparse_1_0_map_bomb_is_refused_in_bounded_memory(tmp_path):
    pax = _pax({"GNU.sparse.major": "1", "GNU.sparse.minor": "0",
                "GNU.sparse.name": "MANIFEST.json", "GNU.sparse.realsize": str(_BIG)})
    bomb = _stream_bundle(tmp_path / "sparse10.tar.gz", [
        _raw_header("././@PaxHeader", len(pax), b"x"), _padded(pax),
        _raw_header("MANIFEST.json", _BIG), (_BIG, b"1\n" * (1 << 19)),
    ])
    report = _vmhwm_extract(tmp_path, bomb)
    assert report["maxrss_kib"] < 128 * 1024, report
    assert "pax extended header" in report["outcome"]


@pytest.mark.parametrize("records", [
    {"GNU.sparse.offset": "0", "GNU.sparse.numbytes": "1"},           # sparse 0.0
    {"GNU.sparse.numblocks": "1", "GNU.sparse.map": "0,1"},           # sparse 0.1
    {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"},               # sparse 1.0
    {"path": "MANIFEST.json"},                                        # even a harmless one
])
def test_every_pax_header_in_the_bundle_is_refused(tmp_path, records):
    pax = _pax(records)
    bundle = _stream_bundle(tmp_path / "pax.tar.gz", [
        _raw_header("././@PaxHeader", len(pax), b"x"), _padded(pax),
        _raw_header("MANIFEST.json", 2), _padded(b"{}"),
    ])
    _refused(tmp_path, bundle, "pax extended header")


def test_chained_extended_headers_are_refused_at_the_first(tmp_path):
    pax = _pax({"path": "a"})
    bundle = _stream_bundle(tmp_path / "chain.tar.gz", [
        _raw_header("p1", len(pax), b"x"), _padded(pax),
        _raw_header("p2", len(pax), b"x"), _padded(pax),
        _raw_header("././@LongLink", 4, b"L"), _padded(b"abc\0"),
        _raw_header("MANIFEST.json", 2), _padded(b"{}"),
    ])
    _refused(tmp_path, bundle, "pax extended header")


@pytest.mark.parametrize("typeflag", [
    b"1", b"2", b"3", b"4", b"5", b"6", b"7", b"x", b"g", b"L", b"K", b"S", b"X", b"V", b"M", b"N",
    b"D", b"\0", b"Z",
])
def test_each_non_regular_typeflag_is_refused_before_its_body(built, tmp_path, typeflag):
    members = _members(built[2])
    manifest = members[0][1]
    bundle = _stream_bundle(tmp_path / "t.tar.gz", [
        _raw_header("MANIFEST.json", len(manifest)), _padded(manifest),
        _raw_header("source/evil", 1 << 20, typeflag), (1 << 20, b"\xff" * (1 << 20)),
    ])
    _refused(tmp_path, bundle, "only regular files are carried")


@pytest.mark.parametrize("header, match", [
    (_raw_header("MANIFEST.json", 2, checksum_delta=1), "checksum"),
    (_raw_header("MANIFEST.json", 2, magic=b"ustar  \0"), "not POSIX ustar"),
    (_raw_header("MANIFEST.json", 2, size_field=b"\x80" + b"\0" * 10 + b"\x02"), "octal|after its NUL"),
    (_raw_header("MANIFEST.json", 2, linkname="x"), "link target"),
])
def test_malformed_headers_are_refused(tmp_path, header, match):
    bundle = _stream_bundle(tmp_path / "h.tar.gz", [header, _padded(b"{}")])
    _refused(tmp_path, bundle, match)


def test_data_after_the_end_marker_is_refused(built, tmp_path):
    with gzip.open(built[2], "rb") as stream:
        data = stream.read()
    bad = tmp_path / "trailing.tar.gz"
    bad.write_bytes(gzip.compress(data + b"\x01" * 512))
    _refused(tmp_path, bad, "after|follows")


def test_data_after_the_gzip_stream_is_refused(built, tmp_path):
    bad = tmp_path / "gztrail.tar.gz"
    bad.write_bytes(built[2].read_bytes() + b"junk")
    _refused(tmp_path, bad, "follows the end of the gzip stream")


def test_the_decompressed_stream_is_capped(built, tmp_path):
    with gzip.open(built[2], "rb") as stream:
        data = stream.read()
    padded = tmp_path / "zeros.tar.gz"
    with gzip.open(padded, "wb", compresslevel=1) as out:
        out.write(data)
        for _ in range(64):
            out.write(bytes(1 << 20))
    _refused(tmp_path, padded, "decompresses beyond")


def test_the_builder_writes_plain_ustar(built):
    with gzip.open(built[2], "rb") as stream:
        first = stream.read(512)
    assert first[257:265] == b"ustar\x0000" and first[156:157] == b"0"


def test_a_path_that_does_not_fit_ustar_is_a_build_error(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    model = tmp_path / ("m" * 150 + ".gguf")
    model.write_bytes(b"GGUF")
    with pytest.raises(ValueError):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                             models=[model], assets_source="test")
    assert not (tmp_path / "b.tar.gz").exists()


def test_a_nested_edge_archive_with_a_sparse_pax_key_is_refused(tmp_path, monkeypatch):
    from azazel_nexus.edge_package import PINS

    PIN = PINS["x86_64"]
    edge = _edge_package(tmp_path / "edge")
    pax = _pax({"GNU.sparse.major": "1", "GNU.sparse.minor": "0"})
    (edge / PIN.artifact_name).write_bytes(gzip.compress(
        _raw_header("p", len(pax), b"x") + _padded(pax) + _raw_header("bin/azazel-edge-core", 1)
        + _padded(b"x") + bytes(1024)))
    manifest = json.loads((edge / PIN.manifest_name).read_text())
    manifest["digest"] = "sha256:" + hashlib.sha256((edge / PIN.artifact_name).read_bytes()).hexdigest()
    (edge / PIN.manifest_name).write_text(json.dumps(manifest))
    _pin_edge(monkeypatch, edge)
    with pytest.raises(BundleRefused, match="pax key"):
        offline_bundle.verify_edge_slot(edge)


@pytest.mark.parametrize("blocks, match", [
    (lambda: _raw_header("p", len(_pax({"a": "b"})), b"x") + _padded(_pax({"a": "b"}))
     + _raw_header("c", 0), "pax key"),
    (lambda: _raw_header("././@LongLink", 4, b"L") + _padded(b"abc\0"), "GNU long-name"),
    (lambda: _raw_header("s", 0, b"S"), "sparse"),
    (lambda: (_raw_header("p", len(_pax({"path": "a"})), b"x") + _padded(_pax({"path": "a"}))) * 2,
     "chained"),
])
def test_the_nested_scanner_refuses_extensions(blocks, match):
    stream = offline_bundle._Plain(blocks() + bytes(1024))
    with pytest.raises(BundleRefused, match=match):
        offline_bundle.scan_nested_tar(stream)


def test_the_nested_scanner_reads_a_gnu_magic_control_file():
    data = b"Package: x\n"
    blocks = _raw_header("./control", len(data), magic=b"ustar  \0") + _padded(data) + bytes(1024)
    found = offline_bundle.scan_nested_tar(offline_bundle._Plain(blocks), want=frozenset({"control"}))
    assert found == {"control": data}


def _dead_pid() -> int:
    child = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                           capture_output=True, text=True, check=True)
    return int(child.stdout)


def test_a_stale_staging_directory_of_a_dead_run_is_removed(built, tmp_path):
    stale = tmp_path / f".out.staging-{_dead_pid()}-abc123"
    stale.mkdir()
    (stale / "partial").write_bytes(b"x")
    live = tmp_path / f".out.staging-{os.getppid()}-def456"
    live.mkdir()
    unrecorded = tmp_path / ".out.staging-killed"
    unrecorded.mkdir()
    other = tmp_path / ".other.staging-1-x"
    other.mkdir()
    link = tmp_path / f".out.staging-{_dead_pid()}-link"
    link.symlink_to(other)
    extract_bundle(built[2], tmp_path / "out")
    assert not stale.exists()
    assert live.exists() and unrecorded.exists() and other.exists() and link.is_symlink()


# -- ratio, free space and the per-member write cap (S3) ----------------------


def test_a_high_compression_ratio_is_refused(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    zeros = tmp_path / "zeros.gguf"
    zeros.write_bytes(bytes(16 << 20))
    build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                         models=[zeros], assets_source="test fixture")
    _refused(tmp_path, tmp_path / "b.tar.gz", "ratio cap")


def test_insufficient_free_space_is_refused_before_writing(built, tmp_path, monkeypatch, private_os):
    private_os(offline_bundle)
    real = os.statvfs

    class Tiny:
        def __init__(self, result):
            self.f_frsize = result.f_frsize
            self.f_bavail = 1

    monkeypatch.setattr(offline_bundle.os, "statvfs", lambda path: Tiny(real(path)))
    _refused(tmp_path, built[2], "bytes free")


def test_a_member_stream_longer_than_declared_stops_at_the_declared_size(tmp_path):
    entry = {"size": 4, "sha256": hashlib.sha256(b"abcd").hexdigest(), "mode": "0644"}
    with pytest.raises(BundleRefused, match="larger than the manifest declares"):
        offline_bundle._write_member(tmp_path, "source/x", io.BytesIO(b"abcd" + b"e" * (2 << 20)), entry)
    assert (tmp_path / "source/x").stat().st_size <= 4 + (1 << 20)


# -- manifest parsing (S4) ----------------------------------------------------


def _manifest_only(tmp_path: Path, data: bytes) -> Path:
    bundle = tmp_path / "m.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        info = tarfile.TarInfo(offline_bundle.MANIFEST_NAME)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return bundle


def test_a_deeply_nested_manifest_is_refused_without_a_traceback(tmp_path, capsys):
    bundle = _manifest_only(tmp_path, b"[" * 200_000 + b"]" * 200_000)
    _refused(tmp_path, bundle, "nests deeper")
    assert offline_bundle.main(["verify", "--bundle", str(bundle), "--into", str(tmp_path / "x")]) == 2
    refusal = json.loads(capsys.readouterr().err)
    assert refusal["bundle_authenticated"] is False and "nests deeper" in refusal["refused"]


def test_a_recursion_error_while_parsing_is_a_refusal(monkeypatch):
    monkeypatch.setattr(offline_bundle, "_json_nesting", lambda text: 0)
    with pytest.raises(BundleRefused, match="RecursionError"):
        offline_bundle.load_manifest(b"[" * 200_000 + b"]" * 200_000)


@pytest.mark.parametrize("data", [b"\xff\xfe", b"{", b"null", b"[]"])
def test_unparseable_manifests_are_refusals(data):
    with pytest.raises(BundleRefused):
        offline_bundle.load_manifest(data)


def test_brackets_inside_strings_do_not_count_as_nesting():
    assert offline_bundle._json_nesting('{"a": "[[[[\\"[[[[", "b": [1]}') == 2


def test_the_cli_turns_any_exception_into_a_refusal(monkeypatch, tmp_path, capsys):
    def boom(*args, **kwargs):
        raise MemoryError("synthetic")

    monkeypatch.setattr(offline_bundle, "extract_and_verify", boom)
    assert offline_bundle.main(["verify", "--bundle", str(tmp_path / "b"), "--into", str(tmp_path / "o")]) == 2
    refusal = json.loads(capsys.readouterr().err)
    assert refusal == {"refused": "MemoryError: synthetic", "bundle_authenticated": False}


# -- paths and the destination (N1-N3) ----------------------------------------


def _resorted(document: dict) -> dict:
    document["artifacts"].sort(key=lambda e: e["path"])
    document["totals"] = {"count": len(document["artifacts"]),
                          "bytes": sum(e["size"] for e in document["artifacts"])}
    return document


def test_paths_that_differ_only_in_case_are_refused(built):
    document = _valid(built)
    twin = copy.deepcopy(next(e for e in document["artifacts"] if e["path"] == "source/README.md"))
    twin["path"] = "source/readme.md"
    document["artifacts"].append(twin)
    with pytest.raises(BundleRefused, match="differ only in case"):
        offline_bundle.validate_manifest(_resorted(document))


def test_a_file_that_is_also_a_directory_prefix_is_refused(built):
    document = _valid(built)
    child = copy.deepcopy(next(e for e in document["artifacts"] if e["path"] == "source/README.md"))
    child["path"] = "source/README.md/inner"
    document["artifacts"].append(child)
    with pytest.raises(BundleRefused, match="also the directory of"):
        offline_bundle.validate_manifest(_resorted(document))


def test_a_sticky_world_writable_parent_is_accepted(built, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("running as root: a sticky shared parent is refused (see the next test)")
    parent = tmp_path / "sticky"
    parent.mkdir()
    parent.chmod(0o1777)
    extract_bundle(built[2], parent / "out")
    assert (parent / "out" / "MANIFEST.json").is_file()


def test_a_sticky_world_writable_parent_is_refused_as_root(built, tmp_path):
    if os.geteuid() != 0:
        pytest.skip("not running as root: a sticky shared parent is accepted (see the previous test)")
    parent = tmp_path / "sticky"
    parent.mkdir()
    parent.chmod(0o1777)
    with pytest.raises(BundleRefused, match="writable by group/others"):
        extract_bundle(built[2], parent / "out")
    assert list(parent.iterdir()) == []


def test_a_group_writable_destination_parent_is_refused(built, tmp_path):
    parent = tmp_path / "shared"
    parent.mkdir()
    parent.chmod(0o775)
    with pytest.raises(BundleRefused, match="writable by group/others"):
        extract_bundle(built[2], parent / "out")
    assert list(parent.iterdir()) == []


# -- recheck before install.sh -------------------------------------------------


def _extracted(built, tmp_path):
    extracted = extract_bundle(built[2], tmp_path / "out")
    return extracted, hashlib.sha256(extracted.manifest_bytes).hexdigest()


def test_recheck_passes_on_an_untouched_tree(built, tmp_path):
    _, digest = _extracted(built, tmp_path)
    report = offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256=digest)
    assert report["recheck"] == "pass" and report["bundle_authenticated"] is False
    assert report["files"] == len(built[3]["artifacts"])
    assert "unauthenticated until bundle signing" in report["own_wheels"]


def test_recheck_compares_the_manifest_with_the_extraction_digest(built, tmp_path):
    _extracted(built, tmp_path)
    with pytest.raises(BundleRefused, match="not the manifest extraction verified"):
        offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256="0" * 64)


def test_a_rewritten_tree_and_manifest_fail_recheck(built, tmp_path):
    _, digest = _extracted(built, tmp_path)
    root = tmp_path / "out"
    document = json.loads((root / "MANIFEST.json").read_bytes())
    target = next(e for e in document["artifacts"] if e["path"] == "source/README.md")
    (root / "source/README.md").write_bytes(b"evil\n")
    target["sha256"] = hashlib.sha256(b"evil\n").hexdigest()
    target["size"] = 5
    document["totals"]["bytes"] = sum(e["size"] for e in document["artifacts"])
    (root / "MANIFEST.json").write_bytes(offline_bundle.manifest_bytes(document))
    with pytest.raises(BundleRefused, match="not the manifest extraction verified"):
        offline_bundle.recheck_tree(root, expected_manifest_sha256=digest)


def test_recheck_runs_the_lock_check_again(built, tmp_path, monkeypatch):
    _, digest = _extracted(built, tmp_path)
    lock, _ = offline_bundle.reviewed_pins()
    with pytest.raises(BundleRefused, match="reviewed checkout builds"):
        offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256=digest,
                                    pins=(lock, {"azazel-nexus": "9", "azazel-nexus-runtime": "9"}))


@pytest.mark.parametrize("tamper, match", [
    (lambda root: (root / "source/packaging/install.sh").write_bytes(b"#!/bin/sh\nevil\n"), "no longer matches"),
    (lambda root: (root / "source/packaging/extra.sh").write_bytes(b"x"), "not declared"),
    (lambda root: (root / "source/README.md").unlink(), "missing"),
    (lambda root: (root / "source/README.md").chmod(0o666), "writable by group/others"),
    (lambda root: (root / "source/tools/link").symlink_to("/etc/passwd"), "is a link"),
    (lambda root: os.link(root / "source/README.md", root.parent / "outside-link"), "hard links"),
])
def test_recheck_refuses_a_tree_changed_after_extraction(built, tmp_path, tamper, match):
    _, digest = _extracted(built, tmp_path)
    tamper(tmp_path / "out")
    with pytest.raises(BundleRefused, match=match):
        offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256=digest)


def test_recheck_is_a_cli_command_that_needs_the_digest(built, tmp_path, capsys):
    _, digest = _extracted(built, tmp_path)
    assert offline_bundle.main(["recheck", "--tree", str(tmp_path / "out"),
                                "--expect-manifest-sha256", digest]) == 0
    assert json.loads(capsys.readouterr().out)["recheck"] == "pass"
    with pytest.raises(SystemExit):
        offline_bundle.main(["recheck", "--tree", str(tmp_path / "out")])


# -- the verifier must not vouch for itself (S3) --------------------------------


def test_a_verifier_inside_the_destination_is_refused(built, tmp_path, monkeypatch):
    monkeypatch.setattr(offline_bundle, "REVIEWED_ROOT", tmp_path / "out" / "source")
    with pytest.raises(BundleRefused, match="is inside"):
        offline_bundle.extract_and_verify(built[2], tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_a_verifier_inside_an_extracted_bundle_is_refused(built, tmp_path, monkeypatch):
    _, digest = _extracted(built, tmp_path)
    monkeypatch.setattr(offline_bundle, "REVIEWED_ROOT", tmp_path / "out" / "source")
    with pytest.raises(BundleRefused, match="inside an extracted bundle"):
        offline_bundle.extract_and_verify(built[2], tmp_path / "other")
    with pytest.raises(BundleRefused, match="inside"):
        offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256=digest)


def test_the_report_says_own_wheels_are_version_pinned_only(built, tmp_path):
    _, report = offline_bundle.extract_and_verify(built[2], tmp_path / "out")
    assert "pinned by version only" in report["own_wheels"]
    assert "unauthenticated" in report["own_wheels"]


# -- third review: parser agreement with tarfile, the Edge pin, venv dir --------


_SMUGGLE_SIZE = b"\0" + b"0000002000" + b"\0"   # tarfile reads 0, a NUL-to-space reader 1024


def _hidden(kind: bytes) -> bytes:
    if kind == b"L":
        body = b"x" * 1000 + b"\0"
        return _raw_header("././@LongLink", len(body), b"L") + _padded(body)
    pax = _pax({"size": "999999", "GNU.sparse.major": "1", "GNU.sparse.minor": "0"})
    return _raw_header("p", len(pax), b"x") + _padded(pax)


@pytest.mark.parametrize("kind", [b"L", b"x"])
def test_a_nul_leading_size_cannot_smuggle_a_hidden_header_past_the_nested_scan(kind):
    hidden = _hidden(kind)[:1024].ljust(1024, b"\0")
    blocks = _raw_header("bin/azazel-edge-core", 0, size_field=_SMUGGLE_SIZE) + hidden + bytes(1024)
    with pytest.raises(BundleRefused, match="after its NUL"):
        offline_bundle.scan_nested_tar(offline_bundle._Plain(blocks))


@pytest.mark.parametrize("kind", [b"L", b"x"])
def test_a_nul_leading_size_is_refused_in_the_bundle_too(tmp_path, kind):
    hidden = _hidden(kind)[:1024].ljust(1024, b"\0")
    bundle = _stream_bundle(tmp_path / "smuggle.tar.gz", [
        _raw_header("MANIFEST.json", 0, size_field=_SMUGGLE_SIZE), hidden,
    ])
    _refused(tmp_path, bundle, "after its NUL")


def test_octal_fields_read_as_tarfile_reads_them():
    assert offline_bundle._octal(b"0000644\0", "mode") == 0o644
    assert offline_bundle._octal(b"012345\0 ", "checksum") == 0o12345
    assert offline_bundle._octal(b"\0" * 12, "size") == 0
    for bad in (b"\x000000002000\0", b"12 34\0", b"00009\0", b"0001\0x"):
        with pytest.raises(BundleRefused):
            offline_bundle._octal(bad, "size")


def test_a_gnu_header_using_its_extension_area_is_refused():
    blocks = _raw_header("./control", 1, magic=b"ustar  \0", area=b"00000000017") + _padded(b"x") + bytes(1024)
    with pytest.raises(BundleRefused, match="extension area"):
        offline_bundle.scan_nested_tar(offline_bundle._Plain(blocks))


def test_an_edge_archive_off_the_reviewed_pin_is_refused_before_any_parsing(tmp_path, monkeypatch):
    from azazel_nexus import edge_package
    from azazel_nexus.edge_package import PINS

    PIN = PINS["x86_64"]
    edge = _edge_package(tmp_path / "edge")

    def must_not_parse(*args, **kwargs):
        raise AssertionError("the archive was parsed before its digest was checked")

    monkeypatch.setattr(offline_bundle, "scan_nested_tar", must_not_parse)
    monkeypatch.setattr(edge_package, "_archive_components", must_not_parse)
    monkeypatch.setattr(offline_bundle, "reviewed_edge_digest",
                        lambda root=None, target=None: ("0" * 64, PIN.artifact_name))
    with pytest.raises(BundleRefused, match="not the one the reviewed checkout pins"):
        offline_bundle.verify_edge_slot(edge)


def test_an_edge_slot_without_a_reviewed_pin_is_refused(tmp_path):
    assert offline_bundle.reviewed_edge_digest() is None, "this repository ships no baseline Edge pin"
    with pytest.raises(BundleRefused, match="pins no Edge artifact"):
        offline_bundle.verify_edge_slot(_edge_package(tmp_path / "edge"))


def test_the_reviewed_edge_pin_file_format(tmp_path):
    pin = tmp_path / offline_bundle.EDGE_ARTIFACT_PIN
    pin.parent.mkdir(parents=True)
    pin.write_text("a" * 64 + "  azazel-edge-core-0.1.0-x86_64.tar.gz\n")
    assert offline_bundle.reviewed_edge_digest(tmp_path) == ("a" * 64, "azazel-edge-core-0.1.0-x86_64.tar.gz")
    pin.write_text("a" * 64 + "\n")
    with pytest.raises(BundleRefused, match="one"):
        offline_bundle.reviewed_edge_digest(tmp_path)


def test_a_sticky_parent_is_refused_for_the_root_venv_case(tmp_path):
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    offline_bundle._check_destination_parent(sticky, allow_sticky=True)
    with pytest.raises(BundleRefused, match="writable by group/others"):
        offline_bundle._check_destination_parent(sticky, allow_sticky=False)


def test_the_venv_directory_is_created_exclusively_and_private(tmp_path):
    venv = tmp_path / "venv"
    offline_bundle._create_private_dir(venv)
    assert venv.stat().st_mode & 0o777 == 0o700
    with pytest.raises(BundleRefused, match="appeared"):
        offline_bundle._create_private_dir(venv)


def test_nested_pax_keys_carry_no_link_or_size_key():
    assert not {"linkpath", "size", "hdrcharset"} & offline_bundle.NESTED_PAX_KEYS
    assert not any(key.startswith("GNU.") for key in offline_bundle.NESTED_PAX_KEYS)


@pytest.mark.real_process
def test_a_large_regular_member_streams_in_bounded_memory(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    model = tmp_path / "model.gguf"
    chunk = os.urandom(1 << 20)  # deflate's 32 KiB window cannot compress a 1 MiB repeat
    with open(model, "wb") as stream:
        for _ in range(96):
            stream.write(chunk)
    build_install_bundle(root, tmp_path / "big.tar.gz", wheelhouse=wheelhouse,
                         models=[model], assets_source="test")
    model.unlink()
    report = _vmhwm_extract(tmp_path, tmp_path / "big.tar.gz")
    assert report["outcome"] == "accepted"
    assert report["maxrss_kib"] < 64 * 1024, report


@pytest.mark.real_process
def test_exceeding_the_gzip_cap_is_refused_in_bounded_memory(built, tmp_path):
    with gzip.open(built[2], "rb") as stream:
        data = stream.read()
    padded = tmp_path / "zeros.tar.gz"
    with gzip.open(padded, "wb", compresslevel=1) as out:
        out.write(data)
        for _ in range(96):
            out.write(bytes(1 << 20))
    report = _vmhwm_extract(tmp_path, padded)
    assert "decompresses beyond" in report["outcome"]
    assert report["maxrss_kib"] < 64 * 1024, report


# -- Fabric in the offline wheelhouse (ADR-0004) -------------------------------


def _uv_lock_packages() -> dict[str, dict]:
    import tomllib

    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {offline_bundle.canonical_name(p["name"]): p for p in lock["package"]}


def test_commissioned_activation_needs_a_fabric_the_offline_lock_carries(monkeypatch):
    """The defect ADR-0004 closes, as a regression test.

    Every production activation pass requires commissioning evidence, and the
    evidence loader projects the current hardware through pinned Fabric, which
    refuses without it. Before ADR-0004 the offline lock carried neither Fabric
    nor pydantic, so a node installed from the bundle could never pass.
    """

    from azazel_nexus import fabric_boundary

    activated = (ROOT / "runtime/src/azazel_nexus_runtime/activated.py").read_text(encoding="utf-8")
    loader = (ROOT / "runtime/src/azazel_nexus_runtime/commissioning_input.py").read_text(encoding="utf-8")
    assert "require_commissioning_evidence=True" in activated
    assert "commissioning_evidence=load_commissioning_evidence" in activated
    assert "current = project_hardware_inventory(" in loader

    monkeypatch.setattr(fabric_boundary, "_import_fabric", lambda: (None, "absent"))
    with pytest.raises(fabric_boundary.CommissioningRecordUnavailable, match="pinned Fabric is required"):
        fabric_boundary.project_hardware_inventory(
            readouts=(), platform={}, storage_devices=(), limitations=(), node_id="n",
            inventory_id="i", collected_at="2026-10-13T00:00:00Z")

    lock = build_wheelhouse.parse_lock(ROOT / build_wheelhouse.LOCK)
    assert f"azazel-fabric=={fabric_boundary.FABRIC_PIN.lstrip('v')}" in lock
    for name in ("pydantic", "pydantic-core"):
        assert any(key.partition("==")[0] == name for key in lock), name


def test_the_fabric_source_build_is_the_pin_pyproject_uv_lock_and_the_boundary_name():
    from azazel_nexus.fabric_boundary import FABRIC_PIN

    import tomllib

    build = build_wheelhouse.SOURCE_BUILDS["azazel-fabric"]
    assert build["tag"] == FABRIC_PIN and build["version"] == FABRIC_PIN.lstrip("v")
    assert len(build["commit"]) == 40
    extras = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["optional-dependencies"]
    assert extras["fabric"] == [f"azazel-fabric @ git+{build['repository']}@{build['tag']}"]
    package = _uv_lock_packages()["azazel-fabric"]
    assert package["source"] == {"git": f"{build['repository']}?rev={build['tag']}#{build['commit']}"}
    assert build_wheelhouse.BUNDLED_EXTRAS == ("fabric", "mio")


def test_mio_extra_is_optional_exact_commit_and_does_not_change_core_dependencies():
    import tomllib

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    build = build_wheelhouse.SOURCE_BUILDS["azazel-mio"]
    requirement = f"azazel-mio @ git+{build['repository']}@{build['commit']}"
    assert project["dependencies"] == []
    assert project["optional-dependencies"]["mio"] == [requirement]
    assert "tag" not in build
    assert len(build["commit"]) == 40
    package = _uv_lock_packages()["azazel-mio"]
    expected = f"{build['repository']}?rev={build['commit']}#{build['commit']}"
    assert package["source"] == {"git": expected}
    assert package.get("dependencies", []) == []
    extras = _uv_lock_packages()["azazel-nexus"]["optional-dependencies"]
    assert extras["mio"] == [{"name": "azazel-mio"}]
    assert build_wheelhouse.bundled_extra_closure(ROOT) >= {"azazel-mio==0.1.0.dev20261105+gite639a65"}


def test_each_pypi_wheel_hash_in_the_lock_is_one_uv_lock_records():
    packages = _uv_lock_packages()
    lock = build_wheelhouse.parse_lock(ROOT / build_wheelhouse.LOCK)
    closure = build_wheelhouse.bundled_extra_closure(ROOT)
    assert closure == {
        "azazel-fabric==0.10.0", "azazel-mio==0.1.0.dev20261105+gite639a65",
        "pydantic==2.13.5", "pydantic-core==2.46.5",
        "annotated-types==0.8.0", "typing-extensions==4.16.0", "typing-inspection==0.4.4",
    }
    for requirement in closure - {"azazel-fabric==0.10.0", "azazel-mio==0.1.0.dev20261105+gite639a65"}:
        name, _, version = requirement.partition("==")
        assert packages[name]["version"] == version
        recorded = {w["hash"].removeprefix("sha256:") for w in packages[name]["wheels"]}
        (digest,) = lock[requirement]
        assert digest in recorded, requirement


def _closure_root(tmp_path: Path) -> Path:
    (tmp_path / "runtime").mkdir()
    for name in ("pyproject.toml", "uv.lock", "runtime/pyproject.toml"):
        (tmp_path / name).write_text((ROOT / name).read_text(encoding="utf-8"), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("path, old, new, match", [
    ("pyproject.toml", "Azazel-Fabric.git@v0.10.0", "Azazel-Fabric.git@main", "not a pinned source build"),
    ("uv.lock", "#397fcce7a87ca7ab1a5e84bc196c44d70c404907", "#" + "0" * 40, "does not resolve azazel-fabric"),
    ("pyproject.toml", "Azazel-MIO.git@1ba191b4daa8b3edd8bcd6ee6517a1b31a982c85",
     "Azazel-MIO.git@main", "not a pinned source build"),
    ("uv.lock", "Azazel-MIO.git?rev=1ba191b4daa8b3edd8bcd6ee6517a1b31a982c85#1ba191b4daa8b3edd8bcd6ee6517a1b31a982c85",
     "Azazel-MIO.git?rev=1ba191b4daa8b3edd8bcd6ee6517a1b31a982c85#" + "0" * 40,
     "does not resolve azazel-mio"),
    ("uv.lock", '    { name = "pydantic-core" },\n', '    { name = "pydantic-core", marker = "x" },\n', "markers"),
    ("uv.lock", 'name = "pydantic"\nversion = "2.13.5"\nsource = { registry = "https://pypi.org/simple" }',
     'name = "pydantic"\nversion = "2.13.5"\nsource = { git = "https://example.invalid/pydantic.git" }',
     "not PyPI"),
    ("uv.lock", 'name = "typing-extensions"\nversion = "4.16.0"\nsource = { registry = "https://pypi.org/simple" }',
     'name = "typing-extensions"\nversion = "4.16.0"\nsource = { url = "https://example.invalid/te.whl" }',
     "not PyPI"),
])
def test_the_extra_closure_refuses_a_drifted_pin(tmp_path, path, old, new, match):
    root = _closure_root(tmp_path)
    text = (root / path).read_text(encoding="utf-8")
    assert old in text
    (root / path).write_text(text.replace(old, new, 1), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        build_wheelhouse.bundled_extra_closure(root)


def test_a_wheelhouse_without_a_locked_wheel_cannot_become_a_bundle(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    (root / "packaging/offline/requirements-x86_64-cp313.lock").write_text(
        "azazel-fabric==0.10.0 --hash=sha256:" + "1" * 64 + "\n", encoding="utf-8")
    with pytest.raises(BundleRefused, match="does not carry"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse)
    assert not (tmp_path / "b.tar.gz").exists()


def test_a_recheck_refuses_a_tree_whose_bundle_lacks_a_locked_wheel(built, tmp_path):
    extracted, report = offline_bundle.extract_and_verify(built[2], tmp_path / "out")
    _lock, versions = offline_bundle.reviewed_pins()
    with pytest.raises(BundleRefused, match="does not carry"):
        offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256=report["manifest_sha256"],
                                    pins=({"azazel-fabric==0.10.0": ["0" * 64]}, versions))


def test_the_builder_children_run_at_umask_022_whatever_the_caller_has(tmp_path):
    """The Fabric wheel hash depends on the modes setuptools copies with (review M1)."""

    probe = ("import os, sys; path = sys.argv[1]; open(path, 'w').close(); "
             "print(oct(os.umask(0)), oct(os.stat(path).st_mode & 0o777))")
    previous = os.umask(0o077)
    try:
        out = build_wheelhouse._run([sys.executable, "-I", "-c", probe, str(tmp_path / "f")])
        git_out = build_wheelhouse._run([sys.executable, "-I", "-c", probe, str(tmp_path / "g")],
                                        env=build_wheelhouse._git_env())
    finally:
        os.umask(previous)
    assert out.split() == ["0o22", "0o644"]
    assert git_out.split() == ["0o22", "0o644"]


def test_a_source_built_wheel_that_did_not_reproduce_the_lock_is_refused():
    build = build_wheelhouse.SOURCE_BUILDS["azazel-fabric"]
    lock = build_wheelhouse.parse_lock(ROOT / build_wheelhouse.LOCK)
    filename = "azazel_fabric-0.10.0-py3-none-any.whl"
    (locked,) = lock["azazel-fabric==0.10.0"]
    assert build["commit"] in build_wheelhouse.source_build_origin(filename, locked, lock)
    with pytest.raises(ValueError, match="did not reproduce"):
        build_wheelhouse.source_build_origin(filename, "a" * 64, lock)
    with pytest.raises(ValueError, match="not a pinned source build"):
        build_wheelhouse.source_build_origin("azazel_fabric-0.9.0rc6-py3-none-any.whl", locked, lock)


def test_the_mio_source_wheel_hash_is_reproduced_and_exactly_pinned():
    build = build_wheelhouse.SOURCE_BUILDS["azazel-mio"]
    lock = build_wheelhouse.parse_lock(ROOT / build_wheelhouse.LOCK)
    digest, = lock["azazel-mio==0.1.0.dev20261105+gite639a65"]
    assert digest == "2672b77909f15580215cf33c95d7bea0c863aeb45901231aca774e28f8682cce"
    for target in offline_bundle.TARGETS:
        target_lock = build_wheelhouse.parse_lock(ROOT / offline_bundle.target_lock(target))
        assert target_lock["azazel-mio==0.1.0.dev20261105+gite639a65"] == [digest]
    origin = build_wheelhouse.source_build_origin(
        "azazel_mio-0.1.0.dev20261105+gite639a65-py3-none-any.whl", digest, lock)
    assert build["commit"] in origin and "hash-pinned" in origin


def test_the_mio_source_checkout_is_archived_only_at_its_exact_commit(tmp_path, monkeypatch):
    build = build_wheelhouse.SOURCE_BUILDS["azazel-mio"]
    calls = []

    def fake_run(argv, *, env=None):
        calls.append(argv)
        if "rev-parse" in argv:
            assert argv[-1] == "HEAD^{commit}"
            return build["commit"] + "\n"
        if "status" in argv:
            return ""
        if "archive" in argv:
            output = next(a for a in argv if a.startswith("--output="))[len("--output="):]
            with tarfile.open(output, "w") as archive:
                data = b"[project]\n"
                info = tarfile.TarInfo("pyproject.toml")
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
        return ""

    monkeypatch.setattr(build_wheelhouse, "_run", fake_run)
    source = tmp_path / "checkout"
    source.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    tree = build_wheelhouse.fetch_source_build("azazel-mio", scratch,
                                               source_checkout=source)
    assert (tree / "pyproject.toml").read_bytes() == b"[project]\n"
    archive, = [argv for argv in calls if "archive" in argv]
    assert archive[-1] == build["commit"]
    assert not any("clone" in argv for argv in calls)


def test_source_archive_extraction_preserves_member_mtime(tmp_path):
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as stream:
        info = tarfile.TarInfo("src/module.py")
        data = b"VALUE = 1\n"
        info.size, info.mode, info.mtime = len(data), 0o644, 315532800
        stream.addfile(info, io.BytesIO(data))

    tree = tmp_path / "tree"
    tree.mkdir()
    build_wheelhouse._extract_regular_tar(archive, tree, directories=True)

    extracted = tree / "src/module.py"
    assert extracted.read_bytes() == b"VALUE = 1\n"
    assert extracted.stat().st_mtime == 315532800


def test_the_fabric_tree_is_archived_by_commit_with_normalised_modes(tmp_path, monkeypatch):
    build = build_wheelhouse.SOURCE_BUILDS["azazel-fabric"]
    calls = []

    def fake_run(argv, *, env=None):
        calls.append(argv)
        if "rev-parse" in argv:
            return build["commit"] + "\n"
        if "archive" in argv:
            output = next(a for a in argv if a.startswith("--output="))[len("--output="):]
            with tarfile.open(output, "w") as archive:
                data = b"[project]\n"
                info = tarfile.TarInfo("pyproject.toml")
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
        return ""

    monkeypatch.setattr(build_wheelhouse, "_run", fake_run)
    tree = build_wheelhouse.fetch_source_build("azazel-fabric", tmp_path)
    assert (tree / "pyproject.toml").read_bytes() == b"[project]\n"
    (archive,) = [argv for argv in calls if "archive" in argv]
    assert archive[-1] == build["commit"] and build["tag"] not in archive
    assert all("tar.umask=0022" in argv for argv in calls)
    assert "tar.umask=0022" in archive and archive[archive.index("tar.umask=0022") - 1] == "-c"


def test_the_lock_comment_names_the_source_build_pin():
    text = (ROOT / build_wheelhouse.LOCK).read_text(encoding="utf-8")
    for name, build in build_wheelhouse.SOURCE_BUILDS.items():
        pin = (f"{build['tag']} = {build['commit']}" if "tag" in build
               else f"commit {build['commit']}")
        assert f"# built from {build['repository']} {pin}\n" in text, name
        assert f"\n{name}=={build['version']} \\\n" in text


def test_a_fabric_tag_that_moved_off_the_pinned_commit_is_refused(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, *, env=None):
        calls.append(argv)
        return "1" * 40 + "\n" if "rev-parse" in argv else ""

    monkeypatch.setattr(build_wheelhouse, "_run", fake_run)
    with pytest.raises(ValueError, match="not the pinned"):
        build_wheelhouse.fetch_source_build("azazel-fabric", tmp_path)
    assert not any("archive" in argv for argv in calls), "a moved tag was archived"
    clone = calls[0]
    assert "--bare" in clone and clone[-2] == build_wheelhouse.SOURCE_BUILDS["azazel-fabric"]["repository"]


def test_the_git_steps_read_no_user_or_system_configuration():
    env = build_wheelhouse._git_env()
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_a_lock_entry_the_bundle_does_not_carry_is_refused():
    checked = [{"requirement": "dbus-next==0.2.3", "pinned_by": "x"}]
    offline_bundle.check_lock_is_carried(checked, {"dbus-next==0.2.3": ["0" * 64]})
    with pytest.raises(BundleRefused, match="azazel-fabric==0.10.0"):
        offline_bundle.check_lock_is_carried(
            checked, {"dbus-next==0.2.3": ["0" * 64], "azazel-fabric==0.10.0": ["1" * 64]})


def test_install_refuses_a_bundle_without_the_locked_fabric_before_any_venv(built, tmp_path, monkeypatch):
    import platform

    monkeypatch.setattr(offline_bundle, "_require_root", lambda: None)
    target = offline_bundle.TARGETS[build_wheelhouse.TARGET]
    monkeypatch.setitem(target, "architecture", platform.machine())
    monkeypatch.setitem(target, "python_version", tuple(sys.version_info[:2]))
    if sys.implementation.name != "cpython":
        pytest.skip("the interpreter probe expects CPython")
    _lock, versions = offline_bundle.reviewed_pins()
    pins = ({"azazel-fabric==0.10.0": ["0" * 64]}, versions)
    with pytest.raises(BundleRefused, match="does not carry"):
        offline_bundle.install(built[2], tmp_path / "out", tmp_path / "venv", Path(sys.executable), pins=pins)
    with pytest.raises(BundleRefused, match="does not carry"):
        offline_bundle.extract_and_verify(built[2], tmp_path / "v", pins=pins)
    assert not (tmp_path / "v").exists()
    assert not (tmp_path / "venv").exists()
    assert not (tmp_path / "out").exists(), "a refused install left its extracted tree"


# -- the Edge slot is per target CPU (S-11, ADR-0005 amendment of 2026-10-30) --


def _pin_named(monkeypatch, edge: Path, name: str) -> None:
    """A reviewed pin of the artifact file ``name`` in ``edge``, for any target."""

    monkeypatch.setattr(offline_bundle, "reviewed_edge_digest", lambda root=None, target=None: (
        hashlib.sha256((edge / name).read_bytes()).hexdigest(), name))


@pytest.mark.parametrize("target,cpu", [("debian-13-x86_64-cp313", "x86_64"),
                                        ("debian-13-aarch64-cp313", "aarch64")])
def test_each_target_accepts_its_own_cpus_edge_package(tmp_path, monkeypatch, target, cpu):
    """On any build host: the CPU checked is the target's, not this machine's."""

    edge = _edge_package(tmp_path / "edge", cpu=cpu)
    _pin_edge(monkeypatch, edge, cpu)
    report = offline_bundle.verify_edge_slot(edge, target)
    assert report["architecture"] == cpu and report["admitted"] is False
    assert report["checks"]["package_present"] == "passed"


@pytest.mark.parametrize("target,other", [("debian-13-x86_64-cp313", "aarch64"),
                                          ("debian-13-aarch64-cp313", "x86_64")])
def test_a_target_refuses_the_other_cpus_edge_package(tmp_path, monkeypatch, target, other):
    from azazel_nexus.edge_package import PINS

    edge = _edge_package(tmp_path / "edge", cpu=other)
    _pin_named(monkeypatch, edge, PINS[other].artifact_name)
    with pytest.raises(BundleRefused, match="must hold exactly"):
        offline_bundle.verify_edge_slot(edge, target)


@pytest.mark.parametrize("target,cpu,other", [("debian-13-x86_64-cp313", "x86_64", "aarch64"),
                                              ("debian-13-aarch64-cp313", "aarch64", "x86_64")])
def test_a_target_refuses_the_other_cpus_binary_under_its_name(tmp_path, monkeypatch, target, cpu, other):
    """Named and described for the target, carrying the other CPU's binary."""

    edge = _edge_package(tmp_path / "edge", cpu=cpu, binary_cpu=other)
    _pin_edge(monkeypatch, edge, cpu)
    with pytest.raises(BundleRefused, match=f"package_present is failed.*says {other}"):
        offline_bundle.verify_edge_slot(edge, target)


def test_each_target_reads_only_its_own_edge_artifact_pin(tmp_path):
    lab, base = "debian-13-aarch64-cp313", "debian-13-x86_64-cp313"
    assert offline_bundle.target_edge_artifact_pin(base) == offline_bundle.EDGE_ARTIFACT_PIN
    assert offline_bundle.target_edge_artifact_pin(lab) != offline_bundle.EDGE_ARTIFACT_PIN
    pin = tmp_path / offline_bundle.target_edge_artifact_pin(lab)
    pin.parent.mkdir(parents=True)
    pin.write_text("b" * 64 + "  azazel-edge-core-0.1.0-aarch64.tar.gz\n")
    assert offline_bundle.reviewed_edge_digest(tmp_path, lab) == ("b" * 64, "azazel-edge-core-0.1.0-aarch64.tar.gz")
    assert offline_bundle.reviewed_edge_digest(tmp_path, base) is None
    with pytest.raises(BundleRefused, match="not a declared target"):
        offline_bundle.reviewed_edge_digest(tmp_path, "debian-13-riscv64-cp313")


def test_the_shipped_lab_pin_names_the_aarch64_artifact_and_no_baseline_pin_ships():
    from azazel_nexus.edge_package import PINS

    lab = offline_bundle.reviewed_edge_digest(target="debian-13-aarch64-cp313")
    assert lab is not None and lab[1] == PINS["aarch64"].artifact_name
    assert offline_bundle.reviewed_edge_digest(target="debian-13-x86_64-cp313") is None


def test_a_lab_pin_never_admits_an_x86_64_package_on_the_baseline(tmp_path, monkeypatch):
    """The lab pin's file is the lab target's; the baseline still has none."""

    edge = _edge_package(tmp_path / "edge", cpu="x86_64")
    with pytest.raises(BundleRefused, match="pins no Edge artifact"):
        offline_bundle.verify_edge_slot(edge, "debian-13-x86_64-cp313")
