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


def _wheelhouse(directory: Path, commit: str) -> Path:
    directory.mkdir()
    wheels = [
        (_wheel(directory, "azazel-nexus", "0.0.1.dev0", "fake_azazel_nexus"), "built:test"),
        (_wheel(directory, "azazel-nexus-runtime", "0.0.1.dev0", "fake_azazel_runtime"), "built:test"),
        (_wheel(directory, "dbus-next", "0.2.3", "fake_dbus_next"), "pypi:test"),
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


def _edge_package(directory: Path, *, observe_only: bool = True) -> Path:
    from azazel_nexus.edge_package import PIN

    directory.mkdir()
    components = {
        "bin/azazel-edge-core": b"#!/bin/sh\necho edge\n",
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
def built(tmp_path: Path):
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
    with tarfile.open(path, "w:gz", format=tarfile.GNU_FORMAT) as archive:
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
    assert report["counts"]["wheel"] == 3


def test_the_same_inputs_make_identical_bundle_bytes(built, tmp_path):
    root, wheelhouse, bundle, _ = built
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
    victim = next(wheelhouse.glob("dbus_next*.whl"))
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
        (lambda d: d.update(target="debian-13-aarch64-cp313"), "not a declared target"),
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
    _refused(tmp_path, corrupt, "could not be read|missing")


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


def test_an_edge_package_slot_is_verified_with_the_edge_checks(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    edge = _edge_package(tmp_path / "edge-in")
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


def test_an_enforcing_edge_package_is_refused(tmp_path):
    edge = _edge_package(tmp_path / "edge", observe_only=False)
    with pytest.raises(BundleRefused, match="package_present"):
        offline_bundle.verify_edge_slot(edge)


def test_an_edge_artifact_that_does_not_match_its_manifest_is_refused(tmp_path):
    from azazel_nexus.edge_package import PIN

    edge = _edge_package(tmp_path / "edge")
    (edge / PIN.artifact_name).write_bytes(b"replaced")
    with pytest.raises(BundleRefused, match="digest_matches"):
        offline_bundle.verify_edge_slot(edge)


def test_an_edge_slot_with_an_extra_file_is_refused(tmp_path):
    edge = _edge_package(tmp_path / "edge")
    (edge / "extra.sh").write_bytes(b"#!/bin/sh\n")
    with pytest.raises(BundleRefused, match="exactly"):
        offline_bundle.verify_edge_slot(edge)


def test_deb_slot_records_and_rechecks_control_fields(tmp_path):
    root = _repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    debs = tmp_path / "debs"
    debs.mkdir()
    _deb(debs / "iproute2_6.15.0-1_amd64.deb")
    document = build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse,
                                    debs=debs, deb_source="test snapshot")
    entry = next(e for e in document["artifacts"] if e["kind"] == "deb")
    assert (entry["package"], entry["version"], entry["architecture"]) == ("iproute2", "6.15.0-1", "amd64")
    report = verify_extracted(extract_bundle(tmp_path / "b.tar.gz", tmp_path / "out"))
    assert report["slots"]["deb"]["installed"] is False
    assert report["slots"]["deb"]["packages"][0]["package"] == "iproute2"


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


def test_model_and_knowledge_slots_are_carried_not_admitted(tmp_path):
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
    assert set(lock) == build_wheelhouse.declared_runtime_dependencies(ROOT)
    assert all(len(hashes) == 1 for hashes in lock.values())


def test_each_locked_wheel_named_in_the_lock_fits_the_target():
    text = (ROOT / build_wheelhouse.LOCK).read_text(encoding="utf-8")
    named = [line.strip("# \n") for line in text.splitlines() if line.strip().endswith(".whl")]
    assert len(named) == 2
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
         "import fake_azazel_nexus, fake_azazel_runtime, fake_dbus_next; print('ok')"],
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
    with pytest.raises(BundleRefused, match="exited"):
        offline_bundle.pip_install_offline(venv_python, extracted.root / "wheels", requirements)


def test_install_refuses_an_interpreter_that_is_not_the_target(built, tmp_path):
    probe = (offline_bundle.TARGETS[build_wheelhouse.TARGET]["architecture"],
             offline_bundle.TARGETS[build_wheelhouse.TARGET]["python_version"])
    import platform

    if (platform.machine(), sys.version_info[:2]) == probe:
        pytest.skip("this interpreter is the target; the refusal is not reachable here")
    with pytest.raises(BundleRefused, match="the bundle targets"):
        offline_bundle.install(built[2], tmp_path / "out", tmp_path / "venv", Path(sys.executable))
    assert not (tmp_path / "venv").exists()


def test_install_refuses_an_existing_venv(built, tmp_path):
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
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools" / "offline_bundle.py"), "verify",
         "--bundle", str(built[2]), "--into", str(tmp_path / "out")],
        capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["bundle_authenticated"] is False


def test_gzip_and_tar_noise_is_not_read_as_a_manifest(tmp_path):
    bundle = tmp_path / "noise.tar.gz"
    bundle.write_bytes(gzip.compress(os.urandom(4096)))
    _refused(tmp_path, bundle, "could not be read|first member")
