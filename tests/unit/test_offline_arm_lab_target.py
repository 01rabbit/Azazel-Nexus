"""The Arm (aarch64) offline-bundle target is a lab target, never the baseline (ADR-0005).

Unit tests over the declared tables, the two locks and synthetic bundles. The
pip/venv steps are not run here; the native aarch64 build and the
``--network none`` install are recorded under docs/evidence/ as a container
rehearsal, which is neither Arm hardware nor an Arm VM.
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

import pytest

from azazel_nexus import platform_profile
from azazel_nexus_runtime import install_platform
from azazel_nexus_runtime.platform_observation import HostObservation
from tests.unit.test_offline_bundle import _repo
from tests.unit.test_offline_install_bundle import _wheelhouse
from tools import build_wheelhouse, offline_bundle
from tools.build_offline_bundle import build_install_bundle, repository_identity
from tools.offline_bundle import BundleRefused

ROOT = Path(__file__).resolve().parents[2]
LAB = "debian-13-aarch64-cp313"
BASELINE = offline_bundle.BASELINE_TARGET
NATIVE = ("pydantic-core", "pyyaml")


# -- the declared targets agree with the reviewed platform profiles ----------


def test_the_targets_are_exactly_the_baseline_and_the_arm_lab_target():
    assert set(offline_bundle.TARGETS) == {BASELINE, LAB}
    assert BASELINE == build_wheelhouse.TARGET == "debian-13-x86_64-cp313"
    baselines = [name for name, t in offline_bundle.TARGETS.items()
                 if t["purpose"] == platform_profile.PURPOSE_DEPLOYMENT_BASELINE]
    assert baselines == [BASELINE]


@pytest.mark.parametrize("name", sorted(offline_bundle.TARGETS))
def test_each_target_is_its_reviewed_profile(name):
    """Purpose, CPU spellings, OS and Python tag come from platform_profile, not from here."""

    target = offline_bundle.TARGETS[name]
    profile = platform_profile.profile(target["platform_profile_id"])
    assert target["purpose"] == profile.purpose
    assert target["architecture"] == platform_profile.kernel_name(profile.architecture)
    assert target["deb_architectures"] == (platform_profile.debian_name(profile.architecture), "all")
    assert target["os"] == f"{profile.os_id}-{profile.os_version_id}"
    assert target["python_tag"] == profile.python_tag
    assert target["python_version"] == (3, int(profile.python_tag[3:]))
    assert target["lock"] == Path(f"packaging/offline/requirements-{target['architecture']}-cp313.lock")
    assert name == f"debian-13-{target['architecture']}-{target['python_tag']}"


def test_the_arm_target_is_the_lab_profile_and_never_the_deployment_baseline():
    target = offline_bundle.TARGETS[LAB]
    assert target["platform_profile_id"] == platform_profile.ARM64_LAB.profile_id
    assert target["purpose"] == platform_profile.PURPOSE_LAB_SOFTWARE_VERIFICATION
    assert offline_bundle.TARGETS[BASELINE]["platform_profile_id"] == \
        platform_profile.DEPLOYMENT_BASELINE.profile_id
    lab = platform_profile.profile(target["platform_profile_id"])
    for use in sorted(platform_profile.PRODUCTION_USES):
        with pytest.raises(platform_profile.PlatformRefused) as refused:
            platform_profile.require_deployment_baseline(lab, use)
        assert refused.value.reason == platform_profile.LAB_PROFILE_NOT_FOR_PRODUCTION


def _host(machine: str, dpkg: str) -> HostObservation:
    return HostObservation(
        sysname="Linux", release="6.12.0", machine=machine, os_id="debian", os_version_id="13",
        soabi=f"cpython-313-{machine}-linux-gnu", lp64=True, byteorder="little",
        dpkg_architecture=dpkg,
    )


@pytest.mark.parametrize("name, machine, dpkg", [
    (BASELINE, "x86_64", "amd64"), (LAB, "aarch64", "arm64"),
])
def test_install_sh_identifies_the_same_profile_and_purpose_as_the_target(name, machine, dpkg):
    """install.sh's platform evaluation (#373) and the bundle target name one profile."""

    os_release = install_platform.parse_os_release('ID=debian\nVERSION_ID="13"\n')
    selected = install_platform.evaluate_install_architecture(
        install_platform.select_install_profile(os_release), _host(machine, dpkg))
    target = offline_bundle.TARGETS[name]
    assert (selected.profile_id, selected.purpose) == (target["platform_profile_id"], target["purpose"])


# -- the aarch64 lock -----------------------------------------------------------


def _locks():
    return (build_wheelhouse.parse_lock(ROOT / offline_bundle.target_lock(BASELINE)),
            build_wheelhouse.parse_lock(ROOT / offline_bundle.target_lock(LAB)))


def test_the_aarch64_lock_pins_what_the_pyproject_files_and_uv_lock_need():
    baseline, lab = _locks()
    assert set(lab) == set(baseline) == build_wheelhouse.bundled_requirements(ROOT)
    for requirement, hashes in lab.items():
        assert len(hashes) == 1, requirement


def test_only_the_native_wheels_differ_between_the_locks():
    baseline, lab = _locks()
    for requirement in lab:
        name = requirement.partition("==")[0]
        if name in NATIVE:
            assert set(lab[requirement]).isdisjoint(baseline[requirement]), requirement
        else:
            assert lab[requirement] == baseline[requirement], requirement


def test_each_aarch64_lock_entry_names_one_file_that_fits_the_lab_target_only():
    text = (ROOT / offline_bundle.target_lock(LAB)).read_text(encoding="utf-8")
    files = re.findall(r"^# (\S+\.whl)$", text, flags=re.MULTILINE)
    lab, baseline = offline_bundle.TARGETS[LAB], offline_bundle.TARGETS[BASELINE]
    names = set()
    for filename in files:
        parts = offline_bundle.parse_wheel_name(filename)
        names.add(offline_bundle.canonical_name(parts["name"]))
        assert offline_bundle.wheel_fits_target(filename, lab), filename
        if offline_bundle.canonical_name(parts["name"]) in NATIVE:
            assert "aarch64" in parts["plat"] and parts["abi"] == "cp313", filename
            assert not offline_bundle.wheel_fits_target(filename, baseline), filename
        else:
            assert parts["plat"] == "any", filename
    assert names == {r.partition("==")[0] for r in _locks()[1]}
    assert "LAB TARGET" in text and "ADR-0005" in text


def test_the_source_built_fabric_wheel_is_pinned_by_the_same_hash_on_both_targets():
    baseline, lab = _locks()
    for name, build in build_wheelhouse.SOURCE_BUILDS.items():
        requirement = f"{name}=={build['version']}"
        assert lab[requirement] == baseline[requirement]


def test_an_undeclared_target_has_no_lock():
    with pytest.raises(BundleRefused, match="not a declared target"):
        offline_bundle.target_lock("debian-13-riscv64-cp313")


# -- bundles: the lock is the manifest target's, and the purpose is reported --


def _lab_repo(root: Path) -> Path:
    """The fixture repository, plus the empty aarch64 lock the lab build reads."""

    _repo(root)
    (root / "packaging/offline/requirements-aarch64-cp313.lock").write_bytes(b"")
    subprocess.run(["git", "add", "packaging/offline/requirements-aarch64-cp313.lock"], cwd=root, check=True)
    subprocess.run(["git", "-c", "user.name=Bundle Test", "-c", "user.email=bundle-test@example.invalid",
                    "commit", "-qm", "aarch64 lock"], cwd=root, check=True)
    return root


def _lab_wheelhouse(tmp_path: Path, commit: str) -> Path:
    directory = _wheelhouse(tmp_path / "wheelhouse", commit, (("dbus-next", "0.2.3"),))
    record = json.loads((directory / "wheelhouse.json").read_text(encoding="utf-8"))
    record["target"] = LAB
    (directory / "wheelhouse.json").write_text(json.dumps(record), encoding="utf-8")
    return directory


@pytest.fixture
def lab_bundle(tmp_path, monkeypatch):
    """A lab-target bundle of the two fake Nexus wheels and a fake dbus-next."""

    real = offline_bundle.reviewed_pins
    seen = []

    def pins(root=None, target=BASELINE):
        seen.append(target)
        lock, versions = real(target=target)
        digest = hashlib.sha256(next((tmp_path / "wheelhouse").glob("dbus_next*.whl")).read_bytes()).hexdigest()
        # Only dbus-next is carried; the lock's other entries would be refused as missing.
        return {"dbus-next==0.2.3": [digest]} if "dbus-next==0.2.3" in lock else {}, versions

    monkeypatch.setattr(offline_bundle, "reviewed_pins", pins)
    root = _lab_repo(tmp_path / "repo")
    wheelhouse = _lab_wheelhouse(tmp_path, repository_identity(root)["commit"])
    output = tmp_path / "lab.tar.gz"
    document = build_install_bundle(root, output, wheelhouse=wheelhouse, target=LAB)
    return document, output, seen


def test_a_lab_bundle_is_verified_against_the_aarch64_lock_and_says_it_is_a_lab_target(lab_bundle, tmp_path):
    document, output, seen = lab_bundle
    assert document["target"] == LAB
    _, report = offline_bundle.extract_and_verify(output, tmp_path / "out")
    assert seen == [LAB]
    assert report["target"] == LAB
    assert report["purpose"] == "lab-software-verification"
    assert report["platform_profile_id"] == "debian-13-arm64-cp313-lab"
    assert "never hardware-gate evidence" in report["purpose_note"]
    assert {"requirement": "dbus-next==0.2.3",
            "pinned_by": "packaging/offline/requirements-aarch64-cp313.lock"} in report["wheels"]
    recheck = offline_bundle.recheck_tree(tmp_path / "out", expected_manifest_sha256=report["manifest_sha256"])
    assert recheck["purpose"] == "lab-software-verification"
    assert "purpose_note" in recheck


def test_a_baseline_report_carries_the_baseline_purpose_and_no_lab_note():
    fields = offline_bundle.target_purpose(BASELINE)
    assert fields == {"platform_profile_id": "debian-13-amd64-cp313", "purpose": "deployment-baseline"}


def test_a_lab_wheelhouse_is_not_a_baseline_bundle_by_default(tmp_path):
    root = _lab_repo(tmp_path / "repo")
    wheelhouse = _lab_wheelhouse(tmp_path, repository_identity(root)["commit"])
    with pytest.raises(ValueError, match="not a wheelhouse for the debian-13-x86_64-cp313 target"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse)
    assert not (tmp_path / "b.tar.gz").exists()


def test_a_baseline_wheelhouse_is_not_a_lab_bundle(tmp_path):
    root = _lab_repo(tmp_path / "repo")
    wheelhouse = _wheelhouse(tmp_path / "wheelhouse", repository_identity(root)["commit"])
    with pytest.raises(ValueError, match="not a wheelhouse for the debian-13-aarch64-cp313 target"):
        build_install_bundle(root, tmp_path / "b.tar.gz", wheelhouse=wheelhouse, target=LAB)


@pytest.mark.parametrize("filename, target", [
    ("azazel_nexus_runtime-0.0.1.dev0-cp313-cp313-linux_x86_64.whl", LAB),
    ("pyyaml-6.0.3-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl", LAB),
    ("azazel_nexus_runtime-0.0.1.dev0-cp313-cp313-linux_aarch64.whl", BASELINE),
    ("pydantic_core-2.46.5-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl", BASELINE),
])
def test_relabelling_a_bundle_to_the_other_target_is_refused_by_its_native_wheels(tmp_path, filename, target):
    parts = offline_bundle.parse_wheel_name(filename)
    entry = {"path": "wheels/" + filename, "kind": "wheel", "sha256": "0" * 64, "size": 1,
             "mode": "0644", "source": "test",
             "requirement": f"{offline_bundle.canonical_name(parts['name'])}=={parts['version']}"}
    with pytest.raises(BundleRefused, match="does not fit the declared target"):
        offline_bundle._validate_wheel_entry(entry, offline_bundle.TARGETS[target])


# -- the wheelhouse builder and the installer refuse the other CPU ------------


def test_the_wheelhouse_builder_refuses_a_host_that_is_not_the_named_target(tmp_path):
    this = (platform.machine(), sys.version_info[:2])
    for name, target in offline_bundle.TARGETS.items():
        if (target["architecture"], target["python_version"]) == this:
            continue
        with pytest.raises(ValueError, match=f"the {name} wheelhouse must be built on"):
            build_wheelhouse.build_wheelhouse(ROOT, tmp_path / name, target_name=name)
        assert not (tmp_path / name).exists()


def test_the_wheelhouse_cli_offers_exactly_the_declared_targets(capsys):
    with pytest.raises(SystemExit):
        build_wheelhouse.main(["--output", "x", "--target", "debian-13-riscv64-cp313"])
    error = capsys.readouterr().err
    for name in offline_bundle.TARGETS:
        assert name in error


class _Probe:
    def __init__(self, stdout: str) -> None:
        self.returncode, self.stdout, self.stderr = 0, stdout, ""


@pytest.mark.parametrize("name, observed", [
    (LAB, ("debian-13-amd64-cp313", "deployment-baseline")),
    (BASELINE, ("debian-13-arm64-cp313-lab", "lab-software-verification")),
])
def test_install_refuses_a_host_whose_observed_profile_is_not_the_target(tmp_path, monkeypatch, name, observed):
    """The install record's purpose is the host's observation, not the manifest's word."""

    target = offline_bundle.TARGETS[name]
    probe = f"{target['architecture']} cpython 3 13\n"
    monkeypatch.setattr(offline_bundle.subprocess, "run", lambda *a, **k: _Probe(probe))
    monkeypatch.setattr(offline_bundle, "_create_private_dir", lambda path: None)
    monkeypatch.setattr(offline_bundle, "_run", lambda argv: None)
    monkeypatch.setattr(offline_bundle, "pip_install_offline", lambda *a: None)
    monkeypatch.setattr(offline_bundle, "_observe_installed_platform", lambda venv_python: observed)
    extracted = offline_bundle.Extracted(root=tmp_path, manifest={"target": name, "artifacts": []},
                                         manifest_bytes=b"", signature=None)
    with pytest.raises(BundleRefused, match="observes as platform profile"):
        offline_bundle._install_verified(extracted, {}, tmp_path, tmp_path / "venv", Path("/usr/bin/python3"))


def test_install_records_the_observed_profile_when_it_matches(tmp_path, monkeypatch):
    target = offline_bundle.TARGETS[LAB]
    monkeypatch.setattr(offline_bundle.subprocess, "run", lambda *a, **k: _Probe("aarch64 cpython 3 13\n"))
    monkeypatch.setattr(offline_bundle, "_create_private_dir", lambda path: None)
    monkeypatch.setattr(offline_bundle, "_run", lambda argv: None)
    monkeypatch.setattr(offline_bundle, "pip_install_offline", lambda *a: None)
    monkeypatch.setattr(offline_bundle, "_observe_installed_platform",
                        lambda venv_python: (target["platform_profile_id"], target["purpose"]))
    extracted = offline_bundle.Extracted(root=tmp_path, manifest={"target": LAB, "artifacts": []},
                                         manifest_bytes=b"", signature=None)
    report: dict = {}
    offline_bundle._install_verified(extracted, report, tmp_path, tmp_path / "venv", Path("/usr/bin/python3"))
    assert report["install"]["observed_platform"] == {
        "platform_profile_id": "debian-13-arm64-cp313-lab", "purpose": "lab-software-verification"}


def test_the_installed_platform_probe_refuses_an_unidentified_host(tmp_path):
    fake = tmp_path / "python"
    fake.write_text("#!/bin/sh\necho 'PlatformRefused: UNKNOWN_ARCHITECTURE' >&2\nexit 1\n")
    fake.chmod(0o755)
    with pytest.raises(BundleRefused, match="did not identify a reviewed platform profile"):
        offline_bundle._observe_installed_platform(fake)


# -- no production reader takes an offline-bundle record -----------------------


def test_no_production_module_reads_an_offline_bundle_or_wheelhouse_record():
    """The bundle, wheelhouse and install reports have no consumer that could accept them."""

    pattern = re.compile(r"offline-bundle-report|wheelhouse\.json|azazel-nexus-wheelhouse|"
                         r"prototype-offline-install-evidence|requirements-aarch64")
    hits = []
    for tree in ("src", "runtime/src"):
        for path in sorted((ROOT / tree).rglob("*.py")):
            if pattern.search(path.read_text(encoding="utf-8")):
                hits.append(path.relative_to(ROOT).as_posix())
    assert hits == []
