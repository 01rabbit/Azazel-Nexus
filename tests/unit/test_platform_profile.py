"""One table of CPU names, and a lab profile that cannot pass as production (ADR-0003).

These run unchanged on either CPU: nothing here reads the host. The same
inputs give the same outputs on amd64 and arm64, which is what "the core does
not branch on the CPU" means for this module.
"""

from __future__ import annotations

import typing

import pytest

from azazel_nexus import compatibility, hil_preflight, model_runtime
from azazel_nexus import platform_profile as pp

KNOWN = {
    # canonical: kernel, debian, systemd, multiarch, fabric
    "amd64": ("x86_64", "amd64", "x86-64", "x86_64-linux-gnu", "amd64"),
    "arm64": ("aarch64", "arm64", "arm64", "aarch64-linux-gnu", "arm64"),
}

# Spellings that look close to a known name and must not be folded into it.
NEAR_MISSES = ["", "X86_64", "x86-64 ", " aarch64", "AARCH64", "ARM64", "AMD64", "x64",
               "i686", "armv7l", "armv8l", "aarch64_be", "arm64e", "riscv64", "ppc64le",
               "s390x", "amd64\n", "x86_64\x00", "unknown"]


def test_the_canonical_names_are_fabrics():
    assert pp.ARCHITECTURES == ("amd64", "arm64")


def test_fabric_literal_matches_when_fabric_is_installed():
    models = pytest.importorskip("azazel_fabric.provisioning_contracts.models")
    assert set(typing.get_args(models.Architecture)) == set(pp.ARCHITECTURES)


@pytest.mark.parametrize("architecture", sorted(KNOWN))
def test_every_boundary_round_trips(architecture):
    for boundary, name in zip(pp.BOUNDARIES, KNOWN[architecture]):
        assert pp.to_boundary(architecture, boundary) == name
        assert pp.from_boundary(boundary, name) == architecture
    assert pp.kernel_name(architecture) == KNOWN[architecture][0]
    assert pp.debian_name(architecture) == KNOWN[architecture][1]
    assert pp.systemd_name(architecture) == KNOWN[architecture][2]
    assert pp.fabric_name(architecture) == KNOWN[architecture][4]


def test_boundary_readers_take_only_their_own_spelling():
    """``x86-64`` is systemd's and ``x86_64`` the kernel's; neither reader
    accepts the other's, so a value from the wrong boundary is visible."""

    with pytest.raises(pp.PlatformRefused):
        pp.from_boundary("kernel", "amd64")
    with pytest.raises(pp.PlatformRefused):
        pp.from_boundary("systemd", "x86_64")
    with pytest.raises(pp.PlatformRefused):
        pp.from_boundary("debian", "aarch64")
    with pytest.raises(pp.PlatformRefused) as refused:
        pp.from_boundary("rpm", "x86_64")
    assert refused.value.reason == pp.UNKNOWN_BOUNDARY


@pytest.mark.parametrize("raw", NEAR_MISSES + [None, 64, b"x86_64"])
def test_unknown_names_are_refused_with_a_reason(raw):
    readers = [pp.from_machine, pp.normalize_machine, pp.canonical]
    readers += [lambda value, b=b: pp.from_boundary(b, value) for b in pp.BOUNDARIES]
    for reader in readers:
        with pytest.raises(pp.PlatformRefused) as refused:
            reader(raw)
        assert refused.value.reason == pp.UNKNOWN_ARCHITECTURE
        assert refused.value.value == raw


def test_machine_reader_keeps_the_spellings_its_callers_accepted():
    assert pp.from_machine("x86_64") == "amd64"
    assert pp.from_machine("aarch64") == "arm64"
    assert pp.from_machine("arm64") == "arm64"
    # Not accepted before this module existed, and still not: no widening.
    with pytest.raises(pp.PlatformRefused):
        pp.from_machine("amd64")
    assert {pp.normalize_machine(n) for n in ("x86_64", "amd64")} == {"amd64"}
    assert {pp.normalize_machine(n) for n in ("aarch64", "arm64")} == {"arm64"}
    with pytest.raises(pp.PlatformRefused):
        pp.normalize_machine("x86-64")


def test_lp64_set_is_the_kernel_names_that_were_hard_coded():
    assert pp.LP64_REVIEWED_KERNEL_MACHINES == frozenset({"x86_64", "aarch64"})


def test_reviewed_profiles_and_their_purposes():
    assert set(pp.REVIEWED_PROFILES) == {"debian-13-amd64-cp313", "debian-13-arm64-cp313-lab"}
    amd = pp.REVIEWED_PROFILES["debian-13-amd64-cp313"]
    arm = pp.REVIEWED_PROFILES["debian-13-arm64-cp313-lab"]
    assert amd is pp.DEPLOYMENT_BASELINE and amd.purpose == pp.PURPOSE_DEPLOYMENT_BASELINE
    assert arm is pp.ARM64_LAB and arm.purpose == pp.PURPOSE_LAB_SOFTWARE_VERIFICATION
    assert (amd.architecture, amd.soabi) == ("amd64", "cpython-313-x86_64-linux-gnu")
    assert (arm.architecture, arm.soabi) == ("arm64", "cpython-313-aarch64-linux-gnu")
    assert [p for p in pp.REVIEWED_PROFILES.values() if p.is_deployment_baseline] == [amd]


def test_the_deployment_baseline_is_still_adr_0002():
    """The profile does not move the baseline; the two existing constants are
    unchanged and agree with it."""

    base = pp.DEPLOYMENT_BASELINE
    assert hil_preflight.BASELINE_ARCHITECTURE == "x86_64" == pp.kernel_name(base.architecture)
    assert compatibility.ADMITTED_ARCHITECTURE == "x86_64" == pp.kernel_name(base.architecture)
    assert (hil_preflight.BASELINE_OS_ID, hil_preflight.BASELINE_OS_VERSION_ID) == (
        base.os_id, base.os_version_id)


def test_the_baseline_and_each_cpus_purpose_come_from_the_reviewed_table():
    """ADR-0006: `compatibility.ADMITTED_ARCHITECTURE` is read from here."""

    assert pp.deployment_baseline_profile() is pp.DEPLOYMENT_BASELINE
    assert pp.profile_for_architecture("amd64") is pp.DEPLOYMENT_BASELINE
    assert pp.profile_for_architecture("arm64") is pp.ARM64_LAB
    assert pp.purpose_for_architecture("amd64") == pp.PURPOSE_DEPLOYMENT_BASELINE
    assert pp.purpose_for_architecture("arm64") == pp.PURPOSE_LAB_SOFTWARE_VERIFICATION


@pytest.mark.parametrize("raw", ["x86_64", "aarch64", *NEAR_MISSES, None, 1])
def test_a_purpose_is_given_only_to_a_canonical_name(raw):
    with pytest.raises(pp.PlatformRefused) as caught:
        pp.purpose_for_architecture(raw)
    assert caught.value.reason == pp.UNKNOWN_ARCHITECTURE


def test_a_table_with_two_baselines_or_two_profiles_for_one_cpu_is_refused(monkeypatch):
    second = pp.PlatformProfile(
        profile_id="debian-13-amd64-cp313-b", purpose=pp.PURPOSE_DEPLOYMENT_BASELINE,
        os_id="debian", os_version_id="13", architecture="amd64", python_tag="cp313",
        soabi="cpython-313-x86_64-linux-gnu", features=pp.DEPLOYMENT_BASELINE.features)
    monkeypatch.setattr(pp, "REVIEWED_PROFILES", {**pp.REVIEWED_PROFILES,
                                                  second.profile_id: second})
    for call in (pp.deployment_baseline_profile, lambda: pp.purpose_for_architecture("amd64")):
        with pytest.raises(pp.PlatformRefused) as caught:
            call()
        assert caught.value.reason == pp.UNREVIEWED_COMBINATION
    assert pp.purpose_for_architecture("arm64") == pp.PURPOSE_LAB_SOFTWARE_VERIFICATION
    monkeypatch.setattr(pp, "REVIEWED_PROFILES", {pp.ARM64_LAB.profile_id: pp.ARM64_LAB})
    with pytest.raises(pp.PlatformRefused):
        pp.deployment_baseline_profile()


@pytest.mark.parametrize("bad", [
    dict(purpose="production"),
    dict(architecture="x86_64"),
    dict(soabi="cpython-313-aarch64-linux-gnu"),
    dict(profile_id="debian-13-amd64-cp313-lab"),
])
def test_a_profile_that_contradicts_itself_is_refused(bad):
    fields = dict(profile_id="debian-13-amd64-cp313", purpose=pp.PURPOSE_DEPLOYMENT_BASELINE,
                  os_id="debian", os_version_id="13", architecture="amd64", python_tag="cp313",
                  soabi="cpython-313-x86_64-linux-gnu", features=frozenset())
    with pytest.raises(pp.PlatformRefused):
        pp.PlatformProfile(**(fields | bad))


def test_a_lab_profile_id_names_itself():
    with pytest.raises(pp.PlatformRefused):
        pp.PlatformProfile(
            profile_id="debian-13-arm64-cp313", purpose=pp.PURPOSE_LAB_SOFTWARE_VERIFICATION,
            os_id="debian", os_version_id="13", architecture="arm64", python_tag="cp313",
            soabi="cpython-313-aarch64-linux-gnu", features=frozenset())


@pytest.mark.parametrize("machine,soabi,expected", [
    ("x86_64", "cpython-313-x86_64-linux-gnu", "debian-13-amd64-cp313"),
    ("aarch64", "cpython-313-aarch64-linux-gnu", "debian-13-arm64-cp313-lab"),
])
def test_select_profile_matches_exactly(machine, soabi, expected):
    selected = pp.select_profile(os_id="debian", os_version_id="13", machine=machine, soabi=soabi)
    assert selected.profile_id == expected


@pytest.mark.parametrize("facts,reason", [
    (dict(machine="armv7l"), pp.UNKNOWN_ARCHITECTURE),
    (dict(machine="amd64"), pp.UNKNOWN_ARCHITECTURE),
    (dict(machine="arm64"), pp.UNKNOWN_ARCHITECTURE),
    (dict(os_id="ubuntu"), pp.UNREVIEWED_OS),
    (dict(os_version_id="12"), pp.UNREVIEWED_OS),
    (dict(os_version_id="13.1"), pp.UNREVIEWED_OS),
    (dict(soabi="cpython-312-x86_64-linux-gnu"), pp.UNREVIEWED_PYTHON_ABI),
    (dict(soabi="cpython-313-aarch64-linux-gnu"), pp.UNREVIEWED_PYTHON_ABI),
    (dict(soabi="cpython-313t-x86_64-linux-gnu"), pp.UNREVIEWED_PYTHON_ABI),
])
def test_select_profile_refuses_with_the_first_unreviewed_field(facts, reason):
    observed = dict(os_id="debian", os_version_id="13", machine="x86_64",
                    soabi="cpython-313-x86_64-linux-gnu") | facts
    with pytest.raises(pp.PlatformRefused) as refused:
        pp.select_profile(**observed)
    assert refused.value.reason == reason


@pytest.mark.parametrize("use", sorted(pp.PRODUCTION_USES))
def test_the_baseline_may_back_a_production_use(use):
    granted = pp.require_deployment_baseline(pp.DEPLOYMENT_BASELINE, use)
    assert granted.profile is pp.DEPLOYMENT_BASELINE and granted.use == use


@pytest.mark.parametrize("use", sorted(pp.PRODUCTION_USES))
def test_the_lab_profile_is_refused_for_every_production_use(use):
    with pytest.raises(pp.PlatformRefused) as refused:
        pp.require_deployment_baseline(pp.ARM64_LAB, use)
    assert refused.value.reason == pp.LAB_PROFILE_NOT_FOR_PRODUCTION
    with pytest.raises(pp.PlatformRefused):
        pp.DeploymentBaseline(pp.ARM64_LAB, use)


def test_production_use_names_are_closed():
    with pytest.raises(pp.PlatformRefused) as refused:
        pp.require_deployment_baseline(pp.DEPLOYMENT_BASELINE, "lab-anything")
    assert refused.value.reason == pp.UNKNOWN_USE


def test_a_lookalike_baseline_profile_is_not_the_baseline():
    """Same id and purpose, different contents: not the reviewed profile."""

    forged = pp.PlatformProfile(
        profile_id="debian-13-amd64-cp313", purpose=pp.PURPOSE_DEPLOYMENT_BASELINE,
        os_id="debian", os_version_id="14", architecture="amd64", python_tag="cp313",
        soabi="cpython-313-x86_64-linux-gnu", features=frozenset())
    with pytest.raises(pp.PlatformRefused) as refused:
        pp.require_deployment_baseline(forged, "model-admission")
    assert refused.value.reason == pp.UNKNOWN_PROFILE
    with pytest.raises(pp.PlatformRefused):
        pp.require_deployment_baseline("debian-13-amd64-cp313", "model-admission")


def test_profile_lookup_refuses_unknown_ids():
    assert pp.profile("debian-13-arm64-cp313-lab") is pp.ARM64_LAB
    for bad in ("debian-13-arm64-cp313", "debian-13-amd64-cp313-lab", "", None):
        with pytest.raises(pp.PlatformRefused):
            pp.profile(bad)


@pytest.mark.parametrize("machine", ["x86_64", "amd64", "aarch64", "arm64"])
def test_runtime_pin_selection_goes_through_the_one_table(machine):
    expected = model_runtime.LLAMA_RUNTIME_DIGESTS[pp.kernel_name(pp.normalize_machine(machine))]
    assert model_runtime.pinned_runtime_digest(machine) == expected


@pytest.mark.parametrize("machine", ["x86-64", "armv7l", "", "AARCH64"])
def test_runtime_pin_refuses_names_outside_the_table(machine):
    with pytest.raises(model_runtime.RuntimeRefused):
        model_runtime.pinned_runtime_digest(machine)


def test_every_reviewed_cpu_has_a_runtime_pin_keyed_by_its_kernel_name():
    assert set(model_runtime.LLAMA_RUNTIME_DIGESTS) == {
        pp.kernel_name(a) for a in pp.ARCHITECTURES}


def test_peergroups_table_covers_every_reviewed_cpu():
    """The SO_PEERGROUPS table is a kernel ABI list wider than the reviewed
    CPUs; it must at least contain each of them, or that CPU silently loses
    supplementary groups."""

    principal = pytest.importorskip("azazel_nexus_runtime.principal")
    assert pp.LP64_REVIEWED_KERNEL_MACHINES <= principal._GENERIC_SOCKET_MACHINES


def test_purpose_alone_does_not_make_a_baseline():
    claimed = pp.PlatformProfile(
        profile_id="debian-13-amd64-cp313", purpose=pp.PURPOSE_DEPLOYMENT_BASELINE,
        os_id="debian", os_version_id="13", architecture="amd64", python_tag="cp313",
        soabi="cpython-313-x86_64-linux-gnu", features=frozenset({"extra"}))
    assert not claimed.is_deployment_baseline
    other_id = pp.PlatformProfile(
        profile_id="debian-13-amd64-cp313-x", purpose=pp.PURPOSE_DEPLOYMENT_BASELINE,
        os_id="debian", os_version_id="13", architecture="amd64", python_tag="cp313",
        soabi="cpython-313-x86_64-linux-gnu", features=pp.DEPLOYMENT_BASELINE.features)
    assert not other_id.is_deployment_baseline
    assert pp.DEPLOYMENT_BASELINE.is_deployment_baseline
    assert not pp.ARM64_LAB.is_deployment_baseline


def test_deployment_baseline_cannot_be_subclassed():
    with pytest.raises(TypeError):
        class Lenient(pp.DeploymentBaseline):  # noqa: F841
            def __post_init__(self):
                pass


def _forged(profile, use="model-admission"):
    value = object.__new__(pp.DeploymentBaseline)
    object.__setattr__(value, "profile", profile)
    object.__setattr__(value, "use", use)
    return value


def test_copy_and_pickle_go_back_through_the_constructor():
    import copy
    import pickle

    good = pp.require_deployment_baseline(pp.DEPLOYMENT_BASELINE, "hil-preflight")
    assert pickle.loads(pickle.dumps(good)) == good
    assert copy.copy(good) == good and copy.deepcopy(good) == good
    forged = _forged(pp.ARM64_LAB)
    with pytest.raises(pp.PlatformRefused) as refused:
        pickle.loads(pickle.dumps(forged))
    assert refused.value.reason == pp.LAB_PROFILE_NOT_FOR_PRODUCTION
    with pytest.raises(pp.PlatformRefused):
        copy.copy(forged)
    with pytest.raises(pp.PlatformRefused):
        copy.deepcopy(forged)


def test_a_consumer_rechecks_what_it_is_handed():
    good = pp.require_deployment_baseline(pp.DEPLOYMENT_BASELINE, "model-admission")
    assert pp.verify_deployment_baseline(good, "model-admission") is good
    with pytest.raises(pp.PlatformRefused):
        pp.verify_deployment_baseline(good, "hil-preflight")
    with pytest.raises(pp.PlatformRefused) as refused:
        pp.verify_deployment_baseline(_forged(pp.ARM64_LAB), "model-admission")
    assert refused.value.reason == pp.LAB_PROFILE_NOT_FOR_PRODUCTION
    with pytest.raises(pp.PlatformRefused):
        pp.verify_deployment_baseline(_forged(pp.DEPLOYMENT_BASELINE, "lab-anything"), "lab-anything")
    from types import SimpleNamespace
    with pytest.raises(pp.PlatformRefused):
        pp.verify_deployment_baseline(
            SimpleNamespace(profile=pp.DEPLOYMENT_BASELINE, use="model-admission"), "model-admission")
