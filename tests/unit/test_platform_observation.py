"""Host observation feeding the reviewed platform profiles (ADR-0003 R6).

Every reader is injected, so these run the same on amd64 and arm64 and say
nothing about the CPU they ran on. One test reads the real container host and
checks only that the observation is internally consistent.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import install_platform
from azazel_nexus_runtime import platform_observation as po
from azazel_nexus_runtime.install_platform import (
    CURRENT_INSTALL_PLATFORM_PROFILES,
    evaluate_install_architecture,
)

from azazel_nexus import platform_profile as pp
from tools.install_profile_fields import resolve as resolve_profile_field

INSTALL_PROFILE = CURRENT_INSTALL_PLATFORM_PROFILES[0]
DEBIAN_13 = 'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
HOSTS = {
    "amd64": dict(machine="x86_64", soabi="cpython-313-x86_64-linux-gnu", dpkg="amd64"),
    "arm64": dict(machine="aarch64", soabi="cpython-313-aarch64-linux-gnu", dpkg="arm64"),
}


def observed(tmp_path, *, machine="x86_64", soabi="cpython-313-x86_64-linux-gnu",
             dpkg="amd64", os_release=DEBIAN_13, sysname="Linux", long_size=8,
             byteorder="little"):
    release = tmp_path / "os-release"
    if os_release is not None:
        release.write_text(os_release, encoding="utf-8")
    return po.observe(
        uname=lambda: SimpleNamespace(sysname=sysname, release="6.12.0-test", machine=machine),
        os_release_path=release, soabi=lambda: soabi, long_size=lambda: long_size,
        byteorder=lambda: byteorder, dpkg_architecture=lambda: dpkg,
    )


def test_observation_reads_every_listed_field(tmp_path):
    observation = observed(tmp_path)
    assert observation.as_record() == {
        "sysname": "Linux", "release": "6.12.0-test", "machine": "x86_64",
        "os_id": "debian", "os_version_id": "13",
        "soabi": "cpython-313-x86_64-linux-gnu", "lp64": True, "byteorder": "little",
        "dpkg_architecture": "amd64",
    }


def test_unreadable_fields_are_unavailable_never_a_reviewed_value(tmp_path):
    observation = observed(tmp_path, os_release=None, soabi=None, dpkg="")
    assert (observation.os_id, observation.os_version_id) == (po.UNAVAILABLE, po.UNAVAILABLE)
    assert observation.soabi == po.UNAVAILABLE
    assert observation.dpkg_architecture == po.UNAVAILABLE
    with pytest.raises(pp.PlatformRefused) as refused:
        po.select(observation)
    assert refused.value.reason == po.DPKG_UNOBSERVED
    with pytest.raises(pp.PlatformRefused) as refused:
        po.select(observed(tmp_path, os_release=None, soabi=None))
    assert refused.value.reason == pp.UNREVIEWED_OS


@pytest.mark.parametrize("architecture", sorted(HOSTS))
def test_select_identifies_each_reviewed_profile(tmp_path, architecture):
    host = HOSTS[architecture]
    profile = po.select(observed(tmp_path, **host))
    assert profile.architecture == architecture
    assert profile is pp.REVIEWED_PROFILES[profile.profile_id]
    assert profile.is_deployment_baseline is (architecture == "amd64")


def test_arm64_is_identified_as_lab_and_cannot_back_any_production_use(tmp_path):
    profile = po.select(observed(tmp_path, **HOSTS["arm64"]))
    assert profile.purpose == pp.PURPOSE_LAB_SOFTWARE_VERIFICATION
    assert profile.profile_id.endswith("-lab")
    for use in sorted(pp.PRODUCTION_USES):
        with pytest.raises(pp.PlatformRefused) as refused:
            pp.require_deployment_baseline(profile, use)
        assert refused.value.reason == pp.LAB_PROFILE_NOT_FOR_PRODUCTION


@pytest.mark.parametrize(("facts", "reason"), [
    ({"machine": "riscv64"}, pp.UNKNOWN_ARCHITECTURE),
    ({"machine": "armv7l"}, pp.UNKNOWN_ARCHITECTURE),
    ({"machine": "aarch64_be"}, pp.UNKNOWN_ARCHITECTURE),
    ({"machine": "i686"}, pp.UNKNOWN_ARCHITECTURE),
    ({"machine": "arm64"}, pp.UNKNOWN_ARCHITECTURE),  # macOS spelling, not Linux uname
    ({"machine": "amd64"}, pp.UNKNOWN_ARCHITECTURE),
    ({"sysname": "Darwin"}, po.UNREVIEWED_KERNEL),
    ({"long_size": 4}, po.LP64_NOT_OBSERVED),
    ({"byteorder": "big"}, po.UNREVIEWED_BYTE_ORDER),
    ({"dpkg": "i386"}, po.DPKG_ARCHITECTURE_MISMATCH),
    ({"machine": "aarch64", "soabi": "cpython-313-aarch64-linux-gnu", "dpkg": "armhf"},
     po.DPKG_ARCHITECTURE_MISMATCH),
    ({"os_release": "ID=debian\nVERSION_ID=12\n"}, pp.UNREVIEWED_OS),
    ({"os_release": "ID=ubuntu\nVERSION_ID=13\n"}, pp.UNREVIEWED_OS),
    ({"soabi": "cpython-312-x86_64-linux-gnu"}, pp.UNREVIEWED_PYTHON_ABI),
    # An amd64 interpreter on an arm64 kernel (or the reverse) is not a profile.
    ({"machine": "aarch64", "dpkg": "arm64"}, pp.UNREVIEWED_PYTHON_ABI),
])
def test_select_refuses_with_a_reason(tmp_path, facts, reason):
    with pytest.raises(pp.PlatformRefused) as refused:
        po.select(observed(tmp_path, **facts))
    assert refused.value.reason == reason


def test_select_takes_only_an_observation():
    with pytest.raises(pp.PlatformRefused) as refused:
        po.select({"machine": "x86_64"})
    assert refused.value.reason == po.UNOBSERVED


@pytest.mark.parametrize("architecture", sorted(HOSTS))
def test_an_unreadable_dpkg_is_refused_for_every_profile(tmp_path, architecture):
    """F1: a Debian host whose dpkg cannot be read is an anomaly. Without dpkg
    a foreign userland would pass unseen, so neither the baseline nor the lab
    profile is selected, and the installer refuses too."""

    host = dict(HOSTS[architecture], dpkg=po.UNAVAILABLE)
    with pytest.raises(pp.PlatformRefused) as refused:
        po.select(observed(tmp_path, **host))
    assert refused.value.reason == po.DPKG_UNOBSERVED
    with pytest.raises(pp.PlatformRefused) as refused:
        evaluate_install_architecture(INSTALL_PROFILE, observed(tmp_path, **host))
    assert refused.value.reason == po.DPKG_UNOBSERVED


@pytest.mark.parametrize("query", [
    ("/nonexistent/dpkg-query",),                       # dpkg-query missing
    ("/bin/echo", "not a package listing"),             # garbage output
    ("/bin/false",),                                    # failing query
])
def test_installer_resolver_refuses_when_the_real_dpkg_reader_fails(tmp_path, monkeypatch, query):
    """The reproduction of F1, through the real reader and a real process."""

    from azazel_nexus_runtime import debian_packages

    monkeypatch.setattr(debian_packages, "QUERY_ARGV", query)
    release = tmp_path / "os-release"
    release.write_text(DEBIAN_13, encoding="utf-8")
    assert po.read_dpkg_architecture() == po.UNAVAILABLE
    with pytest.raises(pp.PlatformRefused, match=po.DPKG_UNOBSERVED):
        resolve_profile_field(field="platform", os_release_path=release)


def test_dpkg_reader_reuses_the_reviewed_package_observer(monkeypatch):
    from azazel_nexus_runtime import debian_packages

    monkeypatch.setattr(debian_packages, "observe_installed_packages",
                        lambda: SimpleNamespace(native_architecture="arm64"))
    assert po.read_dpkg_architecture() == "arm64"
    for failure in (debian_packages.PackageObservationRefused("refused"), OSError("x")):
        def refuse(failure=failure):
            raise failure
        monkeypatch.setattr(debian_packages, "observe_installed_packages", refuse)
        assert po.read_dpkg_architecture() == po.UNAVAILABLE


def test_observation_starts_no_process_of_its_own():
    import ast

    tree = ast.parse(Path(po.__file__).read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module}
    assert not imported & {"subprocess", "shlex", "pty"}


def test_the_real_host_observation_is_consistent():
    """Reads this container. Says nothing about which CPU it ran on."""

    observation = po.observe()
    assert observation.sysname == "Linux"
    architecture = pp.from_machine(observation.machine)
    assert observation.lp64 is True and observation.byteorder == "little"
    assert observation.dpkg_architecture == pp.debian_name(architecture)
    assert po.check_host_abi(observation) == architecture


# -- install.sh (R6) ---------------------------------------------------------


@pytest.mark.parametrize(("architecture", "purpose"), [
    ("amd64", pp.PURPOSE_DEPLOYMENT_BASELINE),
    ("arm64", pp.PURPOSE_LAB_SOFTWARE_VERIFICATION),
])
def test_install_identifies_the_cpu(tmp_path, architecture, purpose):
    host = HOSTS[architecture]
    # Any interpreter may stage an install; the Python ABI is not the
    # installer's decision, so a 3.11 SOABI still identifies the CPU.
    host = dict(host, soabi="cpython-311-" + pp.to_boundary(architecture, "multiarch"))
    profile = evaluate_install_architecture(INSTALL_PROFILE, observed(tmp_path, **host))
    assert (profile.architecture, profile.purpose) == (architecture, purpose)


@pytest.mark.parametrize(("facts", "reason"), [
    ({"machine": "riscv64"}, pp.UNKNOWN_ARCHITECTURE),
    ({"machine": "armv7l"}, pp.UNKNOWN_ARCHITECTURE),
    ({"machine": "ppc64le"}, pp.UNKNOWN_ARCHITECTURE),
    ({"dpkg": "i386"}, po.DPKG_ARCHITECTURE_MISMATCH),
    ({"long_size": 4}, po.LP64_NOT_OBSERVED),
    ({"sysname": "FreeBSD"}, po.UNREVIEWED_KERNEL),
    ({"dpkg": po.UNAVAILABLE}, po.DPKG_UNOBSERVED),
])
def test_install_refuses_an_unreviewed_cpu_with_a_reason(tmp_path, facts, reason):
    with pytest.raises(pp.PlatformRefused) as refused:
        evaluate_install_architecture(INSTALL_PROFILE, observed(tmp_path, **facts))
    assert refused.value.reason == reason


def test_install_cpu_evaluation_needs_a_reviewed_os_x_cpu_pair(tmp_path, monkeypatch):
    monkeypatch.setattr(install_platform.platform_profile, "REVIEWED_PROFILES",
                        {pp.DEPLOYMENT_BASELINE.profile_id: pp.DEPLOYMENT_BASELINE})
    with pytest.raises(pp.PlatformRefused) as refused:
        evaluate_install_architecture(INSTALL_PROFILE, observed(tmp_path, **HOSTS["arm64"]))
    assert refused.value.reason == pp.UNREVIEWED_COMBINATION
    with pytest.raises(ValueError):
        evaluate_install_architecture(object(), observed(tmp_path))


@pytest.mark.parametrize("architecture", sorted(HOSTS))
def test_installer_field_resolver_emits_the_cpu_and_purpose(tmp_path, architecture):
    release = tmp_path / "os-release"
    release.write_text(DEBIAN_13, encoding="utf-8")
    observation = observed(tmp_path, **HOSTS[architecture])
    calls = []

    def observe_once():
        calls.append(1)
        return observation

    value = resolve_profile_field(field="platform", os_release_path=release,
                                  observe_platform=observe_once)
    assert value == f"{architecture} {po.select(observation).purpose}"
    # F6: one field, one observation (one dpkg query) per install.
    assert len(calls) == 1


def test_installer_field_resolver_refuses_an_unknown_cpu(tmp_path):
    release = tmp_path / "os-release"
    release.write_text(DEBIAN_13, encoding="utf-8")
    observation = observed(tmp_path, machine="riscv64")
    with pytest.raises(pp.PlatformRefused, match="UNKNOWN_ARCHITECTURE"):
        resolve_profile_field(field="platform", os_release_path=release,
                              observe_platform=lambda: observation)


def test_installer_refuses_before_writing_and_reports_the_lab_purpose():
    text = (Path(__file__).resolve().parents[2] / "packaging/install.sh").read_text()
    evaluation = text.index("profile_field platform)")
    # F6: the host (and dpkg) is observed by exactly one resolver call.
    assert text.count("profile_field platform") == 1
    # Before any file, account, wrapper or unit is touched.
    assert evaluation < text.index("profile_field unit_directory")
    assert evaluation < text.index('"$STAGER"')
    assert "refusing to install: this host's CPU is not in a reviewed platform profile." in text
    assert 'if [ "$PLATFORM_PURPOSE" != deployment-baseline ]' in text
    assert "lab-software-verification platform, not the" in text
