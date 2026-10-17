import re

import pytest

import azazel_nexus_runtime.bootstrap_systemd_profile as profiles
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    _DEBIAN13_V257_UNIT_PATH,
    SystemdBootstrapProfile,
    bootstrap_systemd_profile_digest,
    observe_bootstrap_systemd_profile,
)
from azazel_nexus_runtime.units import UnitOperationFailed


def test_observes_supported_debian13_systemd257_profile():
    observed = observe_bootstrap_systemd_profile(
        version="257.13-1~deb13u1",
        unit_path=list(_DEBIAN13_V257_UNIT_PATH),
    )

    assert observed.name == "systemd-257.13-deb13-path-v1"
    assert observed.version == "257.13-1~deb13u1"
    assert observed.unit_path == _DEBIAN13_V257_UNIT_PATH


@pytest.mark.parametrize("version", [
    "258.1-1~deb13u1", "256.99-1~deb13u1", "257", "257.13foo",
    "257.99-1~deb13u9", "257.13-1~deb12u1", "257.13-1~ubuntu1",
    "257.13", "",
])
def test_refuses_unknown_or_malformed_systemd_version(version):
    with pytest.raises(UnitOperationFailed):
        observe_bootstrap_systemd_profile(
            version=version,
            unit_path=list(_DEBIAN13_V257_UNIT_PATH),
        )


def test_accepts_debian13_package_revision_only_for_observed_upstream_version():
    observed = observe_bootstrap_systemd_profile(
        version="257.13-1~deb13u9",
        unit_path=list(_DEBIAN13_V257_UNIT_PATH),
    )
    assert observed.version == "257.13-1~deb13u9"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda paths: paths.pop(0),
        lambda paths: paths.insert(0, "/opt/vendor/systemd/system.control"),
        lambda paths: paths.__setitem__(0, "/run/systemd/system.control"),
        lambda paths: paths.__setitem__(1, "/etc/systemd/system.control"),
        lambda paths: paths.append("/run/systemd/system.control"),
    ],
)
def test_refuses_missing_extra_or_reordered_search_path(mutate):
    paths = list(_DEBIAN13_V257_UNIT_PATH)
    mutate(paths)

    with pytest.raises(UnitOperationFailed):
        observe_bootstrap_systemd_profile(version="257.13-1~deb13u1", unit_path=paths)


@pytest.mark.parametrize("unit_path", [None, tuple(_DEBIAN13_V257_UNIT_PATH), ["relative/path"]])
def test_refuses_untyped_or_nonabsolute_search_path(unit_path):
    with pytest.raises(UnitOperationFailed):
        observe_bootstrap_systemd_profile(version="257.13-1~deb13u1", unit_path=unit_path)


def test_additional_measured_profile_can_support_a_different_ordered_path(monkeypatch):
    future_path = ("/etc/systemd/system", "/usr/lib/systemd/system")
    future = profiles._ReviewedProfileDefinition(
        name="reviewed-future-install-v1",
        version=re.compile(r"258\.1-1~example1\Z"),
        unit_path=future_path,
    )
    monkeypatch.setattr(
        profiles, "_REVIEWED_PROFILES", (*profiles._REVIEWED_PROFILES, future)
    )

    observed = observe_bootstrap_systemd_profile(
        version="258.1-1~example1",
        unit_path=list(future_path),
    )

    assert observed.name == "reviewed-future-install-v1"
    assert observed.unit_path == future_path


def test_policy_pin_identifies_exact_reviewed_profile_tuple():
    observed = observe_bootstrap_systemd_profile(
        version="257.13-1~deb13u1",
        unit_path=list(_DEBIAN13_V257_UNIT_PATH),
    )
    pin = bootstrap_systemd_profile_digest(observed)

    assert re.fullmatch(r"sha256:[0-9a-f]{64}", pin)
    assert bootstrap_systemd_profile_digest(observed) == pin
    changed = observe_bootstrap_systemd_profile(
        version="257.13-1~deb13u2",
        unit_path=list(_DEBIAN13_V257_UNIT_PATH),
    )
    assert bootstrap_systemd_profile_digest(changed) != pin


def test_profile_policy_pin_rejects_forged_or_untyped_profile():
    with pytest.raises(UnitOperationFailed):
        bootstrap_systemd_profile_digest(object())
    forged = SystemdBootstrapProfile(
        "systemd-257.13-deb13-path-v1", "257.13-1~deb13u1", ("/tmp",)
    )
    with pytest.raises(UnitOperationFailed):
        bootstrap_systemd_profile_digest(forged)
