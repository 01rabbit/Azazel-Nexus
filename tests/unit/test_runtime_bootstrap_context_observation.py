"""Contract tests for the protected, stable bootstrap context observation."""

from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_approval import BootstrapContext
from azazel_nexus.installed_files import SelectedInstalledFiles
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_declared_context import DeclaredBootstrapContext
from azazel_nexus_runtime import bootstrap_inputs
from azazel_nexus_runtime.bootstrap_systemd_profile import bootstrap_systemd_profile_digest
from azazel_nexus_runtime.bootstrap_inputs import ProtectedBootstrapContextObservation
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    SystemdBootstrapProfile,
    _DEBIAN13_V257_UNIT_PATH,
)
from azazel_nexus_runtime.debian_packages import parse_package_output


DIGEST = "sha256:" + "a" * 64
BOOT_ID = "11111111-1111-1111-1111-111111111111"


def _context(**changes):
    values = {
        "approval_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "node_digest": DIGEST,
        "boot_id": BOOT_ID,
        "generation": 3,
        "generation_digest": DIGEST,
        "package_digest": DIGEST,
        "unit_closure_digest": DIGEST,
        "policy_digest": DIGEST,
        "approval_policy_digest": DIGEST,
        "security_epoch": 2,
        "revocation_digest": DIGEST,
    }
    values.update(changes)
    return BootstrapContext(**values)


def _declared(context=None):
    return DeclaredBootstrapContext(
        _context() if context is None else context,
        "operator-a",
        bootstrap_systemd_profile_digest(_profile()),
    )


def _packages(version="1.0"):
    return parse_package_output(
        (
            f"dpkg\t1.22.22\tarm64\tii \n"
            f"example-package\t{version}\tarm64\tii \n"
        ).encode("ascii")
    )


def _profile(version="257.13-1~deb13u1"):
    return SystemdBootstrapProfile(
        "systemd-257.13-deb13-path-v1",
        version,
        _DEBIAN13_V257_UNIT_PATH,
    )


def _stable_reader(values, calls):
    pending = iter(values)

    def read(*_args, **_kwargs):
        calls.append(True)
        return next(pending)

    return read


def _observation(*, declarations=None, packages=None, files=None, profiles=None,
                 context=None):
    package_values = [_packages(), _packages()] if packages is None else packages
    file_values = (
        [SelectedInstalledFiles(DIGEST, 2, 128)] * 2 if files is None else files
    )
    context = context or _context(
        package_digest=getattr(package_values[0], "digest", DIGEST),
        unit_closure_digest=getattr(file_values[0], "manifest_digest", DIGEST),
    )
    declaration_calls = []
    package_calls = []
    file_calls = []
    profile_calls = []
    readers = {
        "declared": _stable_reader(
            [_declared(context), _declared(context)]
            if declarations is None else declarations,
            declaration_calls,
        ),
        "observe_packages": _stable_reader(
            package_values,
            package_calls,
        ),
        "measure_files": _stable_reader(
            file_values,
            file_calls,
        ),
        "observe_systemd_profile": _stable_reader(
            [_profile(), _profile()] if profiles is None else profiles,
            profile_calls,
        ),
    }
    calls = {
        "declared": declaration_calls,
        "observe_packages": package_calls,
        "measure_files": file_calls,
        "observe_systemd_profile": profile_calls,
    }
    return ProtectedBootstrapContextObservation(**readers), context, calls


def test_returns_context_after_two_matching_observations_of_every_source():
    observer, expected, calls = _observation()

    assert observer() == expected
    assert {source: len(reads) for source, reads in calls.items()} == {
        "declared": 2,
        "observe_packages": 2,
        "measure_files": 2,
        "observe_systemd_profile": 2,
    }


def test_package_digest_mismatch_refuses_before_systemd_observation():
    wrong = _packages("2.0")
    observer, _expected, calls = _observation(
        packages=[wrong, wrong],
        context=_context(package_digest=_packages().digest),
    )

    with pytest.raises(ApprovalRefused):
        observer()

    assert calls["observe_systemd_profile"] == []


def test_live_profile_must_match_profile_pinned_by_approved_policy():
    wrong = SystemdBootstrapProfile(
        "systemd-257.13-deb13-path-v1", "257.13-1~deb13u2", _profile().unit_path
    )
    context = _context(package_digest=_packages().digest)
    declared = DeclaredBootstrapContext(
        context, "operator-a", bootstrap_systemd_profile_digest(_profile())
    )
    observer, _expected, calls = _observation(
        declarations=[declared, declared], profiles=[wrong, wrong], context=context
    )

    with pytest.raises(ApprovalRefused):
        observer()

    assert calls["observe_systemd_profile"] == [True]


@pytest.mark.parametrize("source", ["declaration", "package", "manifest", "profile"])
def test_change_between_stable_source_observations_refuses(source):
    if source == "declaration":
        context = _context(package_digest=_packages().digest)
        values = {
            "declarations": [_declared(context), _declared(replace(context, generation=4))],
        }
    elif source == "package":
        first = _packages()
        values = {"packages": [first, _packages("2.0")]}
    elif source == "manifest":
        values = {
            "files": [
                SelectedInstalledFiles(DIGEST, 2, 128),
                SelectedInstalledFiles("sha256:" + "b" * 64, 2, 128),
            ],
        }
    else:
        values = {"profiles": [_profile(), _profile("257.13-1~deb13u2")]}
    observer, _expected, _calls = _observation(**values)

    with pytest.raises(ApprovalRefused):
        observer()


@pytest.mark.parametrize(
    ("source", "values"),
    [
        ("declarations", [object(), object()]),
        ("packages", [object(), object()]),
        ("files", [object(), object()]),
        ("profiles", [object(), object()]),
    ],
)
def test_malformed_source_types_are_redacted_as_approval_refused(source, values):
    observer, _expected, _calls = _observation(**{source: values})

    with pytest.raises(ApprovalRefused) as error:
        observer()

    assert type(error.value) is ApprovalRefused
    assert "object at" not in str(error.value)


def test_production_refresh_factory_composes_fixed_context_and_clock(monkeypatch):
    context_reader = object()
    clock_reader = object()
    monkeypatch.setattr(
        bootstrap_inputs,
        "protected_bootstrap_context_observation",
        lambda: context_reader,
    )

    def clock_factory(observe_context):
        assert observe_context is context_reader
        return clock_reader

    monkeypatch.setattr(
        bootstrap_inputs, "ProtectedAdministratorClockObservation", clock_factory
    )
    refresh = bootstrap_inputs.protected_bootstrap_inputs()

    assert type(refresh) is bootstrap_inputs.ProtectedBootstrapInputs
    assert refresh.observe is clock_reader
