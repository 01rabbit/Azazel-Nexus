"""One bootstrap measurement validates its decoded manifest once (Nexus#324).

The skip is limited to the exact object that the current call's decode_scope
decoded from byte-identical, pinned input. Nothing carries over to the next
call, and every refusal inside a call is unchanged.
"""

from dataclasses import replace

import pytest

from azazel_nexus import installed_manifest
from azazel_nexus.installed_files import SelectedInstalledFiles
from azazel_nexus.installed_manifest import (
    InstalledManifest,
    decode_installed_manifest,
    decode_scope,
    installed_link_resolver,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs, loaded_modules

import test_runtime_bootstrap_installed_files as installed
import test_runtime_loaded_modules as modules


@pytest.fixture
def validations(monkeypatch):
    calls = []
    real = installed_manifest._validate_manifest

    def counted(manifest):
        calls.append(manifest)
        return real(manifest)

    monkeypatch.setattr(installed_manifest, "_validate_manifest", counted)
    return calls


def _full(calls, raw):
    """Validations of the complete manifest that ``raw`` encodes."""
    calls = list(calls)
    expected = installed_manifest._decode_installed_manifest(
        raw, "sha256:" + installed.sha256(raw).hexdigest())
    return [manifest for manifest in calls if manifest == expected]


def _wire(monkeypatch, raw, *, registry=None, events=None):
    """Production composition with only the filesystem leaves replaced.

    The loaded-module observation runs the real projection (and so the real
    resolver) twice, like observe_loaded_modules; the stand-in measurement
    decodes through the same scope like measure_installed_files does.
    """
    installed._wire_raw_and_content_reader(monkeypatch, raw)
    monkeypatch.setattr(loaded_modules.sys, "pycache_prefix", None)
    registries = iter(registry) if registry is not None else None
    stable = _main_registry()

    def observe_modules(manifest, roots, main_path):
        projections = []
        for _ in range(2):
            current = next(registries) if registries is not None else stable
            projections.append(loaded_modules._project_modules(
                current, manifest, roots, main_path))
        if projections[0] != projections[1]:
            raise ApprovalRefused("loaded module bindings changed")
        return loaded_modules.LoadedModules(roots, *projections[0][:2], ())

    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", observe_modules)

    def measure(actual, *, expected_digest):
        with decode_scope():
            manifest = decode_installed_manifest(actual, expected_digest=expected_digest)
        if events is not None:
            events.append("measured")
        return SelectedInstalledFiles(expected_digest, len(manifest.files), 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)


def _main_registry():
    return {"__main__": modules._main_module()}


def test_one_call_validates_the_manifest_once(monkeypatch, validations):
    raw = installed._manifest_raw()
    _wire(monkeypatch, raw)
    validations.clear()
    result = bootstrap_inputs.measure_bootstrap_installed_files(
        installed._pinned_context(raw))
    assert result.manifest_digest == installed._pinned_context(raw).unit_closure_digest
    total = len(validations)
    # Before Nexus#324: decode (2) + interpreter link (1) + four projections (4).
    assert len(_full(validations, raw)) == 1
    assert total == 1


def test_without_a_scope_every_resolver_still_validates(validations):
    raw = installed._manifest_raw()
    pin = installed._pinned_context(raw).unit_closure_digest
    manifest = decode_installed_manifest(raw, expected_digest=pin)
    validations.clear()
    installed_link_resolver(manifest)
    installed_link_resolver(manifest)
    assert len(validations) == 2


def test_next_call_validates_again_and_sees_a_changed_manifest(monkeypatch, validations):
    raw = installed._manifest_raw()
    _wire(monkeypatch, raw)
    validations.clear()
    bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    # Same bytes, second call: validated afresh, nothing carried over.
    assert len(_full(validations, raw)) == 2

    changed = installed._manifest_raw(
        paths=(*installed.ENTRYPOINTS, "usr/share/azazel/changed.txt"))
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest",
                        lambda: changed)
    # The earlier call's pin and success do not admit the changed bytes.
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    validations.clear()
    # Under its own pin the changed manifest is decoded and validated again.
    result = bootstrap_inputs.measure_bootstrap_installed_files(
        installed._pinned_context(changed))
    assert len(_full(validations, changed)) == 1
    assert result.file_count == len(decode_installed_manifest(
        changed, expected_digest=installed._pinned_context(changed).unit_closure_digest,
    ).files)
    assert installed_manifest._DECODE_SCOPE.get() is None


def test_changed_manifest_bytes_at_the_final_reread_still_refuse(monkeypatch):
    raw = installed._manifest_raw()
    events = []
    _wire(monkeypatch, raw, events=events)
    changed = installed._manifest_raw(
        paths=(*installed.ENTRYPOINTS, "usr/share/azazel/changed.txt"))
    reads = []

    def read():
        reads.append(True)
        return raw if len(reads) == 1 else changed

    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", read)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    assert events == ["measured"] and len(reads) == 2


def test_equal_but_different_bytes_object_reread_is_still_compared(monkeypatch):
    raw = installed._manifest_raw()
    _wire(monkeypatch, raw)
    reads = []

    def read():
        reads.append(True)
        return bytes(bytearray(raw))  # a fresh object with identical bytes

    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", read)
    bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    assert len(reads) == 2


def test_module_registry_change_between_projections_still_refuses(monkeypatch):
    raw = installed._manifest_raw()
    events = []
    unpinned = modules._source_module(name="extra", origin="/opt/env/site/extra.py")
    first = _main_registry()
    _wire(monkeypatch, raw, events=events, registry=(
        first, {**first, "extra": unpinned},
    ))
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    assert events == []


def test_module_registry_change_across_the_measurement_still_refuses(monkeypatch):
    raw = installed._manifest_raw()
    events = []
    other = replace(modules._loaded(), files=("changed",))
    _wire(monkeypatch, raw, events=events)
    real = bootstrap_inputs.observe_loaded_modules
    calls = []

    def observe(manifest, roots, main_path):
        calls.append(True)
        result = real(manifest, roots, main_path)
        return result if len(calls) == 1 else replace(other, import_paths=roots)

    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", observe)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(installed._pinned_context(raw))
    assert events == ["measured"] and len(calls) == 2


def test_in_scope_only_the_decoded_object_skips_validation(validations):
    raw = installed._manifest_raw()
    pin = installed._pinned_context(raw).unit_closure_digest
    outside = decode_installed_manifest(raw, expected_digest=pin)
    forged = object.__new__(InstalledManifest)
    for name, value in (("files", ()), ("directories", ()), ("version", 2), ("links", ())):
        object.__setattr__(forged, name, value)
    with decode_scope():
        decoded = decode_installed_manifest(raw, expected_digest=pin)
        assert decoded == outside and decoded is not outside
        validations.clear()
        installed_link_resolver(decoded)
        assert validations == []
        installed_link_resolver(outside)
        assert validations == [outside]
        with pytest.raises(ApprovalRefused, match="link resolution refused"):
            installed_link_resolver(forged)
        with pytest.raises(ApprovalRefused, match="link resolution refused"):
            installed_link_resolver(object())
    validations.clear()
    installed_link_resolver(decoded)
    assert validations == [decoded]


def test_resolution_refusals_are_unchanged_for_the_decoded_object():
    raw = installed._manifest_raw()
    pin = installed._pinned_context(raw).unit_closure_digest
    plain = installed_link_resolver(decode_installed_manifest(raw, expected_digest=pin))
    with decode_scope():
        scoped = installed_link_resolver(decode_installed_manifest(raw, expected_digest=pin))
        for path in (installed.INTERPRETER_PATH, installed.ENTRYPOINTS[0]):
            assert scoped(path) == plain(path)
        for path in ("opt/env/missing", "etc/passwd", "opt/env/site", "", None):
            with pytest.raises(ApprovalRefused) as scoped_error:
                scoped(path)
            with pytest.raises(ApprovalRefused) as plain_error:
                plain(path)
            assert str(scoped_error.value) == str(plain_error.value)
