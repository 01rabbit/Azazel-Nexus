"""Synthetic module-registry projections and protected negative-path checks."""

from hashlib import sha256
import importlib.machinery
from importlib import util
import os
from types import ModuleType, SimpleNamespace

import pytest

from azazel_nexus.installed_manifest import (
    InstalledDirectory,
    InstalledFile,
    InstalledManifest,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import loaded_modules
from azazel_nexus_runtime.loaded_modules import (
    LoadedModules,
    _observe_at,
    _project_modules,
)


ROOTS = ("/opt/env/site",)
MAIN_PATH = "/usr/libexec/azazel/az-activated"
SOURCE_PATH = "/opt/env/site/sample.py"
SOURCE_CACHE = util.cache_from_source(SOURCE_PATH, optimization="")
_MAIN_BYTES = b"synthetic entrypoint bytes\n"
_SOURCE_BYTES = b"synthetic module bytes\n"
_CACHE_BYTES = b"synthetic pinned bytecode\n"


def _loaded(import_paths=("/opt/env/site",)):
    return LoadedModules(import_paths, (), (), ())


def _manifest(files=None):
    selected = {
        "usr/libexec/azazel/az-activated": (0o755, _MAIN_BYTES),
        "opt/env/site/sample.py": (0o644, _SOURCE_BYTES),
    }
    if files:
        selected.update(files)
    directories = set()
    for path in selected:
        parts = path.split("/")
        directories.update("/".join(parts[:index]) for index in range(2, len(parts)))
    entries = tuple(
        InstalledFile(path, mode, len(content), sha256(content).hexdigest())
        for path, (mode, content) in sorted(selected.items())
    )
    return InstalledManifest(
        files=entries,
        directories=tuple(InstalledDirectory(path) for path in sorted(directories)),
        version=2,
    )


def _main_module():
    module = ModuleType("__main__")
    module.__spec__ = None
    module.__loader__ = importlib.machinery.SourceFileLoader("__main__", MAIN_PATH)
    module.__file__ = MAIN_PATH
    module.__cached__ = None
    return module


def _source_module(*, name="sample", origin=SOURCE_PATH, package=False, loader=None):
    selected_loader = loader or importlib.machinery.SourceFileLoader(name, origin)
    spec = importlib.machinery.ModuleSpec(
        name, selected_loader, origin=origin, is_package=package,
    )
    module = ModuleType(name)
    module.__spec__ = spec
    module.__loader__ = selected_loader
    module.__file__ = origin
    module.__cached__ = util.cache_from_source(origin, optimization="")
    if package:
        location = origin.rsplit("/", 1)[0]
        spec.submodule_search_locations = [location]
        module.__path__ = [location]
    return module


def _registry(module=None):
    return {
        "__main__": _main_module(),
        "sample": _source_module() if module is None else module,
    }


def _project(registry, manifest=None, *, roots=ROOTS, main_path=MAIN_PATH, monkeypatch):
    selected_manifest = _manifest() if manifest is None else manifest
    with monkeypatch.context() as patch:
        patch.setattr(loaded_modules.sys, "pycache_prefix", None)
        return _project_modules(registry, selected_manifest, roots, main_path)


def _protected_tree(root):
    for relative in ("opt/env/site",):
        path = root / relative
        path.mkdir(parents=True, exist_ok=True)
        current = path
        while current != root:
            current.chmod(0o755)
            current = current.parent


def _observe(root, monkeypatch, registry, manifest=None):
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    selected_manifest = _manifest() if manifest is None else manifest
    try:
        with monkeypatch.context() as patch:
            patch.setattr(loaded_modules.sys, "pycache_prefix", None)
            patch.setattr(loaded_modules, "_registry_snapshot", lambda: dict(registry))
            return _observe_at(
                root_fd, selected_manifest, ROOTS, MAIN_PATH, owner=os.getuid(),
            )
    finally:
        os.close(root_fd)


def test_fixture_helper_is_fresh_immutable_empty_projection():
    first = _loaded()
    second = _loaded()
    assert first == LoadedModules(ROOTS, (), (), ())
    assert first is not second
    assert all(type(value) is tuple for value in (first.import_paths, first.modules,
                                                  first.files, first.absence))


def test_valid_main_source_and_pinned_bytecode_project(monkeypatch):
    manifest = _manifest({
        SOURCE_CACHE.removeprefix("/"): (0o644, _CACHE_BYTES),
    })
    projected = _project(_registry(), manifest, monkeypatch=monkeypatch)
    modules, files, absent = projected
    assert tuple(row[1] for row in modules) == ("main", "source")
    assert "opt/env/site/sample.py" in files
    assert SOURCE_CACHE.removeprefix("/") in files
    assert absent == ("etc/ld.so.preload",)


@pytest.mark.parametrize("mutation", [
    "origin-missing",
    "origin-outside-pin",
    "wrong-loader",
    "method-override",
    "wrong-cache-name",
    "package-redirect",
    "namespace-loader",
    "sourceless-loader",
    "initializing",
])
def test_unsupported_source_module_metadata_is_refused(monkeypatch, mutation):
    module = _source_module()
    registry = _registry(module)
    manifest = _manifest()
    if mutation == "origin-missing":
        module.__spec__.origin = None
    elif mutation == "origin-outside-pin":
        module.__spec__.origin = "/opt/env/elsewhere/sample.py"
        module.__file__ = module.__spec__.origin
    elif mutation == "wrong-loader":
        wrong = importlib.machinery.SourceFileLoader("other", SOURCE_PATH)
        module.__loader__ = wrong
        module.__spec__.loader = wrong
    elif mutation == "method-override":
        calls = []

        def custom_get_code(*_args, **_kwargs):
            calls.append(True)
            raise AssertionError("module loader callback invoked")

        module.__loader__.get_code = custom_get_code
    elif mutation == "wrong-cache-name":
        module.__cached__ = "/opt/env/site/__pycache__/other.pyc"
    elif mutation == "package-redirect":
        package = _source_module(name="sample", origin=SOURCE_PATH, package=True)
        package.__spec__.submodule_search_locations = ["/opt/env/redirect"]
        package.__path__ = ["/opt/env/redirect"]
        registry["sample"] = package
    elif mutation == "namespace-loader":
        namespace = ModuleType("sample")
        namespace.__spec__ = importlib.machinery.ModuleSpec(
            "sample", None, origin=None,
        )
        namespace.__loader__ = None
        registry["sample"] = namespace
    elif mutation == "sourceless-loader":
        pyc_path = "/opt/env/site/sample.pyc"
        sourceless = _source_module(
            origin=pyc_path,
            loader=importlib.machinery.SourcelessFileLoader("sample", pyc_path),
        )
        sourceless.__cached__ = None
        registry["sample"] = sourceless
        manifest = _manifest({"opt/env/site/sample.pyc": (0o644, b"pyc")})
    elif mutation == "initializing":
        module.__spec__._initializing = True

    with pytest.raises(ApprovalRefused):
        _project(registry, manifest, monkeypatch=monkeypatch)
    if mutation == "method-override":
        assert calls == []


def test_unpinned_source_origin_inside_declared_root_is_refused(monkeypatch):
    origin = "/opt/env/site/unlisted.py"
    module = _source_module(origin=origin)
    with pytest.raises(ApprovalRefused):
        _project(_registry(module), monkeypatch=monkeypatch)


@pytest.mark.parametrize("optimize", [1, False])
def test_optimization_state_must_be_exact_zero(monkeypatch, optimize):
    manifest, registry = _manifest(), _registry()
    refused = False
    with monkeypatch.context() as patch:
        patch.setattr(loaded_modules.sys, "flags", SimpleNamespace(optimize=optimize))
        try:
            _project_modules(registry, manifest, ROOTS, MAIN_PATH)
        except ApprovalRefused:
            refused = True
    assert refused


def test_existing_unpinned_bytecode_cache_refuses_after_positive_absence(tmp_path, monkeypatch):
    _protected_tree(tmp_path)
    registry = _registry()
    assert _observe(tmp_path, monkeypatch, registry).files
    cache = tmp_path / SOURCE_CACHE.removeprefix("/")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.parent.chmod(0o755)
    cache.write_bytes(b"synthetic unapproved cache; never imported")
    cache.chmod(0o644)
    with pytest.raises(ApprovalRefused, match="Python startup override exists"):
        _observe(tmp_path, monkeypatch, registry)


def test_moduletype_subclass_and_namespace_package_are_refused(monkeypatch):
    class DerivedModule(ModuleType):
        pass

    derived = DerivedModule("sample")
    with pytest.raises(ApprovalRefused):
        _project(_registry(derived), monkeypatch=monkeypatch)

    namespace = ModuleType("sample")
    namespace.__spec__ = importlib.machinery.ModuleSpec(
        "sample", None, origin=None,
    )
    namespace.__loader__ = None
    namespace.__path__ = ["/opt/env/site"]
    with pytest.raises(ApprovalRefused):
        _project(_registry(namespace), monkeypatch=monkeypatch)


def test_zip_import_root_is_not_an_unpacked_module_directory(monkeypatch):
    manifest = _manifest({"opt/env/site.zip": (0o644, b"synthetic zip")})
    with pytest.raises(ApprovalRefused):
        _project(
            _registry(), manifest, roots=("/opt/env/site.zip",),
            monkeypatch=monkeypatch,
        )


def test_genuine_builtin_and_frozen_module_labels_are_accepted(monkeypatch):
    builtin = ModuleType("sys")
    builtin.__loader__ = importlib.machinery.BuiltinImporter
    builtin.__spec__ = importlib.machinery.ModuleSpec(
        "sys", importlib.machinery.BuiltinImporter, origin="built-in",
    )
    frozen_name = "_frozen_importlib"
    frozen = ModuleType(frozen_name)
    frozen.__loader__ = importlib.machinery.FrozenImporter
    frozen.__spec__ = importlib.machinery.ModuleSpec(
        frozen_name, importlib.machinery.FrozenImporter, origin="frozen",
    )
    registry = _registry()
    registry.update({"sys": builtin, frozen_name: frozen})
    modules, _files, _absence = _project(registry, monkeypatch=monkeypatch)
    labels = {row[3]: row[1] for row in modules if row[1] in {"builtin", "frozen"}}
    assert labels == {"sys": "builtin", frozen_name: "frozen"}


def test_observer_requires_negative_cache_absence_and_protected_preload_absence(
    tmp_path, monkeypatch,
):
    _protected_tree(tmp_path)
    result = _observe(tmp_path, monkeypatch, _registry())
    assert SOURCE_CACHE.removeprefix("/") in tuple(
        item[0] for item in result.absence
    )
    etc = tmp_path / "etc"
    etc.mkdir()
    etc.chmod(0o755)
    (etc / "ld.so.preload").write_bytes(b"synthetic preload entry")
    with pytest.raises(ApprovalRefused):
        _observe(tmp_path, monkeypatch, _registry())


def test_pinned_bytecode_and_negative_preload_absence_are_accepted(
    tmp_path, monkeypatch,
):
    _protected_tree(tmp_path)
    manifest = _manifest({
        SOURCE_CACHE.removeprefix("/"): (0o644, _CACHE_BYTES),
    })
    result = _observe(tmp_path, monkeypatch, _registry(), manifest)
    assert tuple(item[0] for item in result.absence) == ("etc/ld.so.preload",)


def test_registry_projection_change_between_snapshots_is_refused(tmp_path, monkeypatch):
    _protected_tree(tmp_path)
    original = _registry()
    extra = ModuleType("sys")
    extra.__loader__ = importlib.machinery.BuiltinImporter
    extra.__spec__ = importlib.machinery.ModuleSpec(
        "sys", importlib.machinery.BuiltinImporter, origin="built-in",
    )
    snapshots = [original, {**original, "sys": extra}]
    calls = []

    def changing_registry():
        calls.append(True)
        return dict(snapshots[min(len(calls) - 1, 1)])

    root_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(loaded_modules.sys, "pycache_prefix", None)
            patch.setattr(loaded_modules, "_registry_snapshot", changing_registry)
            with pytest.raises(ApprovalRefused):
                _observe_at(root_fd, _manifest(), ROOTS, MAIN_PATH, owner=os.getuid())
    finally:
        os.close(root_fd)
    assert calls == [True, True]
