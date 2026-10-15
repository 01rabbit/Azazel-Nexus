"""Tests that current import routing is standard and covered by pinned roots."""

from hashlib import sha256
import zipfile
import zipimport

import pytest

from azazel_nexus.installed_manifest import (
    InstalledDirectory,
    InstalledFile,
    InstalledManifest,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import import_routing
from azazel_nexus_runtime.import_routing import (
    ImportRouting,
    observe_import_routing,
)


_IMPORT_PATHS = ("/opt/env/site",)
_EMPTY_DIGEST = sha256(b"").hexdigest()


def _routing(import_paths=("/opt/env/site",)):
    return ImportRouting(import_paths, ())


def _manifest(*, directories=("opt/env/site",)):
    return InstalledManifest(
        files=(InstalledFile("opt/env/site/marker", 0o644, 0, _EMPTY_DIGEST),),
        directories=tuple(InstalledDirectory(path) for path in directories),
        version=2,
    )


def _zip_fixture(tmp_path, monkeypatch):
    archive_file = tmp_path / "actual.zip"
    with zipfile.ZipFile(archive_file, "w") as archive:
        archive.writestr("pkg/__init__.py", b"value = 1\n")
        archive.writestr("pkg/app.py", b"value = 2\n")
    raw = archive_file.read_bytes()
    archive_path = "/opt/env/site.zip"
    manifest = InstalledManifest(
        files=(InstalledFile(
            "opt/env/site.zip", 0o644, len(raw), sha256(raw).hexdigest(),
        ),),
        directories=(InstalledDirectory("opt/env"),),
        version=2,
    )
    finder = zipimport.zipimporter(str(archive_file))
    state = vars(finder)
    source_archive = state["archive"]
    source_toc = zipimport._zip_directory_cache[source_archive]
    toc = {
        name: (archive_path + "/" + name, *row[1:])
        for name, row in source_toc.items()
    }
    state["archive"] = archive_path
    state["prefix"] = ""
    if "_files" in state:
        state["_files"] = toc
    monkeypatch.setitem(zipimport._zip_directory_cache, archive_path, toc)
    return archive_path, manifest, finder, toc


def _standard_hooks():
    return [zipimport.zipimporter, import_routing.machinery.FileFinder.path_hook(
        *import_routing._details()
    )]


def _observe(
    monkeypatch,
    *,
    import_paths=_IMPORT_PATHS,
    manifest=None,
    cache=(),
    hooks=None,
    meta_path=None,
    configure=None,
):
    if manifest is None:
        manifest = _manifest()
    with monkeypatch.context() as patch:
        patch.setattr(import_routing.sys, "path", list(import_paths))
        selected_meta = meta_path if meta_path is not None else (
            import_routing.machinery.BuiltinImporter,
            import_routing.machinery.FrozenImporter,
            import_routing.machinery.PathFinder,
        )
        selected_hooks = hooks if hooks is not None else _standard_hooks()
        patch.setattr(import_routing.sys, "meta_path", list(selected_meta))
        patch.setattr(import_routing.sys, "path_hooks", list(selected_hooks))
        patch.setattr(import_routing.sys, "path_importer_cache", dict(cache))
        if configure is not None:
            configure(patch)
        return observe_import_routing(import_paths, manifest)


def _finder(path="/opt/env/site"):
    return import_routing.machinery.FileFinder(path, *import_routing._details())


def test_exact_standard_meta_path_and_filefinder_factory_are_accepted(monkeypatch):
    finder = _finder()
    calls = []
    original_snapshot = import_routing._snapshot

    def count_snapshot(*args):
        calls.append(True)
        return original_snapshot(*args)

    result = _observe(
        monkeypatch,
        cache=(("/opt/env/site", finder),),
        configure=lambda patch: patch.setattr(import_routing, "_snapshot", count_snapshot),
    )

    assert result.import_paths == _IMPORT_PATHS
    assert result.cache == ((
        "/opt/env/site", "file", id(finder), finder._path_mtime, (), (),
    ),)
    assert calls == [True, True]


def test_fixed_negative_zip_cache_entry_is_allowed(monkeypatch):
    result = _observe(
        monkeypatch,
        cache=(("/usr/lib/python313.zip", None),),
    )
    assert result.cache == (("/usr/lib/python313.zip", "none"),)


@pytest.mark.parametrize("bad_meta", [
    (),
    (object(), import_routing.machinery.FrozenImporter,
     import_routing.machinery.PathFinder),
])
def test_nonstandard_meta_finder_is_refused_without_invoking_it(monkeypatch, bad_meta):
    class NeverCompare:
        def __eq__(self, _other):
            pytest.fail("meta finder equality must not be invoked")

    items = list(bad_meta)
    if items:
        items[0] = NeverCompare()
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, meta_path=items)


def test_custom_path_hook_is_refused_without_calling_it(monkeypatch):
    calls = []

    def custom_hook(path):
        calls.append(path)
        raise AssertionError("observer invoked a path hook")

    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, hooks=(zipimport.zipimporter, custom_hook))
    assert calls == []


def test_altered_filefinder_closure_suffix_and_loader_metadata_are_refused(monkeypatch):
    bad_details = list(import_routing._details())
    loader, suffixes = bad_details[0]
    bad_details[0] = (loader, [*suffixes, ".evil"])
    altered_hook = import_routing.machinery.FileFinder.path_hook(*bad_details)
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, hooks=(zipimport.zipimporter, altered_hook))

    finder = _finder()
    finder._loaders[0] = (".evil", finder._loaders[0][1])
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, cache=(("/opt/env/site", finder),))


def test_filefinder_find_spec_override_is_refused_without_calling_it(monkeypatch):
    finder = _finder()
    calls = []

    def custom_find_spec(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("observer invoked a finder")

    finder.find_spec = custom_find_spec
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, cache=(("/opt/env/site", finder),))
    assert calls == []


def test_unknown_finder_is_refused_without_equality_or_hook_execution(monkeypatch):
    class NeverCompare:
        def __eq__(self, _other):
            pytest.fail("unknown finder equality must not be invoked")

    finder = NeverCompare()
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, cache=(("/opt/env/site", finder),))


@pytest.mark.parametrize("case", ["uncovered", "wrong-finder-path"])
def test_filefinder_must_be_covered_and_match_its_cache_key(monkeypatch, case):
    key = "/opt/env/other" if case == "uncovered" else "/opt/env/site"
    finder = _finder(key)
    if case == "wrong-finder-path":
        finder.path = "/opt/env/other"
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, cache=((key, finder),))


def test_import_root_requires_exact_manifest_directory_entry(monkeypatch):
    paths = ("/opt/env/site/sub",)
    manifest = _manifest(directories=("opt/env/site",))
    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, import_paths=paths, manifest=manifest)


def test_real_zipimporter_directory_is_copied_and_pinned(tmp_path, monkeypatch):
    archive_path, manifest, finder, toc = _zip_fixture(tmp_path, monkeypatch)
    result = _observe(
        monkeypatch,
        import_paths=(archive_path,),
        manifest=manifest,
        cache=((archive_path, finder),),
    )
    cache_item = result.cache[0]
    assert cache_item[:6] == (
        archive_path, "zip", archive_path, "", id(finder), id(toc),
    )
    records = cache_item[6]
    assert type(records) is tuple
    assert tuple(name for name, _row in records) == (
        "pkg/__init__.py", "pkg/app.py",
    )
    assert all(type(row) is tuple and len(row) == 8 for _name, row in records)
    toc.clear()
    assert cache_item[6] == records


def test_real_zipimporter_with_altered_directory_metadata_is_refused(tmp_path, monkeypatch):
    archive_path, manifest, finder, toc = _zip_fixture(tmp_path, monkeypatch)
    name, row = next(iter(toc.items()))
    toc[name] = (archive_path + "/altered.py", *row[1:])
    with pytest.raises(ApprovalRefused):
        _observe(
            monkeypatch,
            import_paths=(archive_path,),
            manifest=manifest,
            cache=((archive_path, finder),),
        )


def test_zip_directory_replacement_during_snapshot_is_refused(
    tmp_path, monkeypatch,
):
    archive_path, manifest, finder, toc = _zip_fixture(tmp_path, monkeypatch)
    original_records = import_routing._zip_records
    replaced = False

    def replace_global_toc(contents, archive):
        nonlocal replaced
        records = original_records(contents, archive)
        if not replaced:
            replaced = True
            monkeypatch.setitem(
                zipimport._zip_directory_cache, archive, dict(contents),
            )
        return records

    with pytest.raises(ApprovalRefused):
        _observe(
            monkeypatch,
            import_paths=(archive_path,),
            manifest=manifest,
            cache=((archive_path, finder),),
            configure=lambda patch: patch.setattr(
                import_routing, "_zip_records", replace_global_toc,
            ),
        )
    assert replaced
    assert zipimport._zip_directory_cache[archive_path] is not toc


def test_zip_directory_rejects_mutable_rows_and_custom_comparison(monkeypatch, tmp_path):
    archive_path, manifest, finder, toc = _zip_fixture(tmp_path, monkeypatch)
    name = next(iter(toc))
    toc[name] = [*toc[name]]
    with pytest.raises(ApprovalRefused):
        _observe(
            monkeypatch,
            import_paths=(archive_path,),
            manifest=manifest,
            cache=((archive_path, finder),),
        )

    compared = []

    class EvilRow:
        def __eq__(self, _other):
            compared.append(True)
            pytest.fail("zip TOC row equality must not be invoked")

    toc[name] = EvilRow()
    with pytest.raises(ApprovalRefused):
        _observe(
            monkeypatch,
            import_paths=(archive_path,),
            manifest=manifest,
            cache=((archive_path, finder),),
        )
    assert compared == []


def test_nonstring_global_zip_cache_key_is_refused_without_comparison(
    monkeypatch, tmp_path,
):
    archive_path, manifest, finder, toc = _zip_fixture(tmp_path, monkeypatch)
    compared = []

    class CollidingKey:
        def __hash__(self):
            return hash(archive_path)

        def __eq__(self, _other):
            compared.append(True)
            pytest.fail("global zip cache key comparison must not run")

    global_cache = {CollidingKey(): toc}
    with pytest.raises(ApprovalRefused):
        _observe(
            monkeypatch,
            import_paths=(archive_path,),
            manifest=manifest,
            cache=((archive_path, finder),),
            configure=lambda patch: patch.setattr(
                zipimport, "_zip_directory_cache", global_cache,
            ),
        )
    assert compared == []


def test_zip_finder_method_override_is_refused_without_calling_it(tmp_path, monkeypatch):
    archive_path, manifest, finder, _toc = _zip_fixture(tmp_path, monkeypatch)
    calls = []

    def custom_find_spec(*_args, **_kwargs):
        calls.append(True)
        raise AssertionError("observer invoked zip finder")

    vars(finder)["find_spec"] = custom_find_spec
    with pytest.raises(ApprovalRefused):
        _observe(
            monkeypatch,
            import_paths=(archive_path,),
            manifest=manifest,
            cache=((archive_path, finder),),
        )
    assert calls == []


def test_importer_cache_mutation_during_observation_is_refused(monkeypatch):
    cache = {}
    original_details = import_routing._details

    def add_cache_entry():
        details = original_details()
        cache["/opt/env/site"] = None
        return details

    def configure(patch):
        patch.setattr(import_routing, "_details", add_cache_entry)
        patch.setattr(import_routing.sys, "path_importer_cache", cache)

    with pytest.raises(ApprovalRefused):
        _observe(monkeypatch, configure=configure)
    assert "/opt/env/site" in cache


def test_helper_returns_immutable_expected_empty_snapshot():
    observed = _routing()
    assert observed == ImportRouting(("/opt/env/site",), ())
    assert type(observed.import_paths) is tuple
    assert type(observed.cache) is tuple
