"""Fixed standard import routing over independently selected roots.

No configured finder/hook is invoked. This observes current routing, not loaded bytecode,
module-origin coverage, a filesystem freeze or arbitrary in-process resistance.
The caller separately measures files and the protected startup absence set.
"""

from dataclasses import dataclass
import _imp
from importlib import machinery
import math
import sys
from types import FunctionType
import zipimport

from azazel_nexus.installed_manifest import InstalledManifest
from azazel_nexus.operator_trust import ApprovalRefused

from .startup_wrapper import validate_import_paths


_MAX_CACHE = 2048
_MAX_NAMES = 16384


@dataclass(frozen=True)
class ImportRouting:
    import_paths: tuple
    cache: tuple


def _details():
    return (
        (machinery.ExtensionFileLoader, _imp.extension_suffixes()),
        (machinery.SourceFileLoader, [".py"]),
        (machinery.SourcelessFileLoader, [".pyc"]),
    )


def _check_file_hook(hook, details):
    expected = machinery.FileFinder.path_hook(*details)
    if (type(hook) is not FunctionType or hook.__code__ is not expected.__code__
            or hook.__globals__ is not expected.__globals__
            or hook.__defaults__ is not None or hook.__kwdefaults__ is not None
            or hook.__closure__ is None or expected.__closure__ is None
            or len(hook.__closure__) != len(expected.__closure__)):
        raise ApprovalRefused("standard file import hook required")
    values = dict(zip(hook.__code__.co_freevars,
                      (cell.cell_contents for cell in hook.__closure__), strict=True))
    selected = values.get("loader_details")
    if (values.get("cls") is not machinery.FileFinder or type(selected) is not tuple
            or len(selected) != len(details)):
        raise ApprovalRefused("standard file import loaders required")
    for actual, (loader, suffixes) in zip(selected, details, strict=True):
        if (type(actual) is not tuple or len(actual) != 2 or actual[0] is not loader
                or type(actual[1]) is not list or len(actual[1]) != len(suffixes)
                or any(type(suffix) is not str for suffix in actual[1])
                or actual[1] != suffixes):
            raise ApprovalRefused("standard file import suffixes required")


def _covered_directory(path, roots, directories):
    return (path.removeprefix("/") in directories and any(
        path == root or path.startswith(root + "/") for root in roots
        if root.removeprefix("/") in directories
    ))


def _finder_state(finder, expected_keys):
    state = vars(finder)
    if (type(state) is not dict or len(state) != len(expected_keys)
            or any(type(key) is not str for key in state)
            or set(state) != expected_keys):
        raise ApprovalRefused("Python finder instance overrides refused")
    return state


def _names(value):
    if (type(value) is not set or len(value) > _MAX_NAMES
            or any(type(name) is not str or not 0 < len(name) <= 255
                   or name in {".", ".."} or "/" in name
                   or any(ord(char) < 32 or ord(char) == 127 for char in name)
                   for name in value)):
        raise ApprovalRefused("bounded plain Python finder names required")
    return tuple(sorted(value))


def _zip_records(value, archive):
    if type(value) is not dict or len(value) > 4096:
        raise ApprovalRefused("bounded plain Python zip directory required")
    records = []
    for name, row in tuple(value.items()):
        if (type(name) is not str or not 0 < len(name) <= 512
                or name.startswith("/") or any(part in {"", ".", ".."}
                                               for part in name.removesuffix("/").split("/"))
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or type(row) is not tuple or len(row) != 8 or type(row[0]) is not str
                or row[0] != archive + "/" + name
                or any(type(number) is not int or not 0 <= number < (1 << 63)
                       for number in row[1:])):
            raise ApprovalRefused("plain Python zip directory record required")
        records.append((name, row))
    return tuple(sorted(records))


def _snapshot(import_paths, manifest, main_path=None):
    if (type(import_paths) is not tuple or validate_import_paths(import_paths) != import_paths
            or type(manifest) is not InstalledManifest
            or type(sys.meta_path) is not list or type(sys.path_hooks) is not list
            or type(sys.path_importer_cache) is not dict
            or type(sys.path) is not list or not 0 < len(sys.path) <= 16
            or validate_import_paths(sys.path) != import_paths
            or len(sys.meta_path) != 3 or any(
                actual is not expected for actual, expected in zip(
                    sys.meta_path, (machinery.BuiltinImporter, machinery.FrozenImporter,
                                    machinery.PathFinder), strict=True,
                )
            )):
        raise ApprovalRefused("fixed standard Python import routing required")
    if len(sys.path_hooks) != 2:
        raise ApprovalRefused("standard Python path hooks required")
    hooks = tuple(sys.path_hooks)
    if hooks[0] is not zipimport.zipimporter:
        raise ApprovalRefused("standard Python path hooks required")
    if len(sys.path_importer_cache) > _MAX_CACHE:
        raise ApprovalRefused("bounded Python importer cache required")
    cache = tuple(sys.path_importer_cache.items())
    details = _details()
    _check_file_hook(hooks[1], details)
    expected_loaders = tuple((suffix, loader) for loader, suffixes in details for suffix in suffixes)
    directories = {entry.path for entry in manifest.directories}
    files = {entry.path for entry in manifest.files}
    if any(path.removeprefix("/") not in directories and not (
        path.endswith(".zip") and path.removeprefix("/") in files
    ) for path in import_paths):
        raise ApprovalRefused("Python import roots are not exactly covered")
    result = []
    names_seen = 0
    for path, finder in cache:
        validate_import_paths((path,))
        if finder is None:
            # CPython caches this implicit missing zip before the wrapper
            # replaces sys.path. The separate fixed startup reader forbids it.
            # CPython (pymain) also probes the executed script path as a
            # possible zip/directory importer and caches the failure as a
            # negative entry. Accept it only for the exact running main path
            # (the one loaded_modules pins) when it is a manifest FILE entry.
            if path != "/usr/lib/python313.zip" and not (
                main_path is not None and path == main_path
                and path.removeprefix("/") in files
            ) and not _covered_directory(path, import_paths, directories):
                raise ApprovalRefused("uncovered negative Python importer cache")
            result.append((path, "none"))
        elif type(finder) is machinery.FileFinder:
            state = _finder_state(finder, {
                "path", "_loaders", "_path_mtime", "_path_cache", "_relaxed_path_cache",
            })
            if (not _covered_directory(path, import_paths, directories)
                    or type(finder.path) is not str or finder.path != path
                    or type(finder._loaders) is not list
                    or len(finder._loaders) != len(expected_loaders)):
                raise ApprovalRefused("uncovered Python file finder")
            loaders = tuple(finder._loaders)
            if any(
                type(item) is not tuple or len(item) != 2
                or type(item[0]) is not str for item in loaders
            ) or any(actual[0] != expected[0] or actual[1] is not expected[1]
                     for actual, expected in zip(loaders, expected_loaders, strict=True)):
                raise ApprovalRefused("Python file finder loaders differ")
            mtime = state["_path_mtime"]
            if type(mtime) not in (int, float) or not math.isfinite(mtime):
                raise ApprovalRefused("plain Python file finder time required")
            names = _names(state["_path_cache"])
            relaxed = _names(state["_relaxed_path_cache"])
            names_seen += len(names) + len(relaxed)
            result.append((path, "file", id(finder), mtime, names, relaxed))
        elif type(finder) is zipimport.zipimporter:
            # The supported 3.13 interpreter uses the module-level directory
            # cache; older host test interpreters also retain _files per finder.
            legacy = sys.version_info[:2] in {(3, 11), (3, 12)}
            state = _finder_state(finder, {"archive", "prefix", "_files"} if legacy
                                  else {"archive", "prefix"})
            archive, prefix = finder.archive, finder.prefix
            if (type(archive) is not str or archive not in import_paths
                    or not archive.endswith(".zip") or archive.removeprefix("/") not in files
                    or type(prefix) is not str or len(prefix) > 4096
                    or (prefix and (not prefix.endswith("/") or any(
                        part in {"", ".", ".."} for part in prefix[:-1].split("/")
                    )))
                    or path != archive + ("/" + prefix[:-1] if prefix else "")):
                raise ApprovalRefused("uncovered Python zip finder")
            zip_cache = zipimport._zip_directory_cache
            if (type(zip_cache) is not dict or len(zip_cache) > _MAX_CACHE
                    or any(type(key) is not str for key in zip_cache)):
                raise ApprovalRefused("bounded plain Python global zip cache required")
            contents = zip_cache.get(archive)
            if legacy and contents is not state["_files"]:
                raise ApprovalRefused("Python zip cache binding differs")
            records = _zip_records(contents, archive)
            if zip_cache.get(archive) is not contents or zipimport._zip_directory_cache is not zip_cache:
                raise ApprovalRefused("Python global zip cache changed")
            names_seen += len(records)
            result.append((path, "zip", archive, prefix, id(finder), id(contents), records))
        else:
            raise ApprovalRefused("nonstandard Python importer cache")
        if names_seen > _MAX_NAMES:
            raise ApprovalRefused("Python importer observation budget exceeded")
    current_cache = tuple(sys.path_importer_cache.items())
    if (len(current_cache) != len(cache) or any(
        type(current[0]) is not str or current[0] != old[0] or current[1] is not old[1]
        for current, old in zip(current_cache, cache)
    ) or len(sys.path_hooks) != len(hooks) or any(
        current is not old for current, old in zip(sys.path_hooks, hooks)
    )):
        raise ApprovalRefused("Python import routing changed during observation")
    return ImportRouting(import_paths, tuple(sorted(result)))


def observe_import_routing(import_paths, manifest, *, main_path=None) -> ImportRouting:
    """Only protected wrapper/manifest-derived inputs reach production here."""
    try:
        first = _snapshot(import_paths, manifest, main_path)
        if _snapshot(import_paths, manifest, main_path) != first:
            raise ApprovalRefused("Python import routing changed between observations")
        return first
    except Exception:
        raise ApprovalRefused("protected Python import routing refused") from None
