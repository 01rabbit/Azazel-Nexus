"""Bound current module metadata to a protected unpacked source profile.

This checks current names/paths against independently pinned files, including
potential bytecode caches. It is not proof of historical executed bytes, native
DT_NEEDED closure, filesystem freezing or arbitrary in-process resistance.
Debian's kernel/glibc/native loader substrate remains an explicit trust base.
"""

from dataclasses import dataclass
import _imp
from importlib import machinery, util
import os
import re
import sys
from types import ModuleType

from azazel_nexus.installed_manifest import InstalledManifest, installed_link_resolver
from azazel_nexus.operator_trust import ApprovalRefused

from .python_startup import _snapshot_at as _absence_snapshot_at, _stamp
from .startup_wrapper import validate_import_paths


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_MODULES = 2048
_MAX_ATTRIBUTES = 65536
_MISSING = object()
# Spec-less helper modules created by pinned native modules (not by the import
# system).  CPython Modules/pyexpat.c add_submodule() does PyModule_New() and
# inserts into sys.modules and the parent dict; Cython registers
# cython_runtime/_cython_X_Y_Z with PyImport_AddModule().  Both are bare
# PyModule_New modules: __spec__/__loader__ None, no __file__/__path__.
_EXTENSION_SUBMODULES = frozenset({("pyexpat", "errors"), ("pyexpat", "model")})
_EXPAT_ALIASES = frozenset(
    {"xml.parsers.expat.errors", "xml.parsers.expat.model"})
_BARE_DUNDERS = frozenset(
    {"__name__", "__doc__", "__package__", "__loader__", "__spec__"})
_MAX_CODES = 512


def _bounded_values(kind, namespace):
    """Restrict non-dunder content of accepted spec-less modules.

    kind: 'cython' (type objects, optional bool cline_in_traceback),
    'errors' (str constants plus str->int / int->str dicts), 'model' (ints).
    """
    for key, value in namespace.items():
        if key.startswith("__") and key.endswith("__"):
            continue
        if kind == "cython":
            ok = (isinstance(value, type) if key != "cline_in_traceback"
                  else type(value) is bool)
        elif kind == "model":
            ok = type(value) is int
        elif type(value) is str:
            ok = True
        elif key in ("codes", "messages") and type(value) is dict:
            first, second = (str, int) if key == "codes" else (int, str)
            ok = (len(value) <= _MAX_CODES and all(
                type(k) is first and type(v) is second for k, v in value.items()))
        else:
            ok = False
        if not ok:
            raise ApprovalRefused("spec-less module content refused")


_CYTHON_HELPER = re.compile(r"_cython_[0-9]+_[0-9]+_[0-9]+", re.ASCII)


@dataclass(frozen=True)
class LoadedModules:
    import_paths: tuple
    modules: tuple
    files: tuple
    absence: tuple


def _mapping(value, limit):
    if (type(value) is not dict or len(value) > limit
            or any(type(key) is not str for key in value)):
        raise ApprovalRefused("bounded plain module metadata required")
    return value


def _registry_snapshot():
    return dict(_mapping(sys.modules, _MAX_MODULES))


def _path(value):
    validate_import_paths((value,))
    if not value.startswith(("/usr/", "/opt/")):
        raise ApprovalRefused("protected module path required")
    return value.removeprefix("/")


def _under_roots(path, roots):
    return any(path.startswith(root + "/") for root in roots)


def _loader(loader, kind, name, origin):
    if type(loader) is not kind:
        raise ApprovalRefused("standard module file loader required")
    state = _mapping(vars(loader), 2)
    if (set(state) != {"name", "path"} or type(state["name"]) is not str
            or state["name"] != name or type(state["path"]) is not str
            or state["path"] != origin):
        raise ApprovalRefused("module file loader binding differs")


def _project_modules(registry, manifest, roots, main_path):
    registry = _mapping(registry, _MAX_MODULES)
    if (type(manifest) is not InstalledManifest or type(roots) is not tuple
            or validate_import_paths(roots) != roots or sys.pycache_prefix is not None
            or type(sys.flags.optimize) is not int or sys.flags.optimize != 0):
        raise ApprovalRefused("fixed unpacked module profile required")
    directories = {entry.path for entry in manifest.directories}
    selected = {entry.path: entry for entry in manifest.files}
    links = {entry.path for entry in manifest.links}
    if any(_path(root) not in directories for root in roots):
        raise ApprovalRefused("only unpacked declared module roots supported")
    main_relative = _path(main_path)
    if main_relative not in selected or selected[main_relative].mode != 0o755:
        raise ApprovalRefused("pinned controller wrapper required")
    if "etc/ld.so.preload" in selected or "etc/ld.so.preload" in links:
        raise ApprovalRefused("dynamic loader preload must remain absent")
    files, absent, modules = set(), {"etc/ld.so.preload"}, []
    attribute_count = 0
    # One manifest validation per projection; never reused across projections.
    resolve = installed_link_resolver(manifest)
    resolved = {}

    def pinned(origin):
        relative = _path(origin)
        terminal = resolved.get(relative)
        if terminal is None:
            terminal = resolved[relative] = resolve(relative)
        if terminal not in selected:
            raise ApprovalRefused("module origin is not independently pinned")
        files.add(terminal)
        return relative

    native, specless, sources = {}, [], {}

    for alias, module in sorted(registry.items()):
        if not 0 < len(alias) <= 512 or type(module) is not ModuleType:
            raise ApprovalRefused("ordinary loaded modules required")
        namespace = _mapping(vars(module), 4096)
        attribute_count += len(namespace)
        if attribute_count > _MAX_ATTRIBUTES:
            raise ApprovalRefused("module metadata budget exceeded")
        module_name = namespace.get("__name__")
        if (type(module_name) is not str or not 0 < len(module_name) <= 512
                or registry.get(module_name) is not module):
            raise ApprovalRefused("module canonical alias differs")
        spec = namespace.get("__spec__")
        loader = namespace.get("__loader__")
        if module is registry.get("__main__"):
            if (spec is not None or module_name != "__main__"
                    or type(namespace.get("__file__")) is not str
                    or namespace["__file__"] != main_path
                    or namespace.get("__cached__") is not None
                    or "__path__" in namespace):
                raise ApprovalRefused("fixed controller main module required")
            _loader(loader, machinery.SourceFileLoader, "__main__", main_path)
            pinned(main_path)
            modules.append((alias, "main", id(module), id(loader), main_relative))
            continue
        if spec is None:
            specless.append((alias, module, namespace, module_name))
            continue
        if type(spec) is not machinery.ModuleSpec:
            raise ApprovalRefused("ordinary module spec required")
        details = _mapping(vars(spec), 32)
        name, origin = details.get("name"), details.get("origin")
        if (type(name) is not str or not 0 < len(name) <= 512
                or registry.get(name) is not module or details.get("loader") is not loader
                or details.get("_initializing", False) is not False):
            raise ApprovalRefused("module spec binding differs")
        package = details.get("submodule_search_locations")
        if loader is machinery.BuiltinImporter or loader is machinery.FrozenImporter:
            builtin = loader is machinery.BuiltinImporter
            if (type(origin) is not str or origin != ("built-in" if builtin else "frozen")
                    or not (_imp.is_builtin(name) if builtin else _imp.is_frozen(name))
                    or package is not None or "__path__" in namespace):
                raise ApprovalRefused("genuine builtin/frozen module required")
            modules.append((alias, "builtin" if builtin else "frozen", id(module), name))
            if builtin:
                native[alias] = (module, "builtin")
            continue
        if (type(origin) is not str or type(namespace.get("__file__")) is not str
                or namespace["__file__"] != origin or not _under_roots(origin, roots)):
            raise ApprovalRefused("covered module file origin required")
        relative = pinned(origin)
        if type(loader) is machinery.SourceFileLoader and origin.endswith(".py"):
            kind = "source"
            _loader(loader, machinery.SourceFileLoader, name, origin)
            cached = util.cache_from_source(origin, optimization="")
            if (type(namespace.get("__cached__")) is not str
                    or namespace["__cached__"] != cached):
                raise ApprovalRefused("canonical source bytecode cache required")
            cache_relative = _path(cached)
            if cache_relative in selected or cache_relative in links:
                pinned(cached)
            else:
                absent.add(cache_relative)
        elif type(loader) is machinery.ExtensionFileLoader and any(
            origin.endswith(suffix) for suffix in _imp.extension_suffixes()
        ):
            kind, cached = "extension", None
            _loader(loader, machinery.ExtensionFileLoader, name, origin)
            if namespace.get("__cached__") is not None:
                raise ApprovalRefused("native module bytecode cache refused")
        else:
            raise ApprovalRefused("module loader outside unpacked source profile")
        paths = namespace.get("__path__", _MISSING)
        if package is None:
            if paths is not _MISSING:
                raise ApprovalRefused("unexpected module package path")
            locations = ()
        else:
            expected = origin.rsplit("/", 1)[0]
            if (type(package) is not list or type(paths) is not list
                    or len(package) != 1 or len(paths) != 1
                    or type(package[0]) is not str or type(paths[0]) is not str
                    or package[0] != expected or paths[0] != expected
                    or _path(expected) not in directories):
                raise ApprovalRefused("ordinary pinned package directory required")
            locations = (expected,)
        modules.append((alias, kind, id(module), id(spec), id(loader), relative, cached, locations))
        if kind == "source":
            sources[alias] = module
        if kind == "extension":
            native[alias] = (module, kind)
    for alias, module, namespace, module_name in sorted(specless, key=lambda row: row[0]):
        expat_alias = alias in _EXPAT_ALIASES
        if ((module_name != alias and not expat_alias)
                or namespace.get("__spec__", _MISSING) is not None
                or namespace.get("__loader__", _MISSING) is not None
                or namespace.get("__package__", _MISSING) is not None
                or not {key for key in namespace if key.startswith("__")} <= _BARE_DUNDERS):
            raise ApprovalRefused("ordinary module spec required")
        parent, _, child = alias.rpartition(".")
        if expat_alias or (parent, child) in _EXTENSION_SUBMODULES:
            _bounded_values("model" if child == "model" else "errors", namespace)
        else:
            _bounded_values("cython", namespace)
        if expat_alias:
            # xml/parsers/expat.py aliases pyexpat.errors/model under its own
            # name; the object keeps __name__ 'pyexpat.<child>'.
            canonical = "pyexpat." + child
            shim = sources.get(parent)
            if (module_name != canonical or shim is None
                    or registry.get(canonical) is not module
                    or vars(shim).get(child, _MISSING) is not module):
                raise ApprovalRefused("spec-less submodule parent binding differs")
            modules.append((alias, "extension-submodule-alias", id(module), id(shim), canonical))
        elif (parent, child) in _EXTENSION_SUBMODULES:
            owner = native.get(parent)
            if (owner is None or registry.get(parent) is not owner[0]
                    or vars(owner[0]).get(child, _MISSING) is not module):
                raise ApprovalRefused("spec-less submodule parent binding differs")
            modules.append((alias, "extension-submodule", id(module), id(owner[0]), parent))
        elif alias == "cython_runtime" or _CYTHON_HELPER.fullmatch(alias):
            # Limit: this only shows that some pinned ExtensionFileLoader module
            # is loaded; Cython-ness of that module is not provable from its loader.
            if not any(kind == "extension" for _, kind in native.values()):
                raise ApprovalRefused("cython helper requires pinned extension")
            modules.append((alias, "cython-helper", id(module)))
        else:
            raise ApprovalRefused("ordinary module spec required")
    if "__main__" not in registry:
        raise ApprovalRefused("controller main module missing")
    return tuple(modules), tuple(sorted(files)), tuple(sorted(absent))


def _observe_at(root_fd, manifest, roots, main_path, *, owner):
    first = _project_modules(_registry_snapshot(), manifest, roots, main_path)
    absence = _absence_snapshot_at(root_fd, first[2], owner=owner)
    if (_project_modules(_registry_snapshot(), manifest, roots, main_path) != first
            or _absence_snapshot_at(root_fd, first[2], owner=owner) != absence):
        raise ApprovalRefused("loaded module bindings changed")
    return LoadedModules(roots, first[0], first[1], absence)


def observe_loaded_modules(manifest, roots, main_path) -> LoadedModules:
    """Arguments are derived solely from protected manifest/canonical wrappers."""
    try:
        root = os.open("/", _DIR)
        try:
            before = _stamp(os.fstat(root), owner=0)
            result = _observe_at(root, manifest, roots, main_path, owner=0)
            if (_stamp(os.fstat(root), owner=0) != before
                    or _stamp(os.stat("/", follow_symlinks=False), owner=0) != before):
                raise ApprovalRefused("module observation root changed")
            return result
        finally:
            os.close(root)
    except Exception:
        raise ApprovalRefused("protected loaded module profile refused") from None
