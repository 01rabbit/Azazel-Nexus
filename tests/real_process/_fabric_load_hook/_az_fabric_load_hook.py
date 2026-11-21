"""試験専用: プロセスが実際にロードした azazel_fabric を記録する。

site-packages に置いた .pth から読み込まれ、azazel_fabric の import が完了した
時点で、その版・ファイル・dist-info の RECORD 検証・direct_url・wheel の
sha256 を JSON で書く。Nexus 側と Knowledge 側のどちらのプロセスにも同じ仕組みで
働く。記録先ディレクトリが無ければ何もしない。失敗しても import を妨げない。
"""
import atexit
import base64
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
import sys

RECORD_DIR = "/tmp/fabric-load"
_ROLES = (
    ("knowledge_context_mtls_server", "knowledge-listener"),
    ("clocklab_server", "knowledge-listener"),
    ("mio_contextobsd", "nexus-contextobsd"),
    ("mio_entryd", "nexus-entryd"),
    ("knowledge_contextd", "nexus-contextd"),
    ("_knowledge_context_broker_process", "nexus-broker"),
    ("_knowledge_context_producer_process", "knowledge-listener"),
    ("pytest", "pytest"),
)


def _cmdline():
    try:
        with open("/proc/self/cmdline", "rb") as handle:
            return handle.read(2000).replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        return " ".join(sys.argv)


def _role(cmdline):
    for needle, role in _ROLES:
        if needle in cmdline:
            return role
    return "other"


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_check(dist):
    """RECORD の各ファイルのハッシュを実ファイルと突き合わせる。"""
    checked, bad = 0, []
    for entry in dist.files or []:
        name = str(entry)
        if name.endswith(("RECORD", ".pyc")) or entry.hash is None:
            continue
        path = dist.locate_file(entry)
        try:
            raw = open(path, "rb").read()
        except OSError:
            bad.append(name)
            continue
        want = entry.hash.value
        got = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
        checked += 1
        if got != want:
            bad.append(name)
    return {"checked": checked, "mismatched": bad}


def _expectation():
    try:
        with open(os.path.join(RECORD_DIR, "expect.json"), encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _write(final):
    module = sys.modules.get("azazel_fabric")
    if module is None:
        return
    import importlib.metadata as metadata

    cmdline = _cmdline()
    expect = _expectation()
    doc = {
        "schema": "u70-fabric-load/1", "final": final, "pid": os.getpid(), "uid": os.getuid(),
        "role": _role(cmdline), "cmdline": cmdline[:300],
        "module_version": getattr(module, "__version__", None),
        "module_file": getattr(module, "__file__", None),
        "loaded_submodules": sorted(
            getattr(m, "__file__", "") or "" for n, m in list(sys.modules.items())
            if n.startswith("azazel_fabric.")),
        "products_in_process": sorted({
            top for top in ("azazel_knowledge", "azazel_nexus", "azazel_nexus_runtime", "azazel_mio")
            if top in sys.modules}),
        "expected": expect,
    }
    try:
        dist = metadata.distribution("azazel-fabric")
        record_text = dist.read_text("RECORD") or ""
        direct = dist.read_text("direct_url.json")
        doc.update(
            dist_version=dist.version,
            dist_location=str(dist.locate_file("")),
            record_sha256=hashlib.sha256(record_text.encode()).hexdigest(),
            record_entries=len(record_text.splitlines()),
            record_check=_record_check(dist),
            direct_url=json.loads(direct) if direct else None,
            module_file_in_record=any(
                str(dist.locate_file(f)) == doc["module_file"] for f in dist.files or []),
        )
    except Exception as exc:  # 記録の失敗は import を妨げない
        doc["dist_error"] = repr(exc)
    wheel = expect.get("wheel_path")
    if wheel and os.path.exists(wheel):
        doc["wheel_sha256"] = _sha256_file(wheel)
        doc["wheel_sha256_matches_expected"] = doc["wheel_sha256"] == expect.get("wheel_sha256")
    direct = doc.get("direct_url") or {}
    hashes = (direct.get("archive_info") or {}).get("hashes") or {}
    doc["direct_url_sha256"] = hashes.get("sha256")
    path = os.path.join(RECORD_DIR, f"fabric-load-{doc['role']}-{os.getpid()}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, sort_keys=True, indent=1)
    os.replace(tmp, path)
    os.chmod(path, 0o644)


def _safe_write(final):
    try:
        _write(final)
    except Exception:
        pass


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name != "azazel_fabric":
            return None
        try:
            sys.meta_path.remove(self)
        except ValueError:
            return None
        spec = importlib.machinery.PathFinder.find_spec(name, path)
        loader = getattr(spec, "loader", None)
        if loader is None or not hasattr(loader, "exec_module"):
            return spec
        original = loader.exec_module

        def exec_module(module):
            original(module)
            _safe_write(False)

        loader.exec_module = exec_module
        return spec


def install():
    if os.path.isdir(RECORD_DIR) and "azazel_fabric" not in sys.modules:
        sys.meta_path.insert(0, _Finder())
        atexit.register(_safe_write, True)
