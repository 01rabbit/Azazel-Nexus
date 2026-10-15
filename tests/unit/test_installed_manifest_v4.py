"""Schema 4 installed manifests: nested relative links and etc/ paths.

Schema 1/2/3 bytes and refusals must stay exactly as before.
"""

from dataclasses import replace
from hashlib import sha256
import json
import os

import pytest

from azazel_nexus import installed_candidate as candidate
from azazel_nexus import installed_files as measured
from azazel_nexus.installed_manifest import (
    InstalledDirectory as _Dir, InstalledFile as _File, InstalledLink as _Link,
    InstalledManifest,
    decode_installed_manifest, encode_installed_manifest, resolve_installed_link,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs
from azazel_nexus_runtime import python_startup
from azazel_nexus_runtime.startup_wrapper import render_wrapper
from test_bootstrap_generation import _context
import test_runtime_running_python as running_python
import test_runtime_import_routing as import_routing
import test_runtime_loaded_modules as loaded_modules


def InstalledFile(path, mode, size, digest):
    return _File(path, mode, size, digest, True)


def InstalledLink(path, target):
    return _Link(path, target, True)


def InstalledDirectory(path):
    return _Dir(path, 0o755, True)


LIB = "usr/lib/aarch64-linux-gnu/libpython3.13.so.1"
CONFIG_DIR = "usr/lib/python3.13/config-3.13-aarch64-linux-gnu"
SO_LINK = CONFIG_DIR + "/libpython3.13.so"
SO_TARGET = "../../aarch64-linux-gnu/libpython3.13.so.1"
SITE = "etc/python3.13/sitecustomize.py"
SITE_LINK = "usr/lib/python3.13/sitecustomize.py"
SITE_TARGET = "/etc/python3.13/sitecustomize.py"


def file_entry(path, content=b"x\n", mode=0o644):
    return InstalledFile(path, mode, len(content), sha256(content).hexdigest())


def debian(version=4, **changes):
    manifest = InstalledManifest(
        (file_entry(SITE), file_entry(LIB)),
        (InstalledDirectory("usr/lib/python3.13"), InstalledDirectory(CONFIG_DIR)),
        version,
        (InstalledLink(SO_LINK, SO_TARGET), InstalledLink(SITE_LINK, SITE_TARGET)),
    )
    return replace(manifest, **changes) if changes else manifest


def v4(links, files=(SITE, LIB), directories=()):
    return InstalledManifest(
        tuple(file_entry(path) for path in sorted(files)),
        tuple(InstalledDirectory(path) for path in directories), 4,
        tuple(sorted(links, key=lambda link: link.path)),
    )


def pin(raw):
    return "sha256:" + sha256(raw).hexdigest()


def test_v4_accepts_exact_debian_shapes_and_round_trips():
    manifest = debian()
    raw = encode_installed_manifest(manifest)
    assert json.loads(raw)["schema"] == "azazel-nexus/selected-installed-files/v4"
    decoded = decode_installed_manifest(raw, expected_digest=pin(raw))
    assert decoded == manifest and decoded.version == 4
    assert encode_installed_manifest(decoded) == raw
    assert resolve_installed_link(decoded, SO_LINK) == LIB
    assert resolve_installed_link(decoded, SITE_LINK) == SITE
    assert resolve_installed_link(decoded, LIB) == LIB


def test_v4_resolves_chain_through_further_links():
    links = (InstalledLink("usr/lib/a/x", "../b/y"), InstalledLink("usr/lib/b/y", "w"),
             InstalledLink("usr/lib/b/w", "/etc/p/q"))
    manifest = v4(links, files=("etc/p/q",))
    assert resolve_installed_link(manifest, "usr/lib/a/x") == "etc/p/q"
    raw = encode_installed_manifest(manifest)
    assert decode_installed_manifest(raw, expected_digest=pin(raw)) == manifest


def test_v4_cross_root_relative_target_is_allowed():
    link = InstalledLink("opt/env/bin/python", "../../../usr/bin/python3.13")
    manifest = v4((link,), files=("usr/bin/python3.13",))
    assert resolve_installed_link(manifest, link.path) == "usr/bin/python3.13"


def test_v3_bytes_unchanged_and_still_refuses_debian_shapes():
    v3 = InstalledManifest(
        (file_entry("usr/lib/m.py"),), (InstalledDirectory("usr/lib"),), 3,
        (InstalledLink("usr/lib/alias.py", "m.py"),),
    )
    raw = encode_installed_manifest(v3)
    assert json.loads(raw)["schema"].endswith("/v3")
    assert decode_installed_manifest(raw, expected_digest=pin(raw)) == v3
    shapes = (
        ((file_entry(SITE), file_entry(LIB)), (InstalledLink(SO_LINK, SO_TARGET),)),
        ((file_entry(LIB), file_entry("usr/lib/etc.py")),
         (InstalledLink("usr/lib/a", "../aarch64-linux-gnu/libpython3.13.so.1"),)),
        ((file_entry("usr/q"),), (InstalledLink("usr/lib/a", "../q"),)),
        ((file_entry("etc/q"),), (InstalledLink("usr/lib/a", "/etc/q"),)),
        ((file_entry("usr/lib/b"), file_entry("etc/q")), (InstalledLink("usr/lib/a", "b"),)),
    )
    for files, links in shapes:
        with pytest.raises(ApprovalRefused):
            InstalledManifest(files, (), 3, links)
    with pytest.raises(ApprovalRefused):
        encode_installed_manifest(InstalledManifest((file_entry(SITE),), version=2))
    with pytest.raises(ApprovalRefused):
        encode_installed_manifest(InstalledManifest((file_entry(SITE),), version=1))


def test_v3_document_with_v4_shape_does_not_decode():
    document = json.loads(encode_installed_manifest(debian()))
    document["schema"] = document["schema"].replace("/v4", "/v3")
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(ApprovalRefused):
        decode_installed_manifest(raw, expected_digest=pin(raw))


@pytest.mark.parametrize("path,target,files", [
    ("usr/lib/a/x", "../../../x", ("usr/x",)),
    ("usr/lib/a/x", "../../../../x", ("usr/x",)),
    ("usr/lib/a/x", "../..", ()),
    ("usr/lib/a/x", "../../", ()),
    ("usr/lib/a/x", "b//c", ("usr/lib/a/b/c",)),
    ("usr/lib/a/x", "b/", ("usr/lib/a/b",)),
    ("usr/lib/a/x", "/", ()),
    ("usr/lib/a/x", ".", ()),
    ("usr/lib/a/x", "..", ()),
    ("usr/lib/a/x", "../../../../../etc/q", ("etc/q",)),
    ("usr/lib/a/x", "../../../var/q", ("var/q",)),
    ("usr/lib/a/x", "/var/q", ()),
    ("usr/lib/a/x", "/etc/../usr/q", ("usr/q",)),
    ("usr/lib/a/x", "./z/../w", ("usr/lib/a/w",)),
    ("usr/lib/a/x", "d/../f", ("usr/lib/a/f",)),
    ("usr/lib/a/x", "./f", ("usr/lib/a/f",)),
    ("usr/lib/a/x", "a/./b", ("usr/lib/a/a/b",)),
    ("usr/lib/a/x", "a/../b", ("usr/lib/a/b",)),
    ("usr/lib/a/x", "./a", ("usr/lib/a/a",)),
    ("usr/lib/a/x", "a/..", ("usr/lib/a",)),
    ("usr/lib/a/x", "../a/../b", ("usr/lib/b",)),
    ("usr/lib/a/x", "b\x00c", ()),
    ("usr/lib/a/x", "b\nc", ()),
    ("usr/lib/a/x", "b c", ()),
    ("usr/lib/a/x", "b/\x7fc", ()),
    ("usr/lib/a/x", "b/é", ()),
    ("usr/lib/a/x", "a/" * 40 + "b", ()),
    ("usr/lib/a/x", "b/" * 300, ()),
])
def test_v4_refuses_escapes_and_bad_targets(path, target, files):
    with pytest.raises(ApprovalRefused):
        manifest = v4((InstalledLink(path, target),), files=files or (LIB,))
        encode_installed_manifest(manifest)


def test_v4_refuses_unpinned_directory_and_cyclic_targets():
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/x", "../b"),))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/x", "../b"),), directories=("usr/lib/b",))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/x", "../b/y"), InstalledLink("usr/lib/b/y", "../a/x")))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/x", "../a/x"),))


def test_v4_link_depth_limit_is_kept():
    def chain(length):
        links = [InstalledLink(f"usr/lib/c/l{index}", f"../c/l{index + 1}")
                 for index in range(length)]
        links[-1] = InstalledLink(links[-1].path, "../c/final")
        return v4(tuple(links), files=(LIB, "usr/lib/c/final"))
    assert encode_installed_manifest(chain(8))
    with pytest.raises(ApprovalRefused):
        encode_installed_manifest(chain(9))


def test_v4_allows_only_usr_opt_etc_roots():
    with pytest.raises(ApprovalRefused):
        encode_installed_manifest(InstalledManifest(
            (file_entry("var/x"),), version=4))
    assert encode_installed_manifest(InstalledManifest((file_entry("etc/x"),), version=4))


def test_etc_and_nested_link_shapes_still_refused_in_v1_v2_v3_entries():
    for version in (1, 2, 3):
        with pytest.raises(ApprovalRefused):
            encode_installed_manifest(InstalledManifest((file_entry("etc/x"),), version=version))


# --- generator and measurement -------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    contents = {LIB: b"lib\n", SITE: b"site\n", "usr/lib/plain/plain.py": b"p\n"}
    for path, content in contents.items():
        leaf = root / path
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(content)
        leaf.chmod(0o644)
    (root / CONFIG_DIR).mkdir(parents=True)
    (root / SO_LINK).symlink_to(SO_TARGET)
    (root / SITE_LINK).symlink_to(SITE_TARGET)
    for current, _dirs, _files in os.walk(root, followlinks=False):
        os.chmod(current, 0o755)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root, fd
    finally:
        os.close(fd)


DEBIAN_DIRS = ("etc/python3.13", "usr/lib/aarch64-linux-gnu", "usr/lib/python3.13", CONFIG_DIR)


def test_generator_emits_v4_only_when_needed(tree):
    root, fd = tree
    owner = os.getuid()
    raw = candidate._candidate_at(
        fd, (SITE, LIB), owner=owner, allow_etc=True, directories=DEBIAN_DIRS,
        links=(SO_LINK, SITE_LINK),
    )
    manifest = decode_installed_manifest(raw, expected_digest=pin(raw))
    assert manifest.version == 4
    result = measured._measure_at(fd, raw, expected_digest=pin(raw), owner=owner)
    assert (result.file_count, result.link_count, result.directory_count) == (2, 2, 4)
    # Without a v4-only shape the old schemas and bytes are kept.
    plain = candidate._candidate_at(fd, (LIB,), owner=owner)
    assert json.loads(plain)["schema"].endswith("/v1")
    two = candidate._candidate_at(fd, (LIB,), owner=owner, directories=("usr/lib/aarch64-linux-gnu",))
    assert json.loads(two)["schema"].endswith("/v2")
    (root / "usr/lib/plain/simple").symlink_to("plain.py")
    three = candidate._candidate_at(
        fd, ("usr/lib/plain/plain.py",), owner=owner,
        directories=("usr/lib/plain",), links=("usr/lib/plain/simple",),
    )
    assert json.loads(three)["schema"].endswith("/v3")
    # Only an etc/ file also forces schema 4.
    etc = candidate._candidate_at(fd, (SITE,), owner=owner, allow_etc=True)
    assert json.loads(etc)["schema"].endswith("/v4")


def test_measurement_compares_v4_link_text_exactly(tree):
    root, fd = tree
    owner = os.getuid()
    raw = candidate._candidate_at(fd, (SITE, LIB), owner=owner, allow_etc=True, directories=DEBIAN_DIRS,
                                  links=(SO_LINK, SITE_LINK))
    expected = pin(raw)
    measured._measure_at(fd, raw, expected_digest=expected, owner=owner)
    leaf = root / SO_LINK
    leaf.unlink()
    leaf.symlink_to("../../aarch64-linux-gnu/./libpython3.13.so.1")
    with pytest.raises(ApprovalRefused):
        measured._measure_at(fd, raw, expected_digest=expected, owner=owner)
    leaf.unlink()
    leaf.symlink_to(SO_TARGET)
    measured._measure_at(fd, raw, expected_digest=expected, owner=owner)
    (root / SITE).write_bytes(b"tampered\n")
    with pytest.raises(ApprovalRefused):
        measured._measure_at(fd, raw, expected_digest=expected, owner=owner)


def test_generator_refuses_unpinned_v4_link_target(tree):
    _root, fd = tree
    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(fd, (LIB,), owner=os.getuid(),
                                directories=DEBIAN_DIRS, links=(SO_LINK, SITE_LINK))


# --- bootstrap -----------------------------------------------------------------


@pytest.fixture
def bootstrap_tree(tmp_path):
    root = tmp_path / "root"
    values = {
        "usr/bin/python3.13": (0o755, b"synthetic interpreter; never executed\n"),
        "opt/env/pyvenv.cfg": (0o644, (
            b"home=/usr/bin\ninclude-system-site-packages=false\n"
            b"version=3.13.5\nexecutable=/usr/bin/python3.13\n")),
        SITE: (0o644, b"site\n"),
    }
    for name in ("activated", "auditd", "commissiond"):
        values[f"usr/libexec/azazel/az-{name}"] = (0o755, render_wrapper(
            "/opt/env/bin/python", f"azazel_nexus_runtime.{name}:main",
            import_paths=("/opt/env/site",)))
    entries = []
    for path, (mode, content) in sorted(values.items()):
        leaf = root / path
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(content)
        leaf.chmod(mode)
        entries.append(InstalledFile(path, mode, len(content), sha256(content).hexdigest()))
    (root / "opt/env/bin").mkdir(parents=True)
    (root / "opt/env/site").mkdir()
    (root / "usr/lib/python3.13").mkdir(parents=True)
    links = (
        InstalledLink("opt/env/bin/python", "../../../usr/bin/python3.13"),
        InstalledLink(SITE_LINK, SITE_TARGET),
    )
    for current, _dirs, _files in os.walk(root, followlinks=False):
        os.chmod(current, 0o755)
    for link in links:
        (root / link.path).symlink_to(link.target)
    manifest = InstalledManifest(tuple(entries), tuple(InstalledDirectory(path) for path in (
        "etc/python3.13", "opt/env", "opt/env/bin", "opt/env/site", "usr/bin",
        "usr/lib/python3.13", "usr/libexec", "usr/libexec/azazel")),
        version=4, links=tuple(sorted(links, key=lambda link: link.path)))
    raw = encode_installed_manifest(manifest)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root, fd, manifest, raw, pin(raw)
    finally:
        os.close(fd)


def test_bootstrap_measurement_accepts_v4_manifest(bootstrap_tree, monkeypatch):
    _root, fd, manifest, raw, digest = bootstrap_tree
    assert manifest.version == 4
    owner = os.getuid()
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda raw, *, expected_digest, paths: measured._read_pinned_at(
            fd, raw, expected_digest=expected_digest, paths=paths, owner=owner))
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda raw, *, expected_digest: measured._measure_at(
            fd, raw, expected_digest=expected_digest, owner=owner))
    context = replace(_context(), unit_closure_digest=digest)
    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", lambda: running_python._observation(
        content=b"synthetic interpreter; never executed\n", interpreter="/opt/env/bin/python",
        import_paths=("/opt/env/site",), version=(3, 13, 5)))
    monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", lambda interpreter:
                        python_startup._observe_at(fd, interpreter, owner=owner))
    monkeypatch.setattr(bootstrap_inputs, "observe_import_routing", lambda paths, _m:
                        import_routing._routing(import_paths=paths))
    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", lambda _m, paths, _main:
                        loaded_modules._loaded(import_paths=paths))
    assert bootstrap_inputs.measure_bootstrap_installed_files(context).link_count == 2


def test_plain_entries_keep_schema_three_rules_and_flag_is_not_identity():
    for target in ("../q", "a/b", "/etc/q", ".", ".."):
        with pytest.raises(ApprovalRefused):
            _Link("usr/lib/a", target)
    with pytest.raises(ApprovalRefused):
        _File("etc/q", 0o644, 0, "0" * 64)
    with pytest.raises(ApprovalRefused):
        _Dir("etc/q")
    assert _Link("usr/lib/a", "b") == _Link("usr/lib/a", "b", True)
    assert _Link("usr/lib/a", "../b", True).target == "../b"


def test_candidate_seam_refuses_etc_unless_schema_four_root_allowed(tree):
    _root, fd = tree
    with pytest.raises(ApprovalRefused):
        candidate._candidate_at(fd, (SITE,), owner=os.getuid())


def test_v4_accepts_leading_dotdot_then_names_only():
    for target, files in ((SO_TARGET, (LIB,)),
                          ("f", ("usr/lib/a/f",)), ("../f", ("usr/lib/f",)),
                          ("...", ("usr/lib/a/...",))):
        manifest = v4((InstalledLink(SO_LINK if target == SO_TARGET else "usr/lib/a/x",
                                     target),), files=files)
        assert encode_installed_manifest(manifest)


def test_v4_flagged_etc_entries_refused_inside_version_three_manifest():
    for kwargs in ({"files": (file_entry(SITE),)},
                   {"files": (file_entry(LIB),), "directories": (InstalledDirectory("etc/d"),)},
                   {"files": (file_entry(LIB),), "directories": (InstalledDirectory(CONFIG_DIR),),
                    "links": (InstalledLink(SO_LINK, SO_TARGET),)}):
        with pytest.raises(ApprovalRefused):
            InstalledManifest(kwargs["files"], kwargs.get("directories", ()), 3,
                              kwargs.get("links", ()))


def test_v4_canonical_bytes_golden():
    manifest = InstalledManifest(
        (InstalledFile("etc/a.conf", 0o644, 2, "0" * 64),
         InstalledFile("usr/lib/m.so.1", 0o644, 3, "1" * 64)),
        (InstalledDirectory("usr/lib/d"),), 4,
        (InstalledLink("usr/lib/d/m.so", "../m.so.1"),
         InstalledLink("usr/lib/e", "/etc/a.conf")),
    )
    assert encode_installed_manifest(manifest) == (
        b'{"directories":[{"mode":493,"path":"usr/lib/d"}],'
        b'"files":[{"mode":420,"path":"etc/a.conf","sha256":"' + b"0" * 64 + b'","size":2},'
        b'{"mode":420,"path":"usr/lib/m.so.1","sha256":"' + b"1" * 64 + b'","size":3}],'
        b'"links":[{"path":"usr/lib/d/m.so","target":"../m.so.1"},'
        b'{"path":"usr/lib/e","target":"/etc/a.conf"}],'
        b'"schema":"azazel-nexus/selected-installed-files/v4"}')


PRELOAD = "etc/ld.so.preload"


def test_v4_manifest_refuses_ld_so_preload_in_every_shape():
    with pytest.raises(ApprovalRefused):
        v4((), files=(PRELOAD, SITE))
    with pytest.raises(ApprovalRefused):
        v4((), files=(SITE,), directories=(PRELOAD,))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink(PRELOAD, "/etc/python3.13/sitecustomize.py"),))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/p", "/" + PRELOAD),), files=(SITE,))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/p", "../../../" + PRELOAD),), files=(PRELOAD,))
    with pytest.raises(ApprovalRefused):
        v4((InstalledLink("usr/lib/a/p", "../q"), InstalledLink("usr/lib/q", "/" + PRELOAD)),
           files=(SITE,))
    with pytest.raises(ApprovalRefused):
        encode_installed_manifest(v4((), files=(SITE,)).__class__(
            (file_entry(PRELOAD),), version=4))
    assert encode_installed_manifest(v4((), files=("etc/ld.so.conf",)))


def test_needs_v4_with_only_etc_directory_and_v3_valid_absolute_link(tree):
    _root, fd = tree
    (_root / "etc/d").mkdir()
    os.chmod(_root / "etc/d", 0o755)
    (_root / "usr/lib/plain/abs").symlink_to("/usr/lib/plain/plain.py")
    raw = candidate._candidate_at(
        fd, ("usr/lib/plain/plain.py",), owner=os.getuid(), allow_etc=True,
        directories=("etc/d", "usr/lib/plain"), links=("usr/lib/plain/abs",))
    assert json.loads(raw)["schema"].endswith("/v4")


def test_read_pinned_reads_etc_file_from_v4_manifest(bootstrap_tree):
    _root, fd, _manifest, raw, digest = bootstrap_tree
    assert measured._read_pinned_at(
        fd, raw, expected_digest=digest, paths=(SITE,), owner=os.getuid()) == (b"site\n",)
