"""#196 G6 preparation K: the installer records the compiled AppArmor policy hashes.

`docs/deception-exposure-wiring.md` §5.2 and grant §7 "Left to G6": with the
service manager, `packaging/install.sh` runs `tools/record_apparmor_compiled.py`,
which compiles each placed profile with `apparmor_parser -Q -o` and writes
the SHA-256 of each output to `/etc/azazel/activation/apparmor-compiled.json`;
`azazel_nexus_runtime.apparmor_compiled` is its strict decoder.

The module and its names are registered in the shared table of unwired
parts (`tests/unit/test_g6_unwired.py`: `IMPORTERS`, `NAME_FILES`, and the
poisoned pass, which covers `decode_apparmor_compiled`). The checks at the
end (nothing but the installer's tool calls the decoder; neither
`generation-publish` nor the pass reads the record) repeat part of that
here; the duplicate is harmless.
"""

from __future__ import annotations

import ast
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest

from azazel_nexus_runtime import exposure_generation
from azazel_nexus_runtime.apparmor_compiled import (
    APPARMOR_COMPILED_CONTRACT,
    APPARMOR_COMPILED_KEYS,
    APPARMOR_COMPILED_MODE,
    APPARMOR_COMPILED_PATH,
    APPARMOR_COMPILED_REFUSED,
    APPARMOR_PROFILE_NAMES,
    ApparmorCompiledRefused,
    decode_apparmor_compiled,
    encode_apparmor_compiled,
    normalize_parser_version,
)
from azazel_nexus_runtime.decoy_apparmor import REQUIRED_ENFORCED_PROFILES
from azazel_nexus.generation import GenerationRefused

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = (ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
TOOL_CALL = 'python_fixed -IS "$REPO_ROOT/tools/record_apparmor_compiled.py" || exit 1'
VERSION = "AppArmor parser version 4.1.0"
HASHES = {name: format(index, "x") * 64
          for index, name in enumerate(sorted(REQUIRED_ENFORCED_PROFILES), start=10)}


def _canonical(document) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _document(**changes):
    document = {"apparmor_policy_hashes": dict(HASHES),
                "contract": APPARMOR_COMPILED_CONTRACT, "parser_version": VERSION}
    document.update(changes)
    return document


def _tool():
    spec = importlib.util.spec_from_file_location(
        "record_apparmor_compiled", ROOT / "tools" / "record_apparmor_compiled.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- the record's form ---------------------------------------------------------


def test_the_profile_names_are_the_required_profiles():
    assert APPARMOR_PROFILE_NAMES == tuple(sorted(REQUIRED_ENFORCED_PROFILES))


def test_the_record_is_the_wiring_documents_form():
    raw = encode_apparmor_compiled(HASHES, VERSION)
    assert raw == _canonical(_document())
    assert raw.endswith(b"}\n") and raw.count(b"\n") == 1 and b" " not in raw.replace(
        VERSION.encode(), b"")
    assert APPARMOR_COMPILED_CONTRACT == "azazel-nexus/apparmor-compiled/v1"
    assert APPARMOR_COMPILED_PATH == "/etc/azazel/activation/apparmor-compiled.json"
    assert APPARMOR_COMPILED_KEYS == tuple(sorted(json.loads(raw)))
    assert APPARMOR_COMPILED_MODE == 0o644
    decoded = decode_apparmor_compiled(raw)
    assert decoded.apparmor_policy_hashes == HASHES
    assert list(decoded.apparmor_policy_hashes) == sorted(REQUIRED_ENFORCED_PROFILES)
    assert decoded.parser_version == VERSION


@pytest.mark.parametrize("document", [
    _document(contract="azazel-nexus/apparmor-compiled/v2"),
    _document(contract=None),
    {k: v for k, v in _document().items() if k != "parser_version"},
    {k: v for k, v in _document().items() if k != "contract"},
    {k: v for k, v in _document().items() if k != "apparmor_policy_hashes"},
    _document(extra=1),
    _document(apparmor_policy_hashes={k: v for k, v in HASHES.items()
                                      if k != "azazel-decoyd"}),
    _document(apparmor_policy_hashes={**HASHES, "azazel-decoy-other": "0" * 64}),
    _document(apparmor_policy_hashes=list(HASHES.items())),
    _document(apparmor_policy_hashes=None),
    _document(parser_version=""),
    _document(parser_version="AppArmor\nparser"),
    _document(parser_version="AppArmor\tparser"),
    _document(parser_version="x" * 256),
    _document(parser_version="x" * 257),
    _document(parser_version=4),
    [],
    "x",
])
def test_a_record_of_another_shape_is_refused(document):
    with pytest.raises(ApparmorCompiledRefused) as refused:
        decode_apparmor_compiled(_canonical(document))
    assert str(refused.value) == APPARMOR_COMPILED_REFUSED


BAD_HASHES = [
    "0" * 63, "0" * 65, "A" * 64, "sha256:" + "0" * 64, "0" * 64 + "\n",
    " " + "0" * 63, "g" * 64, "", 0, None,
]


@pytest.mark.parametrize("bad", BAD_HASHES)
def test_a_hash_of_another_form_is_refused(bad):
    with pytest.raises(ApparmorCompiledRefused):
        decode_apparmor_compiled(_canonical(_document(
            apparmor_policy_hashes={**HASHES, "azazel-decoyd": bad})))
    with pytest.raises(ApparmorCompiledRefused):
        encode_apparmor_compiled({**HASHES, "azazel-decoyd": bad}, VERSION)


@pytest.mark.parametrize("bad", BAD_HASHES + ["f" * 64, "0123456789abcdef" * 4])
def test_the_hash_rule_is_the_exposure_sections(bad):
    """The same rule as `exposure_generation`'s `apparmor_policy_hashes`, so
    G6's `generation-publish` can copy the field unchanged."""

    hashes = {**HASHES, "azazel-decoyd": bad}
    try:
        exposure_generation._policy_hashes(hashes)
        section_accepts = True
    except GenerationRefused:
        section_accepts = False
    try:
        encode_apparmor_compiled(hashes, VERSION)
        record_accepts = True
    except ApparmorCompiledRefused:
        record_accepts = False
    assert record_accepts is section_accepts
    assert exposure_generation._POLICY_HASH.pattern == r"[0-9a-f]{64}\Z"


@pytest.mark.parametrize("hashes", [
    {k: v for k, v in HASHES.items() if k != "azazel-decoy-nsd"},
    {},
    {**HASHES, "azazel-decoy-extra": "0" * 64},
    {**{k: v for k, v in HASHES.items() if k != "azazel-decoyd"}, "azazel-decoyd ": "0" * 64},
    {**{k: v for k, v in HASHES.items() if k != "azazel-decoyd"}, "AZAZEL-DECOYD": "0" * 64},
    {**{k: v for k, v in HASHES.items() if k != "azazel-decoyd"},
     "azazel-decoyd.service": "0" * 64},
    {**{k: v for k, v in HASHES.items() if k != "azazel-decoy-nsd"},
     "azazel-decoy-nsd//ip": "0" * 64},
    {**{k: v for k, v in HASHES.items() if k != "azazel-decoyd"}, b"azazel-decoyd": "0" * 64},
    dict(HASHES),
])
def test_the_name_set_rule_is_the_exposure_sections(hashes):
    """Missing, extra and other names (review of #304, 4): both accept or both refuse."""

    try:
        exposure_generation._policy_hashes(hashes)
        section_accepts = True
    except GenerationRefused:
        section_accepts = False
    try:
        encode_apparmor_compiled(hashes, VERSION)
        record_accepts = True
    except ApparmorCompiledRefused:
        record_accepts = False
    assert record_accepts is section_accepts
    assert record_accepts is (hashes == HASHES)


def test_the_decoded_hashes_are_what_the_section_takes():
    decoded = decode_apparmor_compiled(encode_apparmor_compiled(HASHES, VERSION))
    assert exposure_generation._policy_hashes(decoded.apparmor_policy_hashes) == HASHES


@pytest.mark.parametrize("raw", [
    _canonical(_document()).rstrip(b"\n"),
    _canonical(_document()) + b"\n",
    _canonical(_document()).replace(b",", b", ", 1),
    json.dumps(_document(), sort_keys=True, indent=1).encode() + b"\n",
    (json.dumps(dict(reversed(list(_document().items()))),
                separators=(",", ":")) + "\n").encode(),
    _canonical(_document())[:-2] + b',"contract":"' + APPARMOR_COMPILED_CONTRACT.encode()
    + b'"}\n',
    b"\xef\xbb\xbf" + _canonical(_document()),
    _canonical(_document()).replace(b"\n", b"\r\n"),
    _canonical(_document(parser_version="AppArmor é")),
    b"",
    b"{}\n",
    b"NaN\n",
    b"x" * 5000,
])
def test_bytes_that_are_not_the_canonical_encoding_are_refused(raw):
    with pytest.raises(ApparmorCompiledRefused):
        decode_apparmor_compiled(raw)


@pytest.mark.parametrize("raw", [None, "text", bytearray(b"{}"), memoryview(b"{}")])
def test_only_bytes_are_decoded(raw):
    with pytest.raises(ApparmorCompiledRefused):
        decode_apparmor_compiled(raw)


# -- the installer -------------------------------------------------------------


def test_the_installer_records_with_the_service_manager_only():
    assert INSTALLER.count("record_apparmor_compiled.py") == 1
    call = INSTALLER.index(TOOL_CALL)
    opened = INSTALLER.rindex('if [ "$WITH_SERVICE_MANAGER" = yes ]; then', 0, call)
    assert INSTALLER[opened:call].count("\n") == 1
    assert INSTALLER[call:].startswith(TOOL_CALL + "\nfi\n")
    # After the profiles are placed and the 0700 activation directory made,
    # before the staging exit and before any unit is masked or enabled.
    for earlier in ('install -m 0644 "$HERE"/apparmor/azazel-decoyd',
                    'install -m 0644 "$HERE"/apparmor/azazel-decoy-nsd',
                    "make_dir 0700 root /etc/azazel/activation"):
        assert INSTALLER.index(earlier) < call, earlier
    for later in ('if [ "$WITH_SERVICE_MANAGER" = no ]; then',
                  "SERVICE-MANAGER STAGE NOT EXECUTED", "systemctl daemon-reload",
                  "systemctl mask", "systemctl enable"):
        assert call < INSTALLER.index(later), later
    # The existing compile check is unchanged and still before any write.
    assert INSTALLER.index("apparmor_parser --skip-kernel-load --skip-cache --quiet") < \
        INSTALLER.index("make_dir 0755 root /etc/azazel")


def test_the_tool_compiles_without_loading():
    source = (ROOT / "tools" / "record_apparmor_compiled.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    lists = [node for node in ast.walk(tree) if isinstance(node, ast.List)
             and node.elts and isinstance(node.elts[0], ast.Name)
             and node.elts[0].id == "parser"]
    flags = sorted(tuple(elt.value for elt in node.elts[1:] if isinstance(elt, ast.Constant))
                   for node in lists)
    assert flags == [("--version",), ("-Q", "-o")]
    for forbidden in ("--replace", '"-r"', '"-a"', '"-R"', "--add", "--remove",
                      "write-cache", "aa-enforce", "systemctl"):
        assert forbidden not in source, forbidden


def test_the_tool_is_in_the_offline_bundle():
    from tools.build_offline_bundle import _inputs

    names = {name for _, name in _inputs(ROOT)}
    assert "tools/record_apparmor_compiled.py" in names
    assert "runtime/src/azazel_nexus_runtime/apparmor_compiled.py" in names


def _installer_python() -> str:
    if sys.version_info >= (3, 11):
        return sys.executable
    for name in ("python3.14", "python3.13", "python3.12", "python3.11"):
        candidate = shutil.which(name)
        if candidate:
            return candidate
    pytest.skip("the installer requires Python 3.11 or newer")


def test_a_staged_install_writes_no_record(tmp_path):
    """DESTDIR staging (`--without-service-manager`) writes no record and does
    not run the tool: its compiler, interpreter and policy features are not
    the node's, so a record from there would describe another compilation."""

    if not Path("/etc/os-release").is_file():
        pytest.skip("installer requires the host's os-release install profile")
    root = tmp_path / "installer-tree"
    shutil.copytree(ROOT / "packaging", root / "packaging")
    (root / "tools").mkdir()
    for name in ("install_profile_fields.py", "provision_mission_read.py",
                 "purge_mio_profile_copies.py", "check_decoy_apparmor_wrappers.py"):
        shutil.copy2(ROOT / "tools" / name, root / "tools" / name)
    shutil.copytree(ROOT / "src", root / "src")
    shutil.copytree(ROOT / "runtime" / "src", root / "runtime" / "src")
    marker = tmp_path / "record-tool-ran"
    (root / "tools" / "record_apparmor_compiled.py").write_text(
        f"open({str(marker)!r}, 'w').close()\n", encoding="utf-8")
    entrypoints = tuple(sorted(set(
        INSTALLER.split("for binary in ", 1)[1].split("; do", 1)[0].split())))
    (root / "tools" / "stage_runtime_entrypoints.py").write_text(
        "import os\nfrom pathlib import Path\n"
        "dest = Path(os.environ['DESTDIR']) / 'usr/libexec/azazel'\n"
        "dest.mkdir(parents=True, exist_ok=True)\n"
        f"for name in {entrypoints!r}:\n"
        "    target = dest / name\n"
        "    target.write_text('#!/bin/sh\\nexit 0\\n', encoding='ascii')\n"
        "    target.chmod(0o755)\n", encoding="utf-8")
    destdir = tmp_path / "stage"
    env = {**os.environ, "DESTDIR": str(destdir), "PYTHON": _installer_python()}
    result = subprocess.run(
        ["sh", str(root / "packaging" / "install.sh"), "--without-accounts",
         "--without-service-manager"],
        env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SERVICE-MANAGER STAGE NOT EXECUTED" in result.stdout
    activation = destdir / "etc/azazel/activation"
    assert activation.is_dir() and list(activation.iterdir()) == []
    assert (destdir / "etc/apparmor.d/azazel-decoyd").is_file()
    assert not marker.exists()


# -- the tool, with a stand-in compiler ------------------------------------------

FAKE_PARSER = r"""#!/bin/sh
if [ "$1" = --version ]; then
    [ -n "${VERSION_FAIL:-}" ] && exit 1
    [ -n "${VERSION_EMPTY:-}" ] && exit 0
    printf '%s\n' "${VERSION_OUT:-AppArmor parser version 9.9.9}"
    echo "Copyright (C) somebody"
    exit 0
fi
[ "$1" = -Q ] && [ "$2" = -o ] && [ "$#" -eq 4 ] || exit 64
if [ -n "${FAIL_ON:-}" ] && [ "$(basename "$4")" = "$FAIL_ON" ]; then
    printf 'AppArmor parser error at line 1: d\303\251j\303\240 vu\n'
    printf '\n'
    for n in 2 3 4 5 6 7 8; do printf 'line %s\001\n' "$n"; done
    exit 1
fi >&2
{ printf 'compiled:'; cat "$4"; } > "$3"
"""


@pytest.fixture
def fake(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    parser = bin_dir / "apparmor_parser"
    parser.write_text(FAKE_PARSER, encoding="ascii")
    parser.chmod(0o755)
    profiles = tmp_path / "apparmor.d"
    profiles.mkdir()
    for name in REQUIRED_ENFORCED_PROFILES:
        (profiles / name).write_bytes(f"profile {name} {{}}\n".encode())
    output_dir = tmp_path / "activation"
    output_dir.mkdir(mode=0o700)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    for name in ("FAIL_ON", "VERSION_FAIL", "VERSION_EMPTY", "VERSION_OUT"):
        monkeypatch.delenv(name, raising=False)
    return profiles, output_dir / "apparmor-compiled.json"


def test_the_tool_records_the_sha256_of_each_compiled_output(fake, capsys):
    profiles, output = fake
    assert _tool().main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 0
    raw = output.read_bytes()
    record = decode_apparmor_compiled(raw)
    assert record.parser_version == "AppArmor parser version 9.9.9"
    assert record.apparmor_policy_hashes == {
        name: sha256(b"compiled:" + (profiles / name).read_bytes()).hexdigest()
        for name in sorted(REQUIRED_ENFORCED_PROFILES)}
    assert stat.S_IMODE(output.stat().st_mode) == 0o644
    assert sorted(p.name for p in output.parent.iterdir()) == [output.name]
    assert "nothing loaded" in capsys.readouterr().out


def test_a_profile_that_does_not_compile_refuses_and_keeps_the_earlier_record(
        fake, monkeypatch, capsys):
    profiles, output = fake
    output.write_bytes(b"earlier\n")
    monkeypatch.setenv("FAIL_ON", "azazel-decoy-netd")
    assert _tool().main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 1
    assert output.read_bytes() == b"earlier\n"
    assert sorted(p.name for p in output.parent.iterdir()) == [output.name]
    err = capsys.readouterr().err
    assert "refusing to install: AppArmor profile azazel-decoy-netd does not compile" in err
    # The parser's first lines (blank ones skipped), printable ASCII only.
    shown = [line for line in err.splitlines() if line.startswith("apparmor_parser (")]
    assert shown == [
        "apparmor_parser (azazel-decoy-netd): AppArmor parser error at line 1: d?j? vu",
        "apparmor_parser (azazel-decoy-netd): line 2?",
        "apparmor_parser (azazel-decoy-netd): line 3?",
        "apparmor_parser (azazel-decoy-netd): line 4?",
        "apparmor_parser (azazel-decoy-netd): line 5?",
    ]
    assert err.isascii()


@pytest.mark.parametrize(("env", "recorded"), [
    ({"VERSION_OUT": "AppArmor parser vérsion 4.1.0"}, "AppArmor parser v?rsion 4.1.0"),
    ({"VERSION_OUT": "AppArmor\tparser\x7f4.1"}, "AppArmor?parser?4.1"),
    ({"VERSION_OUT": "v" * 400}, "v" * 255),
    ({"VERSION_OUT": "   "}, "unknown"),
    ({"VERSION_EMPTY": "1"}, "unknown"),
    ({"VERSION_FAIL": "1"}, "unknown"),
])
def test_a_version_line_of_another_form_is_normalized_not_refused(fake, monkeypatch, env,
                                                                  recorded):
    """The version line is diagnosis only (review of #304, 1): it never refuses."""

    profiles, output = fake
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert _tool().main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 0
    record = decode_apparmor_compiled(output.read_bytes())
    assert record.parser_version == recorded
    assert normalize_parser_version(recorded) == recorded


@pytest.mark.parametrize(("value", "normalized"), [
    ("AppArmor parser version 4.1.0", "AppArmor parser version 4.1.0"),
    (" lead and trail ", " lead and trail "),
    ("é\n\x00", "???"),
    ("", "unknown"),
    ("y" * 256, "y" * 255),
])
def test_the_decoder_accepts_exactly_what_normalization_leaves(value, normalized):
    assert normalize_parser_version(value) == normalized
    raw = encode_apparmor_compiled(HASHES, normalized)
    assert decode_apparmor_compiled(raw).parser_version == normalized
    if normalized != value:
        with pytest.raises(ApparmorCompiledRefused):
            decode_apparmor_compiled(_canonical(_document(parser_version=value)))


def test_the_tool_takes_no_abbreviated_option(fake):
    profiles, output = fake
    with pytest.raises(SystemExit):
        _tool().main(["--apparmor", str(profiles), "--out", str(output)])
    assert not output.exists()


# -- the write, failing at each step (review of #304, 2 and 3) -------------------


def _entries(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


RECORD = encode_apparmor_compiled(HASHES, VERSION)


def _failing(real, *, when=lambda *args: True):
    def fail(*args, **kwargs):
        if when(*args):
            raise OSError(5, "injected")
        return real(*args, **kwargs)
    return fail


def _is_directory(fd, *_):
    return stat.S_ISDIR(os.fstat(fd).st_mode)


@pytest.mark.parametrize("step", ["write", "fchmod", "fsync", "rename"])
def test_a_failure_before_the_rename_keeps_the_earlier_record_and_no_temporary(
        tmp_path, monkeypatch, step):
    tool = _tool()
    directory = tmp_path / "activation"
    directory.mkdir(mode=0o700)
    output = directory / "apparmor-compiled.json"
    output.write_bytes(b"earlier\n")
    when = (lambda fd, *_: not _is_directory(fd)) if step == "fsync" else (lambda *a: True)
    monkeypatch.setattr(tool.os, step, _failing(getattr(os, step), when=when))
    with pytest.raises(tool.Refused):
        tool.write_record(output, RECORD)
    monkeypatch.undo()
    assert output.read_bytes() == b"earlier\n"
    assert _entries(directory) == [output.name]


def test_a_failed_directory_sync_after_the_rename_warns_and_keeps_the_record(
        tmp_path, monkeypatch, capsys):
    tool = _tool()
    directory = tmp_path / "activation"
    directory.mkdir(mode=0o700)
    output = directory / "apparmor-compiled.json"
    output.write_bytes(b"earlier\n")
    monkeypatch.setattr(tool.os, "fsync", _failing(os.fsync, when=_is_directory))
    tool.write_record(output, RECORD)
    monkeypatch.undo()
    assert output.read_bytes() == RECORD
    assert stat.S_IMODE(output.stat().st_mode) == 0o644
    assert _entries(directory) == [output.name]
    assert "WARNING:" in capsys.readouterr().err


def test_the_tool_succeeds_when_only_the_directory_sync_fails(fake, monkeypatch, capsys):
    profiles, output = fake
    tool = _tool()
    monkeypatch.setattr(tool.os, "fsync", _failing(os.fsync, when=_is_directory))
    assert tool.main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 0
    monkeypatch.undo()
    decode_apparmor_compiled(output.read_bytes())
    assert "the record stands" in capsys.readouterr().err


def test_temporary_names_that_keep_colliding_refuse_and_change_nothing(tmp_path):
    tool = _tool()
    directory = tmp_path / "activation"
    directory.mkdir(mode=0o700)
    output = directory / "apparmor-compiled.json"
    output.write_bytes(b"earlier\n")
    taken = [f".{output.name}.{os.getpid()}.{attempt}.tmp"
             for attempt in range(tool._TEMPORARY_ATTEMPTS)]
    for name in taken:
        (directory / name).write_bytes(b"someone else's\n")
    with pytest.raises(tool.Refused):
        tool.write_record(output, RECORD)
    assert output.read_bytes() == b"earlier\n"
    assert _entries(directory) == sorted([output.name, *taken])
    assert all((directory / name).read_bytes() == b"someone else's\n" for name in taken)
    # One free name is enough.
    (directory / taken[-1]).unlink()
    tool.write_record(output, RECORD)
    assert output.read_bytes() == RECORD
    assert _entries(directory) == sorted([output.name, *taken[:-1]])


def test_a_missing_profile_refuses(fake):
    profiles, output = fake
    (profiles / "azazel-decoyd").unlink()
    assert _tool().main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 1
    assert not output.exists()


def test_a_missing_parser_refuses(fake, monkeypatch, tmp_path):
    profiles, output = fake
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    assert _tool().main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 1
    assert not output.exists()


def test_a_linked_output_directory_refuses(fake, tmp_path):
    profiles, output = fake
    link = tmp_path / "linked"
    link.symlink_to(output.parent)
    assert _tool().main(["--apparmor-dir", str(profiles),
                         "--output", str(link / output.name)]) == 1
    assert not output.exists()


def test_the_record_replaces_a_link_rather_than_following_it(fake, tmp_path):
    profiles, output = fake
    target = tmp_path / "elsewhere"
    target.write_bytes(b"keep\n")
    output.symlink_to(target)
    assert _tool().main(["--apparmor-dir", str(profiles), "--output", str(output)]) == 0
    assert target.read_bytes() == b"keep\n"
    assert not output.is_symlink()
    decode_apparmor_compiled(output.read_bytes())


# -- the tool, with the real compiler (the apparmor package) ---------------------


@pytest.mark.skipif(shutil.which("apparmor_parser") is None,
                    reason="apparmor_parser (Debian package apparmor) is not installed")
def test_the_tool_records_what_apparmor_parser_compiles(tmp_path):
    """The recorded value is the SHA-256 of `apparmor_parser -Q -o <out>
    <profile>` for the repository's profiles, the same on every compile."""

    profiles = tmp_path / "apparmor.d"
    profiles.mkdir()
    for name in REQUIRED_ENFORCED_PROFILES:
        shutil.copy2(ROOT / "packaging" / "apparmor" / name, profiles / name)
    output_dir = tmp_path / "activation"
    output_dir.mkdir(mode=0o700)
    output = output_dir / "apparmor-compiled.json"
    tool = [sys.executable, "-IS", str(ROOT / "tools" / "record_apparmor_compiled.py"),
            "--apparmor-dir", str(profiles), "--output", str(output)]
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    first = subprocess.run(tool, env=env, capture_output=True, text=True, timeout=600)
    assert first.returncode == 0, first.stderr
    record = decode_apparmor_compiled(output.read_bytes())
    for name in REQUIRED_ENFORCED_PROFILES:
        out = tmp_path / f"{name}.bin"
        subprocess.run(["apparmor_parser", "-Q", "-o", str(out), str(profiles / name)],
                       check=True, capture_output=True, timeout=300)
        assert record.apparmor_policy_hashes[name] == sha256(out.read_bytes()).hexdigest()
    version = subprocess.run(["apparmor_parser", "--version"], capture_output=True,
                             text=True, check=True).stdout.splitlines()[0].strip()
    assert record.parser_version == version
    raw = output.read_bytes()
    second = subprocess.run(tool, env=env, capture_output=True, text=True, timeout=600)
    assert second.returncode == 0, second.stderr
    assert output.read_bytes() == raw
    assert len(set(record.apparmor_policy_hashes.values())) == 4


# -- not wired (also in the shared table, test_g6_unwired.py) --------------------


def _imports_of(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            names.add(node.module or "")
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
    return names


def test_only_the_installers_tool_and_generation_publish_use_the_record():
    """#196 G6 (wiring §5.2): the record is an input of `generation-publish`
    (and of `request` and `install`, which re-measure the same way), never
    of the pass."""
    users = []
    for base in (ROOT / "src", ROOT / "runtime" / "src", ROOT / "tools"):
        for path in base.rglob("*.py"):
            if path.name == "apparmor_compiled.py":
                continue
            text = path.read_text(encoding="utf-8")
            if (any("apparmor_compiled" in name for name in _imports_of(path))
                    or "apparmor-compiled.json" in text):
                users.append(path.relative_to(ROOT).as_posix())
    assert sorted(users) == ["runtime/src/azazel_nexus_runtime/activation_cli.py",
                             "tools/record_apparmor_compiled.py"]


@pytest.mark.parametrize("module", ["activation_pass.py", "activated.py", "exposure_pass.py"])
def test_the_pass_does_not_read_the_record(module):
    """The pass trusts only the section inside the signed generation."""
    path = ROOT / "runtime" / "src" / "azazel_nexus_runtime" / module
    text = path.read_text(encoding="utf-8")
    assert "apparmor_compiled" not in text and "apparmor-compiled" not in text
