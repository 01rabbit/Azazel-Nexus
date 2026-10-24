"""The first-enrollment procedure in the consumer document runs against the code (#93).

docs/knowledge-lite-consumer.md §11 gives the order a fresh node takes to reach
Knowledge Lite `available`, with the exact library calls for the two steps that
have no shipped entrypoint. These tests take the calls, the anchor documents
and the paths from the document itself and run them, in order, on a temporary
root. A document that drifts from the code fails here rather than on a node.

Owners and modes are not applied, because these tests run as one user. Every
`install`, `chown` and `chmod` the procedure prints is instead parsed and
compared exactly with the owner and mode derived from layout.py (cross-checked
against install.sh), and no step may grant group or other write or place key
or secret material. The repin step
goes through the production `RepinConfirmation` and `production_repin` with the
runtime root relocated, as `test_runtime_repin_integration.py` does; the
socket, the CLI's terminal and systemd are not exercised.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import stat
import sys
import tarfile
from pathlib import Path

import pytest
from azazel_nexus_runtime import runtime_paths
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.repin_confirmation import (
    ANCHOR_FILENAME,
    REASONS,
    RepinConfirmation,
)
from nacl.signing import SigningKey

from azazel_nexus.layout import create_layout, spec_for
from azazel_nexus.lite_import import CommissionedLite, status_summary

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "knowledge-lite-consumer.md"
CONTRACT = ROOT / "contract" / "azazel-knowledge-lite"
AS_OF = "2026-09-21T00:00:00Z"
DIGEST = "sha256:" + "c" * 64
PRINCIPAL = PrincipalPolicy(operator_gid=123, service_uids=frozenset()).classify(0, 0, 42)
LITE_TRUST = "/var/lib/azazel/lite-trust"
KNOWLEDGE = "/var/lib/azazel/knowledge"


def _section() -> str:
    text = DOC.read_text(encoding="utf-8")
    start = text.index("## 11. First enrollment")
    return text[start:text.index("\n## ", start + 1)]


def _steps() -> dict[int, str]:
    parts = re.split(r"^### Step (\d+):", _section(), flags=re.M)
    return {int(number): body for number, body in zip(parts[1::2], parts[2::2])}


def _blocks(text: str, language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", text, flags=re.S)


def _python(step: str) -> str:
    """The program a documented `python -I -c '...'` runs."""

    (program,) = re.findall(r"python -I -c '\n(.*?)\n'", step, flags=re.S)
    return program


def _relocate(text: str, root: Path) -> str:
    return text.replace("/var/lib/azazel/", f"{root}/var/lib/azazel/")


def _run(program: str, root: Path, *argv: str) -> int:
    saved = sys.argv
    sys.argv = ["-c", *argv]
    try:
        exec(compile(_relocate(program, root), "<doc>", "exec"), {"__name__": "__main__"})
    except SystemExit as exit_:
        return int(exit_.code or 0)
    finally:
        sys.argv = saved
    return 0


def _bundle(key: SigningKey, key_id: str) -> bytes:
    """The producer's pinned fixture, re-signed under a key made for this test."""

    with tarfile.open(CONTRACT / "lite.tar.gz", "r:gz") as archive:
        members = {e.name: archive.extractfile(e).read() for e in archive if e.isfile()}
    signature = key.sign(members["manifest.json"]).signature.hex()
    members["manifest.sig"] = f"{key_id}:{signature}\n".encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _reason(root: Path) -> str:
    return status_summary(root=root / KNOWLEDGE.lstrip("/"),
                          trust_root=root / LITE_TRUST.lstrip("/"),
                          query_as_of=AS_OF)["reason_code"]


def test_the_steps_are_the_eight_in_the_table() -> None:
    assert sorted(_steps()) == list(range(1, 9))
    table = re.findall(r"^\| (\d) \|", _section(), flags=re.M)
    assert table == [str(n) for n in range(1, 9)]


def test_the_documented_sequence_reaches_available(tmp_path, monkeypatch) -> None:
    steps = _steps()
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    create_layout(tmp_path)
    bundle_key, revoker = SigningKey.generate(), SigningKey.generate()
    bundle_hex = bytes(bundle_key.verify_key).hex()
    revoker_hex = bytes(revoker.verify_key).hex()
    reasons = [_reason(tmp_path)]

    # Step 2: one anchors.toml, written at both roots the document names.
    (anchors,) = _blocks(steps[2], "toml")
    anchors = anchors.replace("<bundle public key hex>", bundle_hex)
    key_id = re.search(r'^"([^"]+)" = ', anchors, flags=re.M).group(1)
    targets = re.findall(r"anchors\.toml (/\S+/trust/anchors\.toml)", steps[2])
    assert targets == [f"{LITE_TRUST}/trust/anchors.toml", f"{KNOWLEDGE}/trust/anchors.toml"]
    for target in targets:
        path = Path(_relocate(target, tmp_path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(anchors)
    assert str(CommissionedLite(Path(KNOWLEDGE)).anchors_path) == targets[1]

    # Step 3: the root-run pin, exactly as printed.
    assert _run(_python(steps[3]), tmp_path, bundle_hex, DIGEST, AS_OF) == 0
    trust_json = tmp_path / LITE_TRUST.lstrip("/") / "trust.json"
    assert trust_json.is_file()

    # Step 4: the mode the document sets (owners need root and are not checked).
    (mode,) = re.findall(r"chmod (0\d{3}) " + re.escape(f"{LITE_TRUST}/trust.json"), steps[4])
    trust_json.chmod(int(mode, 8))
    reasons.append(_reason(tmp_path))

    # Step 5: the documented anchor document, through the production repin path.
    (document,) = _blocks(steps[5], "json")
    document = (document.replace("<bundle public key hex>", bundle_hex)
                .replace("<revocation public key hex>", revoker_hex))
    (target,) = re.findall(r"repin-anchor\.json (/etc/azazel/commissioning/\S+)", steps[5])
    assert Path(target).name == ANCHOR_FILENAME
    anchor = tmp_path / target.lstrip("/")
    anchor.write_text(document)
    (reason,) = re.findall(r"commission_cli trust-repin --reason (\w+)", steps[5])
    assert reason in REASONS
    confirmation = RepinConfirmation(commissioning_dir=anchor.parent,
                                     snapshot_dir=runtime_paths.state_dir() / "commission",
                                     now=lambda: AS_OF)
    challenge = confirmation.challenge(PRINCIPAL, reason, ANCHOR_FILENAME)
    outcome = confirmation.confirm(PRINCIPAL, challenge["nonce"], challenge["confirmation_words"])
    assert outcome == {"promoted": True, "generation": 1}
    trust_root = tmp_path / LITE_TRUST.lstrip("/")
    for name in ("trust-current", "trust-generations/1.json", "trust-generations/1.revocation.json"):
        assert f"`{name}`" in steps[5]
        assert (trust_root / name).is_file()
    assert sorted(entry.name for entry in trust_root.iterdir()) == [
        "trust", "trust-current", "trust-generations", "trust-reserved",
        "trust-staging", "trust.json"]
    for name in ("trust-reserved", "trust-staging"):
        assert f"`{name}`" in steps[5]
    # What repin leaves takes trust.json's owner, group and mode (files) and the
    # directory mode the document states, and none of it is group/other-writable.
    pinned = trust_json.stat()
    (directory_mode,) = re.findall(r"the directories are `(0\d{3})`", _flat(steps[5]))
    directory_mode = int(directory_mode, 8)
    assert directory_mode & 0o022 == 0
    for name in ("trust-current", "trust-reserved", "trust-generations/1.json",
                 "trust-generations/1.revocation.json"):
        observed = (trust_root / name).stat()
        assert (observed.st_uid, observed.st_gid) == (pinned.st_uid, pinned.st_gid), name
        assert stat.S_IMODE(observed.st_mode) == stat.S_IMODE(pinned.st_mode), name
    for name in ("trust-generations", "trust-staging"):
        observed = (trust_root / name).stat()
        assert (observed.st_uid, observed.st_gid) == (pinned.st_uid, pinned.st_gid), name
        assert stat.S_IMODE(observed.st_mode) == directory_mode, name
    assert list((trust_root / "trust-staging").iterdir()) == []
    reasons.append(_reason(tmp_path))

    # Step 6: the inbox the document names, and the entry id is the file's SHA-256.
    (destination,) = re.findall(r"site-lite\.tar\.gz (/\S+)", steps[6])
    assert Path(destination).parent == CommissionedLite(Path(KNOWLEDGE)).inbox
    placed = Path(_relocate(destination, tmp_path))
    placed.parent.mkdir(parents=True, exist_ok=True)
    placed.write_bytes(_bundle(bundle_key, key_id))
    entry_id = hashlib.sha256(placed.read_bytes()).hexdigest()

    # Step 7: the store-owner import, exactly as printed.
    assert _run(_python(steps[7]), tmp_path, entry_id, AS_OF) == 0
    reasons.append(_reason(tmp_path))

    documented = re.search(
        r"reason `(\w+)` on a fresh install, `(\w+)`\s+after step 4, `(\w+)` after step 5"
        r" and `(\w+)` after step 7", _section())
    assert documented is not None
    assert reasons == list(documented.groups()) == [
        "trust_unreadable", "unverified", "no_bundle", "available"]


def test_the_installer_modes_the_document_states_are_the_declared_ones() -> None:
    step = _steps()[1]
    for path, owner, group, mode in (
        (LITE_TRUST, "azcommission", "azknowledge", 0o2750),
        (KNOWLEDGE, "azknowledge", "azazel-operator", 0o2750),
        ("/etc/azazel/commissioning", "root", "azcommission", 0o750),
    ):
        spec = spec_for(path)
        assert (spec.owner, spec.group, spec.mode) == (owner, group, mode)
        assert f"`{path}` as `{owner}:{group}` `{mode:04o}`" in _flat(step)


def _flat(text: str) -> str:
    return " ".join(text.split())


def _calls(name: str, *, roots: tuple[str, ...]) -> list[Path]:
    """Files under `roots` that call an attribute or function named `name`."""

    found = []
    for root in roots:
        for path in sorted((ROOT / root).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                    if called == name:
                        found.append(path.relative_to(ROOT))
                        break
    return found


PRODUCTION = ("src", "runtime/src")


def test_no_shipped_code_pins_trust_or_imports_a_lite_bundle() -> None:
    """The two steps the document runs by hand have no shipped caller."""

    assert _calls("pin", roots=PRODUCTION) == []
    # ModelImport has its own `import_entry`; no LiteImport caller exists.
    lite_users = set(_calls("LiteImport", roots=PRODUCTION))
    importers = set(_calls("import_entry", roots=PRODUCTION))
    assert not lite_users & importers
    assert "No command calls `TrustStore.pin`" in _steps()[3]
    assert "No shipped command calls `import_entry`" in _steps()[7]


def test_commission_policy_has_no_production_caller() -> None:
    """revocation.md and §11 say only test roots use it."""

    assert _calls("commission_policy", roots=PRODUCTION) == []
    assert _calls("commission_policy", roots=("lab/src", "tools"))
    revocation = (ROOT / "docs" / "revocation.md").read_text(encoding="utf-8")
    assert "production introduction and recovery use repin exclusively" in revocation
    assert "No production code calls it" in _flat(revocation)
    assert "`revocation_policy.commission_policy` is not part of this procedure" in _steps()[5]


def test_repin_document_points_at_the_procedure() -> None:
    for name in ("trust-repin.md", "revocation.md", "knowledge-lite-trust.md"):
        text = (ROOT / "docs" / name).read_text(encoding="utf-8")
        assert "knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available" in text


@pytest.mark.parametrize("step", [3, 7])
def test_documented_programs_compile(step) -> None:
    compile(_python(_steps()[step]), "<doc>", "exec")


def test_the_fixture_key_is_not_the_documented_anchor() -> None:
    """The document uses placeholders, never the published fixture key."""

    fixture = (CONTRACT / "anchors.toml").read_text(encoding="utf-8")
    key = re.search(r'= "([0-9a-f]{64})"', fixture).group(1)
    assert key not in _section()


# Owners and modes ---------------------------------------------------------
#
# Every owner and mode §11 sets, compared exactly with what it must be. The
# roots the installer declares come from layout.py, and install.sh must say the
# same. What the procedure adds is derived from those: a directory below a
# declared root keeps the root's mode, and a file is that mode without setgid
# or search bits (2750 -> 0640). Owners follow the document's rules: the trust
# record belongs to the repin daemon, root writes the anchors, and the store
# owner owns what the import reads.

SHELL_COMMAND = re.compile(r"^sudo (install|chown|chmod) (.*)$", re.M)
ALLOWED_SOURCES = {"anchors.toml", "repin-anchor.json", "site-lite.tar.gz"}


def _file_mode(directory_mode: int) -> int:
    return directory_mode & 0o666


def _expected() -> dict[str, tuple[str, str, str, int]]:
    """path -> (kind, owner, group, mode)."""

    trust, store = spec_for(LITE_TRUST), spec_for(KNOWLEDGE)
    commissioning = spec_for("/etc/azazel/commissioning")
    return {
        f"{LITE_TRUST}/trust": ("dir", "root", trust.group, trust.mode),
        f"{LITE_TRUST}/trust/anchors.toml": ("file", "root", trust.group, _file_mode(trust.mode)),
        f"{KNOWLEDGE}/trust": ("dir", "root", trust.group, store.mode),
        f"{KNOWLEDGE}/trust/anchors.toml": ("file", "root", trust.group, _file_mode(store.mode)),
        f"{LITE_TRUST}/trust.json": ("file", trust.owner, trust.group, _file_mode(trust.mode)),
        f"/etc/azazel/commissioning/{ANCHOR_FILENAME}": (
            "file", commissioning.owner, commissioning.group, _file_mode(commissioning.mode)),
        f"{KNOWLEDGE}/inbox": ("dir", store.owner, store.group, store.mode),
        f"{KNOWLEDGE}/inbox/site-lite.tar.gz": (
            "file", store.owner, store.group, _file_mode(store.mode)),
    }


def _documented() -> tuple[dict[str, list], list[str]]:
    """Every owner/mode the procedure sets, by path, and the sources it copies."""

    found: dict[str, list] = {}
    sources = []
    for verb, rest in SHELL_COMMAND.findall(_section()):
        words = rest.split()
        if verb == "chmod":
            mode, path = words
            found.setdefault(path, []).append(("mode", int(mode, 8)))
        elif verb == "chown":
            owner_group, path = words
            owner, group = owner_group.split(":")
            found.setdefault(path, []).append(("owner", owner, group))
        else:
            directory = words[0] == "-d"
            words = words[1:] if directory else words
            options = {}
            while words and words[0].startswith("-"):
                options[words[0]] = words[1]
                words = words[2:]
            assert set(options) == {"-m", "-o", "-g"}, f"install without explicit owner/mode: {rest}"
            if directory:
                (path,) = words
            else:
                source, path = words
                sources.append(source)
            found.setdefault(path, []).append(
                ("dir" if directory else "file", options["-o"], options["-g"], int(options["-m"], 8)))
    return found, sources


def _settled(entries: list) -> tuple:
    """Combine an install, or a chown plus a chmod, into one result."""

    kind, owner, group, mode = "file", None, None, None
    for entry in entries:
        if entry[0] == "mode":
            mode = entry[1]
        elif entry[0] == "owner":
            owner, group = entry[1], entry[2]
        else:
            kind, owner, group, mode = entry
    return (kind, owner, group, mode)


def test_the_declared_roots_agree_between_layout_and_installer() -> None:
    installer = (ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
    for path in (LITE_TRUST, KNOWLEDGE):
        spec = spec_for(path)
        assert f"make_owned_dir {spec.mode:o} {spec.owner} {spec.group} {path}\n" in installer
    spec = spec_for("/etc/azazel/commissioning")
    assert spec.owner == "root"
    assert f"make_dir {spec.mode:04o} {spec.group} /etc/azazel/commissioning\n" in installer


def test_every_owner_and_mode_the_procedure_sets_is_the_expected_one() -> None:
    found, _ = _documented()
    expected = _expected()
    assert set(found) == set(expected), "a path gained or lost an owner/mode step"
    for path, entries in found.items():
        assert _settled(entries) == expected[path], path


def test_no_step_grants_group_or_other_write() -> None:
    found, _ = _documented()
    for path, entries in found.items():
        assert _settled(entries)[3] & 0o022 == 0, path
    modes = re.findall(r"(?:chmod|-m) (\d{3,4})\b", _section())
    assert modes
    for mode in modes:
        assert int(mode, 8) & 0o022 == 0, mode


def test_no_step_places_private_key_or_secret_material() -> None:
    """#186 guard: only public anchors, the repin document and the bundle are written."""

    _, sources = _documented()
    assert set(sources) <= ALLOWED_SOURCES
    section = _section()
    placeholders = re.findall(r"<([^<>]*key[^<>]*)>", section)
    assert placeholders
    for placeholder in placeholders:
        assert placeholder.endswith("public key hex"), placeholder
    for word in ("PRIVATE KEY", "private_key", "secret", "seed", "passphrase", "password",
                 "SigningKey", ".key ", "/var/lib/azazel/secrets"):
        assert word not in section, word
    for document in _blocks(section, "json") + _blocks(section, "toml"):
        assert not re.search(r"[0-9a-f]{32,}", document), "literal key material in the document"


# Only these commands may appear in the procedure's shell blocks. Anything else
# (a `cp` of a .pem, a `umask 000`, a `mkdir -m`) escapes the owner/mode parsing
# above, so it fails here instead.
ALLOWED_COMMANDS = (
    "sudo install ",
    "sudo chown ",
    "sudo chmod ",
    "sudo /opt/azazel-nexus/venv/bin/python -I -c '",
    "sudo runuser -u azknowledge -- /opt/azazel-nexus/venv/bin/python -I -c '",
    "sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus_runtime.commission_cli trust-repin ",
    "sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus.cli status",
    "sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus.cli setup",
    "sudo sha256sum ",
)


# The one substitution a command line may carry is the timestamp argument, and
# its only angle brackets are quoted placeholders such as "<entry id>".
TIMESTAMP = '"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'
SHELL_METACHARACTERS = (";", "&", "|", "$(", "`", ">", "<")


def _shell_commands(section: str) -> list[str]:
    """Each command line of the shell blocks, skipping the quoted programs.

    A program opens on a line ending in `-c '` and closes on the next line that
    starts with `' `; its arguments follow on that closing line, which is
    checked as a command too.
    """

    commands = []
    for block in _blocks(section, "sh"):
        lines = iter(block.splitlines())
        for line in lines:
            if not line.strip():
                continue
            commands.append(line)
            if line.endswith(" -c '"):
                for inner in lines:
                    if inner.startswith("' "):
                        commands.append(inner)
                        break
                else:
                    raise AssertionError(f"unclosed program after: {line}")
    return commands


def test_the_procedure_uses_only_sh_json_and_toml_blocks() -> None:
    fences = re.findall(r"^```(\S*)$", _section(), flags=re.M)
    openings = fences[0::2]
    assert all(fence == "" for fence in fences[1::2]), fences
    assert set(openings) <= {"sh", "json", "toml"}, openings


def test_the_procedure_runs_only_the_allowed_commands() -> None:
    commands = _shell_commands(_section())
    assert len(commands) >= 11
    for command in commands:
        if command.startswith("' "):
            command = command[2:]
        else:
            assert command.startswith(ALLOWED_COMMANDS), command
        plain = re.sub(r'"<[^<>"]*>"', "", command.replace(TIMESTAMP, ""))
        for metacharacter in SHELL_METACHARACTERS:
            assert metacharacter not in plain, command
        assert ".pem" not in command and "umask" not in command, command


@pytest.mark.parametrize("step", (3, 7))
def test_the_documented_programs_change_no_permissions(step) -> None:
    program = _python(_steps()[step])
    for word in ("chmod", "chown", "umask", "subprocess", "os.system", "shutil"):
        assert word not in program, word


def test_no_sudo_command_relies_on_path_for_a_venv_script() -> None:
    """sudo's secure_path does not contain the venv, so a bare console script
    such as `azazel-nexus` or `az-nexus-commission` is not found (#93, VM)."""

    for command in _shell_commands(_section()):
        assert not re.match(r"sudo (?:runuser -u \S+ -- )?az", command), command


def _modules_run_with_m() -> list[str]:
    return sorted({m for c in _shell_commands(_section())
                   for m in re.findall(r" -I -m (\S+)", c)})


def _module_file(module: str) -> Path:
    relative = Path(*module.split(".")).with_suffix(".py")
    for base in (ROOT / "src", ROOT / "runtime" / "src"):
        if (base / relative).is_file():
            return base / relative
    raise AssertionError(f"no source for {module}")


def _calls_main_under_guard(tree: ast.Module) -> bool:
    for node in tree.body:
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"
                and [type(op) for op in node.test.ops] == [ast.Eq]
                and [getattr(c, "value", None) for c in node.test.comparators] == ["__main__"]):
            return any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "main"
                       for n in ast.walk(node))
    return False


def test_every_module_the_procedure_runs_with_m_has_a_main_guard() -> None:
    """`python -I -m pkg.mod` without a `__main__` guard imports and exits 0
    silently, so a step would look done without running (#93, PR #323)."""

    modules = _modules_run_with_m()
    assert modules == ["azazel_nexus.cli", "azazel_nexus_runtime.commission_cli"]
    for module in modules:
        tree = ast.parse(_module_file(module).read_text(encoding="utf-8"))
        assert _calls_main_under_guard(tree), module


def test_the_status_module_prints_when_run_with_m(tmp_path) -> None:
    import os
    import subprocess

    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    result = subprocess.run([sys.executable, "-m", "azazel_nexus.cli", "--help"],
                            capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)
    assert result.returncode == 0, result.stderr
    assert "status" in result.stdout and "setup" in result.stdout


def test_every_command_of_the_procedure_runs_as_root() -> None:
    """The store and trust roots are 2750 and their files 0640 or tighter, so
    an operator outside their groups cannot even read them: on the VM a bare
    `sha256sum` of the inbox bundle was refused (#93, 2026-10-25)."""

    for command in _shell_commands(_section()):
        if not command.startswith("' "):
            assert command.startswith("sudo "), command
