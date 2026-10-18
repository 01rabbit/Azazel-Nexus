"""HIL runbooks may name only commands, flags, schemas, paths and refusal
symbols that exist in the code, so they cannot silently go stale.

The runbooks are executed by an operator on hardware nobody here can reach. A
stale flag, schema or symbol is discovered there, mid-campaign, which is the
most expensive place to find it. Everything below is read from the code, never
restated in this test.
"""

from __future__ import annotations

import ast
import functools
import hashlib
import hmac
import re
import shlex
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
RUNBOOKS = (*sorted((DOCS / "hil-runbooks").glob("*.md")),
            DOCS / "hil-campaign.md", DOCS / "hil-evidence-records.md",
            DOCS / "local-model-admission.md")
ADMISSION = DOCS / "hil-runbooks" / "mio-admission.md"
CODE_ROOTS = (REPO / "src", REPO / "runtime" / "src", REPO / "tools")

#: Operator placeholders written in capitals; none of them names a code symbol.
PLACEHOLDERS = {"DAEMON_ACCOUNT", "RUN_ID", "APPROVER_PUBLIC_HEX", "MODEL_ID", "DUT_ID"}
#: A file of Azazel-Edge, named by hg-07.md as the producer of the Edge package.
EXTERNAL_REPOSITORY_PATHS = {"packaging/nexus-core/nexus_core_package.py"}
#: Host paths owned by the code; anything else (/proc, /sys, media) is external.
HOST_PREFIXES = ("/etc/azazel", "/var/lib/azazel", "/usr/libexec/azazel",
                 "/run/azazel-mio-identity", "/usr/share/azazel")
#: HMAC domains composed at runtime as "azazel-nexus/" + domain + "/v1\0".
COMPOSED_DOMAINS = {"azazel-nexus/hil-host/v1": "hil-host", "azazel-nexus/hil-boot/v1": "hil-boot"}


def _python_files():
    for root in CODE_ROOTS:
        yield from sorted(root.rglob("*.py"))


@functools.cache
def _module_names(path: Path) -> frozenset[str]:
    """String literals and identifiers defined or used in one module."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            value = node.value
            names.add(value.decode("latin-1") if isinstance(value, bytes) else value)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
    return frozenset(names)


@functools.cache
def _code_names() -> frozenset[str]:
    return frozenset().union(*(_module_names(path) for path in _python_files()))


@functools.cache
def _host_corpus() -> str:
    """Raw text of code and packaging, where fixed host paths are declared."""
    files = [*_python_files(), *sorted((REPO / "packaging").rglob("*"))]
    return "\n".join(path.read_text(encoding="utf-8", errors="replace")
                     for path in files if path.is_file())


@functools.cache
def _scripts() -> dict[str, Path]:
    declared = tomllib.loads((REPO / "runtime" / "pyproject.toml").read_text())
    result = {}
    for name, target in declared["project"]["scripts"].items():
        module = target.split(":", 1)[0]
        result[name] = REPO / "runtime" / "src" / Path(*module.split(".")).with_suffix(".py")
    return result


@functools.cache
def _cli_commands() -> frozenset[str]:
    """Every subcommand registered on the `azazel-nexus` parser and its helpers."""
    names = set()
    for path in sorted((REPO / "src" / "azazel_nexus").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "add_parser" and node.args
                    and isinstance(node.args[0], ast.Constant)):
                names.add(node.args[0].value)
    return frozenset(names)


def _split(text: str):
    """Fenced code (with continuations joined) and inline code spans."""
    fenced, inline = [], []
    blocks = re.split(r"^\s*```[a-z]*\s*$", text, flags=re.MULTILINE)
    for index, block in enumerate(blocks):
        if index % 2:
            fenced.extend(re.sub(r"\\\n\s*", " ", block).splitlines())
        else:
            inline.extend(" ".join(span.split()) for span in re.findall(r"`([^`]+)`", block))
    return fenced, inline


def _documents():
    return [(path, *_split(path.read_text(encoding="utf-8"))) for path in RUNBOOKS]


def _commands(line: str):
    """Repository commands in one shell line: (kind, source, argv)."""
    for segment in re.split(r"\|\||&&|[|;{}()]|\$\(", line):
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
        while words and (words[0] in ("sudo", "env", "exec")
                         or re.fullmatch(r"[A-Z_]+=\S*", words[0])):
            words.pop(0)
        if not words:
            continue
        head = words[0]
        name = head.rsplit("/", 1)[-1] if head.startswith("/usr/libexec/azazel/") else head
        if re.fullmatch(r"az-[a-z]+(?:-[a-z]+)*", name):
            yield "script", name, words[1:]
        elif head == "azazel-nexus":
            yield "cli", head, words[1:]
        elif head in ("python", "python3") and len(words) > 2 and words[1] == "-m":
            if words[2].startswith(("tools.", "azazel_nexus")):
                yield "module", words[2], words[3:]
        elif head.endswith("packaging/install.sh"):
            yield "installer", "packaging/install.sh", words[1:]


def _all_commands():
    for path, fenced, inline in _documents():
        for line in (*fenced, *inline):
            for command in _commands(line):
                yield path.name, line, command


def test_the_runbooks_name_repository_commands():
    assert any(kind == "script" for _, _, (kind, _, _) in _all_commands())
    assert any(kind == "module" for _, _, (kind, _, _) in _all_commands())


@pytest.mark.parametrize("document,line,command", [
    pytest.param(*item, id=f"{item[0]}:{item[2][1]}:{index}")
    for index, item in enumerate(_all_commands())])
def test_every_command_subcommand_and_flag_exists(document, line, command):
    kind, name, arguments = command
    if kind == "script":
        scripts = _scripts()
        assert name in scripts, f"{document}: {name} is not a console script"
        source = scripts[name]
    elif kind == "cli":
        source = REPO / "src" / "azazel_nexus" / "cli.py"
        positional = [a for a in arguments if not a.startswith("-")]
        if positional:
            assert positional[0] in _cli_commands(), f"{document}: azazel-nexus {positional[0]}"
    elif kind == "module":
        source = REPO / Path(*name.split(".")).with_suffix(".py")
        if not source.exists():
            source = REPO / "src" / Path(*name.split(".")).with_suffix(".py")
        assert source.exists(), f"{document}: module {name} does not exist"
    else:
        source = REPO / name
        text = source.read_text(encoding="utf-8")
        for flag in (a.split("=", 1)[0] for a in arguments if a.startswith("--")):
            assert f"{flag})" in text, f"{document}: install.sh has no {flag}"
        return
    names = _module_names(source)
    text = source.read_text(encoding="utf-8")
    for flag in (a.split("=", 1)[0] for a in arguments if a.startswith("--")):
        assert flag in names, f"{document}: {name} has no option {flag}"
    positional = [a for a in arguments if not a.startswith("-")]
    if kind != "cli" and positional and ("add_subparsers" in text or "choices=" in text):
        first = positional[0]
        if not first.isupper() and first not in ("-",):
            assert first in names, f"{document}: {name} has no subcommand {first}"


def test_schema_names_exist_in_code():
    from azazel_nexus_runtime.hil_readiness import digest

    literals = _code_names()
    seen = set()
    for path, fenced, inline in _documents():
        for text in (*fenced, *inline):
            # A schema/domain is never part of a filesystem path such as
            # /opt/azazel-nexus/venv/bin/...; a preceding "/" or word char excludes it.
            for schema in re.findall(r"(?<![/\w-])azazel-nexus/[a-z0-9][a-z0-9/._-]*[a-z0-9]", text):
                seen.add(schema)
                if schema in COMPOSED_DOMAINS:
                    key, value = b"k" * 32, "v"
                    expected = hmac.new(key, (schema + "\0" + value).encode(),
                                        hashlib.sha256).hexdigest()
                    assert digest(value, key=key, domain=COMPOSED_DOMAINS[schema]) == (
                        "hmac-sha256:" + expected)
                    continue
                assert any(schema in literal for literal in literals), (
                    f"{path.name}: schema/domain {schema} is not in the code")
    assert "azazel-nexus/hil-mio-campaign/v1" in seen


def _symbols(inline, text):
    for span in inline:
        if re.fullmatch(r"[A-Z][A-Z0-9_]{3,}", span):
            yield span
        yield from re.findall(r"refused: ?([A-Z][A-Z0-9_]+)", span)
    yield from re.findall(r"refused: ?([A-Z][A-Z0-9_]+)", text)
    for row in re.findall(r"^\| (`[A-Z][^|]*)\|", text, flags=re.MULTILINE):
        yield from re.findall(r"`([A-Z][A-Z0-9_]+)`", row)


def test_refusal_symbols_and_constants_exist_in_code():
    # A symbol may be a whole literal, an identifier, or a word of a fixed
    # message such as "refused: ROOT_REQUIRED".
    names = _code_names() | {word for literal in _code_names()
                             for word in re.findall(r"[A-Z][A-Z0-9_]{3,}", literal)}
    checked = set()
    for path, _fenced, inline in _documents():
        text = path.read_text(encoding="utf-8")
        for symbol in _symbols(inline, text):
            if symbol in PLACEHOLDERS:
                continue
            checked.add(symbol)
            assert symbol in names, f"{path.name}: {symbol} does not exist in the code"
    assert {"ADMISSION_DISABLED", "RESERVE_VIRTUALIZATION_OBSERVED", "ATTESTER_IS_APPROVER",
            "LOCAL_MODEL_ADMISSION_ENABLED"} <= checked


def _host_paths(text):
    for token in re.findall(r"(/(?:etc|var|usr|run)/[A-Za-z0-9_./<>*$-]+)", text):
        if token.startswith(HOST_PREFIXES):
            yield token


def test_fixed_host_paths_exist_in_code_or_packaging():
    corpus = _host_corpus()
    for path, fenced, inline in _documents():
        for text in (*fenced, *inline):
            for token in _host_paths(text):
                prefix = re.split(r"[<*$]", token, maxsplit=1)[0].rstrip("/.-")
                parent, _, base = prefix.rpartition("/")
                if base.startswith("."):
                    # Operator temporary in a fixed directory (atomic placement).
                    prefix, base = parent, ""
                if prefix.lstrip("/") in corpus:
                    continue
                # An example sequence number stands for the code's own name pattern.
                stem = re.split(r"[0-9]{2,}", base, maxsplit=1)[0]
                assert parent.lstrip("/") in corpus and len(stem) > 3 and stem in corpus, (
                    f"{path.name}: host path {token} is not declared by the code")


def test_repository_paths_exist():
    for path, fenced, inline in _documents():
        for text in (*fenced, *inline):
            for token in re.findall(r"(?<![\w/.])((?:tools|packaging|src|runtime|tests)/[\w./-]+)",
                                    text):
                token = token.rstrip(".")
                if token in EXTERNAL_REPOSITORY_PATHS:
                    continue
                assert (REPO / token).exists(), f"{path.name}: {token} does not exist"


# -- values the admission runbook states exactly -------------------------------


def _admission():
    return ADMISSION.read_text(encoding="utf-8")


def test_the_signing_prefix_is_the_operator_approval_transcript():
    from azazel_nexus.operator_trust import ApprovalPurpose, approval_message

    prefix = approval_message(ApprovalPurpose.LOCAL_MODEL_ADMISSION, b"x")[:-1]
    text = _admission()
    stated = re.search(r"must print exactly\s+`([0-9a-f]+)`", text)
    assert stated and stated.group(1) == prefix.hex()
    printf = re.search(r"printf '(azazel-nexus/operator-approval/[^']+)'", text)
    assert printf and printf.group(1).replace("\\000", "\0").encode() == prefix
    assert f"head -c {len(prefix)} message.bin" in text


def test_the_runtime_pin_is_the_code_pin():
    from azazel_nexus.model_runtime import LLAMA_RUNTIME_DIGESTS, LLAMA_RUNTIME_ID

    text = _admission()
    assert f"`{LLAMA_RUNTIME_DIGESTS['x86_64']}`" in text
    assert f"`{LLAMA_RUNTIME_ID}`" in text


def test_the_request_line_has_exactly_the_cli_fields():
    from azazel_nexus_runtime import model_admission_cli

    from azazel_nexus import model_admission as admission

    tree = ast.parse(Path(model_admission_cli.__file__).read_text(encoding="utf-8"))
    sets = [node for node in ast.walk(tree) if isinstance(node, ast.Set)
            and {"operator", "issued_at"} <= {getattr(e, "value", None) for e in node.elts}]
    assert len(sets) == 1
    expected = {element.value for element in sets[0].elts}
    line = re.search(r"printf '%s\\n' '(\{\"envelope_floor_mib[^']+)'", _admission()).group(1)
    raw = line.replace("FLOOR", "1").replace("NEED", "1").encode()
    assert set(admission.decode(raw)) == expected


def test_the_policy_and_wrapper_examples_decode():
    from azazel_nexus import model_admission as admission

    text = _admission()
    policy = re.search(r"printf '%s' '(\{\"max_seconds[^']+)'", text).group(1).encode()
    assert admission.AdmissionPolicy.from_bytes(policy).roles == ("embedding",)
    wrapper = re.search(r"printf '(\{\"payload_b64[^']+)'", text).group(1)
    raw = (wrapper % ("eyJhIjoxfQ==", "00" * 64)).encode()
    doc = admission.decode(raw)
    assert set(doc) == {"schema", "payload_b64", "signature_hex"}
    assert doc["schema"] == admission.FILE_SCHEMA


def test_the_campaign_fields_are_the_validator_fields():
    from azazel_nexus import hil_records
    from azazel_nexus.virtualization import SENSORS

    source = Path(hil_records.__file__).read_text(encoding="utf-8")
    fields = re.search(r"fields = \{([^}]+)\}", source.split("def _mio_campaign", 1)[1])
    runtime_fields = set(re.findall(r'"([a-z0-9_]+)"', fields.group(1)))
    assert len(runtime_fields) == 7
    text = _admission()
    for name in (*runtime_fields, *SENSORS, "virtualization_not_observed",
                 hil_records.MIO_CAMPAIGN_SCHEMA):
        assert f"`{name}`" in text, name
    for key, value in {"class": "hardware-only", "platform": "rugged-x86_64-linux",
                       "provenance": "measured"}.items():
        assert f"| `{key}` | `{value}` |" in text
    from azazel_nexus_runtime.core_reserve_probe import HARNESS_VERSION

    assert f"`{HARNESS_VERSION}`" in text


def test_the_runbook_states_the_cli_output_lines():
    from azazel_nexus_runtime import model_admission_cli

    literals = _module_names(Path(model_admission_cli.__file__))
    text = _admission()
    for line in ("signs nothing, authorizes nothing / 署名・認可は行いません",
                 "feature disabled / 機能無効",
                 "domain/purpose: azazel-nexus/operator-approval/v1\\0local-model-admission\\0"):
        assert f"`{line}`" in text
        assert line in literals
    assert "embedding -> " in literals


def test_vm_output_is_never_evidence():
    text = " ".join(_admission().split())
    assert "## 17. VM rehearsal (never evidence)" in _admission()
    assert "Its outputs are never HIL evidence" in text
    assert "never enroll them on a DUT" in text
