"""Pure startup wrapper grammar and import-path policy tests."""

import pytest

from azazel_nexus_runtime.startup_wrapper import (
    import_bootstrap,
    parse_wrapper,
    render_wrapper,
    validate_import_paths,
    validate_interpreter_path,
    validate_target,
)


INTERPRETER = "/opt/azazel/runtime/bin/python3"
TARGET = "azazel_nexus_runtime.auditd:main"
PATHS = ("/nonexistent/runtime/site-packages", "/nonexistent/runtime/vendor")


def test_pure_render_and_parse_canonical_roundtrip_without_existing_paths():
    raw = render_wrapper(INTERPRETER, TARGET, import_paths=PATHS)

    assert raw.startswith(f"#!{INTERPRETER} -IS\n".encode())
    assert parse_wrapper(raw, target=TARGET) == (INTERPRETER, PATHS)
    assert import_bootstrap(PATHS) == (
        "import sys\n"
        "sys.path = ['/nonexistent/runtime/site-packages', '/nonexistent/runtime/vendor']\n"
        "sys.dont_write_bytecode = True\n"
    )


def test_import_paths_are_bounded_normalized_and_deduplicated_in_order():
    assert validate_import_paths([PATHS[0], PATHS[1], PATHS[0]]) == PATHS


@pytest.mark.parametrize("paths", [
    (), [], ["relative/path"], ["/"], ["/opt//runtime"], ["/opt/./runtime"],
    ["/opt/../runtime"], ["/opt/runtime\nextra"], ["/" + "x" * 4096],
    [f"/opt/p{index}" for index in range(17)],
    ["/opt/runtime", 3],
])
def test_import_path_validation_rejects_invalid_or_overbound_inputs(paths):
    with pytest.raises(ValueError):
        validate_import_paths(paths)


@pytest.mark.parametrize("interpreter", [
    "python3", "/", "/usr//bin/python3", "/usr/./bin/python3",
    "/usr/../bin/python3", "/opt/two words/python", "/opt/é/python",
    "/opt/line\npython", "/" + "p" * 128,
])
def test_interpreter_validation_rejects_noncanonical_or_overlong_shebang(interpreter):
    with pytest.raises(ValueError):
        validate_interpreter_path(interpreter)


@pytest.mark.parametrize("target", [
    "bad;code:main", "module:main()", "module:main:other", "module:",
    "valid..module:main", "class:main", "valid.module:class",
])
def test_target_validation_rejects_injection_and_nonidentifiers(target):
    with pytest.raises(ValueError):
        validate_target(target)
    with pytest.raises(ValueError):
        render_wrapper(INTERPRETER, target, import_paths=PATHS)


def test_rendered_target_is_literal_and_parser_does_not_import_candidate():
    hostile_but_valid_module = "missing_candidate_module_for_parser_test:main"
    raw = render_wrapper(INTERPRETER, hostile_but_valid_module, import_paths=PATHS)
    assert parse_wrapper(raw, target=hostile_but_valid_module) == (INTERPRETER, PATHS)


@pytest.mark.parametrize("mutation", [
    "prefix-flags", "body", "comment", "extra-code", "truncated", "other-target",
])
def test_parser_rejects_noncanonical_wrapper_forms(mutation):
    raw = render_wrapper(INTERPRETER, TARGET, import_paths=PATHS)
    if mutation == "prefix-flags":
        altered = raw.replace(b" -IS\n", b" -I\n", 1)
    elif mutation == "body":
        altered = raw.replace(b"sys.dont_write_bytecode = True", b"sys.path.append('/evil')")
    elif mutation == "comment":
        altered = raw.replace(b"import sys\n", b"import sys\n# comment\n")
    elif mutation == "extra-code":
        altered = raw + b"import evil\n"
    elif mutation == "truncated":
        altered = raw[:-1]
    else:
        altered = raw
    target = "other.module:main" if mutation == "other-target" else TARGET

    with pytest.raises(ValueError):
        parse_wrapper(altered, target=target)


def test_parser_rejects_deep_path_literal_and_oversized_input():
    deep = b"[" * 2000 + b"'/opt/path'" + b"]" * 2000
    raw = (
        f"#!{INTERPRETER} -IS\nimport sys\nsys.path = ".encode()
        + deep
        + b"\nsys.dont_write_bytecode = True\n"
        + f"from {TARGET.split(':')[0]} import main\nraise SystemExit(main())\n".encode()
    )
    with pytest.raises(ValueError):
        parse_wrapper(raw, target=TARGET)
    with pytest.raises(ValueError):
        parse_wrapper(b"x" * 65537, target=TARGET)


def test_rendered_wrapper_at_parser_bound_roundtrips_and_overbound_refuses():
    near_bound = tuple("/" + letter * 3999 for letter in "abcdefghijklmnop")
    raw = render_wrapper(INTERPRETER, TARGET, import_paths=near_bound)
    assert len(raw) <= 65536
    assert parse_wrapper(raw, target=TARGET) == (INTERPRETER, near_bound)

    over_bound = tuple("/" + letter * 4095 for letter in "abcdefghijklmnop")
    with pytest.raises(ValueError, match="parser byte bound"):
        render_wrapper(INTERPRETER, TARGET, import_paths=over_bound)


def test_parser_rejects_nonbytes_and_non_utf8():
    for value in ("not bytes", b"\xff"):
        with pytest.raises(ValueError):
            parse_wrapper(value, target=TARGET)
