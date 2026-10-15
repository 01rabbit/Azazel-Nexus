"""Pure validation, rendering and parsing for fixed isolated startup wrappers."""

import ast
import keyword


def validate_interpreter_path(interpreter: str) -> None:
    if (type(interpreter) is not str or not interpreter.isascii()
            or not interpreter.startswith("/") or interpreter == "/"
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127
                   for char in interpreter)):
        raise ValueError("canonical absolute Python interpreter path required")
    components = interpreter[1:].split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError("canonical absolute Python interpreter path required")
    if len(f"#!{interpreter} -IS".encode("ascii")) > 127:
        raise ValueError("Python interpreter shebang exceeds 127-byte limit")


def validate_import_paths(paths: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if type(paths) not in (list, tuple) or not 0 < len(paths) <= 16:
        raise ValueError("bounded explicit Python import paths required")
    result = []
    for path in paths:
        if (type(path) is not str or not 0 < len(path) <= 4096
                or not path.startswith("/") or path == "/"
                or any(ord(char) < 32 or ord(char) == 127 for char in path)
                or any(part in {"", ".", ".."} for part in path[1:].split("/"))):
            raise ValueError("canonical absolute Python import path required")
        if path not in result:
            result.append(path)
    return tuple(result)


def validate_target(target: str) -> tuple[str, str]:
    if type(target) is not str or target.count(":") != 1:
        raise ValueError("Python module:function target required")
    module, function = target.split(":")
    identifiers = (*module.split("."), function)
    if any(not part.isidentifier() or keyword.iskeyword(part) for part in identifiers):
        raise ValueError("Python module and function identifiers required")
    return module, function


def import_bootstrap(paths: list[str] | tuple[str, ...]) -> str:
    normalized = validate_import_paths(paths)
    return (
        "import sys\n"
        f"sys.path = {list(normalized)!r}\n"
        "sys.dont_write_bytecode = True\n"
    )


def render_wrapper(
    interpreter: str, target: str, *, import_paths: list[str] | tuple[str, ...],
) -> bytes:
    validate_interpreter_path(interpreter)
    module, function = validate_target(target)
    rendered = (
        f"#!{interpreter} -IS\n"
        + import_bootstrap(import_paths)
        + f"from {module} import {function}\n"
        f"raise SystemExit({function}())\n"
    ).encode("utf-8")
    if len(rendered) > 65536:
        raise ValueError("startup wrapper exceeds parser byte bound")
    return rendered


def parse_wrapper(raw: bytes, *, target: str) -> tuple[str, tuple[str, ...]]:
    """Parse only this module's canonical wrapper grammar; never execute it."""
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise ValueError("bounded startup wrapper bytes required")
    module, function = validate_target(target)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("startup wrapper must be UTF-8") from error
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("startup wrapper newline form refused")
    lines = text.splitlines(keepends=True)
    if len(lines) != 6 or lines[1:] != [
        "import sys\n",
        lines[2],
        "sys.dont_write_bytecode = True\n",
        f"from {module} import {function}\n",
        f"raise SystemExit({function}())\n",
    ]:
        raise ValueError("startup wrapper body refused")
    shebang = lines[0]
    if not shebang.startswith("#!") or not shebang.endswith(" -IS\n"):
        raise ValueError("startup wrapper interpreter flags refused")
    interpreter = shebang[2:-len(" -IS\n")]
    validate_interpreter_path(interpreter)
    assignment = lines[2]
    prefix = "sys.path = "
    if not assignment.startswith(prefix) or not assignment.endswith("\n"):
        raise ValueError("startup wrapper import path assignment refused")
    literal = assignment[len(prefix):-1]
    try:
        paths = validate_import_paths(ast.literal_eval(literal))
    except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError) as error:
        raise ValueError("startup wrapper import path literal refused") from error
    if render_wrapper(interpreter, target, import_paths=paths) != raw:
        raise ValueError("startup wrapper is not canonical")
    return interpreter, paths
