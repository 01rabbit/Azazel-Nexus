"""Scoped unit files and the overrides that would change them (#206 P3b).

Temporary roots only: every search-path directory is resolved below a test
root owned by the test user.
"""

import os

import pytest

from azazel_nexus_runtime import activation_unit_files as unit_files
from azazel_nexus_runtime.activation_unit_files import (
    UnitContentRefused,
    UnitFilesRefused,
    UnitOverrideRefused,
    drop_in_directory_names,
    measure_scoped_unit_files,
    rendered_unit,
    require_governed_unit_content,
    require_grantable_unit_files,
    require_no_unit_overrides,
)

EDGE = "azazel-edge-core.service"
INTAKE = "azazel-edge-intaked.service"
SCOPE = (EDGE, INTAKE)
SEARCH = ("etc/systemd/system", "run/systemd/system", "usr/local/lib/systemd/system",
          "etc/systemd/system.control", "run/systemd/system.control",
          "run/systemd/transient", "run/systemd/generator", "run/systemd/generator.late",
          "run/systemd/generator.early", "etc/systemd/system.attached",
          "run/systemd/system.attached")


@pytest.fixture
def root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    vendor = root / "usr/lib/systemd/system"
    vendor.mkdir(parents=True)
    for unit in SCOPE:
        (vendor / unit).write_text(rendered_unit(unit))
        (vendor / unit).chmod(0o644)
    for path in [root, *root.rglob("*")]:
        if path.is_dir():
            path.chmod(0o755)
    monkeypatch.setattr(unit_files, "_ROOT", root)
    monkeypatch.setattr(unit_files, "_OWNER", os.getuid())
    return root


def _dir(root, relative):
    path = root / relative
    path.mkdir(parents=True, exist_ok=True)
    current = path
    while current != root:
        current.chmod(0o755)
        current = current.parent
    return path


def test_measures_the_vendor_files_when_nothing_overrides_them(root):
    assert measure_scoped_unit_files(SCOPE) == {
        unit: rendered_unit(unit).encode() for unit in SCOPE}


def test_search_path_is_the_reviewed_systemd_profile():
    assert set(unit_files._SEARCH_PATH) == {"/" + d for d in SEARCH} | {
        "/usr/lib/systemd/system"}


def test_drop_in_names_include_prefix_and_global_forms():
    assert drop_in_directory_names(EDGE) == (
        "azazel-edge-core.service.d", "azazel-.service.d", "azazel-edge-.service.d",
        "service.d")


@pytest.mark.parametrize("directory", SEARCH)
def test_a_mask_symlink_is_the_accepted_governed_state(root, directory):
    (_dir(root, directory) / EDGE).symlink_to("/dev/null")
    require_no_unit_overrides(SCOPE)
    assert set(measure_scoped_unit_files(SCOPE)) == set(SCOPE)


@pytest.mark.parametrize("directory", SEARCH)
@pytest.mark.parametrize("entry", ["file", "other-link", "relative-null", "directory"])
def test_any_other_same_name_entry_is_an_override(root, directory, entry):
    target = _dir(root, directory) / EDGE
    if entry == "file":
        target.write_text("[Service]\nEnvironment=AZAZEL_ENFORCE=1\n")
    elif entry == "other-link":
        target.symlink_to(root / "usr/lib/systemd/system" / INTAKE)
    elif entry == "relative-null":
        target.symlink_to("../../../dev/null")
    else:
        target.mkdir()
    with pytest.raises(UnitOverrideRefused):
        require_no_unit_overrides(SCOPE)
    with pytest.raises(UnitOverrideRefused):
        measure_scoped_unit_files(SCOPE)


@pytest.mark.parametrize("directory", (*SEARCH, "usr/lib/systemd/system"))
@pytest.mark.parametrize("name", [
    "azazel-edge-core.service.d", "azazel-.service.d", "azazel-edge-.service.d",
    "service.d", "azazel-edge-intaked.service.d",
])
def test_any_drop_in_file_is_refused_in_every_directory_including_vendor(root, directory, name):
    drop_in = _dir(root, directory) / name
    drop_in.mkdir()
    require_no_unit_overrides(SCOPE)  # an empty drop-in directory changes nothing
    (drop_in / "10-environment.conf").write_text("[Service]\nEnvironment=X=1\n")
    with pytest.raises(UnitOverrideRefused):
        require_no_unit_overrides(SCOPE)


@pytest.mark.parametrize("entry", ["file", "symlink", "mask-inside"])
def test_drop_in_entries_of_any_kind_are_refused(root, entry, tmp_path):
    base = _dir(root, "run/systemd/system")
    if entry == "file":
        (base / "azazel-edge-core.service.d").write_text("not a directory")
    elif entry == "symlink":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (base / "azazel-edge-core.service.d").symlink_to(elsewhere)
    else:
        (base / "service.d").mkdir()
        (base / "service.d/vendor.conf").symlink_to("/dev/null")
    with pytest.raises(UnitOverrideRefused):
        require_no_unit_overrides(SCOPE)


def test_unrelated_units_and_their_drop_ins_are_ignored(root):
    base = _dir(root, "etc/systemd/system")
    (base / "ssh.service").write_text("[Service]\n")
    (base / "ssh.service.d").mkdir()
    (base / "ssh.service.d/x.conf").write_text("[Service]\n")
    (base / "sockets.target.d").mkdir()
    (base / "sockets.target.d/x.conf").write_text("[Unit]\n")
    (base / "multi-user.target.wants").mkdir()
    require_no_unit_overrides(SCOPE)


def test_a_writable_or_linked_search_directory_refuses(root, tmp_path):
    base = _dir(root, "etc/systemd/system")
    base.chmod(0o777)
    with pytest.raises(UnitFilesRefused):
        require_no_unit_overrides(SCOPE)
    base.chmod(0o755)
    base.rename(tmp_path / "moved")
    base.symlink_to(tmp_path / "moved")
    with pytest.raises(UnitFilesRefused):
        require_no_unit_overrides(SCOPE)


@pytest.mark.parametrize("units", [(), ("ssh.service",), (EDGE, EDGE), "azazel-edge-core.service"])
def test_scope_must_be_allowlisted_distinct_units(root, units):
    with pytest.raises(UnitFilesRefused):
        measure_scoped_unit_files(units)


def test_a_missing_vendor_file_or_directory_refuses(root):
    (root / "usr/lib/systemd/system" / INTAKE).unlink()
    with pytest.raises(UnitFilesRefused):
        measure_scoped_unit_files(SCOPE)
    (root / "usr/lib/systemd/system" / EDGE).unlink()
    (root / "usr/lib/systemd/system").rmdir()
    with pytest.raises(UnitFilesRefused):
        require_no_unit_overrides(SCOPE)


# -- the grant-marker lines and start guards (#251 H-1) ---------------------

REPO = __import__("pathlib").Path(__file__).resolve().parents[2]
MARKER = "ConditionPathExists=/run/azazel-activation/granted/azazel-edge-intaked.service"


def test_every_packaged_scoped_unit_passes_the_content_check():
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    for unit in ACTIVATION_UNIT_ALLOWLIST:
        data = (REPO / "packaging/systemd" / unit).read_bytes()
        require_governed_unit_content(unit, data)
        assert data == rendered_unit(unit).encode()


def _without(text, line):
    assert text.count(line + "\n") == 1
    return text.replace(line + "\n", "")


def _in_unit(text, line):
    return text.replace("[Unit]\n", "[Unit]\n" + line + "\n", 1)


@pytest.mark.parametrize("edit", [
    lambda t: _without(t, MARKER),
    lambda t: _without(t, "Requires=azazel-activated.service"),
    lambda t: _without(t, "After=azazel-activated.service"),
    lambda t: t.replace(MARKER, MARKER.replace("=", " = ", 1)),
    lambda t: t.replace(MARKER, MARKER.replace("=/", "=!/", 1)),
    lambda t: t.replace(MARKER, MARKER.replace("=/", "=|/", 1)),
    lambda t: t.replace(MARKER, MARKER + "X"),
    lambda t: _without(t, MARKER) + "[Service]\n" + MARKER + "\n",
    lambda t: t + "[Unit]\nConditionPathExists=\n",
    lambda t: _in_unit(t, "ConditionPathExists="),
    lambda t: _in_unit(t, "Requires="),
    lambda t: _in_unit(t, "After="),
    lambda t: _in_unit(t, "ConditionPathExists=|/"),
    lambda t: _in_unit(t, "ConditionHost=other"),
    lambda t: _in_unit(t, "AssertPathExists=/"),
    lambda t: t.replace("[Service]\n", "[Service]\nExecCondition=/bin/true\n", 1),
    lambda t: _in_unit(t, "Description=a \\"),
    lambda t: t.replace("\n", "\r\n"),
    lambda t: t + "\0",
    lambda t: "Description=before any section\n" + t,
    lambda t: _in_unit(t, "not an assignment"),
], ids=["no-marker", "no-requires", "no-after", "spaced-marker", "negated-marker",
        "triggering-marker", "other-marker", "marker-in-service", "reset-in-second-unit",
        "condition-reset", "requires-reset", "after-reset", "added-trigger",
        "added-condition", "added-assert", "added-exec-condition", "continuation", "crlf",
        "nul", "outside-section", "syntax"])
def test_a_unit_file_without_its_grant_lines_or_with_another_guard_is_refused(edit):
    text = rendered_unit(INTAKE)
    with pytest.raises(UnitContentRefused):
        require_governed_unit_content(INTAKE, edit(text).encode())


def test_content_outside_the_scope_or_undecodable_is_refused():
    with pytest.raises(UnitContentRefused):
        require_governed_unit_content(
            "azazel-watchdog.service", rendered_unit(INTAKE).encode())
    with pytest.raises(UnitContentRefused):
        require_governed_unit_content(INTAKE, b"\xff" + rendered_unit(INTAKE).encode())
    with pytest.raises(UnitContentRefused):
        require_governed_unit_content(EDGE, rendered_unit(INTAKE).encode())


def test_knowledge_context_unit_is_marker_guarded_and_grantable(root):
    from azazel_nexus_runtime.activation_markers import (
        GRANTABLE_UNITS,
    )
    from azazel_nexus_runtime.hardening import GRANT_MARKER_UNITS

    context = "azazel-knowledge-contextd.service"
    assert context in GRANT_MARKER_UNITS
    assert context in GRANTABLE_UNITS
    require_governed_unit_content(context, rendered_unit(context).encode())
    vendor = root / "usr/lib/systemd/system"
    (vendor / context).write_text(rendered_unit(context))
    (vendor / context).chmod(0o644)
    require_grantable_unit_files([context])


def test_comments_and_other_settings_do_not_affect_the_content_check():
    """The hash and the operator's signature bind the rest of the file."""
    text = rendered_unit(INTAKE) + "# a comment\n; another\n"
    require_governed_unit_content(INTAKE, text.encode())


def test_measuring_refuses_a_vendor_file_without_its_marker_condition(root):
    target = root / "usr/lib/systemd/system" / INTAKE
    target.write_text(_without(rendered_unit(INTAKE), MARKER))
    with pytest.raises(UnitContentRefused):
        measure_scoped_unit_files(SCOPE)


#: Characters Python's `str.strip()` removes and systemd does not treat as
#: whitespace, plus a BOM and other controls. Each, at the start or end of a
#: line, is refused: Python would otherwise read `\xa0[Unit]` as a header
#: that systemd ignores, and the required lines would land in another section.
OTHER_SPACE = ["\xa0", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f", "\x85",
               "\u1680", "\u2000", "\u2028", "\u2029", "\u202f", "\u3000", "\ufeff",
               "\x01", "\x7f"]


@pytest.mark.parametrize("char", OTHER_SPACE, ids=[f"U+{ord(c):04X}" for c in OTHER_SPACE])
@pytest.mark.parametrize("where", ["header-start", "header-end", "line-start", "line-end",
                                   "file-start"])
def test_any_character_but_printable_ascii_and_tab_is_refused(char, where):
    text = rendered_unit(INTAKE)
    if where == "header-start":
        # Required lines moved behind a header systemd would ignore.
        text = (_without(_without(_without(text, MARKER),
                                  "Requires=azazel-activated.service"),
                         "After=azazel-activated.service")
                + char + "[Unit]\n" + MARKER + "\nRequires=azazel-activated.service\n"
                "After=azazel-activated.service\n")
    elif where == "header-end":
        text = text.replace("[Unit]\n", "[Unit]" + char + "\n", 1)
    elif where == "line-start":
        text = text.replace(MARKER, char + MARKER)
    elif where == "line-end":
        text = text.replace(MARKER, MARKER + char)
    else:
        text = char + text
    with pytest.raises(UnitContentRefused):
        require_governed_unit_content(INTAKE, text.encode("utf-8"))


CONTROLS = ["\x01", "\x0b", "\x0c", "\x1b", "\x1f", "\x7f"]


@pytest.mark.parametrize("char", CONTROLS, ids=[f"U+{ord(c):04X}" for c in CONTROLS])
@pytest.mark.parametrize("where", ["comment-end", "value-middle"])
def test_a_control_only_the_character_filter_sees_is_refused(char, where):
    """A control where no other check looks: only `_decode` can refuse it.

    At the end of a comment line the parser skips the line; in the middle of
    `Description=` the value is neither a start guard nor a required line.
    The same text with a printable character in its place is accepted, so the
    refusal comes from the character filter and from nothing else.
    """
    text = rendered_unit(INTAKE)
    if where == "comment-end":
        assert text.startswith("# Generated")
        edited = text.replace("\n", "@@\n", 1)
    else:
        assert text.count("Description=Azazel-Nexus ") == 1
        edited = text.replace("Description=Azazel-Nexus ", "Description=Azazel-@@Nexus ")
    require_governed_unit_content(INTAKE, edited.replace("@@", "X").encode())
    with pytest.raises(UnitContentRefused, match="encoding refused"):
        require_governed_unit_content(INTAKE, edited.replace("@@", char).encode())


def test_space_and_tab_around_a_line_are_still_accepted():
    text = rendered_unit(INTAKE).replace("Description=", " \tDescription=", 1)
    require_governed_unit_content(INTAKE, text.encode())


def test_every_packaged_unit_is_printable_ascii():
    for path in (REPO / "packaging/systemd").glob("*.service"):
        text = path.read_bytes().decode("ascii")
        assert all(" " <= c <= "~" or c in "\t\n" for c in text), path.name


# -- every grantable unit, in the policy or not ----------------------------


def test_grantable_files_accept_absent_units_and_check_present_ones(root):
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    require_grantable_unit_files(ACTIVATION_UNIT_ALLOWLIST)  # four absent, two rendered
    vendor = root / "usr/lib/systemd/system"
    other = "azazel-mio-entryd.service"
    (vendor / other).write_text(rendered_unit(other).replace(
        f"ConditionPathExists=/run/azazel-activation/granted/{other}\n", ""))
    (vendor / other).chmod(0o644)
    with pytest.raises(UnitContentRefused):
        require_grantable_unit_files(ACTIVATION_UNIT_ALLOWLIST)


def test_grantable_files_refuse_an_override_of_a_unit_outside_the_policy(root):
    from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
    drop_in = _dir(root, "etc/systemd/system/azazel-mio-entryd.service.d")
    (drop_in / "x.conf").write_text("[Unit]\nConditionPathExists=\n")
    with pytest.raises(UnitOverrideRefused):
        require_grantable_unit_files(ACTIVATION_UNIT_ALLOWLIST)


def test_grantable_files_refuse_an_unprotected_present_file(root):
    (root / "usr/lib/systemd/system" / INTAKE).chmod(0o666)
    with pytest.raises(UnitFilesRefused):
        require_grantable_unit_files(SCOPE)
