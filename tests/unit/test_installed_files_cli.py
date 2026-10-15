"""Operator inspection command wiring; no production file inspection."""

import io

import pytest

from azazel_nexus import cli, installed_files
from azazel_nexus.operator_trust import ApprovalRefused


class Input:
    def __init__(self, raw, terminal=False):
        self.buffer = io.BytesIO(raw)
        self.terminal = terminal

    def isatty(self):
        return self.terminal


def test_cli_passes_independent_pin_and_exact_bytes_reports_limited_scope(monkeypatch):
    import sys
    pin = "sha256:" + "a" * 64
    monkeypatch.setattr(sys, "stdin", Input(b"manifest"))
    calls = []

    def measure(raw, *, expected_digest):
        calls.append((raw, expected_digest))
        return installed_files.SelectedInstalledFiles(pin, 2, 8)

    monkeypatch.setattr(installed_files, "measure_installed_files", measure)
    out = io.StringIO()
    assert cli.main(["installed-files-check", "--manifest-digest", pin], out=out) == 0
    assert calls == [(b"manifest", pin)]
    assert "NOT dependency closure" in out.getvalue()
    assert "Selected files matched: 2; bytes: 8" in out.getvalue()


def test_installed_files_check_reports_directory_count_only_when_nonzero(monkeypatch):
    import sys

    pin = "sha256:" + "b" * 64
    monkeypatch.setattr(sys, "stdin", Input(b"manifest"))
    monkeypatch.setattr(
        installed_files, "measure_installed_files",
        lambda _raw, *, expected_digest: installed_files.SelectedInstalledFiles(
            expected_digest, 2, 8, 3,
        ),
    )
    out = io.StringIO()
    assert cli.main(["installed-files-check", "--manifest-digest", pin], out=out) == 0
    assert "Selected directories matched: 3\n" in out.getvalue()


def test_installed_files_check_reports_link_count_only_when_nonzero(monkeypatch):
    import sys

    pin = "sha256:" + "c" * 64
    monkeypatch.setattr(sys, "stdin", Input(b"manifest"))
    monkeypatch.setattr(
        installed_files, "measure_installed_files",
        lambda _raw, *, expected_digest: installed_files.SelectedInstalledFiles(
            expected_digest, 2, 8, 3, 1,
        ),
    )
    out = io.StringIO()
    assert cli.main(["installed-files-check", "--manifest-digest", pin], out=out) == 0
    assert "Selected directories matched: 3\n" in out.getvalue()
    assert "Selected links matched: 1\n" in out.getvalue()


@pytest.mark.parametrize("terminal", [False, True])
def test_cli_refuses_terminal_or_failed_measurement_without_details(monkeypatch, terminal):
    import sys
    monkeypatch.setattr(sys, "stdin", Input(b"untrusted", terminal=terminal))

    def refused(*args, **kwargs):
        if terminal:
            pytest.fail("terminal input reached measurement")
        raise ApprovalRefused("private location must not be printed")

    monkeypatch.setattr(installed_files, "measure_installed_files", refused)
    out = io.StringIO()
    assert cli.main(["installed-files-check", "--manifest-digest", "wrong"], out=out) == 1
    assert out.getvalue() == "Selected installed file inspection refused; no changes made.\n"


def test_candidate_cli_emits_generator_bytes_exactly_and_marks_scope(monkeypatch):
    import sys

    raw_input = b'{"paths":["opt/addon/file","usr/bin/example"]}'
    paths = ("opt/addon/file", "usr/bin/example")
    manifest = b'{"schema":"synthetic canonical manifest"}'
    calls = []

    def generate(selected):
        calls.append(selected)
        return manifest

    monkeypatch.setattr(sys, "stdin", Input(raw_input))
    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate", generate,
    )
    out = io.BytesIO()
    err = io.StringIO()
    assert cli.main(["installed-files-candidate"], out=out, err=err) == 0
    assert calls == [paths]
    assert out.getvalue() == manifest
    assert err.getvalue() == (
        "Candidate only: not dependency closure, approval, or admission.\n"
    )


def test_candidate_default_stdout_writes_exact_manifest_bytes(monkeypatch):
    import sys

    class BinaryStdout:
        def __init__(self):
            self.buffer = io.BytesIO()

    stdout = BinaryStdout()
    err = io.StringIO()
    manifest = b'{"files":[],"schema":"canonical"}'
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/bin/example"]}'))
    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate",
        lambda _paths: manifest,
    )

    assert cli.main(["installed-files-candidate"]) == 0
    assert stdout.buffer.getvalue() == manifest
    assert not stdout.buffer.getvalue().endswith(b"\n")
    assert "Candidate only:" in err.getvalue()


def test_candidate_cli_forwards_explicit_sorted_directories(monkeypatch):
    import sys

    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/bin/example"]}'))
    calls = []
    manifest = b'{"schema":"synthetic v2 manifest"}'

    def generate(paths, *, directories=()):
        calls.append((paths, directories))
        return manifest

    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate", generate,
    )
    out = io.BytesIO()
    err = io.StringIO()
    assert cli.main([
        "installed-files-candidate", "--directory", "usr/bin",
        "--directory", "usr/share",
    ], out=out, err=err) == 0
    assert calls == [(("usr/bin/example",), ("usr/bin", "usr/share"))]
    assert out.getvalue() == manifest


def test_candidate_cli_forwards_explicit_sorted_links_and_keeps_canonical_output(
    monkeypatch,
):
    import sys

    paths = ("usr/bin/python",)
    links = ("usr/bin/python3",)
    manifest = b'{"directories":[],"files":[],"links":[],"schema":"v3"}'
    calls = []

    def generate(selected, *, links=()):
        calls.append((selected, links))
        return manifest

    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/bin/python"]}'))
    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate", generate,
    )
    out = io.BytesIO()
    err = io.StringIO()
    assert cli.main([
        "installed-files-candidate", "--link", "usr/bin/python3",
    ], out=out, err=err) == 0
    assert calls == [(paths, links)]
    assert out.getvalue() == manifest
    assert not out.getvalue().endswith(b"\n")
    assert err.getvalue() == (
        "Candidate only: not dependency closure, approval, or admission.\n"
    )


@pytest.mark.parametrize("directories", [
    ("usr/bin", "usr"),
    ("usr/bin", "usr/bin"),
    ("usr/../etc",),
    ("/usr/bin",),
])
def test_candidate_cli_rejects_invalid_directories_without_output_or_generation(
    monkeypatch, directories,
):
    import sys

    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/bin/example"]}'))
    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate",
        lambda *_args, **_kwargs: pytest.fail("invalid dirs reached generator"),
    )
    argv = ["installed-files-candidate"]
    for directory in directories:
        argv.extend(("--directory", directory))
    out = io.BytesIO()
    err = io.StringIO()
    assert cli.main(argv, out=out, err=err) == 1
    assert out.getvalue() == b""
    assert "Installed files candidate refused; no changes made." in err.getvalue()


@pytest.mark.parametrize("links", [
    ("usr/bin/z", "usr/bin/a"),
    ("usr/bin/a", "usr/bin/a"),
    ("usr/../etc/passwd",),
    ("/usr/bin/python",),
])
def test_candidate_cli_rejects_invalid_links_without_output_or_generation(
    monkeypatch, links,
):
    import sys

    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/bin/example"]}'))
    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate",
        lambda *_args, **_kwargs: pytest.fail("invalid links reached generator"),
    )
    argv = ["installed-files-candidate"]
    for link in links:
        argv.extend(("--link", link))
    out = io.BytesIO()
    err = io.StringIO()
    assert cli.main(argv, out=out, err=err) == 1
    assert out.getvalue() == b""
    assert "Installed files candidate refused; no changes made." in err.getvalue()


@pytest.mark.parametrize("raw,terminal", [
    (b'{"paths":["usr/a"],"extra":true}', False),
    (b'{"paths":["usr/a"],"paths":["usr/b"]}', False),
    (b'{"paths":["usr/b","usr/a"]}', False),
    (b'{"paths":["usr/a","usr/a"]}', False),
    (b'{"paths":["usr/../etc/passwd"]}', False),
    (b'{"paths":[]}', False),
    (b"not json", False),
    (b'{"paths":["usr/a"]}', True),
    (b"{" + b" " * (1 << 20), False),
])
def test_candidate_cli_rejects_invalid_or_unbounded_input_before_generator(
    monkeypatch, raw, terminal,
):
    import sys

    monkeypatch.setattr(sys, "stdin", Input(raw, terminal=terminal))
    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate",
        lambda _paths: pytest.fail("invalid input reached candidate generator"),
    )
    out = io.StringIO()
    err = io.StringIO()
    assert cli.main(["installed-files-candidate"], out=out, err=err) == 1
    assert out.getvalue() == ""
    assert err.getvalue().splitlines() == [
        "Candidate only: not dependency closure, approval, or admission.",
        "Installed files candidate refused; no changes made.",
    ]


def test_candidate_cli_sanitizes_generator_failure(monkeypatch):
    import sys

    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/private-name"]}'))

    def refused(_paths):
        raise ApprovalRefused("/secret/private-name and host details")

    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate", refused,
    )
    out = io.StringIO()
    err = io.StringIO()
    assert cli.main(["installed-files-candidate"], out=out, err=err) == 1
    assert out.getvalue() == ""
    assert "secret" not in out.getvalue() + err.getvalue()
    assert "private-name" not in out.getvalue() + err.getvalue()
    assert "Installed files candidate refused; no changes made." in err.getvalue()


def test_candidate_default_stdout_stays_empty_on_failure(monkeypatch):
    import sys

    class BinaryStdout:
        def __init__(self):
            self.buffer = io.BytesIO()

    stdout = BinaryStdout()
    err = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(sys, "stdin", Input(b'{"paths":["usr/secret"]}'))

    def refused(_paths):
        raise ApprovalRefused("/private/host/path")

    monkeypatch.setattr(
        "azazel_nexus.installed_candidate.generate_installed_candidate", refused,
    )
    assert cli.main(["installed-files-candidate"]) == 1
    assert stdout.buffer.getvalue() == b""
    assert err.getvalue().splitlines() == [
        "Candidate only: not dependency closure, approval, or admission.",
        "Installed files candidate refused; no changes made.",
    ]
    assert "private" not in err.getvalue()
