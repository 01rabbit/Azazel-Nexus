from dataclasses import FrozenInstanceError
import os
import threading

import pytest

from azazel_nexus_runtime import debian_packages as packages


def _output(*rows):
    return ("\n".join(rows) + "\n").encode("utf-8")


def _fixture():
    return _output(
        "dpkg\t1.22.22\tarm64\tii ",
        "libc6:arm64\t2.41-12\tarm64\tii ",
        "libc6:amd64\t2.41-12\tamd64\tii ",
        "old-package\t1.0\tarm64\trc ",
    )


class _SyntheticProcess:
    def __init__(self, output, *, returncode=0, keep_open=False):
        read_fd, write_fd = os.pipe()
        self.stdout = os.fdopen(read_fd, "rb", buffering=0)
        self._write_fd = write_fd
        self._returncode = None
        self._final_returncode = returncode
        self._keep_open = keep_open
        if not keep_open:
            def emit():
                try:
                    view = memoryview(output)
                    while view:
                        written = os.write(write_fd, view[:4096])
                        view = view[written:]
                except OSError:
                    pass
                finally:
                    try:
                        os.close(write_fd)
                    except OSError:
                        pass

            self._thread = threading.Thread(target=emit, daemon=True)
            self._thread.start()

    def poll(self):
        return self._returncode

    def wait(self, timeout=None):
        if self._returncode is None:
            self._returncode = self._final_returncode
        return self._returncode

    def kill(self):
        self._returncode = -9
        if self._keep_open:
            os.close(self._write_fd)
            self._keep_open = False


def _patch_process(monkeypatch, output, *, returncode=0, keep_open=False):
    calls = []

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return _SyntheticProcess(output, returncode=returncode, keep_open=keep_open)

    monkeypatch.setattr(packages.subprocess, "Popen", popen)
    return calls


def test_snapshot_preserves_multiarch_and_derives_native_arch_from_dpkg_row():
    snapshot = packages.parse_package_output(_fixture())
    assert snapshot.schema == packages.SCHEMA
    assert snapshot.native_architecture == "arm64"
    assert [(item.binary_package, item.architecture) for item in snapshot.records] == [
        ("dpkg", "arm64"),
        ("libc6:amd64", "amd64"),
        ("libc6:arm64", "arm64"),
    ]
    assert snapshot.digest.startswith("sha256:")
    assert len(snapshot.digest) == len("sha256:") + 64


def test_snapshot_digest_is_canonical_across_input_row_order():
    forward = _fixture()
    reverse = _output(*reversed(forward.decode().splitlines()))
    assert packages.parse_package_output(forward).digest == packages.parse_package_output(reverse).digest


def test_snapshot_and_records_are_immutable():
    snapshot = packages.parse_package_output(_fixture())
    with pytest.raises(FrozenInstanceError):
        snapshot.native_architecture = "amd64"
    with pytest.raises(FrozenInstanceError):
        snapshot.records[0].version = "changed"


def test_snapshot_boundary_recomputes_digest_and_structure():
    snapshot = packages.parse_package_output(_fixture())
    assert packages.validate_package_snapshot(snapshot) is None
    forged_digest = packages.PackageSnapshot(
        snapshot.schema, snapshot.native_architecture, snapshot.records,
        "sha256:" + "0" * 64,
    )
    with pytest.raises(packages.PackageObservationRefused, match="digest"):
        packages.validate_package_snapshot(forged_digest)
    wrong_schema = packages.PackageSnapshot(
        "other-schema", snapshot.native_architecture, snapshot.records, snapshot.digest,
    )
    with pytest.raises(packages.PackageObservationRefused, match="structure"):
        packages.validate_package_snapshot(wrong_schema)


@pytest.mark.parametrize("rows", [
    ("dpkg:amd64\t1.0\tamd64\tii ",),
    ("dpkg\t1.0\tarm64\tii ", "libc6:amd64\t2.0\tarm64\tii "),
])
def test_ambiguous_native_or_inconsistent_multiarch_qualifier_is_refused(rows):
    with pytest.raises(packages.PackageObservationRefused):
        packages.parse_package_output(_output(*rows))


@pytest.mark.parametrize("raw", [
    b"",
    b"dpkg\t1.0\tarm64\tii ",  # no canonical final newline
    b"dpkg\t1.0\tarm64\tii \r\n",
    b"dpkg\t1.0\tarm64\tii \x00\n",
    b"dpkg\t1.0\tarm64\tii \n\n",
    b"dpkg\t1.0\tarm64\tii \textra\n",
    b"dpkg\t1.0\tarm64\tii \nlibc\xff\t1\tarm64\tii \n",
    b"not-a-package\t1\tarm64\tii \n",
    b"dpkg\tbad version\tarm64\tii \n",
    b"dpkg\t1\tarm64\tbad\n",
])
def test_noncanonical_or_malformed_output_is_refused(raw):
    with pytest.raises(packages.PackageObservationRefused):
        packages.parse_package_output(raw)


def test_duplicate_package_architecture_is_refused_even_if_qualified_differently():
    raw = _output(
        "dpkg\t1.0\tarm64\tii ",
        "libc6\t2.0\tamd64\tii ",
        "libc6:amd64\t2.0\tamd64\tii ",
    )
    with pytest.raises(packages.PackageObservationRefused, match="duplicate"):
        packages.parse_package_output(raw)


def test_missing_native_dpkg_row_is_refused():
    with pytest.raises(packages.PackageObservationRefused, match="native architecture"):
        packages.parse_package_output(_output("libc6:arm64\t2.0\tarm64\tii "))


def test_non_installed_status_is_valid_but_not_included():
    snapshot = packages.parse_package_output(_output(
        "dpkg\t1.0\tarm64\tii ", "old\t1.0\tarm64\trc "
    ))
    assert [item.binary_package for item in snapshot.records] == ["dpkg"]


def test_query_uses_only_fixed_absolute_command_and_redacts_stderr(monkeypatch):
    calls = _patch_process(monkeypatch, _fixture())
    result = packages.observe_installed_packages()
    assert result.native_architecture == "arm64"
    assert calls == [(packages.QUERY_ARGV, {
        "stdin": packages.subprocess.DEVNULL,
        "stdout": packages.subprocess.PIPE,
        "stderr": packages.subprocess.DEVNULL,
        "env": {"LC_ALL": "C", "LANG": "C"},
        "close_fds": True,
    })]
    assert packages.QUERY_ARGV[:2] == ("/usr/bin/dpkg-query", "-W")
    assert len(packages.QUERY_ARGV) == 3


def test_nonzero_process_result_is_redacted(monkeypatch):
    _patch_process(monkeypatch, b"private diagnostic", returncode=1)
    with pytest.raises(packages.PackageObservationRefused) as error:
        packages.observe_installed_packages()
    assert "private diagnostic" not in str(error.value)


def test_timeout_is_redacted_and_process_is_killed(monkeypatch):
    monkeypatch.setattr(packages, "QUERY_TIMEOUT_SECONDS", 0.01)
    process = None

    def popen(argv, **kwargs):
        nonlocal process
        process = _SyntheticProcess(b"", keep_open=True)
        return process

    monkeypatch.setattr(packages.subprocess, "Popen", popen)
    with pytest.raises(packages.PackageObservationRefused, match="timed out") as error:
        packages.observe_installed_packages()
    assert "private" not in str(error.value)
    assert process.poll() == -9


def test_oversized_output_is_stopped_and_refused(monkeypatch):
    monkeypatch.setattr(packages, "MAX_OUTPUT_BYTES", 64)
    process = None

    def popen(_argv, **_kwargs):
        nonlocal process
        process = _SyntheticProcess(b"x" * 4096)
        return process

    monkeypatch.setattr(packages.subprocess, "Popen", popen)
    with pytest.raises(packages.PackageObservationRefused, match="exceeds bound"):
        packages.observe_installed_packages()
    assert process.poll() == -9


def test_exact_output_limit_is_still_parsed_or_refused_by_grammar(monkeypatch):
    monkeypatch.setattr(packages, "MAX_OUTPUT_BYTES", 64)
    process = _SyntheticProcess(b"x" * 65)
    monkeypatch.setattr(packages.subprocess, "Popen", lambda *_args, **_kwargs: process)
    with pytest.raises(packages.PackageObservationRefused, match="exceeds bound"):
        packages.observe_installed_packages()
