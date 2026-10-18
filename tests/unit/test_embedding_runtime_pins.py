"""Production pins and closed admission; all executable/model bytes are TEST data."""
import hashlib
import json
import os
import stat
from dataclasses import replace
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import mio_locald

from azazel_nexus import model_runtime as runtime
from tools import install_llama_runtime


def test_pin_resolution_refuses_pending_unknown_absent_and_wrong(tmp_path, monkeypatch):
    # Metadata is tested separately; host tmp directories are intentionally untrusted.
    monkeypatch.setattr(runtime, "_trusted_runtime_metadata", lambda *a, **k: None)
    tmp_path = tmp_path.resolve()
    assert len(runtime.RUNTIMES) == 1
    with pytest.raises(runtime.RuntimeRefused):
        runtime.pinned_runtime_digest("unknown")
    with pytest.raises(runtime.RuntimeRefused):
        runtime.resolve_runtime(runtime.LLAMA_RUNTIME_ID)
    payload = b"TEST executable bytes, never executed"
    expected = "sha256:" + hashlib.sha256(payload).hexdigest()
    monkeypatch.setitem(runtime.LLAMA_RUNTIME_DIGESTS, "aarch64", expected)
    monkeypatch.setattr(runtime.platform, "machine", lambda: "arm64")
    assert runtime.pinned_runtime_digest() == expected
    executable = tmp_path / "llama-server"
    record = replace(runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID], digest=expected)
    with pytest.raises(runtime.RuntimeRefused, match="absent"):
        runtime.verify_runtime_binary(record, executable)
    executable.write_bytes(payload)
    executable.chmod(0o755)
    runtime.verify_runtime_binary(record, executable)
    executable.write_bytes(b"wrong")
    with pytest.raises(runtime.RuntimeRefused, match="mismatch"):
        runtime.verify_runtime_binary(record, executable)
    executable.unlink()
    executable.symlink_to(tmp_path / "target")
    with pytest.raises(runtime.RuntimeRefused, match="symlink"):
        runtime.verify_runtime_binary(record, executable)


def test_install_rechecks_copied_bytes_and_owns_result(tmp_path, monkeypatch):
    source = tmp_path / "prebuilt"
    source.write_bytes(b"TEST ONLY")
    source.chmod(0o755)
    digest = "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest()
    monkeypatch.setattr(install_llama_runtime.os, "geteuid", lambda: 0)
    owners = []
    monkeypatch.setattr(install_llama_runtime.os, "chown", lambda *args: owners.append(args[1:]))
    monkeypatch.setattr(install_llama_runtime, "pinned_runtime_digest", lambda: digest)
    synced_directories = []
    real_fsync = os.fsync

    def sync(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            synced_directories.append(destination.exists())
        real_fsync(descriptor)

    monkeypatch.setattr(install_llama_runtime.os, "fsync", sync)
    destination = tmp_path / "installed" / "llama-server"
    install_llama_runtime.install_runtime(source, destination)
    assert destination.read_bytes() == source.read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o755
    assert owners == [(0, 0)]
    assert synced_directories == [True]
    source.write_bytes(b"tampered")
    with pytest.raises(runtime.RuntimeRefused):
        install_llama_runtime.install_runtime(source, destination)
    assert destination.read_bytes() == b"TEST ONLY"


def test_unverified_candidates_never_resolve_or_construct_server(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(mio_locald, "resolve_runtime", lambda *a: pytest.fail("resolution before admission"))
    assert mio_locald.prepare_local_models([object()], staging=tmp_path, audit=events.append) == ({}, [])
    assert events == [{"event_type": "mio.local.refused", "refusal": "unverified_candidate"}]


def test_both_model_roles_are_signed_test_only_and_v2_is_readable(tmp_path):
    from test_model_catalog import COMMISSIONING, an_entry, trusted, write_catalog

    from azazel_nexus.model_catalog import catalog_payload, read_catalog

    entries = [an_entry(model_id="bge-m3-q8-0", role="embedding",
                        digest="sha256:950f4a8e5e19477a6d3c26d2f162233c20002c601f75e4b002e3239997821167",
                        size_bytes=634553760, provenance="TEST declaration; MIT"),
               an_entry(model_id="qwen2-5-1-5b-q4-k-m", role="generative",
                        digest="sha256:6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e",
                        size_bytes=1117320736, provenance="TEST declaration; Apache-2.0")]
    path = write_catalog(tmp_path, entries)
    catalog = read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)
    assert {entry.role for entry in catalog.entries} == {"embedding", "generative"}
    document = json.loads(catalog_payload(version=1, commissioning_digest=COMMISSIONING, entries=[entries[1]]))
    document["schema"] = "azazel-nexus/model-catalog/2"
    del document["entries"][0]["role"]
    path = write_catalog(tmp_path, [], payload=json.dumps(document).encode())
    assert read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING).entries[0].role == "generative"


def test_admitted_embedding_uses_pinned_argv_and_generation_budget(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_serve
    from test_model_admission_evidence import admitted_candidate

    from azazel_nexus import model_admission
    from azazel_nexus.model_runtime import ArtifactDisposition, ArtifactInspection
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    candidate = admitted_candidate()
    monkeypatch.setattr(mio_locald, "inspect_artifact_fd", lambda fd: ArtifactInspection(ArtifactDisposition.DATA, ""))
    started = []

    class TestServer:
        def __init__(self, record, **kwargs):
            self.record, self.kwargs = record, kwargs
            started.append(self)

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(mio_serve, "LocalServer", TestServer)
    options, handles = mio_locald.prepare_local_models([candidate], staging=tmp_path, audit=lambda e: None)
    assert len(handles) == 1
    assert "--embedding" in started[0].record.argv
    assert options["retriever"].server is started[0]
    assert options["server"] is None
    assert started[0].kwargs["budget"].generation == 1
    assert started[0].kwargs["descriptors"] is candidate.evidence.descriptors


@pytest.mark.parametrize("mutation", ["missing", "unknown", "legacy_role"])
def test_signed_catalog_role_schema_refuses_ambiguous_roles(tmp_path, mutation):
    from test_model_catalog import COMMISSIONING, an_entry, trusted, write_catalog

    from azazel_nexus.model_catalog import CatalogRefused, catalog_payload, read_catalog

    document = json.loads(catalog_payload(version=1, commissioning_digest=COMMISSIONING,
                                          entries=[an_entry()]))
    if mutation == "missing":
        del document["entries"][0]["role"]
    elif mutation == "unknown":
        document["entries"][0]["role"] = "execute"
    else:
        document["schema"] = "azazel-nexus/model-catalog/2"
    path = write_catalog(tmp_path, [], payload=json.dumps(document).encode())
    with pytest.raises(CatalogRefused):
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)


def test_failed_embedding_start_stops_handle_and_keeps_daemon_available(tmp_path, monkeypatch):
    from azazel_nexus_runtime import mio_serve
    from test_model_admission_evidence import admitted_candidate

    from azazel_nexus import model_admission
    from azazel_nexus.model_runtime import ArtifactDisposition, ArtifactInspection
    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    stopped = []
    monkeypatch.setattr(mio_locald, "inspect_artifact_fd", lambda fd: ArtifactInspection(ArtifactDisposition.DATA, ""))

    class TestServer:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise mio_serve.LocalServerRefused("test startup refusal")

        def stop(self):
            stopped.append(True)

    monkeypatch.setattr(mio_serve, "LocalServer", TestServer)
    assert mio_locald.prepare_local_models([admitted_candidate()], staging=tmp_path, audit=lambda e: None) == ({}, [])
    assert stopped == [True]


def test_legacy_catalog_refuses_known_embedding_digest(tmp_path):
    from test_model_catalog import COMMISSIONING, an_entry, trusted, write_catalog

    from azazel_nexus.model_catalog import (
        KNOWN_EMBEDDING_DIGESTS,
        CatalogRefused,
        catalog_payload,
        read_catalog,
    )

    entry = an_entry(digest=next(iter(KNOWN_EMBEDDING_DIGESTS)), role="embedding")
    document = json.loads(catalog_payload(version=1, commissioning_digest=COMMISSIONING,
                                          entries=[entry]))
    document["schema"] = "azazel-nexus/model-catalog/2"
    del document["entries"][0]["role"]
    path = write_catalog(tmp_path, [], payload=json.dumps(document).encode())
    with pytest.raises(CatalogRefused, match="known embedding"):
        read_catalog(path, trusted_keys=trusted(), commissioning_digest=COMMISSIONING)


def test_admission_compatibility_binds_role():
    from test_cognition import a_catalogue, a_host, a_provider

    from azazel_nexus.cognition import AdmissionGate, admit_local_model

    verdict = admit_local_model(a_provider(role="embedding"), host=a_host(), tested=a_catalogue(model_role=None))
    assert verdict.failed_gate is AdmissionGate.COMPATIBILITY
    assert "role mismatch" in verdict.reason
    verdict = admit_local_model(a_provider(role="embedding"), host=a_host(),
                                tested=a_catalogue(model_role="embedding"))
    assert verdict.failed_gate is not AdmissionGate.COMPATIBILITY


@pytest.mark.parametrize("mode,uid,directory", [
    (stat.S_IFREG | 0o775, 0, False), (stat.S_IFREG | 0o757, 0, False),
    (stat.S_IFREG | 0o755, 501, False), (stat.S_IFLNK | 0o755, 0, False),
    (stat.S_IFDIR | 0o775, 0, True), (stat.S_IFDIR | 0o757, 0, True),
    (stat.S_IFDIR | 0o755, 501, True), (stat.S_IFLNK | 0o755, 0, True),
])
def test_runtime_metadata_refuses_untrusted_file_and_parents(mode, uid, directory):
    with pytest.raises(runtime.RuntimeRefused):
        runtime._trusted_runtime_metadata(SimpleNamespace(st_mode=mode, st_uid=uid),
                                          directory=directory)


@pytest.mark.parametrize("bad_index", range(5))
def test_runtime_walk_checks_every_parent_and_file(monkeypatch, bad_index):
    from pathlib import Path

    checked = []
    closed = []
    flags = []

    def open_fake(path, mode, **kwargs):
        flags.append(mode)
        return 100 + len(flags) - 1

    def metadata(fd):
        checked.append(fd)
        return SimpleNamespace(st_mode=(stat.S_IFREG if fd == 104 else stat.S_IFDIR) | 0o755,
                               st_uid=501 if fd == 100 + bad_index else 0)

    monkeypatch.setattr(runtime.os, "open", open_fake)
    monkeypatch.setattr(runtime.os, "fstat", metadata)
    monkeypatch.setattr(runtime.os, "close", closed.append)
    with pytest.raises(runtime.RuntimeRefused):
        runtime.open_verified_runtime(runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID],
                                      Path(runtime.LLAMA_EXECUTABLE))
    assert checked == list(range(100, 101 + bad_index))
    assert sorted(closed) == checked
    assert all(flag & os.O_NOFOLLOW for flag in flags)


def test_serving_process_refuses_without_held_descriptors(monkeypatch):
    from pathlib import Path

    from azazel_nexus_runtime import mio_supervisor

    from azazel_nexus import model_admission

    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    with pytest.raises(mio_supervisor.SupervisorRefused, match="held verified descriptors"):
        mio_supervisor.ServingProcess(runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID], root=Path("/")).start()


def test_local_server_stop_is_idempotent_without_socket_bind(tmp_path, monkeypatch):
    from admission_helpers import install_fake_serving

    install_fake_serving(monkeypatch)
    from azazel_nexus_runtime.mio_serve import LocalServer

    from azazel_nexus.runtime_lifecycle import LifecycleState

    record = runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID]
    server = LocalServer(record, root=tmp_path, socket_path=tmp_path / "test.sock")
    server._child.process = SimpleNamespace(pid=123)
    stopped = []

    def stop_child():
        if server._child.process is not None:
            stopped.append(server._child.process.pid)
            server._child.process = None

    monkeypatch.setattr(server._child, "stop", stop_child)
    server.stop()
    server.stop()
    assert stopped == [123]
    assert server.state is LifecycleState.STOPPED


def test_production_main_passes_no_candidates(tmp_path, monkeypatch):
    from azazel_nexus_runtime import runtime_paths

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.mio_local_state_dir().mkdir(parents=True)
    captured = []
    monkeypatch.setattr(mio_locald, "prepare_local_models",
                        lambda candidates, **kw: captured.append(candidates) or ({}, []))
    monkeypatch.setattr(mio_locald, "serve_forever", lambda **kw: 0)
    monkeypatch.setattr(mio_locald.PrincipalPolicy, "resolve", lambda **kw: object())
    assert mio_locald.main([]) == 0
    assert captured == [[]]


def test_installer_empty_runtime_option_refuses():
    import subprocess

    result = subprocess.run(["sh", "packaging/install.sh", "--llama-runtime", ""],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 2
    assert "needs one path" in result.stderr


def test_runtime_refuses_symlinked_parent(tmp_path, monkeypatch):
    path = tmp_path.resolve()
    (path / "real").mkdir()
    (path / "link").symlink_to(path / "real", target_is_directory=True)
    monkeypatch.setattr(runtime, "_trusted_runtime_metadata", lambda *a, **kw: None)
    with pytest.raises(runtime.RuntimeRefused, match="symlinked"):
        runtime.verify_runtime_binary(runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID],
                                      path / "link" / "llama-server")


def test_non_procfs_serving_refuses_without_held_descriptors(monkeypatch):
    from pathlib import Path

    from azazel_nexus_runtime import mio_supervisor

    from azazel_nexus import model_admission

    monkeypatch.setattr(model_admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    monkeypatch.setattr(Path, "is_dir", lambda path: False)
    with pytest.raises(mio_supervisor.SupervisorRefused, match="held verified descriptors"):
        mio_supervisor.ServingProcess(runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID], root=Path("/")).start()
