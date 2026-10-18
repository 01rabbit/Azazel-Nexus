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


def test_denied_admission_never_resolves_or_constructs_server(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(mio_locald, "admit_local_model", lambda *a, **k: SimpleNamespace(
        admitted=False, as_event=lambda: {"event_type": "test.denied"}))
    monkeypatch.setattr(mio_locald, "resolve_runtime", lambda *a: pytest.fail("resolution before admission"))
    candidate = mio_locald.LocalModelCandidate(SimpleNamespace(), object(), None, None)
    assert mio_locald.prepare_local_models([candidate], staging=tmp_path, audit=events.append) == ({}, [])
    assert events == [{"event_type": "test.denied"}]


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


@pytest.mark.parametrize("with_generation", [False, True])
def test_admitted_roles_wire_separate_servers_and_embedding_argv(tmp_path, monkeypatch, with_generation):
    from azazel_nexus_runtime import mio_serve
    from test_model_catalog import an_entry

    from azazel_nexus.model_catalog import artifact_filename

    started = []

    class TestServer:
        def __init__(self, record, **kwargs):
            self.record = record
            started.append(self)

        def start(self):
            self.serving = True

        def stop(self):
            self.serving = False

    monkeypatch.setattr(mio_serve, "LocalServer", TestServer)
    monkeypatch.setattr(mio_locald, "admit_local_model", lambda *a, **k: SimpleNamespace(
        admitted=True, as_event=lambda: {"event_type": "TEST.admitted"}))
    monkeypatch.setattr(mio_locald, "containment_for", lambda **k: None)
    record = runtime.RuntimeBinary("TEST", runtime.LLAMA_EXECUTABLE, "b11716", "sha256:" + "0" * 64,
                                   (runtime.LLAMA_EXECUTABLE,))
    monkeypatch.setattr(mio_locald, "resolve_runtime", lambda *a: record)
    candidates = []
    for role in (["embedding", "generative"] if with_generation else ["embedding"]):
        entry = an_entry(model_id="TEST".lower() + role, role=role)
        (tmp_path / artifact_filename(entry)).write_bytes(b"weights, not a program")
        candidates.append(mio_locald.LocalModelCandidate(entry, SimpleNamespace(
            name=entry.model_id, component_digest=entry.digest, memory_need_mib=1024,
            runtime_version="b11716", role=role), None, None,
            SimpleNamespace(reserve=object(), envelope_mib=8192)))
    options, handles = mio_locald.prepare_local_models(candidates, staging=tmp_path,
                                                       artifact_root=tmp_path, audit=lambda e: None)
    assert len(handles) == (2 if with_generation else 1)
    assert "--embedding" in started[0].record.argv
    assert options["retriever"].server is started[0]
    assert options["server"] is (started[1] if with_generation else None)
    if with_generation:
        assert "--embedding" not in started[1].record.argv
        assert started[0].record.argv != started[1].record.argv


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


@pytest.mark.parametrize("embedding", ["missing", "fails", "role_mismatch"])
def test_missing_embedding_cleans_all_started_handles(tmp_path, monkeypatch, embedding):
    from azazel_nexus_runtime import mio_serve
    from test_model_catalog import an_entry

    from azazel_nexus.model_catalog import artifact_filename

    handles = []

    class TestServer:
        def __init__(self, record, **kwargs):
            self.record = record
            self.stopped = False
            handles.append(self)

        def start(self):
            if "--embedding" in self.record.argv:
                raise mio_serve.LocalServerRefused("TEST failed readiness")

        def stop(self):
            self.stopped = True

    monkeypatch.setattr(mio_serve, "LocalServer", TestServer)
    monkeypatch.setattr(mio_locald, "admit_local_model", lambda *a, **k: SimpleNamespace(
        admitted=True, as_event=lambda: {"event_type": "TEST.admitted"}))
    monkeypatch.setattr(mio_locald, "containment_for", lambda **k: None)
    monkeypatch.setattr(mio_locald, "resolve_runtime", lambda *a: runtime.RuntimeBinary(
        "TEST", runtime.LLAMA_EXECUTABLE, "b11716", "sha256:" + "0" * 64,
        (runtime.LLAMA_EXECUTABLE,)))
    candidates = []
    for role in ["generative", *([] if embedding == "missing" else ["embedding"])]:
        entry = an_entry(model_id="test-" + role, role=role)
        (tmp_path / artifact_filename(entry)).write_bytes(b"weights, not a program")
        provider = SimpleNamespace(name=entry.model_id, component_digest=entry.digest,
                                   memory_need_mib=1024, runtime_version="b11716",
                                   role="generative" if embedding == "role_mismatch" else role)
        candidates.append(mio_locald.LocalModelCandidate(
            entry, provider, None, None, SimpleNamespace(reserve=object(), envelope_mib=8192)))
    assert mio_locald.prepare_local_models(candidates, staging=tmp_path,
                                          artifact_root=tmp_path, audit=lambda e: None) == ({}, [])
    assert handles and all(handle.stopped for handle in handles)
    assert len(handles) == (2 if embedding == "fails" else 1)


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

    verdict = admit_local_model(a_provider(role="embedding"), host=a_host(), tested=a_catalogue())
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


def test_linux_exec_uses_hashed_descriptor_and_closes_it(monkeypatch):
    from pathlib import Path

    from azazel_nexus_runtime import mio_supervisor

    closed, calls = [], []
    record = runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID]
    monkeypatch.setattr(mio_supervisor, "open_verified_runtime", lambda *a: 99)
    monkeypatch.setattr(Path, "is_dir", lambda p: str(p) == "/proc/self/fd")
    monkeypatch.setattr(mio_supervisor.os, "close", closed.append)
    monkeypatch.setattr(mio_supervisor.subprocess, "Popen", lambda *a, **k: calls.append(k) or object())
    mio_supervisor.ServingProcess(record, root=Path("/")).start()
    assert calls[0]["executable"] == "/proc/self/fd/99"
    assert calls[0]["pass_fds"] == (99,)
    assert closed == [99]


def test_local_server_stop_is_idempotent_without_socket_bind(tmp_path, monkeypatch):
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
    assert captured == [()]


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


@pytest.mark.parametrize("refuse", [False, True])
def test_non_proc_fallback_reverifies_before_popen_and_closes_fd(monkeypatch, refuse):
    from pathlib import Path

    from azazel_nexus_runtime import mio_supervisor

    events = []
    record = runtime.RUNTIMES[runtime.LLAMA_RUNTIME_ID]
    monkeypatch.setattr(mio_supervisor, "open_verified_runtime", lambda *a: 99)
    monkeypatch.setattr(Path, "is_dir", lambda p: False)
    monkeypatch.setattr(mio_supervisor.os, "close", lambda fd: events.append(("close", fd)))

    def verify(*args):
        events.append("verify")
        if refuse:
            raise runtime.RuntimeRefused("TEST substituted binary")

    def popen(*args, **kwargs):
        assert kwargs["executable"] == runtime.LLAMA_EXECUTABLE
        events.append("exec")
        return object()

    monkeypatch.setattr(mio_supervisor, "verify_runtime_binary", verify)
    monkeypatch.setattr(mio_supervisor.subprocess, "Popen", popen)
    process = mio_supervisor.ServingProcess(record, root=Path("/"))
    if refuse:
        with pytest.raises(runtime.RuntimeRefused):
            process.start()
    else:
        process.start()
    assert events == ["verify", *([] if refuse else ["exec"]), ("close", 99)]
