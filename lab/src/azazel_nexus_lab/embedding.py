"""Non-production LocalServer adapter. No production admission state is changed.

LocalServer's HTTP, readiness, retrieval and stop implementation is reused.
Only construction/admission and the process launcher are lab-specific: production
requires an HG campaign, which this explicitly labelled demonstration cannot supply.
"""
from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from azazel_nexus_runtime.mio_embedding import EmbeddingRetriever

from azazel_nexus.model_runtime import (
    LLAMA_EXECUTABLE,
    LLAMA_RUNTIME_ID,
    RUNTIMES,
    llama_server_record,
    open_verified_runtime,
    pinned_runtime_digest,
)

from .composition import LabServer

DIGEST = "950f4a8e5e19477a6d3c26d2f162233c20002c601f75e4b002e3239997821167"
# Conservative demonstration estimate, not measured HG evidence; includes working buffers.
MODEL_RSS_MIB = 1024
MODEL_BYTES = 634553760


def available_mib():
    rows = Path("/proc/meminfo").read_text().splitlines()
    try:
        return int(next(row.split()[1] for row in rows if row.startswith("MemAvailable:"))) // 1024
    except StopIteration:
        raise ValueError("MemAvailable unavailable") from None


@contextmanager
def retriever(root, model):
    if available_mib() < MODEL_RSS_MIB + 256:
        raise ValueError("MemAvailable below model RSS estimate + 256 MiB")
    if model is None:
        raise ValueError("--model required for embedding")
    directory = root / "embedding"
    if directory.is_symlink():
        raise ValueError("symlink embedding directory refused")
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    binary = replace(RUNTIMES[LLAMA_RUNTIME_ID], digest=pinned_runtime_digest())
    binary_fd = open_verified_runtime(binary, Path(LLAMA_EXECUTABLE))
    model_fd = None
    server = None
    try:
        # Copy into private lab storage while hashing, then hold the read-only inode.
        staged = directory / "bge-m3.gguf"
        temporary_fd, temporary_name = tempfile.mkstemp(prefix="model.staging-", dir=directory)
        os.close(temporary_fd)
        temporary = Path(temporary_name)
        digest = hashlib.sha256()
        source_fd = None
        try:
            source_fd = os.open(model, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(source_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != MODEL_BYTES:
                raise ValueError("bge-m3 size mismatch")
            with os.fdopen(os.dup(source_fd), "rb") as source, temporary.open("wb") as target:
                remaining = MODEL_BYTES + 1
                while remaining and (chunk := source.read(min(remaining, 8 * 1024 * 1024))):
                    remaining -= len(chunk)
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            if digest.hexdigest() != DIGEST:
                raise ValueError("bge-m3 sha256 mismatch")
            temporary.chmod(0o400)
            temporary.replace(staged)
        finally:
            if source_fd is not None:
                os.close(source_fd)
            temporary.unlink(missing_ok=True)
        model_fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW)
        sock = directory / "llama.sock"
        record = llama_server_record(binary, model_path=staged,
                                     socket_path=sock, embedding=True)
        server = LabServer(record, root=root, socket_path=sock, descriptors=(binary_fd, model_fd))
        yield EmbeddingRetriever(server, model_digest="sha256:" + DIGEST,
                                 cache_dir=directory / "cache"), server
    finally:
        if server is not None:
            server.stop()
        os.close(binary_fd)
        if model_fd is not None:
            os.close(model_fd)
