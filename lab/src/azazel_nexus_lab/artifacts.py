"""Ephemeral test signing; production verifiers reject the lab envelope."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

from nacl.signing import SigningKey

BANNER = ("LAB — 実機の根拠ではありません／受け入れではありません／本番の起動ではありません\n"
          "LAB — NOT hardware evidence / NOT admission / NOT production activation")
LAB_DOMAIN = b"azazel-nexus-lab/v1\0"
SCHEMA = "azazel-nexus-lab/transcript/1"


def canonical(document):
    return json.dumps(document, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode()


def output(**fields):
    return {**fields, "schema": SCHEMA, "lab": True, "not_hardware_evidence": True}


def create_key(directory: Path, filename="ephemeral.key") -> SigningKey:
    directory.mkdir(mode=0o700, exist_ok=True)
    key = SigningKey.generate()
    fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(bytes(key))
        stream.flush()
        os.fsync(stream.fileno())
    return key


def shred_keys(directory: Path):
    """Overwrite, sync, unlink. SSD/COW storage cannot promise physical erasure."""
    if not directory.exists():
        return
    for path in directory.iterdir():
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r+b") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe key file")
            for material in (os.urandom(info.st_size), bytes(info.st_size)):
                stream.seek(0)
                stream.write(material)
                stream.flush()
                os.fsync(stream.fileno())
        path.unlink()
    directory.rmdir()


def envelope(payload: bytes, key: SigningKey, kind: str) -> bytes:
    document = output(kind=kind, payload_base64=base64.b64encode(payload).decode(),
                      payload_sha256=hashlib.sha256(payload).hexdigest())
    raw = canonical(document)
    return key.sign(LAB_DOMAIN + raw).signature + raw


def resign_fixture(source: Path, key: SigningKey) -> bytes:
    """Reuse the pinned producer fixture builder's emitted tables and manifest.

    The native payload is for the real Lite importer inside the disposable
    root only. Its public key is never pinned on the production host.
    """
    with tarfile.open(source, "r:gz") as archive:
        members = {entry.name: archive.extractfile(entry).read()
                   for entry in archive if entry.isfile()}
    manifest = members["manifest.json"]
    members["manifest.sig"] = b"lab:" + key.sign(manifest).signature.hex().encode() + b"\n"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in members.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    return stream.getvalue()
