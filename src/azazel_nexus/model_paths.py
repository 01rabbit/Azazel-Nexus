"""Fixed local model paths and bounded commissioning trust decoding; no runtime dependency."""

import json
import os
import re
import stat
from pathlib import Path


def models_root() -> Path:
    return Path(os.environ.get("AZAZEL_ROOT", "/")) / "var/lib/azazel/models"


def fetch_ready_dir() -> Path:
    return Path(os.environ.get("AZAZEL_ROOT", "/")) / "var/lib/azazel/fetch/ready"


def bounded_read(path: Path, limit: int) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular file required")
        raw = stream.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("size")
    return raw


def load_model_trust(path: Path, *, registry: bool = False):
    def unique(pairs):
        doc = {}
        for key, value in pairs:
            if key in doc:
                raise ValueError("duplicate")
            doc[key] = value
        return doc

    doc = json.loads(bounded_read(path, 65536), object_pairs_hook=unique)
    digest = doc["commissioning_digest"]
    if type(digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("digest")

    def keys(name):
        values = doc[name]
        if type(values) is not dict or not 0 < len(values) <= 64:
            raise ValueError("keys")
        if not all(isinstance(k, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", k)
                   and isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{64}", v)
                   for k, v in values.items()):
            raise ValueError("keys")
        return {k: bytes.fromhex(v) for k, v in values.items()}

    return keys("catalog_keys"), digest, keys("registry_keys") if registry else {}
