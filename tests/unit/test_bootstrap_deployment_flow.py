"""Exercise operator CLI through real publication and protected read algorithms.

Only the fixed-directory/owner boundary is redirected to ordinary private files.
No production stores, root privileges, services, keys or devices are accessed.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import io
import os
import sys

import pytest

from azazel_nexus import bootstrap_deployment_store as store
from azazel_nexus.cli import main
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from test_bootstrap_deployment_store import declaration
from test_bootstrap_deployment_interactive import FakeTerminal, interaction


@pytest.fixture
def local_store(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)

    @contextmanager
    def directory():
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    for name in ("_initialize_at", "_recover_at", "_read_at"):
        original = getattr(store, name)

        def local_owner(*args, _operation=original, **kwargs):
            return _operation(*args, **(kwargs | {"owner": os.getuid()}))

        monkeypatch.setattr(store, name, local_owner)
    return tmp_path


def test_preview_initialize_read_and_no_overwrite(local_store, monkeypatch):
    raw = encode_bootstrap_deployment(declaration())
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
    preview = io.StringIO()
    assert main(["bootstrap-deployment-preview"], out=preview) == 0
    assert hashlib.sha256(raw).hexdigest() in preview.getvalue()
    assert list(local_store.iterdir()) == []
    monkeypatch.setattr(sys, "stdin", FakeTerminal(interaction(raw, b"INITIALIZE")))
    assert main(["bootstrap-deployment-initialize"], out=io.StringIO()) == 0
    assert store.load_bootstrap_deployment() == declaration()
    before = (local_store / "deployment.json").stat().st_ino
    monkeypatch.setattr(sys, "stdin", FakeTerminal(interaction(raw, b"INITIALIZE")))
    assert main(["bootstrap-deployment-initialize"], out=io.StringIO()) == 1
    assert (local_store / "deployment.json").stat().st_ino == before


def test_interrupted_publication_requires_explicit_recovery(local_store, monkeypatch):
    raw = encode_bootstrap_deployment(declaration())
    original = store.os.unlink

    def fail(*args, **kwargs):
        raise OSError("injected interruption")

    monkeypatch.setattr(store.os, "unlink", fail)
    monkeypatch.setattr(sys, "stdin", FakeTerminal(interaction(raw, b"INITIALIZE")))
    assert main(["bootstrap-deployment-initialize"], out=io.StringIO()) == 1
    with pytest.raises(store.ApprovalRefused):
        store.load_bootstrap_deployment()
    monkeypatch.setattr(store.os, "unlink", original)
    monkeypatch.setattr(sys, "stdin", FakeTerminal(interaction(raw, b"RECOVER")))
    assert main(["bootstrap-deployment-recover"], out=io.StringIO()) == 0
    assert store.load_bootstrap_deployment() == declaration()
