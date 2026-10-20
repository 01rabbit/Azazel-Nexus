"""An installed Edge package in a temporary root, as Edge's packager lays it out.

Shared by the activation tests (#206 P5): the `tar.gz` archive with the
`bin/azazel-edge-core` and `config/redirect_policy.yaml` members, the
manifest recording the archive digest and each component's digest, and the
extracted copies beside it, owned by the test user and not group or other
writable (the protection `edge_package.measure_extracted_components` checks).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path

from azazel_nexus.edge_package import PIN

BINARY = b"\x7fELF synthetic azazel-edge-core\n"
POLICY = b"redirect: none\n"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def archive(members: dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755 if name.startswith("bin/") else 0o644
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def write_package(root: Path, *, binary: bytes = BINARY, policy: bytes = POLICY,
                  manifest_overrides: dict | None = None) -> tuple[str, dict[str, str]]:
    """Write the package; return the archive digest and the component digests."""
    members = {"bin/azazel-edge-core": binary, "config/redirect_policy.yaml": policy}
    data = archive(members)
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o755)
    (root / PIN.artifact_name).write_bytes(data)
    components = {name: _sha(content) for name, content in members.items()}
    for name, content in members.items():
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.parent.chmod(0o755)
        if path.exists():
            path.unlink()
        path.write_bytes(content)
        path.chmod(0o755 if name.startswith("bin/") else 0o644)
    manifest = {
        "contract": PIN.manifest_contract, "package": PIN.package,
        "version": PIN.version, "architecture": PIN.architecture,
        "artifact": PIN.artifact_name, "digest": _sha(data), "signed": False,
        "health": {"contract": PIN.health_contract,
                   "command": ["bin/azazel-edge-core", "--health"]},
        "posture": {"observe_only": True, "enforcement": False},
        "components": [{"path": name, "digest": digest, "size": len(members[name])}
                       for name, digest in components.items()],
    }
    manifest.update(manifest_overrides or {})
    (root / PIN.manifest_name).write_text(json.dumps(manifest))
    return _sha(data), dict(sorted(components.items()))
