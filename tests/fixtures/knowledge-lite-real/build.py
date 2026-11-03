"""Build synthetic lab data with the pinned, unmodified Knowledge CLI.

Run with a Python containing Knowledge's core dependencies and pass a clean
Knowledge checkout. Only the archive, public anchor and provenance are retained.
The generated signing and alias keys live only in a temporary directory.

The output is generated with Knowledge main's build-lite CLI and crosses the
LiteImport/auditd boundaries in tests. It is not live upstream producer,
authenticity, or full-node interoperability proof. The checkout's export
policy must match the checked-in lite-export-policy.yaml copy.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile

from nacl.signing import SigningKey

SHA = "09d234cde0ceb447a3ebc7e9704eef4758ac4a4d"
OUT = Path(__file__).resolve().parent


def _fail(message: str) -> None:
    raise SystemExit(f"build.py: {message}")


def _run(cmd: list[str], env: dict[str, str], step: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        _fail(f"{step} failed with exit code {result.returncode}\n--- stderr ---\n{result.stderr}"
              f"--- stdout ---\n{result.stdout}")
    return result


def main() -> None:
    if len(sys.argv) < 2:
        _fail("usage: build.py <knowledge-checkout> [evidence-dir]")
    source = Path(sys.argv[1]).resolve()
    head = _run(["git", "rev-parse", "HEAD"], os.environ.copy(), "git rev-parse HEAD", cwd=source)
    if head.stdout.strip() != SHA:
        _fail(f"checkout HEAD is {head.stdout.strip()!r}, expected {SHA}")
    status = _run(["git", "status", "--porcelain"], os.environ.copy(), "git status", cwd=source)
    if status.stdout.strip():
        _fail(f"checkout is dirty:\n{status.stdout}")
    policy = source / "config/lite-export-policy.yaml"
    checked_in = OUT / "lite-export-policy.yaml"
    if policy.read_bytes() != checked_in.read_bytes():
        _fail(f"{policy} differs from the checked-in copy {checked_in}")
    env = {**os.environ, "PYTHONPATH": str(source / "src"), "PYTHONDONTWRITEBYTECODE": "1"}
    key = SigningKey.generate()
    public = key.verify_key.encode().hex()
    with tempfile.TemporaryDirectory(prefix="knowledge-lab-build-") as directory:
        work = Path(directory)
        work.chmod(0o700)
        signing = work / "sign.hex"
        signing.write_text(key.encode().hex())
        signing.chmod(0o600)
        alias = work / "alias.hex"
        alias.write_text(os.urandom(16).hex())
        alias.chmod(0o600)
        db = work / "intel.db"
        _run([sys.executable, "-B", "-c", '''
import sqlite3, sys
from azazel_knowledge.db.repository import apply_migrations
with sqlite3.connect(sys.argv[1]) as conn:
    apply_migrations(conn, "intel")
    conn.execute("INSERT INTO attack_technique (technique_id, name, tactics, attack_version) VALUES (?, ?, ?, ?)",
                 ("T1110", "Brute Force", '["credential-access"]', "lab-v1"))
''', str(db)], env, "synthetic intel database setup")
        archive = OUT / "lite.tar.gz"
        archive.unlink(missing_ok=True)
        args = ["build-lite", "--source-db", str(db), "--out", str(archive),
                "--version", "5", "--profile", "knowledge-lite-16g",
                "--export-policy", str(source / "config/lite-export-policy.yaml"),
                "--alias-key-file", str(alias), "--alias-scope", "nexus-process-lab",
                "--as-of", "2026-10-18T00:00:00Z", "--intel-generation", "5",
                "--stats-generation", "1", "--attack-version", "lab-v1",
                "--config-hash", "nexus-process-lab", "--security-epoch", "1",
                "--sign-key", str(signing)]
        _run([sys.executable, "-B", str(source / "tools/bundle_build.py"), *args],
             env, "Knowledge build-lite")
    (OUT / "anchors.toml").write_text(f'threshold = 1\n[keys]\n"{public[:8]}" = "{public}"\n')
    provenance = json.dumps({
        "producer_commit": SHA, "builder": "tools/bundle_build.py build-lite",
        "export_policy_sha256": hashlib.sha256((source / "config/lite-export-policy.yaml").read_bytes()).hexdigest(),
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "bundle_version": 5, "rows": {"attack_technique": 1},
        "data": "synthetic lab only", "signer": "ephemeral lab key; private seed discarded",
    }, indent=2, sort_keys=True) + "\n"
    (OUT / "provenance.json").write_text(provenance)
    (OUT / "provenance.sig").write_text(key.sign(provenance.encode()).signature.hex() + "\n")
    if len(sys.argv) > 2:
        evidence = Path(sys.argv[2])
        evidence.mkdir(parents=True, exist_ok=False)
        with tarfile.open(archive) as bundle:
            for name in ("manifest.json", "manifest.sig"):
                (evidence / name).write_bytes(bundle.extractfile(name).read())
        (evidence / "build-evidence.json").write_text(json.dumps({
            "source": str(source), "head": SHA, "status_porcelain": "",
            "command": [sys.executable, "-B", str(source / "tools/bundle_build.py"), *args],
            "synthetic_input": {"attack_technique": [["T1110", "Brute Force", ["credential-access"], "lab-v1"]]},
            "builder_sha256": hashlib.sha256((source / "tools/bundle_build.py").read_bytes()).hexdigest(),
            "policy_sha256": hashlib.sha256((source / "config/lite-export-policy.yaml").read_bytes()).hexdigest(),
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "private_key_retained": False, "builder_exit_code": 0,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()
