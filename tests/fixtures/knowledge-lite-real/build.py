"""Build synthetic lab data with the pinned, unmodified Knowledge CLI.

Run with a Python containing Knowledge's core dependencies and pass a clean
Knowledge checkout. Only the archive, public anchor and provenance are retained.
The generated signing and alias keys live only in a temporary directory.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from nacl.signing import SigningKey

SHA = "09d234cde0ceb447a3ebc7e9704eef4758ac4a4d"
OUT = Path(__file__).resolve().parent


def main() -> None:
    source = Path(sys.argv[1]).resolve()
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() == SHA
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip()
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
        subprocess.run([sys.executable, "-B", "-c", '''
import sqlite3, sys
from azazel_knowledge.db.repository import apply_migrations
with sqlite3.connect(sys.argv[1]) as conn:
    apply_migrations(conn, "intel")
    conn.execute("INSERT INTO attack_technique (technique_id, name, tactics, attack_version) VALUES (?, ?, ?, ?)",
                 ("T1110", "Brute Force", '["credential-access"]', "lab-v1"))
''', str(db)], env=env, check=True)
        archive = OUT / "lite.tar.gz"
        args = ["build-lite", "--source-db", str(db), "--out", str(archive),
                "--version", "5", "--profile", "knowledge-lite-16g",
                "--export-policy", str(source / "config/lite-export-policy.yaml"),
                "--alias-key-file", str(alias), "--alias-scope", "nexus-process-lab",
                "--as-of", "2026-10-18T00:00:00Z", "--intel-generation", "5",
                "--stats-generation", "1", "--attack-version", "lab-v1",
                "--config-hash", "nexus-process-lab", "--security-epoch", "1",
                "--sign-key", str(signing)]
        subprocess.run([sys.executable, "-B", str(source / "tools/bundle_build.py"), *args],
                       env=env, check=True, capture_output=True)
    (OUT / "anchors.toml").write_text(f'threshold = 1\n[keys]\n"{public[:8]}" = "{public}"\n')
    (OUT / "provenance.json").write_text(json.dumps({
        "producer_commit": SHA, "builder": "tools/bundle_build.py build-lite",
        "export_policy_sha256": hashlib.sha256((source / "config/lite-export-policy.yaml").read_bytes()).hexdigest(),
        "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "bundle_version": 5, "rows": {"attack_technique": 1},
        "data": "synthetic lab only", "signer": "ephemeral lab key; private seed discarded",
    }, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
