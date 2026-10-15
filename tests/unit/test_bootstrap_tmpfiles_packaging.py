"""Packaging contract for the bootstrap systemd control directory."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGING = REPO_ROOT / "packaging"
TMPFILES_RULE = PACKAGING / "tmpfiles.d" / "azazel-nexus-bootstrap.conf"
EXPECTED_RULE = b"d /run/systemd/system.control :0755 :root :root - -\n"
_ENTRYPOINTS = (
    "az-activated", "az-commissiond", "az-auditd", "az-watchdog",
    "az-edge-probed", "az-model-fetchd", "az-mio-locald", "az-mio-remoted",
)


def _installer_python() -> str:
    if sys.version_info >= (3, 11):
        return sys.executable
    for name in ("python3.14", "python3.13", "python3.12", "python3.11"):
        candidate = shutil.which(name)
        if candidate:
            return candidate
    pytest.skip("the installer requires Python 3.11 or newer")


def _copy_installer_tree(tmp_path: Path) -> Path:
    """Copy real installer inputs; replace only wrapper publication."""
    root = tmp_path / "installer-tree"
    shutil.copytree(PACKAGING, root / "packaging")
    (root / "tools").mkdir()
    for name in ("install_profile_fields.py", "stage_runtime_entrypoints.py"):
        shutil.copy2(REPO_ROOT / "tools" / name, root / "tools" / name)
    shutil.copytree(REPO_ROOT / "src", root / "src")
    shutil.copytree(REPO_ROOT / "runtime" / "src", root / "runtime" / "src")
    fake_stager = root / "tools" / "stage_runtime_entrypoints.py"
    fake_stager.write_text(
        "import os\n"
        "from pathlib import Path\n"
        "dest = Path(os.environ['DESTDIR']) / 'usr/libexec/azazel'\n"
        "dest.mkdir(parents=True, exist_ok=True)\n"
        f"for name in {_ENTRYPOINTS!r}:\n"
        "    target = dest / name\n"
        "    target.write_text('#!/bin/sh\\nexit 0\\n', encoding='ascii')\n"
        "    target.chmod(0o755)\n",
        encoding="utf-8",
    )
    return root


def test_bootstrap_tmpfiles_rule_is_exact_and_does_not_clean_other_paths():
    raw = TMPFILES_RULE.read_bytes()

    directives = [line.strip() for line in raw.splitlines()
                  if line.strip() and not line.lstrip().startswith(b"#")]
    assert directives == [
        EXPECTED_RULE.strip(),
        b"d /run/azazel-nexus-bootstrap :0700 :root :root - -",
    ]


def test_installer_respects_tmpfiles_override_precedence_without_starting_services():
    script = (PACKAGING / "install.sh").read_text()
    call = "systemd-tmpfiles --create azazel-nexus-bootstrap.conf"
    assert script.count(call) == 1
    assert script.index("systemctl mask azazel-mio-remoted.service") < script.index(call)
    assert script.index(call) < script.index("systemctl enable azazel-activated.service")
    assert "systemd-tmpfiles --create /" not in script


def test_staged_install_copies_rule_without_running_tmpfiles(tmp_path):
    if not Path("/etc/os-release").is_file():
        pytest.skip("installer requires the host's os-release install profile")

    installer_root = _copy_installer_tree(tmp_path)
    destdir = tmp_path / "stage"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "systemd-tmpfiles-called"
    fake_tmpfiles = fake_bin / "systemd-tmpfiles"
    fake_tmpfiles.write_text(
        "#!/bin/sh\nprintf called > \"$TMPFILES_MARKER\"\n",
        encoding="utf-8",
    )
    fake_tmpfiles.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "DESTDIR": str(destdir),
            "PATH": f"{fake_bin}:/usr/sbin:/usr/bin:/bin:/sbin",
            "PYTHON": _installer_python(),
            "TMPFILES_MARKER": str(marker),
        }
    )
    result = subprocess.run(
        [
            "sh",
            str(installer_root / "packaging" / "install.sh"),
            "--without-accounts",
            "--without-service-manager",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    installed_rule = destdir / "usr/lib/tmpfiles.d/azazel-nexus-bootstrap.conf"
    assert installed_rule.read_bytes() == TMPFILES_RULE.read_bytes()
    assert not marker.exists(), "staged installation invoked systemd-tmpfiles"
