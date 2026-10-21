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
    "az-edge-probed", "az-edge-intaked", "az-incident-explaind", "az-model-fetchd", "az-mio-locald", "az-mio-remoted",
    "az-mio-entryd", "az-knowledge-lited", "az-mio-identity",
    "az-decoy-nsd", "az-decoy-netd", "az-decoyd",
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
    for name in ("install_profile_fields.py", "stage_runtime_entrypoints.py",
                 "provision_mission_read.py", "purge_mio_profile_copies.py"):
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
        b"d /run/azazel-mio-identity 0750 root azmio - -",
        b"d /etc/azazel/mio-profile 0700 root root - -",
        b"d /run/azazel-activation 0755 root root - -",
        # #196 §13: the decoy must be able to traverse it (not 0750 by the
        # namespace unit's UMask=0027).
        b"d /run/netns 0755 root root - -",
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
    profile = destdir / "etc/azazel/mio-profile"
    assert profile.is_dir() and profile.stat().st_mode & 0o777 == 0o700
    assert list(profile.iterdir()) == []


def test_staged_install_stops_when_the_legacy_copy_purge_refuses(tmp_path):
    """A refused #244 purge exits non-zero before any unit file is written."""
    if not Path("/etc/os-release").is_file():
        pytest.skip("installer requires the host's os-release install profile")

    installer_root = _copy_installer_tree(tmp_path)
    destdir = tmp_path / "stage"
    profile = destdir / "etc/azazel/mio-profile"
    profile.mkdir(parents=True, mode=0o700)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b'{"board_serial":"SYNTHETIC-SERIAL-0000"}')
    (profile / "commissioning-proposal.json").symlink_to(outside)
    (profile / "commissioning-proposal.expected.json").write_bytes(b"synthetic")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_tmpfiles = fake_bin / "systemd-tmpfiles"
    fake_tmpfiles.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_tmpfiles.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "DESTDIR": str(destdir),
        "PATH": f"{fake_bin}:/usr/sbin:/usr/bin:/bin:/sbin",
        "PYTHON": _installer_python(),
    })
    result = subprocess.run(
        ["sh", str(installer_root / "packaging" / "install.sh"),
         "--without-accounts", "--without-service-manager"],
        env=env, capture_output=True, text=True, timeout=60,
    )

    assert result.returncode != 0
    assert "refusing to remove legacy M.I.O. proposal copies" in result.stderr
    assert "SYNTHETIC" not in result.stdout + result.stderr
    # Nothing was removed and the symlink target was never touched.
    assert outside.read_bytes() == b'{"board_serial":"SYNTHETIC-SERIAL-0000"}'
    assert (profile / "commissioning-proposal.json").is_symlink()
    assert (profile / "commissioning-proposal.expected.json").read_bytes() == b"synthetic"
    # The install stopped before units and the tmpfiles rule were written.
    assert not list(destdir.rglob("azazel-mio-entryd.service"))
    assert not (destdir / "usr/lib/tmpfiles.d/azazel-nexus-bootstrap.conf").exists()
