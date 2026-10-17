"""Isolated file-layout experiment, never a live systemd writer.

No caller-selected destination, unit, payload, reload or service operation.
Only a newly created private temporary tree is changed. Selection in snapshot
is a model of documented load precedence, NOT an observed systemd property.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "runtime" / "src"))

from azazel_nexus_runtime.hardening import PROFILES, render_unit  # noqa: E402

PAIR = ("azazel-auditd.service", "azazel-commissiond.service")
CONTROLLER = "azazel-activated.service"
PERSISTENT = "etc/systemd/system"
OVERLAY = "run/systemd/system.control"
VENDOR = "usr/lib/systemd/system"
HIGHER = "etc/systemd/system.control"
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class FixtureRefused(RuntimeError):
    """Prototype input/layout changed; no successful fence claim is possible."""


class MaskOverlayFixture:
    """Fresh scratch only. This is not a protected production transaction.

    Tests may modify root to inject conflicts. Operations compare the complete
    fixture tree, not an incomplete glob of unit files. No host directory is
    inspected and symlink masks are never opened. Same-user hostile concurrent
    mutation and power-loss durability are not established by this prototype.
    """

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="nexus-mask-layout-"))
        try:
            self._fd = os.open(self.root, _FLAGS)
        except BaseException:
            self.root.rmdir()  # Still empty; never remove a pre-existing tree.
            raise
        self._identity = os.fstat(self._fd)
        self._base = {}
        self._owned = {}
        self._written = {}
        self._phase = "masked"
        self._closed = False
        self._payloads = {
            profile.unit: render_unit(profile).encode()
            for profile in PROFILES if profile.unit in (*PAIR, CONTROLLER)
        }
        try:
            self._populate()
        except BaseException:
            self.close()
            raise

    def _populate(self):
        if set(self._payloads) != {*PAIR, CONTROLLER}:
            raise FixtureRefused("fixture declaration set incomplete")
        for directory in (PERSISTENT, OVERLAY, VENDOR, HIGHER):
            path = Path(directory)
            for component in reversed((path, *path.parents)):
                if str(component) == ".":
                    continue
                (self.root / component).mkdir(mode=0o700, exist_ok=True)
                self._base[str(component)] = ("directory", None)
        for name, raw in self._payloads.items():
            path = f"{VENDOR}/{name}"
            (self.root / path).write_bytes(raw)
            (self.root / path).chmod(0o600)
            self._base[path] = ("file", raw)
        for name in PAIR:
            path = f"{PERSISTENT}/{name}"
            (self.root / path).symlink_to("/dev/null")
            self._base[path] = ("mask", "/dev/null")
        self.snapshot()

    def _check_root(self):
        if self._closed:
            raise FixtureRefused("fixture closed")
        info = self.root.lstat()
        if (info.st_dev, info.st_ino) != (
            self._identity.st_dev, self._identity.st_ino
        ) or not stat.S_ISDIR(info.st_mode):
            raise FixtureRefused("fixture root identity changed")

    def _directory(self, path):
        self._check_root()
        fd = os.dup(self._fd)
        try:
            for component in path.split("/"):
                child = os.open(component, _FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _verify(self, *, recovery=False):
        self._check_root()
        root_info = os.fstat(self._fd)
        if root_info.st_uid != os.getuid() or root_info.st_mode & 0o077:
            raise FixtureRefused("fixture root is not private")
        expected = dict(self._base)
        expected.update({f"{OVERLAY}/{name}": ("file", self._written[name]
                                               if recovery else self._payloads[name])
                         for name in self._owned})
        seen = set()

        def walk(fd, prefix):
            for name in os.listdir(fd):
                path = f"{prefix}/{name}" if prefix else name
                if path not in expected:
                    raise FixtureRefused("unexpected fixture entry")
                seen.add(path)
                kind, value = expected[path]
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if info.st_uid != os.getuid():
                    raise FixtureRefused("fixture ownership changed")
                if kind == "mask":
                    if not stat.S_ISLNK(info.st_mode) or os.readlink(name, dir_fd=fd) != value:
                        raise FixtureRefused("persistent mask changed")
                    continue
                if info.st_mode & 0o022:
                    raise FixtureRefused("fixture permissions changed")
                if kind == "directory":
                    child = os.open(name, _FLAGS, dir_fd=fd)
                    try:
                        walk(child, path)
                    finally:
                        os.close(child)
                else:
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                    dir_fd=fd)
                    try:
                        held = os.fstat(child)
                        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                                or held.st_size != len(value)
                                or os.read(child, len(value) + 1) != value):
                            raise FixtureRefused("fixture bytes or file type changed")
                        if prefix == OVERLAY and (held.st_dev, held.st_ino) != self._owned[name]:
                            raise FixtureRefused("candidate identity changed")
                    finally:
                        os.close(child)

        try:
            walk(self._fd, "")
            missing = set(expected) - seen
            allowed_missing = {f"{OVERLAY}/{name}" for name in self._owned} if recovery else set()
            if missing - allowed_missing:
                raise FixtureRefused("fixture entry missing")
        except OSError:
            raise FixtureRefused("fixture traversal refused") from None

    def snapshot(self):
        self._verify()
        return {
            "schema": "azazel-nexus/mask-overlay-fixture/v1",
            "evidence_kind": "file-layout-model-not-systemd-runtime",
            "phase": self._phase,
            "persistent_mask_targets": {name: "/dev/null" for name in PAIR},
            "candidate_sha256": {
                name: hashlib.sha256(self._payloads[name]).hexdigest()
                for name in self._owned
            },
            "production_ready": False,
        }

    def grant(self):
        self._verify()
        if self._phase != "masked" or self._owned:
            raise FixtureRefused("candidate already present")
        directory = self._directory(OVERLAY)
        try:
            for name in PAIR:
                raw = self._payloads[name]
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
                try:
                    info = os.fstat(fd)
                    self._owned[name] = (info.st_dev, info.st_ino)
                    self._written[name] = b""
                    view = memoryview(raw)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise FixtureRefused("candidate write incomplete")
                        self._written[name] += bytes(view[:written])
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(directory)
            self._phase = "candidate"
            return self.snapshot()
        except BaseException as error:
            # No success/atomicity claim after partial publication. Preserve
            # the scratch evidence for inspection until context cleanup.
            self._phase = "incomplete"
            if not isinstance(error, Exception):
                raise
            raise FixtureRefused("candidate publication incomplete") from None
        finally:
            os.close(directory)

    def withdraw(self):
        self._verify()
        if self._phase != "candidate":
            raise FixtureRefused("no complete candidate to withdraw")
        directory = self._directory(OVERLAY)
        try:
            for name in PAIR:
                info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (info.st_dev, info.st_ino) != self._owned[name]:
                    raise FixtureRefused("candidate identity changed")
                os.unlink(name, dir_fd=directory)
                del self._owned[name]
                del self._written[name]
            os.fsync(directory)
            self._phase = "masked"
            return self.snapshot()
        except BaseException as error:
            self._phase = "incomplete"
            if not isinstance(error, Exception):
                raise
            raise FixtureRefused("candidate withdrawal incomplete") from None
        finally:
            os.close(directory)

    def recover(self):
        """Narrow this owned fixture; never reconstruct ownership from contents.

        Exact identity and acknowledged written bytes must still agree. Missing
        owned files need no deletion, but foreign/modified entries refuse before
        any deletion. This is same-process recovery only: ownership is not durable
        across process death, and this cannot prove service inactivity/reload.
        """
        self._verify(recovery=True)
        directory = self._directory(OVERLAY)
        try:
            for name in tuple(self._owned):
                try:
                    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if (info.st_dev, info.st_ino) != self._owned[name]:
                        raise FixtureRefused("recovery candidate identity changed")
                    os.unlink(name, dir_fd=directory)
                del self._owned[name]
                del self._written[name]
            os.fsync(directory)
            self._phase = "masked"
            return self.snapshot()
        except BaseException as error:
            self._phase = "incomplete"
            if not isinstance(error, Exception):
                raise
            raise FixtureRefused("fixture recovery incomplete") from None
        finally:
            os.close(directory)

    def close(self):
        if not self._closed:
            self._check_root()
            shutil.rmtree(self.root)
            os.close(self._fd)
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-offline", action="store_true",
                        help="also inspect the fresh tree with systemd-analyze; never start/reload")
    args = parser.parse_args()
    inspections = []
    version = None
    if args.verify_offline:
        version = subprocess.run(
            ["/usr/bin/systemd-analyze", "--version"],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout.splitlines()[0]

    def inspect(fixture):
        if not args.verify_offline:
            return
        for unit in PAIR:
            result = subprocess.run(
                ["/usr/bin/systemd-analyze", f"--root={fixture.root}",
                 "--generators=no", "--man=no", "--recursive-errors=yes",
                 "verify", unit],
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "SYSTEMD_LOG_LEVEL": "debug"},
                capture_output=True, text=True, timeout=15, check=False,
            )
            inspections.append({
                "phase": fixture.snapshot()["phase"], "unit": unit,
                "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr,
            })

    with MaskOverlayFixture() as fixture:
        states = [fixture.snapshot()]
        inspect(fixture)
        states.append(fixture.grant())
        inspect(fixture)
        states.append(fixture.withdraw())
        inspect(fixture)
    print(json.dumps({"states": states, "scratch_removed": True,
                      "offline_inspections": inspections, "analyzer_version": version,
                      "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
