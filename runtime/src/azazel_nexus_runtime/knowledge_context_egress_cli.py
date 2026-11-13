"""`az-knowledge-context-egress`: the one writer of the broker's egress allowance (U49).

Root only, fixed paths, no argument beyond the verb. The unit is always
re-rendered by `hardening.render_unit` from the allowance derived from the
verified commissioning bundle; nothing is hand-edited and nothing else is
configurable.

* `show`   what would be rendered (read-only).
* `check`  installed unit versus derivation (read-only); exit 0 when equal.
* `apply`  write the unit with the derived `IPAddressAllow=`.
* `remove` write the default-deny unit back.

`apply` and `remove` require, before touching the unit: the broker's grant
marker is absent, the broker is inactive or failed with no job, and its cgroup
is confirmed empty. They write atomically (no links followed, root:root 0644),
ask the manager to reload, then run the normal `generation-publish` (the
operator's interactive confirmation), after which the usual `request` and
`install` re-approve the new generation. Fixed labels only.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import stat
import sys
from pathlib import Path

from .activation_markers import contextd_marker_present
from .activation_unit_files import (
    UNIT_DIRECTORY,
    UnitFilesRefused,
    derived_egress_allowance,
    rendered_unit,
    require_governed_unit_content,
    require_no_unit_overrides,
)
from .activation_withdraw import contextd_is_quiet
from .units import CONTEXTD_UNIT

__all__ = ["egress_summary_lines", "main", "run_apply", "run_check", "run_remove", "run_show"]

_ROOT = Path("/")  # private test seam: where the unit directory and marker live
_OWNER = 0


class Refused(Exception):
    pass


def _is_root() -> bool:
    return os.geteuid() == 0


@contextlib.contextmanager
def _session():
    """The broker's stop authority (read verbs only are used) and the manager's reload."""
    from .systemd_bus import SystemdBusSession
    from .units import ContextdStopAuthority

    with SystemdBusSession.connect() as session:
        yield ContextdStopAuthority.from_session(session, cgroup_caller="operator"), session.reload


def _unit_dir() -> Path:
    return _ROOT / UNIT_DIRECTORY.lstrip("/")


def _installed() -> bytes | None:
    path = _unit_dir() / CONTEXTD_UNIT
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1 << 20:
            raise Refused("installed unit is not a regular file")
        return os.read(fd, info.st_size + 1)
    finally:
        os.close(fd)


def _state(allowance) -> tuple[str, list[str]]:
    """`(label, notes)`: match | default-deny-missing | mismatch | absent-ok."""
    try:
        data = _installed()
    except (Refused, OSError):
        return "mismatch", ["installed unit unreadable"]
    if data is None:
        return "mismatch", ["installed unit missing"]
    try:
        require_governed_unit_content(CONTEXTD_UNIT, data)
    except UnitFilesRefused:
        return "mismatch", ["installed unit refused by the activation checks"]
    has_allow = b"\nIPAddressAllow=" in data
    if allowance is None:
        return ("mismatch", ["installed unit carries an Allow but nothing is derived"]) \
            if has_allow else ("match", ["default deny; nothing to allow"])
    if has_allow:
        return "match", ["installed Allow equals the derivation"]
    return "default-deny-missing", ["installed unit is default deny; apply to add the Allow"]


def egress_summary_lines() -> list[str]:
    """Lines for `generation-publish`'s confirmation screen."""
    allowance = derived_egress_allowance()
    if allowance is None:
        return ["Knowledge Context egress allowance: none derived (default deny)"]
    label, _ = _state(allowance)
    return [f"Knowledge Context egress allowance: peer {allowance.peer_id} host "
            f"{allowance.host}:{allowance.port} address {allowance.address} "
            f"registry v{allowance.registry_version} pin {allowance.certificate_pin[:19]}.. "
            f"digest {allowance.digest}; installed: {label}"]


def _describe(allowance, out) -> None:
    if allowance is None:
        print("derived allowance: none (no verified bundle or no usable address); "
              "the unit renders default deny", file=out)
        return
    print(f"peer: {allowance.peer_id}", file=out)
    print(f"host: {allowance.host}  port: {allowance.port}", file=out)
    print(f"pin: {allowance.certificate_pin}", file=out)
    print(f"registry version: {allowance.registry_version}", file=out)
    print(f"line: {allowance.line}", file=out)
    print(f"allowance digest: {allowance.digest}", file=out)
    print("limit: every port and protocol at this address is reachable; the filter "
          "needs cgroup-BPF support", file=out)


def run_show(*, out) -> int:
    _describe(derived_egress_allowance(), out)
    return 0


def run_check(*, out) -> int:
    allowance = derived_egress_allowance()
    label, notes = _state(allowance)
    print(f"{label}: {'; '.join(notes)}", file=out)
    return 0 if label == "match" else 1


def _preconditions(authority, root: Path) -> None:
    if contextd_marker_present(root):
        raise Refused("the broker's grant is not withdrawn")
    if not contextd_is_quiet(authority):
        raise Refused("the broker is not stopped with an empty cgroup")


def _write_atomically(data: bytes) -> None:
    directory = _unit_dir()
    require_no_unit_overrides((CONTEXTD_UNIT,))
    dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temp = f".{CONTEXTD_UNIT}.egress.{os.getpid()}"
    try:
        info = os.fstat(dirfd)
        if info.st_uid != _OWNER or info.st_mode & 0o022:
            raise Refused("unit directory is not protected")
        try:
            current = os.lstat(CONTEXTD_UNIT, dir_fd=dirfd)
        except FileNotFoundError:
            raise Refused("the broker's unit file is not installed") from None
        if not stat.S_ISREG(current.st_mode):
            raise Refused("the broker's unit file is not a regular file")
        fd = os.open(temp, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o644, dir_fd=dirfd)
        try:
            os.fchmod(fd, 0o644)
            if os.geteuid() == 0:
                os.fchown(fd, 0, 0)
            view, written = memoryview(data), 0
            while written < len(data):
                count = os.write(fd, view[written:])
                if count <= 0:
                    raise Refused("short write")
                written += count
            os.fsync(fd)
            if os.fstat(fd).st_size != len(data):
                raise Refused("written length differs")
            os.lseek(fd, 0, os.SEEK_SET)
            back = b""
            while len(back) <= len(data):
                chunk = os.read(fd, len(data) + 1 - len(back))
                if not chunk:
                    break
                back += chunk
            if back != data:
                raise Refused("written content differs")
        finally:
            os.close(fd)
        os.rename(temp, CONTEXTD_UNIT, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        os.fsync(dirfd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp, dir_fd=dirfd)
        raise
    finally:
        os.close(dirfd)


def _change(*, want_allow: bool, out, publish) -> int:
    try:
        if not _is_root():
            raise Refused("requires root")
        with _session() as (authority, reload):
            _preconditions(authority, _ROOT)
            allowance = derived_egress_allowance()
            if want_allow and allowance is None:
                raise Refused("no verified registry peer to derive an allowance from")
            text = rendered_unit(CONTEXTD_UNIT, allowance=allowance if want_allow else None)
            _write_atomically(text.encode("ascii"))
            reload()
    except Refused as error:
        print(f"refused: {error}. Nothing changed.", file=out)
        return 1
    except Exception:  # noqa: BLE001 - labels only
        print("refused: unit change failed. Run `check`; rerun the same verb.", file=out)
        return 1
    print("unit written. Next: generation-publish below, then `az-activation request` "
          "and `install`; nothing is admitted until the operator signs.", file=out)
    return publish()


def run_apply(*, out, publish) -> int:
    return _change(want_allow=True, out=out, publish=publish)


def run_remove(*, out, publish) -> int:
    return _change(want_allow=False, out=out, publish=publish)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="az-knowledge-context-egress",
        description="Give the Knowledge Context broker its one derived egress address.")
    parser.add_argument("verb", choices=("show", "apply", "remove", "check"))
    args = parser.parse_args(argv)
    out = sys.stdout

    def publish() -> int:
        from .activation_cli import run_generation_publish

        return run_generation_publish(source=sys.stdin, out=out)

    if not _is_root():
        print("refused: requires root. Nothing changed.", file=out)
        return 1
    if args.verb == "show":
        return run_show(out=out)
    if args.verb == "check":
        return run_check(out=out)
    if args.verb == "apply":
        return run_apply(out=out, publish=publish)
    return run_remove(out=out, publish=publish)


if __name__ == "__main__":
    raise SystemExit(main())
