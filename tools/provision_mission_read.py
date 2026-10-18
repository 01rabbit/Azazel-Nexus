#!/usr/bin/env python3
"""Provision the fixed Mission Pack reader without creating unencrypted state."""
from __future__ import annotations

import argparse
import grp
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from azazel_nexus.hil_preflight import luks_backed


def provision(root: Path, *, accounts: bool = True, staging: bool = False,
              encrypted=luks_backed) -> None:
    gid = grp.getgrnam("azmission-read").gr_gid if accounts else None

    def checked(path: Path, directory: bool) -> None:
        info = path.lstat()
        kind = stat.S_ISDIR if directory else stat.S_ISREG
        if (not kind(info.st_mode) or info.st_mode & 0o022
                or accounts and info.st_uid != 0):
            raise ValueError("Mission Pack reader requires root-owned non-writable installation paths")

    def access(path: Path, directory: bool, *, exact: bool = False) -> None:
        checked(path, directory)
        info = path.lstat()
        # Keep world-traversable parents and their existing groups untouched.
        if directory and not exact and info.st_mode & 0o001:
            return
        if gid is not None:
            os.chown(path, -1, gid, follow_symlinks=False)
        mode = (0o2750 if directory else 0o640) if exact else (
            stat.S_IMODE(info.st_mode) | (0o010 if directory else 0o040))
        path.chmod(mode)

    def parents(path: Path, *, create: bool = False) -> None:
        for parent in reversed(path.parents):
            if parent == root or root not in parent.parents:
                continue
            if create:
                parent.mkdir(mode=0o711, exist_ok=True)
            access(parent, True)

    store = root / "data/azazel/mission-packs"
    existing = store
    while not existing.exists():
        existing = existing.parent
    if staging or encrypted(existing):
        parents(store, create=True)
        for directory in (store, store / "generations"):
            directory.mkdir(mode=0o2750, exist_ok=True)
            access(directory, True, exact=True)
        # Upgrade retained published selections, never hidden interrupted stages
        # or the writer's audit/lock files. Symlinks and unsafe writers refuse.
        for generation in (store / "generations").iterdir():
            if not generation.name.isdigit():
                continue
            access(generation, True, exact=True)
            for path in generation.rglob("*"):
                access(path, path.is_dir(), exact=True)
        if (store / "current").exists() or (store / "current").is_symlink():
            access(store / "current", False, exact=True)
    else:
        print("MISSION PACK STORE NOT PROVISIONED: mount commissioned LUKS storage and rerun installer.")

    config = root / "etc/azazel/mission-pack.json"
    if not config.exists() and not config.is_symlink():
        return  # The installer does not invent commissioned trust/inventory.
    parents(config)
    checked(config, False)
    doc = json.loads(config.read_bytes())
    if doc["schema"] != "azazel-nexus/mission-pack-config/1":
        raise ValueError("unknown commissioned Mission Pack config")
    for asset in doc["assets"]:
        if asset["kind"] != "reasoning_playbook":
            continue
        absolute = Path(asset["path"])
        if (not absolute.is_absolute() or ".." in absolute.parts
                or any(absolute.is_relative_to(base) for base in (
                    "/var/lib/azazel/mio", "/var/lib/azazel/run", "/run", "/tmp",
                    "/var/tmp", "/home", "/root"))):
            raise ValueError("playbook must live outside locald writable/private paths")
        path = root / absolute.relative_to("/")
        parents(path)
        access(path, False)
    access(config, False, exact=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--without-accounts", action="store_true")
    args = parser.parse_args()
    destination = os.environ.get("DESTDIR")
    provision(Path(destination or "/"), accounts=not args.without_accounts,
              staging=bool(destination))


if __name__ == "__main__":
    main()
