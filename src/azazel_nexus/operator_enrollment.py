"""Explicit local administrator enrollment; not an installer or signer.

Run with ``python -m azazel_nexus.operator_enrollment enroll|revoke LABEL``.
No production key is generated. The protected directory must already exist.
When the ``azmission-read`` group exists, the directory is kept
root:azmission-read 0750 and the store written root:azmission-read 0640 so
azazel-mio-locald can read public keys for admission; otherwise 0600 is kept.
"""

import argparse
import fcntl
import grp
import hashlib
import json
import os
import sys
import uuid

from .operator_store import _MAX_STORE_BYTES, _protected, _read_at, _trust_directory
from .operator_trust import ApprovalRefused, OperatorTrust
from .signature import SignatureRefused, parse_public_key


def public_key_fingerprint(public_key_hex: str) -> str:
    """SHA-256 over the raw Ed25519 public key, not an SPKI fingerprint."""
    try:
        public = parse_public_key(public_key_hex)
    except SignatureRefused as exc:
        raise ApprovalRefused("invalid operator public key") from exc
    return "sha256:" + hashlib.sha256(public).hexdigest()


def _updated(current, *, action, operator, public_key_hex, confirmation):
    expected = public_key_fingerprint(public_key_hex)
    if type(confirmation) is not str or confirmation != expected:
        raise ApprovalRefused("independent public-key fingerprint confirmation required")
    public = parse_public_key(public_key_hex)
    keys, revoked = dict(current.public_keys), set(current.revoked)
    if action == "enroll":
        if operator in keys or operator in revoked:
            raise ApprovalRefused("operator already exists; silent replacement is forbidden")
        keys[operator] = public
    elif action == "revoke":
        if keys.get(operator) != public:
            raise ApprovalRefused("revocation does not match an enrolled operator key")
        revoked.add(operator)
    else:
        raise ApprovalRefused("unsupported enrollment operation")
    return OperatorTrust(keys, frozenset(revoked))


# Mission/locald readers (azazel-mio-locald runs as azmio with this supplementary
# group) need the public keys and revocations for local model admission. The
# store holds no secrets; it stays root-owned and never group/other-writable.
READER_GROUP = "azmission-read"
TRUST_DIRECTORY = "/etc/azazel/operator-trust"


def _reader_gid():
    """Reader group id when provisioned on this host; None on dev/test hosts."""
    try:
        return grp.getgrnam(READER_GROUP).gr_gid
    except KeyError:
        return None


def _encoded(trust, *, reserve_revocations=False):
    revoked = trust.revoked | frozenset(trust.public_keys) if reserve_revocations else trust.revoked
    return (json.dumps({
        "schema": "azazel-nexus/operator-trust/v1",
        "keys": {name: key.hex() for name, key in trust.public_keys.items()},
        "revoked": sorted(revoked),
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _update_at(fd, *, owner, action, operator, public_key_hex, confirmation):
    """Private regular-file test seam; callers cannot redirect the public API."""
    _protected(fd, owner=owner, directory=True)
    # All application writers lock the same protected directory inode. Readers
    # see a complete old/new snapshot via rename; no unlinked lock-file race.
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    temporary = None
    try:
        try:
            current = _read_at(fd, owner=owner)
        except FileNotFoundError:
            if action != "enroll":
                raise ApprovalRefused("no operator trust store exists") from None
            current = OperatorTrust({})
        updated = _updated(
            current, action=action, operator=operator,
            public_key_hex=public_key_hex, confirmation=confirmation,
        )
        raw = _encoded(updated)
        if action == "enroll" and len(_encoded(updated, reserve_revocations=True)) > _MAX_STORE_BYTES:
            raise ApprovalRefused("operator trust capacity must reserve every key's revocation")
        if len(raw) > _MAX_STORE_BYTES:
            raise ApprovalRefused("operator trust store capacity exceeded")
        gid = _reader_gid()
        if gid is not None and os.fstat(fd).st_gid not in (0, gid):
            # Same rule as provisioning: never hand a store that an operator
            # deliberately gave another group to the reader group. It stays
            # private (0600) and admission refuses visibly instead.
            gid = None
        if gid is not None:
            # Descriptor-based only: the locked, already-checked directory inode.
            os.fchown(fd, owner, gid)
            os.fchmod(fd, 0o750)
            _protected(fd, owner=owner, directory=True)
        candidate = ".operators-" + uuid.uuid4().hex
        target = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        temporary = candidate
        try:
            if gid is not None:
                # Group-readable before any content is written; never writable.
                os.fchown(target, owner, gid)
                os.fchmod(target, 0o640)
            _protected(target, owner=owner, directory=False)
            offset = 0
            while offset < len(raw):
                count = os.write(target, raw[offset:])
                if count <= 0:
                    raise OSError("operator trust write made no progress")
                offset += count
            os.fsync(target)
        finally:
            os.close(target)
        os.replace(temporary, "operators.json", src_dir_fd=fd, dst_dir_fd=fd)
        temporary = None
        os.fsync(fd)
        if _read_at(fd, owner=owner) != updated:
            raise ApprovalRefused("operator trust read-back mismatch; inspect before retry")
    finally:
        try:
            if temporary is not None:
                os.unlink(temporary, dir_fd=fd)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)


def update_operator(*, action, operator, public_key_hex, confirmation) -> None:
    """Root-only explicit change at the fixed path; no service activation."""
    if os.geteuid() != 0:
        raise ApprovalRefused("operator enrollment requires local administrator privilege")
    if not os.path.lexists(TRUST_DIRECTORY):
        # Diagnostic only (the protected open below still decides): say what is
        # missing instead of a generic failure. Nothing has been changed yet.
        raise ApprovalRefused(
            "operator trust directory /etc/azazel/operator-trust is missing; create it as "
            "root first: install -d -m 0750 -o root -g azmission-read /etc/azazel/operator-trust "
            "(or -m 0700 -g root where the azmission-read group does not exist)")
    try:
        with _trust_directory() as fd:
            _update_at(fd, owner=0, action=action, operator=operator,
                       public_key_hex=public_key_hex, confirmation=confirmation)
    except OSError as exc:
        raise ApprovalRefused(
            "operator trust update failed; inspect store before retry (commit may have occurred)"
        ) from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("enroll", "revoke"))
    parser.add_argument("operator")
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or not sys.stdin.isatty():
        print("A local administrator and interactive confirmation are required.", file=sys.stderr)
        return 1
    try:
        public = input("Operator public key (lowercase Ed25519 hex; never a private key): ")
        confirmation = input("Public-key SHA-256 fingerprint from an independent channel: ")
        consent = input(f"Type {args.action.upper()} {args.operator} to confirm: ")
        if consent != f"{args.action.upper()} {args.operator}":
            raise ApprovalRefused("explicit change confirmation refused")
        update_operator(action=args.action, operator=args.operator,
                        public_key_hex=public, confirmation=confirmation)
    except ApprovalRefused as refused:
        # ApprovalRefused messages are fixed literals in this package; no input is echoed.
        print(f"No success confirmed ({refused}). Inspect the trust store before retrying.",
              file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("No success confirmed. Inspect the trust store before retrying.", file=sys.stderr)
        return 1
    print("Operator trust update verified. No service was activated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
