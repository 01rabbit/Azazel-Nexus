"""Off-host signer for commissioning and observe-baseline activation approvals.

Run it on the operator's own workstation, from a reviewed checkout (the seed
shares this process with the imported code), with a pinned PyNaCl, for example
``PYTHONPATH=src uv run --no-project --with 'pynacl>=1.5' python -m tools.operator_sign ...``.
It reads one payload file and one external seed file, and writes one raw
64-byte detached signature. It sends nothing, prints no key material and grants
nothing: the node verifies the signature against its enrolled trust store and
recomputes every binding.

The signed bytes are exactly ``operator_trust.approval_message(purpose, payload)``.
Before signing, the payload SHA-256 must equal the value printed on the node,
and the derived public key must equal the enrolled one, so a wrong file or a
wrong key stops here instead of producing a signature.

Three purposes are offered: the commissioning draft, the full commissioning
proposal and the boot-free v2 activation approval
(``azazel-nexus/activation-approval/v2``, docs/activation-observe-baseline.md
§3.1). For ``activation`` the payload must also be a well-formed canonical v2
document (it must re-encode to exactly the same bytes, with a validity window
inside the 72-hour ceiling) before anything is signed, so neither v1 bytes nor
arbitrary bytes can become an activation signature; a human summary of what is
being approved is printed with the result. This is a shape check only: the
node still verifies the approval against its own independently collected
context, activation policy and floors, and a signature grants nothing by
itself. Local model admission has its own ceremony
(docs/hil-runbooks/mio-admission.md) and v1 activation and bootstrap approvals
are out of scope. See docs/hil-runbooks/commissioning-rehearsal.md.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

from nacl.signing import SigningKey

from azazel_nexus.activation_approval import _utc
from azazel_nexus.activation_approval_v2 import (
    MAX_LEASE_CEILING_SECONDS,
    ObserveBaselineContext,
    _parse,
    observe_baseline_payload,
)
from azazel_nexus.activation_policy import ACTIVATION_UNIT_ALLOWLIST
from azazel_nexus.operator_trust import MAX_APPROVAL_BYTES, ApprovalPurpose, approval_message

PURPOSES = {
    "activation": ApprovalPurpose.ACTIVATION,
    "commissioning": ApprovalPurpose.COMMISSIONING,
    "commissioning-proposal": ApprovalPurpose.COMMISSIONING_PROPOSAL,
}


class SignRefused(Exception):
    pass


def read_seed(path: Path) -> bytes:
    """A 32-byte Ed25519 seed, stored raw or as 64 hex characters.

    Only a regular, single-link file readable by its owner alone is accepted,
    and at most 65 bytes are read, so a mistyped argument cannot block on a
    FIFO, follow a link or pull in an unrelated file.
    """

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SignRefused("seed must be a regular single-link file")
        if info.st_mode & 0o077:
            raise SignRefused("seed file must not be readable by group or other")
        raw = os.read(fd, 66)
    finally:
        os.close(fd)
    if len(raw) > 65:
        raise SignRefused("seed must be 32 raw bytes or 64 hex characters")
    if len(raw) == 32:
        return raw
    try:
        text = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise SignRefused("seed must be 32 raw bytes or 64 hex characters") from None
    if re.fullmatch(r"[0-9a-fA-F]{64}", text) is None:
        raise SignRefused("seed must be 32 raw bytes or 64 hex characters")
    return bytes.fromhex(text)


def activation_summary(payload: bytes) -> dict:
    """What a v2 activation payload approves, or `SignRefused`.

    The document must re-encode to exactly these bytes. The context is taken
    from the payload itself, so this proves well-formedness and canonical form
    only; whether it matches the node is decided by the node's verifier. The
    commissioning evidence binding is checked but not printed.
    """

    try:
        document = _parse(payload)
        context = ObserveBaselineContext(
            node_digest=document["node_digest"], generation=document["generation"],
            generation_digest=document["generation_digest"],
            commissioning_digest=document["commissioning_digest"],
            commissioning_evidence_binding=document["commissioning_evidence_binding"],
            policy_digest=document["policy_digest"],
            security_epoch=document["security_epoch"],
        )
        canonical = observe_baseline_payload(
            context=context, approval_id=document["approval_id"],
            operator=document["operator"], approval_seq=document["approval_seq"],
            units=document["units"], granted_at=document["granted_at"],
            expires_at=document["expires_at"],
        )
        seconds = int((_utc(document["expires_at"])
                       - _utc(document["granted_at"])).total_seconds())
    except Exception:  # never echo payload content in a refusal
        raise SignRefused("payload is not a well-formed v2 activation approval; not signed") from None
    if payload != canonical:
        raise SignRefused("payload is not canonical v2 activation approval bytes; not signed")
    if seconds > MAX_LEASE_CEILING_SECONDS:
        raise SignRefused("approval validity exceeds the 72-hour ceiling; not signed")
    # #251 L-4: only units the node could ever grant (its code-fixed
    # allowlist); the node's policy may narrow this further and still decides.
    if not set(document["units"]) <= set(ACTIVATION_UNIT_ALLOWLIST):
        raise SignRefused("approval names a unit outside the activation allowlist; not signed")
    return {
        "schema": document["schema"],
        "approval_id": document["approval_id"],
        "operator": document["operator"],
        "units": ",".join(document["units"]),
        "generation": document["generation"],
        "generation_digest": document["generation_digest"],
        "node_digest": document["node_digest"],
        "security_epoch": document["security_epoch"],
        "approval_seq": document["approval_seq"],
        "granted_at": document["granted_at"],
        "expires_at": document["expires_at"],
        "validity_seconds": seconds,
    }


def sign(*, purpose: str, payload: bytes, expect_payload_sha256: str, seed: bytes,
         expect_public: str) -> tuple[bytes, dict]:
    if purpose not in PURPOSES:
        raise SignRefused("unsupported purpose")
    if not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise SignRefused("payload must be nonempty and bounded")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expect_payload_sha256.strip().lower():
        raise SignRefused("payload SHA-256 does not match the value shown on the node; not signed")
    summary = activation_summary(payload) if purpose == "activation" else {}
    key = SigningKey(seed)
    public = bytes(key.verify_key).hex()
    if public != expect_public.strip().lower():
        raise SignRefused("seed does not match the enrolled public key; not signed")
    message = approval_message(PURPOSES[purpose], payload)
    signature = key.sign(message).signature
    key.verify_key.verify(message, signature)
    return signature, {
        "purpose": purpose,
        **summary,
        "payload_sha256": digest,
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "public_key": public,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--purpose", required=True, choices=sorted(PURPOSES))
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--expect-payload-sha256", required=True)
    parser.add_argument("--expect-public", required=True,
                        help="enrolled public key, 64 hex characters")
    parser.add_argument("--seed", required=True, type=Path,
                        help="external seed file, outside any checkout")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out.exists() or args.out.is_symlink():
            raise SignRefused(f"{args.out} already exists; not overwritten")
        signature, facts = sign(
            purpose=args.purpose, payload=args.payload.read_bytes(),
            expect_payload_sha256=args.expect_payload_sha256,
            seed=read_seed(args.seed), expect_public=args.expect_public,
        )
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(signature)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            # A partial signature would block the next attempt as "exists".
            args.out.unlink(missing_ok=True)
            raise
    except (SignRefused, OSError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1
    for name, value in facts.items():
        print(f"{name}: {value}")
    print(f"signature: {args.out} ({len(signature)} bytes, verified locally)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
