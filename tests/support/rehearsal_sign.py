"""Test-only signer for the two §8 rehearsal rows the production signer refuses (#196 G6).

`docs/deception-exposure-wiring.md` §8 ("No back door in the production
signer"): two refusals of the VM rehearsal need an approval that
`tools/operator_sign.py` will not make, and must not be able to make:

* `v3-under-activation`: a canonical v3 approval signed under
  `ApprovalPurpose.ACTIVATION` (v2's purpose), to show the node refuses it
  (owner decision Q-C);
* `v3-other-scope`: a canonical v3 approval whose `exposure_scope_digest`
  names another scope digest, signed under `ACTIVATION_EXPOSURE`, to show
  the pass withholds the tier at P10 (`exposure_approval_binding_differs`).

This file lives under `tests/`, which the offline bundle excludes
(`tools/build_offline_bundle.py`, `EXCLUDED_PARTS`) and the installer never
places; nothing in the product imports it. It refuses to run unless the
approval's operator label starts with `rehearsal-`, so it signs only for an
operator enrolled for a rehearsal with a key generated for that run (wiring
§8, "Signatures are the operator's": the operator runs it, with the
rehearsal seed, off the VM). It reads one payload and one seed, writes a
create-only signature (and, for `v3-other-scope`, the changed payload), and
prints the payload SHA-256 to confirm on the node. Never a production key.

    PYTHONPATH=src python tests/support/rehearsal_sign.py --kind v3-under-activation \\
        --payload request.json --seed rehearsal.seed --expect-public HEX --out bad.sig
    PYTHONPATH=src python tests/support/rehearsal_sign.py --kind v3-other-scope \\
        --payload request.json --seed rehearsal.seed --expect-public HEX \\
        --out-payload other.json --out other.sig
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey

from azazel_nexus.activation_approval_v3 import (
    activation_approval_v3_payload,
    decode_activation_approval_v3,
)
from azazel_nexus.operator_trust import MAX_APPROVAL_BYTES, ApprovalPurpose, approval_message

REHEARSAL_PREFIX = "rehearsal-"
KINDS = ("v3-under-activation", "v3-other-scope")


class RehearsalSignRefused(Exception):
    pass


def _other_digest(digest: str) -> str:
    """A different, well-formed scope digest: every hex digit moved by one."""
    flipped = "".join("0123456789abcdef"[(int(c, 16) + 1) % 16] for c in digest[7:])
    return "sha256:" + flipped


def rehearsal_sign(*, kind: str, payload: bytes, seed: bytes, expect_public: str
                   ) -> tuple[bytes, bytes]:
    """`(payload to install, signature)` for one rehearsal row, or refused."""
    if kind not in KINDS:
        raise RehearsalSignRefused("unknown kind")
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_APPROVAL_BYTES:
        raise RehearsalSignRefused("payload must be nonempty and bounded")
    try:
        decoded = decode_activation_approval_v3(payload)
    except Exception:  # never echo payload content
        raise RehearsalSignRefused("payload is not a canonical v3 approval") from None
    if not decoded.operator.startswith(REHEARSAL_PREFIX):
        raise RehearsalSignRefused(
            f"operator label must start with {REHEARSAL_PREFIX!r}: rehearsal keys only")
    key = SigningKey(seed)
    if bytes(key.verify_key).hex() != expect_public.strip().lower():
        raise RehearsalSignRefused("seed does not match the expected public key")
    if kind == "v3-under-activation":
        out, purpose = payload, ApprovalPurpose.ACTIVATION
    else:
        out = activation_approval_v3_payload(
            context=decoded.context, approval_id=decoded.approval_id,
            operator=decoded.operator, approval_seq=decoded.approval_seq,
            units=decoded.units, granted_at=decoded.granted_at,
            expires_at=decoded.expires_at,
            exposure_scope_digest=_other_digest(decoded.exposure_scope_digest),
            exposure_prefix_count=decoded.exposure_prefix_count,
            exposure_ingress_count=decoded.exposure_ingress_count)
        purpose = ApprovalPurpose.ACTIVATION_EXPOSURE
    return out, key.sign(approval_message(purpose, out)).signature


def _create(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def main(argv=None) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from tools.operator_sign import SignRefused, read_seed

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kind", required=True, choices=KINDS)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--expect-public", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--out-payload", type=Path,
                        help="v3-other-scope: where the changed payload is written")
    args = parser.parse_args(argv)
    try:
        if (args.kind == "v3-other-scope") != (args.out_payload is not None):
            raise RehearsalSignRefused("--out-payload is required for v3-other-scope only")
        payload, signature = rehearsal_sign(
            kind=args.kind, payload=args.payload.read_bytes(), seed=read_seed(args.seed),
            expect_public=args.expect_public)
        if args.out_payload is not None:
            _create(args.out_payload, payload)
        _create(args.out, signature)
    except (RehearsalSignRefused, SignRefused, OSError) as error:
        print(f"refused: {error}", file=sys.stderr)
        return 1
    print(f"kind: {args.kind}")
    print(f"payload_sha256: {hashlib.sha256(payload).hexdigest()}")
    print(f"signature: {args.out} (REHEARSAL ONLY; never a production key)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
