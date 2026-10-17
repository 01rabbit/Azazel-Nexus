"""Regenerate public test vectors. This published seed is NEVER a real key."""

import json
from pathlib import Path

from nacl.signing import SigningKey

from azazel_nexus.revocation import REVOCATION_DOMAIN, RevocationList

root = Path(__file__).parent
key = SigningKey(bytes(range(160, 192)))
manifest = {"bundle_format_version": 1, "bundle_version": 7, "kind": "full", "files": {}}
revocation = json.loads(RevocationList(sequence=1, issued_at="2026-10-17T00:00:00Z").as_payload())
for name, document, domain in (
    ("manifest", manifest, b""),
    ("revocation", {**manifest, **revocation}, REVOCATION_DOMAIN),
    ("manifest-with-sequence", {**manifest, **revocation}, b""),
):
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    (root / f"{name}.json").write_text(json.dumps({
        "public_key": bytes(key.verify_key).hex(),
        "payload": payload.decode(),
        "signature": key.sign(domain + payload).signature.hex(),
    }, indent=2) + "\n")
