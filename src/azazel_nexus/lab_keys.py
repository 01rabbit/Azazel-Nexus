"""Public test keys that a production trust root must never hold.

A key whose private half is published signs whatever anybody wants. The
Azazel-Knowledge Lite fixture (`contract/azazel-knowledge-lite/anchors.toml`,
emitted by Knowledge's `tools/lite_fixture.py`) is such a key: its seed is in
Knowledge's public source, so a bundle or a statement "signed" by it proves
nothing about who made it.

**Listed, not inferred.** The set below is the public keys of published
fixtures, compared byte for byte.
`tests/unit/test_knowledge_lite_operator_entry.py`
(`test_every_vendored_fixture_key_is_listed`) keeps it in step with every
vendored fixture anchor, so a new fixture key cannot arrive without being
listed here.

**Refused at registration and on every production read.** Pinning
(`TrustStore.pin`), replacing (`TrustStore.repin`), a revocation policy
(`revocation_policy.prepare_policy_record`, and every reader of one through
`lite_service.KnowledgeLite.revocations`), the commissioned anchor reader
(`lite_import.CommissionedLite.anchors`, which the Mission Pack's
`knowledge_lite` slice also goes through) and the daemon's trust reader
(`lite_import.CommissionedTrust`) all call `refuse_public_fixture_keys`. A
trust root that holds one is unusable, never "usable minus that key": an
operator who pinned it made a mistake that should be seen.

**The one exception is a marked lab host.** The persistent contamination
marker (`lab_host.LAB_HOST_MARKER`, written by the lab tooling and never
removed by it) is what lets a lab rehearsal pin the public fixture. A marked
host is refused by activation health, the bootstrap overlay, commissioning
approval and model admission, so a fixture key accepted there cannot reach a
daemon that runs under an activation grant. Not every gate checks the marker:
Mission Pack verification does not, so on a marked host a Pack's
`knowledge_lite` slice can name a fixture-signed bundle (an owner decision;
off a marked host that slice refuses it like every other reader). The
marker is not an approval: removing it grants nothing, and it never widens
what a production host accepts. There is no flag, argument or environment
variable that does the same.
"""

from __future__ import annotations

from collections.abc import Iterable

from . import lab_host

__all__ = [
    "PUBLIC_FIXTURE_KEYS",
    "PUBLIC_FIXTURE_REFUSED",
    "holds_public_fixture_key",
    "refuse_public_fixture_keys",
]

#: Ed25519 public keys whose private halves are published, by provenance.
PUBLIC_FIXTURE_KEYS: frozenset[bytes] = frozenset({
    # Azazel-Knowledge `tools/lite_fixture.py` (revision 2445c1b, vendored as
    # contract/azazel-knowledge-lite and tests/fixtures/knowledge-lite).
    bytes.fromhex("c561fa9f643fe5c60113cce9db282fde2b9e5ca5fc6b6fc0d1679bb339c9f72f"),
})

#: The fixed refusal text. It names no key: the operator compares the anchor
#: they wrote with the fixture, and the text cannot carry key material.
PUBLIC_FIXTURE_REFUSED = (
    "PUBLIC_FIXTURE_KEY: a published test key is not a trust anchor outside a "
    "marked lab host"
)


def holds_public_fixture_key(keys: Iterable[bytes]) -> bool:
    return any(bytes(key) in PUBLIC_FIXTURE_KEYS for key in keys)


def refuse_public_fixture_keys(keys: Iterable[bytes], error_type=ValueError) -> None:
    """Raise `error_type` when `keys` holds a public fixture key off a lab host."""

    if holds_public_fixture_key(keys) and not lab_host.is_lab_host():
        raise error_type(PUBLIC_FIXTURE_REFUSED)
