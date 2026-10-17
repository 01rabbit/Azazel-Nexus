# Security review of the hand-written Ed25519 verifier

Status: **one defect found and fixed; two items escalated and open.**
`supported` is **not** claimed. [Nexus
#70](https://github.com/01rabbit/Azazel-Nexus/issues/70) stays open until the
escalated items are decided.

Subject: `src/azazel_nexus/signature.py` — a pure-Python Ed25519 **verifier**.
Nexus verifies and does not sign; `tests/unit/test_lite_signature.py` scans
the package for the shape of a signer and fails if one appears.

Related: [Knowledge Lite consumer](knowledge-lite-consumer.md) ·
[contract ownership](contract-ownership.md) · [hardware gates](hardware-gates.md)

## 0. What this review does not establish

Passing RFC 8032's vectors is necessary and not sufficient: the vectors are a
handful of *valid* signatures, and what a verifier has to get right is the
much larger set of inputs that are almost valid. An implementation can be
wrong on every one of those and pass every vector — which is what happened
here, and §1 is that finding.

Nothing below is a claim that this implementation is equivalent to a reviewed,
widely deployed one. It is a claim that on the inputs enumerated here the two
agree.

## 1. Finding: a small-order public key permitted universal forgery — **fixed**

**Severity: high. Reachable only by influencing what key a node pins.**

### What was wrong

`_point_decompress` accepted all eight points of order dividing 8, and
`verify_detached` used whatever it decompressed as `A`. With `A` of order 1
the challenge term `[k]A` is the neutral element for **every** challenge, so
the verification equation

    [s]B == R + [k]A

collapses to `[s]B == R`. An attacker picks any `s < L`, computes `R = [s]B`,
and holds one 64-byte signature that verifies over **every message** under
that key. The other seven small-order points admit the same construction.

The worst part is not the forgery, it is that it **succeeds**: the node
reports a verified signature, so nothing downstream has a failure to act on.

Measured before the fix, against the identity point:

| message | this implementation | libsodium |
| --- | --- | --- |
| `admit this bundle` | **verified** | rejected |
| `a completely different message` | **verified** | rejected |
| *(empty)* | **verified** | rejected |

### The fix

`_is_small_order` — `[8]P == O`, three doublings — and a refusal in both
`parse_public_key` and `verify_detached`. Checked at both entry points because
a caller may hold key bytes that never went through the parser.

Why `[8]P == O` rather than a table of the eight encodings: it catches them at
**any** canonical encoding, and a table is a list that can be short. It never
rejects a legitimate key — a signing scalar is clamped to a multiple of 8
below the group order, so a real public key lies in the prime-order subgroup.
Verified over 300 generated keys: none flagged.

Cost: 22 µs against the ~5.1 ms a verification already spends on two scalar
multiplications — about 0.4%.

### What the fix does not cover, deliberately

**Mixed-order `A`** (order `8L`, on the curve but outside the prime-order
subgroup) is still accepted. Rejecting it needs `[L]A == O`, a full scalar
multiplication — it would roughly double verification cost — and it buys
nothing: with cofactorless verification a mixed-order key can cause a valid
signature to be **rejected**, which is not a forgery. libsodium does not
reject it either.

**Small-order `R`** has no explicit check. The equation already answers `no`:
an attacker would have to solve for `s`. `test_a_small_order_r_is_answered_no_rather_than_raised`
drives all eight and records the reasoning — a guard that never changes an
outcome is not a guard.

## 2. Input limits and denial of service — **measured, no change**

Verification is ~5.1 ms of scalar multiplication plus SHA-512 over the
message, at ~1.9 ms per MiB on the machine this was measured on.

`verify_detached` itself imposes no message-length limit, so the bound has to
come from the callers. It does:

| caller | what bounds it |
| --- | --- |
| `lite_bundle._check_signatures` | `MAX_MANIFEST_BYTES` (8 MiB), enforced **before** verification, and `MAX_SIGNATURE_LINES` (32) |
| `lite_service._first_key_that_verifies` | the trust store's key count |
| `revocation._signer_of` | the trust store's key count |

Worst case per bundle, measured: a manifest at the 8 MiB ceiling with all 32
signature lines used, each failing as late as possible — **0.75 s of CPU**. A
real manifest from the producer's own fixtures is 3236 bytes, where the same
32 lines cost 181 ms.

**Reached only through the operator-selected offline inbox.** There is no
network path that induces a verification: a bundle is enumerated from the
inbox and chosen by content id (`lite_import`). An adversary must first get a
file onto the node and then have an operator select it.

*An earlier draft of this review reported 15.5 s here, by applying the generic
256 MiB member ceiling to the manifest. That was wrong — `MAX_MANIFEST_BYTES`
is 8 MiB and is checked first. The figure above is measured, not scaled.*

Conclusion: bounded, and the bound is proportionate to the path. No change.

## 3. Canonical encoding — **verified, no change**

| checked | how |
| --- | --- |
| a public key has one encoding | `parse_public_key` requires exactly 64 lower-case hex characters; mixed case, `0x`, whitespace and odd lengths are refused rather than coerced |
| `y >= p` has no decoding | `_recover_x` returns `None`; driven as both key and `R` in the differential tests |
| `x = 0` with the sign bit set | `_recover_x` returns `None` — the non-canonical encoding of the only point where the sign is ambiguous |
| `R` is canonical | the same decompression path as a key |
| the challenge is over the **bytes**, not a re-encoding | `_sha512_modq(encoded_r + public_key + message)`, per RFC 8032 §5.1.7 |
| `s < L` | refused above the group order, so `s + L` is not a second signature |

`content_store` normalises digests to `sha256:` plus 64 lower-case hex before
anything reaches the filesystem, which is the same discipline in the other
direction.

**Cofactored or cofactorless?** This implementation is **cofactorless**
(`[s]B == R + [k]A`). RFC 8032 §5.1.7 permits either and says so: the
cofactored equation is required, and checking the cofactorless one instead is
"sufficient, but not required". Cofactorless is the stricter of the two and is
the correct choice here, where one artifact must have one admitted signature.

## 4. Trust root — **two items escalated, open**

### 4a. The revocation list and the bundle share one key set

`revocation._signer_of` accepts a signature from **any** key in
`self.trusted_keys`. `lite_bundle` has `key_roles` and
`required_signer_role` and consults them for bundles; `revocation` consults
neither.

So a key authorised to sign bundles can also sign a revocation list. The
consequence is not forgery — it is that a single compromised bundle-signing
key can revoke, which is a denial of service against the node's own trust
chain. `contract-ownership.md` §4.2's delegated roles express the separation;
the revocation path does not implement it.

**Not fixed here.** Which role may sign a revocation list is a contract
question, and deciding it unilaterally would change published semantics.

### 4b. `repin` requires local commissioning confirmation (#86)

The library now takes a file-based `RepinRequest`, requires a
`RepinConfirmation`, and stages and validates a distinct root before an atomic
generation-pointer promotion. It records six audit fields containing
fingerprints, provenance and generation, never keys or the confirmation nonce.
See [the trust-store contract](knowledge-lite-trust.md#6-the-trust-store) for
the input format, failure behavior and audit ordering.

Authentication and interactive confirmation belong to the runtime local
commissioning boundary; the library records the supplied principal and requires
the confirmation object, but cannot authenticate the principal or verify the
nonce. Filesystem permissions remain unchanged and are not the complete repin
authorization boundary. Initial commissioning `pin` retains its existing API.

### What is sound

- `TrustStore.keys` requires `commissioning_digest` as a keyword argument, not
  an option. Keys pinned under a different commissioning are refused, so the
  pin is bound to the commissioning for the whole lifecycle.
- `repin` refuses when nothing is pinned: a first pinning is a commissioning
  step, not a correction.
- A malformed key in the store is skipped, and only after every other key has
  had its chance — so one unusable key cannot make every list unverifiable,
  and the result does not depend on ordering.

## 5. Differential testing against an established implementation — **done**

`tests/unit/test_signature_differential.py`: the same inputs to this
implementation and to libsodium through PyNaCl, with **any** disagreement a
defect here. **108 cases**, all agreeing:

- valid signatures at nine message lengths around the SHA-512 block boundary
- all 64 single-bit flips of a valid signature, one test each
- `s` at `L`, `L ± 1`, and the actual `s + L` malleability construction
- signatures of seven wrong lengths
- messages one byte longer and one shorter than what was signed
- all eight small-order points, as `A` and as `R`
- non-canonical `y >= p`, as key and as `R`
- 200 random `(key, message, signature)` triples

PyNaCl is in the `dev` extra and **only** there. `dependencies = []` is about
what a node needs to verify its own cache with no wheel available; it says
nothing about what a test needs. `tests/unit/test_signature_differential.py::test_the_library_itself_still_depends_on_nothing`
checks the extra has not become a runtime dependency, and the CORE-imports job
would fail if PyNaCl reached the deterministic path.

**The test cannot silently stop running.** It skips when PyNaCl is absent, so
a contributor without the dev extra is not blocked — and a skip would
otherwise be the whole check quietly not running while the job stayed green.
The `Refuse a silent skip of the differential crypto test` step fails on any
skip and on fewer than 50 cases.

### The signing oracle

Verification needs signatures, and producing them needs a signing key. It is
derived in-process from a fixed literal string, exists only for the duration
of a test run, and is shared with nothing — not a production key, not a
commissioned trust anchor, not a release-signing key. No key material is
written to a file, a fixture, a log or an assertion message, and
`azazel_nexus` itself still contains no signing verb.

## 6. What would let `supported` be claimed

Not this document alone.

1. **4a decided and implemented or recorded as accepted** — the revocation
   signer's role.
2. **4b decided** — whether filesystem permission is the intended authority
   for `repin`, written down either way.
3. A review of this record by someone who did not write the implementation.

Until then, every surface that names this implementation says the same thing:
the cryptographic implementation is **not supported**, and `functional_readiness`
carries that as one of Knowledge Lite's `does_not_mean` entries.
