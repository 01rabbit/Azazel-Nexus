# Knowledge Lite: the trust chain under the cache

Status: **implemented** (`src/azazel_nexus/signature.py`,
`content_store.py`, `lite_generation.py`, `revocation.py`), unit tested and
mutation checked. This is E1 of [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53),
the first half: the primitives. The service that composes them into the
`available` / `stale` / `unavailable` / `quarantined` states an operator sees
is the second half and is **not** in this change.

Related: [the Knowledge Lite consumer](knowledge-lite-consumer.md) ·
[capability model](capability-model.md) · [contract ownership](contract-ownership.md)

## 1. What was missing, and what was broken

[The consumer document](knowledge-lite-consumer.md) records what happens when
an artifact cannot be read. It does not say what *reading* one means, because
until now nothing in this repository verified anything: `StagedReader` took an
injected verifier and defaulted to refusing everything. That default is
correct and it is not a verifier.

One item on the list was worse than missing. `StagedReader._promote` replaced
`live` by rename and then deleted the directory it displaced, so **rollback
was not unimplemented — it was structurally impossible.** A cache that throws
away the generation it just replaced has nothing to go back to.

| Requirement | Before | Now |
| --- | --- | --- |
| Atomic promotion | `lite_cache.py` | unchanged |
| Expired claims never served as current | `lite_cache.py` | unchanged |
| Signature verification | injected, no implementation | `signature.py` |
| Content addressing | — | `content_store.py` |
| Generation management | configuration only (`generation.py`) | `lite_generation.py` |
| Rollback | **impossible by construction** | `lite_generation.py` |
| Revocation | — | `revocation.py` |

## 2. Verification, and the signer that does not exist

`signature.py` verifies Ed25519 and contains no signer. That is checked rather
than asserted: `tests/unit/test_lite_signature.py` walks every module under
`src/azazel_nexus/` and fails if a `private_key`, `secret_key`, `signing_key`
or `seed` is bound or accepted as a parameter anywhere in the package. The
signer the tests need in order to have anything to verify lives in
`tests/unit/signing_oracle.py`, outside the product, where the scan does not
reach and nothing that ships can import it.

It is a pure-Python implementation because `pyproject.toml` says
`dependencies = []` and says why: *"a dependency added here is a dependency the
CORE path can fail on"*. A cache that cannot verify its artifact when an
optional wheel is missing fails for a packaging reason, which is not a reason.
Verification touches no secret — public key, message and signature are all
values an adversary already holds — so there is no secret whose timing could
leak. **The same argument would not license a signing routine, which is the
second reason this module must not grow one.**

RFC 8032 §5.1.7's `s < L` check is present and tested. Without it, `s + L` is a
second, different byte string that verifies over the same message under the
same key, and everything downstream assumes one admitted artifact has one
admitted signature.

## 3. Content addressing: the digest is re-derived on every read

A blob is stored at the digest of its own bytes, and `ContentStore.get`
re-derives that digest before returning anything. A store that hashed on write
and trusted the filename afterwards would detect nothing, because the failure
it exists to catch is bytes changing *after* they were written.

Two consequences are deliberate:

- **A mismatch is reported, never repaired.** `ContentTampered` names both
  digests and leaves the altered bytes on disk. A silent repair turns the one
  moment corruption was visible into no moment at all.
- **A digest is never a path.** `parse_digest` refuses anything that is not
  `sha256:` followed by 64 lower-case hex characters, before any of it reaches
  the filesystem.

`has()` answers presence and says nothing about integrity. They are different
questions with different costs, and the tests hold them apart.

## 4. Generations and rollback

A Lite generation owns nothing. It *names* an artifact in the content store and
records who signed it, when it was admitted, and which generation it
supersedes. Because the bytes are addressed and shared, keeping an old
generation costs a few hundred bytes of metadata — which is what makes rollback
cheap enough to be real.

The doctrine is `generation.py`'s, restated for a different subject:

- **Numbers only increase.** A rollback creates a *new* generation whose
  content is an older one's. The pointer never moves backwards, so the history
  reads as a reversal rather than as an absence.
- **A rollback records why and who.** An unexplained reversal is
  indistinguishable from a mistake about to be repeated.
- **A rollback target is re-verified, not trusted.** Rolling back to an
  artifact that has since been altered is the one rollback that must fail.

`live()` reads the pointer rather than taking the highest number. After a
promotion those agree; after a partially applied one they do not, and the
difference is which artifact is being served.

Pruning is a disk policy and must not become an outage: the live generation is
retained whatever the retention count says, and a blob is removed only when no
retained generation still names it — which matters precisely because a rollback
makes two generations share one artifact.

## 5. Revocation

An artifact admitted yesterday may be known-bad today, and the signature over a
bad artifact is still a valid signature. Revocation is the separate statement.

Four rules, each a refusal:

- **Consulted at serve time, not only at admission.** A list accepted after a
  promotion must stop the current cache from being served without waiting for a
  restart — which, on a node whose feed has been cut, would be never.
- **A list that cannot be verified does not mean nothing is revoked.**
  `current()` raises and the consumer takes the cache out of service. Falling
  back to an empty list would turn tampering with one file into the
  un-revocation of everything, which is exactly the move an adversary would
  make.
- **Sequence numbers only increase.** A correctly signed *older* list is a
  valid signature over a statement that used to be true. Replaying it is how a
  revoked artifact comes back.
- **A revoked signer cannot issue the next list.** The list in force is applied
  to the key that signed the incoming one, before the incoming one is believed.

The signed file is 64 bytes of detached signature followed by the payload
exactly as it was signed. One file, one atomic replace, and no canonicalisation
step that a signer and a verifier could disagree about.

## 6. What this change does not claim

- **No service, no status, no audit wiring.** These are primitives. Nothing in
  `cli.py`, `status.py`, `degradation.py` or the runtime daemons consults them
  yet; that is E1's second half.
- **No `quarantined` state yet.** `lite_cache.Admission` still has
  `ABSENT` / `REFUSED` / `UNVERIFIABLE` / `ADMITTED`. The distinction between
  "we do not have it" and "we had it and it is not trustworthy" is stated in
  [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) and is not
  implemented here.
- **No trust store.** Admitted public keys are passed in by the caller. Pinning
  them at commissioning is not done.
- **Nothing about Edge.** [#44](https://github.com/01rabbit/Azazel-Nexus/issues/44)
  and the hardware gates are unaffected, and no claim here moves
  `edge-baseline-ready`.

## 7. Where the tests are

| File | Holds |
| --- | --- |
| `tests/unit/test_lite_signature.py` | RFC 8032 §7.1 vectors, malleability, and the package-wide absence of a signer |
| `tests/unit/test_lite_content_store.py` | re-derivation on read, tampering reported not repaired, digests that are not paths |
| `tests/unit/test_lite_generation.py` | promotion does not destroy what it displaced, rollback, pruning that does not orphan |
| `tests/unit/test_lite_revocation.py` | replay, the unreadable list, the revoked signer |

Every guard in these four modules was removed in turn and the suite re-run.
One survived: `artifact_of` could read a blob directly instead of through
`ContentStore.get`, and every test still passed — because nothing served the
live artifact after tampering with it. That test now exists. A guard that is
never exercised is not a guard.
