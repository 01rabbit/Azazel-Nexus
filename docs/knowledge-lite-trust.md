# Knowledge Lite: the trust chain under the cache

Status: **implemented** (`src/azazel_nexus/signature.py`,
`content_store.py`, `lite_generation.py`, `revocation.py`, `lite_trust.py`,
`lite_service.py`), unit tested and mutation checked. This is E1 of
[#53](https://github.com/01rabbit/Azazel-Nexus/issues/53): the primitives
(§2–§5), the trust store (§6) and the service that composes them into the four
states an operator sees (§7). Wiring those states into `cli.py`, `status.py`,
`degradation.py` and the audit ledger is E4 and is **not** in this change.

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
| Trust store | — | `lite_trust.py` |
| `available` / `stale` / `unavailable` / `quarantined` | — | `lite_service.py` |

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

## 6. The trust store

A verifier without a trust store verifies against whatever it is handed, which
is not verification. `lite_trust.py` is the set of public keys a node will
accept an artifact under.

**Keys are bound to a commissioning, not to a node.** The file records the
commissioning digest it was pinned under, and reading it requires naming that
same digest. Re-commissioning changes what the node is and who runs it; keys
pinned for the previous commissioning are refused rather than carried across,
because *"these were the right keys for the node this used to be"* is not an
argument for trusting them now.

**Pinning happens once.** `pin` refuses to overwrite. Replacing the set is
`repin`, which records why and who — the rule `lite_generation.py` applies to a
rollback, for the same reason.

**An empty trust set is refused at pin time.** A node with no admitted keys
admits nothing, which is correct as a *consequence* and almost always a
mistake as a *configuration* — one that presents as "Knowledge Lite never
works" rather than as an error. A malformed key is parsed and refused at pin
time for the same reason.

## 7. The four states

`lite_service.py` is the one place that puts the primitives together and
answers the question an operator actually asks.

| state | means | operator response |
| --- | --- | --- |
| `available` | verified, unrevoked, and something in it may be served | none |
| `stale` | verified and unrevoked; nothing in it may be served **now** | refresh the artifact |
| `unavailable` | nothing has been admitted | install an artifact |
| `quarantined` | something was admitted and may not be trusted | investigate, then roll back or re-admit |

**`stale` serves nothing.** An expired claim is withheld, not labelled and
passed along. The freshness label exists so the operator plane can say which
claims were withheld; it is not a disclaimer attached to data served anyway.

**`unavailable` and `quarantined` are different facts.** "We do not have it"
and "we had it and it is not trustworthy" call for different actions, and a
node reporting the first when the second is true has said that nothing
happened. A quarantined reading still carries the generation, digest and
signer it was — being held is not being forgotten.

**Only `available` sources the `knowledge_lite` capability.** A capability
present in name while serving nothing is a claim this product does not make.

**None of the four blocks the deterministic path**, and the tests assert
`blocks_core()` in every state rather than in the convenient one.

### Verification happens again on every read

Content addressing binds bytes to a digest. Nothing else binds the digest *in
a generation record* to a key, so a tampered record could name a different
admitted artifact under a signer that never signed it. Re-verifying the
detached signature on each read is what makes `signer_key` a proven fact —
and it is what makes revoking a key stop the cache that key signed, on the
next read, with no restart and no new artifact.

That is why `LiteGeneration` names a `signature_digest` as well as an
`artifact_digest`: the signature has to still be there to be checked again.

## 8. Two paths, one cache, one serving rule

Two modules can hold a Knowledge Lite artifact: `lite_cache.StagedReader`,
which faces Azazel-Knowledge's archives and its negative fixtures, and
`lite_service.KnowledgeLite`, which is the product path. That is two
implementations of one concern, and two implementations agree only until one
of them is edited. Three things keep them from drifting.

**They do not share a live cache.** `LiteGenerationStore` keeps its live
*pointer* — a file — at `root/live`. `StagedReader` unpacks into
`root/admitted`. They used to share the name: a node with both at one root had
one overwrite the other's `live`, and the next promotion raised
`NotADirectoryError` out of `shutil.rmtree` — an unhandled exception from a
module whose own docstring says it never raises for the node.
`tests/unit/test_lite_one_cache.py` is the regression, in both orders.

**They share one serving rule.** `split_by_freshness` has a single
implementation; `StagedReader.serve` delegates to it and `KnowledgeLite.read`
calls it. The test parses `serve` rather than grepping it, because its
docstring names the shared function too and a mention is not a call.

**Their vocabularies answer different questions, and are disjoint.**
`Admission` (`admitted` / `absent` / `refused` / `unverifiable`) says how one
admission attempt ended. `LiteState` (`available` / `stale` / `unavailable` /
`quarantined`) says what the cache is now. No value appears in both sets, so
no later reader can assume a mapping that does not exist.

**Open:** folding the archive path into the service would need Knowledge's own
signature format, which this repository does not have. `StagedReader` takes an
injected verifier for that reason. Unifying them is an open item on
[#6](https://github.com/01rabbit/Azazel-Nexus/issues/6), not something to
invent here.

## 9. What this change does not claim

- **No status, CLI, degradation or audit wiring.** Nothing in `cli.py`,
  `status.py`, `degradation.py` or the runtime daemons consults `LiteState`
  yet. That is E4 ([#55](https://github.com/01rabbit/Azazel-Nexus/issues/55)).
- **No artifact format.** Azazel-Knowledge owns it. The claim reader is
  injected, and the default refuses — a caller that forgets one gets
  `quarantined`, never `available`.
- **Nothing about Edge.** [#44](https://github.com/01rabbit/Azazel-Nexus/issues/44)
  and the hardware gates are unaffected, and no claim here moves
  `edge-baseline-ready`.

## 10. Where the tests are

| File | Holds |
| --- | --- |
| `tests/unit/test_lite_signature.py` | RFC 8032 §7.1 vectors, malleability, and the package-wide absence of a signer |
| `tests/unit/test_lite_content_store.py` | re-derivation on read, tampering reported not repaired, digests that are not paths |
| `tests/unit/test_lite_generation.py` | promotion does not destroy what it displaced, rollback, pruning that does not orphan |
| `tests/unit/test_lite_revocation.py` | replay, the unreadable list, the revoked signer |
| `tests/unit/test_lite_trust.py` | the commissioning binding, pinning once, the empty set |
| `tests/unit/test_lite_service.py` | the four states, and that they are four |
| `tests/unit/test_lite_one_cache.py` | the two paths not colliding, and one serving rule |

Every guard in these six modules was removed in turn and the suite re-run:
41 mutations for the primitives, 17 for the trust store and the service, 5 for
the unification.

One survived, in the first round: `artifact_of` could read a blob directly
instead of through `ContentStore.get`, and every test still passed — because
nothing served the live artifact after tampering with it. That test now
exists. **A guard that is never exercised is not a guard.**

One test also passed for the wrong reason and was rewritten: the four-states
test drove one shared service through all four states in sequence, so an
earlier state left the service somewhere the next one did not put it. Each
state now gets its own store.

And one *change* turned out not to be load-bearing: renaming `root/retired`
alongside `root/admitted` survived its mutation, because nothing else uses
that name. It was reverted rather than kept for symmetry — a change no test
can miss is a change with no reason.
