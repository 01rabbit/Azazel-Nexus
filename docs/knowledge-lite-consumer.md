# The Knowledge Lite consumer: what happens when it cannot be read

Status: **implemented** (`src/azazel_nexus/lite_cache.py`,
`src/azazel_nexus/capability.py`), with unit tests against the artifacts
Azazel-Knowledge actually emits. This is the first code in this repository; it
is not a release, and nothing here is *verified* in the program's sense.

Related: [the trust chain under the cache](knowledge-lite-trust.md) ·
[capability model](capability-model.md) ·
[contract ownership](contract-ownership.md) ·
[commissioning](commissioning.md) · [recovery](recovery.md)

> The verifier this document calls "injected" now has an implementation, and
> the rollback it does not mention was structurally impossible until E1. See
> [the trust chain under the cache](knowledge-lite-trust.md).

## 1. The split, and why this document exists

Knowledge ADR-0015 D7 divides the concern:

| Concern | Owner |
| --- | --- |
| Lite artifact generation, selection, export policy, signing, **consumer fixtures** | Azazel-Knowledge |
| **Embedded read-only cache, staged/atomic reader, commissioning, trust policy, `FULL -> LITE -> CORE` routing** | **Azazel-Nexus / Azazel-Boot** |

> Knowledge produces and signs; it does not decide where an artifact is
> installed, when it is trusted, or what a consumer does on its absence. […] a
> consumer that cannot read it must remain fully operational — Edge Core is
> never blocked by missing, corrupt, or expired knowledge.

**What a consumer does when it cannot read an artifact is the consumer's
decision, and Knowledge cannot prove it.** This document records the decision
and points at the tests that hold it.

## 2. Four rules, each enforced rather than described

**Absence is not an error.** A missing artifact yields `ABSENT` and a working
node. There is no path in `lite_cache.py` that raises because knowledge is
unavailable. Losing Lite is a normal degradation to `CORE`, not a fault.

**Nexus owns the reader, not the verifier — and its absence fails closed.** The
verifier is injected. The default, `refuse_everything`, verifies nothing and
admits nothing, so a caller that forgets to supply one gets a node running on
`CORE` with no Lite data. The opposite default — admitting what it cannot check
— is the one failure this module must not be able to have.

**Any exception from verification is a refusal.** Knowledge's own
`negative.json` warns that the truncated fixture produces no `BUNDLE_*` code at
all, because the tar decoder raises first: *"a reader that catches only the
verifier's own exception type will let this through as an unhandled error"*. So
the reader catches `Exception`, deliberately, narrowly around the verifier call
and the extraction call.

**Staging is not admission.** Two of Knowledge's negative fixtures write bytes
into staging *before* failing — the truncated one leaves four complete,
digest-checked files there. Promotion happens only after a verdict of admitted,
never as a side effect of having written something.

## 3. Expiry is a serving decision, not a verification failure

The `expired` fixture is a **valid, correctly signed artifact that passes every
gate**. Expiry has no manifest field and no filename convention; it is carried
per claim and evaluated by the consumer against its own `as_of`.

So a conforming reader admits that artifact and then serves no expired
indicator from it. An expired claim is **unavailable, not merely labelled** —
it does not appear in the served list at all. The artifact around it is not
discarded: static reference material, which is versioned rather than dated,
keeps being served. That is what makes "withheld the expired entries"
distinguishable from "threw the artifact away".

An expiry that cannot be parsed is withheld too, and reported as `UNKNOWN`
rather than `EXPIRED`, so the operator plane can see that the artifact is the
problem and not the clock.

## 4. Capability degrades; authority does not move

`CORE`, `LITE` and `FULL` are capability states, not authority levels
([capability model](capability-model.md) §1). Every failure above lands on
`CORE`, and none of them moves or widens an authority — Azazel-Edge's
deterministic arbiter holds it in every state.

`capability.py` contains no authority concept at all, and a test asserts that
absence by name, because an absence is exactly what a later change quietly
fills in.

A core capability is never sourced from an optional component, so losing every
optional component at once leaves the core set intact. The converse is treated
as a different kind of event: a node missing a core capability is **broken**,
not degraded, and `state_for` refuses to report it as a lower state.

## 5. The fixtures are Knowledge's bytes, not ours

`tests/fixtures/knowledge-lite/` holds a copy of what
`Azazel-Knowledge/tools/lite_fixture.py emit` produces, with every digest
recorded in `PROVENANCE.json` and cross-checked against the digests Knowledge
states in its own `negative.json`.

Forging broken artifacts locally was rejected, for Knowledge's own stated
reason: *"A locally forged broken artifact differs from what Knowledge emits in
ways nobody can enumerate."*

**A known limit.** The copy is a snapshot. If Knowledge's emitter changes, this
copy goes stale silently — nothing in this repository can detect that, because
this repository cannot reach Knowledge. `PROVENANCE.json` records the source
revision and the command to regenerate. Stating the limit is the best that can
be done here; pretending the copy tracks upstream would be worse.

## 6. What this does not establish

- That Nexus verifies Knowledge Lite artifacts. **It does not.** It consumes a
  verdict from a verifier it does not own, and refuses when it has none.
- That any trust policy has been decided. What is trusted, and on what anchors,
  is a separate concern ([contract ownership](contract-ownership.md) §4) and is
  not settled here.
- That commissioning, activation, or a release exists. None does.
- That the behaviour has been observed on hardware. It has not; these are unit
  tests on artifacts, not a node.
