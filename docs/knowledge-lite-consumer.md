# The Knowledge Lite consumer: what happens when it cannot be read

Status: **functional** (`src/azazel_nexus/lite_bundle.py`,
`src/azazel_nexus/lite_import.py`, `src/azazel_nexus/lite_cache.py`), with
unit tests and an end-to-end stage against the artifacts Azazel-Knowledge
actually emits ([#67](https://github.com/01rabbit/Azazel-Nexus/issues/67)).

**`functional` here means one thing and no more:** a correct Knowledge Lite
bundle can be imported offline by an operator and its real claims served
read-only. It does **not** mean this node's cryptographic implementation is
supported — the hand-written Ed25519 verifier is under review
([#70](https://github.com/01rabbit/Azazel-Nexus/issues/70)) — nor that this
node has an AZ-04 peer at all, nor any share of Edge authority.

This is not a release, and nothing here is *verified* in the program's sense.

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

## 7. Offline operator import

The only supply route. There is no download, no peer connection and no
scheduler: an operator puts an artifact in a directory and the node reads it.

### The paths, their owners and their ceilings

Everything is derived from one commissioned root, `/data/azazel/knowledge-lite`.
A caller supplies none of it.

| path | what it holds | who writes | ceiling |
| --- | --- | --- | --- |
| `/data/azazel/knowledge-lite/inbox` | artifacts an operator placed | the operator | 32 entries considered, 256 MiB each |
| `/data/azazel/knowledge-lite/trust/anchors.toml` | the commissioned trust root | commissioning | — |
| `/data/azazel/knowledge-lite/admitted` | the one artifact in use | the import service | one file, replaced atomically |
| `/data/azazel/knowledge-lite/quarantine` | refused artifacts, held | the import service | one file per refusal |
| `/data/azazel/knowledge-lite/state/watermark` | the anti-rollback counter | the import service | one integer |

### The caller chooses an entry, and chooses nothing else

`import_entry` takes an **inbox entry id** and an instant. Not a cache root,
not a trust key, not a policy, not a generation number, not a quarantine
path. An entry id is the artifact's own content digest, so a caller cannot
spell a path with one, and an id that is not in a fresh enumeration is
refused rather than looked for somewhere else.

### A bundle's trust material is subject matter

The anchor is read from the commissioned location only. Trust keys, permitted
signer role, security epoch and accepted export policies come from
commissioning and never from the artifact. A bundle carrying a member named
like a trust or state file is **refused** — something that tried is worth
reporting rather than ignoring.

### Quarantine holds, and does nothing else

A refused artifact is moved under its digest and is never executed,
extracted, served or retried. The audit entry carries the digest, the instant
and a structured reason. **Never the bundle's content, a claim's body, or key
material.**

### The audit records transitions, not reads

`lite.import.started`, `lite.import.admitted`, `lite.import.quarantined`,
`lite.import.rolled_back`, `lite.serving.stopped_by_revocation`. A status read
writes nothing: a ledger that grew every time somebody looked at a screen
would be a ledger nobody can read.

## 8. What the operator sees

Four axes, because one word would collapse four different next actions:

```text
Knowledge Lite: functional
    bundle integrity: admitted
    time-bound intelligence: stale
    static reference: available
    cryptographic implementation: not supported (Nexus#70 review pending)
    functional means: a correct Knowledge Lite bundle can be imported offline
        by an operator and its real claims served read-only
    it does not mean: ...
```

| axis | values |
| --- | --- |
| bundle integrity | `admitted` / `quarantined` / `unavailable` |
| time-bound intelligence | `current` / `stale` / `absent` |
| static reference | `available` / `absent` |
| overall | `available` / `stale` / `unavailable` / `quarantined` |

The row above is the **expired** bundle: its indicators have all expired and
its ATT&CK reference material has not. It reads `available (static
reference)` overall while its time-bound line reads `stale`, because static
reference is usable Knowledge and does not stop being usable when an
indicator feed goes cold. Reporting it as serving nothing would send an
operator to replace an artifact that is working.

`stale` overall is the narrower case: admitted, and the only thing left is
expired claims. Readable as history, never applied automatically.

## 9. The fixture contract, and where it came from

`contract/azazel-knowledge-lite/` holds Azazel-Knowledge's own fixtures,
pinned. `contract/azazel-knowledge-lite/FIXTURE.json` is the source manifest:

| field | value |
| --- | --- |
| `source_repository` | `01rabbit/Azazel-Knowledge` |
| `source_revision` | `f29c29d1002881b416286e18aae65455c3623348` |
| `fixture_generator_command` | `python tools/lite_fixture.py emit --out DIR` |
| `artifact_digest` | SHA-256 of every file here |
| `knowledge_contract` | format version, kind, signature scheme, what the anchor decides |
| `purpose` | the canonical input #67 verifies against |

Determinism was checked before pinning: two emissions at that revision
produced byte-identical output for all eight files, and the digests match the
values Knowledge itself declares in `negative.json` and `expected.json`.
`PROVENANCE.md` beside it records the rest.

Six cases run in CI against those bytes — valid, corrupt-signature,
corrupt-payload, corrupt-truncated, expired, absent — and each refusal code
is compared against the `expected_error_code` the producer declares.

## 10. The interpreter floor

CPython **3.11 or newer**, because `tomllib` is the canonical reader for
`anchors.toml` and a hand-written partial TOML parser for the trust anchor of
a signed artifact would trade a dependency for an attack surface. The
installer refuses below it **before writing anything**; there is no fallback
parser and no partial mode. See [support matrix](support-matrix.md) §3.3,
where it is recorded as a software support baseline rather than a hardware
gate.
