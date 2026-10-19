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

The installed store root is `/var/lib/azazel/knowledge`; daemon trust is
commissioned separately under `/var/lib/azazel/lite-trust`. A caller supplies neither.

| path | what it holds | who writes | ceiling |
| --- | --- | --- | --- |
| `/var/lib/azazel/knowledge/inbox` | artifacts an operator placed | the operator | 32 entries considered, 256 MiB each |
| `/var/lib/azazel/lite-trust/trust/anchors.toml` | the commissioned trust root | commissioning | — |
| `/var/lib/azazel/knowledge/admitted` | the one artifact in use | the import service | one file, replaced atomically |
| `/var/lib/azazel/knowledge/quarantine` | refused artifacts, held | the import service | one file per refusal |
| `/var/lib/azazel/knowledge/state/watermark` | the anti-rollback counter | the import service | one integer |

The import creates `admitted/`, `state/` and `quarantine/` as `0750` (keeping
an inherited setgid bit) and removes group/other write from any it finds
loosened, whatever the importer's umask. Under the setgid operator-group store
root, a group-writable `admitted/` or `state/` would let any member swap in an
older validly signed bundle or remove the watermark: serving re-verifies the
signature and the anti-rollback watermark. Files are written `0600`.

Serving refuses a bundle below the watermark. A missing or malformed watermark
with a bundle present makes the store untrusted and blocks import until an
operator restores the state. Import inspects existing store files for regular
file type, single link, effective-uid ownership and absence of group/other write;
it records unsafe state as `lite.import.state_untrusted` and directory tightening
as `lite.import.store_tightened`, naming only directory roles.

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
`lite.import.rolled_back`, `lite.import.state_untrusted`,
`lite.import.store_tightened`, `lite.serving.stopped_by_revocation`. A status read
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

## Milestone 1 daemon status

`az-knowledge-lited` takes no command-line arguments and serves
`knowledge.status`, with no arguments, and `knowledge.lookup` on
`/var/lib/azazel/run/knowledge/knowledge.sock`. The verb admits OPERATOR and
SERVICE; production service principals are limited to `azmioentry`,
`azarbiter` and `azmio` (the locald systemd User). Lookup admits SERVICE only. Kernel credentials and the shared `PrincipalPolicy`/transport
perform admission. Protocol refusals go to this daemon's
`/var/lib/azazel/state/knowledge/refusals.jsonl`.

The installed store root is `/var/lib/azazel/knowledge`, as listed in §7 above.
`LiteImport` still owns
`inbox`, `admitted/current.tar.gz`, `quarantine` and `state/watermark`. The
daemon never imports, repins, accepts revocations, promotes or repairs files.
A successful status request writes neither store nor trust nor a read event.

Trust is a separate commissioner-owned root, `/var/lib/azazel/lite-trust`,
read-only to the daemon. Its `trust/anchors.toml` supplies the bundle's key IDs,
threshold, signer-role, security-epoch and export-policy constraints. These
keys are intersected with the current `TrustStore` pin (`trust.json` or the
repinned `trust-current` generation). Store-local `knowledge/trust` anchors
are deliberately ignored by daemon status. Existing import admission remains
on its existing route; commissioning must provision compatible public anchor
metadata and pins before daemon status can report availability. Missing or
inconsistent metadata never causes a fallback to store-local trust.

`KnowledgeLite`'s content-addressed generations (`live`, artifact/signature
objects) are a different storage format from `LiteImport`'s tar store. The
daemon does not point `KnowledgeLite.read` at the tar store or pretend that
repinning imports a bundle. The read-only `lite_import.status_summary` adapter
verifies the tar and uses `KnowledgeLite.revocations` at the trust root for
the existing commissioned policy, role separation and continuity checks.
The commissioning digest comes from the commissioner-written current trust
record and must match its revocation policy; this is public trust-record
consistency, not a fresh commissioning evidence/activation attestation.
Signed revocations and their continuity record also reside at the trust root.
The bundle version is checked against revoked generations; its archive digest
and verified signing keys are checked against the cumulative revocation list.

The result has exactly four keys:

| key | values |
| --- | --- |
| `state` | `available`, `stale`, `unavailable`, `quarantined` |
| `reason_code` | `available`, `stale`, `unavailable`, `no_bundle`, `quarantined`, `bundle_refused`, `state_untrusted`, `revoked`, `unverified`, `trust_unreadable`, `store_unreadable` |
| `generation` | verified bundle version (at most signed 64-bit maximum), otherwise null |
| `freshness` | `current`, `stale`, `absent` (time-bound claims axis) |

`state_untrusted` means the admitted bundle is below the anti-rollback watermark
or its watermark is missing or malformed; no bundle is served.

Static references can make the state `available` while freshness is `stale`
or `absent`; the existing three-axis bundle rules still apply. No claim body,
key, digest, filesystem path or exception text appears in the reply.
Unreadable store/trust yields `unavailable`; missing, malformed or unverifiable
revocation policy/list yields reason `unverified`. The daemon continues to
answer diagnostics in these conditions. A refused admitted tar or a store
holding only quarantined artifacts reports `quarantined`. None of these
states changes Edge readiness, leases, enforcement or deterministic authority.


## Bounded advisory context lookup

`knowledge.lookup` accepts exactly `{"technique_ids": ["T1110", "T1110.001"]}`
as its arguments, no payload. The list has at most eight items, each matching
`T[0-9]{4}(\.[0-9]{3})?`. Empty lists return no context. Unknown arguments,
invalid IDs and OPERATOR-only principals are refused by the existing transport
and `PrincipalPolicy`. `azmio` is included in the daemon's resolved service
accounts; `knowledge.status` retains its existing admission and response shape.
No import, trust, revocation or promotion authority is added.

The response has `refs` (at most sixteen items) and `reason_code`. The daemon
retains a deterministic prefix fitting a 60 KiB JSON envelope, including ASCII
escaping overhead, below the existing 64 KiB transport limit. Each frozen
library `KnowledgeRef` carries `technique_id`, `name` (120 characters maximum),
`summary` (240 maximum), `claim_id`, `bundle_digest`, and `freshness` (`current`
or `static`), plus `source_kind: knowledge_lite`, the authenticated bundle
`generation`, and `trust_check: verified`. These are read-time provenance,
not approval or authority. `attack_stix.flatten` obtains technique IDs from MITRE external
references and preserves the technique name and description; Knowledge's native
ATT&CK table uses `technique_id` as the stable primary key. That key is both
`technique_id` and `claim_id` here, qualified by the authenticated bundle digest.
A STIX object UUID is not invented. Descriptions become plain text summaries
with HTML, Markdown formatting and links removed, whitespace collapsed, then
truncated. Missing descriptions produce an empty summary, as in the pinned
producer fixture. A missing or empty name is not served.

`lite_import.lookup_context` returns a tuple; `lookup_context_reading` exposes
the same tuple plus a fixed `reason_code`. `available` means at least one
reference. `no_context` means an empty query or no matching usable row (including
expired rows). Trust, revocation and storage failures use the existing status
reason codes. None raises merely because context is absent. Selection follows
`iter_served` in sorted member and row order, retains only sixteen references,
and ignores repeated query IDs. Current claims pass the existing expiry check;
rows without `agg_next_expiry` are static references. Authentication still reads
and verifies the bounded archive in full; streaming selection does not imply
constant-memory archive verification or a new admission path.

Each lookup rechecks the same separate commissioned trust, signatures
and cumulative revocations as status; a repin observed during the read withholds
the result. Only the admitted tar is read. Lookup audit events contain requested
technique IDs and the result count, never names or descriptions. Status remains
free of read events. Existing protocol refusal auditing remains in place.

`azazel_nexus_runtime.knowledge_client.lookup_context` uses the existing
AF_UNIX exchange with a default 0.5-second monotonic deadline, verifies the
`azknowledge` socket owner and peer credentials, and validates the bounded
response. Missing context returns an empty tuple; transport, deadline, invalid
response and unavailable trust/store conditions raise only
`KnowledgeUnavailable("knowledge unavailable")`. Locald main wires this client and maps
that exception to its unavailable audit path, continuing without knowledge.
No network request or retry occurs.

The installer creates a separate service-client socket directory,
`/var/lib/azazel/run/knowledge-read`, mode `2710`, owned by
`azknowledge:azknowledge-read`. Knowledge Lite binds `knowledge-read.sock`
there with mode `0660`, alongside the unchanged operator socket at
`/var/lib/azazel/run/knowledge/knowledge.sock`. Both use the existing transport
and PrincipalPolicy; lookup still admits SERVICE only. Locald's generated unit
has `SupplementaryGroups=azknowledge-read azmission-read`, and its client checks
the dedicated socket GID as well as the `azknowledge` owner and peer credentials.
`azmio` never joins `azazel-operator` and cannot reach audit, commissioning,
watchdog or fetch sockets through these groups. Operators retain their existing
socket and status access. No ACL tools are required.
