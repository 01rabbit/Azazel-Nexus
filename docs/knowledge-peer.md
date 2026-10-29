# Commissioned Knowledge peer advisory integration

This is the Nexus software side of issue #6. A real AZ-04 node and its
production protocol interoperability remain out of scope. The loopback peer
implements the Nexus fixture protocol below; it is not evidence of a deployed
AZ-04 service. No peer is commissioned by default. No daemon, CLI endpoint
option, automatic discovery broadcast, runtime URL or network dependency is
installed. The existing CLI's “no module endpoint is configured” semantics
remain unchanged.

**The protocol below does not interoperate with the real Azazel-Knowledge
API.** They share no endpoint, transport, authentication, request or response
shape; see [the comparison](#the-real-knowledge-api-and-this-protocol). No
production code constructs a `KnowledgeClient` (no daemon or CLI calls it), so
nothing on a node depends on this protocol today. Knowledge reaches a node
through the signed Lite bundle instead ([Knowledge Lite consumer](knowledge-lite-consumer.md)).

## Boundaries and reuse

`src/azazel_nexus/knowledge_peer.py` makes pure decisions. It reuses
`ProviderRecord` for endpoint validation, the existing signature verifier,
and the P0/P1/P2/P3 sanitizer. Separate registry, capability and response
signing domains prevent cross-document signatures. The signing wire format
is the existing detached Ed25519 signature (64 bytes), followed by canonical
UTF-8 JSON. Canonicalization sorts keys, uses compact separators and rejects
non-finite numbers. Schema is `azazel-nexus/knowledge-peer/1`.

`runtime/src/azazel_nexus_runtime/knowledge_egress.py` is the only new network
module. Its explicit entry in `EGRESS_EXEMPT` and the exact-set boundary test
record why the boundary grew: Knowledge needs mTLS negotiation and retrieval.
The library, route selection and remote trust still cannot open connections.
The client reuses inference egress's mTLS context builder and SPKI pin verifier.
It never changes the cognition provider registry or its allowlist.

## Commissioning and discovery

An operator supplies registry-role public keys and the local commissioning
digest to `load_registry`. Inputs are bounded signed bytes, not locations.
The document has exactly `schema`, `commissioning_digest`, `issued_at`,
`expires_at`, positive integer `version`, and `peers`. A peer entry has:

- `endpoint`: the existing ProviderRecord fields. `provider_id` is a symbol;
  `model_id` must be `knowledge-v1`, and `path_template` must be `/knowledge/v1`.
  Hostname, port, SPKI pin, client identity name, privacy classes and all
  request limits are signed commissioning data.
- `addresses`: a nonempty list of numeric IPv4/IPv6 addresses. The client uses
  the first address, with no DNS lookup or alternate destination retry.
  Hostname verification still checks the signed hostname. This avoids an
  unbounded resolver call and makes the destination allowlist exact.
- `public_key`: the peer's Ed25519 public key as 64 hexadecimal characters.
  Registry signing material cannot also be the peer signing material.
- `max_inflight`: an integer from 1 through 8.

Registry-role keys must be commissioned separately from other registry and
artifact roles by the provisioning caller. Signature domains remain distinct
even if a caller misconfigures those other roles. Registry expiry and
commissioning binding are checked before resolution and again before sending
context. There is no peer symbol resolution without a verified registry.
Registry version is metadata, not a durable anti-rollback counter; installation
and lifecycle of commissioned registry generations belong to provisioning.

The trusted runtime constructs one `KnowledgeClient` per service from that
registry, a CA file and an identity-name-to-certificate/key mapping. Keys and
paths never travel in queries, registries or events. There is no commissioning
CLI or runtime state leaf added in this lane. A missing commissioned identity
or unusable TLS material refuses client construction.

## Protocol and limits

A retrieval generates an opaque 128-bit correlation token. Privacy eligibility
and sanitizer application happen before any peer connection. P2-mission and
P3-restricted never leave, P1 requires policy admission, and an unknown class
is denied. The same sanitizer applies to P0 when commissioned. Policy failures,
unlisted fields and excessive size produce local fallback. The mission scope
and alias key remain local; identity fields become scoped aliases, and
redactions are absent from transmitted content.

The client first POSTs `{schema, correlation}` to
`/knowledge/v1/capabilities`. The signed response has exactly `schema`,
`peer_id`, `correlation`, `issued_at`, `expires_at`, `versions: [1]` and
`capabilities: ["advisory-context"]`. Only a fresh response signed by the
commissioned peer key under the capability domain admits the query.

Then the client POSTs `{schema, correlation, query}` to `/knowledge/v1/query`.
`query` is the sanitizer's complete output, including its policy version,
privacy class and redaction reference. The signed response has exactly
`schema`, `peer_id`, `correlation`, `issued_at`, `expires_at`, `bundle_version`,
`facts` and `inferences`. The two content fields are separate lists of at most
64 nonempty strings, each at most 2048 characters. Unknown fields, including
execution/action fields, are refused. Empty context is refused. Bundle version
is bounded to 128 characters. Issuance and expiry require timezone-aware
instants and are compared as UTC instants, including equality at expiry.

Every connection checks the commissioned CA, dates, hostname and SPKI pin,
and presents the commissioned client identity. Pin validation precedes HTTP
traffic. Only HTTP/1.1 200 with one bounded Content-Length is accepted;
redirects, transfer encodings, duplicate headers and truncated bodies refuse.

Limits are signed and additionally hard-capped: requests at 64 KiB, signed
responses at 256 KiB, headers at 8 KiB and the network exchange at 10 seconds.
After local sanitization, one total deadline covers both connections, TLS
handshakes, negotiation, sending and reading. Pending queue capacity is **zero**: an occupied semaphore
returns fallback immediately. There are **zero retries** and no alternate
address attempts. A service must retain one client instance so its concurrency
bound covers all requests. These calls belong on the advisory path; they must
never be awaited by deterministic Edge decision/enforcement work.

## Local-first and degradation

`retrieve` takes a current LiteReading produced by the existing verified Lite
service. A usable embedded cache answers locally without network traffic.
`deeper=True` explicitly requests optional full-node depth; a missing cache may
also try an admitted peer. Successful retrieval yields `full-node context`.
Any refusal yields `embedded cache` if the current local reading serves claims,
otherwise explicit `no-context`. Stale/quarantined/unavailable caches are not
promoted to usable context by this adapter.

Every KnowledgeReading records source class, correlation, asset/bundle
version, freshness and trust. Its event contains metadata only, excluding
claims, facts, inferences, raw frames and key material. Peer context retains
facts and inferences separately. `blocks_core()` is always false. Knowledge
supplier vocabulary in integration remains advisory; readiness, Edge
presence, authority, leases and enforcement claims are unchanged.

## Verification and remaining evidence

`tests/unit/test_knowledge_peer.py` reuses the inference loopback server and
committed test-only TLS fixtures, including `server-fetch` for its valid
commissioned DNS name. Ed25519 signing keys are deterministic test-only keys
created with PyNaCl. Tests cover local/default no-network behavior, privacy,
sanitizer denial, registry trust and expiry, capability/version decisions,
queue/request bounds, the three supply states, authority invariance, and
end-to-end valid retrieval plus invalid signatures, expiry, mTLS rejection,
pin/name/issuer/date failures, malformed responses, redirects, truncation,
response limits and timeout. Loopback tests intentionally do not skip if bind
is forbidden; report those as environment-blocked, not passing evidence.

The actual AZ-04 protocol and signed capability format must be agreed with
Azazel-Knowledge before production interoperability can be claimed. A real
peer, its commissioning/revocation lifecycle and deployment wiring remain
outstanding. This change does not close that part of issue #6.

## The real Knowledge API and this protocol

Read from Azazel-Knowledge `2445c1b` (`src/azazel_knowledge/api/`,
`security/auth.py`, `ops/docker-compose.yml`). Rows marked *measured* were
observed against that revision's API started in a disposable container during
the Fabric/Knowledge survey of 2026-10-28; the rest are from the code. No Nexus
code has exchanged a request with the real API.

| | This protocol (`knowledge_peer.py`, `knowledge_egress.py`) | Real Knowledge `/v1/context` |
| --- | --- | --- |
| Endpoints | `POST /knowledge/v1/capabilities`, then `POST /knowledge/v1/query` | `POST /v1/context` (plus `/v1/health`, lookup, ingest and admin routes). `/knowledge/v1/capabilities` answers 404 (*measured*) |
| Transport | mTLS required: commissioned CA, signed hostname, SPKI pin, client certificate; numeric address from the signed registry, no DNS | **Plain HTTP**: gunicorn/uvicorn binds `0.0.0.0:8443` with no TLS settings. Knowledge `docs/api.md` says "mTLS optional"; nothing implements it |
| Authentication | Client certificate only; no `Authorization` header is ever sent | **Bearer token** `azcti_<key_id>_<secret>` with the `query` scope, required on every endpoint; no token is `401 missing_bearer_token` (*measured*) |
| Response authenticity | Ed25519-signed documents under separate capability and response domains, verified against the commissioned peer key | **Unsigned** JSON. Knowledge records the advisory in its own audit chain; nothing a client can verify comes back |
| Request | `{schema: "azazel-nexus/knowledge-peer/1", correlation, query}`, `query` being the sanitizer's whole output (policy version, privacy class, redaction id) | `ContextApiRequest{entities: [{type, value}], event, edge_id, actor_key, event_id, trace_id}`. Unknown fields are ignored, not refused: a Fabric `CtiContextRequest`-shaped body returns 200 (*measured*) |
| Response | exactly `schema, peer_id, correlation, issued_at, expires_at, bundle_version, facts[], inferences[]` | `threat_context, threat_score, confidence, reason[], confidence_reason[], recommendation, source_freshness, advisory_notice, advisory_id, multi_ioc_scope, engage_refs[], rule_refs[], reported_defensive_state, engagement_advisory, …`; Knowledge checks its own response with Fabric's `assert_advisory_only` |
| Expiry | `issued_at`/`expires_at` on every signed document, compared as UTC instants | no expiry on the response; `source_freshness` describes the data, not the answer |
| Requester identity | the client certificate's commissioned identity | the token's `key_id`; `edge_id` is a free string, and Fabric's `cti_contracts.SourceProduct` has no `nexus` |
| Size and concurrency | request 64 KiB, response 256 KiB, headers 8 KiB, 10 s total, `max_inflight` 1–8, queue 0, no retry | request body capped at 256 KiB (`api/limits.py`); no client-side bound is defined by the server |
| Privacy | P2/P3 never leave; P1 needs policy; sanitizer before any connection; redaction record stays local | the request carries entity values (`ip`, `domain`, …) as given; there is no privacy class or sanitizer contract on the server side |

What a real integration would need is tracked outside this document: an
adapter shaped like Edge's `engagement_advisory_client.py` (Bearer token by
reference, TLS through a lab CA proxy until Knowledge terminates TLS itself,
fail-closed response checks), and a Knowledge decision on response
authenticity. Neither is implemented here, and the loopback tests above do not
count as interoperability.

Related: [Knowledge Lite trust](knowledge-lite-trust.md),
[Knowledge Lite consumer](knowledge-lite-consumer.md),
[remote inference](remote-inference.md),
[runtime boundary](runtime-boundary.md).
