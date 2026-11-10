# Nexus Knowledge Context consumer candidate (#395)

The semantic request/response belongs to Fabric's `knowledge-context/v1`
profile. Nexus imports it only through `fabric_boundary`, where the import is
deferred so CORE remains usable without the optional Fabric package. The
optional `fabric` extra pins the published Fabric `v0.10.0` tag, which
contains this profile as experimental functionality without a compatibility
promise (#402 and #403 are merged). Even with the profile installed, the
adapter remains unavailable unless its explicit transport configuration is
supplied; Knowledge Lite behavior is independent.

The Nexus envelope is separate from the Fabric payload. It binds `key_id`,
`issued_at`, `expires_at`, and the canonical response bytes under the
`azazel-nexus/knowledge-context-envelope/v1` Ed25519 domain. Verification
resolves the provider key through Nexus's commissioning-bound signed Knowledge
registry and requires `key_id` to equal that key's SHA-256 fingerprint. A
maximum TTL has no default and must be explicitly supplied. Fabric validates
the semantic request and response, including exact request/correlation/source
binding and the advisory-only fact/inference model. Nexus also requires the
signed `provider_id` claim to equal the commissioned peer ID. This binds the
claim to the signer selected by Nexus; it does not prove that any Knowledge
fact is true.

The adapter accepts P0-public queries only, even if local policy allows a
wider class. `KnowledgeClient.request_context()` opens an mTLS connection only
when explicitly called on a client with the local opt-in flag, commissioned
peer, client identity, CA and pin configured. The opt-in boolean is caller
configuration; it is not a Context capability in the signed peer registry.
The default-disabled broker composes that method behind the ordinary local path, but the
production commissioning loader and live credentials are absent and
activation remains withheld. Importing this module or installing the package
does not connect, load commissioned state, install a trust anchor, or alter
service startup. The response is a bounded advisory object; it cannot grant
authority or alter Edge's deterministic decision path.

Status: **isolated software path in development; production commissioning is
not wired**. The service boundary and local request path described below are
implemented. No production registry/credential loader or
systemd egress allowance is supplied, so activation remains withheld.

## Process boundary

Ordinary `mio.local.assess` requests still arrive at `azazel-mio-locald` over
its existing AF_UNIX socket. The P0 label on an incoming question is a caller
assertion, not proof that its content is public. The broker checks the label
and applies the commissioned field allowlist and named redactions, but does
not classify arbitrary free text. Production commissioning must restrict
which trusted local inputs can set this label and which question fields can be
sent; untrusted text must remain local. Locald submits the bounded frame to the dedicated
`azazel-knowledge-contextd` broker over a second AF_UNIX socket. Only the
`azmio` local runtime account is in the socket's client group. Locald keeps
`PrivateNetwork=yes` and `IPAddressDeny=any`; `azremote` and its Provider
Registry remain separate.

The broker fixes privacy class to P0-public and calls `KnowledgeClient` with a
commissioned sanitizer policy, mission alias and client identity. It returns
only the already verified response. Broker requests have a 16 KiB frame cap,
responses have a 48 KiB cap, the caller deadline applies end to end, and there
is one in-flight request with no queue or retry. A missing, disabled, expired,
untrusted, oversized or late result becomes a fixed refusal; local FAST_ASSESS
continues without external context. The response is advisory only.

The Nexus fast-assessment response may carry the optional, Nexus-owned field
`full_node_context_status`: `not_queried` means no broker request was made,
`received` means the broker returned a response for M.I.O. to evaluate, and
`unavailable` means an attempted broker request failed. This transport state
is separate from the shared M.I.O. `dependency_outcome` and from Knowledge Lite.
It does not assert that source claims are verified or that a received snapshot
is complete. If Lite is available while the full node is unavailable, the Lite
result remains available and the full-node failure remains visible in the
separate field. Older or degraded fast-assessment responses may omit the field.

The incident snapshot and operator UI show a separate full-node status and,
when an advisory is present, its source kind, unverified trust, snapshot state,
generation and expiry times. Only fixed limitation messages are displayed;
producer limitation text, subjects and opaque identifiers are withheld. An
expired receipt is labelled expired in the UI even if its stored snapshot was
previously current. This display depends on the operator device's clock and is
re-evaluated when the screen is redrawn; it is not an independent trusted-clock
verification. A new incident transition does not reuse the earlier
full-node receipt while its new explanation is pending.

The ordinary P0 entry sends a `question`, not a typed IOC. The candidate
Knowledge producer cannot normalize that type as an IOC and reports it as an
unknown rather than asserting an exact match. This entry establishes bounded
question/unknown interoperability only; typed-IOC lookup requires a separate
contract and must not reclassify restricted incident data as P0.

The service uses the separate `azknowledgeegress` account. The installed unit
is preset disabled, requires its activation grant marker and is absent from
`wired_capabilities()` because no production commissioning loader exists yet.
Its unit retains `IPAddressDeny=any` and has no `IPAddressAllow` entry. Thus
installation does not start it and this candidate cannot reach a Knowledge
peer. The broker's default constructor is closed even if started manually.
The new per-request audit ledger has no retention or disk quota in this
candidate; production activation needs an explicit storage and retention policy.

## Commissioning and credentials

No live credential or trust material is included. Before a live connection is
implemented, an owner must be named for the client certificate/private key,
Knowledge response-signing key and CA trust; their issuance and expiry windows,
rotation notification, revocation source, emergency disable and recovery
procedure must be recorded. The broker must use its own commissioned registry
and identity, never `azremote` credentials or the Provider Registry. A
commissioned endpoint allowlist is also required before any network allowance
can be designed. Until those conditions are met, activation remains withheld.

The open ownership and lifecycle items are:

- endpoint, CA and client-certificate provision owner and accepted trust anchor;
- Knowledge response-signing registry owner and key identifier assignment;
- certificate/signing-key validity, rotation approver and overlap period;
- numeric maximum response TTL;
- revocation authority and notification route; and
- emergency disable and recovery procedure.

The #402 adapter can open a socket only through an explicit enabled client call
with commissioned transport inputs. This #403 change adds the optional local
process boundary without supplying the production registry, credentials,
trust anchor or network allowance; those commissioning decisions remain open.

## Isolated acceptance matrix (software only)

`tests/unit/test_knowledge_context_acceptance.py` drives the ordinary entry
(`LocalRuntimeService` FAST_ASSESS) through a real `KnowledgeClient` and
`KnowledgeContextBroker` against a synthetic producer on loopback mTLS, using
test-only PKI and a test-only signing key. It needs the `fabric` and M.I.O.
extras and skips without them. The AF_UNIX hop between locald and the broker
is replaced by a direct call whose deadline arguments are built in the test,
not by the real socket client; that hop stays covered by the isolated
real-process runner. The matrix asserts:

| Case | Expected result |
| --- | --- |
| valid response for the request | `received`; advisory is `advisory_only`, `source_reported_unverified`, `unverified_advisory_only`; source kind, snapshot state and generated/expiry times reach the stored projection; one producer call; audit holds fixed event names, outcomes and size/time numbers, no content |
| same inputs, Knowledge refused vs. received | every field outside the Knowledge-context fields is identical: the advisory cannot change observations, hypotheses or any decision field |
| bad signature, tampered payload, expired envelope, wrong key id, wrong request id, wrong provider id, HTTP 500, non-envelope body, oversized body, producer absent | `unavailable`, no advisory, local assessment still `assessed`, no producer text or snapshot reference anywhere in the result, projection or audit |
| producer slower than the Knowledge wait budget (0.25 s in locald) | request reaches the producer, is abandoned at the budget, `unavailable`, local assessment completes |
| earlier valid signed answer replayed for a new request, with a fresh client and broker (not a process restart) | refused; a later honest answer is accepted again |
| non-P0 frame, or the shipped uncommissioned broker | producer never queried (`not_queried`); broker returns a fixed `unavailable` |

Not established by this matrix: operator-UI rendering of an expired receipt
(covered by UI tests), a typed-IOC lookup (not in contract), the Linux
peer-credential and systemd confinement (real-process runner), and any real
credential, trust anchor or network.

## Open items before any real connection

Nothing in this repository authorizes a live connection. The items below are
open and undecided; they are listed, not proposed as policy, and none is
satisfied by this software:

1. The open ownership and lifecycle items listed under *Commissioning and
   credentials* are decided and written down, including the numeric maximum
   response TTL.
2. A production commissioning loader and registry exist; today the broker
   factory is closed by design and an injected client is available only to
   tests.
3. Which trusted local inputs may set the P0 label and which question fields
   may be sent (stated above as required; not yet defined).
4. An endpoint allowlist is approved before any `IPAddressAllow` is designed;
   this package supplies none.
5. The per-request audit ledger gets an explicit retention and disk-quota
   policy.
6. The activation grant for `azazel-knowledge-contextd.service` is issued by
   the existing activation path, not by editing the unit.

Stopping and recovery use mechanisms that already exist: the unit is preset
disabled and starts only while its activation grant marker is present, so
removing the grant through the activation path or stopping the unit returns
FAST_ASSESS to `unavailable` (the request fails closed) with Knowledge Lite and
local assessment unchanged. The broker keeps no response cache, so there is nothing
stale to clear after a restart. How a revoked or expired peer key is replaced
is one of the open items above and is not defined here.

## Verification scope

Unit tests cover caller injection refusal, P0 binding, payload bounds and the
disabled default. The isolated real-process test starts locald, the broker,
and Knowledge as separate processes with synthetic certificates and loopback
transport, and asserts the verified advisory response reaches ordinary
FAST_ASSESS. The current candidate has passed this software test. The fixed
head, repository identities, build artifacts and exact results are recorded
in the #403 PR evidence. This does not establish production credential
lifecycle, systemd egress, hardware, release or deployment.

The candidate does not set a production dependency pin to an unreleased Fabric
commit. Product packaging continues to use the accepted Fabric tag until the
normal version and offline-wheel review updates it.

For current implementation and test status, see [M.I.O. runtime](mio-runtime.md)
and [operations](operations.md).
