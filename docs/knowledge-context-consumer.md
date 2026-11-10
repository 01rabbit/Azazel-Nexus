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
The default-disabled broker composes that method behind the ordinary local path.
It is enabled only by the root-owned commissioning bundle described below;
live credentials are not supplied and activation remains withheld. Importing this module or installing the package
does not connect, load commissioned state, install a trust anchor, or alter
service startup. The response is a bounded advisory object; it cannot grant
authority or alter Edge's deterministic decision path.

Status: **isolated software path in development**. The service boundary, local
request path and commissioning-bundle loader described below are implemented.
No credentials, endpoint or systemd egress allowance is supplied, so
activation remains withheld. No environment variable or command-line option
can enable egress; only a complete, root-owned commissioning bundle can.

## Commissioning bundle

`az-knowledge-contextd` reads `/etc/azazel/knowledge-context/commissioning/`
once at start. Absence means closed. `AZAZEL_ROOT` is for tests only: when
it is set, that directory is trusted as the starting point and neither it nor
its ancestors are inspected; it can only relocate where a bundle is read from,
and a complete, root-owned bundle is still required, so it does not enable
egress. Secret files (`client.key`, `alias.key`) are owned by root. Other-readable
secrets are refused (`perm_unsafe`). Group-readable secrets are accepted only
when `st_gid` is the daemon's effective gid or gid 0; any other group is
refused (`perm_unsafe`). A secret the daemon cannot open is `path_unsafe`; in
particular a `root:root` 0600 file cannot be read by a non-root daemon and is
reported as `path_unsafe`. The service-group form is `root:<service group>` 0640.
The directory is flat and holds exactly: `manifest.json` (schema, `enabled`
must be JSON `true`, peer_id, client_identity, commissioning_digest,
max_ttl_seconds, mission, sanitizer_policy; no defaults), `registry-keys.json`,
`registry.signed`, `ca.pem`, `client.pem`, `client.key`, `alias.key` (at least
32 bytes). Every ancestor and file must be root-owned and not group/other
writable, files are opened without following symlinks, must have one link and
a bounded size, and `client.key`/`alias.key` must have no other-user access.
A signed registry alone never enables egress. The loader performs no network
I/O. A refusal is recorded once as `knowledge.context.commissioning` with a
fixed `reason_code`, and the broker stays closed. Removing or replacing
`manifest.json` while running closes the client until restart.

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
peer-credential and systemd confinement (see the Linux isolated acceptance section), and any real
credential, trust anchor or network.

## Linux isolated acceptance (unit 29)

`tests/real_process/test_knowledge_context_linux_acceptance.py` runs in the
existing isolated root container (`run-docker.sh`: `--network=none`, no new
capabilities, read-only mounts, `--rm`), with a real Knowledge mTLS producer
process, the real broker, locald and entryd processes, distinct container-only
uids and real `SO_PEERCRED` / `SO_PEERGROUPS` on real AF_UNIX sockets. It
changes no product code. Two harness seams exist, both test-only: the
producer wrapper fixes the signing seed and port across restarts, and the
broker harness can record the producer envelope and, while a control file
exists, offer an earlier envelope at the network edge (`_post_path`). The
signature, lifetime and request-binding checks that follow the edge are the
product's own.

### Peer authentication (area A)

| Case | Result observed |
| --- | --- |
| service peer `azmio` in the client group | served |
| `azoperator` / `azmioentry` placed in the client group (so the filesystem passes) | refused inside the broker with `principal_denied`; the broker audit holds the kernel uid, the verb, no `requested` event and no producer exchange; root is refused the same way |
| service uid or operator uid outside the client group | `EACCES` at `connect` (this includes the effect of the 2710 parent directory; socket mode alone is not isolated) |
| identity named in the request | at the top level or in `arguments`: `client_asserted_principal` from an allowed peer; a denied peer naming an allowed uid is still `principal_denied` (principal is checked first) |
| client against an impostor socket | wrong owner, mode or group: refused before connect and nothing arrives; correct file attributes but the process behind the socket is another uid: refused as `peer identity` after connect and no request byte is sent |
| missing peer credentials | a real non-AF_UNIX peer reports pid 0, uid/gid -1; the function-level check shows the server never reaches the handler. A daemon only ever listens on AF_UNIX, so this is a function-level observation, not a daemon test. The client branch `pid <= 0` (a peer in another PID namespace) is not verified |
| restart and socket regeneration | orderly stop removes the socket; a crash leaves a stale socket that refuses connects; the restart recreates it with the same owner, group and mode and the same allow/deny results. The shipped `main()` has no SIGTERM handler, so even SIGTERM leaves a stale socket (the restart replaces it) |

### systemd: static versus effective (area B)

Static (`tests/unit/test_knowledge_context_systemd_static.py`, host and Linux):
the shipped unit declares `User=azknowledgeegress`, `NoNewPrivileges`,
`ProtectSystem=strict`, two `ReadWritePaths`, `PrivateTmp`, `PrivateDevices`,
`Protect*`, `RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`, empty capability sets,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `IPAddressDeny=any` with no
`IPAddressAllow` (so the package as shipped cannot egress), `UMask=0027`, the
activation `ConditionPathExists`, and `Type=notify`; the installer's directory
modes match the daemon's socket and state paths. This shows the files agree,
not that the kernel enforces them.

Effective: **real systemd was not run.** The images have no systemd and running
one as PID 1 needs a privileged container with cgroup access, which this
acceptance does not add. A `setpriv` approximation runs the real daemon as a
non-root uid with no-new-privs, an empty inheritable/effective/permitted
capability set and umask 0027, and shows: the socket and ledger attributes,
the fixed refusal from the uncommissioned factory, `principal_denied` in the
daemon's own ledger, `setuid(0)` and `chown` failing with `EPERM`, a write
outside the state area failing with `EACCES` (ordinary file permissions, not
`ProtectSystem`), and the daemon refusing to start when its state area is not
writable or its ledger is corrupt or torn (no socket is bound). **Not
effective in that environment:** `ProtectSystem`/`ReadWritePaths` (mount
namespace), `PrivateTmp`, `PrivateDevices`, `Protect*`, `RestrictNamespaces`,
`RestrictAddressFamilies` and `SystemCallFilter` (seccomp),
`MemoryDenyWriteExecute`, `IPAddressDeny` (the container network is simply
off), the bounding set (the runner's capability set stays in the bounding set; the process holds none effective), `ConditionPathExists`, restart policy, and the `Type=notify`
handshake (`systemd_notify` requires a real systemd context and is not
simulated). Paths are relocated with `AZAZEL_ROOT`, not the real
`/var/lib/azazel`. Needed for real acceptance: a disposable VM or a container
run with a real systemd and cgroup delegation, with the decision to allow it.

### Replay across restarts (area C)

The only replay defence is request binding: each call generates a fresh
128-bit `request_id` in the broker (`make_request`), the producer's signed
envelope carries it, and the answer is validated against that request. There is
no replay state to persist, and none was added. Observed, with the producer
real and the envelope still inside its signed lifetime: after the broker is
stopped (SIGTERM or SIGKILL) and restarted, an earlier valid envelope offered
for a new request is refused as the fixed `unavailable`, and a direct control
call shows the same envelope is accepted for its own request and refused for
the new one (so the refusal is by binding, not expiry or signature). A new
request then succeeds, so there is no permanent refusal. A producer restart
with the same key and port needs no broker restart; a producer restart with a
different key (Knowledge's fixture default) is refused (recovery presumably needs an operator registry key update; not exercised here, and an open commissioning step). Six
concurrent callers: every served answer belongs to its own request and none is served twice, and the rest receive `timeout` or `unavailable`. The audit ledger
is the only durable state; an empty ledger starts, a corrupt or torn one stops
the daemon before it binds. These show the broker keeps no state across a
restart, not a protection specific to restarts. locald and entryd keep no
state either, so restarting them changes nothing for this property.

### Clocks (area D)

| Use | Clock | Observed |
| --- | --- | --- |
| signature validity, TTL, semantic generated/expiry, registry validity | wall clock (`KnowledgeClient.utc_now`) | window is [max(issued, generated), min(expires, semantic expiry)); one microsecond before the start and at the end are refused; no grace; unparseable, naive, empty or non-string time is refused |
| MIO expiry | wall clock of the MIO side (`datetime.now` in `mio_fast_assistance`, taken after the broker returns) | `now` before `generated_at` is rejected; `now` at `expires_at` is dropped with `KNOWLEDGE_CONTEXT_EXPIRED`; one microsecond earlier is accepted |
| request budget | `time.monotonic` | an absolute `deadline_monotonic_ns` in the past is refused as `timeout` before any producer call; the shorter of it and `deadline_ms` governs |

Observation, not a guarantee: the Context path keeps no wall-clock floor.
After a window has passed, moving the injected clock back makes the same
(request, envelope) valid again, and the registry window follows the same
clock. The request is consumed within the call and another request is refused
by binding, so the reach is the caller that holds both. The tests inject only
one side (MIO) to model skew; in production both read the host clock in
different processes. Clock difference between hosts, the allowed skew and the
maximum envelope lifetime (`max_ttl_seconds`, tests use 30) are not defined by
the contract and no grace period was added; they are commissioning decisions.

### Status

| Area | Status |
| --- | --- |
| A peer authentication | isolated acceptance passed (real kernel, container) |
| B systemd | static agreement passed; **real systemd not run**; approximation only |
| C restart replay | isolated acceptance passed |
| D clocks | isolated acceptance passed for the single-host model; cross-host skew not tested; re-validity after a clock rollback is an open observation (see Open items) |
| real credentials, trust anchor, endpoint, audit retention, activation grant | not done |

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
6. Unresolved observation: the Context path has no wall-clock floor, so a
   clock moved back makes the same (request, envelope) valid again for a
   caller holding both (see *Clocks*). This is distinct from the restart
   result above, which shows only that a different request is refused by
   binding; reuse of the same request is not prevented. Whether a floor,
   persisted state or other measure is wanted is undecided.
7. The activation grant for `azazel-knowledge-contextd.service` is issued by
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
