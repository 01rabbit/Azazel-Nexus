# Integration broker (#16)

Nexus owns a local control and assurance plane for optional EDR, FW, NDR,
SIEM, DNS, asset and vulnerability adapters. It verifies admission declarations,
records lifecycle decisions, renders confinement for review, sanitizes data,
and gates exposure **intents**. Edge retains decision and enforcement authority.
There is no adapter wire protocol, provider command protocol or automation bus.
[Fabric#25](https://github.com/01rabbit/Azazel-Fabric/issues/25) remains a dependency:
`deliver()` always returns `transport unavailable: Fabric#25`, including for a
valid signed lease. No service is installed, enabled or contacted by the broker.

## Admission and states

A manifest is a 64-byte Ed25519 signature followed by JSON. The signature covers
`azazel-nexus/adapter-manifest/v1\0` plus the exact JSON bytes. The immutable
manifest binds an exact version, installed-artifact SHA-256, capability set,
tenant, privacy class, literal numeric IP/CIDR and destination ports, symbolic
mTLS identity and credential reference, compatibility identifiers and commissioning
digest. Executable commands, hostnames, URLs, secret values and unknown fields
are refused. Artifact installation and verification remain commissioning tasks.
Adapter-signing keys are separate from catalog, registry, revocation and bundle
keys, by identifier and material; commissioned sibling key maps are checked.

The shared state machine starts at `DISABLED`:

```text
DISABLED -> DISCOVERED -> STAGED -> ADMITTED -> OBSERVE_ONLY
         -> APPROVAL_PENDING -> ACTIVE_BOUNDED -> WITHDRAWING
         -> DEGRADED / QUARANTINED / FAILED
```

These are named states, not an ordering that grants permission. All changes use
`states.transition`; each allowed edge and refusal is tested. Failure states
must reset through `DISABLED`. Read-only adapters enter `OBSERVE_ONLY` after
admission. An exposure adapter stays `ADMITTED` only with eligible commissioned
topology; otherwise it stays `OBSERVE_ONLY`, regardless of RAM. The exposure gate
requires a signed, fresh, adapter/proposal/commissioning-bound Edge lease,
a matching commissioned management path with a healthy check at most 60 seconds
old, explicit dry-run and human confirmation. A successful gate uses the same
verified `EdgeLease` as the state's `Approval` protocol and records
`OBSERVE_ONLY -> APPROVAL_PENDING -> ACTIVE_BOUNDED`. This authorizes only an
intent, with no delivery implementation.

Invalid trust, credential expiry, data/privacy failure, active lease refusal or
transport refusal withdraws local adapter intents. `withdraw_all()` goes through
`WITHDRAWING` to `DISABLED` for every adapter and records deterministic Core
continuation. `expire(now=...)` is an explicit local watchdog tick for lease,
credential and observed-data expiry; no background watchdog is installed.
Withdrawal cannot undo a device operation: none can be delivered by this build.
It never calls an activation controller or changes Edge files or units.

## Persistence and audit

The broker owns `/var/lib/azazel/integration-broker`, including its separate
`audit/ledger.jsonl` leaf. Writers serialize with a local file lock, append a
transaction marker, and publish numbered JSON snapshots followed by an atomic
`current` pointer. Same-directory temporary files, fsync and atomic replacement
reuse the existing import/store pattern. A write-ahead checkpoint binds the
snapshot digest to the append-only `AuditLedger`. Every read verifies the chain
and checkpoint. An interrupted publication, corrupt snapshot or broken ledger
is refused; the status surface reports CORE without repairing or deleting evidence.
Recovery of interrupted publications is an administrator task, with no automatic
recovery command in this release. Local protected storage remains a commissioning
precondition; this is not protection against an administrator rewriting all evidence.

Events cover admission, schema/trust decisions, privacy sanitization, routing,
lease binding, postcondition observation, transitions, rollback and withdrawal.
Observing a successfully sanitized fresh record is a local data-path postcondition,
not a remote device-change postcondition. Snapshots retain public signed manifests,
state/reason codes, credential expiry and data/lease deadlines. Neither payloads,
sanitized frames, proposal bodies, credential contents nor alias keys are stored
in snapshots or audit events. Pure review and status never append audit events.

## Confinement and credentials

`render_adapter_unit()` uses only a verified manifest and reviewed
`AdapterCommissioning`: an installed artifact mapping, per-adapter account
(or DynamicUser) and scoped credential reference. It renders `IPAddressDeny=any`,
only admitted `IPAddressAllow` addresses, restricted address families,
`ProtectSystem=strict`, empty capability sets and `LoadCredential` pointing to
`<adapter-directory>/<symbol>.g<generation>`. Cross-adapter scopes, expired or
revoked references, shell launchers and uninstalled digests are refused.

**Destination ports are declarations in comments, not enforced by this unit.**
Systemd address allowlists constrain IP addresses; socket bind restrictions
constrain explicit local binding, not destination ports. Enforcement of the
admitted destination-port set needs separately reviewed nftables or cgroup BPF
connect/sendmsg policy, including UDP. See the
[systemd resource-control reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
Rendered-unit tests therefore establish address declarations and credential
scoping, not actual endpoint/port enforcement. Linux cgroup/BPF, seccomp,
filesystem ownership and symlink constraints remain runtime/hardware checks.

`rotate_credential()` returns revoked-old and fresh-new immutable reference
metadata; it does not fetch or provision secret bytes. The commissioner must
publish both atomically and commission a new signed manifest/reference. The
broker does not provide a credential rotation installer. Admission requires
`reviewed_at` equal to its supplied current time; routing and gating recheck
stored credential expiry and current manifest trust. Actual mTLS handshakes,
peer disconnect detection and credential provisioning await a transport/runtime.

## Operator surface and levels

```sh
azazel-nexus broker status
azazel-nexus broker status --json
azazel-nexus broker review manifest.signed
```

Status shows adapter IDs, states, bounded reasons, health and the adapter summary
level. Review verifies the signed manifest against fixed commissioned trust and
renders the proposed unit; it performs no writes. There are **no CLI `admit` or
`disable` commands**. Library admission/withdrawal are explicit commissioner actions,
not payload-driven actions; they never operate host units. A future write CLI
must require root and protected commissioning before it is exposed.

The CLI reads `/etc/azazel/integration-broker/commissioning.json` containing
`topology` (the existing CommissioningRecord fields), its `commissioning_digest`,
and hexadecimal public-key maps `adapter_keys`, `catalog_keys`, `registry_keys`,
`revocation_keys`, `bundle_keys`, `edge_keys`. Edge lease keys are held by the
broker, separate from adapter-signing keys, and cannot be supplied by proposal data. An adapter's `<adapter_id>.json` contains
`account` (nullable), `credential_directory`, `installed_artifacts` (digest/path
map), `credential_ref`, `credential_expires_at`, `credential_generation` and
`credential_revoked`. These files must be administrator-reviewed and protected;
there is no self-commissioning trust override in a manifest or payload.
`AZAZEL_ROOT` relocates these fixed paths for the existing fixture workflow.

The broker's `FULL / LITE / CORE` vocabulary is a local adapter summary:

| Level | Exact meaning in this release |
| --- | --- |
| CORE | No currently verified, unexpired, fresh, successfully sanitized read-only adapter observation. Includes no adapters, all withdrawn, admission without observations, expired health, or refused local evidence. |
| LITE | At least one admitted/observe-only read-only adapter has a successfully sanitized observation whose freshness and credential deadlines have not expired, and its manifest still verifies against commissioned trust. Other failed adapters remain visible individually. This is read-only telemetry/advisory availability, LITE-equivalent; it grants no enforcement readiness. |
| FULL | Reserved for healthy bounded integrations with verified operational delivery and rollback support. Fabric#25 is open, so this release never reports FULL, even for ACTIVE_BOUNDED intent records. |

This summary does not modify the six independent product axes in
[the capability model](capability-model.md). Normal status prints it adjacent to
the integration view, without a seventh axis. Setup includes an informational,
optional broker step which never blocks CORE or becomes a readiness grant.

## Acceptance evidence and remaining gates

| #16 criterion | Software evidence / limit |
| --- | --- |
| Adapter failure, revocation or removal preserves Core | `test_broker.py` compares real `ActivationController` outcomes/unit calls and `inspect_edge` results before/after withdrawal; revoked trust also refuses routing and withdraws. |
| Scoped egress and credentials | Real signed manifests through broker review plus lane confinement tests prove rendered address/port declarations and scoped references. Destination-port and actual OS enforcement remain unproven. |
| Audit coverage | Broker acceptance and the e2e stage exercise every required event kind and verify the hash chain; interrupted publication is refused. |
| Topology-ineligible high-memory node stays observe-only | Broker admission/gate tests require confirmed topology; a resource profile does not supply a role. |
| No content-plane privileged operation | Extended lane C transitive static scan, broker/CLI control-plane scan and runtime payload tests cover connector, M.I.O., Knowledge and Deception content. The scan permits routing to import only pure state data types; transition calls remain forbidden there. |
| Management survives change or auto-withdraws within lease | **HIL criterion explicitly not covered.** Local expiry/withdrawal tests do not establish management reachability or device rollback. |

The e2e harness now has **21 stages**, including “Integration broker”: signed
fixture telemetry admission under AZAZEL_ROOT, sanitized routing, refusal without
an Edge lease, intent with a fixture lease, transport refusal, withdrawal and
chain verification. Test keys are ephemeral; no production keys are included.
The issue remains open for Fabric#25, real runtime confinement and HIL.
