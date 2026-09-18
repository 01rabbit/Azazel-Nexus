# Azazel-Nexus Implementation Specification

## 1. Status, scope, and invariants

This specification turns the architecture documents into implementation units for a generic rugged x86_64 Linux PC. It is a normative baseline for an initial production-capable implementation. Terms **MUST**, **SHOULD**, and **MAY** describe requirements, recommendations, and allowed options.

The baseline is a self-contained node. It MUST keep collecting evidence, evaluating signed policy, presenting deterministic explanations, auditing, and applying already supported bounded controls without cloud connectivity or external modules. AZ-04 and AZ-06 increase depth; they never provide the prerequisite for baseline operation.

The following authority rule is non-negotiable:

```text
Evidence -> evaluators -> Action Arbiter -> enforcement adapter
                    \-> M.I.O. / Knowledge / Deception (advisory or bounded capability)
```

Only `azazel-arbiterd` can create an enforcement intent. M.I.O., either Knowledge service, either Deception service, the UI, and remote services MUST use requests or advisories that the arbiter independently validates. No service may hold the arbiter signing key and an enforcement-adapter privilege at the same time.

Out of scope: any device-vendor-specific implementation and a cloud dependency for local protection.

## 2. Target platform and deployment profiles

The reference OS is a supported long-term-support Linux distribution with systemd, nftables, `tc`, cgroup v2, TPM 2.0 tools, LUKS2, and a current kernel. The implementation MUST support a headless console; a touchscreen is an optional presentation device.

| Profile | Minimum hardware | Enabled capability | Retention and limits |
| --- | --- | --- | --- |
| `core` | 4 cores / 8 GB RAM / 512 GB NVMe / two managed NICs | evidence, evaluators, arbiter, enforcement, UI/API, deterministic voice | metadata only; M.I.O., Lite services disabled |
| `lite` | 4 cores / 16 GB RAM / 512 GB NVMe | `core` plus Knowledge Lite, Deception Lite, local M.I.O. | 7-day tactical cache, 3 Lite decoys, one local request |
| `standard` | 6 cores / 32 GB RAM / 1 TB NVMe | normal standalone node; local and eligible remote M.I.O.; AZ-04/AZ-06 links | 30-day tactical cache, 3 Lite decoys, two local requests |
| `extended` | 12 cores / 64 GB RAM / 2 TB NVMe | sustained capture, wider local models, full extensions | profile-defined; audit remains protected |

All profiles require separate protected, observation, management, decoy, and egress/module zones where their functions are enabled. A production profile MUST define interface names by stable MAC or PCI path, not by ephemeral kernel device numbering.

## 3. Filesystem layout and identities

`/etc/azazel/` is configuration; `/var/lib/azazel/` is small mutable state; `/data/` is the encrypted mission volume mounted only after successful boot integrity checks. Permissions below are mandatory defaults.

```text
/etc/azazel/
  node.yaml                    # node identity, profile, interface-role map
  policy/active.bundle          # signed policy bundle (read-only to daemons)
  policy/trust.d/*.pem          # policy and module trust anchors
  mio/sanitizer.yaml            # remote privacy classes and allowlists
  mio/providers.d/*.yaml        # endpoint metadata, no secrets
  knowledge-lite.yaml
  deception-lite.yaml
  modules.yaml                  # expected AZ-04/AZ-06 peers and pinning rules
  voice.yaml
  retention.yaml
  resource-governor.yaml
  systemd/*.conf                # unit drop-ins installed by packages
/var/lib/azazel/
  run/                          # sockets, PID-free transient state (0750)
  state/                        # durable state machines and idempotency index
  secrets/                      # root-only credential material, preferably tmpfs-backed
/data/azazel/
  evidence/objects/             # content-addressed encrypted artifacts
  evidence/index.sqlite         # metadata index; WAL enabled
  audit/ledger/                 # daily append-only segments and signed checkpoints
  knowledge-lite/               # cache database and verified bundles
  deception-lite/               # decoy persistent state; no protected-network data
  models/                       # signed local model assets
  capture/                      # bounded capture spool, lowest retention priority
  exports/                      # operator-approved encrypted exports
  recovery/                     # sealed recovery manifests, never live secrets
```

Each daemon MUST use a dedicated, non-login system account: `azobs`, `azevidence`, `azeval`, `azarbiter`, `azenforce`, `azmio`, `azknowledge`, `azdecoy`, `azmodule`, `azvoice`, and `azui`. A service reads only its stated configuration. Secrets are supplied through systemd credentials or a root-owned secret broker; they MUST NOT appear in YAML, command lines, process environments, journal fields, or audit payloads.

## 4. Runtime units

All local APIs use Unix domain sockets under `/var/lib/azazel/run/` unless an explicit loopback TCP port is specified. Socket ACLs are the first authorization boundary; every request also carries a workload identity and trace ID.

| Unit / executable | Account | Listens or consumes | Owns | Required behavior |
| --- | --- | --- | --- | --- |
| `azazel-observed.service` / `az-observed` | `azobs` | capture sockets, Suricata EVE input, interface telemetry | normalized observations | never drops a valid source event silently; records source loss |
| `azazel-evidenced.service` / `az-evidenced` | `azevidence` | `evidence.sock` | object store, evidence index, hashes | assigns immutable evidence IDs and stores provenance |
| `azazel-evaluatord.service` / `az-evaluatord` | `azeval` | evidence subscription | NOC/SOC assessments | rules only; outputs cited assessments, not actions |
| `azazel-arbiterd.service` / `az-arbiterd` | `azarbiter` | `arbiter.sock`, operator approvals | decision and lease store | sole intent issuer; validates policy, scope, expiry, prerequisites |
| `azazel-enforced.service` / `az-enforced` | `azenforce` | `enforcement.sock` | nftables/tc/route state | applies one approved intent, verifies it, then emits a receipt |
| `azazel-auditd.service` / `az-auditd` | `root` plus append-only group | `audit.sock` | hash-chain ledger, checkpoints | accepts canonical events only and refuses chain discontinuity |
| `azazel-knowledge-lite.service` | `azknowledge` | `knowledge.sock` | tactical cache | returns cited, freshness-labeled context; advisory only |
| `azazel-deception-lite.service` | `azdecoy` | `deception.sock` | decoy bridge and containers | manages only approved Lite decoys; no protected route |
| `azazel-module-manager.service` | `azmodule` | `modules.sock`, mTLS links | module inventory and bundle staging | discovers, verifies, quarantines, and reports modules |
| `azazel-mio-router.service` | `azmio` | `mio.sock` | route state and request budget | local-first selection and deadline management |
| `azazel-mio-local.service` | `azmio` | `mio-local.sock` | local inference worker | strict advisory output; resource-capped |
| `azazel-mio-sanitizer.service` | `azmio` | `mio-sanitize.sock` | redaction decision records | default deny; emits only `MioRemoteFrame` |
| `azazel-mio-remote.service` | `azmio` | loopback `127.0.0.1:9444` | remote request state | egress-only mTLS client; treats response as untrusted |
| `azazel-mio-merger.service` | `azmio` | `mio-merge.sock` | merged advisory cache | retains per-claim provenance and disagreement |
| `azazel-voiced.service` | `azvoice` | `voice.sock` | priority queue and acknowledgement state | deterministic alerts precede explanatory speech |
| `azazel-uid.service` | `azui` | loopback `127.0.0.1:8443` | operator sessions/read model | authenticated UI; no privileged direct controls |
| `azazel-watchdog.service` | `root` | systemd watchdog notifications, health sockets | degradation coordinator | fences failed capabilities; never restarts into a broader authority state |

`azazel-enforced` is the only daemon granted narrowly constrained `CAP_NET_ADMIN`. Its service MUST use `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `PrivateDevices=yes` except explicit NIC access, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, and a systemd `SystemCallFilter` appropriate to netlink operations. The audit daemon writes through a root-owned append-only helper rather than granting write access to other daemons.

## 5. API and port contract

All request and response bodies are versioned JSON or protobuf messages using `schema_version: "v1"`. Network APIs are mutually authenticated TLS 1.3. Local service APIs reject unknown fields unless the schema marks them as extensions. The UI port is bound to management loopback by default and is reverse-proxied only on a designated management interface.

| Boundary | Transport | Authentication | API operations |
| --- | --- | --- | --- |
| operator -> UI | HTTPS `8443` | WebAuthn or client certificate; local break-glass profile | read status, view evidence, acknowledge, submit approval/decline |
| observer -> evidence | `evidence.sock` | `azobs` socket ACL | `PutObservation`, `PutArtifactReference`, `ReportSourceHealth` |
| evidence -> evaluator | `events.sock` | `azeval` ACL | ordered `EvidenceCreated` subscription |
| evaluator -> arbiter | `arbiter.sock` | `azeval` ACL | `ProposeAssessment`; cannot call `IssueIntent` |
| UI -> arbiter | `arbiter.sock` | `azui` plus operator authorization | `ApproveProposal`, `DeclineProposal`, `AcknowledgeReceipt` |
| arbiter -> enforcement | `enforcement.sock` | `azarbiter` ACL plus signed intent | `ApplyIntent`, `InspectScope`, `RollbackLease` |
| all components -> audit | `audit.sock` | component ACL + signed canonical envelope | `AppendAuditEvent` |
| Edge -> Knowledge Lite | `knowledge.sock` | `azeval`, `azmio` ACL | `LookupContext`, `ImportVerifiedBundle` |
| arbiter -> Lite Deception | `deception.sock` | `azarbiter` ACL plus intent | `PrepareDestination`, `ActivateRedirect`, `DeactivateRedirect` |
| M.I.O. internal | Unix sockets | `azmio` subservice ACL | `Route`, `Sanitize`, `Analyze`, `Merge` |
| Nexus <-> AZ-04/AZ-06 | HTTPS `9443` | mTLS, signed manifest, peer identity pin | `GetManifest`, `GetBundle`, `GetHealth`, bounded Deception control |
| remote M.I.O. egress | HTTPS `443` | mTLS client identity / approved provider credential | one-way `Analyze(MioRemoteFrame)` only |

No API exposes shell command execution, arbitrary policy upload, arbitrary container start, packet capture retrieval, or a general network-control primitive. The external AZ-06 control API receives a signed `DeceptionLease`, not an Edge enforcement intent.

## 6. Canonical data schemas

Every record has `schema_version`, ULID `id`, RFC 3339 UTC `occurred_at`, `trace_id`, `producer`, `classification`, and `integrity` fields. Timestamps include a `time_confidence` value: `trusted`, `degraded`, or `untrusted`.

### 6.1 Evidence and assessment

```json
{
  "schema_version": "v1",
  "id": "01J...",
  "trace_id": "AZ-2026-00142",
  "kind": "observation",
  "source": {"id": "suricata:wan0", "sequence": 4812},
  "occurred_at": "2026-09-18T02:30:00Z",
  "classification": "mission-confidential",
  "payload": {"event_class": "authentication_anomaly", "fields": {}},
  "artifact_refs": ["sha256:..."],
  "integrity": {"payload_sha256": "...", "previous_id": "01J..."}
}
```

```json
{
  "schema_version": "v1",
  "id": "01J...",
  "kind": "assessment",
  "risk": 84,
  "risk_state": "high",
  "assessment_type": "soc",
  "rule": {"id": "SOC-CRD-004", "policy_version": "2026.09.1"},
  "evidence_ids": ["01J...", "01J..."],
  "recommended_actions": ["throttle", "isolate"],
  "confidence": 0.91
}
```

### 6.2 Intent, lease, receipt, and rollback

An intent is immutable and has exactly one lifecycle. An action lease bounds any non-permanent control; expiration is enforced independently by `azazel-enforced` even if the arbiter disappears.

```json
{
  "schema_version": "v1",
  "id": "01J...",
  "kind": "enforcement_intent",
  "decision_id": "01J...",
  "policy": {"id": "EDGE-ISO-002", "version": "2026.09.1", "hash": "sha256:..."},
  "action": "isolate_segment",
  "scope": {"zone": "guest", "interfaces": ["lan-guest"], "selectors": ["segment:guest"]},
  "evidence_ids": ["01J..."],
  "approval": {"required": true, "operator_id": "op-17", "approved_at": "..."},
  "lease": {"id": "01J...", "issued_at": "...", "expires_at": "...", "rollback": "restore_previous_ruleset"},
  "signature": {"key_id": "arbiter-2026-01", "ed25519": "..."}
}
```

`receipt` records `intent_id`, adapter, pre-state hash, post-state hash, verification probes, effective time, result (`applied`, `failed`, `rolled_back`, `expired`), and failure reason. A rollback MUST use the receipt's captured pre-state or a policy-declared safe baseline; it MUST NOT reconstruct a ruleset from an untrusted current state.

### 6.3 M.I.O. and privacy classes

`MioSituationFrame` is local-only and may cite evidence IDs. `MioRemoteFrame` is separately built, carries `sanitizer_policy_version`, `redaction_record_id`, `remote_privacy_class`, and contains no raw artifacts or internal addressing.

| Privacy class | Remote eligibility | Examples |
| --- | --- | --- |
| `P0-public` | allowed | product version, generic technique name |
| `P1-sanitized` | allowed after sanitizer | stable aliases, role categories, counts and time buckets |
| `P2-mission` | local only unless explicit policy transformation exists | internal topology, named assets, detailed timelines |
| `P3-restricted` | never remote | credentials, keys, raw capture, operator identity, exact location |

`MioResult` has `summary`, `claims[]`, `confidence`, `evidence_ids[]`, `next_checks[]`, `limitations[]`, and `source` (`local`, `remote`, `merged`). Each claim includes `provenance` and can be shown as untrusted remote content. It contains no executable action field.

### 6.4 Audit ledger

The audit event is a canonical serialized envelope with `event_type`, actor, target IDs, outcome, and redacted details. Each segment stores:

```text
sequence | event_hash = SHA-256(previous_hash || canonical_event_bytes) | previous_hash
```

At rotation (at least daily and on shutdown), `azazel-auditd` writes a signed checkpoint containing the final hash, segment root, policy hash, boot ID, and TPM measurement reference where available. The next segment includes the prior signed checkpoint hash. Audit records are write-only for workloads and are exported as a signed manifest plus encrypted artifacts. A chain gap, failed checkpoint signature, or backwards trusted clock enters `INTEGRITY_RECOVERY`.

## 7. State machines and degradation

The node exposes one computed capability state and individual service states. State changes are appended to audit before being published to the UI.

```text
BOOTSTRAP -> VERIFYING -> CORE -> LITE -> FULL
                          ^       |       |
                          |       +-------+ external or embedded capability loss
                          +--------------- resource shed / local capability loss
VERIFYING -> INTEGRITY_RECOVERY -> RECOVERY -> CORE
```

| State | Preconditions | Permitted operation |
| --- | --- | --- |
| `BOOTSTRAP` | encrypted data unavailable | diagnostics only; no policy activation |
| `VERIFYING` | data mounted | verify boot, policy, audit checkpoint, interfaces, clock |
| `CORE` | Edge health and signed policy valid | evidence, evaluation, deterministic enforcement, UI, audit, deterministic voice |
| `LITE` | `CORE` plus both embedded Lite services healthy | standalone Knowledge/Deception and local M.I.O. if provisioned |
| `FULL` | `LITE` plus verified fresh AZ-04 and AZ-06 links | external capacity under signed leases |
| `CONSTRAINED` overlay | resource or partial service threshold | preserve Core; shed priority-defined optional work |
| `INTEGRITY_RECOVERY` | integrity check fails | read-only diagnostics and protected evidence access; no remote egress, policy activation, or module change |

The expected normal degradation is `FULL -> LITE -> CORE`. AZ-04 loss removes only extended knowledge, and AZ-06 loss stops new full-host redirects then selects an eligible Lite destination. Loss of either Lite service is source-specific: the other remains available; the state is `CORE` plus a visible impairment. Loss of local cognition does not reduce Edge authority or deterministic voice alerts.

Automatic restoration above `CORE` requires a passing health window, signature/segmentation revalidation, and an audited state transition. Restoring a module route or a failed enforcement adapter requires operator acknowledgement.

## 8. Health checks, watchdog, and failure handling

Every daemon MUST expose `GET /healthz` on its Unix socket, returning `ready`, `degraded`, or `failed`, dependency summaries, build ID, last successful work timestamp, and backlog. A `GET /readyz` returns success only when safe to accept new work. systemd `WatchdogSec=30s` is required for core units; the watchdog uses a 10-second polling cadence.

| Component | Health evidence | Failure response |
| --- | --- | --- |
| observer | source sequence advancing; interface carrier and capture counters | mark source impaired; evaluators enforce corroboration prerequisites |
| evidence | encrypted volume writable; index transaction and object hash verification | stop low-priority capture; preserve audit and decisions; if persistent failure, no new automatic action needing missing evidence |
| arbiter | policy signature valid; lease timer alive; decision store transaction | reject new intents; existing enforcement leases continue to expiry |
| enforcement | ruleset/queue inspection equals desired state; rollback baseline present | lock new intents for adapter scope; execute only verified rollback; critical alert |
| audit | chain continuity, free protected space, checkpoint signature | enter `INTEGRITY_RECOVERY` on chain error; halt nonessential mutations |
| Knowledge Lite | query integrity and bundle signature/freshness | return `unavailable` rather than stale as current; evaluators continue without it |
| Deception Lite | container/process, bridge isolation, route-deny probes | remove redirect eligibility, detach unsafe bridge, preserve telemetry |
| module manager | mTLS, peer pin, manifest signature, compatibility, freshness | quarantine peer and degrade to Lite; never retry with trust relaxed |
| M.I.O. sanitizer | policy loaded, negative test, tokenization key available | deny remote route; local or Core path only |
| local M.I.O. | bounded test inference and cgroup headroom | shed to `CORE`; do not starve capture/evidence |
| voice | audio device write and queue serviceability | visual-only alert plus audit; no enforcement impact |

`azazel-watchdog` MUST order remediation as: (1) cancel optional remote work, (2) reduce M.I.O. concurrency/context, (3) stop local model, (4) pause low-priority capture, (5) request controlled shutdown for persistent power or storage risk. It MUST NOT kill the arbiter or audit daemon as a resource-reclamation action. Every fence, restart, and state transition emits an audit event and UI status.

## 9. Enforcement, leases, and network isolation

Policy actions are allowlisted: `observe`, `alert`, `throttle`, `block_selector`, `isolate_segment`, `redirect_to_lite`, `redirect_to_az06`, `revoke_temporary_route`, and `rollback`. A policy binds every action to permitted zones, selector grammar, approval requirement, maximum lease duration, corroboration prerequisites, verification probes, and rollback method.

The enforcement adapter MUST:

1. Verify the arbiter signature, active policy hash, intent expiry, action allowlist, and local scope map.
2. Capture and hash the policy-owned pre-state.
3. Apply a transactionally generated nftables/`tc`/routing change with an intent-specific tag.
4. Run policy-declared verification probes and inspect the effective kernel state.
5. Emit the signed receipt, schedule lease expiration, and publish the result.
6. Roll back tagged changes on expiry or verified failure; fail closed for the affected control if rollback cannot be verified.

Deception uses an equivalent but separate `DeceptionLease`. Lite containers live only on `az-decoy0`; a host firewall and namespace rules deny forwarding to protected, management, control-plane, and Internet zones. The isolation check MUST actively test denied paths on boot and before a redirect is eligible. A failed check immediately removes all redirect eligibility.

## 10. M.I.O. route selection and voice queue

The router selects `local`, `remote`, `local_then_remote`, or `parallel` from mission policy, privacy class, remote health, latency budget, local resource headroom, and incident severity. `remote` is eligible only for P0/P1 frames with a valid sanitizer decision. The default is `local_then_remote`. A remote deadline expiration returns the local result unchanged and records only the sanitized request fingerprint; it never queues P2/P3 data for later submission.

The merger compares claims by cited evidence and outcome. It labels material conflict `ANALYSIS_DISAGREEMENT`; this label never changes an arbiter decision. Remote text is rendered as inert text, with no tool calls, links automatically followed, or instructions treated as commands.

`azazel-voiced` maintains a durable, bounded priority queue:

| Priority | Source | Interrupt rule | Default expiry |
| --- | --- | --- | --- |
| `P0` | integrity, enforcement verification failure | interrupts all speech | 10 min, repeat on escalation |
| `P1` | arbiter action/outcome | interrupts P2/P3 | 5 min, repeat until acknowledgement by policy |
| `P2` | source/module health | waits for P0/P1 | 15 min |
| `P3` | M.I.O. explanation | never interrupts deterministic speech | 2 min |

Queue items include correlation key, severity, scope, immutable source event IDs, suppression window, and acknowledgement state. Deduplicate by correlation key; escalate only if severity or scope changes. The deterministic alert is generated from a template, not model text. Audio failure switches to visual state and audit without blocking the source action.

## 11. Module discovery and signed links

`azazel-module-manager` discovers only peers declared in `/etc/azazel/modules.yaml` or physically provisioned through an operator-approved inventory update. Discovery never grants trust. A candidate presents a TLS client certificate and signed manifest:

```json
{
  "module_id": "az04-field-02",
  "role": "az04-knowledge",
  "api_version": "v1",
  "software_version": "1.0.0",
  "capabilities": ["context.bundle.get"],
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "...",
  "signature": "ed25519:..."
}
```

Acceptance requires certificate chain and pin validation, manifest signature, allowed role/capability, compatible API version, freshness, non-revocation, and zone reachability. AZ-04 content is content-addressed and signed; it is staged, verified, and atomically promoted. AZ-06 receives a lease that names only its assigned decoy zone and bounded action; it cannot query arbitrary evidence or reach protected networks. A changed peer identity, invalid signature, or failed segmentation probe causes quarantine and `FULL -> LITE` degradation.

## 12. Security, boot, update, and recovery

The production assumption is UEFI Secure Boot where supported, TPM 2.0 measured boot, and LUKS2-encrypted system and data volumes. The LUKS data key SHOULD be TPM-sealed to approved PCR measurements with a recovery passphrase held under mission custody. If a TPM is unavailable, require a boot-time operator secret and label measured-boot evidence unavailable; do not silently claim hardware attestation.

Security boundaries are: untrusted ingress -> observation; operator -> authenticated management; arbiter -> privileged enforcement; decoy -> isolated execution; module -> mTLS/signed contract; remote cognition -> sanitizer-controlled egress. Default host firewall policy is deny, with explicit rules for these paths only. Management services bind only to the management zone. Decoys use rootless containers or dedicated namespaces, read-only images, dropped capabilities, and no host socket mounts.

Updates use an A/B or transactional OS deployment with signed repository metadata and pinned package versions. An update bundle includes software SBOM, unit/config migration, schema compatibility, policy compatibility, and rollback manifest. Apply only in maintenance state after: audit checkpoint, encrypted backup of configuration and indexes, and free-space check. Boot the candidate slot, run health and segmentation tests, and promote only after an operator-approved soak window. Failure returns to the prior slot without deleting evidence. Schema migrations MUST be forward-compatible or include a tested reverse migration.

Recovery media is encrypted, signed, and versioned. It can boot diagnostics, verify signatures and audit segments, unlock data through controlled custody, export evidence, and restore a known software slot. It MUST NOT bypass audit verification, silently reset policy, or erase mission data. A repair that breaks audit continuity creates a new ledger genesis explicitly linked to the last valid checkpoint and requires an operator custody record.

## 13. Required configuration examples

The following example is deliberately generic and belongs in a deployed node as `/etc/azazel/node.yaml`:

```yaml
node_id: nexus-field-01
profile: standard
interfaces:
  protected: {match: "pci-0000:04:00.0", zone: protected}
  observation: {match: "pci-0000:05:00.0", zone: observation}
  management: {match: "pci-0000:06:00.0", zone: management}
  decoy: {match: "az-decoy0", zone: decoy}
policy:
  active_bundle: /etc/azazel/policy/active.bundle
  require_signed: true
audit:
  checkpoint_interval: 24h
  minimum_free_gib: 8
```

```yaml
# /etc/azazel/mio/sanitizer.yaml
version: v1
remote_default: deny
classes:
  P0-public: {remote: allow}
  P1-sanitized: {remote: allow, fields: [event_class, role, count, time_bucket]}
  P2-mission: {remote: deny}
  P3-restricted: {remote: deny}
redactions: [ip_address, hostname, account, credential, secret, payload, location]
limits: {max_bytes: 16384, requests_per_hour: 20, remote_deadline_seconds: 20}
```

```yaml
# /etc/azazel/modules.yaml
modules:
  - id: az04-field-02
    role: az04-knowledge
    endpoint: https://az04.module.local:9443
    certificate_pin: sha256:REPLACE_AT_PROVISIONING
    required_capabilities: [context.bundle.get]
  - id: az06-field-02
    role: az06-deception
    endpoint: https://az06.module.local:9443
    certificate_pin: sha256:REPLACE_AT_PROVISIONING
    required_capabilities: [deception.lease.apply]
```

## 14. Acceptance tests and release gates

A release MUST demonstrate the following in an isolated lab before a production profile is signed:

- A cold standalone boot reaches `LITE` (or documented `CORE` profile) with no AZ-04/AZ-06/remote route; an action, receipt, evidence chain, and deterministic alert are visible.
- Loss, expiry, bad signature, and identity change for each external module produces `FULL -> LITE`, retains embedded capability, and creates no extra enforcement privilege.
- A P2/P3 M.I.O. frame, invalid sanitizer policy, and malformed remote response produce no egress or control-plane change.
- An attempted direct UI, M.I.O., Knowledge, or Deception call to enforcement is rejected and audited.
- Intent replay, expired lease, scope widening, failed verification, and adapter restart each result in the specified receipt and safe rollback/fence behavior.
- A decoy compromise simulation cannot reach protected, management, control-plane, or Internet zones; failed isolation makes redirect unavailable.
- Audit tampering, checkpoint mismatch, and trusted-clock rollback enter `INTEGRITY_RECOVERY`.
- CPU, memory, disk, thermal, and battery pressure exercises prove shedding order preserves evidence, audit, arbiter, and lease expiry.
- Candidate update rollback and encrypted recovery media preserve the latest valid audit checkpoint and evidence index.

## 15. Implementation order

Implement in dependency order: common schemas/identity/audit; evidence and evaluators; arbiter and one verified enforcement adapter; UI/voice; Lite services and their isolation checks; module manager; local M.I.O.; sanitizer/remote/merger; finally update/recovery automation. No later capability may bypass or revise the authority and audit contracts established by the first stages.
