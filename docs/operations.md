# Field Operations Design

## 1. Resource envelopes

Status: **target contract**. Nothing in this document is implemented in this
repository.

A resource envelope states how much the host can carry. It never states what
the host is permitted to do to the network. The full rule and its worked
examples are in [capability model](capability-model.md); the summary an
operator needs in the field is below.

The resource profile is selected from **usable RAM in MiB after firmware
reservation**, with the measured Core reserve subtracted. Interface count is
deliberately absent from this table — it belongs to the topology profile and is
established by [commissioning](commissioning.md).

| Usable RAM (MiB) | Resource profile | Capacity permitted | Typical companion hardware |
| --- | --- | --- | --- |
| `< 8192` | `diagnostic` | inventory and diagnostics only; no policy activation | — |
| `8192` – `16383` | `core` | evidence, rules, packet metadata, enforcement, UI, deterministic voice | 4 cores / 8 threads, 512 GB encrypted SSD |
| `16384` – `32767` | `lite` | `core` capacity plus Suricata, local cognition, Knowledge Lite, and Deception Lite | 4 cores / 8 threads, 512 GB encrypted SSD |
| `>= 32768` | `standard` | `lite` capacity plus concurrent analysis, wider local models, and module links | 6+ cores / 12 threads, 1 TB encrypted SSD |

A 64 GB host with 12+ cores and 2 TB of storage selects `standard` and is
measured as the 64 GB performance class. It is not a separate tier.

**A resource profile grants capacity, never capability.** A `standard` host
whose interfaces are uncommissioned, whose management path is not independent
of the enforced path, or whose decoy isolation is unproven remains observe-only.
The operator interface shows each capability separately as well as the overall
`CORE`, `LITE`, or `FULL` summary, so a capable-looking machine is never
mistaken for a permitted one.

The system continuously observes CPU, memory, disk, thermal, battery, and
interface capacity. It uses those signals to shed optional work within the
envelope; it never uses them to weaken policy or to grant a capability that
topology, assets, or trust do not support.

## 2. Graceful degradation states

Each state is explicit in the operator interface and audit ledger. A degradation can reduce analysis quality or retention, but it must never silently broaden enforcement.

| State | Trigger | Remains available | Restricted or disabled | Operator signal |
| --- | --- | --- | --- | --- |
| Nominal | Health checks pass | All enabled components | None | Green status |
| Constrained | Resource threshold crossed | Evidence, existing policy, core enforcement | lower-priority analysis; reduced local model context | Amber capacity notice |
| Offline | Remote route unavailable | Local cognition, Evidence, deterministic core, enforcement | Remote cognition | “Offline: local cognition active” |
| External module unavailable | AZ-04 or AZ-06 health failure | Edge core, Knowledge Lite, Deception Lite, and verified cached context | affected full-node action; stale external data is labeled | Amber extension status; embedded Lite remains ready |
| Embedded Lite impaired | Knowledge Lite or Deception Lite health failure | Edge core and unaffected embedded/external capability | actions requiring the impaired Lite service; full-node capability remains separately evaluated | Red source-specific warning |
| Sensor impaired | Capture adapter or sensor failure | Other sources, prior evidence, policy checks | Actions requiring missing sensor corroboration | Red source-specific warning |
| Enforcement degraded | Adapter cannot verify control state | Evidence, evaluation, operator guidance | New automated enforcement through that adapter | Critical warning and safe hold |
| Integrity recovery | Boot, signature, clock, or ledger anomaly | Limited diagnostics and protected evidence access | Policy activation, remote egress, module changes | Critical service-required state |

Transitions are evented, signed into audit, and surfaced in the UI and voice policy where severity warrants it. Returning to a higher state requires health verification; it is not automatic merely because a process restarted.

Every state above is a **capability** state. Azazel-Edge's deterministic
arbiter holds the same and only decision and enforcement authority in each of
them, and the records published to the operator and the audit ledger are
Azazel-Fabric contracts, not Nexus-local inventions. See
[contract ownership](contract-ownership.md).

## 3. Failure modes and responses

| Failure mode | Detection | Safe response |
| --- | --- | --- |
| Cloud loss or remote timeout | egress health and request deadline | Continue local cognition; retain sanitized request metadata locally; do not queue sensitive raw data for later upload. |
| Local model unavailable | model supervisor health check | Use deterministic summaries and evidence viewer; keep enforcement unchanged. |
| Sanitizer failure | policy or validation error | Deny external request; log reason; retain local-only path. |
| Conflicting cognition | merger comparison | Display disagreement and evidence citations; do not change arbiter outcome. |
| Knowledge package invalid or stale | signature/version/freshness check | Reject invalid package; keep last verified package with freshness label. |
| Deception module compromise or isolation loss | heartbeat, route, and segmentation checks | Detach module route; preserve telemetry; require operator review to restore. |
| Disk pressure | retention monitor | Stop lowest-priority capture first, preserve audit/decision records, and alert operator. |
| Power loss | UPS/battery telemetry | Commit journaled data, checkpoint service state, initiate controlled shutdown at threshold. |
| Clock anomaly | trusted-time comparison | Mark temporal confidence degraded; block actions whose policy depends on trustworthy time. |
| Privileged adapter fault | command/verification failure | Roll back only verified reversible operation; lock new intents for affected scope; require acknowledgement. |

## 4. Field deployment kit

A deployment kit is intentionally serviceable and equipment-neutral:

- rugged x86_64 Linux PC with power supply, spare battery or DC power option, encrypted removable recovery media, and hardware inventory record;
- two or more labeled network adapters, approved cables, compact managed switch where required, and a passive tap or approved capture method;
- touchscreen or external display, keyboard/pointing backup, headphones or speaker for alerts, and visual-only operating option;
- sealed spare storage or approved encrypted evidence media, adapters, and a cable/test kit;
- printed or offline runbook with interface map, policy profile, break-glass procedure, and evidence custody record;
- an isolated lab profile and a production mission profile. Never test a new enforcement policy first on the live boundary.

## 5. Field workflow

1. Inspect seals, inventory, power, clock health, storage encryption, and policy/knowledge signatures.
2. Run read-only inventory, then commission each interface: confirm its composite identity and its logical role (protected, observation, management, decoy, egress/module) explicitly. Roles are never inferred from an interface name, link state, or default route, and an unconfirmed interface stays unassigned and unusable. See [commissioning](commissioning.md).
3. Activate the verified generation; until it exists no operational service is running. Start in observe-only mode and validate visibility, evidence flow, and that the observation interface has transmitted nothing.
4. Load the approved mission profile; confirm the displayed enforcement scope and rollback conditions.
5. Enable bounded controls only after an operator acknowledgement where the policy requires it. A high-impact network change additionally requires an independent management path or physical console and a two-stage commit: acknowledge verified reachability within the lease window or the change rolls back automatically.
6. During operation, use the UI for evidence and decision review; treat M.I.O. as an investigator, not an actuator.
7. On exit, export or seal evidence according to the mission retention policy, revoke temporary credentials, and record hardware custody.

## 6. Operator experience

The primary interface is a touch-friendly status-first console. It must make four questions answerable within one screen: What changed? What evidence supports it? What is currently enforced? What needs an operator decision?

The UI groups information by mission state rather than by internal service. Every recommendation shows source, freshness, confidence, and cited evidence. An approval screen restates action scope, duration, policy rule, and rollback path before it can reach the Action Arbiter.
