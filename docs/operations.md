# Field Operations Design

## 1. Resource tiers

The same architecture scales by disabling optional capacity before compromising core safety.

| Tier | Typical capacity | Required capability | Optional capability |
| --- | --- | --- | --- |
| Field Lite | 4 CPU cores, 16 GB RAM, 512 GB encrypted SSD | Evidence, rules, basic packet metadata, enforcement, UI, voice | small local cognition, limited retention |
| Field Standard | 8 CPU cores, 32 GB RAM, 1 TB encrypted SSD | Full Edge core, Suricata, local cognition, concurrent UI | larger retention, module links, dual cognition |
| Field Extended | 12+ CPU cores, 64 GB RAM, 2 TB+ encrypted SSD | Standard tier with sustained capture/analysis | richer local models, replicated evidence, more sensors |

Tier selection is recorded in the mission profile. The system continuously observes CPU, memory, disk, thermal, battery, and interface capacity; it uses those signals to select safe feature limits, not to weaken policy.

## 2. Graceful degradation states

Each state is explicit in the operator interface and audit ledger. A degradation can reduce analysis quality or retention, but it must never silently broaden enforcement.

| State | Trigger | Remains available | Restricted or disabled | Operator signal |
| --- | --- | --- | --- | --- |
| Nominal | Health checks pass | All enabled components | None | Green status |
| Constrained | Resource threshold crossed | Evidence, existing policy, core enforcement | lower-priority analysis; reduced local model context | Amber capacity notice |
| Offline | Remote route unavailable | Local cognition, Evidence, deterministic core, enforcement | Remote cognition | “Offline: local cognition active” |
| Module unavailable | Knowledge or Deception health failure | Edge core and verified cached knowledge | affected module action; stale data is labeled | Amber module status |
| Sensor impaired | Capture adapter or sensor failure | Other sources, prior evidence, policy checks | Actions requiring missing sensor corroboration | Red source-specific warning |
| Enforcement degraded | Adapter cannot verify control state | Evidence, evaluation, operator guidance | New automated enforcement through that adapter | Critical warning and safe hold |
| Integrity recovery | Boot, signature, clock, or ledger anomaly | Limited diagnostics and protected evidence access | Policy activation, remote egress, module changes | Critical service-required state |

Transitions are evented, signed into audit, and surfaced in the UI and voice policy where severity warrants it. Returning to a higher state requires health verification; it is not automatic merely because a process restarted.

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
2. Label interfaces and establish the intended protected, observation, management, and module zones before enabling bridge or route functions.
3. Start in observe-only mode; validate visibility and evidence flow.
4. Load the approved mission profile; confirm the displayed enforcement scope and rollback conditions.
5. Enable bounded controls only after an operator acknowledgement where the policy requires it.
6. During operation, use the UI for evidence and decision review; treat M.I.O. as an investigator, not an actuator.
7. On exit, export or seal evidence according to the mission retention policy, revoke temporary credentials, and record hardware custody.

## 6. Operator experience

The primary interface is a touch-friendly status-first console. It must make four questions answerable within one screen: What changed? What evidence supports it? What is currently enforced? What needs an operator decision?

The UI groups information by mission state rather than by internal service. Every recommendation shows source, freshness, confidence, and cited evidence. An approval screen restates action scope, duration, policy rule, and rollback path before it can reach the Action Arbiter.
