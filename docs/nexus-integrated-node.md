# Azazel-Nexus Integrated-Node Doctrine

## Definition

Azazel-Nexus is a **rugged Linux integrated node that independently completes the minimum defensive loop—judgement, tactical knowledge, and deception—and expands in depth through external nodes when they are available.**

The normal Nexus baseline is not a degraded controller awaiting attachments. A single deployed node can:

```text
Detect -> Understand -> Decide -> Delay / Isolate / Redirect -> Explain -> Audit
```

AZ-04 Azazel-Knowledge and AZ-06 Azazel-Deception are capacity extensions. They increase the depth, history, and engagement endurance of a complete Nexus; they do not supply capabilities that the core deployment lacks.

How the pieces below are connected without moving any authority is described
in [the integrated defensive loop](integration-loop.md): I0–I3 are implemented
(Edge Core observe-only, intake, explanation, operator status and audit), and
the redirect to a decoy (I4) waits for Edge.

## Integrated topology

```text
                         AZAZEL-NEXUS
                 Rugged Linux Integrated Node

 +-----------------------------------------------------------+
 | Operator Plane: touch UI / console / voice / audit         |
 |                         |                                  |
 |                  M.I.O. Dual Cognition                     |
 |                    local <-> remote assist                 |
 |                         |                                  |
 | AZ-01 Edge Core: evidence -> evaluate -> arbitrate -> act  |
 |          |                 |                  |            |
 |   Enforcement Plane   Knowledge Lite       Deception Lite   |
 |                    embedded cache       embedded runtime   |
 +----------+------------------+-------------------+-----------+
            |                  |                   |
      protected network     AZ-04 Full         AZ-06 Full
                            Knowledge          Deception
                         optional extension  optional extension
```

## Role model

| Component | Role | Authority boundary |
| --- | --- | --- |
| AZ-01 Edge | Judgement | Sole authority for policy-bound decisions and enforcement intents. |
| M.I.O. | Cognition and explanation | Advisory only; cannot decide or actuate. |
| Knowledge Lite | Short-term tactical memory | Provides cited context; never an action authority. |
| AZ-04 Knowledge | Deep mission memory | Extends context and retention; never an action authority. |
| Deception Lite | Immediate decoy | Provides a safe, local redirect destination. |
| AZ-06 Deception | Engagement environment | Extends decoy realism and sustained engagement. |
| Nexus | Integration and command | Hosts the baseline and arbitrates all capability use. |

## Embedded baseline

### Knowledge Lite

Knowledge Lite is an Embedded Tactical Knowledge Cache. It is sized for the field node's active mission, not for retaining an entire intelligence platform.

It retains:

- recent high-confidence indicators and behavioral patterns;
- recent incidents and attacker reactions;
- mission-local allow/deny knowledge and operator annotations; and
- a minimal, mission-relevant reference subset for techniques and vulnerabilities.

Typical retention is measured in recent days for indicators and a bounded number of observations for patterns and incidents. The exact limits are mission profile settings. Its output is a cited `ContextResult` with fields such as `seen_before`, `behavior_hint`, `ioc_match`, `recent_history`, and confidence. `recommended_action`, if present, remains advisory.

### Deception Lite

Deception Lite is an Embedded Tactical Decoy Runtime. It deliberately hosts only a few mission-approved decoys—normally SSH and web, with an optional administration-facing decoy—rather than attempting to reproduce a complete engagement environment.

```text
protected LAN -> Edge -> approved redirect -> decoy bridge -> Lite containers
```

The decoy bridge is separate from forwarding and management zones. Default policy denies all paths from Lite decoys to the protected LAN, the Nexus control plane, and the Internet. Each redirect requires an Arbiter-approved intent, and decoy telemetry enters Evidence as a separately labeled source.

## External extension model

AZ-04 and AZ-06 are additive and may be used simultaneously with their embedded counterparts.

```text
knowledge query:  fresh trusted AZ-04 + Knowledge Lite -> context merge
redirect choice:  Edge policy -> Lite or AZ-06 destination
```

When AZ-04 is connected, it supplies broader history and richer retrieval. A priority filter synchronizes mission-relevant, signed tactical bundles back to Knowledge Lite. If the link is lost, the node continues from the last verified embedded context.

When AZ-06 is connected, Edge may route simple probes to Lite and use AZ-06 for sustained or complex engagement where policy permits. If AZ-06 fails, new full-node redirects stop, eligible redirects fall back to Lite, and the change is visible in the operator plane and audit record.

## Composition modes

A composition mode names **which optional modules are attached**. It is not a
capability state, and the two are never derived from each other — see
[capability model](capability-model.md) §1.1, which holds the same rule for the
resource profile.

| Composition mode | Composition | Meaning |
| --- | --- | --- |
| `CORE` | Edge only | Recovery, constrained, or topology-limited profile; deterministic protection continues. |
| `SELF-CONTAINED` | Edge + M.I.O. + Knowledge Lite + Deception Lite | Normal standalone Nexus operation. |
| `KNOWLEDGE-EXTENDED` | Self-contained + AZ-04 | Deeper memory and context are available. |
| `DECEPTION-EXTENDED` | Self-contained + AZ-06 | Expanded engagement capacity is available. |
| `FULL` | Self-contained + AZ-04 + AZ-06 | All local and external mission capacity is available. |

The expected degradation path is explicit:

```text
FULL -> Knowledge Lite and/or Deception Lite -> Local M.I.O. -> CORE
```

External loss never silently removes local knowledge or the ability to redirect. Local-model loss never removes the deterministic Edge Core.

**A composition mode is not a capability state.** The capability states are
`CORE`, `LITE`, and `FULL` ([capability model](capability-model.md) §1), and
they are the outcome of the four-dimensional intersection. What is *attached* is
part of the verified asset set — one dimension of that intersection, not the
product of it. A `KNOWLEDGE-EXTENDED` node whose interfaces are uncommissioned
reports the capability state `CORE`, and that is the intended case rather than a
contradiction: attaching a module supplies capacity, and capacity is not
capability.

`CORE` and `FULL` appear in both vocabularies, which is what makes the two easy
to confuse. In this section they name compositions; in
[capability model](capability-model.md) §1 they name capability states. A
document that uses either word must say which it means. `SELF-CONTAINED`,
`KNOWLEDGE-EXTENDED`, and `DECEPTION-EXTENDED` are composition modes only and
are never capability states.

Composition modes are **not authority levels** either. Azazel-Edge's
deterministic arbiter holds the same and only decision and enforcement
authority in `CORE`, `SELF-CONTAINED`, and `FULL` alike. Degradation removes
optional capacity; it never removes, transfers, or expands authority, and an
optional component's failure never blocks the deterministic control path.

## Deployment and service boundaries

The rugged PC baseline provides TPM 2.0 where available, encrypted storage, and
battery-supported operation. A self-contained Nexus needs a `lite` resource
envelope or better — 15360 MiB of usable RAM after firmware reservation or
more, with 4 cores / 8 threads and 512 GB encrypted NVMe as companion hardware;
6+ cores / 12 threads, a `standard` envelope, and 1 TB NVMe suit sustained field
work. That figure is the `lite` boundary from
[capability model](capability-model.md) §2 restated, not a second requirement:
16384 nominal minus the 1024 MiB firmware-reservation allowance, so a machine
sold as 16 GB reaches it. Meeting it is a statement about the hardware class
only, and remains subject to the measured Core reserve.

RAM and core count establish **capacity only**. Whether this node may capture,
enforce, or run Deception Lite depends on interfaces commissioned to confirmed
logical roles, on verified assets, and on current trust and health — evaluated
independently and intersected. A high-memory host with no commissioned
observation role, no independent management path, or no proven decoy isolation
is observe-only. See [capability model](capability-model.md) and
[commissioning](commissioning.md).

Persistent content is separated by retention domain. The target layout is a
`/data/` tier:

```text
/data/evidence/          /data/audit/              /data/models/
/data/knowledge-lite/    /data/deception-lite/     /data/bundles/
/data/cache/
```

What is implemented today uses installer-owned leaves under `/var/lib/azazel/`
instead (`runtime/src/azazel_nexus_runtime/runtime_paths.py`): Edge evidence in
`edge-intake/`, the incident ledger in `edge-incidents/`, explanations in
`incident-explain/`, the audit chain in `state/audit/`, Knowledge Lite in
`knowledge/` and models in `models/`. Only mission packs
(`/data/azazel/mission-packs`) and the Deception Lite root
(`/data/azazel/deception-lite`) are named under `/data/`.

The module manager owns capability discovery, signature/compatibility verification, state reporting, and safe handoff between embedded and external services. It does not grant an external module control-plane access.

The units Nexus ships today (`packaging/systemd/`) for the embedded loop are:

```text
azazel-edge-core.service          Edge Core, observe-only (EDGE_BASELINE tier)
azazel-edge-probed.service        Edge package health and running probe
azazel-edge-intaked.service       receive-only Edge findings intake
azazel-incident-explaind.service  local incident explanation and audit forwarding
azazel-knowledge-lited.service    Knowledge Lite read service
azazel-mio-entryd.service         M.I.O. routing entry
azazel-mio-locald.service         local model runtime host
azazel-auditd.service             audit ledger
```

alongside the control units (`azazel-activated`, `azazel-commissiond`,
`azazel-watchdog`, `azazel-model-fetchd`, `azazel-mio-remoted`). Every unit
except the activation controller is installed masked and preset-disabled
(`packaging/install.sh`, `packaging/azazel-nexus.preset`) and enabled only when
activation admits it.

**Planned, not implemented:** a Deception Lite unit (the runtime is
loopback-only, see integration-loop I4), a module-manager unit, and a
context-merger unit. Names such as `azazel-deception-lite.service`,
`azazel-module-manager.service` and `azazel-context-merger.service` are
placeholders; no such unit exists in `packaging/systemd/`, and
`activation.CORE_UNITS` assigns enforcement, Deception Lite and module-manager
units to slices that are not built yet.

## Operator visibility

The top-level UI presents actual capability rather than merely process health:

```text
SYSTEM      READY                 NETWORK    PROTECTED
EDGE        READY                 RISK       NORMAL
M.I.O.      LOCAL / HYBRID
KNOWLEDGE   LITE / LITE + FULL
DECEPTION   LITE / LITE + FULL
```

This makes extension loss legible without suggesting that the node itself has ceased to be operational.

The screen above is the target. What exists today is the console
`azazel-nexus status`: the six-axis [integration view](integration-display.md),
followed by a separate `edge loop:` section (intake and explainer liveness,
recent incidents shown as "Edge would … (observe-only, not executed)" with
their citations) that never changes an axis.

## Design invariant

> **Nexus is not a device that becomes useful when modules arrive. It is a complete field node whose external modules increase depth and endurance.**

Completeness is about capability, not about contract ownership. The records
Nexus exchanges with Edge, Knowledge, and Deception belong to Azazel-Fabric;
Nexus consumes them behind an exact release pin and adds no decision authority
of its own. See [contract ownership](contract-ownership.md).
