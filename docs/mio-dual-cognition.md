# M.I.O. Dual Cognition Doctrine

## Design principle

> **M.I.O. never loses cognition when disconnected; connectivity only expands how deeply it can reason.**

M.I.O. — the Mission Intelligence Operator — is not a switch between a local model and a remote model. It is one operator-facing intelligence function with two independent cognition paths:

- **Local cognition** provides immediate, offline-capable understanding from locally authorized mission evidence.
- **Remote cognition** provides optional deeper analysis from a minimized and sanitized representation of the situation.

The distinction is architectural, not cosmetic. Losing connectivity may reduce analytical depth; it must not remove the system's ability to explain the current situation, show its evidence, or operate the deterministic Azazel-Edge core.

## Authority invariant

Azazel has a single decision path.

```text
Evidence -> Deterministic Core -> Action Arbiter -> Enforcement
                                  |
                                  +-> Decision explanation -> M.I.O.
```

M.I.O. can summarize, contextualize, compare runbooks, identify uncertainty, and recommend verification. It cannot:

- issue enforcement intents;
- alter policy or an evaluator's result;
- enable, reconfigure, or direct Azazel-Deception;
- bypass operator approval requirements; or
- make a remote response trusted merely because it is detailed.

When M.I.O. recommends an action, that recommendation is an evidence-linked advisory input. The Action Arbiter remains the only component permitted to authorize a control change.

## One M.I.O., two internal paths

The operator interacts with **M.I.O.**, not with competing assistant identities. Local and remote cognition are implementation paths whose provenance is visible when it matters, but their outputs are merged into a single coherent operator view.

```text
                                M.I.O.
                                  |
                        operator UI / voice / audit
                                  |
                        Cognition Merger
                          /             \
                 Local Cognition       Remote Cognition
                       |                     ^
                       |                     |
                       +--- Cognitive Router-+ 
                                   |
                    deterministic result + situation frame
```

The UI may display compact health information such as `Cognition: HYBRID`, `Local: READY`, `Remote: CONNECTED`, latency, and `Privacy: SANITIZED`. It does not force the operator to reconcile two personas or decide which model is authoritative.

## Local cognition

Local cognition is the immediate-response path. It uses only locally authorized data and stays available in disconnected operation within the active resource budget.

Typical responsibilities are:

- concise current-state summaries;
- explanation of the deterministic decision and rejected alternatives;
- runbook candidates and bounded next checks;
- short explanatory voice messages;
- use of verified Azazel-Knowledge context; and
- continuity of operator assistance when remote analysis is unavailable.

It may receive the full local `MioSituationFrame`, including evidence identifiers, NOC/SOC state, current and rejected actions, health state, Knowledge response, and Deception state. “Full” does not mean unrestricted propagation: normal least-privilege rules still apply inside the device.

Local cognition is optimized for short, grounded output. It is not allowed to convert uncertainty into a control instruction.

## Remote cognition

Remote cognition is the deep-analysis path. A remote endpoint may be a cloud service, an approved remote GPU service, or a controlled headquarters service. Its responsibilities can include:

- longer-horizon event correlation;
- complex cause and pattern analysis;
- cross-reference with approved knowledge sources;
- comparison of runbook options and past incident patterns; and
- detailed, operator-readable explanation.

Remote cognition never receives raw capture, unrestricted internal identifiers, secrets, enforcement credentials, or a management/control channel. It receives only a `MioRemoteFrame` emitted by the Cognitive Sanitizer.

The correct privacy posture is: **the remote service can understand the situation class and decision context without learning the internal network itself.**

## Cognitive Router

The router does more than test whether a network connection exists. It selects a cognition route from explicit mission conditions:

- connectivity and remote endpoint health;
- data sensitivity and egress policy;
- urgency and latency budget;
- local compute, memory, thermal, and battery headroom;
- incident complexity;
- operator-selected mission policy; and
- availability/freshness of Knowledge and Deception context.

| Mode | Use | Result |
| --- | --- | --- |
| **Local only** | Disconnected operation, sensitive evidence, external-analysis prohibition, or immediate response. | M.I.O. responds from local evidence and knowledge. |
| **Remote only** | Exceptional policy-controlled use when no local cognition backend is provisioned or available. | Remote output remains advisory; Core remains independent. |
| **Local → remote** | Normal connected operation. | Local gives the operator an immediate grounded answer; remote adds analysis when ready. |
| **Local + remote parallel** | High-severity or complex investigation, where policy permits. | Both paths analyze concurrently; the merger shows agreement or discrepancy. |

Remote-only operation is not the preferred field posture. The normal route is local-first so that a loss of connectivity cannot remove immediate operational cognition.

## Cognitive Sanitizer

The sanitizer is a mandatory, one-way egress boundary, not a prompt-preparation helper.

```text
MioSituationFrame -- classify/minimize/tokenize/validate --> MioRemoteFrame
                                                        |
                                                policy-approved egress
```

It applies an allowlist-based schema, replaces identities with stable mission aliases where necessary, strips raw payload and secrets, applies size/rate limits, and records a redaction decision plus request fingerprint. Ambiguous classification, invalid structure, and unavailable sanitizer policy all resolve to **deny remote egress**.

Illustrative transformation:

```text
local:  source_ip=10.21.43.18, hostname=HQ-DC-01, account=admin-tanaka
remote: source=HOST-7, target_role=authentication_server, account_type=privileged
```

The remote response returns through an untrusted-content boundary. It can be stored, cited, summarized, or shown to an operator, but it cannot invoke a tool, modify a policy, or create an enforcement action.

## Cognition Merger

The merger produces the one M.I.O. result shown to the operator. It preserves source provenance for every material claim and emits:

```text
summary | confidence | evidence citations | discrepancy | next checks | limitations
```

It does not blindly combine answers or average away conflict. A disagreement is itself operationally relevant information.

```text
Deterministic decision: THROTTLE
Local cognition:       Supports the current action.
Remote cognition:      Suggests stronger containment.

M.I.O. status: ANALYSIS DISAGREEMENT
Action taken: No additional action. The deterministic decision remains in force.
Next check: Verify corroborating evidence required by the isolation policy.
```

The merger favors evidence-backed deterministic findings for actual system state. It may recommend a bounded verification step, but it cannot escalate a control action.

## Cognition operating states

M.I.O. declares its current capability state rather than silently failing over.

```text
CORE ONLY -- local backend ready --> LOCAL -- remote eligible --> HYBRID
    ^                                  ^                            |
    |                                  +------ remote loss ----------+
    +---------- local backend unavailable ---------------------------+
```

| State | Available cognition | Operator meaning |
| --- | --- | --- |
| **CORE ONLY** | Deterministic explanations, evidence UI, deterministic voice alerts. | The Edge core is operational; model-assisted cognition is unavailable. |
| **LOCAL** | Local cognition and all Core capabilities. | Offline-capable M.I.O. assistance is active. |
| **HYBRID** | Local cognition plus policy-permitted remote cognition. | Immediate local response and optional deeper remote analysis are available. |

The system may enter `LOCAL` from `HYBRID` on remote loss and enter `CORE ONLY` if local cognition becomes unavailable or is shed to protect core resources. In every state, Evidence, the Deterministic Core, audit, and the configured enforcement policy remain independent of M.I.O.

## Two-layer voice design

Voice has separate safety and explanation paths.

| Layer | Source | Purpose | Availability |
| --- | --- | --- | --- |
| **Deterministic Voice Alert** | Action Arbiter and high-confidence health states | Immediate alert, decision, scope, and enforcement outcome. | Required whenever audio output is healthy; independent of AI. |
| **M.I.O. Explanatory Voice** | M.I.O. cognition result | Brief situation explanation, confidence, and next check. | Optional; unavailable in `CORE ONLY`. |

The deterministic path speaks first when urgency demands it. For example: “Warning. High-risk activity detected. Throttling is active.” M.I.O. may subsequently add: “Repeated authentication attempts continue; no lateral movement evidence is present. Review the authentication-service context.”

Both layers share acknowledgement, suppression, severity, and visual-fallback rules. Audio failure never blocks a policy decision or enforcement action.

## Data contracts

**Owner: Azazel-Fabric `mio_contracts` — target contract, not released.** The
shapes below state what Nexus needs from that module. They are illustrative,
not canonical: Nexus MUST NOT publish a local canonical form for a frame that
crosses a product boundary, and MUST NOT adopt an M.I.O. contract pin before
Fabric publishes one. The sanitizer policy, alias key material, and redaction
records themselves are Nexus-local; only the redaction record *reference* is
carried in the frame. See [contract ownership](contract-ownership.md) §3.3.

M.I.O. never receives an unstructured stream of arbitrary evidence. The Edge compiles a versioned, traceable situation record.

```text
Evidence + deterministic result + approved context -> MioSituationFrame
MioSituationFrame -> Local Cognition
MioSituationFrame -> Sanitizer -> MioRemoteFrame -> Remote Cognition
```

Illustrative `MioSituationFrame` (Nexus view of a target Fabric contract):

```json
{
  "trace_id": "AZ-2026-00142",
  "risk": 84,
  "state": "HIGH",
  "event_class": "credential_attack",
  "decision": "throttle",
  "rejected": ["observe", "isolate"],
  "evidence_summary": {
    "repeat_count": 54,
    "service_count": 2,
    "lateral_movement": false
  },
  "knowledge": {
    "seen_before": true,
    "behavior_class": "adaptive_probe"
  }
}
```

All frame versions carry a trace ID, schema version, evidence references, policy version, and data-classification result. `MioRemoteFrame` is a distinct contract; it contains only sanitizer-approved fields and includes the sanitization policy version and redaction record reference.

## Resource protection

The Core is more important than model availability. M.I.O. has explicit resource budgets and sheds optional capability before it threatens packet processing, evidence persistence, audit, or enforcement verification.

1. Reduce local context and concurrency under pressure.
2. Unload larger local backends before smaller local backends.
3. Enter `CORE ONLY` before core-service health is impaired.
4. Log the transition, expose it to the operator, and require verified health before restoration.

Resource policy is tier-specific and implementation-configured; it must define measurable CPU, memory, storage, thermal, battery, and latency thresholds rather than rely on implicit best effort.

## Relationship to mission modules

Azazel-Knowledge acts as M.I.O.'s verified mission memory: prior sightings, behavior patterns, indicators, relevant techniques, and historical response context. Both cognition paths may use the permitted subset of that context, subject to the frame and sanitizer contracts.

Azazel-Deception is an engagement space, not a cognition tool. M.I.O. may say that a deception action could yield evidence. The deterministic policy path must still authorize any change:

```text
M.I.O. advisory -> Action Arbiter -> approved mission action -> Azazel-Deception
```

This preserves the Azazel role model:

> **Edge decides. M.I.O. understands and explains. Knowledge remembers. Deception provides the engagement space.**
