# The integrated defensive loop

Status: **design; phases I0–I5 below are the implementation plan**
([#190](https://github.com/01rabbit/Azazel-Nexus/issues/190): I0 #191, I1 #192,
I2 #193, I3 #194, I4 #196, I5 #195).
Related: [integrated-node doctrine](nexus-integrated-node.md) ·
[contract ownership](contract-ownership.md) ·
[Edge package verification](edge-package-verification.md) ·
[Knowledge Lite consumer](knowledge-lite-consumer.md) ·
[integration display](integration-display.md)

The doctrine promises one node that completes

```text
Detect -> Understand -> Decide -> Delay / Isolate / Redirect -> Explain -> Audit
```

Every piece of that loop exists somewhere, and none of it is connected. Edge
Core detects and decides, but nothing in Nexus receives what it found. M.I.O.
explains a situation frame, but only one a caller typed in. Knowledge Lite
answers lookups, but only for the technique ids a caller supplied. The status
screen shows six axes, but three are passed in as constants. This document
connects them without moving any authority.

## 1. What does not change

These hold in every phase. A change that needs one of them relaxed is out of
scope for this plan and needs its own decision.

- **Edge Core is the only thing that decides or enforces.** Nexus never
  re-derives, overrides, upgrades or replays an Edge decision. It records what
  Edge decided, labelled as Edge's.
- **There is no Nexus-to-Edge control channel.** Every connection in this plan
  carries data from Edge to Nexus. Nothing in Nexus writes to Edge, signals it,
  restarts it or changes its configuration.
- **The Edge Core shipped with Nexus stays observe-only.** The packaged posture
  (`ENFORCE=false`, `DRY_RUN=true`, `LEVEL=advisory`,
  `HIGH_IMPACT_AUTO=false`) is what the health contract checks. An Edge
  decision to isolate or redirect is shown as "Edge would isolate" and is not
  carried out. Enabling enforcement waits for Azazel-Edge#412 to declare the
  single enforcement path and for a commissioned enforcement design. It is not
  part of this plan.
- **M.I.O. and Knowledge advise.** Their output is an explanation with
  citations. It is never an input to an Edge decision and never a condition of
  one.
- **Every input from another product is untrusted data.** It is bounded,
  parsed into a closed shape, and refused as a whole when it does not fit. Its
  text never becomes an instruction, a path, or a unit name.
- **Degradation keeps the deterministic path.** If intake, M.I.O. or Knowledge
  is down, Edge Core keeps detecting and deciding exactly as before; Nexus
  reports what it is missing.

## 2. The loop, by phase

```text
 Suricata eve.json
        |
        v
 azazel-edge-core.service  (Edge's binary, observe-only, Nexus-owned unit)  [I0]
        |  one JSON line per alert, Edge -> Nexus only
        v
 az-edge-intaked  -> evidence store + audit transitions                    [I1]
        |
        v
 incident  -> situation frame -> mio.advise (entryd -> locald)             [I2]
                                    |
                                    +-> knowledge.lookup (technique ids)
        |
        v
 operator status: Edge axis live, incidents, Edge decisions, advice        [I3]
        |
        v
 (later) Edge-signed activation decision -> Deception Lite decoy            [I4]

 [I5] the whole chain run end to end with the real Edge Core binary
```

### I0 — foundations

- **Fabric pin `v0.9.0rc2` → `v0.9.0rc5`.** Edge and Deception produce
  effect references and observations at rc4. rc2 refuses their hierarchical
  refs (`edge:nft:1`) and accepts authority classes rc4 refuses. The diff from
  rc2 to rc5 touches only `effect_contracts`, which Nexus does not import yet,
  so the bump changes no current behaviour. Update `FABRIC_PIN`,
  `pyproject.toml`, and the stale `PLANNED_FABRIC_MODULES` entry that still
  lists `provisioning_contracts` as unused.
- **`azazel-edge-core.service`, shipped by Nexus.** `edge_package.py` already
  probes this unit name; nothing ships it. The unit runs the fixed binary path
  in the verified package (`/opt/azazel/edge-core/bin/azazel-edge-core`) with a
  fixed observe-only environment written in the unit, never one supplied by
  the package manifest. It forwards events to the intake socket
  (`AZAZEL_AI_SOCKET=/var/lib/azazel/run/edge-intake/edge-intake.sock`); Edge's own JSONL copy
  is off because it has no ceiling. It is governed like every other unit:
  masked and preset-disabled, enabled only when activation admits it in the
  `EDGE_BASELINE` tier, and run as its own system user.
- **Known limit: first start.** `EDGE_BASELINE` admission needs all five Edge
  checks, and one of them is "running", which a masked unit can never become.
  I0 does not relax this. Resolving it, without weakening what
  `edge-baseline-ready` means, is a separate design decision before I5
  ([#198](https://github.com/01rabbit/Azazel-Nexus/issues/198)).

### I1 — intake (Detect → Understand)

`az-edge-intaked`, a new daemon under its own user, listens on the intake
socket. Edge Core connects once per event and writes one line.

- **Parse into a closed shape.** The Edge `rust_event_engine_v1` event has
  `normalized`, `defense`, `enforcement`, `enforcement_status`, `source` and
  `pipeline`. Intake accepts exactly that, with every field typed and bounded
  (addresses parse as addresses, ports are 0–65535, severity 1–10, strings
  have length limits). Anything else is counted and refused; its content is
  not logged.
- **Record Edge's decision as Edge's.** `defense.action` and
  `enforcement_status` are stored verbatim as an *Edge decision observation*.
  Under the observe-only posture the status is shown as "would", never as
  "did".
- **Evidence.** Each accepted event becomes an evidence record with a content
  digest and a Fabric `schema.evidence.EvidenceRef` (`source="edge-core"`).
  The store is append-only with bounded retention (size and age), like the
  audit segments.
- **Incidents.** Events are grouped into incidents by a fixed key (source
  address, signature id, destination port) within a fixed window. The audit
  records incident transitions (`edge.incident.opened`, `edge.incident.updated`
  at bounded intervals, `edge.incident.closed`), not every packet. A flood of
  alerts cannot become a flood of audit records.
- **Never block Edge.** Edge Core connects with a blocking `connect` and no
  timeout, so a listener that stops accepting would stall detection. Intake
  accepts continuously and reads with a bound; when it is overloaded it drops
  and counts, it never stops accepting.
- **Liveness.** Intake reports when it last accepted an event, and how many
  it refused, so the status screen can tell "Edge is quiet" from "Edge is not
  reaching us". It cannot tell a quiet Edge from a stopped one by itself; the
  existing `edge-probed` running check answers that.

### I2 — explanation (Explain)

For an incident that is opened, or that crosses a severity threshold, intake
builds a situation frame in the existing `local_advisory.read_frame` shape
(`request_id`, `privacy_class`, `question`, `context`) and sends `mio.advise`
through `mio-entryd`, the same route an operator's request takes.

- **Technique ids.** Knowledge lookups need MITRE technique ids. Edge Core
  drops Suricata's `alert.metadata.mitre_technique_id` when it normalises an
  event, so this needs a small Azazel-Edge change
  ([Azazel-Edge#427](https://github.com/01rabbit/Azazel-Edge/issues/427)): carry the rule's own
  technique ids through as `normalized.technique_ids`. Nexus never maps a
  signature to a technique itself; a guessed mapping would be a claim with no
  source. Without technique ids, the frame goes without knowledge context.
- **When no model is admitted** (today, until HG-05), `mio.advise` already
  answers with the deterministic handoff. The incident view then shows Edge's
  own reason plus the Knowledge Lite references for its technique ids, which
  is still an explanation with sources.
- **Privacy.** Addresses in the frame are aliased by the existing sanitizer
  before anything reaches a remote provider. The remote route stays governed
  by the commissioned ceiling, unchanged.
- **Advice is stored with the incident**, with its route, provider class and
  knowledge citations. It is never sent to Edge.

### I3 — operator view and audit (Explain → Audit)

- `azazel-nexus status` stops passing constants for the axes it can now
  observe. The Edge axis reads intake liveness together with the existing
  probe. Incidents show Edge's decision ("Edge would redirect"), the advice,
  and their citations.
- The Fabric `StatusView` projection (`project_capability`) is called in
  production, not only in tests.
- Incident transitions are written to the audit chain through `auditd` like
  every other transition, and appear in the existing audit verification.

### I4 — redirect to Deception Lite (later)

A redirect is an Edge decision. Deception Lite may materialise a decoy only
when it holds an Edge-signed Fabric `EnvironmentActivationDecision`. Edge
already builds signed transition decisions (`deception_transition.py`) but
nothing calls it in production, and key distribution to Nexus does not exist.
This phase starts when Edge produces those decisions; until then a redirect
decision is shown as "Edge would redirect to a decoy" and no decoy is started.

### I5 — end to end

A Linux-container stage builds the real Edge Core binary from a pinned
Azazel-Edge revision, packages it with Edge's own packager, installs it, and
feeds a fixed Suricata `eve.json` capture through the whole chain: Edge Core →
intake → incident → `mio.advise` → Knowledge Lite lookup → status → audit
verification. The same run is then repeated on the rehearsal VM. Neither is
hardware evidence: HG-07 still needs the real host.

## 3. What is out of scope

- Enforcement by the shipped Edge Core (Azazel-Edge#412, separate design).
- Live AZ-04 and AZ-06 peers (#6, Fabric#25).
- A control or advice channel from Nexus to Edge. Edge's own Knowledge and
  engagement clients remain Edge's business.
- Any new approval, override or environment-variable switch.

## 4. Product boundaries

| Change | Repository |
| --- | --- |
| Fabric pin, Edge Core unit, intake daemon, incidents, advice, status, audit, end-to-end stage | Azazel-Nexus |
| Carry `alert.metadata.mitre_technique_id` into `normalized.technique_ids` | Azazel-Edge |
| Production producer of signed activation decisions and key distribution (I4) | Azazel-Edge, later |
