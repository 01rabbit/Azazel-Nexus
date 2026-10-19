# The integrated defensive loop

Status: **I0 and I1 implemented; I2–I5 planned**
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
  (addresses parse as addresses, ports are 0–65535, severity 0–10 because
  Edge can emit zero; lower numbers are more severe, and strings have length
  limits). Anything else is counted and refused; its content is not logged.
- **Record Edge's decision as Edge's.** `defense.action` and
  `enforcement_status` are stored verbatim as an *Edge decision observation*.
  Under the observe-only posture the status is shown as "would", never as
  "did".
- **Evidence.** Each accepted event becomes an evidence record with a content
  digest and an optional Fabric `schema.evidence.EvidenceRef` (`source="edge-core"`).
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

Concrete I1 limits and paths:

- Socket `/var/lib/azazel/run/edge-intake/edge-intake.sock`: leaf
  `azintake:azedge 2710`, socket `0660`, kernel peer uid must be `azedge`.
  The existing run root remains `root:root 0711`.
- Maximum JSON line 16 KiB plus newline, strict UTF-8, one line followed by
  EOF per connection. Up to 64 readers, each with a total 2 s deadline;
  listen backlog 512. A 256-record queue separates acceptance from disk I/O.
  Overflow accepts and closes immediately (`overloaded`); full queue drops
  with `queue_full`. No response is written to Edge.
- Closed parsing preserves `defense` and `enforcement_status` verbatim.
  Enforcement plans and metadata are validated, then reduced to observation
  fields (mode, trace id, selected action, target, policy reason, result and
  release ledger state); command strings are never retained. Only advisory,
  disabled-enforcement, dry-run, no-high-impact-auto observations are accepted.
  Other postures or applied outcomes produce `EDGE_NOT_OBSERVE_ONLY`.
  Other parser codes are `EDGE_TOO_LARGE`, `EDGE_JSON`, `EDGE_SHAPE`,
  `EDGE_TYPE`, `EDGE_RANGE`, plus fixed per-field `EDGE_TYPE_attack_type`,
  `EDGE_RANGE_attack_type`, `EDGE_TYPE_category`, `EDGE_RANGE_category`.
  Rule messages (`attack_type`) and categories accept up to 1024 characters,
  including tabs; other control characters and NUL are refused.
  Transport/storage codes are `peer_refused`, `overloaded`, `queue_full`,
  `read_deadline`, `read_error`, `storage_failed`, `status_write_failed`,
  `evidence_segment_full`, `incident_segment_full`, `incident_rate_limited`.
  Only fixed codes are counted; refused content and exception text are never
  recorded. Empty addresses remain empty strings (the absent-address sentinel);
  nonempty source and destination addresses use `ipaddress(...).compressed`.
  Signature ids are bounded unsigned
  64-bit values. Optional rule-supplied `technique_ids` accepts at most eight
  `T1234` or `T1234.567` identifiers, refusing the whole event on malformed ids.
- Private state `/var/lib/azazel/edge-intake` (`azintake:root 0700`): evidence
  in `evidence/YYYY-MM-DD.jsonl` (`0640`, append/no-follow), with a 64 MiB
  per-segment ceiling and a 256 MiB / 14-day retention budget. Retention deletes
  oldest whole segments, always keeping the newest and the active segment,
  even if these alone exceed the total budget. Age is relative to the newest
  stored segment's UTC day, never `received_at` or wall clock alone. During a
  run, that age reference advances by at most monotonic elapsed time plus one
  day for midnight rollover, so a forward clock jump cannot age out history.
  A full daily evidence segment refuses appends with `evidence_segment_full`;
  it does not permanently fail storage, and the next day's segment resumes.
  The SHA-256 digest covers canonical JSON of the validated, normalized event
  (including address normalization and reduced enforcement observations),
  not Edge's raw line; received time is separate. New segment creation fsyncs
  the containing directory.
- Incidents key on `(src_ip, sid, target_port)`, idle after 900 s, update at
  most every 60 s. `most_severe` is the minimum severity seen, initialized
  from the first event. At most 1024 remain open; capacity closes the oldest
  idle incident first. New openings are limited to 60 per rolling minute on
  a monotonic clock; excess events still go to evidence and increment
  `incident_rate_limited`, while existing incidents can still update.
  Technique unions retain a deterministic maximum of eight.
  `incidents/YYYY-MM-DD.jsonl` (`0600`) holds independent daily local
  `AuditLedger` hash chains, each at most 64 MiB (with envelope space reserved),
  with the same 256 MiB / 14-day retention and newest/active-segment protection
  as evidence. Only the current segment is verified at startup; older retained
  chains are not startup-verified. A full daily ledger counts
  `incident_segment_full` and omits transitions until the next segment, while
  evidence intake continues. Startup writes `edge.incident.reset` with `at`
  and reason `intake_started`, closing the interpretation of previous runs'
  open incidents. Clean shutdown writes `closed` with reason `shutdown` for
  each open incident (at most 1024). Forwarding to auditd remains I3.
  An evidence or ledger open/verification failure at startup exits nonzero
  before binding or signalling READY. Later writer failures close record
  acceptance until restart while the listener keeps accepting and dropping.
- Liveness `/var/lib/azazel/run/edge-intake-status/status.json` (`0644`) has a
  separate `azintake:azazel-operator 2750` leaf. Atomic snapshots are written
  at most every 5 s, with a final shutdown snapshot. A separate boolean
  `storage_failed` reports permanent record-writer failure; status-file write
  failures only increment `status_write_failed`. The pure `read_intake_status`
  decoder supplies no readiness or enforcement authority.
- `azazel-edge-intaked.service`: `azintake`, `Type=notify`, AF_UNIX only,
  `PrivateNetwork=yes`, no capabilities; only the three leaves above are
  writable. Supporting-tier admission lets it listen before Edge admission.
  Startup timeout is 30 s. It declares no `Restart=`: systemd's default does
  not restart it, and only the bootstrap pair declares lifecycle settings. Limits are `MemoryMax=256M`, `TasksMax=32`,
  `LimitNOFILE=256`, `LimitFSIZE=128M` (above the 64 MiB segment ceiling).
  It is installed masked and preset-disabled, with no dependency on Edge.

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
