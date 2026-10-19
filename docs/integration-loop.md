# The integrated defensive loop

Status: **I0–I3 and I5 (container) implemented; I4 waits for Edge; I5 on the VM pending**
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
- Golden producer-shaped observations are hand-derived from Edge source;
  [fixture provenance and regeneration](../tests/fixtures/edge/README.md)
  records the known source commits and their limits.
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
  at bounded intervals and at once when the incident becomes more severe,
  `edge.incident.closed`), not every packet. A flood of
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
  `evidence_segment_full`, `incident_segment_full`, `incident_rate_limited`,
  `incident_ledger_torn`.
  Only fixed codes are counted; refused content and exception text are never
  recorded. Empty addresses remain empty strings (the absent-address sentinel);
  nonempty source and destination addresses use `ipaddress(...).compressed`,
  with IPv4-mapped IPv6 explicitly converted to dotted IPv4 first so evidence
  digests and incident ids are stable across Python versions.
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
  idle incident first. Ordinary new openings have a shared 60/min rolling
  monotonic budget and a 20/min cap per source. Severity <= 2 (Edge's
  isolate/redirect range) has a separate 30/min allowance, so an ordinary
  scanner flood cannot consume it. Excess events still go to evidence and
  increment `incident_rate_limited`; existing incidents can still update.
  `accepted` includes these rate-limited events because their evidence was
  stored successfully. Technique unions retain a deterministic maximum of eight.
  `/var/lib/azazel/edge-incidents/YYYY-MM-DD.jsonl` (`0640`) holds one local `AuditLedger` chain
  across daily segments: the first entry uses `chain_from=(seq, hash)` from
  the previous segment's head, as auditd does. Each incident segment is at most
  **16 MiB**; evidence remains 64 MiB and `MemoryMax=256M` is unchanged.
  Ledger iteration/verification streams one JSON line at a time, preserving
  newline and hash semantics, rather than expanding an entire segment in RAM.
  Startup verifies all retained incident segments and their links, including
  the current segment against the previous retained head. A backwards clock
  keeps incident writes in the latest segment to preserve chain order.
  The same 256 MiB / 14-day retention budget applies. Unlike auditd (which
  does not delete segments), intake durably writes a small `0640`
  `edge-incidents/retained-boundary.json` before deleting an oldest segment. It
  names the deleted segment and its last sequence/hash, and the next oldest
  retained segment, which must chain from that head. Replacement and directory
  are fsynced before unlink; a restart completes an interrupted prefix deletion.
  This is a local, unsigned retention boundary, not an external trust anchor.
  Missing retained segments or broken links refuse startup; intentional prefix
  deletion remains visible in the retained boundary, including after restart.
  A full daily ledger counts `incident_segment_full` and omits transitions
  while evidence intake continues. A 1 KiB reserve permits one
  `edge.incident.truncated` marker per segment (also remembered across restart)
  when space allows. Tracker state continues to advance even when transitions
  are dropped, so the ledger may miss openings, counts, updates or closes;
  the marker reports a gap, not reconstructed state. The next day resumes.
  Startup writes `edge.incident.reset` with `at` and reason `intake_started`,
  closing the interpretation of previous runs' open incidents. Clean shutdown
  writes `closed` with reason `shutdown` for each open incident (at most 1024),
  flushing all closes to the same segment with one final fsync. The worker
  join allows 20 s, below systemd's default stop timeout; a still-running
  writer reports storage failure and exits nonzero. I3 forwards selected transitions to auditd through the explainer.
  An evidence or ledger open/verification failure at startup exits nonzero
  before binding or signalling READY. An unterminated final incident line
  specifically reports `incident_ledger_torn` in status and is never silently
  truncated (even a parseable JSON record without its newline is refused).
  Operator recovery: stop intake, preserve a copy of the damaged segment and
  its boundary, and restore the complete segment from a trusted backup if
  available. Otherwise inspect and verify the complete prefix against the
  previous retained segment; explicitly remove only the incomplete tail after
  saving it and recording the loss in the operator's incident record. Restart
  then verifies again and writes the normal reset. Do not delete whole days or
  alter the retained boundary to bypass a broken link. Old independent daily
  ledgers also require operator archival/migration; startup does not re-link them.
  Later writer failures close record acceptance until restart while the
  listener keeps accepting and dropping.

- Liveness `/var/lib/azazel/run/edge-intake-status/status.json` (`0644`) has a
  separate `azintake:azazel-operator 2750` leaf. Atomic snapshots are written
  at most every 5 s, with a final shutdown snapshot. A separate boolean
  `storage_failed` reports permanent record-writer failure; status-file write
  failures only increment `status_write_failed`. The pure `read_intake_status`
  decoder supplies no readiness or enforcement authority.
- `azazel-edge-intaked.service`: `azintake`, `Type=notify`, AF_UNIX only,
  `PrivateNetwork=yes`, no capabilities; only its evidence, incident, socket and status leaves are
  writable. Supporting-tier admission lets it listen before Edge admission.
  Startup timeout is 30 s. It declares no `Restart=`: systemd's default does
  not restart it, and only the bootstrap pair declares lifecycle settings. Limits are `MemoryMax=256M`, `TasksMax=32`,
  `LimitNOFILE=256`, `LimitFSIZE=128M` (above the 64 MiB segment ceiling).
  It is installed masked and preset-disabled, with no dependency on Edge.

### I2 — explanation (Explain) — implemented

`az-incident-explaind` independently polls the I1 incident chains every second.
It has no Edge socket, no Edge dependency and no decision authority. M.I.O. or
Knowledge failure produces an explanation of missing context; it changes
nothing in intake, detection or Edge's observe-only decisions.

- **Read access.** Incident segments now live in their own leaf
  `/var/lib/azazel/edge-incidents`, `2750 azintake:azincident-read`, with
  `0640` files. `azexplain` is the only consumer granted `azincident-read`
  (through its unit's supplementary groups). Evidence remains under the
  unchanged `0700 azintake:root /var/lib/azazel/edge-intake` parent. Intake
  can write the new leaf; the explainer can only read it. Previous I1 private
  `edge-intake/incidents` history is not automatically moved by installation;
  stop intake before an administrator migrates any retained historical chains.
- **Cursor and integrity.** Private `0700 azexplain:root`
  `/var/lib/azazel/incident-explain` holds `cursor.json` (`0600`), atomically
  replaced and fsynced with segment name, byte offset, sequence, last hash,
  bounded address-free pending work, last explained severities and counters.
  Checkpoints are written only when their content changes. The reader
  checks the closed audit envelope, consecutive sequence, previous hash and
  `AuditEntry.recomputed()` for every line, carrying the head across daily
  segments. On first start or with a missing cursor, the reader verifies the
  retained history from genesis or the validated, unsigned local
  `retained-boundary.json` and seeds at the current end without explaining
  history. Only new transitions are explained. A lagging cursor whose segment
  was retired by a valid boundary resumes at the oldest retained segment and
  counts `cursor_overtaken`; this does not latch `chain_broken`.
  Reset, truncation and retention control records are validated
  without generating explanations. A broken chain is quarantined at its cursor
  (`chain_broken`), including subsequent segments; a new day cannot hide a gap.
  Status carries a fixed recovery hint; see [operator recovery](operations.md).
  Partial trailing lines wait for completion and report `ledger_tail_incomplete`
  once per cursor lifetime. Valid truncation markers count `incident_segment_full`.
  A poll reads at most 64 lines / 256 KiB, with a 64 KiB line ceiling and
  at most 256 directory entries. A corrupt checkpoint fails startup closed.
- **Selection and load.** Explain `opened`, then `updated` only when its
  `most_severe` number falls below the last explained value. Remember at most
  1024 incident severities; unknown updates are skipped. Pending work is a
  durable FIFO of 64 entries; full queues **drop newest**, counting
  `queue_full`, to preserve already accepted work. Stale queued updates are
  checked again when drained. During outage replay and before draining, an
  `opened` transition more than one hour past `first_seen` is dropped and
  counted as `stale_skipped`. At most six attempts occur in any rolling
  monotonic minute. A resumed cursor conservatively waits 60 seconds before
  further calls, so restarting cannot reset that budget. Record append precedes
  cursor checkpoint: a crash between the two can duplicate the last explanation
  (at-least-once processing), without affecting Edge.
- **Frame and privacy.** Frames use exactly `read_frame`'s four fields, with
  request id `inc-<16 hex>:<ledger sequence>` and a fixed Japanese question.
  Fixed context kinds `edge_alert`, `edge_decision`, `technique` carry the
  incident id, bounded signature/category/protocol, destination port, severity,
  count, “Edge would <action>”, policy reason and verbatim technique ids.
  Source/destination addresses, signature numeric ids, evidence digests, trace
  ids, targets and timestamps are omitted. The no-addresses rule covers both
  frames and explainer records, including checkpoint pending entries.
  The pseudonymous `incident_id` is the only incident/network identifier in
  frames: intake hashes the incident key together with the evidence digest,
  rather than encoding an address. It cannot be reversed to recover an address;
  it is retained only for local correlation and is never sent remotely.
  Technique ids describe public classifications, not network entities.
  Signature text is NFKC-normalized, then only ASCII letters and spaces survive;
  removed characters are dropped, whitespace is collapsed, tokens are capped at
  32 characters and the field at 160. No producer punctuation survives.
  Category is a closed list of common Suricata categories (unknown → `other`),
  protocol is `tcp|udp|icmp|other`, and policy reason is one of Edge Core's five
  `decide_defense` constants, verbatim (unknown → `other`). Signature prose can
  still contain instructions or alphabetic hostnames without dots: the filter
  cannot distinguish those from descriptive words. It is context data, never
  kinds, questions or request ids, and is kept local under P3.
  The class is **P3-restricted**, the most restrictive enum member: local
  inference/reference remains possible, while routing and sanitizer each
  prohibit remote egress regardless of profile or commissioning.
- **Clients and validation.** The sole advisory request is `mio.advise` to
  the fixed `mio-entry` socket. Deadline is **500 ms**, the existing
  `REFERENCE_DEADLINE_MS`, for both the verb and the entire client exchange.
  `azexplain` is admitted as SERVICE in entryd and knowledge-lited's explicit
  service allowlists, never the shared SERVICE list. Entryd identifies its
  kernel-derived UID and permits only `mio.advise` with P3-restricted frames;
  `mio.route` and less restrictive privacy classes are refused before routing.
  `azazel-operator` supplementary membership gives socket
  traversal; `classify()` explicitly excludes service/daemon UIDs from
  OPERATOR. Independent Knowledge `lookup_context` uses the technique ids,
  the `knowledge-read` socket, `azknowledge-read` membership and locald's
  existing **250 ms `KNOWLEDGE_MAX_S`** deadline. Empty ids skip the lookup.
  No signature-to-technique mapping is invented. Both sockets authenticate
  their daemon owner and peer via the shared bounded AF_UNIX exchange.
  Entry reply metadata is closed and bounded; local bodies pass
  `read_delivered`, handoff references pass `read_reference`, and Knowledge
  citations pass `read_knowledge_refs`, including technique membership.
  Remote replies are refused. Without an admitted model, the record can hold
  a deterministic reference banner plus independently obtained Knowledge refs.
- **Records and retention.** Append-only daily
  `incident-explain/explanations/YYYY-MM-DD.jsonl` (`0640`, inside private
  `0700` parents) stores only validated records: incident id, explained time,
  transition, Edge would action, only the sanitized signature and closed policy
  reason used in frames, technique ids, M.I.O. route/outcome/reason and advice
  or reference banner, validated
  knowledge refs, state `available|no_context|unavailable|skipped` and fixed
  failure/outcome codes. Pending checkpoints retain only the fields needed for
  selection and framing (including `first_seen` for freshness); no source or
  destination addresses, rule ids or evidence digests. It reuses intake's
  no-follow, fsynced append and retention:
  64 MiB per segment, 256 MiB total / 14 days, keeping newest and active
  segments, with monotonic protection against forward clock jumps. Full daily
  segments drop explanations for that day; permanent storage failures stop
  explanation work until restart. Startup storage failure exits nonzero before
  READY. Nothing is sent back to Edge.
- **Status and fixed codes.** Atomic `0644` snapshots in
  `/var/lib/azazel/run/incident-explain-status` (`2750
  azexplain:azazel-operator`) report last explained time/count, pending work,
  refusals/drops by code, cursor byte lag, sticky `chain_broken`,
  `storage_failed`, and M.I.O./Knowledge availability of the last attempt
  (`null` when unattempted/skipped). Status is written only on content changes,
  at most once every five seconds; `written_at` alone does not trigger a write.
  Refusal/outcome codes are `transition_refused`,
  `chain_broken`, `queue_full`, `mio_unavailable`, `mio_reply_refused`,
  `knowledge_unavailable`, `knowledge_reply_refused`, `storage_failed`,
  `status_write_failed`, `explanation_segment_full`, `cursor_refused`,
  `read_failed`, `cursor_overtaken`, `stale_skipped`, `incident_segment_full`,
  `ledger_tail_incomplete`, `mio_gated`, `mio_handoff`, `mio_local_non_advisory`.
  Normal gated/handoff/local non-advisory replies have these outcome codes,
  rather than `mio_reply_refused`; reference banners are still validated.
  Knowledge transport failures (including peer, bounds, service refusal and
  JSON decode errors from the exchange) report `knowledge_unavailable`; only
  malformed reply shapes/citations report `knowledge_reply_refused`. Valid
  unavailable Knowledge states also remain `knowledge_unavailable`.
  Neither rejected content nor exception text is logged.
- **Registration.** `azazel-incident-explaind.service` is SUPPORTING,
  `azexplain`, `Type=notify`, AF_UNIX only, `PrivateNetwork=yes`, no
  capabilities, no `Restart=`. Limits match intake: 30 s startup, 256 MiB
  memory, 32 tasks, 256 descriptors and 128 MiB file size. Only its private
  state and status leaves are writable. It is installed masked and
  preset-disabled and is covered by the normal renderer and staging checks.

### I3 — operator view and audit (Explain → Audit) — implemented

- **Separate operator section.** `azazel-nexus status` prints `edge loop:`
  after the integration view. The six axes and their vocabularies remain
  unchanged; intake liveness cannot establish Edge package health, running
  state, readiness or authority. The existing probe remains the Edge-axis
  source. Each loop snapshot is read with a strict decoder and bounded,
  no-follow regular-file read using shared read-only `runtime_paths` (including `AZAZEL_ROOT`);
  the runtime delegates to these same paths without importing runtime into
  the core library.
  Missing/unreadable/malformed snapshots report the fixed reason
  `snapshot absent or refused`.
  Snapshots older than 30 seconds, or over five seconds in the future, are
  stale. The deterministic summary still prints when components are absent.
- **Recent incidents.** `recent.json` shares the explainer's operator leaf
  (`2750 azexplain:azazel-operator`), atomically replaced/fsynced as `0644`,
  only on content change and no more than once per five seconds. Schema
  `azazel-nexus/recent-incidents/v1` holds `written_at` and at most 20 rows,
  sorted newest observation first. Transitions update open/closed state,
  first/last times, count, severity, closed policy reason, Edge action and
  technique ids. Last explanation state, fixed failure codes, route, outcome, summary and up to
  eight citations are retained. Summaries take the first 280 characters of
  validated advice/reference text, then apply I2's ASCII-letter/space filter
  (32 characters per word). Citation fields are only technique id, validated
  name and claim id; address syntax in names is refused. No network addresses,
  rule text, targets, evidence digests or raw advice enter this projection.
  Recent rows and audit comparison severities survive in the private cursor;
  older I2 cursors without these additional fields remain readable. Initial
  seeding still does not replay history. An intake reset closes the previous
  run's recent rows without manufacturing audit close records. Status renders at most five rows,
  always `Edge would <action> (observe-only, not executed)`, their summary and
  citations. The recent reader refuses the whole snapshot on any malformed
  row, unknown field or unsanitized/address-shaped summary; read bound 256 KiB.
- **Liveness detail.** Intake shows last accepted age, accepted count, the top
  four refusal counters and storage failure. Explainer shows explained count,
  chain break and its fixed recovery hint, storage failure, last attempted
  M.I.O./Knowledge availability and `audit_forward_dropped`. Unchanged
  explainer snapshots intentionally do not heartbeat: a quiet snapshot can
  age to stale; that means stale observation, not proof the process stopped.
- **Fabric presentation.** Production status calls `project_capability` with
  the same capability state and available set already displayed. It reports
  `projected (v0.9.0rc5)`, `not available (extra not installed)` or
  `refused (projection_refused)`. Exception text is never rendered and the
  optional extra never determines capability or interrupts status.
- **Exclusive audit writer.** Only auditd adds `azexplain` to the default
  SERVICE allowlist (in addition to I2's explicit entryd/knowledge-lited lists).
  The shared SERVICE list remains unchanged. Auditd also checks the
  kernel-derived uid: azexplain can only `audit.append` the three declared
  `edge.incident.*` types; every other uid, including root, is refused for
  those types (`principal_denied`, fixed detail `incident_writer`). Bootstrap
  and root-only verbs keep their existing admission. DAEMON classification
  prevents azexplain's supplementary operator group from granting OPERATOR.
  Existing `azazel-operator` membership traverses audit's `2710` leaf and
  reaches its `0660` socket; no new groups or socket permissions are needed.
- **Best-effort forwarding.** Openings, updates whose minimum severity falls,
  and closes become `edge.incident.opened|escalated|closed` via authenticated
  `audit.append`, reusing the bounded AF_UNIX client and validated receipt.
  Fields are pseudonymous incident id, severity 0–10, Edge action enum, count
  0–2^64−1, technique count 0–8, UTC occurred time, and for closes only reason
  `idle|capacity|shutdown`. Comparison state is bounded to 1024 ids and is
  independent of explanation attempt/rate limits. Occurrence time is the
  intake update time for openings/escalations and close observation time for
  closes (I1 has no separate close timestamp).
  A separate worker drains a 256-entry memory queue; full queues drop newest.
  Each exchange has a 250 ms total deadline; failures retry every second,
  dropping after five failed attempts so a permanently refused head cannot
  prevent later records. Drops and abandoned queued work at clean shutdown
  increment `audit_forward_dropped`. The queue does not survive crashes, and
  a lost acknowledgement can duplicate an append. Neither failure blocks
  ledger consumption or explanations. Auditd's existing cross-segment verifier
  and CLI health ledger verification accept these typed records. No ledger
  events are manufactured for history skipped during initial seeding.

### I4 — redirect to Deception Lite (later)

A redirect is an Edge decision. Deception Lite may materialise a decoy only
when it holds an Edge-signed Fabric `EnvironmentActivationDecision`. Edge
already builds signed transition decisions (`deception_transition.py`) but
nothing calls it in production, and key distribution to Nexus does not exist.
This phase starts when Edge produces those decisions; until then a redirect
decision is shown as "Edge would redirect to a decoy" and no decoy is started.

### I5 — end to end

The E2E harness stage **integrated defensive loop** (`tools/e2e_loop.py`) runs
the whole chain with real daemons under their real service accounts and unit
supplementary groups: `auditd` (azaudit), `knowledge-lited` (azknowledge, with
the bundle the offline-import stage admitted), `mio-entryd` (azmioentry),
`edge-intaked` (azintake) and `incident-explaind` (azexplain).

```text
python tools/e2e.py --root <short dir> --edge-core <built azazel-edge-core>
```

- **With `--edge-core`** the real Edge Core binary runs as `azedge` with exactly
  the shipped unit's environment (read from the `azazel-edge-core` profile;
  only the socket, eve and ledger paths are relocated into the harness root),
  over a Suricata `eve.json` with two alerts on one incident (the second more
  severe) and one non-alert event Edge must drop. It runs under `strace`: the
  only connections are `AF_UNIX` to the intake socket, writes on that
  connection carry no destination, and nothing binds, listens or opens another
  family. Its stdout shows only `dry_run` decisions.
- **Without it** the stage replays the golden fixture lines as the `azedge`
  peer would, and says so in its result; Edge's own filtering is then not
  exercised.
- Both assert: intake accepted exactly the alerts with no refusal; evidence
  digests match the validated events; the incident ledger verifies and holds
  `opened` then `updated` (escalation) with Edge's decisions unchanged and the
  rule's technique ids; the explainer stored two explanations on the
  deterministic handoff with Knowledge `available` and a citation for one of
  the event's techniques; `recent.json` lists the incident with citations;
  `auditd`'s chain verifies and holds `edge.incident.opened` and
  `edge.incident.escalated`; `azazel-nexus status` shows the incident with
  "Edge would … (observe-only, not executed)" and the citation; no address from
  the eve file appears in status, `recent.json`, explanation records or the
  audit chain; no unexpected socket exists; on shutdown the incident is closed
  (`shutdown`) in both ledgers.
- It needs Linux and root (real accounts and `SO_PEERCRED`); otherwise it is
  *not executed*, like the other account stages.

What it does not establish: the x86_64 package path (the container binary is
built for the host architecture, not packaged by Edge's packager, and not
started by systemd); activation admitting the unit (#198); hardware behaviour.
The same run on the rehearsal VM, through the installed units, is the next
step. Neither is hardware evidence: HG-07 still needs the real host.

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
