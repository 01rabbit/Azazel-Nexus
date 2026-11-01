# The integrated defensive loop

Status: **I0–I3 implemented; I5 harness stage implemented (container); I5 Edge packager x86_64 path and VM run remain; I4 waits for Edge**
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
  reports what it is missing. For intake, "down" here means its socket is
  absent or nothing listens on it. An intake process that is alive but has
  stopped accepting (stopped by `SIGSTOP`, a frozen cgroup, or wedged) is
  covered only by an Edge Core that includes Azazel-Edge#431: see "Never block
  Edge" under I1.

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
 incident  -> situation frame -> mio.advise (entryd -> locald | referenced) [I2]
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
- **First start resolved by [#198](https://github.com/01rabbit/Azazel-Nexus/issues/198).**
  `EDGE_BASELINE` admission needs the four package checks: present, matching
  version, matching digest, and healthy. The supporting probe runs the verified
  binary's fixed `--health` contract without starting the unit. The lease-bearing
  activation pass inspects the installed package and consumes only fresh,
  package-bound probe results; stale, missing or unreadable evidence cannot
  grant. Running is a consequence of starting, so it is not required to admit
  the unit. All other activation gates remain in place. A grant only enables
  the unit for a later boot; it neither starts it nor claims readiness.
  `edge-baseline-ready` still requires all five checks, including running, in
  projections, status and recorded inspection results. This separates permission
  to start from evidence that the baseline is ready without weakening readiness.

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
  digest. The store is append-only with bounded retention (size and age), like
  the audit segments. A projection of a record onto Fabric
  `schema.evidence.EvidenceRef` (`source="edge-core"`) exists
  (`fabric_boundary.project_edge_evidence`) and is tested against the pin;
  intake never imports Fabric. The explanation path carries each incident's
  first and latest evidence digests (pointers, not content) into the
  explanation record, whose Fabric `ClaimSet` view cites them as
  `EvidenceRef`s and says when one may not lead to a stored record
  (`evidence_not_stored`, `evidence_retention_elapsed`).
- **Incidents.** Events are grouped into incidents by a fixed key (source
  address, signature id, destination port) within a fixed window. The audit
  records incident transitions (`edge.incident.opened`, `edge.incident.updated`
  at bounded intervals and at once when the incident becomes more severe,
  `edge.incident.closed`), not every packet. A flood of
  alerts cannot become a flood of audit records.
- **Never block Edge.** Edge Core connects with a blocking `connect` and no
  timeout, so a listener that stops accepting would stall detection. Intake
  accepts continuously and reads with a bound; when it is overloaded it drops
  and counts, it never stops accepting. That covers an intake that is slow or
  flooded, not one that has stopped running: if the process stays alive but
  does not accept (stopped by `SIGSTOP`, a frozen cgroup, a wedged process),
  the kernel queues connections until the 512-entry backlog is full, and then
  Edge's next `connect` blocks and Edge stops detecting. Nexus cannot fix that
  from its side. The fix belongs to Edge, and Edge has it
  ([Azazel-Edge#431](https://github.com/01rabbit/Azazel-Edge/pull/431)):
  sending moves to a separate thread behind a bounded queue of 1024 lines with
  a 1 s write timeout, and when the queue is full Edge drops and counts the
  line instead of waiting. An Edge Core built before that change, if it is the
  one packaged, can still be stopped by an intake that is alive and not
  accepting; with it, the promise in section 1 holds for a wedged intake too.
  The pinned package version did not change with it, so check the producer
  revision recorded with the package.
- **Liveness.** Intake reports when it last accepted an event, and how many
  it refused, so the status screen can tell "Edge is quiet" from "Edge is not
  reaching us". It cannot tell a quiet Edge from a stopped one by itself; the
  existing `edge-probed` running check answers that.
- **Edge's own forward counts (#190, Azazel-Edge#432).** What Edge could not
  deliver never reaches the intake, so the intake cannot count it. Edge
  counts it: `dropped` (its forwarding queue was full) and `failed` (connect
  or write to the intake socket failed), with `sent` for lines written. Its
  only report used to be stderr, which the unit's `LogRateLimitBurst=200`
  suppresses under exactly the load that drops lines (a load test lost about
  460 lines and the journal kept no report of it). An Edge Core that includes
  Azazel-Edge#432 also sends the counts over the same intake socket, in the
  same one-line-per-connection framing and through the same bounded,
  non-blocking queue as events: one line
  `{"schema":"azazel-edge/forward-stats/v1","dropped":N,"failed":M,"sent":K,"since":S}`
  at start, then at most every 10 s when the counts changed since the last
  report Edge delivered, and at least every 5 minutes. Counts are cumulative
  for one Edge process; `since` is its start in epoch seconds. A report that
  is itself dropped or fails is not counted; the next one carries the totals.
  Nothing flows from Nexus to Edge, and Edge's detection and decisions do not
  depend on it.
  The intake accepts this line as its own closed shape: exactly those five
  keys, `schema` exactly that value, counts integers 0 to 2^63-1, `since` an
  integer 0 to 2^37. A line with a `schema` key is held only to this shape,
  and every other line to the event shape, so neither can pass as the other;
  anything else is refused with the usual codes. The counts are never stored
  as evidence, never tracked as an incident and never counted as `accepted`
  or `processed`. Intake status carries the latest report as optional
  `edge_forward` (`dropped`, `failed`, `sent`, `since`, `reported_at` (intake
  receive time) and `restarts`, the number of reports this intake run whose
  `since` changed or whose counts went back, that is Edge restarts), absent
  until a report arrives in this intake run. A reader with this change accepts
  a status without it; a reader that predates it holds status to the older
  closed shape and reads a status carrying it as unavailable. The intake and
  the CLI ship in the same package. Deploy order matters across products:
  update Nexus before an Edge Core with #432, because an older intake refuses
  the stats line as a malformed event (counted under `refused`). The peer is authenticated only as the
  `azedge` account (`SO_PEERCRED`), so the values are Edge's claim, bounded
  and shown as such, and nothing decides on them. They are lost when the
  intake restarts until Edge's next report (at most 5 minutes). An Edge Core
  without #432 never sends the line; status then says the counts were not
  reported.

Concrete I1 limits and paths:

- Socket `/var/lib/azazel/run/edge-intake/edge-intake.sock`: leaf
  `azintake:azedge 2710`, socket `0660`, kernel peer uid must be `azedge`.
  The existing run root remains `root:root 0711`.
- Maximum JSON line 16 KiB plus newline, strict UTF-8, one line followed by
  EOF per connection. Up to 64 readers, each with a total 2 s deadline;
  listen backlog 512. A 2048-record queue separates acceptance from disk I/O;
  it holds what a resumed intake receives at once (Edge's 1024-line forwarding
  queue plus the backlog), which a 256-record queue dropped as `queue_full`.
  Overflow accepts and closes immediately (`overloaded`); full queue drops
  with `queue_full`. No response is written to Edge. Edge flushes its backlog
  every 200 ms as one connection per line, so a connection whose single line
  and EOF are already readable when accepted is finished at once and never
  takes a reader slot; only incomplete ones are registered and count toward
  the 64. (A container load test at 600 lines/s lost 14.7% as `overloaded`
  when every accepted connection waited for the next poll.) At most 64
  connections per accept batch are finished this way, each with at most eight
  reads; the rest are registered as before, except that when no reader slot is
  left a connection is still read once before it is refused. (With Edge's
  forwarding thread, Azazel-Edge#431, lines arrive in bursts; without that
  read a container load test at 800 lines/s lost 13.7% as `overloaded`.) The
  intake never stops accepting to push back, because an Edge Core older than
  #431 would then block on a full backlog. So `overloaded` now means
  incomplete connections beyond the reader slots: a completed connection is
  not refused when the slots are full, and sustained load shows as
  `queue_full` instead.
- **Order across connections (#327).** Edge observations are processed in
  the order the intake accepted their connections, not the order their lines
  happen to be read. Edge sends from one thread, one connection per line, in
  observation order, and the kernel hands connections over first in, first
  out, so accept order is Edge's send order. A line read sooner from a later
  connection (one accepted with its data already there, while an earlier one
  was accepted before its line arrived) waits for every earlier connection
  to finish, so notify then isolate is recorded as `opened` then the
  escalation, however the reads interleave. The contract:
  - The order key is the intake's own accept sequence. Edge's clock
    (`normalized.ts`, `ingest_epoch`) is not used for ordering or for any
    decision: it is Edge's claim, two observations may carry the same time
    (the SO-06 golden pair does, and so does every observation of the SO-06
    replay, which pins Edge's clock inside its harness only; #17), and the
    shipped Edge's clock is not fixed. With no time involved there are no
    ties and no missing values.
  - The wait is bounded: a line waits at most 250 ms (`REORDER_WAIT_S`) for
    each earlier unfinished connection, never past that connection's read
    deadline, and never with more than 1024 lines held behind one
    (`REORDER_HELD`). Normally the earlier line is already in the kernel and
    nothing waits beyond the same poll.
  - A connection still unfinished after that wait no longer holds the lines
    behind it. Its line, if it completes before the read deadline, is
    processed when read, so it may come after later ones, as before #327.
    Nothing is dropped for ordering: accepted equals processed.
  - At shutdown, lines already read are queued in accept order before the
    writer finishes. They go through the same bounded queue, so a queue
    already full at that moment still counts them as `queue_full`.
  - Each record's `received_at` is the intake time its connection was
    accepted (it was the time the line was read). For lines released in
    accept order it therefore follows the processing order. A late line
    (its connection unfinished past the wait) is the exception: it is
    processed after lines accepted later, so its `received_at` is earlier
    than theirs, by at most the read deadline (2 s), and the incident's
    `last_seen` can step back by as much. Severity, escalation and the
    explanation do not depend on it; the only effect is that an idle close
    (after 900 s) can come up to 2 s sooner.
  - Order between two different senders (two Edge processes, or a restart
    overlapping its predecessor) is the order their connections reached the
    kernel; nothing beyond that is promised. Consumers still treat an
    incident without an escalation as possible (a late line as above, a rate
    limited severe opening, a full ledger), and never rely on one alone.
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
  `incident_ledger_torn`, `segment_from_future`.
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
  The day a record is written to is held the same way: during a run the clock
  used to name a segment is at most the first write's time plus elapsed
  time (Linux `CLOCK_BOOTTIME`, which counts suspend) plus one day, so a
  forward jump cannot create a future-dated
  segment. A segment dated more than a day past the clock can still exist
  (written by an earlier version, or by a run that started with the clock
  already ahead). It is reported in status as `segment_from_future`, and
  the status screen always shows it; it is never the age reference: on
  restart, age is measured from the earlier of the newest segment's day and
  the clock plus one day, so correcting the clock does not delete the last
  14 days. Evidence then returns to today's segment. The incident chain can
  only continue in its latest segment, so incident transitions keep going to
  the future segment until its day arrives, and that segment can fill
  (`incident_segment_full`); recovering earlier needs the operator. A run that
  starts with the clock already ahead still measures age by that clock, since
  nothing local says it is wrong.
  *Clock behind.* A node without an RTC starts with its clock at the last
  shutdown time (or earlier) and steps it forward when time sync arrives.
  While the node has been up for less than 15 minutes (`CLOCK_SETTLE_S`,
  measured by `CLOCK_BOOTTIME`), a step past the bound re-anchors it, so
  segments follow the corrected clock. Later in uptime the bound holds: if
  time sync first arrives after that, segments stay dated by the first
  write's time plus elapsed time (plus one day) until the intake or
  explainer restarts; records still carry their own times, and nothing is
  aged out early. The price is that a wrong forward step in those first 15
  minutes does create a future segment, which `segment_from_future` reports
  after the next restart. Ordering the units after `time-sync.target` was not
  chosen: it waits only when a wait-sync service is enabled, and then holds
  the intake that Edge writes to for as long as an offline node has no time
  source.
  A full daily evidence segment refuses appends with `evidence_segment_full`;
  it does not permanently fail storage, and the next day's segment resumes.
  The event still reaches the incident tracker and its transitions still reach
  the incident ledger, so new incidents (severity 1 included) keep opening for
  the rest of that day. Such an event is not counted in `accepted`, and its
  incident's transitions carry `evidence_stored: false` from then on: the
  digests remain correlation ids, but at least one of them names evidence that
  was never stored. The field is absent while all evidence was stored.
  `first_evidence`/`latest_evidence` digests are for correlation only and need
  not exist in the evidence files. The field is not forwarded to audit; it is
  visible only in the incident ledger, `recent.json` and status. Intake status
  counts `processed` (events that reached the tracker, stored or not, so
  `processed >= accepted`) and `last_processed_at`, so a live Edge does not
  look stopped while `accepted` is frozen. While an event's evidence was not
  stored, its ordinary `updated` transitions (severity > 2) are not written to
  the incident ledger; `opened`, `closed` and severe `updated` still are, and
  the closing transition carries the final count.
  The SHA-256 digest covers canonical JSON of the validated, normalized event
  (including address normalization and reduced enforcement observations),
  not Edge's raw line; received time is separate. New segment creation fsyncs
  the containing directory.
- Incidents key on `(src_ip, sid, target_port)`, idle after 900 s, update at
  most every 60 s. `most_severe` is the minimum severity seen, initialized
  from the first event. At most 1024 remain open; capacity closes the oldest
  idle incident first. Ordinary new openings have a shared 60/min rolling
  monotonic budget and a 20/min cap per source. Severity <= 2 (Edge's
  isolate/redirect range) has a separate 30/min allowance with its own cap of
  5/min per source: one host showing more than five new severe
  `(sid, port)` pairs a minute is itself scanning, and five leaves 25 of the
  30 to other sources. An ordinary incident whose severity falls to 2 or
  below takes one of these severe openings (and its source's) at that moment,
  exactly like a severe opening; without one, its recorded severity stops at
  3, the refusal counts in `incident_rate_limited`, and its next severe event
  tries again. Opening ordinary and escalating therefore gets no more severe
  incidents than opening severe; the evidence record keeps the real severity.
  At most 256 (a quarter of 1024) open incidents may be severe, however they
  became severe; a new severe opening or escalation beyond that closes held
  severe incidents (reason `capacity`) until it fits, rather than being
  refused, because the displaced incident has already been opened, recorded
  and explained while a refused one would never be recorded. Severity 2
  incidents are displaced before severity 1, then the least recently seen,
  so 256 fresh severity 2 incidents cannot push out a quiet severity 1 one.
  A displaced or idle-closed incident is gone: the same key later opens a new
  incident with a new `incident_id`, which needs a severe opening again.
  Excess events still go to evidence and
  increment `incident_rate_limited`; existing incidents can still update.
  `accepted` includes these rate-limited events because their evidence was
  stored successfully. Technique unions retain a deterministic maximum of eight.
  What a flood leaves standing:
  - *Ordinary flood* (severity > 2, any number of sources): it uses at most the
    60/min ordinary budget and never the severe allowance, so every new severe
    incident still opens, up to 30/min and 5/min per source. It cannot use the
    ledger's severe reserve (below), so severe openings, escalations and
    closes are still written the day it fills the ordinary space.
  - *Severe flood from one source* (severity <= 2 to many ports or
    signatures): that source opens 5/min and the rest are rate-limited; the
    other 25/min remain for every other source, so another host's severity 1
    still opens.
  - *Severe flood from six or more sources*: it can use all 30/min, and a
    genuine severe opening in the same minute is then rate-limited (counted,
    evidence kept, no incident). Its incidents can also displace older severe
    incidents through the 256 cap; displaced incidents are closed and that
    close is recorded. Nothing here stops a large enough set of severe sources
    from hiding one more severe source for that minute.
  - *Escalation flood* (ordinary incidents then made severe): each escalation
    takes a severe opening, so it is held to the same 30/min and 5/min per
    source, and to the 256 held severe incidents.
  - *How long the reserve lasts.* The 1 MiB severe reserve is a reserve, not a
    budget per minute: once the ordinary space of the day is full, each severe
    opening, fall in severity and severe close uses it. A sustained severe
    flood from six or more sources at the full 30/min, with displacement
    closes, writes about 40 KB a minute into it and uses it up in roughly 25 to
    40 minutes; after that, severe transitions are refused too
    (`incident_segment_full`) until the next day's segment. Evidence still
    keeps the events.
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
  while evidence intake continues. The last 1 MiB of each 16 MiB segment is
  reserved: only the opening and close of an incident whose `most_severe` is
  <= 2, an update that lowers the `most_severe` this ledger last recorded for
  it (including an ordinary incident becoming severe), and the `truncated`,
  `reset` and `retention` control records may use it. Routine 60 s refreshes
  of an open severe incident whose severity has not fallen use the ordinary
  space, so up to 1024 open severe incidents refreshing cannot drain the
  reserve; ordinary churn (for example while evidence is full and the ledger
  alone takes the load) is likewise refused with `incident_segment_full`
  before it can crowd out a later severity 1 opening. The first ordinary
  refusal there writes the
  truncation marker. A further 1 KiB reserve permits one
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
  before binding or signalling READY.
  **Torn tail after a power cut (#212).** The shutdown batch above is the
  moment most exposed to a power cut, and a cut there can leave the newest
  segment ending in an unterminated line. The unit has no `Restart=` (only the
  bootstrap pair may declare lifecycle settings, and a restart would not help
  a refusal that repeats), so such a tail used to keep the integrated loop
  down until an operator repaired it, while Edge kept detecting into a
  missing socket. Startup now recovers it, but only when all of these hold:
  the bytes after the last newline are in the **newest** segment; they are at
  most 64 KiB (the explainer's ledger line limit, so longer than any record
  this ledger writes); every complete line before them verifies, chaining from
  the previous retained segment's head exactly as the normal startup check
  does; at most 64 quarantined tails are already held; and the same bytes have
  not already been recovered at that place. Anything else -- a torn older
  segment, a segment whose name is not `YYYY-MM-DD.jsonl` in digits, a broken
  or relinked line before the tail, a longer tail, non-UTF-8 before the tail,
  a segment that changed between being read and being cut -- refuses exactly
  as before. The segment is read, checked and cut through one descriptor, and
  its size is checked again just before the cut. Recovery never rewrites a
  complete record, and it is not silent:
  1. The torn bytes are written to
     `/var/lib/azazel/edge-intake/incident-quarantine/<segment>.<offset>.<sha256>.pending`
     (directory `0700`, file `0600`, owned by `azintake`; never the
     group-readable incident leaf, since a partial record may hold
     addresses), and the file and directory are fsynced.
  2. The segment is truncated to the last newline and fsynced.
  3. A chain record `edge.incident.ledger_recovered` is appended with `at`,
     `segment`, `offset`, `torn_bytes` and the `sha256` of the quarantined
     bytes (never their content); then the file is renamed to `.torn`. The
     usual `edge.incident.reset` follows.
  A power cut during recovery is finished by the next start: before step 1
  completes nothing changed (a leftover `.torn-*` temporary is removed); after
  step 1 the same bytes find their `.pending` file (its digest is checked)
  and are cut; after step 2 a `.pending` file whose segment, offset and
  digest no retained `ledger_recovered` record names gets its record (the
  digest alone is not enough: short tails share a record's opening bytes, so
  the same bytes can be torn again elsewhere and each cut gets its own record); after step 3 it is only
  renamed. If the segment has no room for the record (it uses the control
  reserve), the file stays `.pending` and the record is written on a later
  start. Status reports `ledger_recovered` (the number of quarantined tails
  held), and `azazel-nexus status` shows it under the intake line. The
  explainer validates the record as a control record and does not forward
  it; auditd's allowlist is unchanged. Intake and explainer ship in the same
  package; an older explainer reading the new record after its chain check
  would count it as `transition_refused`, not `chain_broken`. An explainer cursor saved past the
  recovered bytes (it read lines that were still only in the page cache)
  still reports `chain_broken`; follow its status hint
  (`inspect_incident_chain_then_remove_cursor_and_restart`).
  Inspect a quarantined tail with root, compare its digest with the ledger
  record, and remove it once reviewed; at 64 held tails recovery refuses
  again until some are removed.
  Operator recovery for a refused start: stop intake, preserve a copy of the damaged segment and
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
  1024 incident severities; unknown updates are skipped. Pending work holds
  64 entries and is taken most severe first (an entry ranks by the most severe
  value queued for its incident, so an opening precedes its own escalation),
  oldest first within a rank. Full queues **drop newest**, counting
  `queue_full`, to preserve already accepted work, except that an arrival with
  severity <= 2 (intake's severe threshold, one shared constant) displaces the
  newest entry of another incident ranked above 2, also counted as
  `queue_full`. A queue of only severe work still drops the newest arrival,
  so when the 64 entries are all severe a new severe arrival is lost as
  `queue_full`. While severe arrivals keep exceeding the explanation budget
  ordinary entries are not taken, but this starvation is bounded: an
  `opened` entry more than one hour past `first_seen` is discarded as
  `stale_skipped` when drained. A displaced incident's recent row shows
  `queue_full` unless it already shows an explanation, which stays true for
  the earlier severity and is kept. An incident whose opening was never
  explained (dropped, displaced or stale) has no baseline: an ordinary update
  of it is not explained and its row shows `queue_full` rather than awaiting
  an explanation that will not come, while an update into the severe range is
  explained as the incident's first.
  Entries are checkpointed in arrival order as before, so earlier cursors
  remain readable. Stale queued updates are
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
  entryd's fixed explainer listener, `mio-advise`. Deadline is **500 ms**, the existing
  `REFERENCE_DEADLINE_MS` (now `mio_referenced.REFERENCE_DEADLINE_MS`) for the
  verb; entryd measures it once and the route, any fallback and the playbook
  reference all share it, delivering the reply before it. The client exchange
  waits 250 ms longer (`ADVISE_CALLER_MARGIN_MS`), so the explainer does not
  record `mio_unavailable` for a handoff entry has answered.
  Before capability probes and optional deep inference, entryd gives the
  shared model-free `local.assess` lane at most the slack left after the
  30 ms entry delivery reserve, 200 ms handoff reserve, 100 ms minimum deep
  AI attempt, 50 ms ledger allowance, and 75 ms probe reserve. Three reads
  need 72 ms initially: each of the two observations receives one twelfth of
  the probe remainder, while admission recomputes after them and needs `5/72`
  of the initial remainder. The 75 ms reserve rounds that threshold up to
  `15 * MIN_PROBE_S`. locald also holds 20 ms from its received deadline for
  reply delivery; at a clean 500 ms request, entryd can pass at most 45 ms to
  locald, leaving up to 25 ms for the shared core. Earlier ledger work reduces
  that cap. Each sequential probe rechecks the same monotonic deadline and is
  skipped fail-closed if its share is below `MIN_PROBE_S`; admission is then
  false and LOCAL is not permitted. Slow gate or ledger work consumes the
  same deadline and can make later probes unobservable without changing the
  trusted status of any Knowledge result that was returned. These are software
  bounds, not latency measurements.
  `azexplain` is admitted as SERVICE in entryd and knowledge-lited's explicit
  service allowlists, never the shared SERVICE list. Entryd identifies its
  kernel-derived UID and permits only `mio.advise` with P3-restricted frames;
  `mio.route` and less restrictive privacy classes are refused before routing.
  `mio-advise` is entryd's second listener, in its own leaf
  `/var/lib/azazel/run/mio-advise` (`2710 azmioentry:azmio-advise`), and it
  registers `mio.advise` alone; the operator `mio-entry` socket is unchanged.
  `azexplain` reaches it through `azmio-advise` membership. It does **not**
  hold `azazel-operator`, so it reaches no operator socket leaf and no
  `2750` operator read area (#213 O1); `classify()` also excludes
  service/daemon UIDs from OPERATOR. The latency-bounded shared-core fast
  assessment does not query Knowledge; it returns `not_queried` and a fixed
  next check directing the operator to the separate validated Knowledge lane.
  The explainer's independent `lookup_context` uses the technique ids, the
  `knowledge-read` socket, `azknowledge-read` membership and its existing
  **250 ms `KNOWLEDGE_MAX_S`** deadline. Empty ids skip that lookup.
  No signature-to-technique mapping is invented. Both sockets authenticate
  their daemon owner and peer via the shared bounded AF_UNIX exchange.
  Entry reply metadata is closed and bounded; local bodies pass
  `read_delivered`, handoff references pass `read_reference`, and Knowledge
  citations pass `read_knowledge_refs`, including technique membership.
  Remote replies are refused. Without an admitted model, the record can hold
  a deterministic reference banner plus independently obtained Knowledge refs.
  Readers from before PR #396 reject its new `fast_assistance` record field;
  readers at PR #396's earlier head `48e5885` recognize that field but reject
  this candidate's new `not_queried` status. Rollback does not rewrite or
  discard the append-only source ledger or explanation records.
- **Entry rate and route ledger capacity (#211 S4).** Entryd admits at most
  **30 requests a minute per kernel-reported UID (burst 10)**, five times the
  explainer's ceiling of six `mio.advise` a minute. Over the limit, and when
  the caller's own share of the day's route segment is spent, it replies with
  the bounded refusal `rate_limited` before routing or writing anything. The
  explainer has its own 28 MiB daily share that no operator or other service
  can spend, so a flooding caller cannot make the explainer's advice
  unavailable. The arbiter (`azarbiter`) likewise has its own 4 MiB share
  outside the 12 MiB pool the operators share, so operators cannot refuse
  its `mio.route` (#227). The
  explainer treats that like any refusal from entryd: the explanation is
  still recorded, with route `unavailable` and failure code `mio_unavailable`,
  and the next explanation asks again; nothing latches. Six advice requests a
  minute write about 20 MB a day to entryd's route ledger, which is now daily
  segments with bounded retention (see `docs/mio-runtime.md`).
  `/var/lib` capacity for it: at most about 238 MiB (46 MiB per day, 192 MiB
  / 14 days retained plus the current segment), **plus** the
  `legacy-route.jsonl` archive on nodes upgraded from the single file, whose
  size is whatever `route.jsonl` had reached (about 20 MB per day the loop
  ran) and which stays until the owner removes it.
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
  segments, with monotonic protection against forward clock jumps (including
  the same `segment_from_future` report and restart age reference). Full daily
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
  `ledger_tail_incomplete`, `mio_gated`, `mio_handoff`, `mio_local_non_advisory`,
  `segment_from_future`.
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
  on content change no more than once per five seconds, and rewritten
  unchanged every 20 seconds so a quiet node's rows do not read as stale. Schema
  `azazel-nexus/recent-incidents/v1` holds `written_at` and at most 20 rows,
  sorted newest observation first. Transitions update open/closed state,
  first/last times, count, severity, closed policy reason, Edge action and
  technique ids. Last explanation state, fixed failure codes, route, outcome, summary and up to
  eight citations are retained. Summaries take the first 280 characters of
  validated advice/reference text, then apply I2's ASCII-letter/space filter
  (32 characters per word). Citation fields are only technique id, validated
  name and claim id; address syntax or a bare number token in a name drops
  that citation. No network addresses,
  rule text, targets, evidence digests or raw advice enter this projection.
  Recent rows and audit comparison severities survive in the private cursor;
  older I2 cursors without these additional fields remain readable. Initial
  seeding still does not replay history. An intake reset closes the previous
  run's recent rows without manufacturing audit close records. Status renders at most five rows,
  labelled `most severe <n>` (the minimum seen) apart from
  `latest: Edge would <action> (observe-only, not executed)` (the latest
  decision), their summary (fixed `awaiting explanation` while pending) and
  citations. A row carries optional `evidence_stored: false` (present only as
  false) once some of that incident's evidence hit a full day, and status
  prints `(evidence not stored)` on it. Audit records do not carry this;
  it is visible only in the incident ledger, recent rows and status, and the
  row's evidence digests (ledger only) are correlation ids that need not exist
  in the evidence files. The recent reader refuses the whole snapshot on any malformed
  row, unknown field or unsanitized/address-shaped summary; read bound 256 KiB.
- **Liveness detail.** Intake shows last processed age, processed and
  accepted counts, the top four refusal counters (plus
  `evidence_segment_full` whenever it is nonzero) and storage failure, then
  `Edge forward: dropped N, failed M (as reported by Edge); sent K since Edge
  start <UTC time>; last report Ns ago`, marked `stale` once no report came
  for 900 s (three of Edge's 5-minute reports), with a line counting Edge
  restarts when there were any. Without a report it prints `Edge forward: not
  reported since the intake started`. The intake section ends with the
  Deception Lite decoy's line (#196 P2):
  `decoy (Deception Lite; Nexus's own observation, not Edge's; not hardware
  evidence): accepted N; last accepted Ns ago; refused M (CODE=n, …)`, or
  `decoy (Deception Lite): not listening (decoy socket not open); refused M`
  when the intake has no decoy socket open. It shows counts, the last time
  and refusal counts per fixed code only, never an address, a payload or a
  stored interaction; the decoy's refusal codes (`DECOY_*`, `decoy_*`) are on
  this line only, not in the intake's `refusals:`. Explainer shows explained count,
  chain break and its fixed recovery hint, storage failure, last attempted
  M.I.O./Knowledge availability, `audit_forward_dropped` and
  `audit_forward_refused`. Unchanged
  explainer snapshots intentionally do not heartbeat: a quiet snapshot can
  age to stale; that means stale observation, not proof the process stopped.
- **Fabric presentation.** Production status calls `project_capability` with
  the same capability state and available set already displayed. It reports
  `projected (v0.9.0rc5)`, `not available (extra not installed)` or
  `refused (projection_refused)`. Exception text is never rendered and the
  optional extra never determines capability or interrupts status. An
  unexpected failure in either the loop or the Fabric section (including an
  unparseable `--as-of`) prints only `edge loop: unavailable (internal)` or
  `fabric status view: unavailable (internal)`, and status continues.
- **Exclusive audit writer.** Only auditd adds `azexplain` to the default
  SERVICE allowlist (in addition to I2's explicit entryd/knowledge-lited lists).
  The shared SERVICE list remains unchanged. Auditd also checks the
  kernel-derived uid: azexplain can only `audit.append` the three declared
  `edge.incident.*` types; every other uid, including root, is refused for
  those types (`principal_denied`, fixed detail `incident_writer`). Bootstrap
  and root-only verbs keep their existing admission. DAEMON classification
  would keep any operator group azexplain carried from granting OPERATOR,
  but it carries none. Auditd serves azexplain on a second listener,
  `/var/lib/azazel/run/audit-submit/audit-submit.sock`, in its own `2710
  azaudit:azaudit-submit` leaf; that listener registers `audit.append`
  alone and the handler above still limits azexplain to the incident types.
  The socket inherits `azaudit-submit` from the setgid leaf, auditd verifies
  that GID before READY, and the client verifies owner, GID and `0660` before
  connecting, exactly as for the operator socket. Three units carry
  `azaudit-submit` (as `SupplementaryGroups`, never by enrolment): the
  explainer, `azazel-knowledge-lited` and `azazel-commissiond`. No operator
  reaches this listener, and operators' reach to `run/audit` is unchanged.
  The two Knowledge Lite writers are bound like azexplain, in both
  directions: azknowledge may `audit.append` only the
  `knowledge.lite.import_*` types and azcommission only the
  `knowledge.lite.revocation_*` and `knowledge.lite.trust_*` types (the
  latter from root's trust transactions narrowed to azcommission,
  [ADR-0008](adr/0008-lite-trust-operations.md)); every other uid, including
  root, is refused for those types, and either account is refused for every
  other type (`principal_denied`, fixed detail `bound_writer`)
  ([knowledge-lite-consumer §11 step 6](knowledge-lite-consumer.md#step-6-first-import-knowledgeimport),
  [revocation](revocation.md#accepting-a-list-on-a-node)). A runtime upgraded without re-running
  install.sh refuses to start auditd and entryd, naming the missing group or
  leaf; see [the upgrade steps](operations.md#observe-only-edge-core-unit).
  An incident record's `occurred_at` names its daily segment and segments
  only move forward, so auditd refuses an `edge.incident.*` record more than
  ten minutes before or five seconds after its own clock, or dated after its
  own current UTC day (`argument_range`, detail `occurred_at`). Incident times
  come from the same host and only age in transit; without the day check a
  record dated 00:00Z tomorrow sent after 23:50 would open tomorrow's segment
  and refuse every writer's records for today until midnight. A record from
  before midnight that arrives after another writer has opened today's
  segment (a close at 23:59:58 delivered at 00:00:05) is refused the same way
  rather than failing the append: it cannot be placed, so it is final and
  counted in `audit_forward_refused`, not retried. Other event
  types keep their existing admission.
- **Best-effort forwarding.** Openings, updates whose minimum severity falls,
  and closes become `edge.incident.opened|escalated|closed` via authenticated
  `audit.append`, reusing the bounded AF_UNIX client and validated receipt.
  Fields are pseudonymous incident id, severity 0–10, Edge action enum, count
  0–2^64−1, technique count 0–8, UTC occurred time, and for closes only reason
  `idle|capacity|shutdown`. Comparison state is bounded to 1024 ids and is
  independent of explanation attempt/rate limits. Occurrence time is the
  intake's `last_update` for every transition; on a close it is the time
  intake closed the incident, so an opening and its close replayed after a
  stop carry intake times and fall inside or outside the window together.
  A separate worker drains a 256-entry memory queue; full queues drop newest.
  Each exchange has a 2 s total deadline. A refusal from auditd
  (`principal_denied`, `argument_*`, schema refusals, `rate_limited` and the
  like; see "Audit chain limits" below) is final
  for that record: it is dropped at once and counted in
  `audit_forward_refused`. Only delivery failures (connection, timeout,
  malformed reply, auditd's read deadline) retry, after 0.5, 1 and 2 s; the
  fourth failure drops the head, so one record holds the queue for about
  12 s at most. Retry drops, full-queue drops and work still queued at clean
  shutdown increment `audit_forward_dropped`. A record replayed more than ten
  minutes late (for example after a long stop) is refused by auditd's window.
- **Delivery semantics.** Forwarding is best effort and at most a projection.
  An acknowledgement lost after auditd appended means the retry appends the
  record again, so the chain can hold duplicates. A crash or kill loses
  whatever is still queued, and those losses are not counted anywhere. Absence
  from the audit chain therefore proves nothing; the incident ledger remains
  the complete record of transitions. Neither failure blocks
  ledger consumption or explanations. Auditd's existing cross-segment verifier
  and CLI health ledger verification accept these typed records. No ledger
  events are manufactured for history skipped during initial seeding.

#### Audit chain limits (#211 S3)

auditd never deletes a segment. That is the retention policy (owner
decision, 2026-10-21; see "Retention" at the end of this section): the chain
is kept whole, and low capacity is a warning only. What auditd does bound is how fast one
writer can make it grow. Each `audit.append` from a non-root principal spends a
token from a bucket keyed on the kernel-derived (`SO_PEERCRED`) uid, the event
type and, for incident records, a tier: **severe** when `most_severe` is 2 or
below (Edge's isolate/redirect range, as in intake), otherwise **ordinary**.
Incident records also count against a per-uid daily cap. The day is the
segment the record lands in (the UTC day of its `occurred_at`), so a close
from 23:59:58 delivered at 00:00:03 counts against yesterday's segment.
Over either limit the request is refused with `rate_limited` (detail `rate` or
`daily`) and nothing is appended. For the explainer that is a final refusal:
it is dropped at once and counted in `audit_forward_refused`, not retried, and
nothing latches.

| Limit | Default | What it covers upstream |
| --- | --- | --- |
| Incident bucket, per (uid, `edge.incident.*` type, tier) | burst 2048, refill 10/s (600/min) | Openings: 60/min ordinary, 30/min severe. Escalations: at most seven ordinary falls per incident, so at most 420/min. Closes follow openings, plus a whole 1024-incident table closing at once |
| Other non-root writers, per (uid, event type) | burst 256, refill 0.1/s (6/min) | Unit grants and commissioning reads are rare transitions; 256 covers every interface ordinal at once |
| Incident daily cap, per uid | 524,288 records a daily segment | A whole day with every upstream budget saturated is about 330,000; the normal ~10–16 MiB/day is about 30,000–45,000 |
| Severe reserve inside the daily cap | the last 65,536 | Ordinary records stop at 458,752; severe openings, escalations and closes can use the rest |
| `audit.rate_limited` summaries | one per (uid, type, tier, limit) per 300 s; at most 1024 a day | — |
| root (`audit.bootstrap.append`, root `audit.append`) | not limited | A handful of bootstrap records per start; root does not need this socket to fill a disk |

- **No starvation.** Severe and ordinary records have separate buckets, and
  openings, escalations and closes each have their own, so a flood of ordinary
  openings exhausts only the ordinary-opening bucket: severe records, and the
  closes of incidents already opened, are still written. At the daily cap the
  ordinary records stop first, **closes of ordinary incidents included**, and
  severe ones continue into the reserve; the incident ledger still holds those
  closes. The
  tier is the writer's own claim: a compromised explainer can call every
  record severe, and then only the total cap bounds it. That is the cap's job.
- **Non-binding in normal operation.** Each bucket refills well above the
  upstream budget it receives, so the rolling intake budgets never meet it;
  `tests/unit/test_runtime_auditd_limits.py` drives every budget at once
  (through the real ledger, and for a whole simulated day through the
  admission path) and asserts that nothing is refused. The root E2E run
  (I5) records no `audit.rate_limited` entry. One exception: an explainer
  catching up after a long stop reads the incident ledger at up to 64
  transitions a second, faster than the 10/s refill, so once a bucket's
  2048-record burst is spent some of its replayed ordinary records can be
  refused (`audit_forward_refused`); the incident ledger keeps them.
- **Visibility without amplification.** A refusal is not written to auditd's
  `refusals.jsonl` one line at a time (that would move a flood from the chain
  to that file). Instead auditd counts it, and writes one `audit.rate_limited`
  chain record per (writer uid, event type, tier, limit) per 300 s carrying the
  count. The first refusal of a key is summarized at once and the serve loop
  flushes the rest when the window passes, even if the flood has stopped. At
  most 1024 summaries a day are written (about 0.4 MiB); past that the counts
  remain in `audit.verify` and in `rate_limit_summaries_dropped`. Summaries are
  auditd's own records: `audit.rate_limited` is not a choice of
  `audit.append`, so no caller can forge or bury one, and they never pass
  through the limiter. `audit.verify` (operator) also returns the totals since
  start as `rate_limited` (`<limit>:<event_type>:<tier>` → count).
- **Restarts and clocks.** auditd rebuilds the per-segment counts of incident
  records and summaries during the startup verification pass it already
  makes (one read of the chain, no second scan), so a restart does not reopen
  a day's caps. If that counting itself fails while the chain verifies, auditd
  fails open: the counts start from zero and it logs one line,
  `daily rate-limit counts could not be rebuilt at startup`, with no record
  content; the token buckets still bound the rest of the day. Counts are kept
  per segment day and only days before yesterday (by auditd's clock) are
  dropped, so a clock stepping backwards does not wipe them. The token
  buckets restart full; their burst is the bound for that.
- **Capacity warning, not deletion.** `audit.verify` returns `capacity`:
  `chain_bytes` (the sum of segment sizes, by `stat`), `segments`,
  `filesystem_free_bytes` and `warning`. The serve loop re-reads it hourly and,
  while the chain is at least 1 GiB or the filesystem has less than 1 GiB
  free, writes one line a day to the journal
  (`azazel-auditd: audit chain capacity warning: ...`). Nothing is removed.
- **Capacity in `azazel-nexus status`.** The CLI neither talks to auditd's
  socket nor reads its `0700` ledger. auditd writes a snapshot instead,
  `/var/lib/azazel/run/audit-status/status.json`, in its own `2750
  azaudit:azazel-operator` leaf (file `0640`, temp file and rename), at start
  and every 60 s (`STATUS_INTERVAL_S`), so the warning turning on or off
  reaches status within a minute. Schema `azazel-nexus/audit-status/v1`, at
  most 8 KiB, closed shape: `written_at`, `chain_verified` (did the chain
  verify at auditd's start), `chain_bytes`, `segments`,
  `filesystem_free_bytes`, `warning` with `warning_reasons` (`chain_size`,
  `filesystem_free`, exactly what the numbers imply), the two thresholds,
  `rate_limited` totals (`<limit>:<event_type>:<tier>`, the 48 largest) and
  `rate_limit_summaries_dropped`. No record content, no uid, no incident id.
  The reader is `azazel_nexus.audit_status.read_audit_status`; anything
  outside the shape is refused. Status prints one health line, `audit:`:
  `ok` when the chain verified at auditd's start; a capacity warning is not
  a failure, so the line stays `ok`, its detail starts with `WARNING:
  capacity warning (...)`, says nothing is deleted, and the warning is also
  listed under `next:`. `FAILED` is reserved for a chain that did not verify
  at auditd's start. `unknown` when the snapshot is absent or refused (auditd not running,
  or install.sh not re-run after an upgrade) or stale (older than 300 s,
  `STATUS_STALE_S`, or dated in the future; the last values, including a
  warning, are shown labelled as such and are not listed under `next:`).
  `--ledger PATH` still verifies a ledger file directly and prints `audit chain:` instead. `chain_verified` is the result of the
  verification auditd makes at its start only: damage to a segment after
  that is not reflected until auditd restarts or an operator runs
  `audit.verify`. A missing or unwritable leaf never stops auditd. The unit
  grants the leaf as `ReadWritePaths=-/var/lib/azazel/run/audit-status` (the
  `-` lets systemd start the unit when the directory does not exist, which a
  plain entry would refuse with 226/NAMESPACE); auditd then logs `cannot
  write .../status.json` once (again only after a later success) and keeps
  serving. auditd also removes `.status-*` temp files a killed predecessor
  left in the leaf.
- **Refusal logs are bounded separately.** Every daemon's `refusals.jsonl`
  (including auditd's, for refusals other than `rate_limited`) is diagnostic
  state, not part of the chain. It is aggregated per (caller uid, reason) and
  rotated at a fixed size; see "Refusal logs" in `docs/operations.md`.

`/var/lib` capacity estimate. The records with limits and retention total
about 0.9 GiB (#211). The audit chain has no retention: in normal operation it
grows about 10–16 MiB a day (roughly 4–6 GiB a year), and with the limits
above a misbehaving explainer can add at most about 250 MiB a day (524,288
records of about 450–500 bytes with full-width counts), plus at most about 3.4 MiB a day for each other
non-root writer and event type and 0.4 MiB of summaries. The M.I.O. route
ledger is now bounded (#211 S4): at most about 238 MiB of daily segments
(46 MiB a day, 192 MiB / 14 days retained plus the current segment), plus, on
a node upgraded from the single `route.jsonl`, the `legacy-route.jsonl`
archive at whatever size that file had reached, kept until the owner removes
it (`docs/mio-runtime.md`). The per-daemon refusal logs are bounded too: at
most 12 MiB each (a 4 MiB `refusals.jsonl` and two rotated files) for
auditd, commissiond, watchdog, Knowledge Lite and the fetch daemon, plus at
most 12 MiB of Knowledge Lite's lookup events (`events.jsonl`), so at most
72 MiB together, whatever a caller sends; M.I.O. entry's refusals are
records in the route ledger above. The audit status snapshot adds at
most 8 KiB. Size `/var/lib` for the normal
yearly growth plus headroom; the capacity warning is the prompt to plan
storage or an export, not a signal that anything will be removed.

| Threshold (auditd constant) | Value | Effect |
| --- | --- | --- |
| `CAPACITY_WARN_CHAIN_BYTES` | 1 GiB of segments | warning `chain_size`; at normal growth, roughly two to three months of chain |
| `CAPACITY_WARN_FREE_BYTES` | under 1 GiB free on the ledger's filesystem | warning `filesystem_free` |
| `CAPACITY_CHECK_S` / `CAPACITY_REWARN_S` | 1 h / 24 h | journal re-read / one journal line a day while warning |
| `STATUS_INTERVAL_S` / `STATUS_STALE_S` | 60 s / 300 s | snapshot rewrite / status calls it stale |

A warning is a prompt, never a deletion: status and the journal say so, and
nothing in auditd removes or truncates a segment.

**Retention (owner decision, 2026-10-21): never delete, warn only.** The
chain is not deleted by age or by size, by auditd or by anything else on the
node. Two reasons. Deleting loses evidence on a schedule nobody reviewed for
the case at hand. And a retention window would let a compromised writer push
the oldest evidence out by flooding the chain up to its limits, including the
records of how it was compromised; without deletion a flood can only fill
the disk, which the warning reports and the daily caps above bound. The
status advisory names this policy ("retention policy: never delete, warn
only").

Old records leave the node only as **copies** an operator makes; the node's
copy is never removed, even after a verified export, because removing a
segment breaks the node:

- `SegmentedLedger.verify` starts every walk at sequence 0 and the all-zero
  genesis hash, so without the oldest segment the first remaining record
  "follows 0" and the chain is broken; without a middle segment the next
  one does not chain on. The unsigned checkpoints anchor nothing, so there
  is no later starting point.
- `AuditService.start` then leaves the service unverified: every append and
  `audit.bootstrap.observe` is refused, systemd readiness is withheld, and
  status shows `audit: FAILED`.
- The bootstrap pre-start reader (`bootstrap_audit.py`) also walks the
  directory from genesis to the head pinned in its signed policy and refuses
  any file that is not a `YYYY-MM-DD.jsonl` segment.

Capacity is therefore answered with more storage, or with an export
followed by a reinstall (a new chain starts from genesis only through the
first-install path, on an empty ledger directory). The operator's warning
guide, the export procedure (stop auditd, verify, copy every segment from
the first to external media, record `SHA256SUMS` and the head, verify the
copy) and the continuity check between exports are in `docs/operations.md`,
"Audit chain retention".

### I4 — redirect to Deception Lite (later)

A redirect is an Edge decision. Deception Lite may materialise a decoy only
when it holds an Edge-signed Fabric `EnvironmentActivationDecision`. Edge
already builds signed transition decisions (`deception_transition.py`) but
nothing calls it in production, and key distribution to Nexus does not exist.
Until then a redirect decision is shown as "Edge would redirect to a decoy"
and no decoy is started.

I4 has three prerequisites, not one. The Nexus half of each is designed in
[Redirect to Deception Lite: the Nexus-side prerequisites](deception-redirect-prerequisites.md)
(accepted 2026-10-21; P1 and P2 implemented; nothing is granted; the grant
phase is decided in [granting the exposure tier](deception-exposure-grant.md)):

1. **Edge enforcement.** A redirect moves traffic, and the shipped Edge Core
   is observe-only: its redirect is planned, never applied. A decoy started for
   a redirect that is not applied receives nothing, so the redirect half of I4
   waits for Azazel-Edge#412 (one declared enforcement path) and a commissioned
   enforcement design in Nexus. Neither is part of this plan.
2. **Signed decisions and their key.** Edge signs transition decisions with a
   shared HMAC transport key (Fabric `decision_signing`). Nexus can verify one
   only with that key, so its provisioning, storage and rotation must be
   designed with commissioning, the same way operator keys are. Edge must also
   call the producer in production.
3. **A decoy that can be reached.** Deception Lite is loopback-only today
   (`decoy_loopback.py`): it has no unit, no `az-decoy0` bridge and no
   exposure path beyond the lifecycle in `decoy.py`.

One part does not need enforcement: what an operator-exposed decoy observes
(Fabric `EnvironmentEvent`) can enter this loop as evidence, the way Edge's
alerts do, once item 3 exists. That observation path is the first piece of I4
that can be built while Edge stays observe-only. Its intake half is built
([P2](deception-redirect-prerequisites.md#11-p2-as-implemented)): the intake
stores a decoy's interaction in its own evidence leaf, labelled as not Edge's,
and never passes it to the incident tracker; nothing in this build sends one.

**Edge Core's own output.** Edge Core prints each decision to stdout, which
the unit sends to the journal. Those lines are Edge's record and carry the
raw addresses, target and planned commands. The privacy checks in this loop
cover what Nexus writes (status, `recent.json`, explanation records, the audit
chain), not Edge's journal; a deployment that exports the journal must treat
it as containing addresses.

### I5 — end to end

The E2E harness stage **integrated defensive loop** (`tools/e2e_loop.py`) runs
the whole chain with real daemons under their real service accounts and unit
supplementary groups: `auditd` (azaudit), `knowledge-lited` (azknowledge, with
the bundle the offline-import stage admitted), `mio-entryd` (azmioentry),
`edge-intaked` (azintake) and `incident-explaind` (azexplain).

```text
python tools/e2e.py --root <short dir> --edge-core <built azazel-edge-core> \
    [--edge-redirect-policy <redirect_policy.yaml>]
```

The root is a scratch directory; remove it with `rm -rf <short dir>` afterwards
(as root, since the stage chowns files to the service accounts).

- **With `--edge-core`** the real Edge Core binary runs as `azedge`. Its
  environment is the `Environment=` set of the `azazel-edge-core` profile with
  exactly four keys changed: the intake socket, eve and release ledger paths
  (relocated into the harness root) and `AZAZEL_EVE_FROM_START=true`. The
  profile's `AZAZEL_REDIRECT_POLICY_PATH` is an installed path outside the
  harness root that normally does not exist there, so Edge takes its
  no-policy default; `--edge-redirect-policy` (test tooling, optional) copies
  a policy into the root and points that key at the copy. The unit's sandbox
  (`PrivateNetwork=` and the rest) is not reproduced and systemd does not
  start it; instead it runs under `strace -f`. Calls strace splits across
  threads (`<unfinished ...>` / `<... resumed>`) are joined per pid first.
  The only connections are `AF_UNIX` to the intake socket and they succeed (a
  failed connect is reported as such), writes on that connection carry no
  destination, and nothing binds, listens or opens another family. The eve
  file holds two alerts on one incident (the second more severe) and one
  non-alert event Edge must drop; Edge's stdout holds exactly two `dry_run`
  decisions, `notify` then `isolate`, at Suricata severity 4 then 1.
- **Without it** the stage replays the golden fixture lines as the `azedge`
  peer would, and says so in its result; Edge's own filtering is then not
  exercised.
- Both assert: intake accepted exactly the alerts with no refusal; evidence
  digests match the validated events; the incident ledger verifies and holds
  `opened` then `updated` (escalation) with Edge's decisions unchanged and the
  rule's technique ids; the explainer stored two explanations on the
  deterministic handoff with Knowledge `available` and a citation for one of
  the event's techniques; `recent.json` lists the incident with citations,
  including T1110; `auditd`'s chain verifies and holds `edge.incident.opened`
  and `edge.incident.escalated`; `azazel-nexus status` shows the incident with
  "Edge would … (observe-only, not executed)" and the citation; neither eve
  address appears in the four places checked: `azazel-nexus status` output,
  `recent.json`, the explanation records and the audit chain (evidence and
  the incident ledger are private and not checked); no unexpected socket was
  newly created under the root (sockets present before the stage are the
  baseline); on shutdown the incident is closed (`shutdown`) in both ledgers.
- Both also assert Edge's forward counts (Azazel-Edge#432): intake status
  carries `edge_forward` with `dropped` 0, `failed` 0, `sent` equal to the
  alerts and no restart; `accepted`, `processed` and the evidence lines stay
  at the alert count, nothing is refused, and `azazel-nexus status` prints
  `Edge forward: dropped 0, failed 0 (as reported by Edge); sent 2`. Replay
  sends that line after the alerts as the `azedge` peer. The real binary
  sends it itself, and its connections to the intake are counted as one per
  alert plus one per forward-count write seen in the trace. A binary built
  before Azazel-Edge#432 sends none: the stage then checks that status says
  the counts were not reported and says so in its result, rather than failing.
- Live files are read while daemons append. Only newline-terminated lines
  count (Edge stdout, evidence, explanations, and ledgers, whose complete
  lines are verified in a copy), and status snapshots are replaced
  atomically, so polling retries only an unmet assertion or a file not yet
  created; a decode or chain error fails at once. Startup and observation
  share one 20-second budget; the shutdown close has its own 10 seconds.
- Shutdown. `edge-intaked` and `incident-explaind` handle `SIGTERM`
  themselves. The product mains of `auditd`, `knowledge-lited` and
  `mio-entryd` install no `SIGTERM` handler; their `main()` accepts a stop
  predicate, so the harness starts them through `python -c` with a handler
  that sets it. The clean shutdown asserted here (exit status 0, sockets
  removed) is therefore the product's serve-loop cleanup reached through
  that harness-supplied path, not a claim about how those three units react
  to `SIGTERM` under systemd. Daemons run with only `AZAZEL_ROOT`,
  `PYTHONPATH`, `PATH` and `LANG` from the caller (no `NOTIFY_SOCKET`), and
  their output goes to a temporary file reported if they fail to start.
- It needs Linux and root (real accounts and `SO_PEERCRED`); otherwise it is
  *not executed*, like the other account stages.

What it does not establish: the x86_64 package path (the container binary is
built for the host architecture, not packaged by Edge's packager, and not
started by systemd); activation admitting the unit (#198); hardware behaviour.
The same run on the rehearsal VM, through the installed units and the Edge
packager's package, followed the
[integrated loop rehearsal](hil-runbooks/integration-loop-rehearsal.md) once
on an aarch64 VM (#195), with activation admission not exercised (#206).
Neither is hardware evidence: HG-07 still needs the real host.

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
| One declared enforcement path, before any redirect is applied (I4) | Azazel-Edge#412 |


`health_endpoint_healthy` means the fixed `--health` of the verified binary
answered healthy under the pinned contract with the pinned version. The
observe-only posture is established by the manifest posture checked under
`package_present`; the running unit's posture is established by the fixed unit
environment (I0). Health does not observe the running process.

After admission, a unit that never becomes running (for example, a crash loop)
keeps `edge-baseline-ready` at no. The one-shot probe can still pass its health
check during a crash loop. Detecting that degradation and narrowing the unit
is degradation/watchdog work for a separate issue.
