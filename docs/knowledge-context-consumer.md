# Nexus Knowledge Context consumer candidate (#395)

The semantic request/response belongs to Fabric's `knowledge-context/v1`
profile. Nexus imports it only through `fabric_boundary`, where the import is
deferred so CORE remains usable without the optional Fabric package. The
optional `fabric` extra pins the published Fabric `v0.10.0` tag, which
contains this profile as experimental functionality without a compatibility
promise (#402 and #403 are merged). Even with the profile installed, the
adapter remains unavailable unless its explicit transport configuration is
supplied; Knowledge Lite behavior is independent.

The Nexus envelope is separate from the Fabric payload. It binds `key_id`,
`issued_at`, `expires_at`, and the canonical response bytes under the
`azazel-nexus/knowledge-context-envelope/v1` Ed25519 domain. Verification
resolves the provider key through Nexus's commissioning-bound signed Knowledge
registry and requires `key_id` to equal that key's SHA-256 fingerprint. A
maximum TTL has no default and must be explicitly supplied. Fabric validates
the semantic request and response, including exact request/correlation/source
binding and the advisory-only fact/inference model. Nexus also requires the
signed `provider_id` claim to equal the commissioned peer ID. This binds the
claim to the signer selected by Nexus; it does not prove that any Knowledge
fact is true.

The adapter accepts P0-public queries only, even if local policy allows a
wider class. `KnowledgeClient.request_context()` opens an mTLS connection only
when explicitly called on a client with the local opt-in flag, commissioned
peer, client identity, CA and pin configured. The opt-in boolean is caller
configuration; it is not a Context capability in the signed peer registry.
The default-disabled broker composes that method behind the ordinary local path.
It is enabled only by the root-owned commissioning bundle described below;
live credentials are not supplied and no production policy names the unit. Importing this module or installing the package
does not connect, load commissioned state, install a trust anchor, or alter
service startup. The response is a bounded advisory object; it cannot grant
authority or alter Edge's deterministic decision path.

Status: **isolated software path in development**. The service boundary, local
request path and commissioning-bundle loader described below are implemented.
No credentials, endpoint or systemd egress allowance is supplied, so
activation remains withheld. No environment variable or command-line option
can enable egress; only a complete, root-owned commissioning bundle can.

## Commissioning bundle

`az-knowledge-contextd` reads `/etc/azazel/knowledge-context/commissioning/`
once at start. Absence means closed. `AZAZEL_ROOT` is for tests only: when
it is set, that directory is trusted as the starting point and neither it nor
its ancestors are inspected; it can only relocate where a bundle is read from,
and a complete, root-owned bundle is still required, so it does not enable
egress. Secret files (`client.key`, `alias.key`) are owned by root. Other-readable
secrets are refused (`perm_unsafe`). Group-readable secrets are accepted only
when `st_gid` is the daemon's effective gid or gid 0; any other group is
refused (`perm_unsafe`). A secret the daemon cannot open is `path_unsafe`; in
particular a `root:root` 0600 file cannot be read by a non-root daemon and is
reported as `path_unsafe`. The service-group form is `root:<service group>` 0640.
The directory is flat and holds exactly: `manifest.json` (schema, `enabled`
must be JSON `true`, peer_id, client_identity, commissioning_digest,
max_ttl_seconds, mission, sanitizer_policy; no defaults), `registry-keys.json`,
`registry.signed`, `ca.pem`, `client.pem`, `client.key`, `alias.key` (at least
32 bytes). Every ancestor and file must be root-owned and not group/other
writable, files are opened without following symlinks, must have one link and
a bounded size, and `client.key`/`alias.key` must have no other-user access.
A signed registry alone never enables egress. The loader performs no network
I/O. Removing or replacing `manifest.json` while running closes the client until
restart.

Test-only examples of the file shapes, and a read-only pre-check
(`tools/check_knowledge_context_bundle.py`, no network, no activation), are in
[docs/examples/knowledge-context-test-only](examples/knowledge-context-test-only/README.md).

Boundaries that this bundle does and does not settle:

- Policy wording. Egress cannot be enabled by an environment variable or a
  command-line option (the daemon takes no arguments); only a complete,
  root-owned bundle can enable it.
- Location and modes. The bundle is `/etc/azazel/knowledge-context/commissioning/`.
  The optional observation rule file is its parent's
  `observation-query.json`, not part of the bundle (see *Observation-origin
  query*). The loader requires the bundle directory to be root-owned and not
  group- or other-writable; within that, its mode (for example 0750) is the
  operator's choice. The secret files keep the modes given above.
- A defective bundle. The daemon still starts, the broker stays closed, and the
  daemon records one `knowledge.context.commissioning` event: outcome
  `refused` with a fixed `reason_code`, or `absent` when there is no bundle.
  Nothing falls back to another source.
- Verification is not activation. A bundle that loads as commissioned makes the
  broker able to send; it does not grant the unit, and the bundle is not an
  input to the grant. `azazel-knowledge-contextd.service` is grantable through
  the existing activation path (a policy may name it, A1); the grant only
  lets it start, and `wired_capabilities()` does not list Knowledge Context.

## Observation-origin query (technique-set/1)

Nexus can ask the Knowledge peer one extra question from an observed incident:
which ATT&CK techniques the incident carries. This is a separate contract
(`technique-set/1`), off by default, and it adds no authority: the reply is an
unverified advisory and never changes a decision field. Everything in this
section applies only while a rule file (below) is in place. With no rule file
the explainer asks nothing, no new record field is written, and rows,
checkpoints and records are byte-for-byte what they were before.

### Question shape and the rule file

Since 2026-11-17 ([ADR-0010](adr/0010-context-observation-unit.md)) the broker
accepts one frame only, the technique query `{"privacy_class": "P0-public",
"techniques": [ids]}` (one to eight ids, `T1234` or `T1234.567`; see "ATT&CK
technique query" below), and every such frame is observation-origin. It is
built by `azazel-mio-contextobsd`, not by the explainer, from a sorted,
validated set of ids. A free-form `question` is refused before sending
(`reason_code: refused_before_send` in the ledger, and the same word as the
refusal's `stage` to the caller), including one in the earlier observation
sentence `ATT&CK technique context: T…`; it is not counted against the rule's
limit and cannot latch the broker.

The rule file is `/etc/azazel/knowledge-context/observation-query.json`. It sits
in the parent of the commissioning directory, outside the bundle, so the bundle's
modes are unchanged and `azexplain` and `azui` still cannot read the bundle. The
product does not ship it, and `install.sh` does not create the parent
directory (it creates `/etc/azazel` only); the operator creates the directory
root-owned and not group- or other-writable (0755) and places the file, intended
mode 0644. The loader requires the file and every ancestor to be root-owned and
not group- or other-writable; the file must be a regular file with one link and
at most 4 KiB, and symlinks are not followed. It holds exactly `schema`
(`azazel.knowledge-context.observation-query/1`), `rule` (`technique-set/1`) and
`max_requests_per_minute` (an integer from 1 to 60, no default). Any absence
or defect is simply "no rule"; the loader never says why. No environment
variable or command-line option can supply a rule.

### Who reads it, and when

| Component | Role | When the file is read |
| --- | --- | --- |
| `azazel-incident-explaind` | candidate decision, retention table, the request, the replacement rule, the origin record | before every explanation, so adding, removing or replacing the file takes effect from the next one |
| `azazel-mio-entryd`, `azazel-mio-contextobsd` | entryd relays the request; contextobsd builds the technique query | not read. The rule is enforced by the broker |
| `azazel-knowledge-contextd` (broker) | treats every technique query as observation-origin, counts it, refuses it without a rule; refuses a free-form question before the gate | once at start. After that, on each observation-origin request, it checks that the file's identity (device, inode, mtime, ctime) is unchanged; a missing or changed file latches the broker closed to such requests until restart |
| `azazel-ui` | `capabilities.full_context_from_observation`: true when it reads a valid rule at that moment, false when absent or defective, null for a fixture source | at every view build, so the `/api/view` cache (2 seconds) can delay it. It states only that the file was valid when the UI read it; it says nothing about the broker's latch, grants, the bundle or the peer |

When the broker read a rule, `knowledge.context.commissioning` carries
`observation_rule: loaded`. With no rule the key is absent, so the event is
identical to the earlier one.

### Stopping and resuming

To stop, remove the rule file. The explainer stops asking from its next
explanation. The broker closes at its next observation-origin check; it does
not cancel a request that already passed the check and it has no watcher. To
resume, or to change `max_requests_per_minute`, put the file back and restart
`azazel-knowledge-contextd`; adding or replacing the file does not reopen a
latched broker. Stopping the unit or removing its activation grant stops
everything, as before.

### When the three readers disagree

- Explainer valid, broker not (file added without restarting contextd, broker
  latched, or the bundle was refused): the request reaches the broker and is
  refused as `refused_before_send`; the row shows `unavailable`.
- Broker valid, explainer not (for example `azexplain` cannot read the file):
  nothing is asked and the row stays `not_queried`. The UI reads the file by the
  same rule and normally shows `false`.
- UI only differs: during the 2 second cache, or when only `azui` lacks
  permission. The capability value is a display control, so behaviour does not
  change but the display can lag.

### The limit and its reach

The broker counts the technique queries that passed the rule and limit check in
the last 60 seconds, including ones that later fail (for example `busy`). At
`max_requests_per_minute` the request is refused as `rate_limited`. Both
refusals are decided before the `knowledge.context.requested` event, before the
in-flight slot and before any peer call. The window is in memory, so a broker
restart empties it. Since ADR-0010 every request the broker accepts is a
technique query, so every accepted request is counted; a free-form question is
refused before the gate (`refused_before_send`) and is neither counted nor able
to latch the broker.

The first stage is the explainer's existing six explanations per minute
(`MAX_PER_MINUTE`), which the observation-origin candidates cannot exceed. The
broker's limit is the second layer: it also bounds a restarted explainer and the
one account that may ask (`azmioctx`).

Residual effect: occupancy. The broker has one in-flight slot with no queue. A
technique query holds it for as long as the peer takes (at most the caller's
deadline, 350 ms), so a second query arriving then gets `busy`, is counted, and
its pair is not asked again (below). Since a `busy` refusal still counts toward
the limit, repeated occupancy can use up the minute's allowance without a
single send.

*Before ADR-0010 (2026-11-17), for the record.* The broker also served
caller-classified free-form P0 questions from locald's ordinary FAST_ASSESS.
Those were not counted unless their text matched the observation sentence, they
competed with observation-origin requests for the one slot, and a question that
happened to match the sentence exactly was refused without a rule and counted
with one. None of this applies now: that path and that sentence are gone.

### Audit `reason_code`

`knowledge.context.completed` may carry an optional `reason_code`. `outcome` is
unchanged. Success and unclassified failures carry none.

| reason_code | outcome | Meaning |
| --- | --- | --- |
| `refused_before_send` | `unavailable` | Rejected before any send: frame, P0 label, not ready, no/changed rule file, `requested` audit write failed, client pre-send checks, changed manifest |
| `rate_limited` | `unavailable` | Observation-origin limit reached; not sent |
| `busy` | `timeout` | The single in-flight slot was occupied; not sent |
| `transport` | `unavailable` | Failed while connecting, in TLS pinning, or in HTTP exchange; delivery is not guaranteed either way |
| `verification` | `unavailable` | A response arrived but failed signature, binding, lifetime or schema checks, or the broker rejected it (not an object, over 48 KiB) |
| `late` | `timeout` | A verified response arrived after the deadline |
| `withdrawn` | `unavailable` | The grant marker was missing at admission, or missing or replaced before the answer was adopted; nothing from the peer was adopted |
| `restart_unconfirmed` | `unknown` | Written by a restarted broker for a `requested` line no result refers to. It does not say whether the request was sent, not sent, or answered |

A missing `reason_code` on a record written before this field existed reads as
"not recorded"; on a record written after, it reads as "unclassified". Neither
is inferred. Events never contain exception text, the question or any response
fragment.

### Requests that left no result after a restart (#472)

A broker that stops between `knowledge.context.requested` and its result cannot
tell, on the next start, whether the peer was called: the ledger is the same
whether it stopped just before the call or just after it. It does not resend and
does not write a result that claims either. It writes one line, once:
`knowledge.context.completed` with `outcome: "unknown"` and
`reason_code: "restart_unconfirmed"`. No reader may show that line as "sent",
"not sent" or "answered".

* A `requested` line of the current form carries `"format": 2`. Every result
  that follows it (`completed`, the `late_event` inside `audit.late_record` and
  `audit.outcome_settled`, and the recovery line) carries `requested_sequence`
  and `requested_hash`, the sequence and hash of that line. Nothing is matched
  by position. A refusal before any `requested` line carries no reference. When
  the `requested` write itself had an unknown outcome the refusal waits until
  the line is settled: it refers to the line when it is `present` and carries no
  reference when it is `absent`.
* At start, after taking the writer lock, the broker verifies the whole ledger,
  reads every reference, and writes one recovery line for each `requested` line
  of the current form that no reference names. It does not use the in-memory
  record of the previous process or of `settle`. A stop right after a recovery
  line adds nothing more at the next start.
* A `requested` line without `format` is never matched or filled in. Their number
  is `legacy_unreferenced` in the status (all of them, including those that did
  finish; it is not a count of lost requests).
* The writer lock is `context.jsonl.lock` in the state directory, taken before
  `commissioning` is appended and before the socket is bound. A second broker
  exits with a message and touches neither the ledger nor the socket.
* Egress opens only when the ledger verified, `commissioning` is recorded and
  no recovery is pending. Until then (also after a failed start-up append) the
  broker serves with egress closed: the observation latch and
  `knowledge.context.status` work, a technique query is refused as
  `refused_before_send` after the observation gate and before any peer call,
  and the broker tries again every two seconds. A chain that does not verify is
  never completed; the status says `ledger_broken` until a restart.
* The same closing applies while serving: a chain found broken, or a debt of
  unknown outcome that cannot be settled, refuses the technique query after the
  observation gate and before any record or peer call. The latch and the status
  still work then (the latch's own record is best effort and is not written when
  the ledger cannot take it).
* Until the ledger is verified and `commissioning` is recorded, no other line is
  appended. The latch is still set, but its record and the transport's refusal
  records are dropped (counted as unrecorded), not held back and not written
  later.
* A refusal that waited for its `requested` line to be settled and whose own
  write then has an unknown outcome is not written again until that line is
  settled: `present` removes it, `absent` writes it again.

`knowledge.context.status` (operator group, the SERVICE account and root; no
arguments) answers `egress` (`open` or `closed`), `reason` (`ledger_broken`,
`audit_unavailable` or none), `audit` (`ok`, `owed`, `broken`), `unresolved`,
`legacy_unreferenced`, `recovered` (lines written by this process) and
`observation` (`open` or `latched`).

### The explainer's request: `mio.context.observe` and `mio.contextobs.observe`

The explainer asks at most one observation-origin question per candidate
explanation, after `mio.advise` and Knowledge Lite and before the record is
composed. It uses `mio.context.observe` on `azazel-mio-entryd` (deadline 350 ms,
plus a 250 ms caller margin), which relays to `mio.contextobs.observe` on
`azazel-mio-contextobsd`, the model-free unit whose account `azmioctx` is the
broker's only SERVICE principal (ADR-0010). Until 2026-11-17 the relay went to
`mio.local.observe` on `azazel-mio-locald`; that verb no longer exists.

- `mio.context.observe` is allowed to the explainer only; any other principal
  is `PRINCIPAL_DENIED`. It requires a P3 frame with the structured projection
  and at least one technique. It draws on the same per-caller rate allowance as
  `mio.advise`, writes nothing to the entryd ledger, and does not change
  `mio.advise`'s 500 ms budget, FAST_ASSESS or the ordinary P0 path.
  `mio.contextobs.observe` is a SERVICE verb admitting `azmioentry` alone. Its
  socket `/var/lib/azazel/run/mio-contextobs/` is `azmioctx:azmio-contextobs
  2710`, and only the entry unit carries `azmio-contextobs`. entryd checks the
  socket's owner (`azmioctx`) and group before connecting and the kernel peer
  uid after; the service classifies the kernel peer credentials, so another
  member of the group or root is `principal_denied`. An account without the
  group, such as the model host `azmio`, does not reach the socket at all
  (`EACCES` from the 2710 directory); given the group, it is `principal_denied`.
- The 350 ms deadline is a candidate contract, not a measured one. The reply
  carries a fixed-key `timing` (`context`: received, unavailable or refused,
  `broker_ms`, `total_ms` and `core` from contextobsd, still under the key
  `locald` so that the reply keeps its shape; `entry_ms` from entryd) so that
  success, delay and refusal can be measured. `core` is `ran`, or `failed` when
  the core raised and `fast_assistance` is the fixed degraded payload; the
  broker's outcome is told apart from it, because the `technique_knowledge`
  record rides on the result either way. Nothing is logged or recorded from the
  timing yet, and no measurement has been taken.
- The explainer does not adopt the reply as it arrives: it re-validates the
  returned `fast_assistance` with `read_fast_assistance` before the replacement
  rule runs, and a reply that fails is treated as `unavailable`.
- A broker refusal, an unreachable broker, a timeout or an exhausted budget all
  return `unavailable` in the same shape. contextobsd submits no generation and
  writes nothing to its ledger (which holds only the socket layer's refusals).
- The service stamps `full_node_context_received_at` (UTC, a wall-clock time and not a
  trusted clock) into the fast assistance only when the broker returned a
  response. The reader accepts it as an optional key; a reader from before this
  change reads the unknown key as `invalid_fast_assistance` (see the deployment
  order below).

### Candidates, retention table and replacement

Candidate: the explained transition is `opened` or `updated`, has at least one
technique id, the frame carries the structured projection, `mio.advise`
returned a fast assistance, and the pair (incident, sorted technique set) is not
in the retention table. If `mio.advise` returned none, the explanation is not a
candidate. The table is memory only: per incident, cleared when that incident's
`closed` is observed or on an Edge reset, at most 4096 pairs (the oldest
incident's oldest pair goes first). The pair is entered when the question is
decided, before its result is known; a failure, `rate_limited`, `busy` or a
rejected reply does not make the pair a candidate again, and nothing is retried.
After an explainer restart, or after eviction, the same pair may be asked again,
bounded by the explainer's six per minute and the broker's limit.

The reply replaces the advise fast assistance only when everything outside the
Full-derived fields is equal: `fabric_knowledge_context_advisory`,
`full_node_context_status`, `full_node_context_received_at`, `handoff`,
`reasoning_trace`, `dependency_outcome.knowledge`, the `KNOWLEDGE_CONTEXT_`
items of `unknowns` and two fixed `next_checks` texts may differ: the
incomplete-check text, and the advise side's fixed "This fast result did not
query Knowledge; ..." sentence (Nexus constant `MIO_KNOWLEDGE_NOT_QUERIED_CHECK`,
copied from the pinned azazel_mio 4511f1fc). Both are removed before comparing
and the remaining `next_checks` must be equal in order. If azazel_mio changes
that sentence, the replacement stops holding and the row shows `unavailable`,
which is the safe side. When the azazel_mio pin is updated, compare
`MIO_KNOWLEDGE_NOT_QUERIED_CHECK` with the sentence the new wheel emits for a
fast result that did not query Knowledge (the `tests/unit` comparison tests pin
the Nexus side only); a mismatch is a release note item, not a silent change. `state`, `hypotheses`, `knowledge` and the rest must be
equal. `trace`,
`trace_id` and `frame_id` stay the advise side's. Otherwise the advise result is
recorded with status `unavailable`. A reply that the broker verified but the
explainer dropped this way therefore appears as `verified_advisory` in the
broker's audit while the row says `unavailable`; this mismatch is expected.
Whether a real Fabric reply leaves `state` and `hypotheses` unchanged is not
established by unit tests (the pinned shared core is not installed in the test
environment); acceptance S2 must show it, else the replacement always fails.

The record gets `full_node_context_origin` (`observation_rule_v1`,
`observation_rule_v1_repeat`, `none`) only while a rule is usable. The optional
`full_node_context_received_at` comes from contextobsd and is present only when the
broker answered. The projection
`explanation.fast_assistance.full_node_context` gains the optional `query_origin`
(same three words), which explaind copies from the record. Old rows have neither
and read unchanged.

### ATT&CK technique query (observation origin)

The observation-triggered query no longer sends a `question`. The broker frame
is `{"privacy_class": "P0-public", "techniques": [ids]}` (1 to 8 ids, sorted,
unique, `T[0-9]{4}(\.[0-9]{3})?`), and `make_request` turns it into one typed
entity `attack-technique/v1` per id. This is a separate, closed entry of
`make_request`: it accepts exactly the key `techniques`, never widens another
entry, and is admitted only when the commissioned sanitizer policy admits the
fixed observation question for the same ids. The broker applies the observation
rule gate to every technique frame. Since ADR-0010 there is no other request path.

The signed answer does not go to M.I.O. The path is: signature and Fabric
correlation (existing), then `technique_knowledge.validate_technique_response`
in the client (a failure is stage `technique_verification`), then the same
validator and `project_technique_response` in contextobsd, then storage, UI and
handoff. contextobsd runs the core as for an unavailable Full lookup
(`full_node_context_status: unavailable`, no response argument) and puts the
closed record beside the result as `technique_knowledge`; the reader requires
that no Fabric advisory comes with it.

The validator refuses the whole response on any violation: only the four
predicates `coverage`, `technique_name`, `tactics`, `attack_version`; exactly one
leading `coverage` per requested technique, in request order; `found` carries
three more facts, every other word none; `stale` and `unavailable` are uniform;
fixed fact ids `tq-<i>-<n>`; provenance `knowledge:attack-coverage` for coverage
and `knowledge:attack-stix` for content; no inferences; the fixed
`NO_MATCH_UNKNOWN` exactly when a technique is `no_match`; the two fixed
`LIMITATIONS`; `snapshot.state` consistent with the coverages; `snapshot.ref`
`attack-stix@<version>` equal to the one `attack_version` of the found items
(`attack-stix@none` when nothing is found); tactics from the ATT&CK tactic list,
ascending. The name is checked by one structural grammar, `technique_knowledge.name_grammar_ok`, which
the Knowledge side must mirror exactly: 1 to 120 characters; letters and digits of any script, `_`, space and
`: , ( ) ' & + - / .`; no control character, no leading, trailing or doubled space; no `< > { } \\` or
backtick (nor `;` or `#`, so no HTML entity); no `://` or `www.`; no IPv4 or IPv6 literal; no token that looks
like a domain. A violation fails the whole response; the validator never judges words. The projector alone
applies a word screen as a heuristic deterrent: a name that reads as an instruction or a causal claim is
withheld (`name: null`, `name_withheld: true`, coverage stays `found`), never truncated. The screen can miss
phrasings and is not a security boundary; the boundary is that the label is display-only. The grammar and the
tactic list are tested against every in-scope technique of the official Enterprise ATT&CK 20.1 corpus (706
names, `tests/fixtures/attack-enterprise-20.1-extract.json`, source commit and sha256 recorded in the file).
In the handoff package only, a name that the package's leak scanners (`unix_path`, `base64_value`, ...)
would flag, for example one containing `/`, is also withheld (`name: null`, `name_withheld: true`), because
the scanners fail the whole package closed; the scanners are not relaxed. `/api/view` and the screen are not
scanned that way and still show such a name, so the same row may show a name on screen and
`name_withheld: true` in the handoff; `name_withheld` there means either reason, never that coverage changed. The handoff Markdown says so in words (the name was withheld by the
handoff secrecy check or by the name word screen; the ATT&CK mapping exists; it is not "no knowledge") and
also prints the technique's provenance. The screen renders only `/api/view`, where a name can be withheld
by the word screen alone, so the screen names only that reason.
The stored record also carries `as_of`, `expires_at`, `provenance` (the two fixed values), `authority`
(`advisory_only`) and `trust` (`unverified`); the reader re-validates them and the UI shows them as text.
The Knowledge side must emit exactly these constants.

Axes of the record (`technique-knowledge/1`): `transport` (`received`,
`unavailable`, `refused`), `verification` (`ok`, `failed`, `not_run`,
`withdrawn`, `unrecorded`; HTTP 422 counts as `failed`), per technique
`coverage` (`found`, `no_match`, `stale`, `unavailable`) and `useful_content`
(true exactly for `found`). The pairs in use are received/ok, received/failed
(validator refusal), received/withdrawn (verified, not adopted: the grant marker changed, or the
check at adoption failed, for example on expiry or clock health -- this value
alone does not tell whether the grant was withdrawn), received/unrecorded (verified, not adopted because the broker
could not record its completion: its audit chain broke, #458, or the record
could not be written, #467 -- the send happened once and the daemon does not
repeat it; the same frame asked again after the record is settled is a new
request, judged by the usual admission and, when admitted, sent and recorded
once),
refused/failed
(signature, Fabric, 422), refused/not_run (refused before send),
unavailable/not_run. `unavailable/not_run` also covers a query whose send had
started when it failed, so it does not say the query was not sent; the issuer
does not re-send such a query automatically (operations, *When the result is
unknown*, #470). A record that is not received/ok carries no techniques. `name` and `tactics` are
display labels: they are not copied into observations, hypotheses, next checks,
actions, the reasoning trace or unknowns. The UI shows them with `textContent`
under 「未検証の ATT&CK ラベル（参考）」; the handoff copies fixed keys only.
The row trace (`last_attempt`) still reflects the Fabric Full path only, so it
reads `unavailable` for a technique query. That value means "no Fabric advisory was
adopted"; it is not the outcome of the ATT&CK query. The UI and the handoff
Markdown label the Fabric axis as such and show the ATT&CK query's own transport,
verification and expiry in the technique block. A stored row written before this
labelling reads the same way (no field changed).

### Past reference of a technique answer (DESIGN-D53)

The current technique answer lives in the row's current Full-node projection only
while it answers the row's latest observation. When that projection is replaced
(an update, a close, an Edge reset, or a late explanation of an earlier
transition) the answer is copied once to the row key `technique_past_reference`
and shown as a **past reference**: retained and viewable, never adoptable for a
current decision, never an answer to a new query. At most one per incident; a
newer observation (larger `observed_sequence`) replaces an older one, the same or
an older one never does, and a failed or unavailable record is never kept. The
copy is made before the current projection is removed (also on reset), and a late
explanation is captured from its own arguments only. The ledger is not read and
nothing signed or stored changes; the key is a derived copy in `recent.json`, the
checkpoint, the ui status view and the ui handoff. Operator and root views carry
none.

Stored shape (`technique-past-reference/1`; `RECENT_SCHEMA`, `technique-knowledge/1`
and the handoff schema are unchanged): either `retained` with `binding`
(`incident_id`, `observed_sequence`, `technique_ids`, `attempted_at`, the four values
that exist at capture time; no transition kind, no request id), the unchanged
`technique-knowledge/1` `record`, and `capture_digest` (sha256 of the canonical
`{binding, record}`), or a stub `{version, state}` with state `binding_missing`
(the answer left the current projection but its binding could not be made) or
`size_dropped` (reduced to fit `RECENT_BYTES`). The reader refuses the whole snapshot
when the digest, the incident id or the record's technique ids do not match exactly.
`attempted_at` is the time of the explanation that asked, not a receipt time.

Derived words (never stored; one function for the API, the screen and the handoff):
`kind` (`past_before_update`, `past_closed`, `past_unavailable`), `adoption`
(always `not_adoptable`), `adoption_reason` (`past_observation`, `closed_incident`,
`binding_missing`, `size_dropped`), `freshness` (`fresh`, `expired`, `unjudgeable`,
or null for a stub; the status view compares `expires_at` with its `now` as it is, the handoff floors both to whole seconds as its `judged_at` is, and the screen judges on the device clock; a retained view carries `judged_at`) and `revocation`
(always `not_checked`: `technique-knowledge/1` has no revocation field). A stub
carries none of the record's keys. `observed_sequence` is shown here (unlike the
trace, whose sequence stays internal) because it is the binding; it is the audit ledger's transition number, not a per-incident count. Names are copied
as stored; the handoff's leak-scanner withholding is applied to the copy it emits
and is never written back. The window is the latest 20 rows: a past reference leaves
with its incident, the audit ledger is untouched, and the screen and the handoff say so.
Known limits: a newer answer whose binding could not be made leaves an older retained reference in place (its own transition number is shown), and a stub left by size pressure can later be replaced by an older retained candidate, since there is no sequence to compare. Under size pressure past references are reduced first (closed rows oldest first, then
open rows oldest first, pending rows included) before slow analysis and explanations.

### Recorded Full-node reference: row trace and reader

The explainer's recent rows may carry an optional row-level key
`full_node_trace`. A row with a malformed trace refuses the whole snapshot, as any
other unknown or invalid row key does. The trace has exactly four keys:
`transition_query` (`queried`, `repeat`, `no_candidate`, `rule_absent`,
`pending`, `not_explained`, `closed`), `last_attempt` (null or `attempted_at`,
`result`, `technique_ids`; `result` is `received`, `received_not_adopted` or
`unavailable`), `last_receipt` (null, or the nine closed projection fields with
`outcome` `complete`/`partial`/`stale`, plus `received_at` and `technique_ids`)
and `observed_sequence`. `received_not_adopted` means the record has status `received` and outcome
`rejected`, `expired` or `unavailable`. A reply dropped by the replacement rule is
`unavailable`, matching the row. An advisory (`complete`, `partial`, `stale`)
whose receipt time is missing from the ledger side is also `unavailable`, and
`last_receipt` is not replaced.

`observed_sequence` is an internal value used only to decide whether a late
explanation belongs to the row's latest transition. It is not copied to the
status view, the handoff package or a peer. It is present in the ui's recent copy
file (not a secret, and no view shows it). The trace is kept for the ui and
operator display only; it is never an input to a candidate decision, a frame, a
request, an M.I.O. input, a record or the current-explanation fields.

How it is written. A trace is created only by an explanation made while a rule is
usable. An explanation of the row's latest transition creates it with that
transition's word. An explanation of an earlier transition (it was queued and a
later one was observed first) also leaves its attempt and receipt: if the row
has no trace yet, one is created with the narrowest word that fits (`closed` if
the row is closed, `pending` if the row's explanation is still pending,
otherwise `not_explained`) and the explainer's in-memory latest observed
sequence. Right after an explainer restart that memory is empty, so such a first
late explanation creates no trace. Observing
a later transition copies the trace and sets `transition_query` (`pending`,
`not_explained`, `closed`) and `observed_sequence`; `last_attempt` and
`last_receipt` are not changed. An explanation sets `queried`, `repeat`,
`no_candidate` or, on a row that already has a trace after the rule is gone,
`rule_absent`, and updates `last_attempt`; `last_receipt` is replaced only by a
reply with an advisory. The trace survives close, reset and restart (checkpoint)
and goes with the row when it leaves the 20-row window; it is not rebuilt when
the incident returns.

"Latest". An explanation belongs to the row's latest transition when the row is
`open` and its ledger sequence equals the trace's `observed_sequence`; without a
trace, the in-memory latest sequence; right after a restart (neither), the row's
`count` and `first_seen`. A late explanation otherwise updates only `last_*` and
gets the same conversion as a new unexplained transition (current fields
`not_queried`); a closed row is not reopened by it.

Known residuals:

- After a restart, with no trace and no in-memory sequence, "latest" is judged
  from the row's `count` and `first_seen`; an incident reopened within the same
  second with the same count can be taken for the same transition.
- A late explanation of an earlier transition, as the first explanation after a
  restart (no in-memory latest sequence), creates no trace, so that receipt is
  not shown (the ledger has it).
- If `observe_transition` raises for a transition, the row (and trace) stay as
  they were and the earlier explanation is still treated as latest.
- If the record cannot be written (`SegmentFull`), `last_attempt` is not recorded
  though the question was sent; the broker's audit has it.
- A row whose optional fields are all at their reader maximum is about 60 KB;
  twenty such rows exceed the 256 KiB recent snapshot limit, with or without a
  trace. This is a property of the existing limits (the trace adds under
  1 KiB per row); ordinary rows are far smaller.
- Rows that leave the 20-row window lose the trace for good.

The ui reader's `/api/view` rows gain one closed word, `full_node_reference`
(the operator and root views do not carry it), judged at the
view's `as_of`: `not_recorded` (no trace), `none` (no receipt), `unknown`
(no usable judging time), `expired` (judging time at or after `expires_at`),
`set_changed` (the receipt's technique set differs from the row's, order
ignored) and `in_window`. `in_window` means only: not past its expiry at the
judging time and queried for the same set as now. It is an unverified advisory,
not the answer to the current transition, and not an upgrade of `partial` or
`stale`. All times in the trace and in the judgement are wall-clock times of the
machine that wrote or judged them, not a trusted clock; a clock moved back can
return `expired` to `in_window` (the open wall-clock-floor item below). The
handoff package for principal `ui` carries the same facts; see
[handoff package](handoff-package.md).

### Deployment order and rollback

Install the new readers first. A reader from before this change reads an unknown
row key as a refusal of the whole recent snapshot (up to 20 rows) and an unknown
fast-assistance key as `invalid_fast_assistance`, after which entryd replaces the
whole fast assistance with a degraded one. So install the release, restart every
resident reader (entryd, explaind, the ui and the daemons that write status;
the CLI handoff reader is in the same package), and only then place the rule
file.

Rolling back past the trace goes to `74a6189` only. After the rule has been in
place, checkpoints carry `full_node_trace` and `query_origin`, and the release at
`74a6189` refuses both (`cursor_refused`, no READY). Convert the stopped
checkpoint with `checkpoint_for_release_before_full_node_trace` and install
`74a6189`; the steps are in [operations](operations.md) (Rolling the explainer
back past the Full-node trace). The trace conversion refuses any existing
`cursor.json.pre-rollback`, even an identical one (the conversion for #392
still resumes an interrupted run). While the earlier release runs, the Full-node
facts of those incidents can be read neither in the ui nor with the CLI, because
it cannot read the new records either. The ledger keeps the original records and
the conversion leaves no record of itself.

## Process boundary

Ordinary `mio.local.assess` requests still arrive at `azazel-mio-locald` over
its existing AF_UNIX socket, and since ADR-0010 locald does not query the
broker: it holds no client group of the broker, and its fast assistance reports
`full_node_context_status: not_queried`. Until 2026-11-17 locald forwarded a
caller-classified free-form P0 question; the broker now refuses any free-form
question before sending, so a P0 label asserted by a caller no longer reaches
the peer at all.

The only client of the dedicated `azazel-knowledge-contextd` broker is
`azazel-mio-contextobsd` (`azmioctx`), the one account in the socket's client
group `azknowledge-context-client` and the broker's only SERVICE principal
(`azmio`, `azmioentry` and root are `principal_denied`). It sends only the
technique query built from a validated fast-transition projection. It runs no
model, holds no model, admission, operator-trust or Mission Pack path, has
`PrivateNetwork=yes`, `IPAddressDeny=any` and AF_UNIX only, and answers the
entry service alone. Locald keeps `PrivateNetwork=yes` and `IPAddressDeny=any`;
`azremote` and its Provider Registry remain separate.

The broker fixes privacy class to P0-public and calls `KnowledgeClient` with a
commissioned sanitizer policy, mission alias and client identity. It returns
only the already verified response. Broker requests have a 16 KiB frame cap,
responses have a 48 KiB cap, the caller deadline applies end to end, and there
is one in-flight request with no queue or retry. A missing, disabled, expired,
untrusted, oversized or late result becomes a fixed refusal; local FAST_ASSESS
continues without external context. The response is advisory only.

The Nexus fast-assessment response may carry the optional, Nexus-owned field
`full_node_context_status`: `not_queried` means no broker request was made,
`received` means the broker returned a response for M.I.O. to evaluate, and
`unavailable` means an attempted broker request failed. This transport state
is separate from the shared M.I.O. `dependency_outcome` and from Knowledge Lite.
It does not assert that source claims are verified or that a received snapshot
is complete. If Lite is available while the full node is unavailable, the Lite
result remains available and the full-node failure remains visible in the
separate field. Older or degraded fast-assessment responses may omit the field.

The incident snapshot and operator UI show a separate full-node status and,
when an advisory is present, its source kind, unverified trust, snapshot state,
generation and expiry times. Only fixed limitation messages are displayed;
producer limitation text, subjects and opaque identifiers are withheld. An
expired receipt is labelled expired in the UI even if its stored snapshot was
previously current. This display depends on the operator device's clock and is
re-evaluated when the screen is redrawn; it is not an independent trusted-clock
verification. A new incident transition does not reuse the earlier
full-node receipt while its new explanation is pending.

The broker sends only the typed `attack-technique/v1` entities of the technique
query; no `question` and no typed IOC. Before ADR-0010 the ordinary P0 entry
sent a free-form `question`, which the candidate producer reported as an unknown
rather than an exact match; that entry no longer exists. Typed-IOC lookup
requires a separate contract and must not reclassify restricted incident data
as P0.

The service uses the separate `azknowledgeegress` account. The installed unit
is preset disabled, requires its activation grant marker and is absent from
`wired_capabilities()`; a commissioning loader exists and consumes a
root-owned bundle, but activation remains a separate gate.
Its unit retains `IPAddressDeny=any` and, as shipped, has no `IPAddressAllow`
entry. Thus installation does not start it and the shipped unit cannot reach a
Knowledge peer; the one way to give it a destination is *Egress allowance*
below. The broker's default constructor is closed even if started manually; the
service enables the broker only when the root-owned commissioning bundle loads
as commissioned, and any absence or defect leaves it closed.
The new per-request audit ledger has no retention or disk quota in this
candidate; production activation needs an explicit storage and retention policy.

## Commissioning and credentials

No live credential or trust material is included. Before a live connection is
implemented, an owner must be named for the client certificate/private key,
Knowledge response-signing key and CA trust; their issuance and expiry windows,
rotation notification, revocation source, emergency disable and recovery
procedure must be recorded. The broker must use its own commissioned registry
and identity, never `azremote` credentials or the Provider Registry. A
commissioned endpoint allowlist is also required before any network allowance
can be designed. Until those conditions are met, activation remains withheld.

Before any activation request, an operator can confirm the start-up
configuration with read-only commands only (nothing here changes state):

1. `AZAZEL_ROOT` is not set for the service: `systemctl show -p Environment -p EnvironmentFiles azazel-knowledge-contextd.service`
   prints empty values, and `grep -rs AZAZEL_ROOT /etc/systemd/system /usr/lib/systemd/system` finds nothing relevant.
2. No drop-in sets `Environment=` or `EnvironmentFile=`: `systemctl cat azazel-knowledge-contextd.service`.
3. No drop-in exists yet: `systemctl cat azazel-knowledge-contextd.service` shows no drop-in section, and
   `/etc/systemd/system/azazel-knowledge-contextd.service.d/` does not exist (`ls -d`). A network allowance is not designed here.
4. The unit is still in the state the plan expects: `systemctl is-enabled azazel-knowledge-contextd.service`
   (disabled or masked) and `systemctl is-active azazel-knowledge-contextd.service` (inactive).
5. No activation grant marker exists yet: `ls -l /run/azazel-activation/granted/azazel-knowledge-contextd.service` reports no such file (the unit's `ConditionPathExists`). Do not create or edit anything there.
6. The bundle is root-owned and not group/other-writable, secrets have no other-user access:
   `stat -c '%U:%G %a %n' /etc/azazel/knowledge-context/commissioning /etc/azazel/knowledge-context/commissioning/*`
   (`stat -f '%Su:%Sg %Lp %N'` on macOS), and `ls -ld` on each parent directory.
7. `sudo -u azknowledgeegress -g azknowledgeegress python3 tools/check_knowledge_context_bundle.py` (never as root; the group is the daemon's primary group `azknowledgeegress`, not the socket group `azknowledge-context-client`, or the pre-check passes where the daemon refuses with `perm_unsafe`; the loader's checks depend on the caller's uid and group) reports `commissioned` and its
   warnings are understood. `--pin <cert>` prints the Nexus (SPKI) and Knowledge
   (DER SHA-256) pin forms for comparison with each side's configuration.

Passing these checks is a precondition for requesting activation, not the
activation itself.

The open ownership and lifecycle items are:

- endpoint, CA and client-certificate provision owner and accepted trust anchor;
- Knowledge response-signing registry owner and key identifier assignment;
- certificate/signing-key validity, rotation approver and overlap period;
- numeric maximum response TTL;
- revocation authority and notification route; and
- emergency disable and recovery procedure.

The #402 adapter can open a socket only through an explicit enabled client call
with commissioned transport inputs. This #403 change adds the optional local
process boundary without supplying the production registry, credentials,
trust anchor or network allowance; those commissioning decisions remain open.

## Isolated acceptance matrix (software only)

`tests/unit/test_knowledge_context_acceptance.py` keeps a real `KnowledgeClient`
and `KnowledgeContextBroker` against a synthetic producer on loopback mTLS
(test-only PKI and signing key; it needs the `fabric` and M.I.O. extras and
skips without them). Since ADR-0010 it asserts refusals only: the ordinary entry
(`LocalRuntimeService` FAST_ASSESS) asks the broker nothing (`not_queried`), and
the commissioned broker refuses the same free-form question, the old
observation sentence included, before sending, so the producer receives no
request whatever it would have answered. The table below is the matrix as it
stood before 2026-11-17, kept as the record of the removed free-form path; its
positive cases no longer exist. The technique query is covered by
`tests/unit/test_technique_knowledge_path.py` and the real-process runner. The
matrix asserted:

| Case | Expected result |
| --- | --- |
| valid response for the request | `received`; advisory is `advisory_only`, `source_reported_unverified`, `unverified_advisory_only`; source kind, snapshot state and generated/expiry times reach the stored projection; one producer call; audit holds fixed event names, outcomes and size/time numbers, no content |
| same inputs, Knowledge refused vs. received | every field outside the Knowledge-context fields is identical: the advisory cannot change observations, hypotheses or any decision field |
| bad signature, tampered payload, expired envelope, wrong key id, wrong request id, wrong provider id, HTTP 500, non-envelope body, oversized body, producer absent | `unavailable`, no advisory, local assessment still `assessed`, no producer text or snapshot reference anywhere in the result, projection or audit |
| producer slower than the Knowledge wait budget (0.25 s in locald) | request reaches the producer, is abandoned at the budget, `unavailable`, local assessment completes |
| earlier valid signed answer replayed for a new request, with a fresh client and broker (not a process restart) | refused; a later honest answer is accepted again |
| non-P0 frame, or the shipped uncommissioned broker | producer never queried (`not_queried`); broker returns a fixed `unavailable` |

Not established by this matrix: operator-UI rendering of an expired receipt
(covered by UI tests), a typed-IOC lookup (not in contract), the Linux
peer-credential and systemd confinement (see the Linux isolated acceptance section), and any real
credential, trust anchor or network.

## Linux isolated acceptance (unit 29)

`tests/real_process/test_knowledge_context_linux_acceptance.py` runs in the
existing isolated root container (`run-docker.sh`: `--network=none`, no new
capabilities, read-only mounts, `--rm`), with a real Knowledge mTLS producer
process, the real broker, contextobsd and entryd processes, distinct container-only
uids and real `SO_PEERCRED` / `SO_PEERGROUPS` on real AF_UNIX sockets. It
changes no product code. Since ADR-0010 (2026-11-17) the served peer is
`azmioctx` (`azazel-mio-contextobsd`), the request is the technique query, and
the chain is the explainer → entryd → contextobsd → broker; the rows below were
re-run in that form (container runner, Knowledge source 7019ac1). Two harness
seams exist, both test-only: the
producer wrapper fixes the signing seed and port across restarts, and the
broker harness can record the producer envelope and, while a control file
exists, offer an earlier envelope at the network edge (`_post_path`). The
signature, lifetime and request-binding checks that follow the edge are the
product's own.

### Peer authentication (area A)

| Case | Result observed |
| --- | --- |
| service peer `azmioctx` in the client group, technique query | served; the producer receives typed `attack-technique/v1` entities only |
| the same peer, free-form question (also the old observation sentence) | refused before sending (`refused_before_send`); no `requested` event and no producer exchange |
| `azoperator` / `azmioentry` / `azmio` placed in the client group (so the filesystem passes) | refused inside the broker with `principal_denied`; the broker audit holds the kernel uid, the verb, no `requested` event and no producer exchange; root is refused the same way |
| service uid or operator uid outside the client group | `EACCES` at `connect` (this includes the effect of the 2710 parent directory; socket mode alone is not isolated) |
| identity named in the request | at the top level or in `arguments`: `client_asserted_principal` from an allowed peer; a denied peer naming an allowed uid is still `principal_denied` (principal is checked first) |
| client against an impostor socket | wrong owner, mode or group: refused before connect and nothing arrives; correct file attributes but the process behind the socket is another uid: refused as `peer identity` after connect and no request byte is sent |
| missing peer credentials | a real non-AF_UNIX peer reports pid 0, uid/gid -1; the function-level check shows the server never reaches the handler. A daemon only ever listens on AF_UNIX, so this is a function-level observation, not a daemon test. The client branch `pid <= 0` (a peer in another PID namespace) is not verified |
| restart and socket regeneration | orderly stop removes the socket; a crash leaves a stale socket that refuses connects; the restart recreates it with the same owner, group and mode and the same allow/deny results. The shipped `main()` has no SIGTERM handler, so even SIGTERM leaves a stale socket (the restart replaces it) |

### systemd: static versus effective (area B)

Static (`tests/unit/test_knowledge_context_systemd_static.py`, host and Linux):
the shipped unit declares `User=azknowledgeegress`, `NoNewPrivileges`,
`ProtectSystem=strict`, two `ReadWritePaths`, `PrivateTmp`, `PrivateDevices`,
`Protect*`, `RestrictNamespaces`, `RestrictSUIDSGID`, `MemoryDenyWriteExecute`,
`SystemCallFilter=@system-service`, empty capability sets,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `IPAddressDeny=any` with no
`IPAddressAllow` (so the package as shipped cannot egress), `UMask=0027`, the
activation `ConditionPathExists`, and `Type=notify`; the installer's directory
modes match the daemon's socket and state paths. This shows the files agree,
not that the kernel enforces them.

Effective: **real systemd was not run.** The images have no systemd and running
one as PID 1 needs a privileged container with cgroup access, which this
acceptance does not add. A `setpriv` approximation runs the real daemon as a
non-root uid with no-new-privs, an empty inheritable/effective/permitted
capability set and umask 0027, and shows: the socket and ledger attributes,
the fixed refusal from the uncommissioned factory, `principal_denied` in the
daemon's own ledger, `setuid(0)` and `chown` failing with `EPERM`, a write
outside the state area failing with `EACCES` (ordinary file permissions, not
`ProtectSystem`), and the daemon refusing to start when its state area is not
writable or its ledger is corrupt or torn (no socket is bound). **Not
effective in that environment:** `ProtectSystem`/`ReadWritePaths` (mount
namespace), `PrivateTmp`, `PrivateDevices`, `Protect*`, `RestrictNamespaces`,
`RestrictAddressFamilies` and `SystemCallFilter` (seccomp),
`MemoryDenyWriteExecute`, `IPAddressDeny` (the container network is simply
off), the bounding set (the runner's capability set stays in the bounding set; the process holds none effective), `ConditionPathExists`, restart policy, and the `Type=notify`
handshake (`systemd_notify` requires a real systemd context and is not
simulated). Paths are relocated with `AZAZEL_ROOT`, not the real
`/var/lib/azazel`. Needed for real acceptance: a disposable VM or a container
run with a real systemd and cgroup delegation, with the decision to allow it.

### Replay across restarts (area C)

The only replay defence is request binding: each call generates a fresh
128-bit `request_id` in the broker (`make_request`), the producer's signed
envelope carries it, and the answer is validated against that request. There is
no replay state to persist, and none was added. Observed, with the producer
real and the envelope still inside its signed lifetime: after the broker is
stopped (SIGTERM or SIGKILL) and restarted, an earlier valid envelope offered
for a new request is refused as the fixed `unavailable`, and a direct control
call shows the same envelope is accepted for its own request and refused for
the new one (so the refusal is by binding, not expiry or signature). A new
request then succeeds, so there is no permanent refusal. A producer restart
with the same key and port needs no broker restart; a producer restart with a
different key (Knowledge's fixture default) is refused (recovery presumably needs an operator registry key update; not exercised here, and an open commissioning step). Six
concurrent callers: every served answer belongs to its own request and none is served twice, and the rest receive `timeout` or `unavailable`. The audit ledger
is the only durable state; an empty ledger starts. (Observed on the version before
#472: a corrupt or torn one stopped the daemon before it bound. Since #472 such a
ledger is read as broken: the daemon binds and serves with egress closed, the status
says `ledger_broken`, requests are refused and the ledger bytes do not change. The
Linux c4 run, which needs its own runner, now asserts that; it was not run for this
change. `tests/unit/test_w472_contextd_recovery.py` checks the same three ledgers
(broken JSON, a torn line, a lone surrogate) with a real process.) These show the broker keeps no state across a
restart, not a protection specific to restarts. locald and entryd keep no
state either, so restarting them changes nothing for this property.

### Clocks (area D)

| Use | Clock | Observed |
| --- | --- | --- |
| signature validity, TTL, semantic generated/expiry, registry validity | wall clock (`KnowledgeClient.utc_now`) | window is [max(issued, generated), min(expires, semantic expiry)); one microsecond before the start and at the end are refused; no grace; unparseable, naive, empty or non-string time is refused |
| MIO expiry | wall clock of the MIO side (`datetime.now` in `mio_fast_assistance`, taken after the broker returns) | `now` before `generated_at` is rejected; `now` at `expires_at` is dropped with `KNOWLEDGE_CONTEXT_EXPIRED`; one microsecond earlier is accepted |
| request budget | `time.monotonic` | an absolute `deadline_monotonic_ns` in the past is refused as `timeout` before any producer call; the shorter of it and `deadline_ms` governs |

Observation, not a guarantee: the Context path keeps no wall-clock floor.
After a window has passed, moving the injected clock back makes the same
(request, envelope) valid again, and the registry window follows the same
clock. The request is consumed within the call and another request is refused
by binding, so the reach is the caller that holds both. The tests inject only
one side (MIO) to model skew; in production both read the host clock in
different processes. Clock difference between hosts, the allowed skew and the
maximum envelope lifetime (`max_ttl_seconds`, tests use 30) are not defined by
the contract and no grace period was added; they are commissioning decisions.

### Status

| Area | Status |
| --- | --- |
| A peer authentication | isolated acceptance passed (real kernel, container) |
| B systemd | static agreement passed; **real systemd not run**; approximation only |
| C restart replay | isolated acceptance passed |
| D clocks | isolated acceptance passed for the single-host model; cross-host skew not tested; re-validity after a clock rollback is an open observation (see Open items) |
| real credentials, trust anchor, endpoint, audit retention, activation grant | not done |

## Egress allowance

The broker's unit may carry exactly one `IPAddressAllow=<ip>/32` (or `/128`),
the registry peer's one address, the address the client connects to (no DNS
lookup, `knowledge_egress.egress_address`). The registry loader refuses a peer
whose `addresses` does not hold exactly one entry, so neither the connection nor
the Allow ever depends on list order. Nothing else is configurable. The
allowance digest (peer id, host, port, SPKI pin, address, registry version,
registry commissioning digest) is written into the unit as a header comment, so
it is part of the generation-hashed bytes: a different host, pin or version at
the same IP changes the unit and needs a new generation and approval.

The only writer is `az-knowledge-context-egress` (root):

- `show` the derived line and digest; `check` the installed unit against the
  derivation (exit 0 when equal); both read-only.
- `apply` / `remove` require the grant marker to be absent and the broker to be
  stopped with an empty cgroup. They re-render the unit from the declaration,
  write it atomically, reload the manager and run `az-activation
  generation-publish`. Then `az-activation request` and `install` as usual.
  Nothing is admitted until the operator signs.
- IP change: new signed registry (new single `addresses` entry, higher version), replace
  the bundle, withdraw and stop, `apply`, publish, sign, install. Until then the
  pass refuses (the unit's Allow and digest differ from the derivation); there
  is no wider fallback.
- Removal: withdraw and stop, `remove`, publish, sign, install. Disabling the
  bundle alone makes the pass refuse the Allow-bearing unit.

The derivation (`show`, `check`, `apply`, and the pass) reads only the manifest
and the signed registry, under the same owner and mode rules as the daemon, and
never the secret files. Those are `root:azknowledgeegress 0640`, readable only
by the daemon's own group, so a root caller (egid 0) must not need them; the
daemon's own reads are unchanged. A bundle the daemon would refuse for a short
`alias.key` still derives an allowance; the daemon stays closed. `apply` and
`remove` check the broker's cgroup in operator mode: the same cgroup2 mount
binding as the pass, but the caller may be a login shell (own cgroup `/` or
under `init.scope`, `user.slice`, `system.slice`, present under the mount);
anything unestablished is `unknown`, which is not empty.

The pass compares the unit's `IPAddress*` lines (absent or exactly the derived
line, `IPAddressDeny=any` once) and the manager's loaded `IPAddressAllow` /
`IPAddressDeny` (D-Bus `a(iayu)`; loaded Allow must equal the unit file's, `system.slice` and `-.slice` must have an empty Allow whether or not the broker is loaded (a withdrawn, masked broker has no loaded read, so they are read on their own), a wider one refuses). The loaded representation of `IPAddressDeny=any` (two zero-prefix entries) was confirmed on systemd 257 in an isolated container (lab evidence, not a deployment). A drop-in is
still refused. Limits, stated so they are not read as more than they are:

- The filter is per address, not per port: every port and protocol at the
  allowed address is reachable.
- `AF_UNIX` is allowed to the broker, so a local forwarder it can reach could
  delegate egress; the filter does not cover that.
- It is a cgroup-BPF filter. Where the kernel or container manager lacks
  support it has no effect; acceptance needs a real allowed/denied connection
  test, not the loaded property alone.
- Address reassignment, NAT or routing change after approval is not detected.

## Open items before any real connection

Nothing in this repository authorizes a live connection. The items below are
open and undecided; they are listed, not proposed as policy, and none is
satisfied by this software:

1. The open ownership and lifecycle items listed under *Commissioning and
   credentials* are decided and written down, including the numeric maximum
   response TTL.
2. A production commissioning registry exists. The loader that consumes the
   root-owned bundle ships, and the broker stays closed unless that bundle
   loads as commissioned; activation remains a separate gate.
3. Which trusted local inputs may set the P0 label and which question fields
   may be sent (stated above as required; not yet defined).
4. The endpoint (one address) is approved with the signed registry; this
   package ships no `IPAddressAllow`, and the deployment-time mechanism is
   *Egress allowance* below.
5. The per-request audit ledger gets an explicit retention and disk-quota
   policy.
6. Unresolved observation: the Context path has no wall-clock floor, so a
   clock moved back makes the same (request, envelope) valid again for a
   caller holding both (see *Clocks*). This is distinct from the restart
   result above, which shows only that a different request is refused by
   binding; reuse of the same request is not prevented. Whether a floor,
   persisted state or other measure is wanted is undecided. The Full-node
   trace and its `reference_state` (also `full_node_reference` and
   `expired_at_generation`) are judged on the same wall clock, so a clock moved
   back can also return an `expired` reference to `in_window`; this change adds
   no floor, and the item stays unresolved.
7. The activation grant for `azazel-knowledge-contextd.service` is issued by
   the existing activation path, not by editing the unit: a signed policy
   names the unit and the lease lists it. A bundle that loads as commissioned
   does not grant it, an absent bundle does not withhold it, and Knowledge
   Context is not added to `wired_capabilities()`.

Stopping and recovery: the unit is preset disabled and starts only while its
activation grant marker is present. The controller can stop this unit, and
only this one (`docs/activation-observe-baseline.md` §8.3). When the grant
ends (the unit dropped from the policy, a lease that does not list it, an
expired approval, a revoked operator, failed health or commissioning
evidence), the next pass, or the periodic recheck (every 30 s as configured,
not a bound), removes the marker, replaces a start job that is pending for the unit
(`StopUnit`, recorded as `queued_job_replaced`; before the mask, because the mask
and the reload would make systemd fail it), masks the unit, reloads the manager,
sends `StopUnit` if it is running, then confirms the unit quiet (inactive, or, for this confirmation only, `failed` after a kill, with no job, and in both cases its cgroup confirmed empty; `failed` alone does not show that no process remains, see "What a stop does and does not show" in activation-observe-baseline.md §8.3). The broker also
reads its marker when it accepts a request and again before it adopts the
peer's answer: after the marker is gone it accepts nothing and adopts no
answer (`reason_code` `withdrawn`). An answer adopted earlier may still reach
the caller until the unit is inactive. Stopping by hand is no longer
required, and stopping alone is still not durable: while the policy and
approval still grant the unit, a later pass grants it again. When the
operator that signed the approval is explicitly revoked, the approval is
retired and the same approval is refused afterwards. The pass never issues
StartUnit, so the broker runs again only at the next boot or an operator start
as below.

Recovery after a withdrawal. A withdrawn broker is masked, with its marker
removed. A plain `systemctl start azazel-knowledge-contextd.service` of that MASKED
broker is refused (`Unit ... is masked`) and pulls in no pass, so it changes
nothing. (Starting an UNMASKED, granted broker is different: see step 3.)
To bring the broker back, in this order:

1. `systemctl start azazel-activated.service`, which runs a pass. It grants
   the broker again only if the approval, the policy, health and evidence
   still allow it (an approval retired after an explicit revocation does not,
   and a new approval is needed: after retiring approval N it must be signed with
   `--seq` N+2 or higher; see the retirement paragraph of `activation-observe-baseline.md`
   section 8.3 for why N+1 is refused).
2. Confirm that the pass granted it: the newest `activation.inputs_incomplete`
   record in `/var/lib/azazel/state/activation.jsonl` lists the broker in
   `grant_markers`, and `/run/azazel-activation/granted/azazel-knowledge-contextd.service`
   exists. If the pass failed or did not grant it, do not go on.
3. `systemctl start azazel-knowledge-contextd.service`.

What step 3 does. The broker has `Requires=azazel-activated.service`, and
the controller has exited after step 1 (it has no `RemainAfterExit`), so
starting the broker queues a second controller pass first. The second pass is
designed to keep the broker's queued start job and to re-grant it:

- its preflight removes the markers and masks and reloads every governed unit
  except a broker that is inactive with a start job queued, which it leaves as
  it is (masking and reloading would make systemd fail that job; the job cannot
  run before READY, because the broker is ordered after the controller);
- it decides: if the broker is granted again (unmask, enable, reload, marker
  written) the queued job runs once READY is sent and finds its marker; if it is
  withheld (the approval, the policy, health or evidence no longer allow it, or a
  retirement is pending, which makes the pass withhold every unit), or the pass
  narrows for any reason or runs out of budget, the queued job is replaced with
  `StopUnit` (mode `replace`) FIRST, the replacement is recorded as
  `activation.queued_job_replaced`, and only then is the broker masked and the
  manager reloaded: masking and reloading first makes systemd fail the job
  ("Failed to start"), with no replacement and no record. If the job has already
  ended when the pass gets to it, its fate is recorded as
  `activation.queued_job_ended` with the broker's `ActiveState` and unit-file state
  as far as they can be read. This holds for the verdict's own mask, a rollback,
  an emergency narrowing, a budget expiry and a failed READY or barrier.
  Every narrowing of the pass also runs the full broker withdrawal afterwards, because
  when READY or its barrier failed, READY may already have released the held job
  and started the broker;
- if the pass dies, `Requires=` fails the job, which is the fail-closed side.

Other conditions can also make the second pass withhold or narrow, for example a
governed unit that is running (a containment failure). This sequence is the
design; it counts as confirmed only once the same-boot procedure has been run on
a clone (unit 45 S1) and its result recorded there. If the queued job is
instead cancelled or failed on a host, the supported recovery is a reboot after
the grant of step 1: the broker is enabled, and the boot pass writes its marker
before the broker's start job is evaluated.
Introduce in this order: new release,
then a policy naming contextd. Withdraw in this order: remove contextd from
the policy and re-sign, confirm on the next pass that it is closed, then
return to an older release (an older release refuses a policy that names
contextd as a whole). A policy whose `units` changed no longer matches the
published generation, so that pass grants nothing at all, the other
SUPPORTING units included (they lose their grant and cannot be started
again). To withdraw only contextd, republish a generation built for the
reduced unit list and sign a new approval for it as well as the policy.
Markers are removed and rewritten by every pass, so a stale contextd marker
does not survive; a unit the pass withholds stays masked, and only granted
units are unmasked. Either way, FAST_ASSESS returns to
`unavailable` (the request fails closed) with Knowledge Lite and
local assessment unchanged. The broker keeps no response cache, so there is nothing
stale to clear after a restart. How a revoked or expired peer key is replaced
is one of the open items above and is not defined here.

## Verification scope

Unit tests cover caller injection refusal, P0 binding, payload bounds and the
disabled default. The isolated real-process tests start Knowledge, the broker,
the context observation unit and entryd as separate processes under their own
uids, with synthetic certificates and loopback transport, and assert that the
explainer's `mio.context.observe` gets a verified technique record
(`technique_knowledge` received/ok) that is never handed to M.I.O., and that a
free-form question never reaches Knowledge. Before ADR-0010 the same suite
asserted a verified advisory on ordinary FAST_ASSESS through locald; that path
was removed, and the #403 PR evidence records that earlier result. This does not establish production credential
lifecycle, systemd egress, hardware, release or deployment.

The candidate does not set a production dependency pin to an unreleased Fabric
commit. Product packaging continues to use the accepted Fabric tag until the
normal version and offline-wheel review updates it.

For current implementation and test status, see [M.I.O. runtime](mio-runtime.md)
and [operations](operations.md).
