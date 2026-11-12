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

A question that is exactly `ATT&CK technique context: ` followed by one to eight
technique ids (`T1234` or `T1234.567`, single spaces) is treated by the broker
as observation-origin. The question is built by `azazel-mio-locald`, not by the
explainer, from a sorted, validated set of ids. Other questions are handled as
before.

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
| `azazel-mio-entryd`, `azazel-mio-locald` | relay the request; locald builds the question | not read. The rule is enforced by the broker |
| `azazel-knowledge-contextd` (broker) | treats matching questions as observation-origin, counts them, refuses them without a rule | once at start. After that, on each observation-origin request, it checks that the file's identity (device, inode, mtime, ctime) is unchanged; a missing or changed file latches the broker closed to such questions until restart |
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

The broker counts observation-origin requests that passed the rule and limit
check in the last 60 seconds, including ones that later fail (for example
`busy`). At `max_requests_per_minute` the request is refused as `rate_limited`.
Both refusals are decided before the `knowledge.context.requested` event, before
the in-flight slot and before any peer call. The window is in memory, so a
broker restart empties it. The limit covers questions of this shape only; other
P0 questions are never counted.

The first stage is the explainer's existing six explanations per minute
(`MAX_PER_MINUTE`), which the observation-origin candidates cannot exceed. The
broker's limit is the second layer: it also bounds a restarted explainer and any
caller that sends a question of this shape.

Residual effects:

- Occupancy. The broker has one in-flight slot with no queue. An
  observation-origin request holds it for as long as the peer takes (at most the
  caller's deadline, 350 ms), so an ordinary P0 request arriving then gets `busy`.
  The reverse also happens: if an ordinary request holds the slot, an
  observation-origin request gets `busy`, is counted, and its pair is not asked
  again (below). Since a `busy` refusal still counts toward the limit,
  repeated occupancy can use up the minute's allowance without a single send.
- Effect on ordinary P0 callers. Without a rule, an ordinary P0 question whose
  text happens to match the shape exactly is refused (`refused_before_send`),
  and with a rule it is counted against the limit. The ordinary entry sends free
  text questions, so this is not expected in normal use (推測です), but it
  is the one place where the rule file changes the behaviour of the earlier path.

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

A missing `reason_code` on a record written before this field existed reads as
"not recorded"; on a record written after, it reads as "unclassified". Neither
is inferred. Events never contain exception text, the question or any response
fragment.

### The explainer's request: `mio.context.observe` and `mio.local.observe`

The explainer asks at most one observation-origin question per candidate
explanation, after `mio.advise` and Knowledge Lite and before the record is
composed. It uses `mio.context.observe` on `azazel-mio-entryd` (deadline 350 ms,
plus a 250 ms caller margin), which relays to `mio.local.observe` on
`azazel-mio-locald`.

- `mio.context.observe` is allowed to the explainer only; any other principal
  is `PRINCIPAL_DENIED`. It requires a P3 frame with the structured projection
  and at least one technique. It draws on the same per-caller rate allowance as
  `mio.advise`, writes nothing to the entryd ledger, and does not change
  `mio.advise`'s 500 ms budget, FAST_ASSESS or the ordinary P0 path.
  `mio.local.observe` is a SERVICE verb under the existing `azmioentry`-only policy.
- The 350 ms deadline is a candidate contract, not a measured one. The reply
  carries a fixed-key `timing` (`context`: received or unavailable, `broker_ms`,
  `total_ms` from locald; `entry_ms` from entryd) so that success, delay and
  refusal can be measured. Nothing is logged or recorded from it yet, and no
  measurement has been taken.
- The explainer does not adopt the reply as it arrives: it re-validates the
  returned `fast_assistance` with `read_fast_assistance` before the replacement
  rule runs, and a reply that fails is treated as `unavailable`.
- A broker refusal, an unreachable broker, a timeout or an exhausted budget all
  return `unavailable` in the same shape. Locald does not submit generation.
- Locald stamps `full_node_context_received_at` (UTC, a wall-clock time and not a
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
`full_node_context_received_at` comes from locald and is present only when the
broker answered. The projection
`explanation.fast_assistance.full_node_context` gains the optional `query_origin`
(same three words), which explaind copies from the record. Old rows have neither
and read unchanged.

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
its existing AF_UNIX socket. The P0 label on an incoming question is a caller
assertion, not proof that its content is public. The broker checks the label
and applies the commissioned field allowlist and named redactions, but does
not classify arbitrary free text. Production commissioning must restrict
which trusted local inputs can set this label and which question fields can be
sent; untrusted text must remain local. Locald submits the bounded frame to the dedicated
`azazel-knowledge-contextd` broker over a second AF_UNIX socket. Only the
`azmio` local runtime account is in the socket's client group. Locald keeps
`PrivateNetwork=yes` and `IPAddressDeny=any`; `azremote` and its Provider
Registry remain separate.

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

The ordinary P0 entry sends a `question`, not a typed IOC. The candidate
Knowledge producer cannot normalize that type as an IOC and reports it as an
unknown rather than asserting an exact match. This entry establishes bounded
question/unknown interoperability only; typed-IOC lookup requires a separate
contract and must not reclassify restricted incident data as P0.

The service uses the separate `azknowledgeegress` account. The installed unit
is preset disabled, requires its activation grant marker and is absent from
`wired_capabilities()`; a commissioning loader exists and consumes a
root-owned bundle, but activation remains a separate gate.
Its unit retains `IPAddressDeny=any` and has no `IPAddressAllow` entry. Thus
installation does not start it and this candidate cannot reach a Knowledge
peer. The broker's default constructor is closed even if started manually; the
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

`tests/unit/test_knowledge_context_acceptance.py` drives the ordinary entry
(`LocalRuntimeService` FAST_ASSESS) through a real `KnowledgeClient` and
`KnowledgeContextBroker` against a synthetic producer on loopback mTLS, using
test-only PKI and a test-only signing key. It needs the `fabric` and M.I.O.
extras and skips without them. The AF_UNIX hop between locald and the broker
is replaced by a direct call whose deadline arguments are built in the test,
not by the real socket client; that hop stays covered by the isolated
real-process runner. The matrix asserts:

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
process, the real broker, locald and entryd processes, distinct container-only
uids and real `SO_PEERCRED` / `SO_PEERGROUPS` on real AF_UNIX sockets. It
changes no product code. Two harness seams exist, both test-only: the
producer wrapper fixes the signing seed and port across restarts, and the
broker harness can record the producer envelope and, while a control file
exists, offer an earlier envelope at the network edge (`_post_path`). The
signature, lifetime and request-binding checks that follow the edge are the
product's own.

### Peer authentication (area A)

| Case | Result observed |
| --- | --- |
| service peer `azmio` in the client group | served |
| `azoperator` / `azmioentry` placed in the client group (so the filesystem passes) | refused inside the broker with `principal_denied`; the broker audit holds the kernel uid, the verb, no `requested` event and no producer exchange; root is refused the same way |
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
is the only durable state; an empty ledger starts, a corrupt or torn one stops
the daemon before it binds. These show the broker keeps no state across a
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
4. An endpoint allowlist is approved before any `IPAddressAllow` is designed;
   this package supplies none.
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
not a bound), removes the marker, masks the unit, reloads the manager and
sends `StopUnit`, then confirms the unit inactive with no job. The broker also
reads its marker when it accepts a request and again before it adopts the
peer's answer: after the marker is gone it accepts nothing and adopts no
answer (`reason_code` `withdrawn`). An answer adopted earlier may still reach
the caller until the unit is inactive. Stopping by hand is no longer
required, and stopping alone is still not durable: while the policy and
approval still grant the unit, a later pass grants it again. When the
operator that signed the approval is explicitly revoked, the approval is
retired and the same approval is refused afterwards. The pass never issues
StartUnit, so the broker runs again only at the next boot or an operator start.
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
disabled default. The isolated real-process test starts locald, the broker,
and Knowledge as separate processes with synthetic certificates and loopback
transport, and asserts the verified advisory response reaches ordinary
FAST_ASSESS. The current candidate has passed this software test. The fixed
head, repository identities, build artifacts and exact results are recorded
in the #403 PR evidence. This does not establish production credential
lifecycle, systemd egress, hardware, release or deployment.

The candidate does not set a production dependency pin to an unreleased Fabric
commit. Product packaging continues to use the accepted Fabric tag until the
normal version and offline-wheel review updates it.

For current implementation and test status, see [M.I.O. runtime](mio-runtime.md)
and [operations](operations.md).
