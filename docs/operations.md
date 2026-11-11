# Field Operations Design

## 0. Read-only operator setup guide

Run these from the reviewed Nexus source directory when the guide needs to
print the relative installer command:

```sh
azazel-nexus setup
azazel-nexus setup --next
azazel-nexus setup --json
azazel-nexus setup --next --json
```

Every row contains a step name, `done`, `needed`, `blocked`, or
`not-applicable`, a reason, and a next command or an explicit statement that no action is available. `--next` selects the
first `needed` or `blocked` row. It only prints guidance: even commands naming
`sudo`, publication, recovery, import, or `systemctl` are never executed.
Setup creates no files, audit entries, directories, or service-manager jobs.
Exit 0 means the guide was read, **not** that setup or activation succeeded;
incomplete paired manifest arguments return 2. JSON uses schema
`azazel-nexus/setup/1` with `steps`, `read_only`, `hg05`,
`provider_admission`, `enforcement_readiness`, `lab_host`, and `mio` fields.

The order is installed files → host preflight → commissioning presence →
signed draft review → bootstrap deployment and current-boot selection →
Knowledge Lite store and trust → Mission Pack selection → fetch commissioning
presence → fetched model candidates → provider admission → activation/unit
state → integration broker → M.I.O. configuration. `done` applies only to the fact named in that row. It does not grant
capabilities or certify later steps.
On a LAB HOST, next steps that would be refused by LAB_HOST_MARKER are
reported as unavailable; successful reads remain `done`. The ordered `--next`
guide stops at the first unresolved step even when it is unavailable on a lab host;
use `setup` to inspect later steps. Bootstrap diagnostics distinguish boot-binding mismatch
from missing or unreadable inputs; retained state requires administrator review,
not another invocation of setup. No state is repaired by these displays.

Both setup and status show the recorded M.I.O. ceiling (CORE/LITE/FULL), capability
state and reasons from the latest `mio.capability.transition` (or the `mio.capability.carried` record that opens each daily segment) in the hash-chain consistent route ledger
`/var/lib/azazel/state/mio/route/` (or the pre-migration `route.jsonl`). This is the last recorded observation,
not a live probe or a freshness guarantee. Without readable ledger evidence the
values are unknown; operator commands do not read entryd credentials or infer
LITE/FULL from RAM. The recorded ceiling is not a grant or admission; entryd records CORE when no
profile is selected or its reader fails. Status does not
query systemd, and audit-chain health is unknown without an explicit `--ledger`.

`azazel-nexus status --json` prints the read model the text screen is rendered
from, schema `azazel-nexus/status-view/1` (`src/azazel_nexus/status_view.py`),
instead of the text. It reads exactly what `status` reads, through the same
strict snapshot readers, and is built by allowlist: each section carries a
`status` word, a `reason_code` for anything unknown, unmeasured, refused or
stale, and its `source` (snapshot schema, `written_at` and freshness where a
snapshot is the source). Edge decisions appear only as `would` with
`executed: false`; the execution result is fixed to `none` with reason
`nexus_accepts_observe_only`, because the intake refuses any Edge event that is
not observe-only. A loop component whose snapshot reports `chain_broken` or
`storage_failed` is `degraded`, not `running`, and the M.I.O. reading is
judged against the status clock. The route ledger records transitions only,
so on a stable node the reading stays unchanged for days: how long is shown
as `age_s` and is information, not a verdict. What makes the reading `stale`
is that its writer, entryd, is no longer shown to be alive (`liveness`,
`liveness_evidence_expired`): entryd's operator snapshot (rewritten every
minute) counts when it is fresh against its own 300-second limit and holds
the same reading. Only when that snapshot cannot be read (absent or
refused) does the route ledger's newest capability record (a transition, or
the carried record a day's first write opens a segment with) count instead,
when it is at most two days old (`MIO_OBSERVATION_STALE_S`); an expired
snapshot, or one that holds no record, an uncertain record or another
reading, is not replaced by the ledger (`operator_snapshot_present`).
An observation dated in the future (`observed_at_in_future`), evidence dated
in the future (`liveness_evidence_in_future`), an unreadable time or an
unknown clock stay stale or unknown whatever else is fresh. This is option 1
of the re-review, the default until the owner decides otherwise.
`reason_code` names only the reason that ranks first
(a stale snapshot stays `stale` even when it also reports `chain_broken`), so
always read it together with `conditions`. Interface descriptions, filesystem paths, Edge finding
reasons, exception text and any fixed sentence that names a path are shown on
the terminal only; the read model names each one under `withheld` and carries
a code beside it. Knowledge citations in recent incidents carry the shortened
bundle digest, generation, freshness, lookup instant and dataset citation, and
the Knowledge Lite section carries the verified bundle's facts under `bundle`
(shortened digest, signing key ids, claim counts, nearest expiry; `null` when
no trusted bundle was read); each is checked again, and one outside its shape
or naming a path is withheld. Values are checked against their fixed vocabularies, and an
integer beyond JavaScript's exact range is reported as `too_large`. On a LAB HOST the `LAB HOST` marker goes to
stderr so the JSON stays parseable. Like the text, it is a display: it grants,
admits and activates nothing.

The read model also carries five sections the text screen shows as one line each
(U2 `src/azazel_nexus/operator_snapshots.py`, U3 `src/azazel_nexus/noc_status.py`),
so that an account that is not root reads what root would:

| Section | Source | Leaf (`install.sh`) | Stale after |
| --- | --- | --- | --- |
| `knowledge_status` | `az-knowledge-lited` writes `knowledge.status` as codes (`knowledge-status/v1`) after READY and every 30 s; its `freshness` is as of the write (`content_freshness_evaluated_at`) | `run/knowledge-status`, `2750 azknowledge:azazel-operator` | 150 s |
| `mio_status` | `az-mio-entryd` writes the last **recorded** capability reading (`mio-status/v1`) at start, on each recorded change and every 60 s; the route ledger stays `0700` | `run/mio-status`, `2750 azmioentry:azazel-operator` | 300 s |
| `services` | `azazel-units-observe.timer` runs `az-units-observe` (as `azprobe`, `AF_UNIX` only) every 30 s; it reads `LoadState`/`ActiveState`/`SubState` of the packaged services through a read-only reader (`units-status/v1`) | `run/units-status`, `2750 azprobe:azazel-operator` | 120 s |
| `noc` | `azazel-noc-observe.timer` runs `az-noc-observe` (as `aznoc`, `AF_NETLINK AF_UNIX`, `IPAddressDeny=any`) every 60 s: the passive collection of `az-nexus-noc`, projected to counts and codes by ifindex (`noc-status/v1`, [NOC observation](noc-observation.md) §7a) | `run/noc-status`, `2750 aznoc:azazel-operator` | 300 s |
| `storage` | `statvfs` at read time under fixed labels (`state_root`, `audit`, `edge_incidents`, `models`, `mission_data`); no path is reported | none | measured now |

Each snapshot is written by temp file and rename (`0640`), refused by its
reader when it is a symlink, not a regular file, oversized, malformed, outside
its fixed vocabulary, or dated more than 5 s ahead; a refused or absent one is
`unavailable`, an old one `stale`, and `freshness` is its own item. A fresh
snapshot never makes a section `running`: each says what it read
(`knowledge_status`: `available` or `degraded` with Knowledge Lite's reason;
`mio_status`: `recorded` or `unknown`; `services`: `read`, `degraded` /
`unit_failed`, or `unknown` / `unit_state_unread`). A stopped daemon therefore
shows as stale, never as its last answer. The writers' leaves are optional writable paths, so
a node upgraded without re-running `install.sh` still starts each daemon and
shows the section as unavailable. The observer and its timer are installed
but neither enabled nor masked: enable the timers with `systemctl enable --now
azazel-units-observe.timer azazel-noc-observe.timer`. No unit requires or binds to the observer, so
stopping it (or the UI that reads these sections) stops nothing else.
`azazel-nexus setup` lists this as the step `operator-observers` (`needed`
with that command until both wants links exist).
Each writer also puts a byte-identical copy of its snapshot (these four, and
the Edge loop's and auditd's) into its own `run/ui-read/<leaf>`, `2750
<writer>:azui`, for the read-only UI's account, which joins no group
([ADR-0007](adr/0007-ui-read-leaves.md)); `status --snapshot-reader ui`
reads those copies. A copy that cannot be written is logged once and never
fails the daemon. Re-run `install.sh` after an upgrade to create the leaves.
The text screen prints one line per operator snapshot and the operator view
(the admission gates, the catalog, what was not read), the same words and
codes as `--json` (L8).
The same read model is what the read-only operator UI shows
([operator-ui.md](operator-ui.md)): `azazel-ui.socket` listens on
`127.0.0.1:8443` once an operator enables it, and `azazel-nexus ui-login`
(operator group) prints its one-use login code. The UI performs no action.

Select M.I.O. CORE / LITE / FULL with `az-nexus-commission proposal-export --operator LABEL`, then obtain the existing separate full-proposal signature/review; entryd uses CORE until that selection verifies.
The whole sequence, including off-host signing with `tools/operator_sign.py`, is
rehearsed step by step in the [commissioning VM rehearsal](hil-runbooks/commissioning-rehearsal.md).
Installation creates `/etc/azazel/mio-profile/` as root:root 0700 even before
commissioning. It holds only the reviewed detached signature (root-owned 0600),
which a successful `proposal-review --operator LABEL` publishes. The proposal
itself carries raw identity and stays in the encrypted
`/etc/azazel/commissioning/`, from which the unit loads its two fixed files;
never copy a proposal, record, draft or protection key into
`/etc/azazel/mio-profile/`. Installation removes the two proposal copies earlier
releases put there ([M.I.O. runtime](mio-runtime.md), #244). The unit
separately loads only the node declaration and the
operator trust store's public enrollment/revocation document. Keep their existing
protected permissions; no access grant to `azmioentry` is needed. Missing node
or trust credentials, a missing signature, a locked commissioning volume, or
an absent optional Fabric extra yield CORE: every credential source has an
`absent` fallback. Credential
copies are 0400 owned by the service user. Restart entryd using the existing
operational procedure after changing any proposal, node declaration or trust
material: a revocation becomes effective at the next entryd restart. Admission
remains closed regardless of the selected ceiling.

The first pass checks for selected runtime entrypoints. Presence alone cannot
complete installed-file verification. Supply an independently reviewed manifest
and its independently obtained pin to reuse the existing selected-file reader:

```sh
azazel-nexus setup --installed-manifest /media/reviewed/installed.json --manifest-digest "$REVIEWED_MANIFEST_DIGEST"
azazel-nexus setup --operator "$ENROLLED_OPERATOR"
```

The manifest options must be paired. Setup never derives a trusted pin from the
installed node. Selected-file matching proves neither dependency closure nor
runtime admission. Without necessary operator-specific inputs the printed
command opens the existing command's help; use its documented commissioning or
pack workflow. `--operator` reuses signed draft review against current assigned
bindings; setup never remembers a prior review or treats a signature's presence
as approval. Full commissioning evidence and authoritative promotion remain
separate. Host preflight uses the existing inventory's A-1 through A-11 missing
codes; operator HIL decisions and the full interactive campaign preflight remain
with `hil-preflight`.

Knowledge Lite is read at `/var/lib/azazel/knowledge` through the library
`lite_import.status_summary`, as used by `knowledge-lited`. Both setup and
status check the pin, revocation policy and revocation list under
`/var/lib/azazel/lite-trust` (prefixed by `AZAZEL_ROOT` when set). Store-local
anchors cannot grant availability. Status renders state, reason code, generation
and freshness from this shared reader. Setup marks only `available` as done,
`no_bundle` as needed, and other results as blocked. A commissioning draft
without a commissioning record also remains needed.
The separate daemon trust pin at `/var/lib/azazel/lite-trust` is read through
`TrustStore`; a readable pin alone does not establish its commissioning binding
or admitted bundle trust. Fetch commissioning is **presence only**: the runtime
owns consent, registry, catalog, TLS and optional client-identity validation.
Fetched model candidates come from the existing verified model catalog and the
fetch ready directory. Their bytes remain unverified until the separately
printed root import command succeeds; license acknowledgement remains explicit
in that command's workflow. No import runs during setup.

**HG-05 is always `unmeasured`; provider admission stays `blocked`.** Pack
selection, downloaded bytes, imported models, and readable trust do not change
that. Missing or stale Knowledge Lite does not block the deterministic path.
Unit files and `/dev/null` masks are filesystem observations only. Live unit
state is unobserved; the guide prints `systemctl status` for the operator.
Setup never claims enforcement readiness. Edge retains decision and enforcement
authority. See [Debian installation](debian-live-install.md) for installation
prerequisites and [hardware gates](hardware-gates.md) for HG-05.

### Full-node Knowledge Context broker

The optional `azazel-knowledge-contextd.service` is shipped preset disabled
and receives no activation grant in this build. It has no production peer
commissioning loader, network address allowance, or live credential setup.
Do not manually start it or add a systemd drop-in to enable egress. Installing
the package only lays down the disabled unit, account and socket directory.
See [the Knowledge Context consumer boundary](knowledge-context-consumer.md)
for the AF_UNIX process split and the credential, expiry, revocation and
recovery decisions still required before live connection work.

## 1. Resource envelopes

Status: the resource envelopes and field behavior below are a **target contract**.
The read-only setup guide in §0 is implemented.

A resource envelope states how much the host can carry. It never states what
the host is permitted to do to the network. The full rule and its worked
examples are in [capability model](capability-model.md); the summary an
operator needs in the field is below.

The resource profile is selected from **usable RAM in MiB after firmware
reservation** — the figure the host actually reports, not the nominal module
size. That figure is the selector's only input; the measured Core reserve is
applied separately, after selection. Interface count is deliberately absent from
this table — it belongs to the topology profile and is established by
[commissioning](commissioning.md).

| Usable RAM (MiB, after firmware reservation) | Resource profile | Capacity permitted | Typical companion hardware |
| --- | --- | --- | --- |
| `< 7168` | `diagnostic` | inventory and diagnostics only; no policy activation | — |
| `7168` – `15359` | `core` | evidence, rules, packet metadata, enforcement, UI, deterministic voice | 4 cores / 8 threads, 512 GB encrypted SSD |
| `15360` – `31743` | `lite` | `core` capacity plus Suricata, local cognition, Knowledge Lite, and Deception Lite | 4 cores / 8 threads, 512 GB encrypted SSD |
| `>= 31744` | `standard` | `lite` capacity plus concurrent analysis, wider local models, and module links | 6+ cores / 12 threads, 1 TB encrypted SSD |

Each threshold is the nominal size it admits minus a **1024 MiB
firmware-reservation allowance** (8192 − 1024, 16384 − 1024, 32768 − 1024), so
a machine sold as 8, 16, or 32 GB reaches the row named after it. Firmware takes
its cut before Linux sees the memory — UEFI runtime services, ACPI tables,
kernel-reserved regions, and above all integrated-GPU stolen memory, commonly
512 MiB and adjustable in BIOS. A measured 16 GB host reported 16,095 MiB
usable, 289 MiB under 16384.

**In the field:** if a host selects a lower profile than its label suggests,
read `MemTotal` in `/proc/meminfo` and check the BIOS video-memory aperture. A
host reserving more than 1024 MiB — a 2 GiB aperture, for instance — will still
land one row low. Report it with the measurement; it is fixed by measuring real
hardware, not by widening the allowance.

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

### Refusal logs

Each socket daemon (auditd, commissiond, watchdog, Knowledge Lite and the
fetch daemon) writes the requests it refused to its own `refusals.jsonl`:
`/var/lib/azazel/state/<daemon>/refusals.jsonl`, and
`/var/lib/azazel/fetch/partial/refusals.jsonl` for fetch. These files are
diagnostic, not audit evidence: they are not hash-chained, nothing verifies
them, and the audit chain and the M.I.O. route ledger are separate files with
their own limits. They are bounded (#211), so a caller that can reach a socket
cannot fill `/var/lib` through them:

- **Aggregated per caller.** The first refusal of a (caller uid, reason) is
  written as a `runtime.request_refused` line. Further refusals of that key in
  the next 60 s are only counted; when the window ends, one
  `runtime.request_refused_summary` line carries `suppressed` (the count),
  `window_s`, `unrecorded`, and the last suppressed refusal's
  `last_request_fingerprint` (and `last_verb` when it named a declared verb),
  and a new window opens. A continuing flood therefore writes one line a
  minute per key; once it stops, the last count is written within about a
  minute (the serve loop checks between connections). At most 1024 keys are
  tracked; the oldest is summarized and dropped to make room. Inside a window
  only the count and the last fingerprint are kept, so distinct frames
  repeated within one minute are no longer told apart line by line.
- **Other events apart.** Events that are not refusals (Knowledge Lite's
  `knowledge.lookup` lines) go to `events.jsonl` in the same directory, with
  the same rotation. They are not aggregated, and a flood of them never
  rotates a refusal line away.
- **Rotated by size.** Before a line would take `refusals.jsonl` (or
  `events.jsonl`) past 4 MiB it is renamed to `.1`, the previous `.1` to
  `.2`, and the previous `.2` is deleted. A daemon's refusal logs take at most
  12 MiB, and its other events at most another 12 MiB (only Knowledge Lite
  writes any). The newest lines are in the live file; read `.2`, `.1` and
  then the live file for chronological order. Rotated files keep the original
  owner and mode.
- **Never fatal.** A refused request did nothing, so a refusal line that
  cannot be written (a full disk, a removed directory) is counted, not raised;
  the daemon keeps answering. `unrecorded` counts refusals, not lines: a lost
  summary adds every refusal it stood for. `watchdog.status` reports the watchdog's
  counters as `refusal_log`: `written`, `suppressed`, `unrecorded`,
  `rotations` since start. The other daemons have no status answer that
  carries them; a summary line's `unrecorded` shows earlier losses.

The counts are since the daemon started and are not persisted: a restart
begins new windows, so the first refusal of each key after a restart is
written again.

### Audit chain retention (#211)

**Policy (owner decision, 2026-10-21): the audit chain is never deleted; a
low-capacity condition is a warning only.** auditd does not remove, truncate
or rotate away any segment of `/var/lib/azazel/state/audit/`, and nothing else
on the node does either. When space runs short it warns, in `azazel-nexus
status` (the `audit:` line, #231) and in the journal; it does not delete to
make room. This was the default since #224 and is now the policy. Why:

- **Evidence is not lost.** The chain is the record of what the node did and
  was asked to do. A retention window would remove the oldest evidence
  silently, on a schedule nobody reviewed for the case at hand.
- **A writer cannot push evidence out.** With deletion by age or by size, a
  compromised writer that floods the chain (up to its rate and daily
  limits) would force the oldest records out, including the ones that
  record how it was compromised. Without deletion a flood can only fill the
  disk, which is loud (the warning) and bounded per day by the limits in
  [Audit chain limits](integration-loop.md#audit-chain-limits-211-s3).

**Reading the warning.** `audit: ok -- WARNING: capacity warning (<reasons>):
nothing is deleted; ...` is not a failure; the chain verified at auditd's
start; the advisory names this policy ("retention policy: never delete,
warn only"). The reasons:

| Reason | Means | What to do |
| --- | --- | --- |
| `chain_size` | the segments total at least 1 GiB | Nothing urgent. At the normal 10–16 MiB a day this appears after two to three months and then stays on. Check that the free space still covers the yearly growth below, and export a copy if one is due. |
| `filesystem_free` | the ledger's filesystem has under 1 GiB free | Act. Plan more storage or a reinstall (below) before the disk fills. |

The journal carries the same reading once a day while it lasts:
`azazel-auditd: audit chain capacity warning: chain_bytes=... segments=...
filesystem_free_bytes=...; nothing is deleted`. If the filesystem does fill,
appends fail closed: auditd refuses writers rather than claim a record it
did not write, and the intake and explainer latch `storage_failed`.
Knowledge Lite also stops: when its clock floor cannot be written,
`knowledge.status` reads `unavailable` / `state_untrusted` and no reference is
served, static reference included, until space returns
([Knowledge Lite consumer](knowledge-lite-consumer.md#wall-clock-floor)).

**`/var/lib` capacity estimate** (details in
[Audit chain limits](integration-loop.md#audit-chain-limits-211-s3)). The
records that have limits and retention total about 0.9 GiB. The audit chain
is the only record without retention: about 10–16 MiB a day in normal
operation (roughly 4–6 GiB a year), and at most about 250 MiB a day from a
misbehaving explainer under the daily cap. Size `/var/lib` for the years of
service you intend, at about 6 GiB a year plus the 0.9 GiB and headroom.

**Moving old records off the node: copy, never delete.** Removing a segment
from `/var/lib/azazel/state/audit/` breaks the node, so it must not be done,
including after a verified copy:

- auditd verifies the whole chain at every start from sequence 1 and the
  all-zero genesis hash (`SegmentedLedger.verify`,
  `runtime/src/azazel_nexus_runtime/auditd.py`). With the oldest segment gone,
  the first remaining record does not follow sequence 0 and the chain is
  reported broken; with a middle segment gone, the next one does not chain on.
  There is no anchor to start from instead: the checkpoints are unsigned and
  "anchor nothing".
- A broken chain leaves auditd unverified: it refuses every append and
  `audit.bootstrap.observe`, withholds systemd readiness, and status shows
  `audit: FAILED`. auditd is bootstrap-critical: the bootstrap waits for its
  readiness, so the next boot does not complete.
- The bootstrap pre-start check reads the ledger directory from genesis too,
  against the head its signed policy pins, and refuses any file that is not a
  `YYYY-MM-DD.jsonl` segment (`runtime/src/azazel_nexus_runtime/bootstrap_audit.py`).

So the capacity remedies are **more storage** (a larger disk or partition
mounted for `/var/lib`, with the ledger copied over intact to the same path,
owner and modes; a symlink in the path is refused, since the bootstrap check
opens each component with `O_NOFOLLOW`) or a **reinstall**: export
the whole chain as below, then reinstall; a new chain starts from genesis only
through the first-install path, which requires an empty ledger directory. The
exported chain remains verifiable on its own.

**Export procedure.** It uses only the installed venv and coreutils. Do it in
a maintenance window, not during a bootstrap or activation pass. While auditd
is stopped, nothing is appended: the explainer's forwarded records are dropped
and counted in `audit_forward_dropped` (the incident ledger keeps them), and
`azazel-commissiond.service` stops with auditd (`BindsTo=`).

1. Note what is running, then stop auditd:

   ```sh
   systemctl is-active azazel-auditd.service azazel-commissiond.service
   sudo systemctl stop azazel-auditd.service
   ```

2. Verify the chain in place and record its head (the same verifier as the
   [integration-loop rehearsal](hil-runbooks/integration-loop-rehearsal.md)):

   ```sh
   sudo /opt/azazel-nexus/venv/bin/python -I -c 'import sys; from pathlib import Path; from azazel_nexus_runtime.auditd import SegmentedLedger
   ledger = SegmentedLedger(Path(sys.argv[1])); ledger.verify(); seq, head = ledger.head()
   print(sys.argv[1], "verified;", len(ledger.segments()), "segments; head", seq, head)' /var/lib/azazel/state/audit
   ```

   It must print `verified` with a non-zero head. If it raises
   `AuditChainBroken` instead, the chain is evidence of a fault: still copy
   it (steps 3 and 4), but report the break before going further; auditd
   started on it would show `audit: FAILED` and refuse every writer.

3. Copy **every** segment, from the first, to the external medium (mounted
   here at `/mnt/export`). The verifier starts at genesis, so a copy that
   leaves out the oldest segments cannot be verified. Write nothing into the
   ledger directory itself. (The ledger directory is `0700 azaudit`, so the
   globs below are expanded inside `sudo sh -c`, not by your shell.)

   ```sh
   DEST=/mnt/export/azazel-audit-$(hostname)-$(date -u +%Y%m%dT%H%M%SZ)
   sudo install -d -m 0700 "$DEST"
   sudo sh -c 'cp --preserve=mode,timestamps /var/lib/azazel/state/audit/*.jsonl "$1"/' sh "$DEST"
   ```

4. Record the hashes and the head next to the copy, and keep a second copy of
   both off the medium (for example in the operator's notes):

   ```sh
   sudo sh -c 'cd "$1" && sha256sum -- *.jsonl > SHA256SUMS && cat SHA256SUMS' sh "$DEST"
   echo "<sequence> <head hash from step 2>" | sudo tee "$DEST/HEAD"
   ```

5. Verify the copy with the same command as step 2, giving `"$DEST"` instead
   of the ledger directory. Its segment count and head must equal step 2's.
   `SHA256SUMS` and `HEAD` are not `*.jsonl` and are not read as segments.

6. Start auditd again, and commissiond if step 1 showed it active, then check
   that status shows `audit: ok`:

   ```sh
   sudo systemctl start azazel-auditd.service
   sudo systemctl start azazel-commissiond.service   # only if it was active
   azazel-nexus status
   ```

**On the ordinary path (ADR-0008).** When the integrated loop runs, the
chain's writer is `azazel-auditd-loop.service`, not the bootstrap helper
named above. Stop that unit in step 1 instead (commissiond is not running).
It is not started again in the same boot -- a `systemctl start` re-runs the
activation pass, which fails closed while other granted units run -- so step
6 is a reboot. Until then Knowledge Lite imports and trust changes are
refused (`audit_unavailable`) and the explainer's records are dropped and
counted as above.

**Continuity between exports.** Segments are daily and appends never go to a
day before the latest segment, so every segment older than the newest is
closed and never changes. A later export therefore holds the earlier export's
closed segments byte for byte: their lines in the two `SHA256SUMS` files must
match, and in the later copy the record at the earlier `HEAD`'s sequence
carries the earlier `HEAD`'s hash:

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'import sys; from pathlib import Path; from azazel_nexus_runtime.auditd import SegmentedLedger
seq, head = open(sys.argv[2]).read().split(); ledger = SegmentedLedger(Path(sys.argv[1])); ledger.verify()
print("continuous" if any(e.sequence == int(seq) and e.event_hash == head for e in ledger) else "NOT continuous")' "$DEST" /mnt/export/<earlier export>/HEAD
```

A mismatch on a closed segment, or `NOT continuous`, means the node's chain
changed after the earlier export: keep both copies and treat it as an
incident.

Keep every export; none of them replaces the copy on the node.

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
8. To hand an incident to an expert, write the offline handoff package with `sudo azazel-nexus handoff export --incident latest --output-dir DIR` and give the expert the directory and the printed manifest digest. Nothing is uploaded; identifiers are suppressed by default. See [handoff package](handoff-package.md).

## 6. Operator experience

The primary interface is a touch-friendly status-first console. It must make four questions answerable within one screen: What changed? What evidence supports it? What is currently enforced? What needs an operator decision?

The UI groups information by mission state rather than by internal service. Every recommendation shows source, freshness, confidence, and cited evidence. An approval screen restates action scope, duration, policy rule, and rollback path before it can reach the Action Arbiter.

## Activating the integrated loop (observe baseline, #206)

The boot-time `az-activated` pass can grant the five SUPPORTING loop units
(`azazel-edge-intaked`, `azazel-incident-explaind`, `azazel-edge-probed`,
`azazel-mio-entryd`, `azazel-knowledge-lited`), the loop's audit writer
`azazel-auditd-loop` (2026-10-30, [ADR-0008](adr/0008-lite-trust-operations.md);
needed for any Knowledge Lite import or trust change, see below) and, when the
policy, generation and approval name it, the model-free playbook reference
service `azazel-mio-referenced` (proposed 2026-10-28,
[§6](activation-observe-baseline.md#6-owner-decisions); without it a deterministic
handoff reports `reference_service_unavailable` and shows the fixed notice only)
when every input of
[§8 of the design](activation-observe-baseline.md#8-p4-supporting-wired-into-the-pass)
verifies: full commissioning evidence, the declared node and epoch from the
deployment declaration, `/etc/azazel/activation/policy.json`, the high-water
floors and clock, an observe-baseline generation matching the installed unit
files, a signed v2 approval naming the units, and node health. Since P5 the
same pass can also grant `azazel-edge-core.service` when the policy, the
generation and the approval name it
([§8.1](activation-observe-baseline.md#81-p5-edge-core-in-the-pass)):
`generation-publish` then pins the installed Edge package digest and the
digests of the extracted `bin/azazel-edge-core` and
`config/redirect_policy.yaml` (which must equal the manifest's component
digests and the archive's members, and be root-owned, not group or other
writable, and not links), and the pass grants edge-core only when the
package checks pass, the installed package and extracted files are the
pinned ones, and `azazel-edge-probe-preflight.service` wrote a
healthy result in this boot (`running` is not required). Otherwise edge-core
is withheld (`edge_not_ready`) and the SUPPORTING units are still granted;
an installed package other than the signed one, or an extracted binary or
policy rewritten after publication, refuses the whole pass, and needs a new
publish, request and signature. Health is trust in the `azprobe` account:
it can report the signed package healthy, never make another one
launchable.

- A grant **enables** a unit for the next boot and writes
  `/run/azazel-activation/granted/<unit>`; it never starts anything. Each
  governed loop unit has `ConditionPathExists=` on its marker, so at boot a
  unit enabled by an earlier pass starts only if this boot's pass granted it
  again; otherwise systemd skips it (`unmet condition check`). Markers vanish
  at reboot and are recreated by every pass.
- Read the result with `journalctl -b -u azazel-activated.service -o cat`
  (`granted=N`) and the last `activation.inputs_incomplete` entry of
  `/var/lib/azazel/state/activation.jsonl`: `missing_producers` lists only the
  inputs that failed (plus the two not required for this scope, and
  `edge_evidence` unless edge-core was launchable), and
  `observed_inputs.producers` shows `verified`, `failed` or `not_attempted`
  for each. `observed_inputs.edge_evidence` and `edge_package_binding` say
  why edge-core was or was not launchable, and the `activation.unit_withheld`
  entry for it names the failed checks. `observed_inputs.commissioning_storage`
  (`luks_backed` or `not_luks_backed`; absent when it cannot be determined:
  the path or `/sys/dev/block` unreadable, or an anonymous device) says
  whether `/etc/azazel/commissioning` was on LUKS during the pass: a volume left
  locked reads `not_luks_backed`. It is diagnostic only and decides nothing.
  The entry contains no identity, digest, device or path.
- **Requiring a synchronized clock (optional, #251 M-1).** By default the
  pass trusts the OS clock down to the high-water floor, so a node without an
  RTC, or one whose clock is not synchronized yet, can accept an approval
  that has already expired in real time
  ([design §10.2](activation-observe-baseline.md#102-residual-risks)). To
  refuse that instead, put `"require_clock_synchronized":true` in
  `policy.json` (canonical form: sorted keys, so between `"operators"` and
  `"resource_floors"`). The pass's `trusted_clock` then also requires
  systemd-timesyncd's marker `/run/systemd/timesync/synchronized` (a
  synchronization happened in this boot); without it `trusted_clock` is
  `failed`, `observed_inputs.clock_synchronization` is `not_proven`, and
  nothing is granted. The pass reads the marker once and never waits itself.
  **Enable `systemd-time-wait-sync.service` on such a node**
  (`sudo systemctl enable systemd-time-wait-sync.service`): the controller is
  `After=time-sync.target`, so the service holds it until timesyncd has
  synchronized. Without it the pass races the first synchronization (on the
  VM about 33 s after boot, while the controller runs about 10 s after boot
  when no LUKS passphrase holds it back) and is likely to refuse that boot
  with `not_proven`. With it enabled, a node that cannot synchronize
  (offline) makes the controller wait **indefinitely**: its start timeout
  does not count an ordering wait. Nothing is granted while it waits
  (fail-closed), but the loop does not come up until the clock synchronizes.
  Without it, an offline node refuses every boot. Only timesyncd writes the
  marker, so a node that keeps time with chrony or another daemon refuses
  every boot either way. Absent or `false` keeps the default, and needs no
  wait-sync service. The field is part of
  the policy: changing it changes `policy_digest`, so the installed approval
  no longer verifies and a new request, signature and install are needed, as
  for any policy change. A package from before this field refuses a policy
  that carries it.
- To withdraw: remove `approval.json`/`approval.sig`, raise the declared
  `security_epoch`, revoke the operator, or let the approval expire. The next
  boot's pass then grants nothing, writes no marker, and the units stay
  masked and unstarted.
- The inputs come from `az-activation generation-publish`, `request` and
  `install` (below) and the off-host signer. The reboot sequence is not yet
  confirmed on a VM (P6; procedure in the
  [activation rehearsal](hil-runbooks/activation-rehearsal.md)). Until then the
  [integrated loop rehearsal](hil-runbooks/integration-loop-rehearsal.md)
  still uses its rehearsal-only start.

### Knowledge Lite trust operations while the loop runs (ADR-0008)

Every Knowledge Lite change is recorded in az-auditd **before** it happens,
and is refused when it cannot be. On the ordinary path the writer is
`azazel-auditd-loop.service` ([ADR-0008](adr/0008-lite-trust-operations.md)),
a loop unit like the others: to use any of the commands below, name it,
with `azazel-knowledge-lited.service`, in `policy.json`, publish the
generation, request and install the signed approval; the next boot's pass
grants both. The bootstrap helper `azazel-auditd.service` and
`azazel-commissiond.service` stay outside the loop. Each command runs as root
on a local terminal; the inputs are fixed leaves that root installs
`root:azcommission 0640` in `/etc/azazel/commissioning/`; no command takes a
path, key or flag.

| task | input leaf | command (`sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus_runtime.commission_cli ...`) |
| --- | --- | --- |
| first registration of the trust root | `lite-enrollment.json` | `trust-enroll` |
| import a bundle | the store inbox (`knowledge/inbox/`) | `knowledge-import --entry <sha256 hex>` |
| rotate or replace keys, with their anchor | `repin-anchor.json` | `trust-repin --reason {rotation,recovery,compromise}` |
| accept a signed revocation list | `lite-revocations.signed` | `knowledge-revocation-accept` |

- **Enrollment** binds the keys, roles, threshold (an integer from 1 to the
  keys that can meet it), epoch, export policies and the revocation authority
  to this node's verified commissioning, shows them, and asks for fresh
  confirmation words. The request format and every refusal are in
  [knowledge-lite-consumer §11](knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available).
- **Repin** asks for fresh words after showing the anchor file's fingerprint;
  with `anchors` in the document the key ids and threshold change with the
  keys ([trust repin](trust-repin.md#replacing-the-anchor-with-the-keys)).
- **Revocation acceptance** asks nothing: the signed list is the authority
  and only withdraws ([revocation](revocation.md#accepting-a-list-on-a-node)).
- Enrollment, repin and revocation acceptance run in a child process that has
  become `azcommission` (the commissioning daemon's account and groups); they
  hold the commissioning lock, so a second one at the same time is refused
  (`busy`), never queued.
- Each prints one JSON object (or, for a repin, `Trust anchors replaced;
  generation N.`) and exits 0 only when the change was made, is durable,
  **and** its records reached auditd. `audit_complete: false` with a change
  made means the outcome record is missing: the change stands; the request
  record is in the chain.
- **In force but not fully recorded.** A failure after the commit point is
  read back and reported as such, never as a refusal: enrollment
  `durability: unsynced`, repin `state: pointer_unsynced` or
  `ledger_incomplete` -- the change is in force; **do not repeat it**.
  `enrolled: null` / `state: unknown` means the trust root could not be read
  back: inspect it before anything else. These cases exit 1.

**When auditd is not running.** `knowledge-import` prints `outcome: refused`,
`refused: audit_unavailable`; `trust-enroll` and `knowledge-revocation-accept`
print `code: audit_unavailable`; `trust-repin` prints `Trust replacement
refused or interrupted.` Nothing in the store or the trust root has changed.
`azazel-auditd-loop.service` is not restarted in the same boot: a
`systemctl start` re-runs the activation pass, which then fails closed while
other granted units run
([§10.2 M-5](activation-observe-baseline.md#102-residual-risks)). Check the
chain (`audit.verify`, or `azazel-nexus status`), fix the cause (capacity,
a broken chain), and reboot; the next pass grants it again.

**When a command was interrupted.** An enrollment stopped before it wrote
`trust.json` leaves files no reader trusts (status `trust_unreadable`): run
the same `trust-enroll` again; it replaces exactly that residue. A repin or
revocation acceptance either moved the trust pointer or the list, or did
not; read `azazel-nexus status` (Knowledge Lite reason), the chain's last
`knowledge.lite.trust_*` / `knowledge.lite.revocation_*` record and, for a
repin, `/var/lib/azazel/state/commission/commission.jsonl`, then repeat the
command if nothing was promoted. An import stopped mid-way is the daemon's
own recovery ([consumer §7](knowledge-lite-consumer.md)).

## Observe-only Edge Core unit

`azazel-edge-core.service` is shipped masked and preset-disabled, runs as
`azedge`, and belongs to the existing `EDGE_BASELINE` activation tier.
`azazel-edge-probed.service` remains a supporting one-shot observer; it reads
the payload's running state and never starts it. See
[Edge package verification](edge-package-verification.md#the-edge-core-payload-unit-i0)
for fixed paths, posture, deployment-specific Suricata read permissions, and
the unchanged first-start readiness limitation. Intake is implemented in I1.

`azazel-edge-intaked.service` is the supporting receive-only Edge findings
listener, running as `azintake`, masked and preset-disabled. It writes bounded
private evidence under `/var/lib/azazel/edge-intake`, a reader-group incident
chain under `/var/lib/azazel/edge-incidents`,
and operator-readable liveness under `run/edge-intake-status/status.json`.

`azazel-incident-explaind.service` is the supporting local incident explainer,
running as `azexplain`, masked and preset-disabled. It reads the incident
chains as `azincident-read`, asks M.I.O. and Knowledge over their
explainer-only local listeners (`mio-advise`, `knowledge-read`), forwards
incident records to auditd's `audit-submit` listener, and stores bounded explanations/cursor state privately under
`/var/lib/azazel/incident-explain`. Liveness is operator-readable at
`/var/lib/azazel/run/incident-explain-status/status.json`. It grants no Edge
control or enforcement authority; optional advisory failures never stop Edge.
See [integration loop I2](integration-loop.md#i2--explanation-explain--implemented)
for privacy, deadlines, rate/retention limits and fixed refusal codes.

**Upgrading to the explainer-only listeners (#213 O1).** The explainer no
longer holds `azazel-operator`. auditd and M.I.O. entry each bind a second
listener for it, in the `run/audit-submit` (`azaudit-submit`) and
`run/mio-advise` (`azmio-advise`) leaves. `azazel-knowledge-lited` and
`azazel-commissiond` also carry `azaudit-submit` (as do root's trust
transactions, narrowed to `azcommission`, ADR-0008), and auditd lets each
record only its own Knowledge Lite import, revocation or trust events (P4; see
[integration loop I2](integration-loop.md#i2--explanation-explain--implemented)). The installer creates the groups,
the leaves and the units' new `ReadWritePaths`. An upgraded runtime on a node
where install.sh was not re-run refuses to start auditd and
`azazel-mio-entryd` with `SocketMisconfigured` naming the missing group or
leaf, before it binds anything or reports READY. To upgrade:

1. Re-run `packaging/install.sh` (idempotent; existing accounts, groups and
   data are kept).
2. `systemctl daemon-reload`.
3. Restart `azazel-auditd.service` and `azazel-mio-entryd.service`, then
   `azazel-incident-explaind.service`.

Operators' sockets, leaves and group membership do not change. Nobody is
added to the two new groups; only the explainer unit carries them.

**Upgrading to the audit status snapshot (#211).** auditd writes its capacity
snapshot into a new leaf, `run/audit-status` (`2750 azaudit:azazel-operator`),
granted by a new optional `ReadWritePaths=-/var/lib/azazel/run/audit-status`
in `azazel-auditd.service`. Unlike the listeners above, a missing leaf does
not stop auditd, which is bootstrap-critical: the `-` lets systemd start the
unit without the directory, and auditd logs `azazel-auditd: cannot write
.../audit-status/status.json` once and serves without the snapshot, and
status shows `audit: unknown`. (The same `unknown` appears for an operator
not in `azazel-operator`, who cannot read the leaf.) To enable it, re-run `packaging/install.sh`,
`systemctl daemon-reload`, and restart `azazel-auditd.service`.

For `chain_broken`, the explainer latches closed across polls, days and restarts.
Status shows `inspect_incident_chain_then_remove_cursor_and_restart`. Stop
`azazel-incident-explaind.service` before recovery. Inspect the incident segment
named by `/var/lib/azazel/incident-explain/cursor.json`, its byte offset and
sequence/hash, the adjacent retained segments, and `retained-boundary.json`.
Check for missing segments, truncation, changed hashes and an incomplete final
line; compare against intake's own status and storage health. Preserve suspect
files for investigation and restore a valid chain or validated retention boundary
before resetting the reader. Do not edit ledger lines to bypass verification.

After resolving the cause, remove only
`/var/lib/azazel/incident-explain/cursor.json` and restart the explainer. This
clears its latch, pending work, remembered severities and counters, but preserves
explanation records. With a missing cursor it verifies retained history and
seeds at the current end; it does not replay the previous 14 days. If integrity
is still broken it latches again. First installation uses the same seeding rule.
A checkpoint from the earlier I2 format containing full pending transitions is
refused at startup; inspect it and use this reset procedure after upgrading.

**No new explanations for about a minute after a restart.** When the
explainer restarts with a checkpoint (`cursor.json` present), it treats the
rolling six-per-minute budget as fully used and waits 60 seconds from startup
before the next explanation attempt, severe incidents included; a restart
cannot reset that budget. During the wait the explainer's `status.json`
(`/var/lib/azazel/run/incident-explain-status/status.json`, or
`azazel-nexus status --json`; the text `status` omits `pending` and
`last_explained_at`) shows `pending` rising (or unchanged) and
`last_explained_at` not advancing, and this is expected. A handoff exported
meanwhile reports the incident's AI assessment as `explanation_pending`. Only explaining stops: ingest, checkpoints,
the recent list, close handling, audit forwarding and status writes continue;
recorded explanations are not altered by the restart, and recent rows keep
updating from new transitions. A first start or a start after the cursor reset
above has no checkpoint and does not wait. If `pending` stays above 0 and
`last_explained_at` does not advance well beyond a minute, the cause is
something else: check that status's `written_at` is still fresh (the unit's
state and journal), `storage_failed`, and `refused` (the text `status` lists only the top four) for
`explanation_segment_full` or `stale_skipped`. (An unavailable M.I.O. or a
broken chain does not produce this picture: the explainer still records an
explanation without content, and a broken chain shows as `chain_broken` with
the recovery hint above.)
Status carries no restart time or remaining wait, so none is shown.

**Rolling the explainer back past #392.** From #392 the checkpoint's pending
entries carry Edge evidence pointers (digests and receive instants), and
explanation records carry `evidence` and `mio.provenance`. The release before
it refuses both: its explainer stops at start with `cursor_refused`, and its
readers refuse the new records. There is no backward compatibility, so do not
use the cursor reset above for a rollback: it would drop every queued
explanation. Instead, with the new release still installed:

1. Drain. While status (`/var/lib/azazel/run/incident-explain-status/status.json`)
   shows `pending` above 0, let the explainer run (it takes at most six entries
   a minute). Once it shows `0`, stop `azazel-incident-explaind.service` and
   decide on the stopped checkpoint itself, not on status (new incidents can
   be queued between the status you read and the stop):

   ```sh
   sudo systemctl stop azazel-incident-explaind.service
   sudo /opt/azazel-nexus/venv/bin/python -I -c 'from azazel_nexus_runtime.incident_explaind import pending_pointers as n; print(n("/var/lib/azazel/incident-explain/cursor.json"))'
   ```

   It prints how many pending entries still carry pointers, and changes
   nothing. `0`: the earlier release reads the checkpoint unchanged. (Status
   is also rewritten at shutdown after the last checkpoint, but the
   checkpoint is what the earlier release reads.) Otherwise start the service
   again and repeat, or convert (step 2).
2. If it does not drain (new incidents keep arriving, or `storage_failed`),
   convert the stopped checkpoint. This keeps every queued entry and removes
   only its pointers, keeps the original as `cursor.json.pre-rollback` with the
   same owner and mode, and writes nothing if the checkpoint is refused:

   ```sh
   sudo systemctl stop azazel-incident-explaind.service
   sudo /opt/azazel-nexus/venv/bin/python -I -c 'from azazel_nexus_runtime.incident_explaind import checkpoint_for_previous_release as c; print(c("/var/lib/azazel/incident-explain/cursor.json"))'
   ```

   It prints how many entries lost their pointers. Those incidents are then
   explained by the earlier release without evidence references. It never
   replaces an existing `cursor.json.pre-rollback`: a run interrupted after
   saving the backup goes on (the backup holds this very checkpoint), and any
   other backup refuses the run with `rollback_backup_exists`. Move an old
   backup aside yourself, after checking it, before converting again.
3. Install the earlier release and start the explainer. Explanation records
   written by the new release stay in the ledger. The earlier release's
   explainer only appends to it, but its handoff package skips each such
   record and reports the ledger as `record_refused`; roll forward to read
   them again.

**Rolling the explainer back past the Full-node trace (to `74a6189`).** Once an
observation rule is in place, checkpoints and recent rows carry a row-level
`full_node_trace` and a nested `query_origin`; the release at `74a6189` (the one
before this change) refuses both: its explainer stops at start with
`cursor_refused` and its readers read the snapshot as `None`. The target of
this rollback is `74a6189`; roll back only to it. With the new release still
installed:

1. `sudo systemctl stop azazel-incident-explaind.service`
2. Convert the stopped checkpoint (a function separate from the #392 conversion
   above; it changes nothing else, and pending entries are untouched):

   ```sh
   sudo /opt/azazel-nexus/venv/bin/python -I -c 'from azazel_nexus_runtime.incident_explaind import checkpoint_for_release_before_full_node_trace as c; print(c("/var/lib/azazel/incident-explain/cursor.json"))'
   ```

   It prints how many recent rows lost either field. The original is kept as
   `cursor.json.pre-rollback` (owner and mode kept). An existing backup is never
   replaced, and this conversion (unlike the one above) does not resume: any
   existing `cursor.json.pre-rollback`, identical or not, refuses the run with
   `rollback_backup_exists`; move it aside yourself. Nothing is written if the checkpoint is refused.
3. Install `74a6189` and start the explainer. It rewrites `recent.json` and
   the ui copy from the converted checkpoint after it starts; until then the
   earlier ui reads the snapshot as `None`.

The ledger keeps the original records; the conversion leaves no record of
itself. The earlier release cannot read the new records either (as for #392),
so while it runs the Full-node facts of those incidents can be read neither in
the ui nor with the CLI. Rolling forward again reads them as before. When rolling forward, install
the new readers and restart the resident ones before putting the observation
rule file back (order in [Knowledge Context consumer](knowledge-context-consumer.md),
*Deployment order and rollback*).

Normal retention overtaking a cursor reports `cursor_overtaken` and resumes from
the oldest retained segment without operator reset. Outage replay drops `opened`
transitions older than one hour (`stale_skipped`). A valid segment-full marker
reports `incident_segment_full`; a torn final line reports
`ledger_tail_incomplete` and waits for completion without advancing its cursor.
When the intake instead cuts a tail torn by a power cut at its next start
(`ledger_recovered` on the status intake line), the explainer reads on past
the `edge.incident.ledger_recovered` record; see
[the torn tail recovery](integration-loop.md).
These counters describe missing context, not Edge control or enforcement.

See [integration loop I1](integration-loop.md#i1--intake-detect--understand).


### Reading the integrated loop (I3)

`azazel-nexus status` now includes `edge loop:` after the six-axis integration
view. Intake/explainer snapshots degrade independently to unavailable or stale
(over 30 seconds); a quiet explainer's unchanged snapshot may become stale.
Use the existing Edge probe to assess the payload itself. Status also shows
accepted/explained counts, refusal counters, storage failure, last advisory
availability, `audit_forward_dropped` (delivery gave up or queue full) and
`audit_forward_refused` (auditd refused the record). A chain break shows
`inspect_incident_chain_then_remove_cursor_and_restart`; follow the recovery
procedure above before removing any cursor.

The intake's part ends with one line for the Deception Lite decoy
(#196 P2). With the decoy socket open it reads
`decoy (Deception Lite; Nexus's own observation, not Edge's; not hardware evidence): accepted 3; last accepted 12s ago; refused 5 (DECOY_SHAPE=4, decoy_rate_limited=1)`;
otherwise `decoy (Deception Lite): not listening (decoy socket not open); refused 0`
(`decoy_listener_unavailable` among the refusals says why it is closed).
These are interactions with Nexus's own decoy, not something Edge observed, and
a count in status is not hardware evidence. Edge's `accepted`/`processed`
never include them, and the decoy's refusal codes (`DECOY_*`, `decoy_*`) are
shown on this line, not in the intake's `refusals:`. Only counts, the last
time and refusal counts per fixed code are shown; the intake's bounded refusal
log (`/var/lib/azazel/edge-intake/decoy-refusals.jsonl`) keeps the uid and code
of each, nothing more. No address or payload is ever shown. Until the decoy daemon
ships (a later phase of #196), nothing sends an interaction, so the count stays 0.

### Deception Lite decoy network (#196)

The decoy's network is built by two one-shot units, never granted in this
build: `azazel-decoy-nsd.service` creates the namespace
`/run/netns/azazel-decoy` and the veth pair (its unit file runs six fixed
`/usr/bin/ip` commands and no other program), `azazel-decoy-netd.service` the
bridge `az-decoy0` and the `inet azazel_decoy` nftables table, which drops
everything to and from the decoy until approved prefixes exist
([prerequisites §13](deception-redirect-prerequisites.md#13-the-namespace-units-and-the-helpers-bodies-as-implemented)).

**Prerequisite: iproute2.** The namespace unit runs `/usr/bin/ip` from the
Debian package `iproute2` itself; Nexus does not ship or stage it. With the
service manager the installer refuses when `/usr/bin/ip` is missing.

**A namespace unit start that fails with `File exists`.** The names
`azazel-decoy` (the namespace) and `az-decoy*` (the links) are reserved for
the decoy. If the unit's start fails at `ip netns add` or `ip link add` with
`File exists`, find out what created an object of that name (an earlier
crashed run, or something else using a reserved name) before starting it
again: the unit's roll-back (`ExecStopPost=`) has already removed it.

**Existing objects are never overwritten.** The helper refuses to start, and
changes nothing, while a bridge `az-decoy0` or a table `inet azazel_decoy`
already exists, and its ruleset is loaded with `create table`, which never
replaces an existing table of that name. Remove a stale one by hand after a
crash. On stop it removes the table only after the bridge and the host end
are gone; if that fails, the table stays and the stop is reported as failed.
Each normal start logs one expected `ip`/`nft` "does not exist" error per
check, after a line saying so.

**`/run/netns`** is created `0755 root root` by the package's tmpfiles rule,
so that the decoy's account can reach its namespace handle; do not tighten it.

**Fallback tunnel devices.** If the host loads tunnel modules (`sit`, `ipip`,
`ip_gre`, `ip6_tunnel`, ...), the kernel creates their fallback devices
(`sit0`, `tunl0`, ...) in every new network namespace, and the decoy refuses
to start in a namespace that holds them. Such a host sets, persistently,

```
# /etc/sysctl.d/60-azazel-decoy.conf
net.core.fb_tunnels_only_for_init_net = 2
```

so that fallback devices are created only in the host's namespace. The
namespace unit never changes this value and never deletes such devices; a
Debian 13 host with no tunnel module loaded needs nothing (its new namespace
holds `lo` alone).

**The isolation record.** After it has built the host side, the helper lists
the table and the host's links and writes this boot's record of fixed results
to `/run/azazel-decoy-isolation/isolation.json` (its runtime directory, root
`0755`; the file root `0644`); its journal shows one line `isolation check:
<check> pass|fail|unreadable, ...`. If any check does not pass, it removes
what it built and fails, and the decoy is not started. The decoy refuses to
listen without a record from this boot with every check passed; the record
holds no address. Do not write or edit it by hand: a hand-made record is
refused unless it is byte for byte what the helper writes, and the directory
goes away when the helper stops
([prerequisites §14](deception-redirect-prerequisites.md#14-isolation-evidence)).
The table is compared as nftables' JSON (`nft -j`) against what the helper
rendered from its scope; the record carries the scope's digest, never a
prefix or an interface name. A `nft_table` failure after an nftables upgrade
can mean the JSON form changed, not that the rules did; the decoy stays
refused until the expected listing is updated in a release. The helper's
unit loads the scope file `/run/azazel-activation/decoy-scope.json` as the
credential `decoy-scope`; if the file is missing the unit fails to start.
No activation pass writes that file yet, so the helper is not started by
a grant in this build.

The check reads only the decoy's own table, `inet azazel_decoy`. NAT,
`mark`, `notrack` or any other rule in another table is not seen, and the
decoy table's drops (the ingress drop K2 and the reply rule R3) do nothing
against another table's rewriting, nor does the watch below. Do not add
rules that touch the decoy's traffic in other tables; the pass is to
withhold the tier while a ruleset-managing service is enabled (G6).

An ingress interface is for the decoy alone (the `deception_bridge` role):
the decoy table drops everything received on an ingress that does not go to
`az-decoy0`, including forwarding from one ingress interface to another.

**A firewall reload removes the decoy table.** Reloading `nftables.service`,
or anything else that runs `nft flush ruleset` (Debian's default
`/etc/nftables.conf` begins with it, and the unit's stop runs it), removes
`inet azazel_decoy` together with every other table. The same holds for a
`firewalld` reload and for an Edge enforce posture that replaces the
ruleset. At boot this does not happen: the helper is ordered after
`nftables.service`, `firewalld.service` and `netfilter-persistent.service`
(`After=` only, so a host without them is unaffected), and their load runs
before the table is built. Later it still does, and the ordering does not
stop or restart the helper.

**The watch** (#196 G2,
[grant design §6.1](deception-exposure-grant.md#61-detection-and-stop)) is
what notices. The decoy pulls in two more units, which are installed with
the package and are never masked, enabled or granted (they have no
`[Install]` section and no grant marker):

- `azazel-decoy-verify.service` runs `az-decoy-netd verify`, the helper's
  executable with one more word, once before the decoy starts and then every
  10 s (`azazel-decoy-verify.timer`). It lists the table and the host's links
  and compares them with the scope exactly as the helper's isolation check
  does, and it re-reads the reachability conditions
  ([reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired),
  R4): forwarding on the ingress interfaces and off everywhere else but
  `az-decoy0` (IPv6 off everywhere), `proxy_arp` off, no IPv4 routing rule
  before the main table but the local rule and each ingress's two K1 rules,
  and no route of `main` inside `10.255.196.0/24` but the bridge's own /30.
  It writes nothing; the isolation record stays the helper's. Its journal
  line is fixed names only, for example `az-decoy-netd verify: departed:
  nft_table unreadable, approved_v4_matches unreadable, ingress_matches
  unreadable` or `... departed: forwarding_other_on`; it never shows an
  interface name, a prefix or an address.
- When it fails (a departure, a table that is gone, a read it cannot make,
  or a scope it refuses), its `OnFailure=` starts
  `azazel-decoy-trip.target`, whose only content is `Conflicts=` on
  `azazel-decoy-nsd.service`, `azazel-decoy-netd.service` and
  `azazel-decoyd.service`: systemd stops the decoy, the helper and the
  namespace unit, in that order (the reverse of their `After=`), each by
  name, so the trip does not depend on the `Requires=` chain. Nothing in
  Nexus calls the service manager for this. Starting any of the three again
  stops the trip target.

The window between a flush and the stop is at most one period (10 s) plus
one verify run. It has been rehearsed on a Debian 13 VM (G4, grant §11: a
`nft delete table inet azazel_decoy` tripped the three units in about 2 s,
and `systemctl start nftables.service`, whose default `/etc/nftables.conf`
flushes the ruleset, tripped them in about 6–7 s; a mechanism check, not
hardware evidence) and not yet observed on the real host; a firewall
reload as the trigger was not part of those runs. The trip
leaves the units stopped, and `azazel-decoy-netd.service` ends
**`failed`** after the trip (seen on the VM). The cause is inferred, not
read from the journal in that run: its `ExecStop=` (`az-decoy-netd stop`)
fails at `nft delete table` because the table is already gone. That is expected, and it is a closed state:
the decoy is down, and the next start of the namespace unit brings the
helper up again with no `reset-failed` needed (seen on the VM). Do not
treat the helper's `failed` as the cause; the verify's journal holds it. Find the cause
with `journalctl -u azazel-decoy-verify.service`, fix it (the firewall that
reloaded, the forwarding or routing configuration of
[reachability §8](deception-exposure-reachability.md#8-the-operators-part-outline)),
and start the decoy again: starting the namespace unit stops the trip target,
so a later failure trips again. Do not load the table again by hand.

**A masked exposure unit that is still running** (G4, grant §6.3 and §11; a
VM observation, not hardware evidence). The controller masks an exposure
unit it finds running without a grant, and does **not** stop it. After the
next `daemon-reload` that unit's definition is `/dev/null`: its
`Requires=`, `After=`, `ExecStop=` and `ExecStopPost=` are gone. On the VM a
trip in that state stopped only the namespace unit, left its namespace and
veth pair behind, and left the helper and the decoy running for more than
20 s. The trip unit now names all three, so the job engine stops each of
them directly (VM-checked: all three stopped, and two veth links and the
namespace were left); it cannot run the clean-up steps that are no longer
defined, and it still waits for a verify to fail. If `systemctl status`
shows one of the three as `masked` and `active`, stop it by hand
(`sudo systemctl stop azazel-decoyd.service azazel-decoy-netd.service
azazel-decoy-nsd.service`), then check for leftovers (`ip netns list`,
`ip link show az-decoy-host0`, `nft list table inet azazel_decoy`) and
report them. How this is closed without relying on the trip is a G6
decision.

**Rehearsing on a VM** (grant §11). A rehearsal places the grant markers by
hand, uses a VM-only scope file, and runs copies of the units without
`Requires=`/`After=azazel-activated.service`; the pass grants nothing.
**Make every copy, probe copies included, from a copy with
`Requires=azazel-activated.service` already removed**, never from the
packaged file: in G4 a probe copy that kept it started the controller,
which masked the running rehearsal units (without stopping them) and
failed with `activation.rollback_failed`. Such
a run checks the mechanism only: never record it as `HG-06`, `HG-09` or
`HG-10` evidence, and never do it on a node in service. Afterwards remove
the copies, the markers and the scope file, and `systemctl daemon-reload`.
A helper left `failed` by a trip (above) is part of the expected result,
not a fault of the rehearsal.

Starting `azazel-decoy-trip.target` by hand is a stop button for the three
units and nothing more. Do not mask, edit or add a drop-in to any of the
three watch units: a masked trip target would let a failed verify stop
nothing. To check the table yourself:

```
sudo nft list table inet azazel_decoy
sudo systemctl list-timers azazel-decoy-verify.timer
```

**AppArmor profiles** (#196 G3, G2). Each of the three units, and the
verify unit, names its own profile with `AppArmorProfile=`
(`azazel-decoy-nsd`, `azazel-decoy-netd`, `azazel-decoy-verify`,
`azazel-decoyd`), without `-`, and carries `AssertSecurity=apparmor`. The
verify unit's profile is the helper's without its one writable place, plus
read access to `forwarding` and `proxy_arp` under `/proc/sys/net`. The
namespace unit's profile confines `ip` itself, which systemd starts under it;
it has no child profile (the G4 follow-up, grant design §7). All four carry
`flags=(attach_disconnected)`, so that a path under systemd's sandbox (such
as the verify unit's `/dev/null`) is named rather than refused; the denies
still apply to the name. The namespace unit's also sets
`attach_disconnected.path=/.azazel-nsfs/`: the namespace `ip netns
add` binds onto its handle is such a path, and the prefix keeps it apart
from the host's real `/` (grant design §7). The profiles' `deny` rules for
the D-Bus and systemd sockets are defence in depth only: on Debian 13's
kernel a connect to those sockets was not refused by them (G4 rehearsal),
and keeping the units from the service manager is, by design, their
sandbox's part (`RestrictAddressFamilies=` and `InaccessiblePaths=`;
observed refused on the VM under probe copies of the decoy and the verify
unit, not yet for the namespace unit and the helper). The decoy's unit also has
`ProtectProc=invisible`, because its profile's `/proc/<pid>/net/dev` rule
cannot be `owner` and would otherwise match the host's processes. Do not remove those
unit lines or add a drop-in that changes them. With
AppArmor enabled, a start without that profile loaded fails; with AppArmor
disabled systemd ignores `AppArmorProfile=` and the assertion fails the
start instead, so none of them runs unconfined. The installer needs the
Debian package `apparmor` (not `apparmor-utils`), compiles the four
profiles before it writes anything, warns when the kernel has AppArmor
disabled, and places them in `/etc/apparmor.d/`; it does not load them. It
also refuses to install when the decoy wrappers' (`az-decoy-netd`,
`az-decoyd`; the namespace unit has none) interpreter is not
`/usr/bin/python3.13` or their code lies outside `/usr/lib/python3.13` and
`/opt/azazel-nexus/venv` (the only places the profiles let them read):
install the runtime into that venv. The package's `apparmor.service` loads them at the next boot. Do not
edit them, switch them to complain mode or remove them: the activation pass
is to withhold the tier unless AppArmor is enabled and all of them are in
enforce mode. That check exists, but in this build it is not reached: the
tier is withheld as `isolation_evidence_absent` on every pass whatever the
profiles' state, so nothing is granted by them
([grant design §7](deception-exposure-grant.md#7-lsm-apparmor-as-a-gate-f6)).
To see their state, as root:

```
sudo grep '^azazel-decoy' /sys/kernel/security/apparmor/profiles
```

**The compiled-policy record** (#196 G6 preparation K; implemented, record
only: the reader is G6's). With the service manager, after placing the four
profiles, the installer compiles each placed file with `apparmor_parser -Q
-o` into a private temporary file (nothing is loaded) and writes the
SHA-256 of each output to `/etc/azazel/activation/apparmor-compiled.json`
(root, `0644`; contract `azazel-nexus/apparmor-compiled/v1`, the four
profile names to 64 lowercase hex digits, and the parser's version line
for diagnosis, normalized to printable ASCII and never a reason to refuse).
A profile that does not compile there refuses the install and shows the
parser's first error lines; a failure before the record is renamed into
place leaves an earlier record as it was, and a failed directory sync
after the rename is only a warning. A `DESTDIR` or
`--without-service-manager` run writes none. **Checked on the VM** (Debian
13, parser 4.1.0; a mechanism check, not hardware evidence): the four
values this installer recorded equalled the kernel's `raw_sha256` once
`apparmor.service` loaded the profiles. Nothing reads the record in this
build: G6's `generation-publish` is to copy it into the generation the
operator signs. Do not edit it; install again to refresh it. To compare it
with what the kernel holds, as root:

```
sudo cat /etc/azazel/activation/apparmor-compiled.json
sudo cat /sys/kernel/security/apparmor/policy/profiles/azazel-decoyd.*/raw_sha256
```

**Removing a stale decoy child profile.** Before the G4 follow-up the
namespace profile had a child, `azazel-decoy-nsd//ip`. Replacing a parent
profile (`apparmor_parser -r`, or the installer placing a new file and
`apparmor.service` loading it) does **not** remove a child the kernel
already holds: on the VM (Debian 13, AppArmor 4.1; a mechanism check, not
hardware evidence) `azazel-decoy-nsd//ip (complain)` stayed listed after the
parent was replaced. The pass is to withhold the tier while any
`azazel-decoy…//…` line is listed (`lsm_profile_child_present`), and the
installer says so when it sees one (it loads and removes nothing). Clear it
in one of two ways:

- **Reboot.** `apparmor.service` loads `/etc/apparmor.d` into an empty
  kernel policy at boot, and that file has no child. *Inferred*: not
  checked on the VM.
- **Without a reboot** (checked on the VM): with the units that use the
  parent stopped, remove the parent from the kernel, then load it again from
  its file, as root. For the namespace profile:

  ```
  sudo systemctl stop azazel-decoyd.service azazel-decoy-netd.service azazel-decoy-nsd.service
  sudo apparmor_parser -R /etc/apparmor.d/azazel-decoy-nsd
  sudo apparmor_parser -r -W /etc/apparmor.d/azazel-decoy-nsd
  sudo grep '^azazel-decoy' /sys/kernel/security/apparmor/profiles
  ```

  The last command must list the four profiles in `(enforce)` and no line
  with `//`. For another parent, use its name and stop the unit that names
  it. Do not use `aa-remove-unknown`: it removes every loaded profile that
  has no file in `/etc/apparmor.d`, other tools' included, and is not
  needed here.

**Removing what a failed start left behind.** The namespace unit removes
its objects itself: its `ExecStopPost=` lines (`ip link delete
az-decoy-host0`, then `ip netns delete azazel-decoy`) run after every stop
and after a start that failed or timed out, including one that failed because
an `azazel-decoy` namespace was already there, which it then removes; that
start still fails, and the next one starts clean. The helper undoes its own
steps when a start fails; if it was killed before it could (for example
`SIGKILL` at `TimeoutStartSec=`), systemd runs no `ExecStop=` after a failed
one-shot start, and its objects stay (see "Existing objects are never
overwritten" above). If the namespace unit's objects are still there (the
handle `/run/netns/azazel-decoy`, the host end `az-decoy-host0`), for example
because its undo was itself killed at `TimeoutStopSec=`, remove them by hand,
as root, with the same fixed commands the unit uses, in this order:

```
sudo systemctl stop azazel-decoyd.service azazel-decoy-netd.service azazel-decoy-nsd.service
sudo /usr/bin/ip link delete az-decoy-host0
sudo /usr/bin/ip netns delete azazel-decoy
sudo systemctl reset-failed azazel-decoyd.service azazel-decoy-netd.service azazel-decoy-nsd.service
```

Deleting the host end takes the decoy's end (`az-decoy-ns0`) with it. A
command that reports the object does not exist means that object was not
left behind; go on with the next one. If the helper's objects are also left
(see "Existing objects are never overwritten" above), remove them first, path
before rules: `sudo /usr/bin/ip link delete az-decoy0`, then
`sudo /usr/sbin/nft delete table inet azazel_decoy`. Afterwards
`ip netns list` shows no `azazel-decoy`, `ip link show` shows no `az-decoy*`
link, and `nft list tables` shows no `inet azazel_decoy`. A reboot also
clears all of them, because `/run` and the kernel's links do not survive it.

**The three units can block the whole activation pass.** None of the three
units is ever granted, but every pass checks their unit files and loaded
definitions like those of every grantable unit. If any of the three departs
from what the package installed (a drop-in, an edited vendor file, or a
definition loaded with either), the pass is refused as a whole and **no
unit is granted that boot**, Edge Core and the supporting units included.
The typical cause is a VM check that unmasked the units by hand and removed
the grant-marker condition or the controller dependency with a drop-in.
After such a check, remove every drop-in and grant marker you added, then
mask the three units again and reload:

```
sudo systemctl stop azazel-decoy-nsd.service
sudo systemctl mask azazel-decoy-nsd.service azazel-decoy-netd.service azazel-decoyd.service
sudo systemctl daemon-reload
```

Remove the drop-ins (`/etc/systemd/system/<unit>.d/`, `/run/systemd/system/<unit>.d/`)
before reloading. The library's systemd client (`SystemdUnitCalls`) can
unmask and enable these three units, because they are in the fixed unit
table. Only the controller's decision keeps them masked, so do not script
an unmask of them outside the activation pass
([prerequisites §10](deception-redirect-prerequisites.md#10-p1-as-implemented)).

The explainer's operator leaf also contains `recent.json` with up to 20 recent
incidents; status renders five. Rows show pseudonymous ids, open/closed state,
severity/count, technique ids, sanitized summaries and knowledge citations.
`Edge would isolate (observe-only, not executed)` records the decision Edge
reported. Closing an incident does not imply an action was executed. Missing
or malformed recent snapshots show unavailable while other sections continue.

Auditd accepts only azexplain's bounded incident openings, severity escalations
and closes. The existing audit verifier accepts these events. Audit forwarding
uses a separate worker, a 256-entry memory queue and 2 s exchanges. Transport
failures are retried after 0.5, 1 and 2 s and then dropped; a refusal from
auditd is dropped at once and counted separately (`audit_forward_refused`);
that includes `rate_limited`, auditd's per-writer rate and daily limits, which
normal operation never reaches. A rising `audit_forward_refused` together with
`audit.rate_limited` records in the chain means the explainer is writing far
more than the intake budgets allow: inspect it before anything else. auditd
never deletes segments; when the chain reaches 1 GiB or its filesystem has
less than 1 GiB free it logs `audit chain capacity warning` to the journal once
a day, and `audit.verify` reports `capacity` (see `docs/integration-loop.md`,
"Audit chain limits"). `azazel-nexus status` shows the same reading as the
`audit:` health line, from auditd's snapshot
`/var/lib/azazel/run/audit-status/status.json` (rewritten every 60 s; stale
after 300 s). `audit: ok -- WARNING: capacity warning (...)`, also listed
under `next:`, means the chain or its filesystem crossed a threshold. It is
not a failure: nothing is deleted, by policy; see "Audit chain retention"
above for what each reason asks of the operator.
`audit: FAILED` means only that the chain did not verify at auditd's start. `audit: unknown` means no readable snapshot (auditd not
running, or install.sh not re-run after the upgrade that added the leaf) or a
stale one.
Queue overflow, exhausted retries and clean-shutdown abandonment count as
audit drops (`audit_forward_dropped`). Crashes can lose
queued work; lost acknowledgements can duplicate events. Explanations and
ledger reads continue through an audit outage. `recent.json` is a projection,
not a replacement for either verified ledger.

### Observe-baseline activation tooling (#206, P3)

`az-activation` prepares the inputs the observe-baseline activation pass
verifies at the next boot (see "Activating the integrated loop" above).
Nothing it does starts or enables a unit itself.

1. `sudo az-activation generation-publish` measures the installed unit files
   of the activation policy's scope (and the installed Edge package when
   edge-core is in scope), refuses any override or drop-in of those units
   other than a `/dev/null` mask, binds verified commissioning evidence, prints the
   generation digest and publishes after the digest is re-entered and
   `PUBLISH` typed. Publishing is not admission.
2. `az-activation request --operator LABEL --approval-id ID --seq N
   --valid-for SECONDS [--units …] --out FILE` writes the unsigned v2
   payload to `FILE` (create-only `0600`, in a directory not writable by group
   or others) and prints a summary with its `payload_sha256`. `--out` is
   required for the payload: the payload carries the commissioning evidence
   binding, so without `--out` only the summary is printed, nothing is
   written and it exits 1. It writes nothing else.
3. Sign it on the operator's workstation with `tools/operator_sign.py
   --purpose activation`.
4. `sudo az-activation install --payload FILE --signature FILE
   --confirm-sha256 HEX` verifies it against freshly collected context, the
   activation policy and the high-water floors, raises the floor and places
   `/etc/azazel/activation/approval.json` and `approval.sig`. Replacing an
   installed approval needs `--replace` and typing `REPLACE`. Once a floor
   exists, the approval's `--seq` must be above the floor's `approval_seq`;
   the only exception is installing the byte-identical installed pair again.
   So neither re-signing the same `--seq` to extend the expiry nor
   re-installing the same approval after its files were removed works any
   more: request a higher `--seq` and sign it anew.
5. **Raising the declared security epoch** (#251) ends every approval for
   the current epoch at once, the installed one included. It only raises
   and cannot be undone. `az-activation epoch-request --operator LABEL
   --to-epoch N --out FILE` writes the unsigned payload (node digest, digest
   of the current deployment declaration, current and new epoch); sign it on
   the workstation with `tools/operator_sign.py --purpose
   activation-epoch-raise`; `sudo az-activation epoch-raise --payload FILE
   --signature FILE` verifies it, asks for the payload SHA-256 again and
   `RAISE`, raises the high-water epoch floor, replaces
   `/etc/azazel/bootstrap/deployment.json` with the same declaration at the
   new epoch and records `activation.epoch_raised` in the activation ledger.
   `epoch-request` works without a high-water file (it only refuses a new
   epoch below an existing floor); `epoch-raise` refuses without one, so an
   approval must have been installed before. Afterwards request, sign and
   `install --replace` a new approval at the new epoch, with a `--seq` above
   the floor. Also:
   - a summary line `WARNING: the epoch rises by …` appears when the step is
     above 1000; check the number, it can never be lowered;
   - a signed payload that is not applied is deleted together with its
     signature (it has no expiry);
   - the bootstrap path binds the declaration as well. Do not raise while a
     bootstrap lease is valid (its revalidation is then refused until it
     expires). A bootstrap selection carries the declaration digest and is
     refused after a raise; it is never replaced, so root moves
     `/etc/azazel/bootstrap/selection.json` (and `selection.pending`) aside
     into a root-only directory, keeping it, while the controller is not
     running. A later bootstrap needs a new bootstrap approval and selection;
   - exit 2 with the ledger record missing (or the declaration's durability
     unconfirmed) cannot be repaired by running it again: record the raise
     outside the node as an audit gap.

   Details:
   [observe-baseline activation §11](activation-observe-baseline.md#11-raising-the-declared-security-epoch-251).

Exit 1 means nothing changed; exit 2 means a later step was not confirmed and
the state must be inspected before any retry. A missing high-water file on a
node whose activation ledger records a floor is never re-initialized from
zero; follow the
[recovery procedure](activation-observe-baseline.md#recovering-from-a-time-floor-set-too-far-ahead)
(`--recover-high-water`). Details:
[observe-baseline activation §3.1, §3.2](activation-observe-baseline.md#31-activation-approval-schema-v2-boot-free).
