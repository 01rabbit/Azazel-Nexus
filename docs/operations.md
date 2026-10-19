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
state and reasons from the latest `mio.capability.transition` in the hash-chain consistent ledger
`/var/lib/azazel/state/mio/route.jsonl`. This is the last recorded observation,
not a live probe or a freshness guarantee. Without readable ledger evidence the
values are unknown; operator commands do not read entryd credentials or infer
LITE/FULL from RAM. The recorded ceiling is not a grant or admission; entryd records CORE when no
profile is selected or its reader fails. Status does not
query systemd, and audit-chain health is unknown without an explicit `--ledger`.

Select M.I.O. CORE / LITE / FULL with `az-nexus-commission proposal-export --operator LABEL`, then obtain the existing separate full-proposal signature/review; entryd uses CORE until that selection verifies.
The whole sequence, including off-host signing with `tools/operator_sign.py`, is
rehearsed step by step in the [commissioning VM rehearsal](hil-runbooks/commissioning-rehearsal.md).
Installation creates `/etc/azazel/mio-profile/` as root:root 0700 even before
commissioning. Keep it limited to the two retained proposal copies and the
reviewed detached signature (root-owned 0600). `proposal-export` publishes the
copies; successful `proposal-review --operator LABEL` publishes the signature.
Do not copy commissioning records, drafts or protection keys there. Debian 13
(systemd 257) supports the required directory `LoadCredential` source. The unit
separately loads only the node declaration and the
operator trust store's public enrollment/revocation document. Keep their existing
protected permissions; no access grant to `azmioentry` is needed. Missing node
or trust credentials, an empty proposal directory, or an absent optional Fabric
extra yield CORE. Do not delete the installed source directory: a missing or
unreadable directory can prevent systemd from starting the unit. Credential
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

## 6. Operator experience

The primary interface is a touch-friendly status-first console. It must make four questions answerable within one screen: What changed? What evidence supports it? What is currently enforced? What needs an operator decision?

The UI groups information by mission state rather than by internal service. Every recommendation shows source, freshness, confidence, and cited evidence. An approval screen restates action scope, duration, policy rule, and rollback path before it can reach the Action Arbiter.

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
chains as `azincident-read`, asks M.I.O. and Knowledge over their existing
local sockets, and stores bounded explanations/cursor state privately under
`/var/lib/azazel/incident-explain`. Liveness is operator-readable at
`/var/lib/azazel/run/incident-explain-status/status.json`. It grants no Edge
control or enforcement authority; optional advisory failures never stop Edge.
See [integration loop I2](integration-loop.md#i2--explanation-explain--implemented)
for privacy, deadlines, rate/retention limits and fixed refusal codes.

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

Normal retention overtaking a cursor reports `cursor_overtaken` and resumes from
the oldest retained segment without operator reset. Outage replay drops `opened`
transitions older than one hour (`stale_skipped`). A valid segment-full marker
reports `incident_segment_full`; a torn final line reports
`ledger_tail_incomplete` and waits for completion without advancing its cursor.
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
auditd is dropped at once and counted separately (`audit_forward_refused`).
Queue overflow, exhausted retries and clean-shutdown abandonment count as
audit drops (`audit_forward_dropped`). Crashes can lose
queued work; lost acknowledgements can duplicate events. Explanations and
ledger reads continue through an audit outage. `recent.json` is a projection,
not a replacement for either verified ledger.
