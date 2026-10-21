# azazel-nexus-runtime

The OS service layer for Azazel-Nexus.

`az-nexus-bootstrap generation-preview` and `generation-publish` are operator
provisioning commands, not services. They verify exact bootstrap metadata/config
against protected administrator selection. Preview consumes two canonical JSON
lines from redirected stdin and writes nothing; publication requires a terminal,
digest re-entry and a separate `PUBLISH` confirmation. The selected-context digest
binds the complete target context/operator, not only the payload. Publication
goes only to the separate private bootstrap-generation namespace, never the
ordinary operational store, and never starts a service. Complete closure,
health, approval/deadline and lifecycle admission remain independent prerequisites.
The runtime distribution installs this operator command in its environment's
`bin`, not as a systemd unit or unit-backed `/usr/libexec/azazel` wrapper.

The same operator tool provides `time-initialize` and `time-recover` for an
explicit administrator-confirmed UTC anchor. Both require a terminal, the exact
canonical record, a context-and-operation-bound digest re-entry and a separate
operation word. They use the protected selected context and clock store; no
caller-supplied expected context, OS wall-clock trust, clock setting, deadline
reset or service operation is involved. Supplying a record is an administrator
assertion, not authentication/calibration of an external time source. Current
boot, pinned drift/uncertainty/lifetime policy and expiry still must pass. Existing
records cannot be replaced; stale-boot renewal remains separate unfinished work.

`azazel_nexus` holds what the node decides: state, contracts, the audit model,
and the refusals that make them checkable. It imports nothing that can spawn a
process, open a socket, or touch host storage, and a static scan enforces that
against its source. That is not a limitation of the library — it is why its
decisions can be tested at all.

This distribution is where the privileged half lives: Unix domain sockets,
netlink reads, and systemd operations. The dependency runs one way. The library
never imports this package, and CI proves it by importing the library in a job
where this package is not installed.

Nothing here listens on a network. Daemons that serve clients use Unix domain
sockets and identify callers from operating-system peer credentials. The
activation controller is different: it calls only the systemd system bus through
the fixed D-Bus method table in `systemd_bus.py`; it never starts a unit. Its
production composition now loads authenticated full commissioning evidence,
but still lacks lease, authoritative admission and measured health producers,
so it withholds all governed services and records that decision rather than
assuming readiness. Its `state/activation.jsonl` is a local controller ledger,
not the `az-auditd` segmented shared chain; it is neither signed nor anchored.

The packaged controller uses `Type=notify` without `RemainAfterExit`: its process
exit must not leave a logically active supervisor. Audit and commissioning bind
their lifetime to it with `BindsTo` plus `After`, without automatic restart.
The current entrypoint still performs one refusing pass and exits without a
readiness notification; systemd therefore does not report successful service
startup even when the refusal was recorded with exit status zero. It does not
yet run the bootstrap supervisor. These unit declarations alone neither grant
startup nor establish persistent-mask/reboot fencing or installed lifecycle
verification.

The bootstrap manager also exposes a private composition method,
`inspect_loaded`, which runs the read-only loaded-unit inspector on a fresh
owned system-bus connection and closes/drains that connection after success or
failure. It accepts only the audit/commission helper enum and independently
supplied dependency and service-setting expectations. Its result fingerprints
the checked projection, not the complete unit, transitive dependency admission,
health, or permission to start. This method is not exposed by a CLI/RPC and is
not yet called by the production entrypoint. The manager's widening methods
continue to refuse; inspection does not install an overlay or reload systemd.

`bootstrap_audit.inspect_existing_audit` is a separate read-only pre-start
producer for existing nonempty audit history. It reads auditd's actual fixed
`/var/lib/azazel/state/audit` directory without creating it, checks ownership,
file identities and bounded UTF-8 segmented-chain contents twice, and requires
an independently supplied exact expected head and explicit observation limits.
It does not trust its own measured head or a local unsigned checkpoint. Empty
history is refused by this reader. Fresh genesis is admitted only through a v5
prestart admission policy (`audit_mode: "first-install-genesis"`), which the
operator's signed bootstrap approval binds through `policy_digest`;
`bootstrap_audit.inspect_first_install_audit` then accepts exactly an existing,
correctly owned, mode-0700, EMPTY ledger directory, takes no expected head and
yields the fixed genesis observation. Once history exists that policy refuses, so
later boots need an existing-history (v3/v4) admission. Nothing machine-enforces
single use beyond that: a wiped ledger plus a fresh signed approval would be
accepted again, and assurance remains `LOCAL_CONTINUITY_ONLY`.

The controller run now performs the first admission of the bootstrap deadline
itself: after a fresh approval verification, generation admission and the
stopped-writer prestart, `ProtectedBootstrapInitialAdmission` re-verifies and
creates the immutable deadline exactly once (create-only), and the kernel guard
is armed from that retained deadline before any grant, publication, READY or
start. The supervisor's refresh still never initializes. Until cross-boot renewal
exists, a node bootstraps once; a retry needs a clean state (on a VM, a snapshot
revert), never deletion of retained records.
The caller must establish that the writer is stopped and authenticate the
expected head; this producer supplies neither fact nor a complete health grant.
It is not yet connected to the production startup path.

`ProtectedBootstrapGenerationAdmission` connects the protected fixed-layout
generation reader to the supervisor's admission interface. It checks the
fixed `/etc/azazel/bootstrap/installed-files.json` selected-file manifest
against `unit_closure_digest` and measures its listed files before and after
the explicit semantic checker. The checker remains mandatory and must raise on
uncertainty; a truthy flag is not accepted. This is selected-file integrity,
not complete Python/package closure or package authenticity, and supplies no
health admission, publisher, production composition, or permission to start
services. A missing manifest fails closed.

## Operator commissioning adapter

`az-nexus-commission` (or `python -m azazel_nexus_runtime.commission_cli`)
connects the existing library `inventory`, `commission`, and
`commission-review` commands to the read-only netlink permanent-address
collector. It is an operator tool, not a daemon or an activation path.
Inventory and commissioning require an interactive terminal and display only
the existing physical-label/bus-path allowlist. No current-MAC fallback or
role inference is supplied. Confirmation and successful review recheck the
link name/index/permanent-address snapshot; this does not establish atomic
stability of every sysfs field. Missing, malformed or changed kernel evidence
fails closed. Draft export/review retain the library's fixed encrypted-storage,
protection-key and enrolled-signature requirements. No key is generated and
no record is promoted or service activated by this adapter.

`az-nexus-commission proposal-export --operator LABEL` connects a protected,
signed role draft to the full linked proposal. It requires an interactive
terminal, protected declared node and enrolled operator, complete current
hardware/resource observations and explicit `EXPORT` confirmation. It rechecks
node/trust/draft inputs and hardware/netlink before creating
`/etc/azazel/commissioning/commissioning-proposal.expected.json` followed by
`commissioning-proposal.json` (0600, encrypted-storage prerequisites, exclusive
creation under one directory lock; never overwrites). Raw identities, node
labels and digests are not printed. A failure can leave a partial private file;
inspect it before retrying. No signature, key or authoritative record is
created. The expected copy is created only from locally collected model inputs,
not imported candidate bytes. An existing proposal, expected copy or signature
refuses a new export without altering any of them. Local assembly time is not
trusted-time evidence; resource samples
retain their observation time and are not continuously refreshed.

The retained proposal needs separate review and a new signature under the
`commissioning-proposal` purpose. Keep its raw inventory in protected storage;
export here does not authorize external disclosure. Production signature
promotion into authoritative persistence still require freshness/state checks
and a reviewed activation loader. Never parse an imported proposal and reuse
its own contents as the independent expected snapshots. This command does not
enable services or satisfy activation gates.

`az-nexus-commission proposal-review --operator LABEL` reads the retained local
expectations, signing view and externally supplied `commissioning-proposal.sig`
only from that fixed protected directory. The detached signature must be
exactly 64 bytes in an owner-only, single-link ordinary file. It must cover
`approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)` using the
independently enrolled operator key; signing raw JSON alone is not sufficient.
No private key is accepted or generated. Canonical reconstruction validates all
linked profiles; candidate bytes must exactly match retained expectations,
the configured node must match, and the signer must still be enrolled. The
file set, node and trust are reread before a redacted historical-review success.

An older export without retained expectations is refused; it is not migrated
or trusted automatically. Missing/partial files, lock contention or changed
inputs refuse without cleanup. Protected ownership is the local provenance
boundary, not protection against its privileged owner or rollback. A successful
review does not measure present hardware/resources, establish trusted time or
promote an authoritative record, and no service is enabled.

Add `--check-current-hardware` after the operator label to require a fresh
whole-hardware comparison in the same review. Both retained and current Fabric
inventory digests are independently validated. Only snapshot ID, collection
timestamp and inventory digest are excluded from content comparison; every
other field (including node, platform, storage, all interfaces and limitations)
must match exactly, including list order. Current metadata/digests are retained,
not rewritten to impersonate the historical snapshot. A locally earlier
collection time refuses but this is not trusted-clock evidence. Runtime
recollects hardware and brackets it with fresh netlink reads, then rereads
protected node/trust/proposal inputs before reporting a match. This is change
detection, not an atomic snapshot; resources, capture/isolation, policy and
activation remain unverified. Without the flag, review remains historical.

The activation entrypoint uses `commissioning_input.load_commissioning_evidence`
after its mandatory all-unit masking pass. This fixed-path loader revalidates
the full retained signature, collects and compares current hardware, brackets
recollection with netlink checks, then rereads node, operator trust, protected
binding key and retained files. It retains the complete proposal and current
inventory rather than reducing them to profile names. The additional private
HMAC binding must match generation metadata and signed activation approval;
the legacy record must independently match roles and confirmation provenance.
There is no persistent verified flag, key creation or authoritative promotion.
See [binding and rollback limits](../docs/commissioning.md#7-verified-generations-and-the-activation-controller).

The generated activation unit allows `AF_UNIX AF_NETLINK` for D-Bus and the
read-only route-netlink observation. Its capability set remains empty,
`IPAddressDeny=any` remains set and no internet address family is added.
Declaration/unit tests are not execution under the real systemd sandbox.
Authoritative commissioning admission, production approval context/loading, node identity binding,
policy, renderer measurement, epoch/high-water, trusted clock, node health and
authenticated Edge evidence still need production producers. No lease or
health is fabricated from a successful commissioning verification.

The library now has `activation_store.load_activation_approval` for the fixed
private `/etc/azazel/activation/approval.json` and `approval.sig` pair. It uses
current enrolled trust, independently supplied context/operator/time/duration,
bounded single-link ordinary-file reads and shared nonblocking directory locks.
It reopens the fixed path to detect directory replacement, then rechecks bytes
and trust. It creates nothing and accepts no public path override. This is an
input reader, not an expected-context producer: `_run_once` still supplies no
lease until the [independent runtime inputs](../docs/runtime-activation-remaining.md)
exist. Unit tests using synthetic storage are not production enrollment or
installed-service evidence.

`az-nexus-commission resources` is a separate read-only aggregate assessment.
It reports kernel usable memory, online logical CPU count, and caller-available
space on an existing `/data` filesystem distinct from root. Missing, malformed
or read-only mission storage is unavailable, not a fallback to the root disk.
Exit 1 indicates at least one unavailable observation; exit 0 means only that
those observations were acquired, never profile readiness or admission.
GPU, throughput, thermal/power, cgroup constraints and storage trust remain
unmeasured/unverified. No physical device is opened or filesystem created.

`az-nexus-commission hardware-assess` reads fixed sysfs platform/storage/NIC
metadata twice, rechecks the kernel link snapshot, and prints only counts and
fixed limitations. It never prints raw records/digests or saves anything.
Missing optional platform/model/serial values are explicit; required storage
size/rotational/removable fields cannot be guessed. Virtual block devices and
partitions are excluded, and their capacity is not added to whole devices.
Exit zero reports collection, not complete commissionability or admission.
`collect_hardware_inventory()` additionally projects a Fabric snapshot in
memory when supplied an independently established node identity. It refuses
unprojectable interfaces and does not generate or enroll that identity.

Hardware snapshots exclude only positively classified kernel loopback
(ARPHRD type 772 and resolved virtual/net placement), with an explicit count
and limitation. Other virtual interfaces are not silently removed. Use the
observation's `commissioning_proposal()` for topology review so its interface
scope agrees with the hardware snapshot.

The runtime wizard and signed-draft review now supply that scoped proposal
through the library's injected commissioning reader. Confirmation/export and
review success recheck the hardware fields, with fresh netlink reads before
and after recollection. The general library inventory remains unfiltered.
This is a change-detection boundary, not an atomic system snapshot or a grant.

The node-context reader uses the explicit `/etc/azazel/node.yaml` declaration,
not a generated machine-ID/hostname fallback. It requires protected root-owned
ancestry and a bounded regular single-link file; duplicate keys, aliases,
explicit YAML tags, multiple documents and excessive nesting are refused.
`PyYAML==6.0.3` is a runtime-only dependency. It is loaded lazily so a parser
failure cannot prevent activated's mandatory masking pass. Staging checks the
dependency before writing wrappers. Only a redacted declaration-present status
enters the activation diagnostic; a declaration is neither node attestation nor
disclosure approval, and roles/resource claims in that file grant nothing.

## Administrator declaration preview

Before protected deployment, an administrator can validate an independently
prepared canonical declaration without installing or activating anything:

```sh
azazel-nexus bootstrap-deployment-preview < deployment.json
```

Input is the exact canonical `azazel-nexus/bootstrap-deployment/v1` record
(no trailing newline), bounded to 4096 bytes. Interactive stdin is refused.
The command prints only its SHA-256 and the limits of the check; it does not
echo node/operator identifiers, read protected stores, inspect hardware, or
publish a file. Exit zero means **syntax valid only**, not trusted policy,
approved identity, provisioning, or runtime admission. VM and physical hosts
use the same schema; current observations and independently authorized
protected publication remain separate requirements.

The library `initialize_bootstrap_deployment` now supports first publication
only, to the already protected fixed bootstrap directory. It requires the
exact preview SHA-256 and a separate exact-boolean initialization confirmation;
there is no path override, automatic directory creation, or overwrite/update
mode. The one replacement is the operator-signed, raise-only security epoch
change of `az-activation epoch-raise` (docs/activation-observe-baseline.md §11). Cooperative exclusive locking and a durable pending marker keep readers
from accepting an interrupted publication. Failure leaves state for review,
not automatic deletion/retry. If the final directory fsync fails after removing
the marker, durability is unknown even though the file may be readable; the
operation still reports failure. Neither publication nor readability grants
runtime admission. No live store has been initialized during development.

`azazel-nexus bootstrap-deployment-initialize` now requires an interactive
terminal: enter the canonical JSON on one line, re-enter its reviewed SHA-256,
then separately type `INITIALIZE`. The line terminator is input framing only;
the JSON bytes are not reformatted. Piped input, mismatched digest, incomplete
input or a different confirmation word refuses before publication. The fixed
protected directory must already have been installed under administrator policy;
this command neither creates it nor escalates privileges.

After inspection of interrupted publication, `azazel-nexus
bootstrap-deployment-recover` uses the same input sequence with `RECOVER`.
Recovery requires both the known private pending marker and the exact complete
declaration matching the administrator's confirmation. It fsyncs and rechecks
retained content before removing the marker; it does not rewrite declaration
bytes. Missing, truncated, different or unsafe state is left untouched. There
is no generic reset, overwrite, repair, or automatic retry. Final-fsync failure
still leaves uncertain durability. Neither command starts services or supplies
runtime semantic admission, and both require review before deployment use.
Exit status 2 explicitly means the declaration may be published but final
durability is unconfirmed; inspect retained state and do not retry automatically.
Exit status 1 is refusal/error and may also retain partial state. Exit status 0
means declaration publication completed, not runtime authorization.

### Policy-bound capacity prerequisites

`check_bootstrap_capacity(expected=...)` now reads the fixed protected
`/etc/azazel/bootstrap/admission.json` and checks both resource and state-volume
capacity against its explicit floors. The exact canonical
`azazel-nexus/bootstrap-prestart-policy/v3` bytes must hash to the independently
supplied context's `policy_digest`; the record cannot hash itself or supply its
own expected context. `approval_policy_digest` remains the separate signer and
duration policy. A second protected read must match after the capacity checks.

This v3 is explicitly the exact audit/commission pair, existing-history,
`LOCAL_CONTINUITY_ONLY` profile. It also pins package/unit-closure expectations,
the exact reviewed systemd profile digest, an expected audit head and audit scan
limits. It does not measure those packages,
validate audit continuity, prove rollback anchoring, or provide first-install
genesis. A deployment requiring another assurance cannot silently use this
profile. No production policy was generated or installed. This capacity checker
must not be used as the complete semantic-admission callback: trusted time,
actual installed closure, audit state, lifecycle and storage trust remain gates.

V3 requires explicit `systemd_profile_digest` in addition to
`max_anchor_lifetime_ns`, `max_uncertainty_ns` and `drift_ppb`; earlier schemas
and missing values refuse rather than acquiring defaults. The profile digest
identifies the reviewed profile name, exact version and ordered UnitPath; the
full policy hash binds it. Administrator clock projection widens
its UTC interval by the ceiling of elapsed boot nanoseconds times `drift_ppb`
divided by one billion, then rounds outward to UTC seconds. The rate is a bound
on accumulated UTC error per measured boot-clock elapsed time; its calibration
is an administrator/provisioning responsibility, not a measured fact inferred
from the numeric value. Final rounded uncertainty and total anchor lifetime
must fit policy. Protected anchor provisioning and freshness checks through
verification/retention remain required before this is a production time source.

The runtime now distinguishes a point projection from `AdministratorTimeWindow`,
whose UTC bounds cover every instant in its half-open BOOTTIME validity window.
Window projection uses the policy uncertainty budget and anchor expiry to bound
reuse rather than assuming verification is instantaneous. Observations preserve
that window and bind it to node/policy/boot and both UTC endpoints. Protected
inputs check the window before and after deadline retention and reject elapsed
rollback or metadata disappearing during refresh. A refusal after retention may
have advanced local state, but returns no usable result and never resets it.
Protected source admission/publication and actual runtime wiring are still
required; constructing a window does not establish clock trust.

The selected local-administrator source now has a fixed protected reader:
`/etc/azazel/bootstrap/time.json`, canonical
`azazel-nexus/administrator-clock-anchor/v1` with source
`administrator-confirmed`. It binds the explicit UTC bounds and BOOTTIME
anchor/expiry to node, policy and boot, rechecks record/policy/boot, and uses the
pinned v2 clock limits. Persistent records from a different boot refuse. No
record is created by this reader and no sync-marker/wall-clock fallback exists.
Local root is trusted to assert the interval; this does not authenticate an
external time source, prove calibration or resist a malicious root's replay.

`ProtectedAdministratorClockObservation` connects that reader to the existing
administrator/node binding and validity-window observation. It still requires
an independently measured current context producer; the candidate approval is
not that producer. Use only in the explicitly selected administrator-managed
mode. Operator confirmation/publication remains unimplemented and no live time
record has been provisioned during this work. Production activation stays closed.

`inspect_bootstrap_prestart(expected=..., manager=...)` composes these capacity
checks with the existing audit-history reader using the policy's head and scan
limits. Both helpers must be positively masked and inactive before and after
inspection, and the protected policy must remain unchanged. The manager is a
trusted runtime dependency, not a public request parameter. These calls inspect
state only; they do not mask, stop, start or enable units. The result remains a
`LOCAL_CONTINUITY_ONLY` audit observation, not a start token. Before/after checks
cannot prove a continuous absence of writers or replace the controller's
transaction, reviewed dependency graph, installed closure or trusted time.
Missing history still refuses rather than initializing a new ledger.
The supervisor now uses this inspector by default under its lifetime transaction,
after initial containment and before its first audit record or READY notification.
Containment now requires the manager's exact-pair `close_starts()` fence before
mask/stop/remask. Missing, failed or non-`None` completion still triggers every
best-effort cleanup operation but cannot produce `BootstrapResult`. The current
narrowing adapter explicitly refuses this guarantee: refusing its own start
API does not cancel earlier or externally submitted jobs. A reviewed deployment
fence and explicit subsequent grant transition remain necessary; no production
start path is enabled by this contract.
The supervisor now requests one `open_pair()` grant after controller readiness,
grant-intent audit persistence and refreshed admission; it no longer unmasks
each helper independently. Audit readiness still precedes commissioning start.
Containment calls `withdraw_pair()` only after the start fence, cleanup calls
and both inactive observations succeed, then remasks and checks again. Unknown
ownership or withdrawal failure cannot be hidden by inactive/masked observations.
Both grant methods remain refusing in the production narrowing adapter pending
a reviewed durable ownership/reload/reboot implementation.

`BootstrapJobDrain` supplies the bounded queue-drain portion only. Through an
owned manager session, `drain_pending_jobs(check_closed=...)` revalidates an
independently established closed-start fence, pins systemd's unique bus owner,
validates the complete bounded `ListJobs` response and issues `CancelJob` only
for auditd/commissiond IDs. Two consecutive pair-empty observations are required,
with a finite total deadline and list-round budget. Unknown replies, owner/fence
changes or persistent jobs refuse. The component does not install a mask or
prove that running operations have stopped; `close_starts()` remains refusing
until the actual deployment fence exists. No CLI exposes job IDs or targets.

`BootstrapAuditClient` sends the supervisor's bounded event to the fixed
`audit.bootstrap.append` Unix-socket verb and requires an exact chain receipt.
Bootstrap event types are excluded from the general service-writable append
verb and the dedicated verb admits root only. The supervisor omits `unit_key`
when the lifecycle event has no unit. Audit refusal or transport uncertainty
propagates into containment. This proves the code path and schema, not the
installed socket credentials or the currently unavailable supervisor wiring.
This prestart pass runs once; repeated generation checks must not reuse the
initial audit head after legitimate records advance. A separate continuation
inspector now verifies the entire bounded chain still contains the previously
verified head and accepts only unchanged history or valid extensions. The
supervisor advances its in-session head only after verification, clock and
transaction checks succeed. Truncation, rewritten prefixes, policy changes or
unstable snapshots refuse; no automatic retry or external rollback protection
is implied. Concurrent audit writes can trigger conservative refusal, so actual
service lifecycle usability remains unverified. Trusted tests may override the inspector with
synthetic evidence; production daemon wiring and widening remain unavailable.
