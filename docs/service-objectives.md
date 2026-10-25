# Nexus service objectives and evidence records

Issue #17 implements the Nexus consumer evidence path from
[Service Objective Assignments §2](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/service-objective-assignments.md).
No target value changes here.

**No green CI run satisfies SO-01 or SO-10.** Both are **hardware-only**.
Until their field exercises run on the declared rugged-PC class, status remains
`implemented, hardware-unverified`; neither a synthetic record nor a schema
validation test supports a hardware claim. Track `not-run / failed / passed`
and the target hardware in the release matrix. An absent record is `not-run`,
never a pass. See also [hardware gates](hardware-gates.md).

| Objective | Target, unchanged | Class | Gate |
| --- | --- | --- | --- |
| SO-01 | Every cold boot ready within 120 seconds; report maximum | hardware-only | R7; re-read R8 |
| SO-06 | 100% continuation: zero divergence and zero missing records | software, Nexus consumer | R4 Knowledge; R5 Deception; R6 remote cognition |
| SO-10 | Zero transmitted frames in every 10-minute stress run | hardware-only | R7 |

## Version 1 record contract

The executable format and validator are `tools/service_objectives.py` (standard
library and existing Nexus modules; no new framework). One JSON object covers
one exercise/replay invocation, one product configuration and, for hardware,
one declared hardware class. Its `samples` contain every observation. Do not
pool hardware classes or omit a failed observation. Unknown schema versions
are rejected. JSON integers are required for nanoseconds and frame counts;
booleans are not integers in this format.

Validate an archived record from the repository root:

```sh
PYTHONPATH=src python3 -m tools.service_objectives record.json
```

Validation failure exits 2. `validate_record` returns `shape_only` or `attested`.
The CLI always prints that status. A shape-only validation never prints a
verdict. Hardware records carry a `claimed_verdict`, which is an untrusted
claim until attested validation succeeds; no consumer may use it as a gate
verdict without that status. A failed claim can still be a valid record.

For attested validation, provide the operator public key **outside** the record:

```sh
PYTHONPATH=src python3 -m tools.service_objectives record.json \
  --operator-key /trusted/operator.pub --artifact-root /archive/exercise
```

The key file contains a lowercase hex Ed25519 public key. The detached hex
signature is `operator_attestation.signature`. The signed message is
`b"azazel-nexus/service-objective-attestation/v1\0"` followed by Nexus canonical
UTF-8 JSON of the entire record excluding only `operator_attestation` (the
signature envelope). No public key supplied inside the record is trusted.
Signing is done outside Nexus; Nexus only uses its existing verifier.
For SO-01/SO-10 the validator also reads every manifest, commissioning,
capture and durable-audit reference and checks file existence and SHA-256.
Relative paths resolve against `--artifact-root`, or the record's directory.
An invalid signature, missing artifact or digest mismatch is refused.

**This proves operator attestation and artifact integrity, not that physics
happened.** An operator can sign fabricated data. Field review still needs
physical provenance, raw captures and the exercise procedures below.

All records require these fields:

| Field | Value / meaning |
| --- | --- |
| `schema` | `azazel-nexus/service-objective/v1` |
| `objective_id` | `SO-01`, `SO-06`, or `SO-10` |
| `owner_repository`, `owner_commit` | `Azazel-Nexus`, full lowercase 40- or 64-hex commit of the measured implementation |
| `class` | `software` for SO-06; `hardware-only` for SO-01/SO-10 |
| `configuration.product_configuration` | Nonempty declaration of the exact installed product/image and workload |
| `clock` | `CLOCK_MONOTONIC` for every objective |
| `samples` | Nonempty array, with nonnegative integer start/end nanoseconds for every sample |
| `pass_rule` | Exact objective-specific string in `RULES` in the validator; changing a bound is rejected |
| `evaluation` | Recomputed result: SO-01 `maximum_elapsed_ns`; SO-06 `comparisons` and `failed_comparisons`; SO-10 `attributed_frames` array |
| `claimed_verdict` | Hardware claim: `passed` or `failed`, checked against all samples; usable only after `attested` validation |
| `execution_result` | Software execution observation: `PASS` or `FAIL`; not an attested release verdict |

Hardware records additionally require `synthetic: false`, and configuration
fields `hardware_class`, `dut_id`, `os`, `driver`, `operator`, `exercise_id`,
`physical_hardware: true`. Record exact OS/kernel, driver/firmware versions,
installed image digest, exercise date, declared class and physical device
identities in the product configuration and capture manifest.
`hardware_capture` requires `synthetic: false`, `clock_host` and `manifest`.
Every artifact reference is an object with a nonempty `path` and a lowercase
64-hex `sha256` of the retained raw artifact. Every sample requires a consecutive
`sequence` starting at 1, nonnegative integer `start_ns` / `end_ns` with
end at least start, and a `capture_artifact` reference.

The validator checks structure, counts, thresholds, correlations and claims.
Software cannot acquire the required physical evidence. There is deliberately
no hardware record generator or committed measurement here. Records missing
hardware capture fields or marked synthetic are refused even when their
numbers satisfy the target. Schema fixtures are explicitly named shape-only.

## SO-01 field exercise — hardware-only

1. Install the declared image on each declared rugged-PC hardware class. Record
   OS/kernel, drivers, image, operator and DUT identity. Declare and restore the
   **coldest declared cache state** (`configuration.coldest_cache_state`) before
   each cold boot. Do **10 consecutive cold boots per class**; keep failures.
2. Instrument both events on the DUT using **CLOCK_MONOTONIC** nanoseconds.
   Start when the decryption layer reports the volume mapped and usable, with
   the unlock unit reaching active (`start_event` is
   `unlock-unit-active-volume-usable`). Passphrase entry is not the start.
3. Submit a synthetic probe event to the installed deterministic Core decision
   path. Stop only after the probe has received a decision **and that decision's
   audit-chain record is durable** (`end_event` is
   `probe-decision-and-audit-durable`). Init completion alone is insufficient.
   The probe is synthetic; the boot, clock and durable-audit observations must
   be physical measurements. Record `boot_id`, `probe_decision_id`,
   `cold_boot: true`, and `durable_audit_artifact` in each sample. Retain the
   unlock/probe/durability event capture as `capture_artifact`.
4. `hardware_capture.clock_host` must equal `configuration.dut_id`. Each boot
   has its own monotonic origin; subtract within that boot only. NTP and wall
   clock corrections play no role. Record the ten distinct boot IDs and raw
   timestamps in sequence; do not substitute a percentile.
5. Compute each `end_ns - start_ns`. Pass only if **every sample is at most
   120,000,000,000 ns**. Report the maximum, including a failing maximum. If a
   boot never completes, retain the raw failure and mark the release exercise
   failed/incomplete; do not invent an end timestamp or emit a passing record.
6. Validate and archive the record with its capture manifest and artifacts as a
   field-exercise record in the owning repository. Obtain field review before
   using it at R7/R8. This procedure has not been run by this change.

## SO-10 field exercise — hardware-only

1. Resolve the installed **commissioned observation role** against the physical
   adapter. Retain the complete commissioning evidence as
   `configuration.commissioning_artifact`, set `commissioned_role: observation`,
   and copy `commissioned_composite_identifier`: `bus_path`, `permanent_mac`,
   and at least one of `pci_id`, `usb_id`, or `serial`. These correspond to the
   composite in `commissioning.ConfirmedRole`; no kernel interface name is
   accepted in this object. Recheck the binding after reboot or adapter changes.
2. Attach an **independent physical capture device on the same segment**: a
   second host, tap, or switch mirror port. A tap/mirror feeds an independent
   recording host. Set `hardware_capture.device_id` to that independent recorder,
   `method` to `second-host`, `tap`, or `switch-mirror`, and
   `same_physical_segment: true`. `clock_host` must be the recorder's identity,
   different from `dut_id`. **Measurements on the device under test prove
   nothing.** DUT counters or DUT-local packet capture cannot satisfy this row.
3. Verify the independent capture sees the segment, distinguishes direction and
   attributes outgoing frames to the commissioned link. Retain topology,
   direction/attribution method, full packet capture, capture health/drop
   counters and stress event logs in the manifest. An incomplete/dropping
   capture is inconclusive, never evidence of zero transmitted frames.
4. For each of **3 runs per hardware class**, start the independent capture
   before stress. Timestamp stress start (`independent-capture-stress-start`)
   and stop (`independent-capture-stress-stop`) with **CLOCK_MONOTONIC on the
   independent recording host**. Keep that host awake; only the DUT suspends,
   so the measured interval includes the DUT's suspended time. Drive stress
   continuously over at least **600,000,000,000 ns** between these timestamps.
5. During every interval drive link up/down, IPv6 Router Advertisements, DHCP
   offers/requests, and at least one DUT suspend/resume. Each sample's `stress`
   object requires all four booleans true: `link_up_down`, `ipv6_ra`,
   `dhcp_offer_request`, `suspend_resume`. Raw logs must corroborate them.
   A driver reload may supplement these operations; it replaces none of them.
6. Count **every frame attributed to the commissioned interface's outgoing
   link**, explicitly including **ARP, DHCP, IPv6 RS/NS/NA, mDNS, LLDP and
   802.1X**. Inbound stress traffic is distinguished by the capture topology,
   not subtracted by an assumption that host protocols are harmless. Record
   the independent `capture_artifact` and integer `attributed_frames` per run.
7. Pass only if **all three counts are exactly zero**. A single frame fails;
   averages and rounded rates are forbidden. Validate and retain the record,
   packet captures and manifest for field review at R7. This procedure has not
   been run by this change.

## SO-06 deterministic consumer replay

The in-repo adapter in `tools/so06_replay.py` drives actual Nexus
`degradation.call_with_deadline`, `degradation.assess`, `integration.build_view`
and durable `AuditLedger.append` / `verify` paths. Each scenario runs fresh
state with identical input events once healthy and once for all 15 combinations
of `knowledge_node_absent`, `deception_node_absent`, `remote_path_unreachable`
and `absent`, `refusing`, `hanging`, `corrupt`, `expired`.

These are injected dependency responses at the consumer boundary: not
configured, declined, pending beyond deadline, invalid JSON and expired data.
A harness-owned virtual clock advances the pending response beyond the 10 ms
budget; the production deadline helper must reject it. In this check there is no real sleep
or blocking callee. This tests synchronous deadline consumption, not network
cancellation or a preemptive timeout of arbitrary code.

Core retention and disposition come from the executed outcome. The adapter
also records actual integration rows and what continues, checks peer supplier
removal and refusal to claim Edge readiness, and compares observed behaviour
against an independent expected disposition table. A changed integration
continuation is detected and recorded as `expected_behaviour: false` and
`execution_result: FAIL`. Arbitrary injected runners and supplied output traces
are no longer accepted by the CLI as execution evidence.

Each run also drives the consumer loop in `tools/so06_loop.py` with fresh
state. The two golden Edge observations of the integrated loop (lines 4 and 6
of `tests/fixtures/edge/rust_event_engine_v1.jsonl`, notify then isolate) go
over a Unix socket into the real `IntakeServer`: closed parsing, the evidence
store and the incident ledger. The real `Explainer` then reads that incident
chain, calls the production M.I.O. and Knowledge clients, and forwards the
incident transitions (opened, escalated, shutdown close) into the same durable
`AuditLedger` as the input events. Intake and explainer share one fixed clock,
so two runs can be compared byte for byte. The loop sends the second line only
after the first is processed. The intake no longer needs that: it processes
lines in accept order across connections ([integration loop](integration-loop.md),
#327), and a unit test sends both lines without waiting, the later one read
first, and gets the same records, escalation included.

The fault is injected where this loop actually meets each dependency:

| Dependency | Boundary the loop calls | absent / refusing / hanging / corrupt / expired |
| --- | --- | --- |
| Deception | the decoy socket of the same `IntakeServer` | not configured / connects and closes without a line / partial line held past the intake's own read deadline / invalid JSON / interaction an hour old (`DECOY_CLOCK`) |
| Knowledge | `knowledge.lookup` under `lookup_context` | no socket / declared refusal / reply pending past the caller's deadline / malformed refs / no rows served, as for expired claims (`no_context`) |
| Remote cognition | `mio.advise`, the only way the loop reaches cognition | no socket / declared refusal / reply pending past the caller's deadline / reply the consumer refuses / deterministic handoff that `fell back` |

For Knowledge and M.I.O. only the socket transport under the production
clients is replaced, because the real one verifies service accounts. The
clients' deadline argument, error classification and reply validation run
unchanged; `hanging` uses harness-owned virtual time, as above. The shipped
M.I.O. entry never admits the remote route (it passes no remote request and no
opt-in), so a remote loss could reach this loop only through `mio.advise`.
Faulting that boundary covers more than remote loss does. The decoy's
`hanging` uses the intake's real read deadline.

The adapter checks each fault against an independent table of where it must be
consumed: the decoy refusal code or acceptance, each explanation's Knowledge
state, M.I.O. route and failure codes, and one call per explanation at each
boundary. A fault that did not arrive, or a changed client mapping, makes
`expected_behaviour: false`.

Two paths are always driven: **`evidence_records`** (the intake's evidence
store) and **`audit_chain`** (input events, then the forwarded incident
transitions). Every fault run is compared with the healthy run, and a driven
path must have records in the healthy run. Tests show a decoy interaction
stored as Edge evidence, or an audit record that depends on Knowledge, being
reported as dropped or divergent. The bundle records where the observations
came from as `evidence_source`.

### `evaluation_outcomes`: the real Edge Core on a pinned clock

With `--edge-core PATH` (a built `azazel-edge-core`; test tooling only, Linux
with a C compiler), every run, healthy and each of the 15 faults, also executes
the real observe-only Edge Core once on fresh state (`tools/so06_edge.py`). It
gets the shipped unit's `Environment=` (only the socket, `eve.json` and release
ledger paths are relocated) and the `eve_events()` of the integrated loop: two
alerts and a flow. The observations it forwards, notify then isolate, are the
run's **`evaluation_outcomes`**, and they are what the loop's intake reads in
place of the golden fixture. Its forward-count reports are not observations.

Edge stamps its own wall clock into `normalized.ingest_epoch` and
`enforcement.metadata.release_due_epoch` (the release it would schedule,
`now + 300 s`). The comparison still excludes only the two advisory fields
below, so the harness **pins Edge's clock** instead:

- The Edge binary has no clock argument, and none is added. The shipped
  entrypoint has no way, by environment or configuration, to be told the time.
- The pin is a small preload library that the harness compiles with the
  instant fixed at compile time (`PINNED_EPOCH`, the intake's and explainer's
  `FIXED_NOW`) and sets for the Edge process it starts. It answers
  `CLOCK_REALTIME`, `gettimeofday` and `time` with that instant and reads no
  environment variable. `CLOCK_MONOTONIC` and every other clock are real, so
  Edge's polling and report timers run as shipped.
- A pin that did not take effect is refused, never compared: every
  observation must carry exactly `PINNED_EPOCH` and either no release or
  `PINNED_EPOCH + 300`.

**The clock is recorded, not decided.** Edge's action, policy reason, plans,
trace id and posture do not read it; `decisions_ignore_clock` checks that the
pinned and the wall-clock runs agree on everything except the two fields
(`python -m tools.so06_edge --edge-core PATH` checks a binary: pinned runs
identical, wall-clock runs not, decisions unchanged). Two places in Edge do
compare times, and neither is reached here: a release task is not built at all
for a negative or non-finite instant (the pinned one is valid), and release
reconciliation acts on ledger tasks whose `due_epoch` has passed. An
observe-only Edge only plans (`planned_only`) and writes no ledger, so there is
nothing to release. Two cautions for when Edge enforces (Azazel-Edge#412),
which intake refuses today: under a pinned clock a release would never fall
due, and the release ledger's temporary file name in Edge's `release.rs`
(`temp_path`, process id plus wall-clock nanoseconds) would repeat within one
process. Neither is reached by an observe-only Edge, which writes no ledger.

Unit tests in CI run a stand-in producer with the same wire shape, because CI
has no Edge binary: two pinned runs are byte-identical, two unpinned runs differ
in the two fields only (the mutation), and an unpinned capture diverges in all
15 samples. They also check the validator on the driven path: an empty healthy
path, a run that alone declares it `not_driven`, a dropped record and a changed
nested clock field are each refused or reported.

Without `--edge-core`, `evaluation_outcomes` stays `not_driven` and the
evidence comes from the golden fixture, as before.

### Still `not_driven`

A `not_driven` path has a reason in every run, must be empty and the same in
every run, and `audit_chain` can never be `not_driven`.

- `enforcement_lease_records`: the shipped Edge Core is observe-only
  (`ENFORCE=false`, `DRY_RUN=true`), and intake refuses any other posture
  (`EDGE_NOT_OBSERVE_ONLY`). Nothing issues an enforcement lease until
  Azazel-Edge#412 declares the single enforcement path.
- `evaluation_outcomes`, when no Edge binary is supplied.

So every sample still fails, and all current in-repo records say
`execution_result: FAIL`. With `--edge-core`, the other three paths are
byte-identical with nothing dropped in all 15 samples, and the lease path is
the only reason. This is partial consumer execution coverage, not a completed
SO-06 gate. A failed run is retained. Container runs are not hardware evidence.

Input JSON contains a nonempty `scenarios` array; each entry has a unique `id`
and nonempty `inputs` array of event objects. For example:

```json
{"scenarios":[{"id":"probe","inputs":[{"event_id":"probe-1"}]}]}
```

```sh
PYTHONPATH=src:runtime/src python3 -m tools.so06_replay inputs.json record.json \
  --commit FULL_MEASURED_COMMIT --configuration 'exact scenario/product declaration' \
  [--edge-core /path/to/azazel-edge-core]
PYTHONPATH=src python3 -m tools.service_objectives record.json
```

The CLI executes the adapter and exits 1 for FAIL (0 for PASS, 2 for invalid
input). The record retains captured runs under `configuration.replay_inputs`
with schema `azazel-nexus/so06-input/v3`; validation recomputes the observations'
comparisons and execution result. This structural recomputation returns
`shape_only`, not an attested gate verdict. Operator attestation may be added
outside the harness using the same canonical signing contract above.

Each replay invocation has `CLOCK_MONOTONIC` start/end nanoseconds, measured
around the adapter call. Each fault sample includes its `start_ns` / `end_ns`
and the baseline's `healthy_start_ns` / `healthy_end_ns`. These metadata fields
are **excluded from path byte-identity comparison**: they live outside the four
stream arrays. They remain covered by an operator signature if one is supplied.
Entire record bytes naturally vary between executions. Within stream records,
only top-level `advisory_reason_entries` and `advisory_source_generation` are
excluded; timestamps inside streams, nested fields, order, counts and audit
hashes remain significant. There is no audit rechaining during comparison.
Every path comparison retains counts, dropped-record counts, SHA-256 and byte
identity. Missing execution and observed divergence both prevent passing.
