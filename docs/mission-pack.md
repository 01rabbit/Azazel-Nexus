# Offline Mission Packs

Mission Packs select already installed, verified assets as one signed unit.
They confer no Edge authority, enable no unit and install no code. The
[Activation Controller](commissioning.md) still owns operational activation;
[Edge decides and enforces](contract-ownership.md). Packs cannot require a
remote provider, Knowledge full node or Deception full node. Optional services
retain their existing FULL → LITE → CORE degradation paths.

These are **Nexus-local versioned records**, not a Fabric wire standard or a
new Fabric release pin. The implementation composes the existing
[model import](model-import.md), [Knowledge Lite import](knowledge-lite-consumer.md),
`GenerationStore`, exact compatibility tuples, resource profiles and
[Core reserve](core-reserve-measurement.md). HG-05 remains open: without an
admissible measured reserve, verify/stage/activate/rollback refuse. Tests inject
a reserve result explicitly; the product ships no measurement.

## Media and signature

A removable-media directory contains exactly `mission-pack.signed`, a regular
file, with no symlink, payload, archive, installer or extra member. Its bytes
are 64 bytes of detached Ed25519 signature followed by UTF-8 JSON. Verification
covers the exact payload bytes prefixed with the fixed domain:

```python
b"azazel-nexus/mission-pack/v1\x00"
```

A catalog or registry signature cannot be used here, even under the same key.
The maximum JSON payload is 1 MiB and there are at most 128 components. JSON
objects reject duplicate and unknown manifest/component fields.

The manifest fields are:

| Field | Meaning |
| --- | --- |
| `schema` | `azazel-nexus/mission-pack/1` |
| `pack_version` | Local numeric `major.minor.patch`; used for the rollback floor |
| `signer`, `signing_epoch` | Commissioned signing-role key ID and exact current trust epoch |
| `issued_at`, `expires_at` | UTC `Z` timestamps; interval is start-inclusive, end-exclusive |
| `rollback_predecessor` | SHA-256 of the previous complete signed pack, or null on first installation |
| `features` | Unique symbolic features; subset of commissioned supported features |
| `compatibility` | Exact `TestedTuple.as_record()` including security epoch, adapter digest, resource profile and oldest permitted rollback version |
| `memory_need_mib` | Aggregate declared RAM need; cannot undercut commissioned per-asset RAM floors |
| `total_size_bytes` | Exact sum of selected asset sizes, bounded by local selection budget |
| `components` | List of exact installed selections, described below |

Every component has exactly `kind`, `id`, `digest` (`sha256:<64 lowercase hex>`),
`size_bytes` and `version`. IDs and versions are bounded symbolic strings,
never paths. Required kinds are `adapter`, `policy`, `runbook` and
`reasoning_playbook`. The only additional kinds are `model`, `knowledge_lite`
and `deception_asset`. Unknown kinds fail closed. A policy selection is an
installed advisory data reference; no Edge policy writer exists in this path.
There is no representation for installers, hooks, units, containers, topology,
network settings, trust updates or enforcement authority.

Exact versions, sizes and hashes must match the commissioned installed
inventory, keyed by `(kind, id, digest)`, and the bytes are rehashed with
bounded reads. Multiple installed digests may share an ID, allowing a new pin
to coexist with the retained pin for rollback. Each pack selects one pin per
`(kind, id)`; duplicate inventory triples are refused. Models additionally
pass `ModelImport.reading_for()` against the existing signed catalog and
installed generation. Their commissioned RAM floor must cover the catalog's
declared minimum. Lite references additionally pass `LiteImport`'s existing
admitted-bundle signature/revocation verification and exact bundle version.
Claim freshness and serving stay with Lite; a pack never manufactures claims
or resets a watermark. No asset is copied from media or reimported.

## Operations

```text
azazel-nexus pack inspect /media/mission --dry-run
azazel-nexus pack verify /media/mission --dry-run
azazel-nexus pack stage /media/mission --actor operator --dry-run
azazel-nexus pack stage /media/mission --actor operator
azazel-nexus pack activate GENERATION --actor operator --reason 'reviewed selection' --dry-run
azazel-nexus pack activate GENERATION --actor operator --reason 'reviewed selection'
azazel-nexus pack rollback --actor operator --reason 'restore previous selection' --dry-run
azazel-nexus pack rollback --actor operator --reason 'restore previous selection'
```

Inspect is an explicitly **untrusted** bounded preview and needs no local
configuration. Verify writes nothing. Stage checks signature, hashes, exact
compatibility, signing epoch, revocations, component/feature allowlists,
rollback ancestry (including stored digest/tree integrity of the retained
predecessor and the new tuple’s oldest rollback version), selection capacity, disk headroom and RAM after the Core
reserve **before any staging write**. Disk needs include the new selection
record, framing/audit allowance and retained headroom; installed asset bytes
are referenced and already consume local disk. Generations are retained rather
than deleted. All dry runs are read-only and run the applicable gates.

Stage reports a generation number for explicit operator review. Activate takes
that reviewed number and repeats all gates against the staged signed bytes and
current commissioned state. A stale staged predecessor cannot be activated.
Root is required for CLI writes. There are no command-line options for
replacement keys, state roots, reserve values, download URLs or network access.

## Local configuration and storage

Provisioning supplies root-owned `/etc/azazel/mission-pack.json` (not writable
by group/others), with schema `azazel-nexus/mission-pack-config/1`. It is never
read from media. It contains:

- `trusted_keys` (signer ID → public-key hex), `signing_epoch`, `revoked_keys`,
  `revoked_packs`, `commissioning_digest`, and `allowed_features`.
- `host`, with the `HostFacts` fields: `os_abi`, `architecture`, `cpu_features`,
  `fabric_version`, `fabric_features`, `schema_features`, `profile`,
  `overlay_schema`, `security_epoch`; plus `tested_tuples` in `as_record()` form.
- `host_digest` and `reserve_path`, referring to the externally recorded HG-05
  evidence. CLI RAM is read from the OS, not from the pack or configuration.
- `assets`, each with `kind`, `id`, `path`, `digest`, `size_bytes`, `version`,
  `memory_need_mib`. Provisioning owns the verification/provenance of these
  installation pins; the pack cannot add to this inventory. Multiple entries
  with the same kind and ID require distinct digests. Data assets can
  declare zero RAM; model/adapter RAM must be bounded conservatively.
- Optional `models_root` (existing model slice and its independent commissioned
  catalog trust), and `lite_root` (existing Lite slice and independent anchors).
- `max_pack_bytes` (complete signed metadata size), `max_selected_bytes` (sum of
  installed selections), `disk_headroom_bytes`. API defaults are 1 MiB, 64 GiB
  and 2 GiB respectively; CLI requires explicit commissioned values.

State is fixed at `/data/azazel/mission-packs`. The CLI checks the backing
volume with the existing read-only LUKS check and refuses unverified encrypted
storage. Library callers must supply an equally protected commissioned root;
this is a trusted local storage API, not a filesystem security boundary against
its privileged owner. Trust anchors, revocations, reserve evidence, installed
inventory and admission/audit state stay outside the signed pack. No private
key material is accepted or logged.

The local admission schema `azazel-nexus/mission-pack-admission/1` records the
pack digest, actual predecessor generation, actor and admission time. Each
immutable generation contains exactly the signed pack and its admission
record. It uses the existing `GenerationStore` digest/read-back/fsync/promotion
implementation. Pack selection generations live separately from operational
Edge generations; they cannot become an Activation Controller authorization.

## Interruptions, recovery and rollback

A single writer lock serializes stage/activate/rollback. Staging publishes a
complete immutable generation and appends admission evidence without changing
`current`. An interrupted staging tree remains hidden and unreferenced. A
published generation lacking admission audit evidence cannot activate; a new
stage may be performed after inspection. Retained/orphan generations consume
disk and are never automatically promoted or deleted.

Activation writes an append-only, hash-chained `commit_intent` before publishing
`current` with a same-directory temporary, fsync and atomic replace. Audit
records include reason, actor, pack digest and old/new generation numbers and
digests. After publication it appends `completed`. Failures before the replace
leave the prior complete selection; failures after replace expose the new
complete selection. The pointer's directory is fsynced for durability.

After interruption, read `MissionPack.status()` and verify the indicated
`GenerationStore` tree and `AuditLedger`. A durable intent without completion
is reconciled against `current`: matching `to_generation` means publication
became visible; matching `from_generation` means the previous selection remains.
A post-replace I/O error is an uncertain commit, so inspect before retrying.
The next successful write operation, or an explicit `MissionPack.recover(now=...)`,
verifies the audit chain and active generation under the writer lock. If the
latest unfinished intent matches the active generation, tree digest and pack
digest, it fsyncs the pointer directory and appends the missing `completed`
event from that intent, preserving its original attribution and recording
`recovered_at` and `commit_intent_hash`. Recovery is idempotent. An intent whose
target is not active gets no completion and never changes the pointer.
Status, verify and dry runs remain read-only. Hidden temporary trees/pointer files can
be inspected by an administrator; none is treated as active. On first-install
failure with no active selection the status/refusal explicitly reports
**CORE (no previous provider)**. CORE and Edge units are never disabled by a
pack failure.

Rollback selects only the actual prior admitted generation, rechecks its
signature/expiry/revocation, installed assets, compatibility, current trust
epoch and resources, and enforces the active tuple's oldest rollback version.
It uses the existing generation rollback metadata rules to publish the prior
contents as a new monotonically numbered generation, recording the actual
selection ancestry separately from storage publication ancestry. It then uses
the same intent/pointer/completion transaction. A revoked or expired rollback target is refused. A revoked or expired active
pack does not block replacement or rollback away from it: the retained source
is checked only for its stored admission digest and generation tree integrity,
with its version used to enforce the relevant rollback floor. Its expiry,
revocation, current signing epoch, inventory, compatibility and resources are
not re-admitted merely to establish ancestry; the replacement or rollback
target still passes every candidate gate, including signature, current trust,
expiry/revocation, installed pins and resources. `MissionPack.status(now=...)`
reports `state: degraded` and reasons (`revoked pack`, `revoked signer`,
`expired pack`) while leaving the complete active selection in place; without
`now`, status uses current UTC. Recovery neither clears revocations nor extends
validity, promotes a pack automatically, disables units, or restores a missing
asset. An operator must stage/activate a valid replacement or request a valid
rollback target. The old pin must still be installed for rollback to succeed. No previous provider means rollback refuses with CORE
explicitly reported.

`tests/unit/test_mission_pack.py` covers whole-pack validation, real model/Lite
composition, failures before writes, injected stage/activation/rollback
interruptions, retained generations, CLI dry runs and unchanged Edge inspection
and Activation Controller state. The Mission Pack modules import no network,
process or runtime-egress implementation; the existing boundary scans remain
unchanged. Injected interruption tests exercise filesystem ordering; they do
not claim physical power-cut or hardware measurement evidence.

See [Reasoning playbooks](reasoning-playbooks.md) for baseline/site data layers
and the signed component digest required when loading their installed bytes.

## Local advisory consumption

Locald now reads the active `reasoning_playbook` selection using the existing
commissioned configuration and encrypted store paths. The read-only
`playbook_selection.active_playbooks` resolver accepts a commissioned PackContext
(or its read-only selection subset), requires active status, verifies retained
generation/admission integrity, and additionally verifies the retained signature,
current trusted signer, signing epoch and validity interval. It resolves only
installed inventory paths and loads the exact selected digest, size and version.
It composes one baseline followed by site layers in manifest order; no baseline,
multiple baselines, missing assets or verification failures remove all playbooks.

Locald caches successful composition and stable failures, checks pointer/configuration/retained-file/
asset metadata on each request and reloads on changes or expiry. Failures discard
the cached library; verification retries when watched metadata changes. Audits report fixed reason
and ordered library IDs/versions/digests only. This consumer never writes pack
state or promotes a generation; existing model admission remains closed.

Packaging creates the dedicated `azmission-read` group and grants it to locald
through the generated unit's supplementary groups. The existing commissioned
configuration becomes `0640 root:azmission-read`; the reader still rejects
non-root ownership and all group/other write bits. Installed inventory
`reasoning_playbook` files receive group read, with group traverse on private
ancestors where required. Their owners and write permissions remain unchanged;
unsafe writable or symlink paths refuse provisioning. Other asset kinds are not
granted access. Install playbooks outside locald's writable/private paths, as
listed in [Reasoning playbooks](reasoning-playbooks.md).

The installer creates `/data/azazel/mission-packs` and `generations` as
`2750 root:azmission-read` only on a backing volume passing the existing LUKS
check. This store lives under the commissioned encrypted `/data` mount; the
installer neither mounts storage nor creates an unencrypted replacement. If
storage is unavailable/unverified it prints `MISSION PACK STORE NOT PROVISIONED`;
mount the commissioned encrypted volume and rerun the installer. DESTDIR staging
projects the same modes without claiming encryption evidence.

Published generation directories/trees use `2750`, their files and `current`
use `0640`, with the reader GID inherited from the setgid store. Staging stays
private until complete. The installer also upgrades existing published
selections; hidden interrupted stages and writer audit/lock files remain private.
Other GenerationStore consumers retain their private defaults. Root remains the
only writer; CLI encryption/admission checks are unchanged. Rerun installation
after provisioning the config or new inventory assets. The installer never
invents commissioned configuration or signs/selects a pack.

Unreadable state still gives audited `store_unreadable` with no playbooks; an
absent current pointer is `no_pack`. See [Reasoning playbooks](reasoning-playbooks.md)
for cache behavior and the complete reason vocabulary. The existing runtime root convention applies;
there is no new path override or environment variable.
