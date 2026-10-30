# The Knowledge Lite consumer: what happens when it cannot be read

Status: **functional** (`src/azazel_nexus/lite_bundle.py`,
`src/azazel_nexus/lite_import.py`, `src/azazel_nexus/lite_cache.py`), with
unit tests and an end-to-end stage against the artifacts Azazel-Knowledge
actually emits ([#67](https://github.com/01rabbit/Azazel-Nexus/issues/67)).

**`functional` here means one thing and no more:** a correct Knowledge Lite
bundle can be imported offline by an operator and its real claims served
read-only. It does **not** mean this node's cryptographic implementation is
supported — the hand-written Ed25519 verifier is under review
([#70](https://github.com/01rabbit/Azazel-Nexus/issues/70)) — nor that this
node has an AZ-04 peer at all, nor any share of Edge authority.

This is not a release, and nothing here is *verified* in the program's sense.

Related: [the trust chain under the cache](knowledge-lite-trust.md) ·
[capability model](capability-model.md) ·
[contract ownership](contract-ownership.md) ·
[commissioning](commissioning.md) · [recovery](recovery.md)

> The verifier this document calls "injected" now has an implementation, and
> the rollback it does not mention was structurally impossible until E1. See
> [the trust chain under the cache](knowledge-lite-trust.md).

## 1. The split, and why this document exists

Knowledge ADR-0015 D7 divides the concern:

| Concern | Owner |
| --- | --- |
| Lite artifact generation, selection, export policy, signing, **consumer fixtures** | Azazel-Knowledge |
| **Embedded read-only cache, staged/atomic reader, commissioning, trust policy, `FULL -> LITE -> CORE` routing** | **Azazel-Nexus / Azazel-Boot** |

> Knowledge produces and signs; it does not decide where an artifact is
> installed, when it is trusted, or what a consumer does on its absence. […] a
> consumer that cannot read it must remain fully operational — Edge Core is
> never blocked by missing, corrupt, or expired knowledge.

**What a consumer does when it cannot read an artifact is the consumer's
decision, and Knowledge cannot prove it.** This document records the decision
and points at the tests that hold it.

## 2. Four rules, each enforced rather than described

**Absence is not an error.** A missing artifact yields `ABSENT` and a working
node. There is no path in `lite_cache.py` that raises because knowledge is
unavailable. Losing Lite is a normal degradation to `CORE`, not a fault.

**Nexus owns the reader, not the verifier — and its absence fails closed.** The
verifier is injected. The default, `refuse_everything`, verifies nothing and
admits nothing, so a caller that forgets to supply one gets a node running on
`CORE` with no Lite data. The opposite default — admitting what it cannot check
— is the one failure this module must not be able to have.

**Any exception from verification is a refusal.** Knowledge's verifier wraps
the tar decoder's error on the truncated fixture as `BundleVerifyError` with
code `BUNDLE_ARCHIVE_UNREADABLE`, and its own `negative.json` still warns not to
rely on that: *"a reader that catches only the verifier's own exception type is
one decoder change away from letting a truncated artifact through as an
unhandled error"*. So the reader catches `Exception`, deliberately, narrowly
around the verifier call and the extraction call.

**Staging is not admission.** Two of Knowledge's negative fixtures write bytes
into staging *before* failing — the truncated one leaves four complete,
digest-checked files there. Promotion happens only after a verdict of admitted,
never as a side effect of having written something.

## 3. Expiry is a serving decision, not a verification failure

The `expired` fixture is a **valid, correctly signed artifact that passes every
gate**. Expiry has no manifest field and no filename convention; it is carried
per claim and evaluated by the consumer against its own `as_of`.

So a conforming reader admits that artifact and then serves no expired
indicator from it. An expired claim is **unavailable, not merely labelled** —
it does not appear in the served list at all. The artifact around it is not
discarded: static reference material, which is versioned rather than dated,
keeps being served. That is what makes "withheld the expired entries"
distinguishable from "threw the artifact away".

An expiry that cannot be parsed is withheld too, and reported as `UNKNOWN`
rather than `EXPIRED`, so the operator plane can see that the artifact is the
problem and not the clock.

## 4. Capability degrades; authority does not move

`CORE`, `LITE` and `FULL` are capability states, not authority levels
([capability model](capability-model.md) §1). Every failure above lands on
`CORE`, and none of them moves or widens an authority — Azazel-Edge's
deterministic arbiter holds it in every state.

`capability.py` contains no authority concept at all, and a test asserts that
absence by name, because an absence is exactly what a later change quietly
fills in.

A core capability is never sourced from an optional component, so losing every
optional component at once leaves the core set intact. The converse is treated
as a different kind of event: a node missing a core capability is **broken**,
not degraded, and `state_for` refuses to report it as a lower state.

## 5. The fixtures are Knowledge's bytes, not ours

`tests/fixtures/knowledge-lite/` holds a copy of what
`Azazel-Knowledge/tools/lite_fixture.py emit` produces, with every digest
recorded in `PROVENANCE.json` and cross-checked against the digests Knowledge
states in its own `negative.json`.

Forging broken artifacts locally was rejected, for Knowledge's own stated
reason: *"A locally forged broken artifact differs from what Knowledge emits in
ways nobody can enumerate."*

**A known limit.** The copy is a snapshot. If Knowledge's emitter changes, this
copy goes stale silently — nothing in this repository can detect that, because
this repository cannot reach Knowledge. `PROVENANCE.json` records the source
revision and the command to regenerate. Stating the limit is the best that can
be done here; pretending the copy tracks upstream would be worse.

## 6. What this does not establish

- That Nexus verifies Knowledge Lite artifacts. **It does not.** It consumes a
  verdict from a verifier it does not own, and refuses when it has none.
- That any trust policy has been decided. What is trusted, and on what anchors,
  is a separate concern ([contract ownership](contract-ownership.md) §4) and is
  not settled here.
- That commissioning, activation, or a release exists. None does.
- That the behaviour has been observed on hardware. It has not; these are unit
  tests on artifacts, not a node.

## 7. Offline operator import

The only supply route. There is no download, no peer connection and no
scheduler: an operator puts an artifact in a directory and the node reads it.

### The paths, their owners and their ceilings

The installed store root is `/var/lib/azazel/knowledge`; daemon trust is
commissioned separately under `/var/lib/azazel/lite-trust`. A caller supplies neither.

| path | what it holds | who writes | ceiling |
| --- | --- | --- | --- |
| `/var/lib/azazel/knowledge/inbox` | artifacts an operator placed | the operator | 32 entries considered, 256 MiB each |
| `/var/lib/azazel/lite-trust/trust/anchors.toml` | the commissioned trust root that status, setup and `knowledge-lited` read | root, at commissioning (§11) | — |
| `/var/lib/azazel/knowledge/trust/anchors.toml` | the anchor the library `import_entry` and `azazel-nexus pack` verify against; the daemon's `knowledge.import` uses the trust root above instead | root, at commissioning (§11) | — |
| `/var/lib/azazel/knowledge/admitted` | the one artifact in use | the import service | one file, replaced atomically |
| `/var/lib/azazel/knowledge/quarantine` | refused artifacts, held | the import service | one file per refusal |
| `/var/lib/azazel/knowledge/state/watermark` | the anti-rollback counter | the import service | one integer |

The import creates `admitted/`, `state/` and `quarantine/` as `0750` (keeping
an inherited setgid bit) and removes group/other write from any it finds
loosened, whatever the importer's umask. Under the setgid operator-group store
root, a group-writable `admitted/` or `state/` would let any member swap in an
older validly signed bundle or remove the watermark: serving re-verifies the
signature and the anti-rollback watermark. Files are written `0600`.

Serving refuses a bundle below the watermark. A missing or malformed watermark
with a bundle present makes the store untrusted and blocks import until an
operator restores the state. Import inspects existing store files for regular
file type, single link, effective-uid ownership and absence of group/other write;
it records unsafe state as `lite.import.state_untrusted` and directory tightening
as `lite.import.store_tightened`, naming only directory roles. The fixed codes
are `WATERMARK_MISSING`, `WATERMARK_MALFORMED`, `WATERMARK_UNREADABLE` and
`STORE_FILE_UNSAFE`.

Imports run as the store owner (`azknowledge`, which owns
`/var/lib/azazel/knowledge`); store files owned by anyone else are refused, not
adopted. The shipped route is `az-knowledge-lited`'s ROOT-only
`knowledge.import` verb (§11 step 6), which runs as that owner, verifies
against the commissioned trust root and records every transition in
`az-auditd`. The bundle is renamed and its directory synced before the watermark
is written, so a crash leaves a bundle at or above the watermark, never below.
A crash during the very first import can leave `admitted/current.tar.gz`
without a watermark. That state is refused like a deleted watermark. To
recover, an operator moves `admitted/current.tar.gz` aside (keep it for review)
and imports again; nothing repairs it automatically.

### The caller chooses an entry, and chooses nothing else

`import_entry` takes an **inbox entry id** and an instant. Not a cache root,
not a trust key, not a policy, not a generation number, not a quarantine
path. An entry id is the artifact's own content digest, so a caller cannot
spell a path with one, and an id that is not in a fresh enumeration is
refused rather than looked for somewhere else.

### A bundle's trust material is subject matter

The anchor is read from the commissioned location only. Trust keys, permitted
signer role, security epoch and accepted export policies come from
commissioning and never from the artifact. A bundle carrying a member named
like a trust or state file is **refused** — something that tried is worth
reporting rather than ignoring.

### Quarantine holds, and does nothing else

A refused artifact is moved under its digest and is never executed,
extracted, served or retried. The audit entry carries the digest, the instant
and a structured reason. **Never the bundle's content, a claim's body, or key
material.**

### The audit records transitions, not reads

`lite.import.started`, `lite.import.admitted`, `lite.import.quarantined`,
`lite.import.rolled_back`, `lite.import.state_untrusted`,
`lite.import.store_tightened`, `lite.serving.stopped_by_revocation`. A status read
writes nothing: a ledger that grew every time somebody looked at a screen
would be a ledger nobody can read.

## 8. What the operator sees

Four axes, because one word would collapse four different next actions:

```text
Knowledge Lite: functional
    bundle integrity: admitted
    time-bound intelligence: stale
    static reference: available
    cryptographic implementation: not supported (Nexus#70 review pending)
    functional means: a correct Knowledge Lite bundle can be imported offline
        by an operator and its real claims served read-only
    it does not mean: ...
```

| axis | values |
| --- | --- |
| bundle integrity | `admitted` / `quarantined` / `unavailable` |
| time-bound intelligence | `current` / `stale` / `absent` |
| static reference | `available` / `absent` |
| overall | `available` / `stale` / `unavailable` / `quarantined` |

The row above is the **expired** bundle: its indicators have all expired and
its ATT&CK reference material has not. It reads `available (static
reference)` overall while its time-bound line reads `stale`, because static
reference is usable Knowledge and does not stop being usable when an
indicator feed goes cold. Reporting it as serving nothing would send an
operator to replace an artifact that is working.

`stale` overall is the narrower case: admitted, and the only thing left is
expired claims. Readable as history, never applied automatically.

## 9. The fixture contract, and where it came from

`contract/azazel-knowledge-lite/` holds Azazel-Knowledge's own fixtures,
pinned. `contract/azazel-knowledge-lite/FIXTURE.json` is the source manifest:

| field | value |
| --- | --- |
| `source_repository` | `01rabbit/Azazel-Knowledge` |
| `source_revision` | `2445c1b125ab1210b826b40f027d6eec4c5de125` |
| `fixture_generator_command` | `python tools/lite_fixture.py emit --out DIR` |
| `artifact_digest` | SHA-256 of every file here |
| `knowledge_contract` | format version, kind, signature scheme, what the anchor decides |
| `purpose` | the canonical input #67 verifies against |

Determinism was checked before pinning: two emissions at that revision
produced byte-identical output for all eight files, and the digests match the
values Knowledge itself declares in `negative.json` and `expected.json`.
`PROVENANCE.md` beside it records the rest.

Six cases run in CI against those bytes — valid, corrupt-signature,
corrupt-payload, corrupt-truncated, expired, absent — and each refusal code
is compared against the `expected_error_code` the producer declares.

**The fixture key is published, so it is never a production anchor.** Its
seed is in Knowledge's public source; anything "signed" by it proves nothing.
`azazel_nexus.lab_keys.PUBLIC_FIXTURE_KEYS` lists it (a test keeps the list in
step with every vendored fixture anchor), and it is refused with
`PUBLIC_FIXTURE_KEY` when it is pinned (`TrustStore.pin`), proposed by a repin
(as a bundle key or a revocation key), named by a revocation policy
(`prepare_policy_record`, which `commission_policy` and repin use, and every
reader of the policy), read from a commissioned
`anchors.toml` (`CommissionedLite.anchors`, gate `anchors`, code
`ANCHOR_PUBLIC_FIXTURE_KEY`) or found in the pin the daemon reads (status and
lookup report `trust_unreadable`; `knowledge.import` refuses with
`trust_unreadable`). `verify_bundle` itself stays a pure function of the
anchors it is given, so the conformance cases above still run against the
producer's bytes.

The only exception is a host carrying the persistent lab marker
`/etc/azazel-lab/LAB-HOST` (`lab_host.py`). A marked host is refused by
activation health, the bootstrap overlay, commissioning approval, model
admission and Mission Pack verification (`LAB_HOST_MARKER`; owner-decisions
H7, decided 2026-10-30), so a fixture key accepted there never reaches a
daemon that runs under an activation grant, and no Pack's `knowledge_lite`
slice can name a fixture-signed bundle; off a marked host that slice refuses
it like every other reader. The
[VM integration rehearsal](hil-runbooks/vm-integration.md) writes the marker
before it pins the fixture key; unit tests that drive the fixture through a
commissioned reader declare the same marker, and the end-to-end harness
re-signs the fixture's content under a key it makes for the run. There is no
flag, argument or environment variable that does the same.

## 10. The interpreter floor

CPython **3.11 or newer**, because `tomllib` is the canonical reader for
`anchors.toml` and a hand-written partial TOML parser for the trust anchor of
a signed artifact would trade a dependency for an attack surface. The
installer refuses below it **before writing anything**; there is no fallback
parser and no partial mode. See [support matrix](support-matrix.md) §3.3,
where it is recorded as a software support baseline rather than a hardware
gate.

## 11. First enrollment: from a fresh install to `available`

The order a fresh node takes to reach `state: available`, with the shipped
entries only (#93; [ADR-0008](adr/0008-lite-trust-operations.md) since
2026-10-30). The trust root is registered by one audited transaction,
`az-nexus-commission trust-enroll`, and the bundle is imported by
`az-knowledge-lited`'s ROOT-only `knowledge.import`. No step below adds a
flag, environment variable or approval.

| step | what | route | who |
| --- | --- | --- | --- |
| 1 | directories | `packaging/install.sh` | root |
| 2 | audit writer and Lite reader running | an activation grant whose policy names `azazel-auditd-loop.service` and `azazel-knowledge-lited.service` | root |
| 3 | enrollment request | file write, fixed leaf | root |
| 4 | first enrollment | `az-nexus-commission trust-enroll` → child as `azcommission` → `lite_enrollment.enroll` | root |
| 5 | bundle in the inbox | file copy | root |
| 6 | first import | `az-nexus-commission knowledge-import` → `az-knowledge-lited` `knowledge.import` → `LiteImport.import_entry` | root |
| 7 | status | `azazel-nexus status`, `azazel-nexus setup` | root |
| 8 | store-local anchor, only for a Mission Pack on this store | file copy | root |

Status reports reason `trust_unreadable` on a fresh install, `no_bundle`
after step 4 and `available` after step 6.
`tests/unit/test_knowledge_lite_enrollment.py` runs the documents and calls
below against the production code in that order and checks those three
reasons; `tools/e2e_lite_trust.py` runs them with the real accounts and
daemons as root.

### Step 1: directories

The installer creates `/var/lib/azazel/lite-trust` as
`azcommission:azknowledge` `2750`, `/var/lib/azazel/knowledge` as
`azknowledge:azazel-operator` `2750` and `/etc/azazel/commissioning` as
`root:azcommission` `0750` ([layout.py](../src/azazel_nexus/layout.py)). It
creates no trust file, key, anchor or inbox, and it masks every governed
unit.

### Step 2: the audit writer and the Lite reader

Both the enrollment and the import record themselves in az-auditd before
they change anything, and are refused without it. On the ordinary path the
writer is `azazel-auditd-loop.service`
([ADR-0008](adr/0008-lite-trust-operations.md) D1); it runs only under an
activation grant, like `azazel-knowledge-lited.service`. Name both in the
activation policy, publish the generation and sign the approval
([activation rehearsal](hil-runbooks/activation-rehearsal.md)); the next
boot's pass grants them. A node that has run only the supporting-only
bootstrap has no commissioning evidence yet, and step 4 refuses there
(`evidence_unavailable`).

### Step 3: the enrollment request

One closed JSON document (schema `azazel-nexus/lite-enrollment/v1`) names
everything the trust root will hold. Public keys only, as 64 lowercase hex
digits; key ids from `[A-Za-z0-9._-]` (the id the bundle's `manifest.sig`
names).

```json
{
  "schema": "azazel-nexus/lite-enrollment/v1",
  "commissioning_digest": "<commissioning digest>",
  "keys": {"site-bundle": "<bundle public key hex>"},
  "threshold": 1,
  "minimum_security_epoch": 0,
  "revocation_policy": {
    "keys": {"site-revoker": "<revocation public key hex>"},
    "key_roles": {"site-revoker": "revocation-signing"},
    "threshold": 1,
    "generation": 1
  }
}
```

Optional fields: `key_roles` (a role per bundle key id), `required_signer_role`
and `accepted_export_policy_digests` (a list of `sha256:` digests). The
request is refused, and nothing is written, when:

- `threshold` is not an integer from 1 to the number of bundle keys that can
  meet it (those holding `required_signer_role` when it is set): zero, a
  negative number, `true`, `"1"` and a threshold above the keys are all
  `threshold_invalid`; the revocation threshold likewise against the
  revocation keys;
- a key holds both roles, by material or id, or a bundle key is given the
  role `revocation-signing` (`role_conflict`);
- any key is the published fixture key (`public_fixture_key`, §9);
- `commissioning_digest` is not the digest of this node's verified
  commissioning (`binding_mismatch`), or the evidence cannot be verified
  (`evidence_unavailable`): the digest is the SHA-256 of the signed full
  commissioning proposal, the same value the activation generation and
  approval carry (`observe_baseline.evidence_commissioning_digest`);
- anything else is outside the closed shape (`request_invalid`).

```sh
sudo install -m 0640 -o root -g azcommission lite-enrollment.json /etc/azazel/commissioning/lite-enrollment.json
```

### Step 4: first enrollment (`trust-enroll`)

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus_runtime.commission_cli trust-enroll
```

`sudo` replaces `PATH` with its `secure_path`, which does not contain the venv,
so a bare `az-nexus-commission` or `azazel-nexus` is not found under `sudo`;
this procedure runs the console scripts' modules with the venv's interpreter
instead, as the [activation rehearsal](hil-runbooks/activation-rehearsal.md)
does.

The command needs a local terminal. It verifies the node's commissioning
evidence, shows the request digest, the key counts, the thresholds, the
epoch, the export policies and whether the binding matches, and asks you to
type fresh confirmation words. Then a child process that has become
`azcommission` (the commissioning daemon's account and groups, no way back to
root) records `knowledge.lite.trust_enroll_requested` in az-auditd, writes
`trust/anchors.toml`, `revocation-policy.json` and, last, `trust.json` (all
`0640`, the directory `2750`, owner `azcommission`, group `azknowledge`), and
records `knowledge.lite.trust_enrolled`. It prints one JSON object of fixed
words and numbers (`enrolled`, `code`, `bundle_keys`, `threshold`,
`revocation_keys`, `trust_fingerprint`, `audit_complete`) and exits 0 only
for an enrollment whose records both reached auditd.

- If auditd does not take the first record, nothing is written
  (`audit_unavailable`).
- If the request file changed after you confirmed it, nothing is written
  (`request_changed`).
- A root already enrolled is refused (`already_enrolled`): later changes are
  `trust-repin` ([trust repin](trust-repin.md)) and
  `knowledge-revocation-accept` ([revocation](revocation.md)).
- **Interrupted.** Until `trust.json` is renamed into place, no reader trusts
  the root (status `trust_unreadable`). Run the same command again: it
  replaces exactly what the interrupted run left and completes. Anything
  else in the root refuses the request (`trust_root_not_empty`) and needs
  inspection.

Status now reports `no_bundle`.

### Step 5: the bundle in the inbox

The installer creates no inbox.

```sh
sudo install -d -m 2750 -o azknowledge -g azazel-operator /var/lib/azazel/knowledge/inbox
sudo install -m 0640 -o azknowledge -g azazel-operator site-lite.tar.gz /var/lib/azazel/knowledge/inbox/site-lite.tar.gz
sudo sha256sum /var/lib/azazel/knowledge/inbox/site-lite.tar.gz
```

The SHA-256 hex is the entry id (§7). The store is `2750` and the bundle
`0640`, both `azknowledge:azazel-operator`, so an account outside
`azazel-operator` cannot read it; the checksum runs as root like every other
line of this procedure.

### Step 6: first import (`knowledge.import`)

Root asks `az-knowledge-lited` to import the entry. The daemon runs as the
store owner `azknowledge`, which the import requires, and is the only shipped
importer: its `knowledge.import` verb, on the operator socket only and for
ROOT only, takes the entry id and nothing else. It verifies the bundle against
the commissioned trust root it serves from (the pin, the anchor that goes with
it and the cumulative revocation list; never the store-local copy) and
appends `knowledge.lite.import_*` records to `az-auditd` through auditd's
append-only `audit-submit` listener. The start is recorded before the store
is touched: if auditd cannot record it, the import is refused with
`audit_unavailable` and the store is not changed. Every other refusal
(`refused` below) admits, quarantines and moves nothing and leaves the
watermark as it was; the store directories may already have been tightened
by then (§7), which stays and is recorded as
`knowledge.lite.import_store_tightened`. A repin or an accepted revocation
list that lands while the bundle is verified is caught just before promotion
(`trust_changed`).

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus_runtime.commission_cli knowledge-import --entry "<entry id>"
```

The command prints one JSON object of fixed words and numbers: `outcome`
(`admitted`, `quarantined`, `refused` or `failed`), `refused`
(`not_in_inbox`, `entry_changed`, `state_untrusted`, `trust_unreadable`,
`unverified`, `trust_changed`, `clock_untrusted` or `audit_unavailable`),
`state`, `bundle_version`, `gate`, `code` and `audit_complete`. It exits 0
only for an admitted bundle whose records all reached auditd. A refused
bundle is quarantined; a bundle whose digest, generation or signing key the
revocation list names is quarantined with `BUNDLE_REVOKED`, so a revoked
bundle never replaces the admitted one or raises the watermark. An import
holds the daemon's single request loop while it verifies the archive, so
status and lookup wait for it (lookups past their deadline read as Knowledge
unavailable, which never blocks the deterministic path).

### Step 7: status

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus.cli status
sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus.cli setup
```

Status shows `state: available` and `reason: available`. Setup shows
`knowledge-store: done` and `knowledge-trust: done`. `knowledge.status` from
`knowledge-lited` uses the same reader.

### Step 8: the store-local anchor (Mission Pack only)

`azazel-nexus pack` and the library import without commissioned trust read
`/var/lib/azazel/knowledge/trust/anchors.toml`, not the trust root. The
daemon import and status never read it. Only when a Mission Pack names this
store, copy the enrolled anchor there:

```sh
sudo install -d -m 2750 -o root -g azknowledge /var/lib/azazel/knowledge/trust
sudo install -m 0640 -o root -g azknowledge /var/lib/azazel/lite-trust/trust/anchors.toml /var/lib/azazel/knowledge/trust/anchors.toml
```

After a repin that replaces the anchor
([trust repin](trust-repin.md#replacing-the-anchor-with-the-keys)), copy
`/var/lib/azazel/lite-trust/trust-generations/N.anchors.toml` the same way.

### What was rehearsed

On 2026-10-30 (ADR-0008) steps 3 to 7 ran with the real accounts and daemons
in a disposable Debian 13 container as root (`tools/e2e.py`, stages
"Knowledge Lite trust enrollment" and "Knowledge Lite import, repin,
revocation and audit stop"): az-auditd as `azaudit`, az-knowledge-lited as
`azknowledge`, the enrollment child as `azcommission`, keys generated for
the run and never written to disk. The commissioning evidence was supplied to
the transaction (the container has no signed full commissioning); the real
`trust-enroll` entry on a pseudo-terminal refused there with
`evidence_unavailable`. **Container evidence of real processes, not of
systemd, a VM or hardware.**

Earlier runs of the hand procedure this section replaced (2026-10-24 in a
container and on the Debian 13 test VM, 2026-10-25 twice more on the VM)
are recorded in the history of this file and on #93. They reached
`available` through the supporting-only bootstrap and the rehearsal-only
start of `knowledge-lited`, not through an activation grant.

## Milestone 1 daemon status

`az-knowledge-lited` takes no command-line arguments and serves
`knowledge.status`, with no arguments, and `knowledge.lookup` on
`/var/lib/azazel/run/knowledge/knowledge.sock`. The verb admits OPERATOR and
SERVICE; production service principals are limited to `azmioentry`,
`azarbiter` and `azmio` (the locald systemd User). Lookup admits SERVICE only. Kernel credentials and the shared `PrincipalPolicy`/transport
perform admission. Protocol refusals go to this daemon's
`/var/lib/azazel/state/knowledge/refusals.jsonl`, and lookup events to
`events.jsonl` beside it; both are bounded diagnostic logs (#211, "Refusal
logs" in [operations](operations.md)).

The installed store root is `/var/lib/azazel/knowledge`, as listed in §7 above.
`LiteImport` still owns
`inbox`, `admitted/current.tar.gz`, `quarantine` and `state/watermark`. The
daemon imports only through its ROOT-only `knowledge.import` (§11 step 6),
never on its own. It never enrolls, repins, accepts revocations, promotes
trust or repairs files: those are the commissioning account's, through root's
`az-nexus-commission` transactions
([ADR-0008](adr/0008-lite-trust-operations.md),
[revocation](revocation.md#accepting-a-list-on-a-node)). A successful status
request writes neither store nor trust nor a read event.

Trust is a separate commissioner-owned root, `/var/lib/azazel/lite-trust`,
read-only to the daemon. Its `trust/anchors.toml` supplies the bundle's key IDs,
threshold, signer-role, security-epoch and export-policy constraints. These
keys are intersected with the current `TrustStore` pin (`trust.json` or the
repinned `trust-current` generation). Store-local `knowledge/trust` anchors
are deliberately ignored by daemon status and by `knowledge.import`; the
library `import_entry` without commissioned trust and `azazel-nexus pack`
still read that store-local copy, so commissioning provisions compatible
public anchor metadata and pins at both places. Missing or inconsistent metadata never
causes a fallback to store-local trust.

`KnowledgeLite`'s content-addressed generations (`live`, artifact/signature
objects) are a different storage format from `LiteImport`'s tar store. The
daemon does not point `KnowledgeLite.read` at the tar store or pretend that
repinning imports a bundle. The read-only `lite_import.status_summary` adapter
verifies the tar and uses `KnowledgeLite.revocations` at the trust root for
the existing commissioned policy, role separation and continuity checks.
The commissioning digest comes from the commissioner-written current trust
record and must match its revocation policy; this is public trust-record
consistency, not a fresh commissioning evidence/activation attestation.
Signed revocations and their continuity record also reside at the trust root.
The bundle version is checked against revoked generations; its archive digest
and verified signing keys are checked against the cumulative revocation list.

The result has exactly nine keys, in this order: the four diagnostic keys and
five display facts (`lite_import.STATUS_KEYS`):

| key | values |
| --- | --- |
| `state` | `available`, `stale`, `unavailable`, `quarantined` |
| `reason_code` | `available`, `stale`, `unavailable`, `no_bundle`, `quarantined`, `bundle_refused`, `state_untrusted`, `revoked`, `unverified`, `trust_unreadable`, `store_unreadable` |
| `generation` | verified bundle version (at most signed 64-bit maximum), otherwise null |
| `freshness` | `current`, `stale`, `absent` (time-bound claims axis) |
| `signer_key_ids` | the commissioned anchor key ids whose signatures verified (sorted, at most eight), otherwise null |
| `bundle_digest_short` | `sha256:` and the first twelve hex digits of the admitted archive digest, otherwise null; a display aid, never compared |
| `static_count` | rows without an expiry (static reference), otherwise null |
| `current_count` | dated rows not yet expired at the query instant, otherwise null |
| `next_expiry` | the earliest expiry among current rows, RFC3339 UTC truncated to seconds, or null |

The display facts are set only when a verified, trusted, unrevoked bundle was
read (`available` or `stale`); every refusal leaves all five null. They carry
no key material, full digest, path, address or exception text. `azazel-nexus
status` prints them under Knowledge Lite as `bundle: … (shortened); signing
key ids: …` and `claims: static N; current N; nearest expiry: …`.

`state_untrusted` means the admitted bundle is below the anti-rollback watermark
or its watermark is missing or malformed (state `quarantined`); no bundle is
served. With state `unavailable` it means the wall clock is behind the
daemon's persisted clock floor, or that floor cannot be read or kept (see
below); nothing -- dated or static -- is served.

### Wall-clock floor

`query_as_of` is the wall clock, and each dated row's expiry is compared with
it. A clock moved backwards would make expired rows current again, so
`az-knowledge-lited` keeps a raise-only floor: the latest instant it has
observed, in `/var/lib/azazel/state/knowledge/clock-floor.json` (its own
private `0700 azknowledge:root` state leaf, already in the unit's
`ReadWritePaths`; no new write permission). The in-process floor is exact.
The file holds a UTC instant truncated to whole seconds, never later than an
observed one, and is raised -- before the reply is returned -- whenever an
observation reaches a later second: at most one write per second. After a
crash and restart, only a regression back into the same second as the last
answered instant goes undetected.

Two limits are deliberate. The floor moves only when a request is answered,
so a clock moved back while nobody asked is compared only with the last
answered instant. Nothing bounds a forward jump (for example by the time of
signed material): a clock that runs ahead raises the floor with it, and
whether to add such a ceiling is an owner decision.

| condition | `knowledge.status` | `knowledge.lookup` |
| --- | --- | --- |
| clock at or after the floor | unchanged | unchanged |
| clock behind the floor (also after a restart) | `unavailable` / `state_untrusted` | no refs, `state_untrusted` |
| floor file malformed, non-canonical, a link, not a regular file, group/other writable, linked twice, unreadable, or the leaf missing/unprotected; or the raise cannot be written | `unavailable` / `state_untrusted` | no refs, `state_untrusted` |
| floor file absent (first start, or removed) | unchanged; the floor is created | unchanged |

The daemon records `knowledge.clock_untrusted` with cause `regressed` or
`floor_unavailable` in its own `events.jsonl` once per transition, with no
instant or path. Callers see the existing `knowledge_unavailable` failure.
The administrator-confirmed `bootstrap_clock` anchor is not used: it lives in
root-only `/etc/azazel/bootstrap`, is bound to one boot and exists only in the
administrator-managed time mode, and `azknowledge` must not read it.

Recovery after a clock that once ran ahead: correct the clock first, then, as
root, remove `clock-floor.json` and restart the unit. The daemon then records
`knowledge.clock_floor_created` in its `events.jsonl` -- with cause
`absent_after_use`, because the leaf already holds its other state -- so a
removal is visible afterwards; cause `initial` appears only for a first start
on an empty leaf. Any recreation with `absent_after_use` that no administrator
performed is worth investigating. This is local trust; the floor protects
against a clock moved backwards, not against root. None of this changes Edge
readiness, leases, enforcement or deterministic authority.

**Limit: snapshot restore.** A VM or disk snapshot restored to an earlier
point rolls `clock-floor.json` back with the rest of the state tree, so the
floor agrees with the restored clock and rows that expired after the snapshot
can be served again. The floor does not defend against that; only an anchor
outside the restored storage could.

**Storage.** The floor is written with fsync (file, then directory) at most
once per second while requests arrive. If it cannot be written -- for example
the filesystem is full -- Knowledge Lite is `unavailable` / `state_untrusted`,
static reference included, until it can be written again.

**Acceptance on target hardware (not yet measured).** On the deployment's
storage (for example an SD card or eMMC), measure the floor's fsync latency
and the bytes written per day under a realistic request rate, and record both
with the device model. CI and VM runs do not measure wear or latency of the
real medium.

Static references can make the state `available` while freshness is `stale`
or `absent`; the existing three-axis bundle rules still apply. No claim body,
key, digest, filesystem path or exception text appears in the reply.
Unreadable store/trust yields `unavailable`; missing, malformed or unverifiable
revocation policy/list yields reason `unverified`. The daemon continues to
answer diagnostics in these conditions. A refused admitted tar or a store
holding only quarantined artifacts reports `quarantined`. None of these
states changes Edge readiness, leases, enforcement or deterministic authority.


## Bounded advisory context lookup

`knowledge.lookup` accepts exactly `{"technique_ids": ["T1110", "T1110.001"]}`
as its arguments, no payload. The list has at most eight items, each matching
`T[0-9]{4}(\.[0-9]{3})?`. Empty lists return no context. Unknown arguments,
invalid IDs and OPERATOR-only principals are refused by the existing transport
and `PrincipalPolicy`. `azmio` is included in the daemon's resolved service
accounts; `knowledge.status` retains its existing admission and response shape.
No import, trust, revocation or promotion authority is added.

The response has `refs` (at most sixteen items) and `reason_code`. The daemon
retains a deterministic prefix fitting a 60 KiB JSON envelope, including ASCII
escaping overhead, below the existing 64 KiB transport limit. Each frozen
library `KnowledgeRef` carries `technique_id`, `name` (120 characters maximum),
`summary` (240 maximum), `claim_id`, `bundle_digest`, and `freshness` (`current`
or `static`), plus `source_kind: knowledge_lite`, the authenticated bundle
`generation`, `trust_check: verified`, `as_of` (the lookup's own
`query_as_of`, RFC3339 UTC truncated to seconds with `Z`) and `citation` (the
signed manifest's `profile.provenance.<dataset>.dataset.citation` for the
row's `tables/<dataset>.jsonl` member, as plain text of at most 160
characters, or empty when the bundle declares none or its text does not settle
under that cleaning). `read_knowledge_refs` requires exactly these eleven
fields at every process boundary, and a citation that is a fixed point of the
same plain-text cleaning. These are
read-time provenance, not approval or authority. `attack_stix.flatten` obtains technique IDs from MITRE external
references and preserves the technique name and description; Knowledge's native
ATT&CK table uses `technique_id` as the stable primary key. That key is both
`technique_id` and `claim_id` here, qualified by the authenticated bundle digest.
A STIX object UUID is not invented. Descriptions become plain text summaries
with HTML, Markdown formatting and links removed, whitespace collapsed, then
truncated. Missing descriptions produce an empty summary, as in the pinned
producer fixture. A missing or empty name is not served.

`lite_import.lookup_context` returns a tuple; `lookup_context_reading` exposes
the same tuple plus a fixed `reason_code`. `available` means at least one
reference. `no_context` means an empty query or no matching usable row (including
expired rows). Trust, revocation and storage failures use the existing status
reason codes. None raises merely because context is absent. Selection follows
`iter_served` in sorted member and row order, retains only sixteen references,
and ignores repeated query IDs. Current claims pass the existing expiry check;
rows without `agg_next_expiry` are static references. Authentication still reads
and verifies the bounded archive in full; streaming selection does not imply
constant-memory archive verification or a new admission path.

Each lookup rechecks the same separate commissioned trust, signatures
and cumulative revocations as status; a repin observed during the read withholds
the result. Only the admitted tar is read. Lookup events contain requested
technique IDs and the result count, never names or descriptions. They are
diagnostic records in the daemon's bounded `events.jsonl`, not audit evidence:
not hash-chained, and rotated away at a fixed size. Status remains free of read
events. Protocol refusals are still recorded, in the bounded `refusals.jsonl`.

`azazel_nexus_runtime.knowledge_client.lookup_context` uses the existing
AF_UNIX exchange with a default 0.5-second monotonic deadline, verifies the
`azknowledge` socket owner and peer credentials, and validates the bounded
response. Missing context returns an empty tuple; transport, deadline, invalid
response and unavailable trust/store conditions raise only
`KnowledgeUnavailable("knowledge unavailable")`. Locald main wires this client and maps
that exception to its unavailable audit path, continuing without knowledge.
No network request or retry occurs.

The installer creates a separate service-client socket directory,
`/var/lib/azazel/run/knowledge-read`, mode `2710`, owned by
`azknowledge:azknowledge-read`. Knowledge Lite binds `knowledge-read.sock`
there with mode `0660`, alongside the unchanged operator socket at
`/var/lib/azazel/run/knowledge/knowledge.sock`. Both use the existing transport
and PrincipalPolicy; lookup still admits SERVICE only. Locald's generated unit
has `SupplementaryGroups=azknowledge-read azmission-read`, and its client checks
the dedicated socket GID as well as the `azknowledge` owner and peer credentials.
`azmio` never joins `azazel-operator` and cannot reach audit, commissioning,
watchdog or fetch sockets through these groups. Operators retain their existing
socket and status access. No ACL tools are required.
