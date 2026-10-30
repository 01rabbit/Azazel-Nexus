# Local trust replacement confirmation

The commissioning CLI requires a local interactive TTY and fresh confirmation
words for trust replacement. This guards human intent against accidental or
non-root use, not against a malicious root process. Single-use, short-lived
challenges bind the principal and proposed anchor bytes; they do not attest
human presence.

**Where it runs (ADR-0008, 2026-10-30).** `az-nexus-commission trust-repin
--reason R` no longer asks `az-commissiond`, which is masked on the ordinary
path. It runs the same `RepinConfirmation` in its own process, after
narrowing to the commissioning account (`lite_trust_ops`: a forked child as
`azcommission` with groups `azknowledge` and `azaudit-submit`, umask `0027`,
`no_new_privs`, root unreachable), under the commissioning lock
(`/var/lib/azazel/state/commission/trust.lock`). After the words are typed it
appends `knowledge.lite.trust_repin_requested` (anchor file digest and reason)
to az-auditd and **refuses before any change** if that append fails; the
outcome follows (`..._promoted` with the generation, or `..._refused`). The
commissioning ledger below still records `trust.repin.authorized` and
`trust.repin.promoted`; the two are matched by generation. The daemon keeps
its two ROOT-only verbs for a bootstrap boot, under the same lock; a root
process can complete challenge and confirm there without the CLI or a TTY.
The auditd records are `RepinConfirmation`'s own, so the daemon's confirm
needs the same receipt before any change and records the same outcome
(R390-03).

**A failure at or after the commit point is not a refusal (R390-02).**
`TrustStore.repin` raises `RepinUncertain` once the pointer may have moved,
with what it reads back: `pointer_unsynced` (the pointer names the new
generation but its rename was not confirmed durable, and the ledger has no
`trust.repin.promoted`), `ledger_incomplete` (durable; only the ledger's
promotion record is missing) or `unknown` (the pointer cannot be read). The
reply is then `promoted: true` with that `state` and generation, or
`promoted: null` with `state: unknown`; auditd records
`knowledge.lite.trust_repin_promoted` with the state, or
`knowledge.lite.trust_repin_unconfirmed`. The CLI says the replacement is in
force but not fully recorded, or that the outcome is unknown, and exits 1;
do not repeat the repin in either case. A failure before the pointer moved
stays a refusal with the old root in force (`trust_repin_refused`).

After a completed replacement, snapshot cleanup failure adds the fixed boolean
`cleanup_failed: true` to the outcome. The reported promotion and generation
remain valid; a cleanup error does not turn a committed promotion into a refusal.
The pending challenge map relies on single-threaded daemon dispatch, or on
the CLI's own single process.

`production_repin` adapts the immutable runtime request and confirmation to
`lite_trust.RepinRequest` and `lite_trust.RepinConfirmation`, then invokes the
real `TrustStore.repin`. The audit principal is the fixed string `root`, derived
only after the peer credential has uid 0 and the ROOT class. Caller arguments
cannot set it. The confirmation timestamp supplies the operation's `now`.

Production placement and permissions
------------------------------------

The fixed TrustStore root is `/var/lib/azazel/lite-trust`, provided by
`runtime_paths.lite_trust_root`. Previously the library took a caller-selected
root; the installer declared no production Lite TrustStore directory or owner.
This integration declares that dedicated directory as `azcommission:azknowledge`
mode `2750`. The installer now creates the non-login `azknowledge` consumer
account as well as `azcommission`. The consumer group has read/search access,
with no directory or file write access. No bundle, content cache or operational
generation directory belongs in this trust-only leaf.

Initial commissioning is the enrollment, `az-nexus-commission trust-enroll`
([ADR-0008](adr/0008-lite-trust-operations.md)): one audited transaction, as
`azcommission`, that writes the anchor, the revocation policy and
`trust.json` (`azcommission:azknowledge` mode `0640`) from one checked
request. Repin runs as `azcommission` and copies that file's owner to every
file it writes. `TrustStore.pin` remains a library call with no shipped
caller. The installer creates directories, never a trust root or keys. For an existing
caller-selected store, root must provision its public trust records into this
leaf with that ownership and mode before starting the daemon; there is no
automatic discovery or migration. Consumers must open `TrustStore` at the same
fixed root and supply their commissioned digest to `keys()`. The whole first
enrollment, with the exact calls and the anchor files repin also reads, is
[Knowledge Lite consumer §11](knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available).

`az-commissiond` runs as non-root `azcommission`, with supplementary group
`azknowledge` so it can preserve that GID on new files. Repin preserves the
initial trust record's uid, gid and mode, including on the generation pointer;
readable generation directories get search permission. Setgid on the trust
root also preserves the reader group for newly created children. The Lite
consumer can read the promoted generation after restart through `trust-current`.
It receives no write permission to the trust directory or ledger.

The commissioning unit's `ReadWritePaths` contains exactly the trust leaf,
`/var/lib/azazel/state/commission`, and its existing socket leaf
`/var/lib/azazel/run/commission`. Broad writes to `/var/lib/azazel/run` and
`/etc/azazel/commissioning` have been removed. The state leaf is daemon-owned
mode `0700`, holding private confirmation snapshots, refusals and its ledger;
no shared state, auditd chain, bundle cache or generation tree becomes writable.
The declarations in [layout.py](../src/azazel_nexus/layout.py),
[install.sh](../packaging/install.sh), and
[hardening.py](../runtime/src/azazel_nexus_runtime/hardening.py) agree.

The repin ledger is the commissioning daemon's own append-only hash chain at
`/var/lib/azazel/state/commission/commission.jsonl`, fixed by
`runtime_paths.commission_ledger_path`. It is separate from `refusals.jsonl`
and auditd's single-writer chain, following watchdog's `watchdog.jsonl` pattern.
The real library appends `trust.repin.authorized` before swapping the pointer,
and `trust.repin.promoted` after the durable swap. Each has the six original
provenance fields: generation, old/new bundle fingerprints, principal, `at`, and
reason, plus `old_revocation_policy_fingerprint` and
`new_revocation_policy_fingerprint` (and the event type). Policy fingerprints
are SHA-256 over `azazel-nexus/revocation-policy/v1\0` followed by canonical
JSON of the policy alone (sorted keys, compact separators); absence is JSON
`null`. Continuity floors and signed blobs are excluded from this fingerprint. Nonces and key bytes are excluded. An authorization audit
failure or failed pointer replacement keeps the old active root. A failure
after pointer replacement (directory fsync or promotion audit) may leave the new
root active and must be investigated using the pointer and ledger; it does not
prove rollback.

The challenge input remains `/etc/azazel/commissioning/repin-anchor.json`.
Its directory is `root:azcommission` mode `0750`; root provisions the file as
`root:azcommission` mode `0640` containing `{"keys": ["<Ed25519 public key hex>"]}`.
Root alone can replace/write it, and the daemon can read it through its primary
group. Keeping it out of daemon-owned state prevents the daemon from replacing
the operator's proposed input. It is read-only inside the service sandbox.
Challenge and confirm reject symlinks and non-regular/oversized input, bind its
bytes to a short-lived nonce, then pass a private immutable snapshot to the
library. The snapshot is removed after success or failure.

Verification
------------

[Runtime integration tests](../tests/unit/test_runtime_repin_integration.py)
exercise challenge → confirm with the production adapter and real library on a
temporary root using generated test keys. They verify promotion, the two audit
records and all eight provenance fields, new-key bundle verification and old-key rejection,
and retention of the old root/bundle on injected audit or pointer failure.
[Boundary scans](../tests/unit/test_runtime_repin_boundary.py) continue to pin
local commissioning reachability. Their exact string inventory now includes
the library audit event names introduced in lane B; these are events, not wire
verbs. No library socket/subprocess/runtime import or repin reachability
exception was added.


Combined authority replacement
------------------------------

The fixed anchor JSON may also include `revocation_policy`, using the explicit
[revocation policy](revocation.md) schema:

```json
{
  "keys": ["<bundle public key hex>"],
  "revocation_policy": {
    "keys": {"revoker": "<revocation public key hex>"},
    "key_roles": {"revoker": "revocation-signing"},
    "threshold": 1,
    "generation": 1
  }
}
```

This is also how a policy is introduced on a store that `TrustStore.pin`
created without one (a root enrolled by hand before ADR-0008): keep the pinned
`keys` and add the section. Unchanged bundle keys with a changed policy are a
change, so the repin is accepted.

The threshold has no default. Policy generations must increase on replacement;
they are independent of the trust-store generation reservation. Omitting the
section retains existing policy and continuity; it never removes revocation
authority. A policy-only change with unchanged bundle keys is accepted, allowing
recovery after loss of the old revocation private keys. Both roles cannot use the
same public key, including aliases. Previously revoked keys cannot return in
either role. Existing revocations and the sequence floor survive recovery.

`TrustStore.repin` composes lane A's continuity validation inside the library:
`prepare_policy_record` performs the same checks as `commission_policy` without
publishing. Repin stages `trust-generations/N.revocation.json` and `N.json`,
preserving commissioned permissions, before audit and the single `trust-current`
swap. Policy reads and continuity updates resolve through this same pointer.
Staging failure between the two records leaves both old authorities selected;
orphan records are inactive and generation reservations prevent reuse. After
pointer replacement both authorities are selected together, including when a
later fsync or promotion audit reports an indeterminate completion. There is no
two-pointer rollback window. The initial `trust.json` and legacy policy file
remain untouched. Once a generation names a policy, a missing policy record
fails closed instead of falling back to the legacy file.

The existing local ROOT challenge/confirm path snapshots the entire anchor JSON;
no runtime verb, network path, operator-plane route or key argument was added.
The [production integration tests](../tests/unit/test_runtime_repin_integration.py)
exercise introduction, recovery, invalid policy refusal, floor continuity,
new-key verification, old-key `unverified` refusal and failures between staging
parts, authorization audit and pointer promotion.


## Replacing the anchor with the keys

A key rotation changes the key material the anchor names, so the anchor
(key ids, roles, threshold, epoch, export policies) has to change with the
pin. The repin document may carry `anchors`, with exactly the fields and
checks of the enrollment request's anchor half
([knowledge-lite-consumer §11 step 3](knowledge-lite-consumer.md#step-3-the-enrollment-request)):

```json
{
  "keys": ["<next bundle public key hex>"],
  "anchors": {
    "keys": {"site-bundle-2": "<next bundle public key hex>"},
    "threshold": 1
  }
}
```

Its keys must be exactly the proposed `keys`; its threshold must be an
integer from 1 to the keys that can meet it. The repin writes
`trust-generations/N.anchors.toml` beside `N.json` (the trust record's owner,
group and mode) and marks the record `"anchors": true`; the single pointer
move then switches pin and anchor together, and every reader takes the
anchor that goes with the record it read (`TrustStore.anchors_path_for`).
Without `anchors`, the current anchor is kept; a key change that the kept
anchor could not meet is refused rather than promoted into a root that
verifies nothing. "Meet" counts what the verifier counts
(`lite_bundle.meetable_keys`): the anchor's keys whose material stays pinned,
whose id is not in its `revoked`, and that hold `required_signer_role` when
the anchor names one (R390-01). To roll a key over without a gap, repin first to both keys
with an anchor naming both, import a bundle signed by the new key, then repin
to the new key alone.
