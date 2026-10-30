# Revocation authority and signed lists

Revocations use a commissioning policy independent of bundle admission. The
local policy record (initially `revocation-policy.json`) records public keys by key ID, `key_roles`, an
explicit positive `threshold`, a positive policy `generation`, and the
commissioning digest. There is no inherited or default revocation threshold.
Missing policy refuses verification, including on nodes with no stored list.

Roles are exactly `bundle-signing` and `revocation-signing`. An unassigned key
cannot revoke. Aliases for the same public key cannot assign both roles, and
aliases never count as additional threshold signers. Conflicts with
`trust/anchors.toml` key roles, including aliases of the same key material, are
refused. Malformed keys are refused when the policy is commissioned.

## Signed bytes and transport

The single definition in `revocation.py` is:

```python
REVOCATION_DOMAIN = b"azazel-nexus/revocation/v1\0"
```

Every detached signature covers this fixed length prefix followed by the exact
UTF-8 JSON payload bytes. `RevocationList.signature_target()` supplies those bytes
for external signers; Nexus contains no signing implementation. A payload names
`role: "revocation-signing"`, `generation`, `sequence`, `issued_at`, and the
cumulative `revoked_digests`, `revoked_generations`, and `revoked_keys` arrays.
Keys in the last array are complete lowercase public-key hex, rather than key
IDs, so renaming an ID cannot restore a key.

`revocations.signed` has either of two transport encodings:

- One signature: 64 detached signature bytes followed by the exact payload.
- Multiple signatures: ASCII `AZRV1` followed by newline, then a JSON object
  with `payload` (hex of the exact payload bytes) and `signatures` (an array of
  detached signature hex). `encode_signed` packages externally made signatures.

Both encodings verify the same signing target. Duplicate signatures, aliases,
bundle keys and unassigned keys cannot satisfy a revocation threshold. A stored
list below threshold produces the distinct operator word **unverified**, serves
no claims and supplies no Knowledge Lite capability. Absence, staleness and an
unverified statement are separate conditions.

The test vectors in `tests/fixtures/revocation/` use only a published test seed.
They include a manifest, a revocation statement, and a valid manifest containing
all required revocation metadata. Positive bundle and revocation controls prove
that the cross-protocol refusals occur despite otherwise valid signatures and
payloads. A changed separator byte is also refused.

## Continuity and local repin recovery

`prepare_policy_record(root, new_policy, commissioning_digest=..., anchors_key_roles=...,
anchors_keys=...)` performs the continuity checks below without publishing.
`TrustStore.repin` calls it under the local authorization, confirmation and
audit ceremony, and the first enrollment (`lite_enrollment.enroll`,
[ADR-0008](adr/0008-lite-trust-operations.md)) calls it to build the initial
record; those are the only production callers. `commission_policy`
takes the same arguments and also writes the record. No production code calls
it: the lab provisioning and the end-to-end fixture use it to provision test
roots. Neither function authenticates a principal or exposes a remote
operation. Their caller must supply the independently read anchor roles and
keys. The protected policy record must be retained across commissioning.

Each accepted list first persists its cumulative payload as a floor, together
with the SHA-256 of that exact signed blob, in the protected policy record.
Before replacing a policy, the function verifies and preserves this state. Policy generations must increase. The exact checkpointed blob remains
readable after switching authority; another statement from the old authority
cannot pass that checkpoint. New lists must name the new policy generation,
exceed the old sequence, and retain every revoked entry. New policy material
cannot contain a revoked key under any ID or role. A missing checkpointed list
is a refusal. Reopening the store or changing the commissioning digest does not
clear this record.

Lists cannot revoke any of their own verified signers or the last remaining
revocation-signing key. Acceptance persists the protected high-water mark, then
publishes the complete signed list. Each write uses a temporary file, fsync and
atomic replacement. Interruption between these two writes holds the cache
closed. Retrying the exact already checkpointed blob recovers publication;
another statement cannot bypass the failed read or drop the revocations.
Deletion or rollback of the signed list cannot erase the protected floor.
Policy promotion uses the shared trust-generation pointer described below. The local policy record is trust material protected by commissioning
filesystem permissions. This persisted record is fail-closed when missing or
corrupt, but is not cryptographically tamper-evident: it uses a local-trust
model. Replacing or rolling back that trust material is outside
the signed-list threat model. Introducing or recovering authority requires the local ROOT challenge/confirm
ceremony documented in [trust repin](trust-repin.md); signed lists cannot add
authority.

Legacy untagged lists and role-less policies are refused immediately. Existing
commissioning fixtures must explicitly provision the new policy; bundle keys
are never silently promoted to revocation authority. A legacy stored list needs
a local migration decision rather than a permissive fallback.


The fixed repin anchor document may supply `revocation_policy` with the same
`keys`, `key_roles`, explicit `threshold` and increasing `generation` fields.
`TrustStore.repin` validates and stages both bundle and revocation authority,
then promotes them through one atomic generation pointer. A policy-only change
is sufficient to recover a lost revocation role. No signature by the lost key
is required; ROOT peer credentials, challenge/confirm and append-only audit
provide the local authorization. Recovery preserves every revoked entry and the
sequence floor. An old signed blob remains readable only as the exact preserved
checkpoint; new statements must verify with the new keys and generation.
A missing or corrupt persisted list with a non-zero floor blocks recovery repin (fail-closed) and requires a local migration step.

After repin, `read_policy_record` and `RevocationStore` continuity writes use
`trust-generations/N.revocation.json`, selected by `trust-current`, rather than
the original policy file. Knowledge Lite uses this resolver on subsequent
operations. Retained store instances refuse a superseded policy. Repin audit
adds old/new revocation-policy fingerprints to the original six provenance
fields; absent policy is `null`. See [trust repin](trust-repin.md) for the exact
fingerprint encoding and failure semantics. The low-level `commission_policy`
helper remains a trusted provisioning primitive for test roots, with no runtime
exposure. The production introduction is the enrollment
(`az-nexus-commission trust-enroll`), which registers the bundle keys and the
revocation authority together; later changes and recovery use repin. The full
order is
[Knowledge Lite consumer §11](knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available).

## Accepting a list on a node

The Knowledge Lite trust root (`/var/lib/azazel/lite-trust`) is written only
by the commissioning account `azcommission`. Since
[ADR-0008](adr/0008-lite-trust-operations.md) root's
`az-nexus-commission knowledge-revocation-accept` accepts a list itself, on
the ordinary path, in a child that has become that account (its groups,
umask `0027`, `no_new_privs`) and holds the commissioning lock; it needs
`az-auditd` (`azazel-auditd-loop.service` on the ordinary path) and no
`az-commissiond`. The daemon's ROOT-only verb `trust.revocation.accept`
(assess-c P4) does the same for a bootstrap boot and takes the same lock:

```sh
sudo install -m 0640 -o root -g azcommission revocations.signed /etc/azazel/commissioning/lite-revocations.signed
sudo /opt/azazel-nexus/venv/bin/python -I -m azazel_nexus_runtime.commission_cli knowledge-revocation-accept
```

Both take only the fixed leaf name
`lite-revocations.signed` in the commissioning directory, read without
following links and bounded to 256 KiB. The signed statement is the
authority: `RevocationStore.accept` verifies it under the commissioned
policy (threshold, payload generation, a sequence above the one in force,
nothing re-enabled, no self-revocation, never the last revocation key). Root
chooses when, never what is trusted. No confirmation words are asked, because
nothing here can widen trust: a list only withdraws.

`knowledge.lite.revocation_requested` is appended to `az-auditd` (through its
append-only `audit-submit` listener, as `azcommission`) before the store is
touched; if that fails nothing is written and the reply says
`audit_unavailable`. Then `knowledge.lite.revocation_accepted` (the list's
`list_sequence`, generation and counts; until 2026-10-30 the field was named
`sequence`, which auditd assigns itself and refuses in a payload, so every
accepted record was refused and the reply said `audit_complete: false`) or `knowledge.lite.revocation_refused` with one of
`malformed`, `trust_unreadable`, `unverified`, `replay` or `re_enable`. An
accepted list whose outcome record fails stays accepted (more revocation only
closes) and the reply says `audit_complete: false`.

The list and the continuity record take `trust.json`'s owner, group and mode
(`RevocationStore._metadata`, as repin does for its own files), so
`az-knowledge-lited` (`azknowledge`, group read) reads the list and reports
`revoked`, not `unverified`. Before this, a list written by the commissioning
account was its private `0600` file and the reader saw `unverified`
(finding F3 of the [2026-10-28 container rehearsal](evidence/vm-integration-container-2026-10-28.md)).
A `trust.json` that is not a regular file without group/other write refuses
the acceptance.
