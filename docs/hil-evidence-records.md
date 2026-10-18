# HIL evidence records

Status: **storage and vocabulary contract; no hardware records exist here**.
This addresses [#100](https://github.com/01rabbit/Azazel-Nexus/issues/100) AC4.
Use with the [campaign](hil-campaign.md) and
[inventory confidentiality](inventory-confidentiality.md), which takes priority
where an older schema asks for raw identity.

## Separate locations and vocabulary

CI artifacts belong to the CI job or its disposable development directory and
[integration evidence](integration-evidence.md). Call them `software execution`,
`synthetic`, `fixture` or `shape_only` according to what ran. A green CI run
satisfies none of HG-01–07, SO-01/SO-10 or #100's hardware acceptance criteria.
Development runs on VM/Pi/laptop/workstation remain development references,
never HIL gate results, even if their schema validates.

Retain actual field records in an access-controlled **HIL archive outside all
Git checkouts**, grouped by campaign, approved anonymous DUT ID, class, boot
HMAC fingerprint and unique run ID. These are logical archive partitions,
not new CLI options. Do not commit measured records, raw captures, signed
hardware fixtures, or a record marked `provenance: measured` or
`synthetic: false`. There is no hardware record generator. A fixture is useful
only as a rejection test, never an admission input.

| Term | Meaning |
| --- | --- |
| `not-run` | no completed physical exercise; includes blocked/incomplete with classified reason |
| `failed` | physical exercise observed a violated requirement; retain all observations |
| `passed` | claimed physical result; may inform a gate only after attested validation and field review |
| `shape_only` | syntax/structure checked; no gate verdict |
| `attested` | signature and required artifact references validated; not proof of physical execution |
| `unmeasured` | HG-05 still has no accepted campaign measurement |
| `hardware-unverified` | hardware behaviour remains unestablished |

A failed exercise can have a valid attested record. An absent or incomplete
record is never passed. Do not fill missing observations with zeros, invent
end timestamps, discard failures or rename CI evidence into field evidence.

## Protected source and export boundary

Raw MACs, serials, asset numbers, boot IDs, detailed NIC/kernel inventory and
TPM identities stay **only in the encrypted commissioning record on the node**.
Raw address/hostname-bearing captures or command output cannot be attached to
an evidence bundle, repository, issue, audit or ordinary journal. If required
for field review, retain them within that protected record boundary, with
access controls and encrypted storage; do not create a second raw archive.

Outward identities are only the operator-approved anonymous `dut_id`/host ID
and, where correlation is necessary, key-protected HMAC fingerprints bound to
the TPM or commissioning secret. Bare hashes of identifiers are not
anonymisation. Manifest SHA-256 hashes cover **sanitised artifact bytes** for
integrity; they do not anonymise their contents. File paths, names, notes,
errors, packet metadata and tool transcripts must also be free of raw identity.

Bundle **A** holds automatically acquired, sanitised facts and acquisition
methods; **B** holds explicit operator approvals, workload declarations and
responsibility references. Do not represent B as a measured fact. Bind both to
the same campaign/run, approved DUT, class, boot fingerprint, exact owner commit,
harness/schema version and artifact generations. Keep keys outside both blocks
and the record; use approval IDs/roles rather than personal inventory in reports.

## Tools and trust

The following are **added in this change**; planned names are integration
references, not a claim that another lane's files exist in this worktree:

- Lane B: [tools/hil_evidence.py](https://github.com/01rabbit/Azazel-Nexus/blob/main/tools/hil_evidence.py),
  per-run SHA-256 manifest, confidentiality lint, separated A/B blocks and
  signing/verification. Its distinct attestation domain is
  `azazel-nexus/hil-evidence/v1\0`; use an independently trusted operator key
  outside the record. It follows the existing
  [service-objective attestation](service-objectives.md) pattern.
- Lane C: [src/azazel_nexus/hil_records/](https://github.com/01rabbit/Azazel-Nexus/tree/main/src/azazel_nexus/hil_records/),
  gate, six-behaviour E2E and degradation record schemas/validators, and the
  Core-reserve campaign validator. Hardware records require physical provenance,
  `synthetic: false`, anonymous `dut_id` and acquisition method. Validators
  accept only attested hardware evidence; shape-only inputs and fixtures cannot
  pass. Use the integrated package's executable API; no CLI is invented here.
- Lane D: [probe v2](../runtime/src/azazel_nexus_runtime/core_reserve_probe.py),
  recording a HMAC boot fingerprint, run sequence, commit/kernel context and
  a distinct file per run without overwriting earlier runs; and the **read-only
  readiness command**, checking required subsystem units, azazel.slice,
  commissioning key and class. Its final command spelling, root-only on-device
  key initialization procedure and HG-01/HG-04 read-only acquisition command
  names are integration references to that lane, not additional probe or
  hil-preflight arguments. They must be available before the field campaign.

For HG-05 retain at least three attested runs with distinct boot fingerprints,
the same class and harness, and nonempty workload notes. The campaign validator
checks those relationships and takes the maximum of per-run maxima. Individual
`core_reserve.validate` acceptance alone does not validate a campaign. v1
reader compatibility does not supply missing v2 campaign provenance.

SO-01/SO-10 keep their existing [service-objective validator](../tools/service_objectives.py)
and exact event/clock/count rules. That older SO-10 contract requires raw
composite identity and raw captures: **do not export those fields as a HIL
bundle or replace required values with fingerprints and call it attested**.
Keep the full validation/review inside the encrypted commissioning boundary;
export only a sanitised derived report and its separate bundle attestation.
If the integrated validators cannot support that boundary, stop external
publication and leave the gate open pending reconciliation. The same rule
applies to probe kernel context: raw kernel inventory stays protected; a bundle
uses only permitted class facts or approved HMAC references, never raw output.

## Record lifecycle

1. Acquire observations only on authorised target hardware under the linked
   [runbook](hil-campaign.md). Allocate a fresh run; preserve failures and
   interrupted-run classifications. Record provenance and acquisition method.
   No schema tool can establish that a physical event occurred.
2. Store raw source only within the encrypted commissioning record. Produce
   sanitised A observations and separate B declarations in the field archive;
   review confidentiality before bundling. Never rely on lint alone: pattern
   rejection cannot recognise every sensitive value.
3. Use `tools/hil_evidence.py` **added in this change** to manifest/hash the
   sanitised per-run artifacts, lint them, and sign the A/B bundle. Supply keys
   from protected locations outside the record. Do not reuse a test key for
   field attestation. Retain the manifest, detached signature and trusted-key
   provenance without private key material.
4. Verify the bundle with the independently trusted public key, then validate
   the applicable attested gate/E2E/degradation records and the class campaign.
   Verify required referenced files and digests; an intact manifest alone says
   nothing about run completeness or requirements. Preserve all refusal reasons.
5. Obtain independent physical-provenance review and owner ratification before
   linking a sanitised report to the owner issue or changing a gate. Audit only
   the closed list allowed by the confidentiality rule; detailed measurements
   belong to the HIL archive, not the append-only audit.

Signatures establish who attested and that referenced bytes match. They do not
prove the workload, the boot, isolation, silence, privilege refusal or Core
continuation happened. Neither validators nor a bundle grant operational
activation, provider approval, model quality or support certification.
