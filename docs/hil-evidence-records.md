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

The integrated tools are:

- [tools/hil_evidence.py](../tools/hil_evidence.py): run
  `python -m tools.hil_evidence bundle DIRECTORY --run-id RUN --gate-id HG-01 --dut-id DUT --artifact capture.json=PATH --operator-input B.json`,
  then `lint DIRECTORY`, `sign DIRECTORY --key-file EXTERNAL_SEED`, and
  `verify DIRECTORY --operator-key EXTERNAL_PUBLIC_KEY` using the same module.
  Repeat `--gate-id` and `--artifact` as needed. The seed is an external
  32-byte Ed25519 seed encoded as lowercase hex; generate real keys only on
  the authorised target/operator system. A signature uses the distinct domain
  `azazel-nexus/hil-evidence/v1\0`. Verification without an external trusted key
  returns `shape_only`, including when a signature file exists.
- [azazel_nexus.hil_records](../src/azazel_nexus/hil_records/__init__.py):
  `validate_record(record, bundle_directory=root, operator_key=external_key)` validates
  `azazel-nexus/hil-gate/v1` (`gate_id`), `azazel-nexus/hil-on-host/v1`
  (`behaviour`), `azazel-nexus/hil-degraded-drill/v1` (`drill`),
  `azazel-nexus/core-reserve-campaign/v1` (`runs`), and
  `azazel-nexus/hil-mio-campaign/v1` (`runs` plus `embedding_runtime` and
  virtualization observations; the only admission input, see
  [M.I.O. admission](hil-runbooks/mio-admission.md)). The admission loader calls
  it with `bundle_files=` and `public_key=` (enrolled key bytes) instead of a
  directory and key path. Only verification of a signed bundle with an out-of-band public key can yield
  an admissible result; status constants and callbacks are not accepted. These are Python APIs.
  The six behaviour values are `local_inference`, `remote_fallback`,
  `network_loss`, `model_crash`, `resource_pressure` (shed order), and `revocation`.
- The runtime console scripts are `az-core-reserve-probe`, `az-hil-readiness`,
  and `az-hil-capture hg-01` / `az-hil-capture hg-04`; admission adds the
  read-only `az-nexus-model-admission request` / `verify` and the root
  pre-start `az-mio-identity`. Readiness is read-only
  and reports required subsystem units, `azazel.slice`, commissioning key and
  pilot class. Use the [on-device key initialization procedure](core-reserve-measurement.md#commissioning-key-initialization-root-only).
  Probe and preflight arguments remain unchanged.

### Acquisition and attestation binding

There is one outward DUT format: `dut-` followed by **32 lowercase hex digits**.
The capture tool derives it from the first 32 hex digits of the protected host
HMAC. All host, boot, NIC and permanent-address fingerprints use
`hmac-sha256:` followed by **64 lowercase hex digits**. Host and boot HMACs use
separate `azazel-nexus/hil-host/v1\0` and `azazel-nexus/hil-boot/v1\0` domains;
NIC domains are `hil-nic` and `hil-permanent-address` under the same prefix and
version. A bare digest is not a fingerprint. Keep the commissioning key stable
within a campaign; key rotation changes correlation and requires a new campaign.

`validate_acquisition(record)` checks acquisition **shape only**, returning
`Status.SHAPE_ONLY` or `Status.REFUSED`; it never returns `attested` or a reserve.
It accepts the HG-01/HG-04 acquisition schemas
`azazel-nexus/hil-capture/hg-01/1` and `azazel-nexus/hil-capture/hg-04/1`,
and probe schemas `azazel-nexus/core-reserve/2` and `azazel-nexus/core-reserve/3`. This does not satisfy
`validate_record`: qualification requires a complete gate/campaign envelope.

Both capture outputs carry `gate_id`, `capture_method`, `dut_id`,
`dut_fingerprint`, `boot_fingerprint`, `build_commit`, and `kernel_release`.
HG-01 adds `systemd_version`, `unit_files`, and `units` (active/sub states).
HG-04 adds `interfaces` with `nic_fingerprint`, `ifla_perm_address_present`
(bool or null for unknown), `permanent_address_usable`, and
`permanent_address_fingerprint` (null when unusable). Neither tool claims
packet silence, role/account correctness, renaming continuity or qualification.
A gate envelope can embed the automatic output as `capture`; its gate and DUT
must match. Its `observations` must still supply all gate-specific outcomes and
artifact references. Do not fill unobserved outcomes to make validation pass.

Probe v2 fields are `schema`, `provenance`, `profile`, `host_digest`,
`harness_version`, `subsystems_active`, `samples`, `boot_fingerprint`,
`run_sequence`, `build_commit`, and `kernel_release`. The current harness
(`core-reserve-probe/3`) writes v3, which adds `virtualization_observations`
and `virtualization_not_observed` (a negative filter only). `host_digest` is the
legacy field spelling for the same protected value called `dut_fingerprint`
in campaign/capture envelopes. A campaign run embeds the probe document
unchanged under `measurement`, copies its boot fingerprint and harness version,
and uses its host digest as `dut_fingerprint`; the anonymous DUT and explicit
`hardware_class` (`8GiB`, `16GiB`, `32GiB`, `64GiB`) remain envelope fields.
This is a field mapping, not a hardware-record generator. The probe publishes
`/var/lib/azazel/run/core-reserve-run-00000001.json` and subsequent eight-digit
minimum-width sequences without replacement; it never promotes
`core-reserve.json` itself.

The bundle manifest's signed `attestation_ref` is `hil-evidence:<run_id>`.
Gate/campaign/run envelopes use that value as `operator_attestation_ref`.
Run IDs must be unique within the protected campaign archive; a reference alone
is not trust. Bundle A contains named sanitized artifacts and SHA-256 digests;
B contains operator input. Include each complete run and aggregate as its own
canonical JSON artifact (use `canonical_event_bytes(record)`). The validator's
shared library verifier checks the external key, manifest, artifact hashes,
reference, DUT, and the SHA-256 of exact canonical record bytes. Matching a reference, signing a capture,
or putting `status: attested` in JSON cannot qualify a record. Fixture markers
remain refused even when the fixture bundle is signed with an ephemeral test key.

The same confidentiality lint protects bundle input, capture stdout and probe
publication. Identifier-bearing platform strings cause a refusal, never silent
redaction. Only sanitized UTF-8 artifacts belong in these bundles.

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
3. Use `python -m tools.hil_evidence bundle` to manifest/hash the
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

No run record is promoted to the legacy `core-reserve.json`; the admission
loader never reads it. Admission consumes only the attested
`azazel-nexus/hil-mio-campaign/v1` bundle placed under
`/etc/azazel/model-admission/evidence/`, in which the aggregate and every run
are canonical artifacts of one manifest signed by an enrolled operator who is
not the approver. `azazel-nexus/core-reserve-campaign/v1` runs require
`azazel-nexus/core-reserve/2`; `azazel-nexus/hil-mio-campaign/v1` runs require
`azazel-nexus/core-reserve/3`. Both require matching measurement/envelope
boot fingerprints, distinct positive run sequences, and consistent build commit,
kernel release and harness across all runs. No environment variation is allowed
within a campaign. Identical measurement payloads across runs are refused.
