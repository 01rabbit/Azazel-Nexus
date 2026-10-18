# Local embedding admission (disabled)

`LOCAL_MODEL_ADMISSION_ENABLED = False` is a reviewed code kill switch.
The production loader returns `ADMISSION_DISABLED` before reading files.
No real campaign, approval, key or measurement ships in this repository.
Tests use freshly generated keys and synthetic observations; their results
are never hardware evidence. Explanation/generative admission is future work.
The admitted architecture is x86_64 only, even though the runtime installer
also has an aarch64 binary pin.

Admission is advisory and supplies no Edge authority. The activation daemon
still supplies no lease and no health evidence, and its invariant refuses any
production grant. Enabling this feature requires a separate reviewed code
change after the first attested DUT campaign and the signing ceremony below.

## Prerequisites and combined campaign

Use the existing [HG-05 procedure](core-reserve-measurement.md) on the target
DUT, with the required Core subsystems under load. Probe schema
`azazel-nexus/core-reserve/3` adds bounded file observations for hypervisor type,
CPU hypervisor flags, systemd container marker, container marker file, DMI
vendor/product classes and init cgroups. A missing mandatory observation or a
read failure refuses. Optional markers may be absent. Every campaign run must
carry complete v3 observations. Earlier reserve schemas remain available to
legacy diagnostics but cannot support this admission path.

The combined `azazel-nexus/hil-mio-campaign/v1` record extends the existing
three-distinct-boot campaign with `virtualization_not_observed: true`,
`virtualization_observations`, and `embedding_runtime`. The latter has exactly:

- `peak_rss_mib`, `startup_ms`, `retrieval_p50_ms`, `retrieval_p95_ms`: positive
  whole measurements; p95 must be at least p50.
- `runtime_binary_digest`, `model_digest`, `argv_digest`: full SHA-256 digests.

Measure runtime behavior in an isolated HIL campaign, running the pinned binary
directly with the fixed embedding arguments. Do not obtain measurements by
admitting a model through locald. Record the actual argv, peak RSS, startup
and retrieval timings alongside the workload and captures. The embedding
settings are fixed in code: context 2048, two threads, 256 max tokens and the
embedding flags produced by `llama_server_record`. The approved argv uses the
fixed installed binary/model/socket paths; execution substitutes only the two
held descriptor paths, as described below.

Use the existing HIL manifest/bundle contract for the aggregate and each run.
The attester must use an independently enrolled, currently non-revoked operator
key. The admission approver must use a different enrolled key. The manifest,
aggregate and per-run canonical artifacts are verified; declaring an attestation
status in a record has no effect. Fixture, synthetic, shape-only, VM and
container observations refuse. `virtualization_not_observed` is a negative
filter only: it means virtualization was not observed by these file checks.
TPM/secure-boot attestation is follow-up work.

Model import/promotion and runtime installation must precede the request.
The loader uses the existing fixed `/var/lib/azazel/models/trust/` catalog and
trust, `state/current`, generation manifests and digest-named store artifacts.
It ignores `AZAZEL_ROOT` and any configured alternative model root. Catalog
signatures, exact catalog version/digest, installed generation identity and
rollback lineage are all checked. An older catalog cannot satisfy an approval
bound to a newer version/digest. This is not durable rollback-resistant storage.

The protected Mission Pack config supplies host facts, tested tuples and the
model asset's `memory_need_mib`. The signed catalog supplies the envelope floor
(`declared_min_ram_mib`). Those declarations are independently checked against
attested peak RSS and observed MemTotal; declarations alone never establish fit.
Need is at most 3840 MiB, leaving 256 MiB for locald within its 4096 MiB unit.
The DUT HMAC is recomputed using the existing HIL identity derivation, and the
node binding also includes SHA-256 of the protected node declaration bytes and
the commissioning digest. Architecture comes from `os.uname().machine`.

**Deployment prerequisite still unresolved:** the existing HIL identity reader
requires the root-only commissioning HMAC protection file. The `azmio` account
cannot read that file under current provisioning, so it refuses collection.
This change does not broaden key access. A reviewed identity-observation handoff
is needed before enabling; do not change the kill switch to work around this.
Host facts other than architecture and DUT identity retain their existing
commissioned-declaration semantics.

## Protected read-only storage

Provision `/etc/azazel/model-admission/` and `evidence/` as root:azmio 0750.
Policy, approval, manifest, signature and artifact files are root:azmio 0640,
regular files with one link. No component may be a symlink; group/other write
access refuses. The loader uses held directory descriptors, bounded reads and
no writes. The directory and operator trust/models are ReadOnlyPaths for locald.
No payload revocation-list file or separate runtime-evidence directory is used.

`policy.json` is canonical ASCII JSON with exactly `schema`, `operators`,
`max_seconds` and `roles`. Schema is `azazel-nexus/model-admission-policy/v1`;
roles must be `["embedding"]`; operators must be a nonempty explicit set of
operator identifiers. `max_seconds` is mandatory, positive and no greater than
604800 (seven days). Prefer a substantially shorter ceremony-specific window.
There are no defaults and booleans cannot substitute for integers.

The atomic `embedding.approval` file has exactly `schema`, `payload_b64` and
`signature_hex`. Schema is `azazel-nexus/local-model-admission-file/v1`;
base64 and lowercase signature hex must use their canonical representations.
The payload is canonical ASCII JSON and the signature is 64 bytes after decoding.
Write a temporary file in the same directory, set root:azmio 0640, fsync the file,
rename it over `embedding.approval`, then fsync the directory. Never install
payload and signature as separate mutable files. Installation is an external
administrator operation; the request/verify CLI has no write capability.

## Request, independent review and external signing ceremony

Run as root, with no group granted write access to the admission directory.
All groups have read/search access at most under the required modes.

1. Install the attested combined bundle under `evidence/`, and the explicit
   policy described above. Verify trust enrollment and revocations independently.
2. Run `az-nexus-model-admission request --role embedding`. Supply one canonical
   JSON line on stdin with exactly `operator`, `issued_at`, `expires_at`,
   `memory_need_mib`, `envelope_floor_mib`. Times are whole-second UTC ending
   in Z. Resource values must exactly match the independently commissioned
   asset/catalog declarations. The command prints unsigned payload bytes,
   payload and message hashes, and the domain/purpose transcript prefix.
3. The Japanese/English summary prints model ID/digest, binary digest, exact
   argv, Core reserve, peak RSS, virtualization-not-observed status, validity
   window and protected node binding. The signer must independently compare
   **every one of these** with the HIL report and node inventory before signing.
   A matching hash displayed by the requesting node is insufficient review.
4. Off-host, use an external Ed25519 tool (for example OpenSSL 3 `pkeyutl`
   with raw input) to sign exactly the existing operator-approval domain prefix,
   the `local-model-admission` purpose separator and the canonical payload.
   Do not sign a HIL manifest through the approval protocol. No signer or
   signing-key reader is added to either package by this feature.
5. Have root install the wrapper atomically as above. Run
   `az-nexus-model-admission verify --role embedding`; while disabled it reports
   `embedding -> refused:ADMISSION_DISABLED`. Request rehearsal still performs
   all evidence checks and explicitly reports that the feature is disabled.
6. Record independent ceremony review and the first attested DUT campaign
   before proposing a code change to the kill switch. Production activation
   still needs its separate lease/health producers.

Both commands are read-only and have no key, path, root, output or approval-flag
options. A failed collector reports a refusal, never a successful proposal.
The CLI signs nothing and authorizes nothing.

## Withdrawal, execution and residual limits

Revocation means removing the atomic approval, revoking either signer in
operator-trust, or bumping the host security epoch. There is no optional
payload revocation list and therefore no missing-list fail-open behavior.
Generation movement invalidates an approval; restoring the exact prior
catalog/generation can use a retained approval only while it is unexpired and
all other bindings still match.

Activated retries a changing verification snapshot at most three times and
otherwise leaves the provider unwired. Locald independently verifies on start;
refusal leaves its service available without a model. It checks watched metadata
and validity before each request and polls every **1.0 seconds** while idle.
Withdrawal occurs on the next request or poll (subject to the existing service
loop's accept/request scheduling). It stops the embedding child, removes the
retriever and uses keyword retrieval. A replacement approval is considered only
on the next service start. Failures are audited with symbols and digests only;
no prompts, paths, keys or raw identity appear in admission audit events.

The binary and weights descriptors remain held. Immediately before each spawn
both inodes are re-hashed and the executable and `-m` argument use
`/proc/self/fd/N` with `pass_fds`. This route refuses on non-procfs platforms;
there is no admitted path-reopen fallback. The generic pre-existing supervisor
benchmark route is separate from admission. Root remains the trust boundary:
an administrator able to alter protected storage or mutate an inode after the
last verification can defeat software-only observation. The old path-open-after-
hash residual for admitted Linux execution is removed by descriptors.

There is no trusted time source or boot-ID binding. Wall-clock rollback can
extend effective approval exposure; the mandatory policy bound, capped at seven
days, limits the signed interval but is not a rollback-resistant clock. Durable
epoch/catalog high-water and trusted time remain follow-ups. Locald still has
ReadWritePaths for `/var/lib/azazel/run`; narrowing requires a socket-layout
change and remains a follow-up. Admission never reads the legacy Core reserve
record in that directory, even if it declares a measurement.
