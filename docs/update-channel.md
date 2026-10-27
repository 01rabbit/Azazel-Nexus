# Update Channel

Status: **target contract**. Azazel-Nexus has **no update channel**. There is
no release, no signing key, no published manifest, and no released offline
bundle. An unsigned, unencrypted offline install bundle *format* is
implemented for building and rehearsal (§2.1); it is not a channel and carries
no release authority. This document states what a channel will have to carry when one
becomes possible, and marks what nobody has decided.

Nothing below may be cited as evidence that Azazel-Nexus has been built,
signed, published, or updated. None of that has happened.

One consumer-side piece exists: Nexus can **verify** an issuer signature,
a signed revocation list and a rollback floor for the one released component
it installs, the Edge Core package (§1a). That is a verifier with no issuer
key behind it, not a channel, and it does not change any row of §1.

Related: [Contract ownership](contract-ownership.md) §4, §5 ·
[Commissioning and activation](commissioning.md) §6, §7 ·
[Support matrix](support-matrix.md) · [Recovery](recovery.md) ·
[Implementation specification](IMPLEMENTATION_SPEC.md) §12 ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§4, §5 R2/R7/R8

## 1. There is no channel

| Thing | State |
| --- | --- |
| A released Nexus artifact of any kind | **none, ever** |
| A signing root, delegated role, or key for Nexus | **none** |
| A published update manifest | **none** |
| An encrypted offline installation bundle | **none** |
| An update server, mirror, or endpoint | **none** |
| An SBOM or provenance attestation | **none** |
| An Azazel-Fabric pin to update *from* | **none** — see [support matrix](support-matrix.md) §4 |
| A tested compatibility tuple | **none**, so nothing would pass admission even if a signed artifact existed |

The R0 exit criteria require that Nexus "publish their own security policy,
support matrix, license, update channel, and recovery procedure before a
release is called supported". This document is that publication. It describes a
channel; it does not open one.

## 1a. Edge package issuer verification (consumer side)

Status: **implemented, unit tested, not configured on any node**
([Edge package verification](edge-package-verification.md) §3a–§3c,
`src/azazel_nexus/edge_issuer.py`,
`runtime/src/azazel_nexus_runtime/edge_issuer_floor.py`).

| Thing | State |
| --- | --- |
| Verifying a detached Ed25519 signature over the canonical Edge manifest under an administrator-configured issuer key | **implemented**; reported as `issuer_authenticated`, separately from `digest_verified` |
| A signed revocation list of Edge package versions and digests | **implemented**; a revoked package is refused even when its digest matches |
| A raise-only rollback floor, raised only after an authenticated activation | **implemented**; refuses a lower version, a replayed manifest at the floor version and an older revocation list |
| An Edge issuer, an issuer key, or a signed Edge package | **none** |
| A requirement that an Edge package be issuer-authenticated to be admitted | **none**; with no anchor configured, acceptance is exactly as before. Requiring it is an owner decision |
| A path that fetches or installs an Edge package update | **none** |

This is the *authenticity* and *obsolete artifact* half of §3 for one
artifact class, verified locally and offline. It is not a release-admission
policy, it grants no authority, and nothing here moves the pinned Edge
version (`0.1.0`, exact).

## 2. Both transports are required

Program plan §5 R2 makes this a deliverable, not an option:

> support signed online manifests and encrypted offline installation bundles
> through the product-local release-admission policy

The two are **not** a primary and a fallback. A field Nexus may never have
egress — the product is defined by remaining safe and useful when disconnected
— so an offline bundle is a first-class path that carries the same admission
burden as an online manifest, and an online manifest is never a prerequisite
for installing or updating a node.

| Transport | What it is | Constraints it inherits |
| --- | --- | --- |
| Signed online manifest | signed metadata describing available artifacts, fetched over a network path | fetching happens only inside the bounded `ASSET_ACQUISITION` state ([commissioning](commissioning.md) §6): one operator-selected interface, outbound-only namespace, endpoint allowlist with metadata and certificate pinning, no forwarding and no listening service, bounded download size/count/duration, no path to the protected, observation, decoy, or management zones, and cleanup of routes, credentials, DNS, proxy state, and wireless association on exit |
| Encrypted offline installation bundle | an encrypted, signed bundle carried to the node on media | the same admission sequence, the same tested-tuple requirement, and the bounded extractor of program plan §4.4 — declared regular files only, no traversal, links, devices, or nested archives, with size, count, depth, and quota limits enforced while hashing, syncing, rehashing, and only then promoting a complete tree |

Asset acquisition never assigns a role and never grants a capability. Obtaining
an update is not a step toward being allowed to run it.

### 2.1 Offline install bundle — implementation status

`tools/build_wheelhouse.py`, `tools/build_offline_bundle.py --wheelhouse` and
`tools/offline_bundle.py` implement the integrity half of the offline
transport for a first install; the procedure is in
[Debian Live install](debian-live-install.md#offline-install-bundle). They do
not implement the admission sequence of §3, and they change no acceptance
policy: an unsigned bundle is handled exactly as before, and every report says
`bundle_authenticated: false`.

| Requirement (§2 offline transport) | Status |
| --- | --- |
| One manifest listing every artifact with sha256, size, kind and source | **implemented** — `MANIFEST.json`, first member of the bundle |
| Declared regular files only; no traversal, links or devices | **implemented** — refused before anything is promoted |
| Size and count limits enforced while hashing | **implemented** — caps can be lowered by the operator, never raised; extended tar headers capped at 64 KiB before they are read; declared-to-archive ratio cap; free-space check before writing |
| Promote only a complete tree | **implemented** — private staging directory, renamed into place after every check; stale staging from a killed run removed; tree removed when verification refuses; `recheck` re-hashes it before `install.sh` |
| Third-party wheels limited to the reviewed lock | **implemented** — name, version and sha256 checked against the reviewed checkout's lock at install |
| No nested archives | **partly** — wheels, the Edge package and `.deb` files are archives by nature; the extractor carries them as opaque files checked by sha256 and never unpacks them. Their consumers (pip, `edge_package`, `.deb` control check) read them with their own bounds |
| Depth and quota limits | depth and path length **implemented**; disk quota **not implemented** |
| Hash-pinned dependencies, installed with no index | **implemented** — `--require-hashes --no-index --find-links`; container-rehearsed with `--network none`, not hardware |
| Signature over the manifest | **not implemented** — integration point `verify_bundle_signature`; waits for the issuer/operator signing work and a key (§8) |
| Encryption | **not implemented** — format and key distribution are open (§8) |
| Exact tested compatibility tuple, release-admission gates | **not implemented** — §3 |
| Debian package set from a pinned apt snapshot | **slot only** — `.deb` files can be carried and checked against the manifest; the set and its source are not decided |
| Python interpreter provisioning on the target | **not carried** — the target must already have `python3` and `python3-venv` |
| Edge-side sensor packaging | **not here** — Azazel-Edge's; the bundle carries the pinned Edge Core package only |
| Install on x86_64 hardware | **not done** |

Container evidence for the wheelhouse build and the offline install:
[offline-install-container-2026-10-28.json](evidence/offline-install-container-2026-10-28.json).
It is a rehearsal under emulation and is not hardware evidence.

## 3. Release admission is product-local

A publication decision and an installation decision are different decisions
made by different parties. Azazel-Fabric describes; the products that perform
side effects decide what they will admit. The **release-admission policy** is
Nexus-local ([contract ownership](contract-ownership.md) §3.4) and does not
exist yet; when it does, it MUST evaluate every gate **in order**, each able to
reject:

```text
authenticity
  -> exact tested compatibility tuple
  -> semantic content policy
  -> resource/topology admission
  -> operator or policy-authority approval
  -> staged activation
```

Cryptographic authenticity is one input to admission, not admission itself
(program plan §4.1). Consequences that a channel design must not erode:

- A correctly signed artifact that matches **no** tested tuple is rejected. A
  version range is a descriptive compatibility claim and cannot authorize
  activation.
- A correctly signed artifact from the **wrong delegated role** is rejected.
  OS images, Edge packages, Knowledge bundles, Deception packages, models, and
  emergency overlays have separately provisioned offline roots and delegated
  roles.
- A correctly signed but **obsolete** artifact is rejected, as is one below the
  minimum security epoch or older than the tuple's `max_rollback_version`.
- **Update signing is a different credential role from intent signing.** Only
  the Edge arbiter workload identity may use the intent-signing credential; the
  activation controller may install that credential but MUST NOT be able to
  read or reuse it (program plan §4.3;
  [contract ownership](contract-ownership.md) §4.2). The authority boundary is
  held in the key material, not only in the code — so possession of the update
  channel is not a path to deciding anything.

## 4. An update must not weaken the authority settings

The R2 exit gate states the rule for the mechanism updates normally travel
with:

> a deployment overlay cannot weaken Edge approval, scope, lease, policy, or
> trust settings
> — program plan §5 R2

That gate is stated for one mechanism, and Nexus extends it to the whole update
path, because the route by which a setting is weakened does not change what has
been lost. An update, a manifest,
a bundle, a migration step, or an overlay carried by any of them **MUST NOT**
reduce Edge approval requirements, widen action scope, raise or extend lease
ceilings, alter action policy, or change trust roots, signing-key locations, or
any other authority field. A deployment overlay is a **monotonic reduction**:
it may bind commissioned interfaces, select a subset of allowed components,
reduce resource limits, and add labels, and nothing else
([contract ownership](contract-ownership.md) §5).

Three corollaries:

- **An update never grants authority.** A signed release leaves Nexus with
  exactly the authority it had unsigned, which is none. Edge's deterministic
  arbiter is the only decision and enforcement authority before, during, and
  after an update.
- **Rollback is not a way back to weaker rules.** "Software rollback never
  restores obsolete trust state, policy, or hardware bindings"
  ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12) — a rolled-back node runs
  older software under current trust.
- **An update cannot reopen commissioning.** "A remote request, a configuration
  overlay, a package update, and a module manifest MUST NOT reopen
  commissioning or change a role" ([commissioning](commissioning.md) §10).

## 5. Applying an update

The shape is fixed by [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12 and
program plan §5 R7:

1. **A/B or transactional deployment**, with signed repository metadata and
   pinned package versions. An update bundle carries a software SBOM,
   unit/config migration, schema compatibility, policy compatibility, and a
   rollback manifest.
2. **Preconditions**, applied only in maintenance state: an audit checkpoint,
   an encrypted backup of configuration and indexes, and a free-space check.
3. **Trial**: boot the candidate slot, run health and segmentation tests.
4. **Promotion** only after an operator-approved soak window.
5. **Failure returns to the prior slot without deleting evidence**, and the R7
   exit gate requires that "a failed update returns to the prior verified
   generation without losing the last valid audit checkpoint".
6. **Migrations** are forward-compatible or carry a tested reverse migration.

Activation of the promoted generation is the ordinary generation-based
transaction of [commissioning](commissioning.md) §7 — validated signature,
hardware inventory digest, policy digest, security epoch, generation counter,
expiry, renderer digest, and every generated-file digest, on every boot. An
update that cannot produce a verified generation leaves operational units
masked, which is the safe outcome and not a failure of the update channel.

What happens when any of this goes wrong belongs to [recovery](recovery.md).

## 6. What a release record carries

Program plan §4 rule 6: "Every release records component versions, hashes,
signatures, SBOM references, profile, hardware inventory, and applied overlay
digest." R8 adds exact released component pins, source revisions, migration
notes, and a compatibility matrix.

Two requirements deserve restating in Nexus's own terms:

- **Release evidence must be verifiable offline** (R8 exit gate). A
  verification path that requires reaching a transparency log, a key server, or
  a vendor endpoint does not satisfy it for a node deployed without egress.
- **The component pins are part of the release.** Nexus integrates released
  packages rather than copying source, so the Edge package, any Knowledge Lite
  bundle, any Deception package, any model, and the Fabric pin each appear by
  exact version and digest, each with its own SBOM reference.

## 7. Cadence — there is none, by design

Program releases are "capability gates rather than calendar commitments. A gate
closes only when its evidence is stored and review findings are resolved"
(program plan §5). Nexus has no release cadence, no version schedule, and no
support window; inventing one would create an expectation the product is not
required to meet. See [support matrix](support-matrix.md) §7.

## 8. Undeclared — not decided here

| Question | State |
| --- | --- |
| The Edge package issuer: who it is, how its key is created and held, rotation and compromise, whether revocation uses the issuer key (as implemented) or a separate role, whether issuer authentication becomes required for admission, and the Edge-side change that signs packages (Azazel-Edge `packaging/nexus-core/nexus_core_package.py` hard-codes `signed: False` today) | **open** — §1a; the verifier exists and nothing is configured |
| Signing key hierarchy: which roots exist, who holds them, threshold rules, rotation, revocation, custody, and the ceremony that provisions any of it | **open.** The program fixes the *shape* — separately provisioned offline roots, delegated roles per artifact class, recorded threshold/rotation/revocation (§4.1) — and no concrete hierarchy anywhere |
| Signature envelope and algorithms | **open** |
| SBOM format | **open.** The plan requires "SBOM references" (§4 rule 6) and "SBOMs" (§5 R8) and names no format |
| Provenance attestation format | **open.** Required as completion evidence (§6) without a named scheme |
| Manifest format, transport, and endpoint identity | **open**, and constrained by the `ASSET_ACQUISITION` bounds in §2 |
| Offline bundle format, encryption, and key distribution | **open** for the release format, encryption, and keys. The unsigned prototype format of §2.1 is an implementation, not a decision on the release format |
| Soak-window duration and the health/segmentation tests that gate promotion | **undeclared** |
| Security epoch numbering and `max_rollback_version` policy | **undeclared** — see [support matrix](support-matrix.md) §7 |
| Reproducibility of a Nexus artifact | **untried.** R8 requires two independent builders to reproduce an unsigned payload digest; Nexus wheels have only been built by single prototype builders (§2.1), and no second builder has compared digests |

These are decided in their own records, by the owner, not inside the first
implementation pull request that needs an answer.

## 9. What this document does not establish

- That Azazel-Nexus can be released or updated. It cannot: there is no
  release, no signing key, and no admission policy. The offline bundle tools of
  §2.1 build and install an unsigned bundle; they do not release anything.
- That any SBOM, provenance, signing, or bundle mechanism has been selected or
  evaluated. The unsigned offline bundle of §2.1 is a prototype implementation;
  it does not select the release format. The Edge package verifier in §1a
  verifies signatures nobody produces yet; it selects no signing mechanism for
  Nexus.
- That the update path described in §5 has ever been executed or tested.
- That an update channel, once it exists, makes a configuration *supported*.
  That additionally requires operational evidence for a declared environment,
  and [support matrix](support-matrix.md) §7 records how much of that
  environment is still undeclared.
