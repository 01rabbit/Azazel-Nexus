# Update Channel

Status: **target contract**. Azazel-Nexus has **no update channel**. There is
no release, no signing key, no published manifest, no offline bundle, and no
code to update. This document states what a channel will have to carry when one
becomes possible, and marks what nobody has decided.

Nothing below may be cited as evidence that Azazel-Nexus has been built,
signed, published, or updated. None of that has happened.

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
| Signing key hierarchy: which roots exist, who holds them, threshold rules, rotation, revocation, custody, and the ceremony that provisions any of it | **open.** The program fixes the *shape* — separately provisioned offline roots, delegated roles per artifact class, recorded threshold/rotation/revocation (§4.1) — and no concrete hierarchy anywhere |
| Signature envelope and algorithms | **open** |
| SBOM format | **open.** The plan requires "SBOM references" (§4 rule 6) and "SBOMs" (§5 R8) and names no format |
| Provenance attestation format | **open.** Required as completion evidence (§6) without a named scheme |
| Manifest format, transport, and endpoint identity | **open**, and constrained by the `ASSET_ACQUISITION` bounds in §2 |
| Offline bundle format, encryption, and key distribution | **open** |
| Soak-window duration and the health/segmentation tests that gate promotion | **undeclared** |
| Security epoch numbering and `max_rollback_version` policy | **undeclared** — see [support matrix](support-matrix.md) §7 |
| Reproducibility of a Nexus artifact | **untried.** R8 requires two independent builders to reproduce an unsigned payload digest; no Nexus build has ever been performed |

These are decided in their own records, by the owner, not inside the first
implementation pull request that needs an answer.

## 9. What this document does not establish

- That Azazel-Nexus can be released or updated. It cannot: there is no code, no
  builder, and no key.
- That any SBOM, provenance, signing, or bundle mechanism has been selected,
  prototyped, or evaluated.
- That the update path described in §5 has ever been executed or tested.
- That an update channel, once it exists, makes a configuration *supported*.
  That additionally requires operational evidence for a declared environment,
  and [support matrix](support-matrix.md) §7 records how much of that
  environment is still undeclared.
