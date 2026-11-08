# ADR-0009 — Nexus candidate pins published Fabric v0.10.0

Status: **accepted for the current PR candidate (2026-11-05)**; does not
approve a Nexus release, merge, trust-root change, or deployment. Supersedes the
release-pin value in ADR-0001 and the corresponding wheel hash in ADR-0004;
those records retain the rationale for the original optional-dependency design.

## Context

Nexus #402/#403 consume Fabric's Knowledge Context v1 contract on an optional,
explicitly configured path. Fabric v0.10.0 is now the published stable release
that contains this profile. The profile itself remains experimental in Fabric
and has no compatibility promise. The release is an annotated signed tag; its
source commit is `397fcce7a87ca7ab1a5e84bc196c44d70c404907`, and its release
digest is `d789f27464114bf29bbdc64fcc515cdbdfc02903a0b42af4de3dc707446e302f`.
The GitHub Release publishes no wheel or sdist asset, so the offline builder
rebuilds a wheel from the exact tagged source.

The exact tag-to-commit and wheel-content pins must agree across the project
extra, `uv.lock`, `fabric_boundary.FABRIC_PIN`, `tools/build_wheelhouse.py`,
and both platform locks. CORE remains usable without Fabric.

## Decision

1. For this candidate, set the optional `fabric` extra and `FABRIC_PIN` to
   `v0.10.0`; do not add Fabric to core dependencies or use a floating ref.
2. Lock `uv.lock` to tag `v0.10.0` resolving to commit
   `397fcce7a87ca7ab1a5e84bc196c44d70c404907`.
3. Build the offline wheel from that tag using the existing pinned backend,
   normalized archive modes, `SOURCE_DATE_EPOCH`, and umask rules. The expected
   platform-independent wheel hash is
   `b22356fd672cd60471606d3a7b73ccdba99091e680fedd854381a29d76e21424` for
   `azazel_fabric-0.10.0-py3-none-any.whl`; both x86_64 and aarch64 locks use
   this hash. A build that differs refuses, and an existing release artifact
   is never overwritten.
4. Treat `knowledge_context` as experimental despite the stable product tag.
   Nexus consumes it only through the existing Fabric boundary; absent package
   or explicit transport configuration fails closed. Signature and schema
   validation establish signer, integrity, and shape, not claim truth.
5. Retain ADR-0004's source-build boundary: Nexus does not begin verifying
   Fabric's release signature or trust keys in this change. The recorded
   release verification supports the selected tag; it does not introduce a
   Nexus trust-root policy.

The earlier candidate's MIO wheel was
`azazel_mio-0.1.0.dev20261107+gited860f2-py3-none-any.whl`, built from exact
source commit `989dd959a635b5877814bd2912639676308cf999` and was pinned in both
target locks at SHA-256
`a99fdc1bb15484581b41cb1bd22914b4d1e1f452499278b5f42902daacc2a3cb`. The
optional `mio` source extra resolved to the same immutable commit. The
`gited860f2` version suffix identifies the implementation baseline; `989dd959…`
is the source commit that carries this version metadata. The former
`gite639a65` / `1ba191b…` artifact and hash are superseded and must not be used
for that candidate. Reproduction used `SOURCE_DATE_EPOCH=1793887544`, the
fixed reproducible-build epoch; Fabric retains its separately pinned
1980 epoch so its released wheel hash is unchanged.

## Verification and limits

The release digest and signature were verified against the tagged release in
its release record. The exact source produced the wheel above under Linux arm64
CPython 3.13.18, setuptools 84.0.0, wheel 0.48.0,
`SOURCE_DATE_EPOCH=315532800`, and umask 022. The pin migration is accepted for
the candidate only after the required Nexus four-configuration matrix and
wheelhouse source/hash check pass on that candidate. It does not establish
Nexus main integration, the full Knowledge-to-Nexus production route, a Nexus
release, credentials, trust configuration, or deployment.

## 2026-11-08 advice runtime pin update

The current candidate pins optional MIO source commit
`762305354ce1cb8ef6f190b48f10f9297e79bb5a` (tree
`4bd981030e9fca70252e7ecf0383e738f1af9243`), version
`0.1.0.dev20261108+gitadvice3`, template `1.9.0`. Both target locks pin
`azazel_mio-0.1.0.dev20261108+gitadvice3-py3-none-any.whl` at SHA-256
`175dd38cd613b3775ba23d137d68cf8c1dcb48766217ead7a067cea688399068`.
The source archive recipe uses the pinned build backend, umask 022 and
`SOURCE_DATE_EPOCH=1794058907`. Two canonical builds produced identical
bytes and a fresh offline install verified the package origin and template.
The updated Nexus wheelhouse recipe still requires its own reproduction
check and candidate-level integration and D3b evidence; the pin does not
open model admission, authorize release, or establish deployment.

## 2026-11-08 deterministic guidance pin update

The candidate now pins optional MIO source commit
`86a707f0933c9013d99246305f32d99f140aa4dc` (tree
`f811a638763110286347797ceb0efd498a1eac5d`), version
`0.1.0.dev20261108+gitguidance1`, template `1.9.0` (unchanged, so no template
allowlist change). Both target locks pin
`azazel_mio-0.1.0.dev20261108+gitguidance1-py3-none-any.whl` at SHA-256
`5b42d752672d02fd3ffad896b1d7c47dd145f8cfb83429e3b72ebe54f74d5913`
(`SOURCE_DATE_EPOCH=1794107668`, umask 022). Two canonical builds produced
identical bytes and a fresh offline install loaded the module from
site-packages. The previous `+gitadvice3` pin (wheel
`175dd38cd613b3775ba23d137d68cf8c1dcb48766217ead7a067cea688399068`) is
superseded and kept above as history. The new MIO module
`azazel_mio.guidance` makes no model call; it adds no admission or release
authority.
