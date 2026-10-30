# Where these files come from

Copied verbatim from `packaging/nexus-core/contract/` in
[01rabbit/Azazel-Edge](https://github.com/01rabbit/Azazel-Edge), at commit
`8d5cc215c86a1e8c46af6f547f679220fba42459` on the branch of
[Azazel-Edge#522](https://github.com/01rabbit/Azazel-Edge/pull/522)
(per-CPU package, manifest and pin; manifest contract
`azazel-edge-core/package-manifest/v2`). Rechecked there against two fresh release builds per CPU on
aarch64 and x86_64 (`nexus_core_package.py --emit-contract`): every
regeneration is byte-identical to these three copied contract files. That PR changes `pin.json` to
`azazel-edge-core/nexus-pin/v2` (one entry per CPU under `architectures`, each
with its artifact, manifest and ELF identity) and adds `elf` to the manifest
schema; the manifest contract moves to `package-manifest/v2` so that a
reader older than the per-CPU checks refuses every per-CPU package (this
reader also still reads v1, see `edge_package.LEGACY_MANIFEST_CONTRACTS`).
**Until Azazel-Edge#522 is merged, this copy is ahead of Edge main**;
when it merges, the commit named here is replaced by its main commit, and the
files do not change (`health-schema.json` is unchanged).

Before that, the files were copied at `ae9557d15e5e8347609e2fe2251b03c0a48a86b6`
(Azazel-Edge main after
[Azazel-Edge#465](https://github.com/01rabbit/Azazel-Edge/pull/465) and
[Azazel-Edge#468](https://github.com/01rabbit/Azazel-Edge/pull/468)), and
first at `f44a66835eb55aa9c0196f0ec6964e6361606eab`, a commit on the branch of
[Azazel-Edge#426](https://github.com/01rabbit/Azazel-Edge/pull/426) (on Edge
main `2a3e42d653f6be148fd010bc18e2afc77aaa78d7`).

**They are copied, never edited here.** A consumer that edits the contract it
is verifying against is a consumer that verifies its own opinion. If one of
these files is wrong, the change belongs in Azazel-Edge, and this copy is
refreshed afterwards.

## Why copies rather than an import

Azazel-Nexus verifies the Edge package without importing the packager. The two
repositories build and test separately, and a consumer that needed the
producer's source in its own CI would be sharing an implementation rather than
verifying a contract.

## Why copying is safe to keep in step

The three documents carry **no digest and no timestamp**. They are
byte-identical across Edge rebuilds, so this copy does not go stale every time
the Edge binary is recompiled -- and a diff here always means the contract
itself changed and needs reading.

Both sides hold the tie mechanically:

| side | guard |
| --- | --- |
| Edge | `tests/test_nexus_contract_export.py` regenerates and asserts the committed files are byte-identical |
| Nexus | `tests/unit/test_edge_package.py` asserts every constant in `edge_package.py` equals what these files say |

So a field added to the Edge manifest turns the Edge suite red until the
contract is regenerated, and a constant drifting in Nexus turns the Nexus
suite red against this copy.

## What the contract says Nexus must do

`pin.json` carries it in `consumer_must`, and the tests read it from there
rather than restating it:

- re-derive the artifact digest and compare it with the manifest
- treat a digest match as integrity against accidental change only, because
  nothing here is signed
- report package absence, a corrupt manifest, a version mismatch, a digest
  mismatch, an unhealthy report and a not-running payload as **six separate
  findings**
- not claim `edge-baseline-ready` from accepting this package
- select the entry for the host's CPU and refuse a package whose name,
  manifest architecture or binary ELF header names another CPU (v2)
