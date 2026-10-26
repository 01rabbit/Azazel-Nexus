# Where these files come from

Copied verbatim from `packaging/nexus-core/contract/` in
[01rabbit/Azazel-Edge](https://github.com/01rabbit/Azazel-Edge), at commit
`ae9557d15e5e8347609e2fe2251b03c0a48a86b6` (Azazel-Edge main after
[Azazel-Edge#465](https://github.com/01rabbit/Azazel-Edge/pull/465) and
[Azazel-Edge#468](https://github.com/01rabbit/Azazel-Edge/pull/468)).

The files were first copied at `f44a66835eb55aa9c0196f0ec6964e6361606eab`
([Azazel-Edge#426](https://github.com/01rabbit/Azazel-Edge/pull/426)). At
`ae9557d` they were regenerated from a release build
(`nexus_core_package.py --emit-contract`) and are byte-identical to that
copy: the contract has not changed between the two commits, so only this
note moved.

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
