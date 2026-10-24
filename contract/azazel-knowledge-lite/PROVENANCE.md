# Where these files come from

Emitted by [01rabbit/Azazel-Knowledge](https://github.com/01rabbit/Azazel-Knowledge)
at revision `2445c1b125ab1210b826b40f027d6eec4c5de125` (the merge of
Azazel-Knowledge#109), with:

```sh
python tools/lite_fixture.py emit --out DIR
```

`FIXTURE.json` records that revision, the command, and the SHA-256 of every
file here. **They are copied, never edited.** A consumer that edits the
artifacts it is verifying against is a consumer that verifies its own opinion.

## Why these are committed when Knowledge deliberately does not commit them

Knowledge emits rather than commits, and says why: the same selection tuple
reproduces the same bytes, so a *rebuilt* fixture re-proves determinism every
time, while a committed blob would only prove that a file was once checked in.

That argument is about the producer's own repository. On this side the need is
different and it is the one [#67](https://github.com/01rabbit/Azazel-Nexus/issues/67)
states: the fixture is a **cross-repository contract**, pinned by version,
source revision and digest. Nexus CI has no Azazel-Knowledge checkout, and a
reader that could only be tested where the producer happens to be installed is
a reader that is not tested.

Determinism was checked before pinning: two emissions at this revision
produced **byte-identical** output for all eight files, and the digests in
`FIXTURE.json` match the `sha256` values Knowledge itself declares in
`negative.json` and the `bundle_sha256` in `expected.json`. Nothing here was
taken on trust from one run.

## What is here

| file | what it is |
| --- | --- |
| `lite.tar.gz` | a signed, valid, full-only Lite bundle |
| `anchors.toml` | the trust anchor it verifies under |
| `expected.json` | profile block, per-file SHA-256, row counts |
| `negative/corrupt-signature.tar.gz` | refused at the signature gate, nothing staged |
| `negative/corrupt-payload.tar.gz` | refused at the per-member digest gate, after staging |
| `negative/corrupt-truncated.tar.gz` | refused at the archive-decode gate as `BUNDLE_ARCHIVE_UNREADABLE` (the decoder error, wrapped) |
| `negative/expired.tar.gz` | verifies completely; every indicator in it is expired |
| `negative.json` | what each negative fixture is and where it must fail |

`negative.json` also names an `absent` case, which is a path guaranteed *not*
to exist. Nothing is committed for it, by definition.

## Three things the producer tells consumers, which are easy to get wrong

1. **The truncated fixture fails in the tar decoder, and the verifier wraps
   that.** The decoder error surfaces as `BundleVerifyError` with code
   `BUNDLE_ARCHIVE_UNREADABLE`, the decoder error kept as its cause. Do not
   rely on the wrapping alone: a reader that catches only the verifier's own
   exception type is one decoder change away from letting a truncated artifact
   through as an unhandled error, so **any** exception from verification is a
   refusal. (Revisions before Azazel-Knowledge#109 described this fixture as
   producing no `BUNDLE_*` code; that description was stale, the code was
   already real.)
2. **"Expired" is not a corruption.** It is correctly signed and passes every
   gate. Expiry has no manifest field: ADR-0015 D4 puts it per claim,
   evaluated by the consumer against its own `query_as_of`. A conforming
   reader verifies the artifact and then serves no indicator from it.
3. **Each fixture needs a fresh watermark.** They all declare
   `bundle_version 1` because they are independent cases, not a sequence.
   Reusing one watermark across them trips anti-rollback and masks the gate
   under test.

## The trust decisions are the consumer's, and they live in `anchors.toml`

`required_signer_role`, `minimum_security_epoch` and
`accepted_export_policy_digests` are read from the anchor, never from the
manifest. A bundle must not be able to state which role may sign it, which
epoch is acceptable, or which privacy policy this node will tolerate -- an
attacker holding any valid key could otherwise declare itself eligible. The
manifest may *claim* an epoch and *record* the policy digest it was built
under; whether those are good enough is decided here.

## Refreshing this copy

Re-emit at the new Knowledge revision, replace the files, regenerate
`FIXTURE.json`, and read the diff. A change in these bytes means the contract
changed and somebody has to say whether this node still accepts it.
