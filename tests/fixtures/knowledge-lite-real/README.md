# Real Knowledge Lite builder fixture

`lite.tar.gz` is unmodified output from Knowledge commit
`09d234cde0ceb447a3ebc7e9704eef4758ac4a4d`:
`tools/bundle_build.py build-lite`, using that commit's default export policy.
`provenance.json` records the archive and policy digests. Its detached
`provenance.sig` is verified with the same public lab key as the archive.
Tests pin the expected policy file digest and semantic policy digest, verify
the original manifest signature and table digests, and check manifest selection
inputs and row counts. This binds these fixture components to the lab signer;
it does not cryptographically attest the upstream Git commit or builder process.
An external build record under CodexWork records the clean source revision,
command, synthetic inputs, actual builder/policy hashes, and original manifest
and signature for review against the pinned Knowledge checkout.

The source is a newly migrated synthetic intel database containing one T1110
reference. There are no real feeds, operators, incidents, model outputs or
credentials. A fresh random lab signing key and alias key are created in a
private temporary directory and discarded. Only the public anchor is retained.
Regeneration intentionally produces a different signer/archive digest.

To regenerate with Knowledge's core Python dependencies installed:

```sh
python -B tests/fixtures/knowledge-lite-real/build.py /path/to/clean/pinned/Knowledge /path/to/new/evidence-dir
```

The generator refuses a dirty or different Knowledge revision and never writes
into Knowledge. It does not extract, edit or re-sign the builder's archive.
The default export policy intentionally omits technique descriptions; this
fixture preserves that output rather than adding prose in the consumer.

`test_real_knowledge_lite_fixture.py` checks unmodified import and signed
reference provenance. The `knowledge-builder` normal-intake process case uses
`run_import` → public `knowledge.import` socket → production `LiteImport` plus
production `auditd`, then sends the standard Edge fixture through intake and
checks the explainer's separately authenticated Knowledge lookup. It checks
that the admitted archive still has the builder output digest. It retains the
existing synthetic case and tests both installed and absent MIO package states
when run through the disposable Linux process runner.

Linux, root and the runner's disposable service identities are required for
that process case. A host skip is not evidence of successful process execution.
