# Model Catalog and Artifact Contract

Status: **implemented** (`src/azazel_nexus/model_catalog.py`, Nexus#94).
This document fixes what may be *offered* to a Nexus node as a cognition
model, and — more importantly — what offering one does not mean.

This contract is deliberately settled before the import, staging, admission
and activation work it bounds ([#95](https://github.com/01rabbit/Azazel-Nexus/issues/95)–[#99](https://github.com/01rabbit/Azazel-Nexus/issues/99)).
Those steps inherit their safety boundary from here; if this moves later,
they all move with it.

Related: [M.I.O. runtime control plane](mio-runtime.md) ·
[offline model import](model-import.md) ·
[the operator screen](operator-view.md) ·
[the route policy](mio-route-policy.md) ·
[Hardware gates](hardware-gates.md) ·
[Core reserve measurement](core-reserve-measurement.md) ·
[Capability model](capability-model.md) ·
[Commissioning](commissioning.md)

## 1. The four states are four

The single most valuable thing in this module is a distinction that costs
nothing to lose and is very expensive to have lost:

| State | What a node is saying |
| --- | --- |
| `absent` | *We were told nothing.* No catalog was presented. |
| `empty` | *We were told that nothing is offered.* A signed, trusted catalog with zero entries. |
| `declared` | A trusted catalog names this model; **no artifact has been verified** on this node. |
| `present` | The artifact exists, matches its declared size and digest, and is weights rather than a program. |

`absent` and `empty` are not the same node. One has no trust anchor and no
statement; the other has a statement from a trusted signer. Collapsing them
turns "we never asked" into "there is nothing", which is the answer an
operator would act on.

**None of the four is `available`**, and `CatalogState` has no such member.
The word is absent from the vocabulary rather than forbidden by a check,
because a check can be edited while a member that does not exist cannot be
returned. `tests/unit/test_model_catalog.py` and the CORE CI job both assert
its absence, including over the module's constants.

### `present` is not `admitted`

`ModelReading.admitted` is always `False`, and constructing a reading with
`admitted=True` raises. Admission is decided elsewhere, against a **measured**
Core reserve — [`HG-05`](hardware-gates.md) — and this module has no
measurement. A verification that could also admit would be a verification
that could be mistaken for permission.

So the four states are four, and a fifth thing — *actually serving as a
provider* — is not reachable from this file at all. The status expression
for M.I.O. therefore stands unchanged:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration.

## 2. The catalog

A catalog is a single file, `catalog.signed`: a 64-byte detached Ed25519
signature followed by the payload it covers.

**Signed.** Verified with the standard-library verifier in `signature.py`
(Nexus#70), under keys supplied by the caller. The catalog imports and
verifies on a node with nothing installed, which the CORE CI job proves.

**Domain-separated.** The signature covers
`b"azazel-nexus/model-catalog/v1\x00"` prepended to the payload. Nexus signs
several kinds of thing under operator-held keys — Edge packages, revocation
lists, and now catalogs — and until this tag existed, the only thing keeping
a signature over one from reading as a signature over another was that their
schemas did not happen to overlap. A coincidence is not a boundary. The tag
is fixed, versioned, canonical and fixed-length.

**Versioned.** The payload carries `schema` and `version`. An unrecognised
schema is refused rather than best-effort parsed.

**Canonical.** `json.dumps(..., sort_keys=True, separators=(",", ":"))`,
UTF-8, with entries ordered by `model_id`. Entry order is not caller-chosen
because an id names exactly one entry — duplicates are refused — so the order
carries no meaning and could only be a way for two builders to disagree about
the same set of models. Signer and verifier cannot disagree about the bytes.

**Bound to the commissioning trust policy.** The payload names a
`commissioning_digest`, and `read_catalog` refuses a catalog whose digest is
not this node's. A catalog is a statement made *to a particular commissioned
node* by the trust policy that node accepted; it does not travel.

**Bounded.** At most 1 MiB and at most 64 entries, checked before parsing.

**Not shipped.** No catalog is committed to this repository, and CI fails if
one appears. A catalog signed under a commissioning policy that only exists
on a node cannot meaningfully exist in the source tree.

## 3. The entry

Thirteen fields, all mandatory, all symbolic or numeric — there is no free
text that steers anything:

| Field | Meaning |
| --- | --- |
| `model_id` | `^[a-z0-9][a-z0-9._-]{0,63}$`. What an operator selects. |
| `format` | From `KNOWN_FORMATS`. Unknown formats are refused, not attempted. |
| `digest` | `sha256:<64 hex>` over the artifact. |
| `size_bytes` | Positive; checked before the digest is computed. |
| `provenance` | Recorded, displayed, and never acted on. |
| `license_acknowledgement_required` | Whether the operator must acknowledge before use. The licence *text* is not carried here. |
| `runtime_abi` | From `KNOWN_RUNTIME_ABIS`. |
| `purpose` | What advice this model is for. |
| `context_limit` | Declared. |
| `declared_min_ram_mib` | Declared. |
| `declared_min_disk_mib` | Declared. |
| `declared_profile` | A `ResourceProfile` **ceiling**, not a grant. |
| `rollback_lineage` | Ids this entry supersedes. |

### Declared is not measured

The three `declared_*` fields and `context_limit` are for **display and
pre-check only**. They are inputs an operator may read before spending an
hour importing something that will not fit. They are not evidence that a
model fits, and nothing downstream may treat them as admission proof — the
same rule `capability-model.md` §2 states for every declaration. The thing
that decides fit is a measured Core reserve, which this module does not have
and does not pretend to.

### No free-text selection

An operator picks a `model_id` **from a verified catalog**. There is no
free-form model name, no provider string, and no URL anywhere in this
contract. An identifier that was not verified cannot be selected, so the set
of things that can be named is exactly the set of things a trusted signer
named to this node.

## 4. Artifacts: weights, not programs

`verify_artifact` refuses in a fixed order, cheap-and-absolute first, so that
a node never hashes gigabytes only to discover it was never permitted to:

1. **`LICENSE_NOT_ACKNOWLEDGED`** — required and not given.
2. **`STALE_ROLLBACK_LINEAGE`** — the entry is superseded by what is installed.
3. **`PATH_TRAVERSAL`** — the resolved path left the artifact root.
4. **`ARTIFACT_ABSENT`** — nothing is there; the entry stays `declared`.
5. **`SIZE_MISMATCH`** — declared size and actual size differ.
6. **`NOT_WEIGHTS`** — the leading bytes are an executable or an archive.
7. **`DIGEST_MISMATCH`** — the only refusal that costs a full read.

The filename is derived from the **digest**, never from `model_id`. A
filename built from a name in the catalog would be a filename the catalog
could steer.

`NOT_WEIGHTS` scans for ELF, PE, shebang, zip, gzip, tar, xz, bzip2, lz4 and
zstd magic. Nothing here unpacks an archive, runs a command, or takes an
install script. An artifact is a blob of weights that is either bit-for-bit
what the catalog declared or refused.

## 5. What a model may do once it is present

Nothing, yet — and by contract, never more than advise:

- A model serves **M.I.O. advisory cognition only**.
- It cannot change an Edge action, a lease, an enforcement decision, or an
  activation. Only the Edge-owned deterministic arbiter decides and enforces;
  `FULL → LITE → CORE` is a capability state, not an authority state.
- No prompt text, evidence body, secret, licence text or key material enters
  catalog metadata, audit records or status output.

## 6. The fourteen refusals

`CATALOG_ABSENT`, `CATALOG_UNSIGNED`, `CATALOG_INVALID`, `UNKNOWN_MODEL`,
`UNKNOWN_FORMAT`, `UNKNOWN_RUNTIME_ABI`, `UNDEFINED_PROFILE`,
`STALE_ROLLBACK_LINEAGE`, `LICENSE_NOT_ACKNOWLEDGED`, `ARTIFACT_ABSENT`,
`SIZE_MISMATCH`, `DIGEST_MISMATCH`, `NOT_WEIGHTS`, `PATH_TRAVERSAL`.

Each is named, each is reported on its own, and each is reachable by a test
that reaches only it. A refusal that could only be observed in combination
with another would be a refusal nobody could act on.
