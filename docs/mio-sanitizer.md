# The deterministic sanitizer, and three things the contract leaves open

Status: **implemented** (`src/azazel_nexus/sanitizer.py`), unit tested and
mutation checked. This is `docs/mio-runtime.md` §6 and
`docs/IMPLEMENTATION_SPEC.md` §6.3. **No egress path exists anywhere in this
repository**, before or after this change.

Related: [M.I.O. runtime control plane](mio-runtime.md) ·
[M.I.O. dual cognition doctrine](mio-dual-cognition.md) ·
[contract ownership](contract-ownership.md)

## 1. Why this could be built before the remote path

`IMPLEMENTATION_SPEC.md` §6.3 hands the frame's canonical **wire shape** to
Fabric `mio_contracts`, which is not released — and in the same paragraph
says:

> Privacy classes, sanitizer policy, and alias key material are **Nexus-local**.

So what may leave, under which class, in what form, is decidable here. Only
how it is encoded on the wire is not. The boundary can exist before the wire
does, and this one is built so that adopting `mio_contracts` later changes the
encoder and nothing else: `sanitize` returns bytes from one canonicaliser, and
every rule above it is expressed over field names and classes.

## 2. The rules, and the failure each one prevents

| Rule | The failure it prevents |
| --- | --- |
| Deny is the default, applied to the **policy** as well as the frame | A policy that is ambiguous resolves to the friendlier reading |
| A redacted field is **absent**, not masked | A mask still says the field was present and how long it was |
| Redaction is checked **before** the allowlist | Every real frame carrying an address gets denied instead of cleaned |
| An unlisted field **denies the frame** | A field quietly dropped is a disclosure decision nobody made |
| Aliases carry the **mission in the derivation** | A stable alias lets a remote party join two missions on one subject |
| The alias input is **length-prefixed** | mission `a` + subject `b\|c` and mission `a\|b` + subject `c` hash alike |
| Over budget **denies whole** | A truncation passed off as a complete answer |
| A denial carries **no frame object at all** | A caller one refactor away from sending it |
| Nothing reads a clock, a random source or the environment | A sanitizer that cannot be replayed cannot be audited |

The last one is checked by parsing the module for those imports and for
`now`/`utcnow`/`today`, and by a **frozen expected frame**: the bytes in
`tests/unit/test_sanitizer.py` were produced once and are now a fixture, so a
change in field order, separator or key set breaks the test. Comparing a call
to itself would have proved nothing.

## 3. Three discrepancies, recorded rather than resolved

These are places where the contract as written does not decide something the
implementation had to. **None of them is settled here.**

### 3.1 The example policy allows a class with no field allowlist

`IMPLEMENTATION_SPEC.md` §11 writes:

```yaml
classes:
  P0-public: {remote: allow}
  P1-sanitized: {remote: allow, fields: [event_class, role, count, time_bucket]}
```

`P0-public` is marked `remote: allow` with no `fields`. Against §6's
*"allowlist by privacy class; anything unlisted is denied"*, that could mean
every field or no field — the two readings are opposite and both defensible.

**This loader refuses it**, naming the ambiguity, because §6's own rule is
that *"ambiguous classification, invalid structure, or unavailable policy
resolves to deny remote egress — deny-on-ambiguity is not a fallback, it is
the default."* Refusing an ambiguous policy is that rule applied one level up.

**Open:** whether §11's example should gain an explicit `fields` list for
`P0-public`, or whether `remote: allow` without `fields` should be given a
defined meaning. Either is a contract edit and is not made here.

### 3.2 The policy is YAML in the contract and this package parses none

`IMPLEMENTATION_SPEC.md` §3 puts the policy at
`/etc/azazel/mio/sanitizer.yaml`. `pyproject.toml` keeps `dependencies = []`
and says why: *"a dependency added here is a dependency the CORE path can fail
on."* A YAML parser on the CORE path is exactly that.

`SanitizerPolicy.from_mapping` therefore takes an **already-parsed mapping**
and this package ships no loader. Where the policy lives and in what syntax is
a packaging decision — JSON in a generation tree, a vendored parser, or a
parse step outside the CORE path — and it is not one a module makes by
reaching for an import.

**Open:** which of those, decided against the dependency rule rather than
around it.

### 3.3 Three policy keys the example does not have

§6 requires that *"identities are replaced by aliases"* and that *"coarse time
and count buckets replace exact timestamps and counts"*, without saying which
fields those are. The example policy has `redactions:` and nothing equivalent.

This implementation adds `aliases:`, `time_buckets:` and `count_buckets:`,
each a list of field names, alongside `redactions:`. That is within
§6.3's *"sanitizer policy … are Nexus-local"*, and it is an addition rather
than a reading of something already written, so it is recorded here.

The alternative — inferring which fields are identities from their names —
was rejected: a sanitizer that guesses which field is an identity fails
silently on the one it has not seen before.

## 4. The buckets

Time coarsens to the **UTC hour**. A timestamp that cannot be parsed denies
the frame rather than passing through.

Counts coarsen to `0`, `1`, `2-5`, `6-20`, `21-100`, `>100`. A value that is
not a non-negative integer — including a `bool`, which Python would otherwise
accept as one — denies.

Both are deliberately coarser than they could be. A bucket exists to stop a
remote party counting, and a fine bucket does not.

## 5. What this does not establish

- **No remote path.** No client, no socket, no endpoint, no egress function,
  in this module or in `cognition.py`. Both are scanned for their absence.
- **No response handling.** §6's *"a remote response cannot request or trigger
  follow-up disclosure"* is a rule about a path that does not exist.
- **No rate or privacy budget.** §5's per-mission request rate and cumulative
  privacy budget need state across requests; `sanitize` is a pure function and
  holds none.
- **No wire shape.** The bytes here are canonical for *this* implementation.
  They are not an interoperable form and must not be treated as one until
  Fabric `mio_contracts` is read.
