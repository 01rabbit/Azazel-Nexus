# Source Registry and the Artifact Fetch Service

Status: **implemented** (`src/azazel_nexus/source_registry.py`,
`runtime/src/azazel_nexus_runtime/artifact_egress.py`, Nexus#105).
Where a source symbol resolves, under what conditions, and which single
module may open a connection.

Related: [the model catalog contract](model-catalog.md) ·
[online acquisition](model-acquisition.md) ·
[offline model import](model-import.md) ·
[runtime boundary](runtime-boundary.md) ·
[the operator screen](operator-view.md) ·
[the deterministic sanitizer](mio-sanitizer.md)

## 1. Two authorities that cross, and neither contains the other

```
catalog (signer A)              registry (administrator B)
  model_id                        source_id
  digest / size                     → host, port, path
  source_id ─── symbol ────────────→ certificate pin
  (cannot spell a location)          client identity
                                     bandwidth ceiling
                                     allowed artifact classes
        \                          /
         └── both, or no candidate ┘
```

**The catalog signer cannot name an endpoint. The registry administrator
cannot introduce a model.**

| an attacker holding | cannot |
| --- | --- |
| the catalog signing key | point this node at a host of their choosing — the symbol resolves here, and a symbol this registry does not carry resolves to nothing |
| the registry | bring in a model — models are named by the catalog, and a `model_id` the catalog does not carry is not a candidate |

Only both together produce an arbitrary download. **The breadth that
compromise requires is what this separation buys**, and a design where one
document carried both would hand that breadth to whoever held it.

## 2. Separate policies, enforced rather than described

Two documents under one trust policy is one key that signs both, and the
crossing collapses to a single point.

So `CommissionedSources` **refuses to be built** when a key id — or the same
key material under two ids — appears in both roles. Not a paragraph in a
document. A constructor that will not build.

Domain separation carries the rest:

| document | domain |
| --- | --- |
| catalog | `azazel-nexus/model-catalog/v1\0` |
| registry | `azazel-nexus/source-registry/v1\0` |

Different kinds, so different domains. Even the same key material cannot
produce a signature that reads as both — the tag is part of what is signed.
(These `v1`s move by the rule in [the catalog contract](model-catalog.md)
§2.1: kind, canonicalisation, or cross-protocol separation. Never a field.)

## 3. What a registry record carries

| field | note |
| --- | --- |
| `source_id` | the symbol the catalog names |
| `host` | a **hostname**. No scheme, port, path, query or credentials — and no address literal |
| `port`, `path_template` | separate fields; `{digest}` is the only substitution |
| `certificate_pin` | `sha256:` over the **public key**, not the certificate |
| `client_identity` | a **name**. The commissioned key store holds the material; the registry never carries a key |
| `bandwidth_bytes_per_second` | a ceiling, so an acquisition cannot starve a node whose job is to keep answering while it happens |
| `allowed_artifact_classes` | at least one, enumerated. A source approved for weights is not thereby approved for anything else |

**An address literal in `host` is refused.** The registry *names* a source;
the commissioned address allowlist says which addresses that name may resolve
to. A literal would be one document doing both jobs and skipping the
allowlist entirely.

**The pin is over the key, not the certificate.** A server that renews its
certificate keeps its key, and a pin over the whole certificate would turn
every ordinary renewal into an outage indistinguishable from an attack —
which is how pinning gets switched off.

## 4. One module may open a connection, and it is named

`artifact_egress.py`. Everything else in the runtime distribution speaks
`AF_UNIX` or reads the kernel.

`tests/unit/test_runtime_boundary.py` used to assert that *nothing* in the
package could reach an internet address family. It now asserts "nothing
**except this module**", and **records the exemption by name**, asserts the
module exists, asserts it actually uses its exemption, and asserts the set
has exactly one member.

A boundary that moved and left no trace is a boundary nobody can audit. "The
test still passes" would have been true either way.

The exemption is by **file name**, never by a marker a file can grant itself:
a module that took egress by writing a comment would be a module that granted
itself egress.

### What the loosening did not change

`functional_readiness.py` declares Deception Lite `loopback-only`, and its
stated reason is the absence of any internet address family **that binds**.
Outbound TCP does not make a decoy reachable — that needs a `bind` to a
non-loopback address and a `listen` — so the claim stands. The test that
backs it was broader than the declaration; it has been narrowed to what the
declaration actually claims, plus a new check that the exempt module never
binds, listens or accepts.

Had the declaration claimed the broader reason, the honest move would have
been to change the declaration instead.

## 5. What the fetch service refuses

| refusal | why |
| --- | --- |
| a peer whose public key does not match the pin | CA trust alone is one compromised issuer away from any host. Checked as the **first act after the handshake** — nothing is requested from an unpinned peer |
| a redirect | a fetcher that follows one is a fetcher whose allowlist is bypassed in a single hop |
| a resolved address outside the allowlist | DNS is an attack surface, and "the name was right" is not "the address was" |
| an empty allowlist | a refusal, never "anything" |
| a response larger than declared | a file that grew is not the file that was planned for |
| a header block that will not end | refused **unparsed**; a ceiling enforced after reading everything is a ceiling on nothing |
| a 206 that does not start where `Range` asked | the bytes would append to what is staged, the length would often come out right, and only the digest would notice — after the whole transfer |
| a deadline passed | a fetch with no deadline is one nobody learns has stopped |
| any status but 200 (whole) or 206 (resumed) | |

Every bound is an argument and none has a permissive default. A zero or
negative deadline or bandwidth is refused rather than treated as unlimited.

## 6. What it never emits

No credential, no private key material, no token, no request body and no
assembled URL reaches a return value, an exception message or an event. A
refused redirect does not echo the `Location` it refused.

There is no command line here at all — this is a function, not a process.
That is deliberate: an argument vector is readable by every user on the host,
so a design that passed a token as an argument would have published it.

## 7. It is not the inference transport

| | model artifact download | inference request |
| --- | --- | --- |
| carries | public weights | this node's observations |
| privacy class | none — content owes nothing to what this node saw | P0–P3, and `P2`/`P3` never leave |
| digest | known in advance | there is no such thing |
| verified by | the same path an offline import takes | not applicable |

Reusing one for the other would turn **the route that fetches weights** into
**the route that sends observations**. Different service, different identity,
different policy.

`tests/unit/test_artifact_egress.py` asserts the privacy-class vocabulary is
**absent** from the module body, and that it imports nothing from
`azazel_nexus`: a module that cannot name a privacy class cannot carry one,
and one that imported policy could apply its own.

## 8. A candidate is not a permission

`resolve_candidate` produces a `DownloadCandidate` only when the catalog
names the model, the registry resolves its symbol, and the class is allowed.

It carries no operator confirmation — that is
[acquisition](model-acquisition.md)'s, and still separate — and admission is
further away still, behind a measured Core reserve
([`HG-05`](hardware-gates.md)) and every gate after it.

`Outcome` has no `VERIFIED` and no `PROMOTED`. This layer decides neither.

## 9. Testing

The failure paths are driven against a **real local TLS server** on loopback,
with a certificate generated for the run and discarded. No fixture carries a
key that exists anywhere else, and nothing reaches a real network.

The DER walk that extracts the public key for pinning is checked
**differentially against OpenSSL's own extraction**, rather than against a
fixture this suite wrote — the only comparison worth making for a minimal
parser.
