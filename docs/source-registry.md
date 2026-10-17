# Source Registry and the Artifact Fetch Service

Status: **implemented** (`src/azazel_nexus/source_registry.py`,
`runtime/src/azazel_nexus_runtime/model_fetchd.py`,
`runtime/src/azazel_nexus_runtime/artifact_egress.py`, Nexus#105).
Where a source symbol resolves, under what conditions, and which single
**service** may open a connection.

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

## 4. One **service** may open a connection, and it is named

`az-model-fetchd` — its own unit, its own system account (`azfetch`), its own
socket, its own runtime directory, and one writable path. Everything else in
the runtime distribution speaks `AF_UNIX` or reads the kernel.

A module with a socket in it is a *module* boundary. This is the service
boundary, and it is fixed in three places that must agree:

| where | what |
| --- | --- |
| `hardening.py` | the only `ServiceProfile` with `is_artifact_fetcher=True`, and the only one permitted `AF_INET` |
| `packaging/` | its own account, its own directory at `0750`, masked on install, `disable` in the preset |
| `model_fetchd.py` | one verb, symbolic arguments only, a `main` that takes no arguments at all |

`IPAddressDeny=any` **stays on it.** The exemption opens an address *family*,
not an address: what the service may reach arrives as a commissioning drop-in
built from the signed Source Registry, so the unit as shipped reaches nothing.

### The unit ships, and is not granted

Being governed is not the same as being granted. Activation's tiers ask what
the *node* has established — a verified generation, health, a lease, a
commissioning record — and every one of those is satisfied on an ordinary
healthy node. None of them asks whether this **build** contains a transport
for the unit to use.

So `UnitDefinition` carries a fourth requirement alongside the tier:

```
UnitDefinition("azazel-model-fetchd.service", SUPPORTING, "azfetch", …,
               wiring=ARTIFACT_TRANSPORT)
```

The unit is withheld as `wiring_absent` until fetch commissioning loads
successfully (or the legacy `ENDPOINT_FOR` table is nonempty). A fresh node
still has no artifact transport. `activated.wired_capabilities()` uses the same
`load_fetch_commissioning` reader as the daemon; an invalid file leaves it
unwired. This requires the full trust, registry, catalog, TLS, address and
consent set described in [model-acquisition.md §9](model-acquisition.md#9-the-composed-path-96).
The daemon fetches only; root promotes with `azazel-nexus model-import-fetched`.

Complete fetch commissioning makes the transport wired without a code change;
activation still requires its other commissioning, tier and health gates.

The unit, its account, its directory, its socket and its hardening ship
either way. The service boundary is part of the product whether or not
anything is commissioned yet; an uncommissioned daemon refuses startup.

### A caller cannot say where the bytes come from

`protocol.ArgumentKind` has no free-text member. A request carries
`model_id`, `source_id`, `digest`, `size_bytes` and `resume_from` — and there
is no way to *express* a URL, a proxy, a header, a shell command or a file
path in one. That is not a check the service performs; it is a shape a
request cannot take.

The destination is derived from the digest in the **registry-resolved** plan,
never from the request: a caller who could name a file could name any file.

There is no command line to leak a credential through either — `main` refuses
any argument vector, because an argument vector is readable by every user on
the host.

### The endpoint table ships empty

An earlier version filled it with `.invalid` hosts and had the constructor
refuse anything else. That stops a mistaken fetcher, and it is the wrong
shape: **going to production would then mean loosening the validator**, and a
design whose next step is to relax a check is a design that gets relaxed —
probably in a hurry, probably by someone who did not write it.

So the validator refuses what is actually dangerous (address literals, and
anything smuggling a scheme, a port, a path, a query or userinfo into a host
field) and accepts an ordinary hostname. The table is empty instead, and **a
real endpoint is commissioned data**: it arrives in the signed Source
Registry, reviewed, signed and audited. Test fixtures put loopback endpoints
in a registry of their own.

Two independent scans used to assert that *nothing* in the package could
reach an internet address family — one in `test_runtime_boundary.py` over the
source, one in `test_runtime_hardening.py` over the rendered units. Both now
assert "nothing **except this one**", both **record the exemption by name**,
and both assert the exempt set has exactly one member. The source scan also
asserts the exempt module exists and uses its exemption; the unit scan
asserts that a profile taking an internet family without declaring itself the
fetcher cannot be built, and that one declaring itself the fetcher without
using an internet family cannot either.

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
| a certificate that does not verify | issuer, dates and name, against the **commissioned** anchor — never the host's own store. The pin is layered on this, not a substitute: it answers "is this the key I expect" and nothing about expiry, name or issuer |
| a peer whose public key does not match the pin | checked as the **first act after the handshake** — nothing is requested from an unpinned peer |
| an empty pin | not "any key". A fetch with nothing to compare against does not happen |
| a client certificate the server will not accept | mutual: the node shows who it is, or it is not served |
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
using **fixed certificates committed under `tests/fixtures/tls`**. The tests
use the standard library's `ssl` and nothing else, and **none of them skips**.

An earlier version generated a certificate with the `openssl` CLI at test
time and skipped when the CLI was absent. That made the binary's presence,
version and command-line behaviour a precondition of exactly the tests that
mattered most — so the ones most likely not to run were the TLS ones, and a
green pipeline would not have said whether they did.

The expected SPKI pins are **fixed constants**, recorded when the fixtures
were made. A pin the test computed from the certificate it is checking would
go on agreeing with itself after the extraction it is meant to verify had
broken.

What runs every time: untrusted issuer, expired certificate, hostname
mismatch, client certificate absent, client certificate the server will not
accept, unknown pin, empty pin, redirect, an address outside the allowlist,
an oversized response (including an overrun arriving with the headers),
unterminated headers, an unexpected status, interruption, resume, a peer that
ignores `Range`, the deadline, and a digest mismatch after a resume.

`tests/unit/test_tls_fixture_hygiene.py` scans the distribution by **content**
and refuses to find this key material in production source, the privileged
runtime, packaging, ops, tooling, CI or docs — and refuses to find *any*
private key outside the fixture directory. A private key committed to a
repository is a compromised key; these are committed because they are
worthless, and that scan is what would say so if one ever stopped being.
