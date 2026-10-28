# Remote inference transport (#98)

This is **not** work that makes a remote AI usable. It fixes the boundary a
future remote path would have to cross, before anything can argue for an
exception on the grounds that it is inconvenient.

Nothing described here contacts anything on any node this build runs on.

---

## 1. Three services, and none inherits another

| service | account | socket | may | resolves through |
| --- | --- | --- | --- | --- |
| `az-model-fetchd` | `azfetch` | `fetch` | pull public bytes **in** | Source Registry |
| `az-mio-locald` | `azmio` | `mio` | run one local binary | package allowlist |
| `az-mio-remoted` | `azremote` | `remote` | push a sanitised frame **out** | **Provider Registry** |

Separate distribution entry point, separate system account, separate Unix
socket, separate systemd profile, separate egress exception, separate
commissioned registry.

`ServiceProfile` refuses a profile holding more than one of
`is_artifact_fetcher`, `is_model_host`, `is_inference_transport`. Pulling a
file, running a program and pushing a report are three acts with three blast
radii; a unit holding two of them is a node where one compromise is two.

The three capabilities are separate in activation too —
`ARTIFACT_TRANSPORT`, `LOCAL_MODEL_PROVIDER`, `REMOTE_INFERENCE_TRANSPORT` —
and wiring one grants none of the others.

### What is shared, and why it is safe

One thing: `azazel_nexus.spki`, a DER walk that extracts a certificate's
SubjectPublicKeyInfo. It imports no `ssl` and no `socket` and decides
nothing. Two copies of a certificate-key extraction is one copy that gets a
fix and one that does not — and the one that does not is still pinning, just
to whatever a subtly different walk produced.

Sharing a parser is not sharing an egress exception.

---

## 2. A caller supplies two symbols and something it cannot mint

`remote.infer` takes `provider_id` and `request_id`, both `IDENTIFIER`.
`protocol.ArgumentKind` has no free-text member, so there is no way to
*express* a URL, a header, a proxy, a certificate path, a model name, a
prompt, an evidence blob or a privacy class in a request.

The payload is exactly two base64 strings — the frame and its envelope —
decoded under a ceiling with `validate=True`, because a lenient decoder
silently drops characters it does not recognise, which would mean the bytes
the envelope was checked against are not the bytes that were sent.

**A caller cannot say what class its frame is.**

---

## 3. The envelope: what the daemon accepts as proof of sanitisation

A `SanitizerDecision` is a Python object. Anything that can construct one can
claim its contents, and "the caller told us this frame is `P1-sanitized`" is
a caller saying so. What reaches the daemon has crossed a process boundary,
so what it receives is bytes.

It believes one shape: a detached Ed25519 signature under
`azazel-nexus/sanitized-envelope/v1` over a canonical payload (schema
`azazel-nexus/sanitized-envelope/2`) binding six things a forgery would have
to get right together.

| bound | what a mismatch would otherwise allow |
| --- | --- |
| `content_digest` | an envelope minted for one frame reused to send another |
| `privacy_class` | a caller asserting its own class |
| `policy_revision` | a frame sanitised under a policy since withdrawn |
| `expires_at` | an envelope kept and used later, under conditions nobody re-checked |
| `nonce` + `provider_id` | the same authorised request replayed, or sent to a provider it was never authorised for |
| `opt_in_generation` | a frame authorised under a remote opt-in the operator has since withdrawn |

The nonce is spent **last**, after every other check: spending it earlier
would let a malformed envelope burn the nonce a correct request needs. The
ledger refuses when full rather than evicting — an eviction policy is a
policy for forgetting that a request was already sent.

`now` is passed in. A component that read its own clock would have an expiry
nobody can reproduce, and an expiry nobody can reproduce is one nobody can
test.

### Domain separation

A different **kind** of signing target from a catalog or a registry: those
authorise a *document*, this authorises *one request, once*. A key that signs
catalogs does not thereby authorise egress of a frame, even if the same key
holds both roles.

### Remote opt-in at the send gate

`opt_in_generation` is a positive integer (an envelope minted with no opt-in
in force authorises nothing); schema 1, which bound none, is refused as an
unknown schema. Opening the envelope only believes the number. Immediately
before the transport -- and before the "no transport" refusal, so this runs
in the shipped build too -- the daemon takes the send gate of the remote
opt-in store ([runtime](mio-runtime.md) *Remote opt-in store*), and refuses
with `opt_in_unavailable` (store unreadable, malformed, rolled back or busy),
`opt_in_not_granted` (absent, incomplete or withdrawn) or
`opt_in_generation_mismatch` (any other generation in force). The gate stays
held until the transport returns, and a withdrawal returns only after it has
drained, so no send starts after a confirmed withdrawal. Without an injected
reader the daemon reads entryd's store as `azmioentry`; on a node where
`azremote` cannot read that leaf (every node as shipped) the answer is
`opt_in_unavailable`. Making it readable to `azremote` is part of wiring a
transport, not of this build.

### It ships unmintable

No signer here, no commissioned sanitizer key. No envelope can be produced
and none would verify.

---

## 4. The Provider Registry is not the Source Registry

| registry | says | signed by |
| --- | --- | --- |
| model catalog | which models exist | the catalog role |
| Source Registry | where an **artifact** is fetched from | the registry role |
| Provider Registry | where an **inference request** is sent | the provider role |

`ProviderTrust` refuses a key holding the provider role and another. One
holder could then name a model *and* say where this node reports on it, which
is the single point all three exist to remove.

A record fixes host, port, path template, certificate pin, client identity,
**the model as a symbol in the record**, request and response ceilings, the
deadline, and which privacy classes the provider may receive at all. A record
permitting a never-remote class cannot be built. The client identity is a
*name*; key material never passes through this document.

It ships absent.

---

## 5. The fourth refusal of P2 / P3

`routing`, `sanitizer` and `remote_trust` each refuse a class that may not
leave. The transport is the fourth, and it is not a replacement for any of
them.

The instant before a byte leaves is the last place a mistake is still a
mistake rather than a disclosure. Not checking there is betting that the
other three are correct — and they are three pieces of code, each of which
can be edited by somebody who has read only one of them.

`tests/unit/test_mio_remoted.py` drives exactly that: the envelope layer's
own class check is **switched off in the test**, the provider record's check
is bypassed, and the service still refuses on its own reading of the signed
class. The test first asserts the disabling worked, because otherwise it
would prove nothing.

---

## 6. mTLS is mutual or it is not this

`inference_egress.tls_context` requires a CA, a client certificate and a
client key. The artifact fetcher's equivalent takes the client pair
optionally — a public mirror may not ask who is pulling. Here it is not
optional.

One-way TLS is TLS. It is not mTLS, and a context that could be built
without a client identity is one that will be.

Verified transport-side, every attempt: the chain, the dates, the hostname,
then the SPKI pin **layered on top**, then the provider allowlist, the
resolved address against the commissioned set, the request ceiling before
the connection is opened, the response ceiling, the deadline and
cancellation.

A redirect is **not followed and its target is not read** — a transport that
followed one is a transport whose allowlist is one hop wide.

DNS is an attack surface, not a permission: a name resolving outside the
commissioned addresses is a name that has been moved.

### A rejected client certificate is a TLS failure, not an interruption

Under TLS 1.3 the server's verdict on our client certificate arrives *after*
the client considers the handshake finished, so it surfaces as an alert on
the first read. Reporting that as an interruption would send an operator to
look at the network when the fact is that this node's identity was not
accepted. Found by the fixture tests, and classified as what it is.

---

## 7. No retry inside the transport

`route_selection` decides whether a failure falls back, and it decides
**once**. A retry inside the transport would spend that single fallback
silently and report the slower result as though the first attempt had gone
that way — a failure nobody sees. Scanned for by name.

---

## 8. The response is advice, and advice is never authority

The guarantee is not that a filter removes the dangerous parts. It is that
**no type here is one an executor consumes**: `AdvisoryText` is a bounded
string, `AdvisoryData` a flat mapping of strings, numbers and booleans. No
nesting, because a structure that can nest can carry a payload past a check
written for the top level.

Refused loudly: tool calls, URLs and schemes, shell prompts, commands,
enforcement instructions, lease and activation instructions, unit
instructions, control and format characters (a bidirectional override makes
text read differently from how it parses), unknown keys, and anything over
the provider's ceiling.

There is no partial success. A half-read answer from an untrusted system is
an answer whose missing half nobody chose.

---

## 9. Words that are not available

`TransportOutcome` has no `ANSWERED` and no `COMPLETED`. Whether a request
was answered is `route_selection`'s word, decided from the transport result
*and* whether the advisory validated.

`TerminalEvent` gained three, each with its own word rather than folded into
`FAILED`:

| event | why not `FAILED` |
| --- | --- |
| `TLS_FAILED` | a provider that is up and answering with the wrong key is not one that is down |
| `SANITIZER_FAILED` | nothing went wrong with the provider; **this node declined to send** |
| `NOT_ADVICE` | a provider that answers with a command has answered, but it has not advised |

`SANITIZER_FAILED` produces `REFUSED` even when a fallback exists: falling
back to a different remote would be this node trying again elsewhere with
something it just decided must not leave.

---

## 10. Nothing is written down that must not be

No prompt, no evidence, no frame content, no response body, no credential,
no private key, no token, no assembled URL — not in a reply, not in an audit
event, not in the journal. Refusal reasons name **shapes and quantities**; a
reason that quoted the response would carry attacker-authored text into the
journal.

There is no command line to leak one through: the executable takes no
arguments at all.

---

## 11. `HG-05` still refuses, and the status expression does not move

A green local TLS end-to-end run says the transport is correct. It says
nothing about whether a provider may be admitted or activated, which the
unmeasured Core reserve refuses (`docs/hardware-gates.md` HG-05,
`docs/mio-local-runtime.md` §6).

The M.I.O. status expression is unchanged:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration

---

## 12. What this does not establish

- No real provider, no real endpoint, no real credential, no real inference.
  The TLS fixtures are committed test-only material that signs nothing
  outside the suite, and the pins are fixed constants — a fixture
  regenerated without its pin fails rather than silently pinning to whatever
  was produced.
- The Provider Registry ships absent and no key holds the sanitizer role.
- This path does not wait on Fabric#25 (that is the integration broker's
  transport, #16). What it does wait on is listed in
  [the issue map](issue-map.md#remote-inference-what-it-waits-on-not-fabric25).
- What systemd actually enforces is `HG-01`/`HG-02`, which no test here runs.
