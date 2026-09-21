# Remote provider commissioning — what must be settled before anything connects (#116)

This document is **preparation, not permission**. It fixes the shape of the
decisions a deployment has to make. It authorises no implementation and no
connection, and it contains no real endpoint, no real credential and no real
pin — `tests/unit/test_remote_commissioning_doc.py` scans for exactly that.

The transport's software boundary is implemented and CI-verified (#113). What
is not done is **deployment validation**, and the gap between those two is
this document.

---

## 1. The bundle

A commissioning bundle is **one signed document plus the trust that reads
it**. The document's shape is fixed by `provider_registry.py`, and the table
below is generated from the same code the verifier uses — not transcribed.

```json
{
  "schema": "azazel-nexus/provider-registry/1",
  "version": 1,
  "commissioning_digest": "sha256:…",
  "providers": [
    {
      "provider_id": "…",
      "host": "…",
      "port": 443,
      "path_template": "/v1/{model}/advise",
      "certificate_pin": "sha256:…",
      "client_identity": "…",
      "model_id": "…",
      "max_request_bytes": 65536,
      "max_response_bytes": 65536,
      "deadline_seconds": 20,
      "allowed_privacy_classes": ["P1-sanitized"]
    }
  ]
}
```

Signed as `azazel-nexus/provider-registry/v1` + `\x00` + payload, detached
Ed25519, 64 bytes of signature followed by the canonical payload. The domain
tag is prefixed **before** the payload and is part of what is signed, so a
signature made for another kind of document does not verify here. Canonical means
`sort_keys=True, separators=(",", ":")` — the verifier re-serialises what it
parsed and compares, so a signature over a differently-ordered payload does
not verify.

### What the bundle does **not** contain

| absent | where it lives instead |
| --- | --- |
| any private key | the node's own filesystem, readable by one account |
| the mTLS client key | as above; the bundle names the **identity**, not the key |
| a model name a caller supplies | `model_id` is *in* the record |
| a URL | host, port and path template are separate fields |

A `client_identity` is a bounded name. Key material is not a name and does
not belong in a document that is read aloud.

---

## 2. The three roles, and why one holder may not have two

| registry | says | role |
| --- | --- | --- |
| model catalog | which models exist | catalog |
| Source Registry | where an **artifact** is fetched from | registry |
| Provider Registry | where an **inference request** is sent | **provider** |

`ProviderTrust` refuses a key holding the provider role **and** another —
both by id and by key material, because two ids for one key is one key. One
holder could otherwise name a model *and* say where this node reports on it,
which is the single point all three registries exist to remove.

Domain separation holds even if that refusal were removed: a catalog
signature does not verify under the provider domain, whatever key made it.

---

## 3. What a deployment must settle

Each is a separate decision with a separate owner. They are listed
separately because **a single "yes" covering all of them is a person
consenting to one thing and authorising nine.**

| # | decision | who owns it | recorded as |
| --- | --- | --- | --- |
| 1 | which provider, and under what contract | the operating organisation | contract reference |
| 2 | who owns the endpoint and answers for it | the provider's organisation | named individual or role |
| 3 | which privacy classes may be sent | the data owner | `allowed_privacy_classes` |
| 4 | the mTLS identity this node presents | the operating organisation | `client_identity` + key placement |
| 5 | the CA this node trusts for that endpoint | the operating organisation | CA file, node-local |
| 6 | the SPKI pin | both, jointly | `certificate_pin` |
| 7 | the sanitizer role key | the operating organisation | commissioned key set |
| 8 | revocation and rollback: what, in what order, by whom | the operating organisation | runbook + named owner |
| 9 | the decision to connect at all | the accountable owner | dated record |

### The pin is over the key, not the certificate

A server that renews its certificate keeps its key. Pinning the certificate
turns every ordinary renewal into an outage indistinguishable from an attack
— which is how pinning gets switched off. Rotation therefore means: publish
the new key's pin, accept both for an overlap agreed in advance, then
withdraw the old one. The overlap is a **commissioning decision**, not a
default this code picks.

### The sanitizer key does not exist yet

**This build contains no signer.** Nothing can mint an envelope, so nothing
verifies. Commissioning one is decision 7, and it is the decision that turns
the whole transport from inert to operable — which is why it is listed
separately from the provider's own trust material.

---

## 4. Acceptance checklist, before any real connection

Each line is confirmed on its own. Nothing here is satisfied by confirming
the line above it.

- [ ] the provider and the contract are identified
- [ ] the endpoint's owner and responsible party are named
- [ ] the privacy classes permitted to this provider are stated
- [ ] the mTLS identity is issued and its key placed, readable by `azremote` alone
- [ ] the CA for that endpoint is placed
- [ ] the SPKI pin is obtained from the key, and the rotation overlap agreed
- [ ] the sanitizer role key is commissioned
- [ ] revocation and rollback have a runbook and a named owner
- [ ] the decision to connect is recorded, dated and attributable

---

## 5. HIL procedure (to be executed, not now)

| step | what it establishes |
| --- | --- |
| real mTLS handshake | the identity is accepted **by the provider**, observed from their side as well as ours |
| real request sanitization | a real frame passes the sanitizer, an envelope is minted, the transport believes it |
| deadline / cancellation | behaviour under real network latency, not a loopback's |
| network-loss fallback | the router's once-only fallback works when the link actually drops |
| certificate rotation | the overlap works, and the old pin stops working afterwards |
| provider compromise | a changed key is refused by the pin, loudly |

Each step is a separate record. A step that was not executed is not a step
that passed.

---

## 6. What does not change when a provider arrives

**`P2-mission`, `P3-restricted` and un-sanitised `P1` remain unsendable, and
the check that proves it runs under the same conditions as today.**

`tests/unit/test_mio_remoted.py` drives the transport's own refusal with the
envelope layer's class check **switched off** and the provider record's check
bypassed. That test does not relax when a real provider exists. Having a
provider is not a reason to stop checking that the last component before the
byte leaves refuses on its own evidence.

Nor do these:

- the transport holds no retry; the router decides fallback once
- a response is bounded advisory text or flat fields, and nothing else
- no prompt, evidence, credential, key, token or raw response reaches the
  journal, the audit chain, a status output or a command line
- `TransportOutcome` has no `ANSWERED` and no `COMPLETED`
- Edge authority, the action lease, activation and enforcement are unchanged
  in every transport state

---

## 7. `HG-05` is a separate gate, and it does not move

A commissioned Provider Registry makes the *transport* operable. It says
nothing about whether a **local** provider may be admitted or activated,
which the unmeasured Core reserve refuses (`docs/hardware-gates.md` HG-05,
`docs/mio-local-runtime.md` §6, `docs/runtime-lifecycle.md` §7).

The M.I.O. status expression does not move for either:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration
