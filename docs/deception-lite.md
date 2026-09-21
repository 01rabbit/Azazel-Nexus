# Embedded Deception Lite: the refusals around a decoy

Status: **lifecycle implemented** (`src/azazel_nexus/decoy.py`), unit tested
and mutation checked. **Nothing starts, binds or changes anything outside this
process**, and the module is scanned for the absence of every verb that could.
This is E3 of [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) /
[#54](https://github.com/01rabbit/Azazel-Nexus/issues/54).

Related: [capability model](capability-model.md) ·
[degradation matrix](degradation-matrix.md) ·
[hardware gates](hardware-gates.md) · [commissioning](commissioning.md)

## 1. What this is, and what it is not

The decoy is **the only internal feature that can be reached from outside**.
Everything below follows from that one fact.

It is also explicitly *not* the external AZ-06 Deception node. That is a peer
and a capability extension; this is the embedded runtime that a Nexus node
carries on its own. The two are separate issues on purpose — mixing them lets
an unimplemented required feature read as "a peer is not connected".

## 2. Initially disabled, and that is a state rather than a setting

A decoy begins `DISABLED`. It reaches `ELIGIBLE` only when **all three** of
these are present:

| Precondition | Refusal if absent |
| --- | --- |
| an operator commissioning record | being in a catalogue is not being approved to listen |
| a verified generation digest | carried on the commissioning record |
| a **passing** isolation check | see §4 |

and `EXPOSED` only when an operator then exposes an eligible decoy.
**Eligibility is not exposure**, and they are separate words because the
operator action between them is a real one.

An operator exposing a decoy whose preconditions are not met does not expose
it. Intent is one input, never the only one.

## 3. Nothing arbitrary

> No API exposes shell command execution, arbitrary policy upload, arbitrary
> container start, packet capture retrieval, or a general network-control
> primitive.
> — `docs/IMPLEMENTATION_SPEC.md` §7

The catalogue is data bound to a verified generation. The runtime accepts what
it names, exactly.

| Rule | Why |
| --- | --- |
| The image is named by **digest**, never a tag | a tag is a pointer somebody else can move |
| `0.0.0.0` and `::` are refused whatever the catalogue says | binding one listens on every interface — a general-network primitive wearing a decoy's clothes |
| Loopback is refused | a decoy reachable only by this host is not a decoy |
| An address outside the **commissioned** bridge prefix is refused | a decoy lives on `az-decoy0` and nowhere else |
| Ports below 1024 are refused | binding one needs a capability this runtime must not hold |
| One to three decoys; a fourth is refused | `IMPLEMENTATION_SPEC.md` §2.1 caps it at three in *every* envelope |
| Two decoys may not share an address and port | one would silently fail to bind and nobody would be told which |
| An empty catalogue is refused | a node with no decoys has **no** catalogue, not an empty one |

There is no default bridge prefix. A default would be a network this product
chose on an operator's behalf.

## 4. The isolation check is three-valued

`IsolationCheck.passed` is `True`, `False`, or `None`, and the third is not a
kind of second.

- `None` — **nobody ran it.** The decoy stays disabled. The remedy is to run
  the probe.
- `False` — **the bridge forwarded something it should not.** The decoy stays
  disabled. The remedy is to fix the bridge.
- `True` with **no denied paths tested** — refused. A check that tested
  nothing did not pass.
- `True` with **no timestamp** — refused. A passing check records when it ran,
  because §9 requires it before *every* exposure and not once at install.

Running the probe for real is [`HG-06`](hardware-gates.md). Nothing in this
repository sends a packet, so nothing here is evidence that a kernel refused
to forward one.

## 5. Redirect is a different question, and the answer here is always no

`IMPLEMENTATION_SPEC.md` §9 lists `redirect_to_lite` among the policy actions
the **arbiter** issues. Nothing in this stage grants it.

`DecoyStatus.redirect_eligible` is a **derived property, not a field**, and it
returns `False` in every state this module can produce. A test asserts it is
not a field: a future change has to be written deliberately rather than set.

**An exposed decoy is an observation surface, not an enforcement one.**

## 6. A failure stops the decoy, not the node

Quarantine stops and isolates one decoy. It wins over every other condition —
a decoy that is not trusted is not trusted whatever else is true — and it
**preserves telemetry**, per the Deception Lite row of
`IMPLEMENTATION_SPEC.md` §7's degradation table. The record of what happened
is the reason the failure is worth anything.

`blocks_deterministic_path()` returns `False` in every state, and the tests
assert it in every state rather than in the convenient one.

## 7. The audit keeps provenance, never secret material

A decoy's whole purpose is to be reached by someone hostile. **What they send
is not this node's to keep.** The audit records that a decoy was reached,
which one, under which generation, and why something was refused. It does not
record credentials, and a static scan refuses a field whose name would hold
one.

The status event carries the decoy name, state, reason, generation digest and
`redirect_eligible`. It does not carry the operator's identity or the image
digest — provenance about the decoy, not about the people or the payload.

## 8. What this does not establish

- **Nothing runs.** No container is started, no socket is bound, no process is
  spawned. `decoy.py` imports none of `subprocess`, `os`, `socket`, `signal`,
  `ctypes` or `multiprocessing`, and the test asserts that.
- **No bridge is created or configured.** `az-decoy0` is named; nothing here
  brings it up.
- **No isolation probe is performed.** [`HG-06`](hardware-gates.md).
- **No redirect, no enforcement, no external device change.**
- **No status or operator wiring.** Nothing in `cli.py` or `status.py` reports
  a decoy yet; that is E4 ([#55](https://github.com/01rabbit/Azazel-Nexus/issues/55)).
