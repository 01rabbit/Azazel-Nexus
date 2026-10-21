# Embedded Deception Lite: the refusals around a decoy

Status: **lifecycle implemented** (`src/azazel_nexus/decoy.py`) and a
**loopback-only functional layer implemented**
(`runtime/src/azazel_nexus_runtime/decoy_loopback.py`), unit tested and
mutation checked. This is E3 of
[#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) /
[#54](https://github.com/01rabbit/Azazel-Nexus/issues/54) /
[#69](https://github.com/01rabbit/Azazel-Nexus/issues/69).

The library half still **starts nothing, binds nothing and changes nothing
outside this process**, and is scanned for the absence of every verb that
could. The runtime half binds — and only ever a private Unix socket. §9 holds
that half.

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

## 9. The loopback-only functional layer

Until [#69](https://github.com/01rabbit/Azazel-Nexus/issues/69), no decoy
process or container was started by anything: the freshness row read
`control-plane-only`, and it was accurate.

Decoys now really start and really listen. Every one of them listens on an
**`AF_UNIX` socket inside a `0700` directory**, and the row reads
`loopback-only`.

### Why that is stronger than `127.0.0.1`

Not because binding loopback is refused — because **nothing in the runtime
distribution that runs can bind an address or a port**.
`tests/unit/test_runtime_boundary.py` scans the whole distribution for
`AF_INET`, `AF_INET6`, `AF_PACKET` and `create_connection` and refuses to find
any outside its named exemptions. External exposure is not a path that is
checked and rejected; it is a path that is absent from the code that runs.

Since #196 P1 ([prerequisites](deception-redirect-prerequisites.md) §10) one
module, `decoy_listener.py`, is exempt by file name for **ingress only**: it may
bind and listen, and the same scan refuses `connect`, `connect_ex`,
`create_connection`, `sendto`, `sendmsg` and `AF_PACKET` in it. Nothing imports
it yet, and the unit it would run in (`azazel-decoyd.service`, tier
`DECEPTION_EXPOSURE`) is never granted in this build;
`tests/unit/test_functional_readiness.py` fails the day something imports it, so
the row cannot stay `loopback-only` by accident.

A Unix socket under a private directory has no IP stack in front of it, no
port to scan, nothing an interface can carry, and needs filesystem permission
on this host to reach. That is what #69 means by "an equivalent local-only
namespace".

**An operator's exposure request does not reach further.** Commissioning, a
verified generation and a passing isolation check are what the control plane
requires before a decoy may be `EXPOSED`; none of them is an input to this
runtime, and all three together still produce a Unix socket.

### A separate type, so one permission is never the other

`DecoyEntry` **refuses** loopback — correctly, because a decoy an attacker
cannot reach is not an externally exposed decoy. That discipline is not
inverted. `LoopbackDecoy` is a different type with two fields, `name` and
`responder`, and **no address, port, image or command at all**. They are not
refused; they are absent, and a field that does not exist cannot be validated
wrongly. The two types share only the name field, and a test asserts it.

### A responder is selected, never supplied

`RESPONDERS` is a table of constant byte strings defined in code. A catalogue
entry names a key. Nothing formats, templates or interpolates — a responder
that took an argument would be a command with extra steps.

### What is observed, and what is never kept

An `Observation` records **that** a decoy was reached, which one, when, under
which generation, how many bytes arrived, and whether the peer sent more than
the decoy was willing to read. It does not record the bytes. The field list is
the whole record and a test asserts it exactly: a field able to hold a payload
is how a decoy's audit becomes a credential store.

### A crash stops one decoy

A responder that fails quarantines that decoy — socket closed and unlinked,
reason recorded, `deterministic_path_affected: false` — and every other decoy
keeps listening. The exception does not leave the module, and a restart does
not revive a quarantined decoy: it was stopped because it is not trusted, and
a restart is not a pardon.

### Why the row does not say `available`

Because nothing outside this host can reach a decoy, so a word that said the
capability was being supplied would describe a deception with nobody on the
other end of it. `loopback-only` is its own word for its own reason, and
`functional_readiness.py` refuses to let a feature be both `functional` and
`loopback_only`.

External exposure is a different stage. It is out of scope here, along with
bridge creation, redirect, enforcement, external device change, AZ-06
integration and `HG-06`.
