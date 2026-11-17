# ADR-0010 — Observation-origin Knowledge Context leaves the model host: a model-free unit is the broker's one caller

Status: **proposed (2026-11-17), a technical decision delegated by the owner**
(the owner's direction to convene AI specialists, review their result and
decide where the owner's judgement would otherwise be needed). It changes
decision 2 of
[activation-observe-baseline §6](../activation-observe-baseline.md#6-owner-decisions)
in the same way ADR-0008 did on 2026-10-30, and records why. Issue #439 (B5).

## Context

The 2026-11-12 change to decision 2 made `azazel-knowledge-contextd.service`
grantable. The broker's one SERVICE principal was still `azmio`, the account
of `azazel-mio-locald.service`: the observation-origin request
(`mio.context.observe`, explainer → entryd → locald → contextd) was built in
locald, and locald also forwarded a caller-classified free-form P0 `question`
from `mio.local.assess`. Locald is the only unit that could ever start a model
process, decision 2 keeps it out of the grantable set, and on a node with no
admitted model it is withheld anyway. So a policy could grant the broker, and
nothing granted could ask it anything. Granting locald would make "the unit
that may run a program" and "the account that may ask the one unit that may
reach the network" the same uid again, the separation the unit split exists
to keep.

## Options

* **A. Grant locald.** Rejected: the model process and the path to the network
  share a uid; the control would only make an attack harder, not impossible,
  and it reverses decision 2. A grant would also run locald's root
  `ExecStartPre`, and a lease ending would not stop it.
* **B. Move the query into `azazel-mio-referenced.service`.** Rejected: that
  unit's invariant is that it loads no Knowledge code
  (`tests/unit/test_mio_reference.py`), and its serial loop would make playbook
  references wait on the broker.
* **C. entryd asks the broker itself.** Rejected: the operator's trust and the
  hub that reaches remoted would hold the network path too.
* **B'. Chosen: a new model-free unit whose account is the broker's only
  SERVICE principal.**

## Decision

**D1. `azazel-mio-contextobsd.service`** (`az-mio-contextobsd`,
`azazel_nexus_runtime.mio_contextobsd`, account `azmioctx`) answers one verb,
`mio.contextobs.observe`, with the body that was locald's
`mio.local.observe`: the same frame checks, the same `{privacy_class,
techniques}` P0 query of 1 to 8 technique ids, the same projection into
`technique_knowledge`, the same re-run of the fast core as for an unavailable
Full lookup and the same fixed-key `timing`. Its handler writes nothing to its
ledger; the ledger (`/var/lib/azazel/state/mio-contextobs`) holds only the
socket layer's refusals, as locald's did for that verb.

* *Who may ask it.* Its socket `/var/lib/azazel/run/mio-contextobs/` is
  `azmioctx:azmio-contextobs 2710`; only entryd carries the new
  `azmio-contextobs` group, and the daemon's policy admits `azmioentry` alone
  as SERVICE. entryd checks the socket's owner and group before connecting and
  the kernel peer uid (`azmioctx`) after.
* *What it holds.* AF_UNIX only, `PrivateNetwork=yes`, `IPAddressDeny=any`,
  the one supplementary group `azknowledge-context-client`, no model, model
  admission, operator trust or Mission Pack path. It imports none of that code
  (`tests/unit/test_mio_contextobsd.py`).
* *Lifetime.* Like every governed unit: `Requires=`/`After=` the controller,
  `ConditionPathExists=` on its grant marker, masked by the installer, preset
  `disable`.

**D2. The broker admits `azmioctx` alone.** `knowledge_contextd` resolves its
SERVICE principal set to `("azmioctx",)`; `azmio`, `azmioentry` and root are
refused (`principal_denied`). Locald loses `azknowledge-context-client`.

**D3. Free-form questions are refused before sending.** With one caller, which
only ever sends the technique form, the broker accepts only `{privacy_class:
"P0-public", techniques: [...]}`. A `question` frame, including one that
matches the old observation sentence, is refused with `refused_before_send`
(in the ledger and, since 2026-11-17, also to the caller) and never reaches the gate, the slot, the audit `requested` event or the
client. Locald's `mio.local.assess` no longer queries the broker: it reports
`full_node_context_status: not_queried` and its `mio.local.observe` verb is
removed.

**D4. Scope.** The new unit is added to `ACTIVATION_UNIT_ALLOWLIST`,
`activation_markers.GRANTABLE_UNITS`, `GRANT_MARKER_UNITS` and the installer's
mask list. Locald stays excluded.

## Consequences

* A policy that grants contextd and wants the observation-origin path names
  `azazel-mio-contextobsd.service` and `azazel-mio-entryd.service` too. A
  policy that does not name the new unit keeps working; entryd then answers
  `mio.context.observe` with the fixed degraded payload (`unavailable`).
* entryd's reply keeps its shape: the hop's timing is still carried under the
  `timing.locald` key, so the explainer and the measurement tools read it
  unchanged. The key name is now historical.
* A test client running as `azmio` is refused by the broker. Do not mix this
  change into an acceptance run that uses one.
* The controller may mask the unit: it is in `units.UNIT_NAMES`, which the
  narrowing and withdrawal use, so a bootstrap narrowing masks it with the
  other governed units.
* What the process loads: the module imports no model runtime, model host,
  admission, embedding, Mission Pack or Knowledge Lite client code. Its
  broker client no longer reaches the audit daemon's import graph (the
  framing helpers moved to `socket_frames`). The request path imports
  `azazel_nexus.incident_explain` for the frame reader, as entryd does, and
  that reaches the `model_admission` *library* (the closed admission constant
  and document verifier) through `activation`; it holds no admission and
  starts nothing. Cutting that edge is left for later.
* Not done here (second stage): entryd running the core itself and handing the
  new unit only the P0 technique ids. Whether the core's output is the same
  that way is not checked.
* The real-process suite (`tests/real_process/`) runs the new path under real
  uids on real sockets: Knowledge producer ← contextd (`azknowledgeegress`) ←
  contextobsd (`azmioctx`) ← entryd (`azmioentry`) ← explainer (`azexplain`),
  with `azmio`, `azmioentry`, operators and root refused by the broker and
  free-form questions refused before sending (reworked 2026-11-17 after
  review).
* `timing.core` (`ran` / `failed`) tells a core failure from the broker's
  outcome; the technique record is kept on the degraded payload too.

**D5 (2026-11-17). Every broker refusal carries a stage.** With one request
form, the broker returns `{refusal, stage}` for every refusal, including the
unknown-verb and already-expired early returns, so the caller never sees a
response-shape error for a refusal. The words: `refused_before_send` (nothing
was sent: no grant marker at admission, frame or question refused, gate,
busy, audit failure, early returns), `transport` (the client was called and
failed, including a failure that names no stage), `verification` and
`technique_verification` (the answer failed checks), and `withdrawn` (the
answer arrived and was verified, then was not adopted because the grant
marker changed before adoption). The admission check and the adoption recheck
are separate phases (`admit`, `grant`); before this change both mapped to
`refused_before_send`, which misreported an answer that had been received.
contextobsd projects `withdrawn` as transport `received`, verification
`failed` (the stored record has no "received, not adopted" pair); the broker
ledger keeps `reason_code: withdrawn`.
