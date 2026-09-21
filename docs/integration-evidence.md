# What the integration run establishes

`tools/e2e.py` runs the sequence Nexus#43 lists, in finite time, against a
throwaway root:

```
install → units masked → inventory → operator-confirmed commissioning
→ verified generation → activation → health/status → daemon failure
→ remask/rollback → audit chain → CORE + Lite configurations
```

The last stage is Nexus#56's and is not part of #43's sequence. It depends on
nothing the others set up — it drives the library rather than the installed
tree — which is why it is last and why it runs on a runner that is not root.

## It establishes that the distribution does not contradict itself

`install.sh` creates the directories `azazel_nexus.layout` declares, at the
modes it declares. The daemons bind the sockets their units name and answer on
them. A commissioning record leads to a generation whose digest re-derives from
its own tree, and an activation pass grants exactly the supporting tier. An
injected daemon failure is detected, fenced, rolled back and recorded.

That is a real and limited claim. Every part of it is about **this
repository's own artifacts agreeing with each other.**

## The nine CORE + Lite configurations

`tests/unit/test_core_lite_integration.py` holds the assertions; the stage
composes all nine and checks the two claims that must hold in every one:
**nothing claims enforcement or baseline readiness, and every configuration
names what continues.**

The nine are the configurations of *what is there*, not of what works:
knowledge alone, M.I.O. alone, deception alone, all three, none, a stale
cache, a quarantined cache, a quarantined decoy, and remote not permitted.
The one most likely to ship is **none of the three holding content**, and the
test that matters most is that it reports no defect: an uncommissioned node is
not a broken one.

Three things it establishes that the per-feature tests cannot:

- **The privilege boundary survives composition.** Each feature is advisory
  alone; the question is whether chaining them produces a path to enforcement
  that none of them has. Six modules are scanned together for a runtime
  import, a socket, a process, and an acting verb — *a boundary that holds in
  each module and not across them is not a boundary* — and the composed output
  is asserted to be JSON, with nothing to invoke.
- **A failure propagates no further than the feature that had it.** A
  quarantined decoy leaves the Knowledge row and the cognition row byte-identical.
- **Degradation only ever narrows**, over all 8 × 3 trigger/route pairings.

## It establishes nothing about hardware, and nothing about systemd

The harness never reports a stage it did not run as one that passed. A stage
it cannot execute here is `not_executed` with the reason, and
`Report.summary()` counts it separately; `Report.ok(require_all=True)` — what
a host with a running systemd would use — refuses such a run outright.

On a machine where systemd is not PID 1, **the service-manager stage does not
run**. Nothing masks a unit, and nothing establishes that a unit is masked.
That is `HG-01`, it stays open, and a green integration job does not touch it.

The phrases that would turn this into a hardware claim — "verified on
hardware", "production", "rugged" — are refused in the stage sources by
`tests/unit/test_e2e_harness.py`.

## Two bugs the first run found

Worth recording, because both were invisible to the unit suite.

**A duplicated module is two modules.** `NotExecuted` lived in the runner,
which the stages imported again under a second module name. The runner's
`except NotExecuted` did not catch the stages', so every skipped stage was
reported as a failure. The shared types now live in `tools/e2e_harness.py`,
which both import.

**`AF_UNIX` addresses hold 107 bytes.** A root long enough to push a declared
socket path over produced `OSError: AF_UNIX path too long` from inside a
subprocess, naming neither the limit nor the length. Both `bind_socket` and
the harness now refuse up front, with the arithmetic in the message.

Neither was reachable from a unit test, because neither is about a function.
They are about two files being one module and a path being a length — which is
what an integration run is for.

## Running it

```sh
python tools/e2e.py --root /tmp/az-e2e
python tools/e2e.py --root /tmp/az-e2e --require-all   # on a host with systemd
```

The root must be short: a unix socket address holds 107 bytes and the longest
declared socket path takes 35 of them.
