# Software lifecycle evidence (#114)

#112 fixed the service **boundary** on a build that starts nothing. Its
`crashed` state was an injected one — a value placed into `readiness`, not a
process that died. This is the **lifecycle**, driven against a real process.

Nothing here is a provider. No real model, no real inference, no provider
admission is claimed, and `HG-05` still refuses everything.

---

## 1. Two kinds of evidence, and they are not interchangeable

| mark | what it means |
| --- | --- |
| `real_process` | an actual process was started and observed |
| `injected` | a state was set and what follows from it was checked |

Registered in `pyproject.toml`, so they can be selected and counted:

```
pytest -m real_process   # 14 — the process evidence, and nothing else
pytest -m injected       # 29 — states, budgets, verdicts, scans
```

`test_the_two_kinds_of_evidence_are_distinguishable` asserts both sets are
non-empty and **disjoint**. Conflating them is what #112 left behind: a suite
of injected states reading as a suite of process evidence.

---

## 2. The stub is a real process, and it stays in `tests/`

`tests/fixtures/runtime_stub/usr/libexec/azazel/az-runtime-stub` starts,
answers, stays silent, hangs, crashes, dies by signal, floods its output, or
forks a child — chosen by **the first element of the fixed argv**, never an
environment variable. The supervisor replaces the environment, so a stub
steered by one would be steered by something the supervisor does not control.

Containment is checked in **both directions**:

- the stub is under `tests/` and nowhere else
- nothing shipped names it: package, runtime package, catalog,
  `model_runtime.RUNTIMES`, `packaging/`, unit files, the preset, the console
  scripts

The second direction is the one that matters after somebody adds a real
runtime. `RUNTIMES` gaining an entry is a reviewed change; `RUNTIMES` gaining
the *stub* is the accident this scan makes loud.

### The shebang is absolute, on purpose

`#!/usr/bin/python3`, not `#!/usr/bin/env python3`. The supervisor replaces
the environment, so there is no `PATH` for `env` to search — correct for a
provider, fatal for a script that needs one. A real runtime binary is an ELF
and has the property for free.

---

## 3. Two modules may execute, and the count is asserted

`edge_probed.py` runs a fixed health contract once and exits.
`mio_supervisor.py` starts a long-lived process and watches it. Until #114
there was one; both are named in `test_runtime_activated.py`, and a third
cannot acquire the ability by accident.

A caller influences a **runtime ID**, and nothing else. There is no
parameter for a command, an argv, an environment, a shell or a working
directory — asserted on the signature, so one appearing is a failure rather
than a capability nobody noticed.

---

## 4. Bounded on every axis a process can be unbounded on

| axis | bound |
| --- | --- |
| time | a deadline, with an injected clock |
| stdout / stderr | `STDIO_BYTE_CEILING`, and **reading stops there** |
| restarts | `RestartBudget`, per generation, fencing when spent |
| children | its own session, killed as a group |

### The output ceiling bounds the reading, not the keeping

Found while building this. The first implementation used
`Popen.communicate`, which reads to EOF — so a two-megabyte flood was read in
full and trimmed afterwards. That is a ceiling on what is kept, not on what
the node spent getting there, and a provider that can make the daemon drain
that much has decided how much memory the daemon uses.

It now reads with `selectors`, stops at the ceiling, and unregisters the
pipe. The test asserts `stdout_bytes <= STDIO_BYTE_CEILING` against a stub
that writes 2 MiB.

### A flood after a `READY` reports both facts

It answered, and then it flooded. A report saying `not-checked` would erase
the first; one saying `failed` would invent a failure nobody observed.

### The process group is captured at spawn

Also found while building this. `os.getpgid(pid)` raises once the parent is
reaped — so a cleanup that derived the group from the process could only run
while the thing it cleans up was alive, and missed exactly the orphans it
exists for. The group is remembered at spawn and killed unconditionally
afterwards.

---

## 5. The restart budget grants exactly its limit

`MAX_RESTARTS = 3` means one start plus three restarts. Found by a
real-process test counting starts: the first implementation fenced when it
*granted* the last restart rather than when the next was *requested*, so a
budget of three delivered two. A limit that means one fewer than it says is a
limit nobody can reason about.

Exhausting it **fences**. A fence is not cleared by supervising again:
returning a provider to service is an operator's decision against a
revalidated generation, exactly as it is for a fenced unit, and a supervisor
that could un-fence itself would grant itself a fresh budget by asking twice.

The budget is per **generation**, not per boot — one a reboot refilled would
be one a crash loop refills by taking the node down with it.

---

## 6. Runtime binary verification: all three, or it does not start

`RuntimeBinary.digest` was declared in #97 and nothing compared anything
against it. A field that reads like a guarantee and is not one is worse than
an absent field, because the absent one is noticed.

| checked | refusing case |
| --- | --- |
| digest | does not hash to what the record declares |
| signature | did not verify, **or nobody checked** |
| provenance | undeclared, or `FIXTURE` rather than `PACKAGED` |

Every reason is reported, not the first: an operator who fixes one and is
then told about the next has been sent round twice. The refusal never prints
the expected digest — a message that named the target would hand an attacker
what to forge.

---

## 7. `HG-05` refuses with the whole lifecycle green

Binary verified, provenance packaged, signature good, the process starts,
answers, is bounded and is supervised — and **still no activation**, because
the Core reserve is unmeasured.

> "Verified" and "may be used" are not the same word, and a lifecycle that
> went green is not a measurement.

The gate is also shown **reachable** with a reserve supplied, because a gate
that refuses only by being unreachable is one that starts passing the day
something upstream stops refusing.

---

## 8. What this does not establish

- No real runtime binary, no real model, no real inference, no provider
  admission.
- `HG-05` is unmeasured and nothing here stands in for it (#115).
- What systemd enforces is `HG-01`/`HG-02`, which no test here runs.
- The stub is a stub. It demonstrates that the **supervisor** behaves; it
  says nothing about how a real runtime behaves.

The M.I.O. status expression is unchanged:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration
