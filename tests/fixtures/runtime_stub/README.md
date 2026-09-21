# `runtime_stub` — a real process for lifecycle tests (#114)

`az-runtime-stub` is a **test-only** model runtime. It exists so that the
supervisor's lifecycle can be checked against a process that actually starts,
answers, hangs, crashes, floods its output or forks a child — rather than
against an injected state.

## It stays here

It is not in the production package, not in `model_runtime.RUNTIMES`, not in
the model catalog, not in `packaging/install.sh` and not in the systemd
preset. `tests/unit/test_runtime_stub_containment.py` scans for exactly that,
in both directions: the stub is under `tests/`, and nothing shipped names it.

## The tree shape is deliberate

The stub sits at `usr/libexec/azazel/az-runtime-stub` under this directory,
mirroring where a real runtime would live. `mio_supervisor.run_once` takes a
`root` and resolves the record's executable **relative to it**, so a test can
supply this tree without the supervisor gaining a path parameter a caller
could point anywhere.

## Behaviours

| argv[1] | what it does |
| --- | --- |
| `ready` (default) | writes `READY` and exits 0 |
| `silent` | exits 0 having said nothing |
| `env` | exits 3 if it inherited `AZ_PARENT_MARKER`, else `READY` and 0 |
| `crash` | exits 9 |
| `signal` | kills itself with SIGKILL |
| `hang` | sleeps for ever |
| `flood` | writes 2 MiB to stdout |
| `orphan` | forks a child that sleeps for an hour |

The behaviour is the **first argv element after the executable**, so it is
part of the fixed argv in the `RuntimeBinary` record a test builds — not an
environment variable and not a runtime input. The supervisor replaces the
environment, and a stub steered by one would be a stub steered by something
the supervisor does not control.
