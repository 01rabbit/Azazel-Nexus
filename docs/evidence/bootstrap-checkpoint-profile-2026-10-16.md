# Evidence: per-primitive profile of the bootstrap `_check` checkpoint (build 58dfde1)

Date: 2026-10-16. Companion to `docs/evidence/bootstrap-design-ready-budget-2026-10-16.md` (design) and `docs/evidence/bootstrap-qualification-q4r2-2026-10-16.md` (real checkpoint times).
Raw outputs (`raw_out.txt`, `raw_err.txt`, `before.txt`, `after.txt`, `check_prof.py`) are retained in the operator's scratch area, not in the repo.

## Setup

- Debian 13 ARM64 test VM, build 58dfde1, read-only profiling; root via temporary sudo (since removed).
- Interpreter flags `python -I -B`; `raw_err.txt` is empty (0 bytes).
- Before/after filesystem snapshots (47 lines each over `/etc/azazel`, `/run/azazel-nexus-bootstrap`, `/var/lib/azazel`, ...): diff empty (byte-identical). 0 `.pyc` files written.
- Method: each primitive called by `_check` timed in isolation, 1 warm-up + mean of 3 runs (`REPS = 3`), plus cProfile accumulated over the same 3 runs. No product state written.

## Why there is no end-to-end `_check` profile

- `measure_bootstrap_installed_files` binds to the pinned wrapper process state: `sys.path`, `-IS`, `__main__ == az-activated`, loaded modules, import routing.
- Profiling from any other process makes these observations refuse. Running the real entrypoint was out of scope.
- An attempt to disguise `__main__` to satisfy the check was not pursued: it would weaken a check, so it was blocked.
- Consequence: `observe_import_routing` and `observe_loaded_modules` could not be measured in their real context. The standalone numbers below (0.0000 s and 0.0034 s) are from a process where they bind to the wrong state and "may refuse"/"refuses here"; they are not representative.

## Per-primitive wall time (unprofiled, mean of 3, seconds; from raw_out.txt)

| Primitive | mean | min-max |
|---|---|---|
| `measure_installed_files` (hash all selected + dir membership) | 0.0917 | 0.0914-0.0921 |
| `read_pinned_installed_files` (3 wrappers) | 0.0203 | 0.0202-0.0204 |
| `decode_installed_manifest` | 0.0104 | 0.0103-0.0105 |
| `observe_installed_packages` (dpkg snapshot) | 0.0089 | 0.0088-0.0089 |
| `observe_running_python` (standalone) | 0.0043 | 0.0043 |
| `load_bootstrap_approval` (1x, incl. `trust.verify`) | 0.0034 | 0.0034-0.0035 |
| `observe_loaded_modules` (standalone, refuses here) | 0.0034 | 0.0033-0.0035 |
| systemd profile (D-Bus Get x2) | 0.0014 | 0.0013-0.0015 |
| `load_declared_bootstrap_context` | 0.0005 | 0.0005-0.0006 |
| `load_administrator_time_window` | 0.0005 | 0.0005 |
| `check_bootstrap_capacity` | 0.0001 | 0.0001-0.0002 |
| `read_bootstrap_installed_manifest` | 0.0001 | 0.0001 |
| `load_bootstrap_generation` | 0.0001 | 0.0001 |
| `observe_python_startup_absence` (standalone) | 0.0001 | 0.0001 |
| `observe_import_routing` (standalone) | 0.0000 | 0.0000 |
| `load_bootstrap_deployment`, `load_bootstrap_prestart_policy`, `revalidate_deadline` | 0.0000 | 0.0000 |

cProfile detail (3 runs accumulated): `measure_installed_files` 0.484 s total (0.161 s/run, inflated by profiler overhead vs 0.0917 s unprofiled); `_snapshot_at` 2 per call, `decode_installed_manifest` 2 per call (0.170 s of 0.484 s), `_validate_manifest` 4 per call. The approval path is dominated by file reads and context, not crypto: `verify_detached` 0.00277 s/run, `load_bootstrap_approval` 0.00365 s/run (cProfile).

## Call counts per `_check` (from the design doc, not re-measured here)

10 installed-files measurements, 10 dpkg snapshots, 10 systemd profile reads, 4 approval loads (each with one `trust.verify`).

## Model vs real checkpoint time

Real: 2.311-2.342 s x12 in `open_pair` (Q4-R2).

Model = sum(count x measured mean):
- Installed-files: 10 x 0.0917 = 0.917 s; dpkg: 10 x 0.0089 = 0.089 s; profile reads: 10 x 0.0014 = 0.014 s; approvals: 4 x 0.0034 = 0.014 s. Total about 1.03 s unprofiled (about 1.73 s if the cProfile-inflated 0.161 s/run is used for installed-files).
- An earlier per-measure estimate (about 150 ms per installed-files measurement) gave about 1.65 s modelled and 0.65 s residual. From the raw means: unprofiled model gives about 1.03 s (residual about 1.29 s of 2.32 s), the profiler-inflated one about 1.73 s (residual about 0.6 s). Treat the model total as 1.0-1.7 s depending on profiler overhead; this is model/inference, not a measurement. Pin down with an in-process timer.
- Residual: attributed by inference to import-routing and loaded-modules observations (and any other wrapper-bound work), which were not measurable here. Unmeasured.
- Signature verification: 4 x 0.00277 s (cProfile) = about 0.011 s, about 0.5% of a 2.32 s checkpoint (model/inference from per-call timing).

## Conclusion for the design

- Option B (memoize the pure signature step) is not worthwhile: it addresses about 0.5% of a checkpoint.
- The measurable cost is repeated installed-file measurement (about 0.92 s of about 1.03 s modelled; roughly 23% of each measurement is manifest decode+validate, repeated) and repeated manifest decode/validation.
- Next steps: (1) within-call decode dedupe (in progress); (2) Option C adjacency analysis (fewer redundant checkpoints); (3) an in-process timer inside the real wrapper to measure the unexplained residual (needs a VM run).

## Limits

- VM only, not hardware.
- Per-primitive timing, not the composite `_check`; model totals are inference.
- Three repetitions per primitive; wrapper-bound observations not measured in context.
- No product state touched.
