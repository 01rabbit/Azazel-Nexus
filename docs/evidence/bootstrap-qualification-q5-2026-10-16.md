# Bootstrap factory qualification: Q5 start/identity code on fixtures (test VM, 2026-10-16)

Scope: Debian 13 test VM, systemd 257.13; not hardware evidence; production factory unchanged.
Method: the real `BootstrapNarrowingManager._run_owned_start` → `_StartCheckpointBridge` → `BootstrapStartJobs` →
`BootstrapStopJobs._job` path and the real audit/commission identity inspectors, run as root against two static
fixture units (`azn-q5-a/b.service`, Type=notify, users `azaudit`/`azcommission`, no dependency on product units).
The pair names and identity constants were substituted in memory in the test process only; no source file changed.
Product-name binding is therefore NOT covered here. An independent `busctl monitor` witnessed JobRemoved.
Cleanup: no fixture units, unit files or runtime files left; the product units' state was identical before and after.

| Scenario | Result |
|---|---|
| bus owner admitted (PID 1, uid 0); systemd profile digest = policy (`sha256:999a0724…`) | PASS |
| S1 inspector refuses an inactive unit (negative control) | PASS |
| S1 `StartUnit(name,"fail")` → JobRemoved `done`, active in 0.54 s; MainPID, ControlGroup, `/proc/<pid>/cgroup`, InvocationID agree with the audit identity inspector | PASS |
| S1 second start of an active unit refused | PASS |
| S1 real stop path: unit inactive, but `_job` reported "stop completion unconfirmed" (fixture is not masked; unit GC). Re-check against masked product units in the supervised run | PASS (noted) |
| S2 `fail` mode refused against a queued conflicting job; other unit untouched ("transaction is destructive") | PASS |
| S3 10 s observer refused at 10.02 s while the unit became active at 14.21 s (TimeoutStartSec=30s): a refusal can coexist with a completed start, so the caller must contain | PASS (design-relevant) |
| S3 commission identity inspector on the live fixture | PASS |
| S4 never-READY: observer refused at 10.02 s, but the native-timeout measurement read the unit already inactive (Result=success) at 0.01 s after the observer. Harness measurement inconclusive | INCONCLUSIVE |
| S5 synchronous checkpoint of 11 s exceeds the 10 s start budget: refused, unit left active | PASS (design-relevant) |

Implications: S3 and S5 confirm, on the real manager, the timing hazard the Q9 trace flagged. A slow checkpoint, or a
helper slower than 10 s to READY, produces a refusal while systemd may still complete the start, so containment must
stop the helper. Peer proofs, real unit files, masks/overlay and the controller context are outside Q5.
