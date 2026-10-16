# Loaded-unit dependency record: finding and design options

Date: 2026-10-16. Status: finding established by measurement; no code changed; owner decision required.
Evidence: Q4-R4 run (`docs/evidence/bootstrap-qualification-q4r4-2026-10-16.md`) and the Q4-M measurement (VM Debian 13, systemd 257.13-1~deb13u1, build c79291b). Raw outputs retained in the operator's scratch area (`systemctl show` of the 27 dependency properties, warm/cold repeats, the GC experiment, decoder runs, candidate records).

## 1. Finding

The first real start refuses at the loaded-unit inspector with "loaded bootstrap dependencies differ". Measurement shows two independent causes; fixing either alone leaves the pair unstartable.

### Cause 1: the pinned record was built from unit text and never measured

`loaded-units.json` is produced by the owner tool `build_loaded_units.py` (scratchpad `owner-bundle/tools`), which parses the fixed payload text and adds in-pair inverse edges. systemd adds implicit edges that are not in the text. Measured on the VM using fixture copies of the exact payloads (names `azn-q4m-*`, only the 3 `azazel-auditd.service` references in commissiond renamed; the product names are masked and were not touched). Observed versus pinned, identical for both units:

| Property | Missing from the pinned record |
|---|---|
| After | `-.mount`, `system.slice`, `systemd-journald.socket`, `systemd-tmpfiles-setup.service`, `tmp.mount` |
| Requires | `-.mount`, `system.slice` |
| Wants | `-.mount`, `tmp.mount` (pinned: empty) |

Everything else matched (BindsTo, Conflicts, Before of commissiond, all empty sets). The source of each implicit edge is inferred from the directives (RuntimeDirectory/RequiresMountsFor=/run/azazel, PrivateTmp, Slice, journal stdout), not isolated by experiment.

### Cause 2: the decoder requires inverse edges that systemd cannot report

`_profile_azazel_edges` (`runtime/src/azazel_nexus_runtime/bootstrap_loaded_policy.py:60-84`, enforced at `:146-147`) requires auditd `Before`/`RequiredBy`/`BoundBy` to equal {azazel-commissiond.service}. The runtime comparison (`bootstrap_loaded.py:138-143`) compares the live property to the pinned one for exact equality. Live auditd never shows those edges: in the GC experiment 0 of 20 runs showed commissiond in auditd's `Before`, in any read order or timing, and after `LoadUnit` plus 1 s idle both `GetUnit` calls return "not loaded". An inactive, never-started unit with no job is garbage-collected, and its reverse edges disappear with it. The product inspects one unit per fresh session, so it only ever sees a unit's own forward edges plus implicit ones. Control: live units show normal inverse edges (e.g. `systemd-journald.socket` RequiredBy `systemd-journald.service`).

Decoder check (offline, nothing written): the pinned record is accepted; the measured candidate (implicit edges added, inverse edges absent) is refused solely by `_profile_azazel_edges`; the same candidate plus the three inverse edges is accepted by the decoder but would still fail the live comparison. So no record can satisfy both the decoder and the live comparison.

### Diagnostic gap

The inner refusal `loaded bootstrap dependencies differ` (`bootstrap_loaded.py:143`) does not name the unit or property, and the wrapper (`:245`) discards the cause. Diagnosis required an independent measurement. Not a security defect (it avoids leaking state), but any redesign should keep a reviewed offline diff tool so owners are not blind.

## 2. Constraints for any fix

- Never weaken to "ignore differences"; no new authority, boolean, or environment bypass.
- Any trust-bearing record stays owner-signed and pinned by digest in the pre-start policy.
- Fail closed: unknown, extra, or missing edges refuse.
- The record is environment-sensitive (tmp.mount, `-.mount`, system.slice, journald, tmpfiles exist on this VM; another host may differ). A pin is valid only for comparable hosts and systemd 257.13.

## 3. Options

### O1: decoder stops requiring unobservable inverse edges; owner re-measures and re-pins (recommended)

Decoder: auditd's in-pair inverse sets (Before/RequiredBy/BoundBy, azazel-* subset) are expected to be empty, i.e. exactly what systemd reports for a freshly loaded single unit. Forward edges and the `_dependency_policy` invariants (BindsTo/Requires/After contain the controller, plus auditd for commissiond; positive dependencies ordered After) stay. Record: owner regenerates `loaded-units.json` from a reviewed measurement, includes the implicit edges, and pins the new digest.
- Pros: runtime comparison stays exact equality over the full 27-property projection (implicit edges included, nothing subtracted); no new authority or code path; smallest change; the record reflects what the manager reports.
- Cons: the pair's mutual lifetime binding is no longer pinned from auditd's side; it rests on commissiond's own verified forward `BindsTo`/`Requires`/`After` auditd (and the start-closure relation checks). Needs review that an unloaded peer cannot influence auditd's lifecycle. The record is host-specific.
- Security reasoning: the removed expectation cannot be observed by any inspector today, so dropping it removes no real check; replacing "required non-empty" with "required empty" retains strictness, and any appearance of the inverse edges (different systemd behaviour) fails closed and signals a changed environment.

### O2: compare only the explicitly declared edge set after subtracting a fixed implicit-edge allowlist

Runtime ignores {`system.slice`, `-.mount`, `systemd-journald.socket`, `tmp.mount`, `systemd-tmpfiles-setup.service`} when comparing.
- Pros: record stays derivable from unit text; tolerant of host variation.
- Cons: it is a partial "ignore differences" in the trust path; the allowlist is environment-specific and would need to be a reviewed, pinned constant; a malicious drop-in adding one of those edges becomes invisible (e.g. an extra `After=tmp.mount` is harmless, but `Requires=-.mount` semantics must be argued per edge). Does not solve Cause 2 by itself. Not recommended.

### O3: load both pair units in one session before inspecting

Make the peer exist so inverse edges are reportable.
- Pros: keeps the decoder as is.
- Cons: GC experiment shows inactive no-job units do not stay loaded (0/20); would require holding a reference (a job or pin), i.e. new manager-side state before start, more complexity and a larger authority surface. Not recommended.

### O4: strict equality, record generated from a live measurement at install time

An installer step measures and writes the record.
- Pros: always matches the host.
- Cons: the measured value becomes the trust root with no owner-reviewed baseline (provenance: the installer vouches for itself); conflicts with the owner-signed, pinned-digest model. Only acceptable if the measurement is reviewed and signed by the owner before the digest is pinned, which collapses into O1 with an automated tool. Not recommended as a standalone.

## 4. Recommendation

O1, with measurement done by a reviewed tool (the fixture-name approach of `q4m-measure.sh` is proven but depends on name substitution; a measurement during the publication phase under the real names would remove that residual, at the cost of new code to review). Rationale: it is the only option that fixes both causes while leaving the live comparison an exact match and the trust model (owner-signed, digest-pinned) intact.

### Owner decisions required

1. Accept dropping the in-pair inverse requirement for auditd (pin "empty"), given the argument above.
2. Choose the measurement method: fixture-name tool versus real-name measurement; approve the tool for review.
3. Accept the host-specific scope of the pin (VM class, systemd 257.13) and the procedure for other hosts.
4. Approve re-signing the pre-start policy (new `loaded_policy_digest`) and the approval payload.

### Code, test, and tool changes (file:line)

- `runtime/src/azazel_nexus_runtime/bootstrap_loaded_policy.py:60-84` (`_profile_azazel_edges`): remove the `reverse` loop (`:67`, `:72-83`) so in-pair inverse sets are expected empty; `:146-147` check unchanged.
- `runtime/src/azazel_nexus_runtime/bootstrap_loaded.py:74-102` (`_dependency_policy`): optionally tighten `allowed` for auditd Before/RequiredBy/BoundBy (`:80-81`) so commissiond is no longer permitted there; keep the invariants at `:94-101`.
- `runtime/src/azazel_nexus_runtime/bootstrap_loaded.py:138-143`: no change (exact equality retained).
- `hardening.py`: no code change expected; the new record digest flows through the existing `loaded_policy_digest` pin (confirm during implementation which constants must be re-pinned).
- Tests: `tests/unit/test_runtime_bootstrap_loaded_policy.py:62-64` and `:224` (fixtures with inverse edges), `tests/unit/test_runtime_bootstrap_loaded.py:42-61`, `:169-171`, `:275-277`, `:388`, `:414-416` (inverse-edge fixtures and the parametrised refusal): update to the empty expectation; add cases that a populated auditd inverse edge now refuses, and that the measured implicit edges accept.
- Owner tool `scratchpad/owner-bundle/tools/build_loaded_units.py:57-70`: drop the inverse step; replace unit-text derivation with (or verify against) the measured edge sets; add an offline diff mode that names unit and property (cf. the Q4-M "observed vs pinned" table).

### VM procedure to re-qualify

`loaded-units.json` and the policy digests change, so the existing records are invalid: revert the snapshot to the pre-install state, reinstall the new build, then repeat the owner procedure (Phase 2g, records, deployment/selection/generation/time, owner-signed approval with >= 600 s margin). Then: smoke (expect `smoke-d6-selftest-ok`), preflight, one Q4-R4 style run in the owner's go window (D6 still declared). Expected: loaded-unit inspector passes for auditd then commissiond; prerequisite and closure second snapshots equal; `retained_check` runs; `stop-before-ready`. Any new refusal is the next finding; no in-VM repair, no retry in the same session.

## 5. Next never-run check

After the dependency comparison, `_SERVICE_EXPECTED` and the service-settings comparison of the loaded unit (`bootstrap_loaded.py:34-57`, `:145-150`, `_service_policy` `:105-120`) are executed for the first time. The measurement did not cover service properties (Exec*, User, KillMode, environment, timers); they may produce the next mismatch and should be measured by the same reviewed tool before the next run.
