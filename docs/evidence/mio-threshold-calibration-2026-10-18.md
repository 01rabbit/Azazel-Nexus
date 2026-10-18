# M.I.O. retrieval thresholds — calibration, 2026-10-18

`provenance=bench`. Container measurement (aarch64, 4 CPU / 8 GiB, `--network none`), not hardware
evidence. Embedding model bge-m3 Q8_0, baseline library 1.0.0, production text formulas
(`mio_embedding.document_text`, question + context query).

## Data
All frames were written by reviewers who saw no model output and no tuning.

| Set | Frames | Use |
|---|---:|---|
| `heldout_set.json` (30) + `heldout2_set.json` (34) | 64 | calibration |
| `calibration/calib_frames.json` (Japanese SOC perspective) | 60 | calibration |
| `calibration/valid_frames.json` (branch office / factory / clinic perspective) | 60 | validation, opened once after the values were fixed |

Each calibration and validation set has 24 attacks, 12 benign (evidence in system-sourced
context items), 6 missing-type or misleading, 6 ambiguous, 12 out-of-scope (half with IT/OT words).

## Rules for choosing the values
Each value is the boundary the rule allows, floored to 0.01, with a 0.01 safety margin.
- `SCOPE_MIN`: zero security questions refused as out of scope.
- `SIM_MIN`: no frame whose correct playbook ranks first may fall to "no matching class".
- `GAP_MIN`: smallest gap whose "clear" state is right at least 90% of the time (0.04:
  25/27), plus the margin → 0.05.

## Calibration (124 frames)
- Lowest top-1 similarity of a security question without a scope-lexicon hit: 0.468 →
  `SCOPE_MIN = 0.45` (margin 0.018). Out-of-scope frames gated: 10/16.
- Lowest top-1 similarity of a correct first-ranked playbook: 0.5335 → `SIM_MIN = 0.52`
  (the former 0.55 dropped 4 of the 56 correct top-1 frames to "no matching class").
- `GAP_MIN = 0.05`: "clear" right 19/20 (with the system-record rule below).

### Benign evidence finding
The benign lexicon detected support in only 6/25 calibration and 0/12 validation benign frames
(neutral wording such as "signed off" or a ticket number, and conservative negation voiding most
Japanese text). With a lower gap, benign frames were shown as "clear: <attack class>" (12 in
calibration at 0.05). New rule: **any collector-attached system record (change record, schedule,
inventory, approval…) keeps the state from "clear"**, independent of wording; the display asks the
operator to check that record. With the rule, benign frames shown as clear: 0 in both sets.
Caveat: the authors put benign evidence in system-sourced items by instruction, so this measures
the rule, not how often real benign activity carries such a record.

## Validation (60 frames, real pipeline, final values)

| Metric | Old values (0.40 / 0.55 / 0.09) | New values (0.45 / 0.52 / 0.05 + record rule) |
|---|---|---|
| Security questions refused as out of scope | 0/48 | 0/48 |
| Out-of-scope questions gated | 3/12 | 6/12 |
| Correct playbook first / in top 3 | 26/30 / 28/30 | 26/30 / 28/30 |
| Correct top-1 still shown as a candidate | 24/26 | 25/26 |
| "Clear" state: count, right | 7, 7/7 | 14, 14/14 |
| Benign frames shown as clear | 1 | 0 |
| Attack with benign as top candidate | 0 | 0/30 |
| Retrieval latency p50 / p95 | — | 0.30 / 0.41 s |

Half of the out-of-scope questions still reach retrieval and are shown as "no matching class"
(harmless, but not gated). Their similarities overlap the lowest security questions, so a higher
`SCOPE_MIN` would start refusing real security questions.

## Reproduce
`bench/mio_quality/calibration/dump_similarities.py` (run in the bench image with `/src`, `/sets`,
`/models`, `/out` mounted) records the full similarity list per frame;
`bench/mio_quality/calibration/analyze.py <sets>` prints the calibration figures.
