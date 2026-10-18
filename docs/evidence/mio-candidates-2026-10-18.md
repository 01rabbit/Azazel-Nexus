# M.I.O. local advice — closed-choice vs similarity-ordered candidates, 2026-10-18

`provenance=bench`. Not HG-05 evidence and not a production admission claim. RUNTIMES pins exactly one runtime;
neither the generative model nor the embedding model is admitted.

## Setup
aarch64 4 CPU / 8 GiB container (`az-llama:b11716`, `--network none`), baseline playbooks (75 template
entries). Generative model Qwen2.5-1.5B-Instruct Q4_K_M; embedding model bge-m3 Q8_0
(MIT, 634,553,760 bytes, sha256 `950f4a8e5e19477a6d3c26d2f162233c20002c601f75e4b002e3239997821167`).
Evaluation sets were authored by independent reviewers who saw neither model outputs nor tuning:
`bench/mio_quality/heldout_set.json` (30 frames; became dev data once used) and
`bench/mio_quality/heldout2_set.json` (34 frames incl. 4 out-of-scope; final, untouched before this run).

## Step 1 — model picks one of the candidate options (design v2), dev set of 30
Pre-registered thresholds failed: attack delivered as benign 1/20 (a negation gap in the guard,
fixed), definite accuracy 3/6, definite coverage 6/30, p95 35 s. Causes: the keyword matcher had the
right playbook in its top 3 for 4/24 frames; the lexical scope gate refused 12/30 real security
questions; the 1.5B model chose "benign" for 11/18 frames and changed its choice when the option
order was reversed on 12/18. The model is not used as a decider.

## Step 2 — similarity-ordered candidates, no model verdict (design v3)

| Metric | dev (30) | final (34) |
|---|---|---|
| Correct playbook ranked 1st (embedding) | 19/24 | 14/20 |
| Correct playbook in top 3 (embedding) | 21/24 | 17/20 |
| Same, keyword matcher | 4/24 | 2/20 |
| Security questions refused as out of scope | 0/30 | 0/30 |
| Out-of-scope questions gated | — | 2/4 (other 2 shown as "no matching type") |
| Attack delivered with benign as top candidate | 0/20 | 0/22 (structurally impossible) |
| Benign frames with system-sourced evidence flagged | 3/6 | 2/6 |
| States clear / split / none | 5 / 24 / 1 | 1 / 22 / 9 |
| Retrieval latency p50 / p95 | 0.40 / 0.50 s | 0.41 / 0.53 s |
| Model explanation latency p50 / p95 | 25.0 / 34.4 s | 15.3 / 32.9 s |

Thresholds (SIM_MIN 0.55, GAP_MIN 0.09, SCOPE_MIN 0.40) were chosen on dev data only.
On the final set "clear" is almost never reached and 9 frames fall under SIM_MIN; the right playbook
is still listed among the alternatives for most of them. Model explanations were dropped by the
validators for about half of the frames where they were attempted (mostly `reason_without_quote`)
and take 15–33 s.

## Conclusion
- Similarity retrieval is the component that makes local advice useful offline: 85% top-3 on unseen
  wording vs 10% for keywords, in ~0.4 s.
- A small generative model should not decide, and its optional explanation does not currently earn
  its latency. Recommended offline configuration: retrieval candidates + trusted playbook text +
  provenance banner, with no generative model.
- With ~20 attack frames, 0 attacks delivered as benign bounds that rate only at ~14% (95%).
