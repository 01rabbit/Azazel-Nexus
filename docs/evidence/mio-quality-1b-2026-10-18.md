# M.I.O. local advice quality — step 1b (reasoning playbooks), 2026-10-18

`provenance=bench`. Not HG-05 evidence and not a production admission claim.
Production stays closed: RUNTIMES empty, HG-05 unmeasured, `playbooks=None` in locald `main()`.

## 条件 / Setup

- Harness: `bench/mio_quality` (14 labelled frames), llama.cpp b11716 CPU build,
  container `az-llama:b11716`, aarch64 4 CPU / 8 GiB, `--network none`.
- Code under test: commit `fb8bb20` (lanes P/D/K merged, before the playbook review fixes in
  `e774b30`). The review fixes changed playbook wording/references, not which entry the 14
  frames select (same top match for all 14).
- Models: Qwen2.5-1.5B-Instruct Q4_K_M; shisa-v2.1 Llama 3.2 3B Q4_K_M.
- `-pb` = baseline playbook library (`playbooks/baseline/azazel-baseline.json`, 75 template
  entries) matched and passed as a reference message. Knowledge lookup not used (no fixture).
- Grading: independent Sonnet reviewer, 1–5 per axis. The operator view is the delivered
  answer plus the trusted playbook `first_response` attached by locald. `not_advice`
  (validator refusal) counted as 1/1/1/5/3.

## 結果 / Results

| 条件 | 正確性 | 文脈 | 実行可能性 | 安全性 | 言語 | 合計平均 |
|---|---|---|---|---|---|---|
| qwen-none (1a) | 2.50 | 2.86 | 2.07 | 4.29 | 4.21 | 3.19 |
| qwen-pb (1b) | 3.00 | 2.93 | 2.93 | 4.43 | 3.86 | 3.43 |
| llama-none | 2.86 | 2.93 | 2.57 | 4.43 | 4.14 | 3.39 |
| llama-pb | 2.86 | 2.79 | 2.79 | 4.36 | 4.00 | 3.36 |

Mechanical proxies (bench `summary.md`): playbook match 11/14 for `-pb` (q09/q14 gated,
q10 none); accepted 9/12 qwen-none, 8/12 qwen-pb, 7/12 llama-none, 7/12 llama-pb;
command output 0/14 in every condition.

## 所見 / Findings

- Playbooks fix the Qwen misreadings (q03 "insufficient information", q06 "misconfiguration",
  vague q01) and raise correctness 2.50→3.00, actionability 2.07→2.93.
- Remaining: the model copies template text into unrelated fields (q07, q13), one
  contradiction with context (q13), and validator refusals of answerable frames (q04, q05, q10,
  q12: `ungrounded_facts`, `not_text` truncation, `language_mismatch`).
- Llama 3B is better on English analysis but loses Japanese frames to language refusals and
  degrades with playbooks on q12/q13; overall it does not justify ~3x latency over Qwen 1.5B
  (p50 21.5 s vs 6.9 s, see `mio-local-bench-2026-10-18.md`). Qwen 1.5B + playbooks remains the
  local default candidate.
