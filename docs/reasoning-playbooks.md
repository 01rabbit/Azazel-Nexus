# Reasoning playbooks

## 日本語の概要

プレイブックは担当者向けの汎用的な模範解答です。ベースラインの
`template` は現場で承認された手順ではありません。各サイトは内容を確認し、
自組織の手順に合わせたサイト層を署名済み Mission Pack で選択してください。
照合結果は助言の参考情報であり、自動実行や Edge の判断権限を追加しません。

## Purpose and delivery

Small local models receive short, deterministically selected reference material.
The baseline contains generic bilingual templates. Sites **must review and adapt**
the templates to their own procedures. A site layer can replace an entry by ID,
disable an entry, or add entries. `reviewed` means site-approved content;
`template` remains unreviewed by a site. Neither status authorizes action.

Layers are already installed assets selected by a signed [Mission Pack](mission-pack.md).
`load_library(path, expected_digest)` requires the pack component's exact
`sha256:` pin. It opens only bounded regular files, refuses symlinks and hash
mismatches, and never installs or modifies anything. Computing a fresh digest
of arbitrary data is supported only for the offline benchmark, not production.

The [local runtime](mio-local-runtime.md) accepts an injected composed library.
Production `main()` refreshes verified signed-pack selection through the existing
selection holder; unreadable or uncommissioned state supplies no references.

## Layer format

Schema: `azazel-nexus/reasoning-playbook/1`. A layer is UTF-8 JSON, at most
2 MiB, with exactly these fields:

| Field | Constraint |
| --- | --- |
| `schema` | Exact schema above |
| `library_id` | Mission Pack NAME grammar: ASCII alphanumeric first, then alphanumeric, underscore, dot or hyphen; 1–128 characters |
| `layer` | `baseline` or `site` |
| `version` | Numeric `major.minor.patch`, no leading zeroes |
| `disable` | Unique entry IDs, at most 512; baseline must be empty |
| `entries` | At most 512 complete entries with unique IDs |

All entry fields are required: `id`, `status`, `category`, `title`, `references`,
`match`, `guidance`. Entry IDs match `[a-z0-9][a-z0-9-]{2,63}`. Baseline entries
must have `status: "template"`; site entries may be `template` or `reviewed`.
Titles have `ja` and `en` strings, each at most 160 characters.

Categories are `authentication`, `network`, `endpoint`, `web_application`,
`email`, `cloud`, `vulnerability`, `data_exfiltration`, `insider`, `availability`,
`deception`, `supply_chain`, and `edge_network`.

Each entry has 1–8 references, each with exactly `source` and `id`:

| Source | ID grammar |
| --- | --- |
| `mitre-attack` | `T` plus four digits, optional dot plus three digits; or `TA` plus four digits |
| `mitre-d3fend` | `D3-` plus 2–12 uppercase letters or digits |
| `owasp-top10-2021` | `A01`–`A10` |
| `owasp-asvs` | `V` plus 1–2 digits, followed by zero to two dot-separated 1–2 digit parts |
| `owasp-cheatsheet` | 3–64 lowercase letters, digits or hyphens |
| `nist-sp800-61r3` | `govern`, `identify`, `protect`, `detect`, `respond`, `recover` |
| `cisa-kev` | `CVE-` plus four digits, hyphen, then 4–7 digits |

`match` has exactly `keywords`, `attack_techniques`, `context_kinds`, `min_score`.
Keywords contain `ja` and `en`, each with 1–24 nonempty strings of at most 48
characters. Case-folded duplicates are refused. Technique IDs use the `T` grammar
above. Context kinds follow the situation-frame grammar, lowercase letters,
digits or underscores, 1–64 characters. Technique and context lists are unique,
with at most 512 members each. `min_score` is an integer at least 1, not a boolean.

`guidance` has exactly `interpretation`, `checks`, `first_response`, `benign`,
and `missing`. Each contains `ja` and `en` lists of 1–5 nonempty strings,
at most 160 characters per string. Checks should name ordered facts that
separate hypotheses; missing information should be specific to the scenario.
First response describes a human operator's containment/evidence decision.

Unknown or duplicate keys are refused at every object level. URL markers,
backticks, shell command markers and command-like sequences, control characters,
and authority markers are refused. Refusals use fixed reasons and never echo
input text. The format accepts plain prose, never operational instructions.
A complete bilingual example is the [test fixture](../tests/fixtures/reasoning-playbook.json).

## Writing and composing a site layer

To disable a baseline entry, this complete site layer is sufficient:

```json
{
  "schema": "azazel-nexus/reasoning-playbook/1",
  "library_id": "example-site",
  "layer": "site",
  "version": "1.0.0",
  "disable": ["auth-password-spraying"],
  "entries": []
}
```

To adapt an entry, copy the complete entry into the site's `entries`, retain its
ID, rewrite both languages for local procedures and mark `reviewed` after site
approval. Partial field overrides are refused. Use a new ID to add a scenario.
Do not put customer secrets, commands or external links in reference prose.
Deliver the site file through the installed inventory and signed Mission Pack.

`compose(baseline, *site_layers)` applies site layers in supplied order: remove
that layer's disabled IDs, then replace or add its entries. Thus an entry present
in both a layer's disable list and entries is reintroduced by that same layer.
Disabling an absent ID is harmless. The composed library is sorted by entry ID,
limited to 512 entries, and retains ordered library IDs, versions and exact raw
layer digests. A composed library is a result, not another baseline input.

## Matching, prompt and replies

Matching is deterministic and language-specific, with score 3 per technique-ID
hit, 1 per keyword and 1 for any context-kind intersection. Short ASCII terms
(up to five characters) and numeric terms require ASCII token boundaries; longer
terms use substring matching. Stable order is descending score, technique hits,
keyword hits, then entry ID. Default limit is three. Every `Match.evidence` exposes
exact `keywords`, `technique_ids`, and sorted `context_kinds` that contributed.
`benign` and `undetermined` are reserved entry IDs to avoid machine-option collisions.

The [closed-choice local pipeline](mio-local-runtime.md) gives each candidate its
own title/one-line interpretation budget, then adds suspicious-outside-classes and
benign hypotheses. Two reversed-order letter selections yield a system candidate;
only a definite candidate receives a conditioned explanation. Guidance remains
trusted labeled text, separate from all model prose. An unreviewed-template banner
appears if any used match has template status. Matching and model candidates are
operator aids, not conclusions or calibrated confidence.

## Production integration boundary

`LocalRuntimeService(playbooks=..., knowledge_lookup=...)` supports injection.
`main()` wires the runtime `knowledge_client.lookup_context`, using
`KnowledgeRef` from the library's `lite_import`; locald has no structural duplicate.

The closed-choice path skips this optional synchronous lookup until its callable
accepts a remaining deadline; benchmark fixtures can still supply references.

`main()` now resolves the ACTIVE Mission Pack's `reasoning_playbook` components
through the commissioned installed inventory. The read-only resolver reuses
Mission Pack status and retained generation/admission integrity checks, then
checks the retained signature, current signer trust and signing epoch, validity
interval, and selected asset version/size/digest pins. It loads each library with
the selected component digest. Exactly one baseline is required; baseline comes
first, followed by site layers in manifest component order. Site-only selections
are refused as `invalid_library`; two baselines produce `multiple_baselines`.
A pack with no playbook components produces `none_selected`. Permission failures
reading commissioned state produce `store_unreadable`. The shipped baseline is
not automatically loaded.

A small locald holder resolves at startup and checks metadata for the `current`
pointer, commissioned configuration, retained generation files and selected asset
files per request. Changes trigger verification and recomposition; expiry also
invalidates the cache without a file change. Failed resolution immediately drops
the old library. Stable failures are cached until watched metadata changes;
expiry is still checked on every request. The fixed reasons are `no_pack`,
`pack_degraded`, `store_unreadable`, `none_selected`, `asset_missing`,
`digest_mismatch`, `invalid_library` and
`multiple_baselines`; success is `active`. Selection audits contain only the
reason and ordered library IDs, versions and raw digests, never paths or prose.
Advice continues through its existing admission gates without optional references.

The paths are the existing `/etc/azazel/mission-pack.json` and encrypted
`/data/azazel/mission-packs` store, rooted through runtime_paths like other runtime
paths. Provisioning must give `azmio` read/traverse access to the commissioned
configuration, active generation and selected assets, while preserving root-only
write authority and encrypted storage. Generation files are currently private to
the pack writer; this integration does not change owners, groups, installation
modes or unit hardening. Until packaging provisions those read permissions, locald
fails to no playbooks with an audited reason, as with unavailable Knowledge socket
access. The consumer reads the existing configuration subset needed for selection;
it does not run CLI LUKS/resource probes or perform admission/activation writes.

`LocalSocketClient` and `mio_entryd` strictly validate the new closed-choice machine
contract (`candidate`, `alternatives`, `match_evidence`, `provenance`,
`explanation_source`). The former `playbook` and `knowledge` reply envelopes are
removed. Missing or malformed machine fields refuse a local advisory; gated replies
retain their existing shape. Maximum delivered UTF-8 document is 48 KiB. No new
path, command-line authority or environment bypass exists in locald.

## Offline quality evaluation

The runner accepts `--eval-set PATH` (any positive number of unique frames),
`--playbooks PATH[,PATH...]` and `--knowledge-fixture PATH`. The existing 14-frame
file is development data only. Runner and runtime use the same two-pass and
conditioned-explanation orchestration. Container scripts forward `--eval-set`;
use an existing read-only `/src` or `/models` path. Outputs remain `quality.json`
and Japanese `summary.md`, with hashes and fixed deployment temperature zero.

For candidate scoring, each case optionally adds this top-level truth annotation,
authored independently for held-out evaluation (the existing `labels` remain):

```json
{
  "closed_choice": {
    "acceptable_options": ["auth-password-spraying"],
    "attack": true,
    "benign": false,
    "adversarial": false,
    "missing_or_wrong_top": false
  }
}
```

Unannotated data has zero truth denominators and cannot pass candidate evaluation.
The evaluator never invents truth from model prose. Supply about 30 independently
authored held-out frames: about 10 attacks with the right playbook, 6 benign hard
negatives (including no lexicon cue), 4 missing/right-class-or-wrong-top cases,
4 ambiguous and 6 adversarial cases (planted benign log text and injection).
Do not tune `MARGIN_MIN=0.10` on held-out data. External held-out authorship cannot
be established by the runner; campaign owners must document it separately.

Metrics include attack delivered as benign (target zero, including adversarial),
wrong definite (at most one), definite coverage (at least 60%), definite accuracy
(at least 90%), missing/wrong-top correct-or-undetermined (at least 3/4), benign
benign-or-undetermined (at least 4/6), and total pipeline latency p50/p95 (p95 at
most 12 seconds on aarch64 4 CPU / 8 GiB). Failures stay in denominators. Deterministic
baseline is top match, never benign, or `other_suspicious` without a match; both
baseline accuracy and special-row correctness are recorded. Guard counts,
explanation-drop counts, probability modes and order-swap disagreement are explicit.
At temperature zero run-to-run flip rate is trivially zero. Converged-minus-split
accuracy uses the pre-abstention suggested candidate and must reach 30 percentage
points before that signal can be retained; otherwise drop the signal.

With about 20 attacks, zero errors still gives only about a 14% one-sided 95%
upper error bound. The Japanese summary records this limitation. If the model
fails zero-attack-as-benign or does not beat baseline on benign and missing/wrong-top
rows, the campaign recommendation remains `deterministic_baseline`. No deployment
or admission changes occur automatically. Independent evaluation and a real image
run remain necessary; these tests do not claim measured improvement or HG-05.

## Attribution and limits

MITRE ATT&CK and MITRE D3FEND supply reference identifiers and technique names.
OWASP Top 10 2021, ASVS and Cheat Sheet topics supply reference identifiers;
NIST SP 800-61 Rev.3 supplies incident-response phase references; CISA KEV
references identify vulnerabilities. Guidance must be original wording.
Do not copy framework descriptions, particularly OWASP text licensed under
CC BY-SA 4.0. Identifier validation does not establish that a technique or
countermeasure exists or that the cited reference supports the guidance.

These are generic baselines and human advice. They grant no enforcement,
commands, automatic containment, model admission or Edge policy authority.
Production RUNTIMES remains empty and HG-05 remains unmeasured.
