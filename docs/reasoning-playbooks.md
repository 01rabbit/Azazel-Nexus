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
Production `main()` currently leaves this unset; the integration boundary below
must be commissioned before references can be delivered on a node.

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

The question selects Japanese when it contains kana or kanji, otherwise English.
The matcher examines the question and all context texts, case-insensitively:

- 3 points per distinct configured ATT&CK technique token present.
- 1 point per configured keyword present from the question-language list.
- 1 point if any configured context kind is present.

Only scores at least `min_score` survive. Sort by descending score then ascending
ID; the default limit is two. Technique tokens have identifier boundaries, so a
parent technique does not accidentally match a subtechnique. Keyword matching
uses literal substrings. Scores describe lexical evidence, not confidence or
incident verification; context remains untrusted.

`build_prompt(frame, playbooks=(), knowledge=())` adds one `system` message
labelled `reference`, containing titles, interpretation, checks, first response,
missing information and Knowledge technique/name/claim IDs. The entire extra
message is deterministically cut at 1200 characters. Later material can be
omitted by this cap. Benign explanations remain available in match data but are
not added to this short message. With no references the prompt is unchanged.
The situation frame stays in the separate untrusted user message.

Only after the existing advisory reader accepts model output does locald attach
trusted metadata: `playbook` contains ordered `ids`, parallel `status`, flattened
`references`, and flattened question-language `first_response`. Without matches
it is null. When Knowledge was used, `knowledge.claim_ids` contains its IDs.
The model's JSON schema is unchanged, so it cannot supply or override metadata.
Gated replies keep their existing shape. Audits carry IDs, counts and fixed
availability state, never reference prose or frame text.

The optional lookup callable receives up to eight sorted distinct technique IDs
from the frame. It must implement a runtime deadline. Exceptions, including
socket deadlines, proceed without Knowledge and audit `knowledge: unavailable`;
audit failures remain fatal. At most sixteen refs are used. There is no network
operation in the library.

## Production integration boundary

`LocalRuntimeService(playbooks=..., knowledge_lookup=...)` supports injection.
`main()` has neither a commissioned `PackContext` nor an installed-inventory
resolver; it leaves both dependencies unset. Integration must obtain the active
Mission Pack through its existing trust/admission path, recheck current trust,
revocation, expiry and installed-asset pins, resolve selected `reasoning_playbook`
components through `PackContext.assets[(kind, id, digest)].path`, and call
`load_library` with each **selected component digest**. Establish baseline then
site order from the commissioned selection, compose, and inject the result.
Wire Lane K's deadline-bound runtime client as the lookup callable. Reconcile
its frozen `KnowledgeRef` with locald's structural protocol (technique_id, name,
summary, claim_id, bundle_digest, freshness). Selection changes and trust loss
must refresh or remove the injected references through the same lifecycle.
The existing `LocalSocketClient` and `mio_entryd` currently reconstruct only
advice/fields. Integration must also validate and forward the trusted metadata
through those callers if it is needed in the operator-facing entry reply;
those files are outside Lane P's scope. The direct locald reply includes it.
No new path, command-line option or environment bypass exists in locald.

## Offline quality evaluation

The quality runner accepts `--playbooks PATH[,PATH...]`, baseline first and then
sites in explicit order. It computes digests locally only for this benchmark.
`--knowledge-fixture PATH` accepts an offline JSON list (at most sixteen refs)
with the six KnowledgeRef fields above. No network is used. Rows record
`playbook_ids`; the Japanese summary reports matching rows over all frames,
including gates. The container launcher forwards these runner options after
its optional model filename. Use container paths under the existing read-only
`/src` or `/models` mounts. No new mounts are created.

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
