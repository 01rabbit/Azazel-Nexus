# Reasoning playbook baseline

このベースラインは汎用の模範解答案です。全75件は `template` であり、各サイトが実際の資産、
承認経路、連絡体制に合わせて必ずレビューし、署名済みMission Packのsiteレイヤーで調整してください。
人間への助言のみで、自動対処や権限の追加は行いません。

[azazel-baseline.json](baseline/azazel-baseline.json) contains 75 bilingual draft
entries across all 13 categories in `azazel-nexus/reasoning-playbook/1`. These are
generic model answers, not an approved procedure for any site. Every baseline
entry has `status: "template"`. Each site **must review and adapt** the content,
including containment tradeoffs, before treating it as its operating guidance.

Adapt through a `layer: "site"` library delivered in the signed Mission Pack:
replace an entry using the same ID, remove an unsuitable entry using `disable`,
or add a new ID. Supply complete replacement entries, retain both languages,
and mark entries `reviewed` only after site approval. Keep the schema unchanged.
Composition applies site layers in order. Do not embed customer procedures in
this baseline. This directory does not create an installation or admission path.

Each entry separates interpretation, ordered checks, advisory first response,
realistic benign explanations, and concrete missing facts. Checks first identify
the decisive evidence, then test a scenario-specific benign explanation against
approvals and the responsible owner. First responses describe decisions for a
human operator. They contain no executable instructions, commands, or URLs.
Neither a match nor a framework identifier proves compromise.

Keywords include alert phrases and log terms in both languages. Context kinds
are intentionally empty: a generic log or telemetry item is not extra evidence
for a particular incident. Most entries use `min_score: 1` for explicit scenario
phrases. RDP guessing and encoded PowerShell use `min_score: 2` so a bare `4625`
or `4688` does not select them. Their protocol/tool keywords supply a second
signal. ATT&CK IDs provide the contract's stronger signal. Shared technique IDs
can match several scenarios; site review and the bounded matcher still matter.

The KEV entry cites CVE-2021-44228 as an illustrative known-exploited vulnerability,
not a claim about an installed product. Operators must check the current catalog,
affected versions, exposure, and remediation status for the actual reported CVE.
The baseline is static and is not a vulnerability feed.

Check offline from the repository root:

```sh
python3 tools/check_playbooks.py
```

The stdlib-only checker rejects malformed layers, duplicate or unknown keys,
invalid identifiers and references, oversized content, and forbidden prose.
It is a structural development check, not signature verification or admission.
Integration should switch it to the authoritative library validator. Runtime
loading must separately verify the Mission Pack component digest and trust.

## Attribution and limits

All guidance and keyword wording here is original. No framework descriptions,
procedural text, tables, or diagrams were copied. Identifiers and, where useful,
technique names refer to these public frameworks:

- [MITRE ATT&CK](https://attack.mitre.org/): technique and sub-technique identifiers.
  ATT&CK is a registered trademark of The MITRE Corporation.
- [MITRE D3FEND](https://d3fend.mitre.org/): countermeasure identifiers, including
  authentication-event analysis, network analysis, and decoys. D3FEND is a MITRE trademark.
- [OWASP Top 10 (2021)](https://owasp.org/Top10/2021/): category identifiers A01–A10.
  The schema also permits OWASP ASVS and Cheat Sheet topic references. OWASP text
  is not reproduced or adapted here.
- [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): incident
  response context, represented by the `respond` identifier.
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
  a CVE reference for the KEV example.

These references do not imply endorsement or certification. Advice remains for
a human operator, adds no decision or enforcement authority, and introduces no
Edge policy or automatic action. Production admission stays closed: RUNTIMES is
empty and HG-05 remains unmeasured. No environment-variable bypass is provided.
