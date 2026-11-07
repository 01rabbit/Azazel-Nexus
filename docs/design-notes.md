# D-PUBLIC: typed content digest IDs (2026-11-08)

MIO's evidence contract and Nexus frame producers use `sha256:` plus a lowercase
64-digit hexdigest. Nexus's public binding rejected these IDs as long tokens even
after the controlled receipt and its source manifest had validated successfully.
The D-PUBLIC adjudication aligns the public ID type with that existing producer
contract; it does not make a digest proof of content, trust or model correctness.

`model_text.is_typed_content_digest` is the shared exact, pre-normalization type
check. Binding validation and projection apply it only to evidence reference IDs.
The handoff JSON scan tracks field paths so its allowance covers only binding
evidence IDs and advisory reference IDs; arbitrary `id`, `source` and prose fields
retain their checks. Markdown already handles typed digests and is unchanged.

The advisory scanner records exact raw digest occurrences before NFKC and checks
membership through the existing manifest. Occurrence counting prevents a valid
ASCII copy from masking an additional fullwidth copy of the same digest. Existing
compatibility handling for short IDs is preserved. Malformed or other long tokens
make extraction partial, and unlisted valid digests remain partial. Public prose
still passes the unchanged secret, repertoire, address, path and 32+ token guards;
the digest type is not a general free-text exemption.

Tests cover fixed NOC1/SOC1 controlled receipts, the full recent/status/handoff
JSON/Markdown route, exact and malformed IDs, scope/source restrictions, unlisted
membership, and R10-M1/R12/R13/R14 secret regressions with a digest-backed complete
binding. Controlled providers establish contract behavior, not model quality.
Budgets, deadlines, caps, templates, expectation tables, MIO sources and the
general secret/allowlist policies remain unchanged. Run artifacts and exact
pytest summary lines are recorded separately in B's `report-2.md`.

R1 (Medium, 2026-11-08) is resolved by the coordinator's W7 boundary ruling:
`+` and `/` are allowlisted punctuation, so `digest+Abc` and `digest/Abc`
contain a digest ID followed by a separate token. With listed evidence the
manifest remains complete, while the unchanged prose guard withholds the body.
ID-character suffixes (`Abc`, `_x`, `-1`, `.x`, `:1`) extend the token, fail the
digest type and make extraction ambiguous/partial under the existing 32+ rule
(existing trailing-period stripping is unchanged). `token=digest` still
withholds the entire body. R1 adds only contract text and extraction/recent/
JSON/Markdown counterexamples; no general guard or source behavior changes.
The rerun evidence is recorded in B's `report-3.md` and `tests-focused-3.log`.
