# Contributing to Azazel-Nexus

Azazel-Nexus Gateway (`AZ-07`) is a persistent, self-contained installation on
a generic rugged x86_64 Linux PC. One rule is judged before anything else in a
contribution:

> **Azazel-Edge's deterministic arbiter is the only decision and enforcement
> authority.** Nexus integrates released components. It never arbitrates, never
> overrides, and never becomes a fallback authority when Edge is degraded or
> absent.

A change that moves any decision authority into Nexus is **rejected regardless
of its merits** — regardless of how much it improves latency, availability,
operator experience, or offline behavior. There is no threshold of usefulness
at which this rule bends, and "only while Edge is unavailable" is the case it
most specifically forbids.

Two consequences that are not separately negotiable:

- `FULL`, `LITE`, and `CORE` are **capability states, not authority levels**.
  Degrading removes optional capacity and exactly zero authority. A change that
  makes any state confer additional latitude is a change to the authority
  model.
- Effective capability is an **intersection**, never a sum:
  `resource profile ∩ topology profile ∩ verified asset set ∩ current
  trust/health state`. A dimension can only remove capability. RAM alone never
  enables NIC roles, capture, enforcement, or Deception.

## This is a documentation-stage repository

There is no package, no dependency manifest, no Azazel-Fabric pin, and no
product code. Everything in `docs/` is a **target contract**: a statement of
intended behavior with no release evidence behind it. The outstanding bootstrap
work is listed in [contract ownership](docs/contract-ownership.md) §6 and
sequenced as Phase 0 of the [roadmap](docs/roadmap.md).

That constrains what a pull request may claim.

### Status vocabulary — apply it strictly

Write in the series status vocabulary from the
[third-party development handoff](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
§7 — **target contract**, **implemented**, **verified**, **supported**,
**experimental**, **retired** — and never collapse them into a blanket claim.

**Do not describe unimplemented behavior in the present indicative.** "Nexus
validates the renderer digest on every boot" reads as a statement about a
running system; nothing in this repository runs. Write what the design
requires — "the activation controller MUST validate…" — or what a release will
have to carry. A reviewer will read any present-tense operational sentence as a
claim and ask for the evidence, and there is none.

A design written down here is *target contract*. It becomes *implemented* when
code and focused tests exist, and *verified* only when a declared evidence gate
has passed. Do not promote a status in the same pull request that introduces
the behavior.

## Before you start

Read, in this order:

1. [Third-party development handoff](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
   — permanent design decisions, product ownership, status vocabulary.
2. [Nexus and Boot program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
   — §2 authority and ownership, §4 admission and activation, §5 R2/R3/R7 the
   gates Nexus passes through, §6.6 Nexus's backlog, §15 open findings.
3. [R0 product and compatibility baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md)
   — observed version facts and open R0 work.
4. This repository's [README](README.md), [architecture](docs/architecture.md),
   [capability model](docs/capability-model.md),
   [contract ownership](docs/contract-ownership.md), and
   [commissioning](docs/commissioning.md).

Do not treat a closed issue, an archived roadmap, or a demonstration artifact
as current product authority.

## Boundaries a pull request must respect

### The capability vocabulary has one owner

[`docs/capability-model.md`](docs/capability-model.md) owns the capability
vocabulary for this repository: the four-dimension intersection, the selector
outputs `diagnostic` / `core` / `lite` / `standard`, the capability states
`FULL` / `LITE` / `CORE`, the audit assurance profiles `ROLLBACK_ANCHORED` and
`LOCAL_CONTINUITY_ONLY`, and `COMMISSIONING_REQUIRED`.

Other documents **reference** it. They do not fork it into parallel terms. A
second name for an existing concept — a new tier, a synonym for an envelope, a
"mode" that is really a capability state — is rejected even when it reads
better locally, because the reader who meets both names has no way to know they
are the same thing. [M.I.O. runtime control plane](docs/mio-runtime.md) §2 is
the one place that maps the envelope names to eligibility phrasing, and it
exists precisely so that the mapping is written once.

If a term is genuinely missing, raise it against the owning document — or
against the owning repository, when the term crosses a product boundary —
rather than coining a Nexus-local synonym.

### Numeric thresholds are inherited, never locally adjusted

The RAM selector's boundaries are fixed by the program plan §5 R2 and restated
in [capability model](docs/capability-model.md) §2. They are derived — each
nominal size minus a stated 1024 MiB firmware-reservation allowance — not
chosen, and the plan is explicit about what a product may do with them:

> No product may substitute its own numbers; a product that believes the
> allowance is wrong raises a finding rather than diverging locally.
> — program plan §5 R2

So: **a contributor who believes a threshold is wrong raises a finding in the
program plan** (§15, `OF-xx`, with severity, evidence, affected requirement,
proposed correction, owner, and verification). They do not change Nexus's copy,
not even "temporarily", not even with a comment explaining why. The numbers
appear in several Nexus documents; a local edit to one of them produces a
repository that contradicts itself and a program that cannot tell which
document is authoritative.

The same rule applies to every quantitative target Nexus inherits rather than
owns, including the service objectives in program plan §8.

### Ownership boundaries

- **Do not define a canonical form for a shared record.** Azazel-Fabric owns
  every record that crosses a product boundary, with its serialization,
  digests, validation, and fixtures. Nexus may describe an adapter; it may not
  fork a Fabric model or publish a Nexus-local wire shape. Where a Fabric
  contract does not exist yet — `provisioning_contracts`, `mio_contracts` —
  the dependent work waits for the Fabric release rather than inventing a local
  canonical form. See [contract ownership](docs/contract-ownership.md) §1, §3.
- **Do not inherit Azazel-Edge's device-specific network installer**, its fixed
  NIC values, or its unit defaults. Nexus's interface layout is unknown until
  inventory, so an inherited fixed value would be a guess presented as a fact.
  See [commissioning](docs/commissioning.md) §1.
- **Do not infer an interface role.** A role comes from read-only inventory
  plus explicit operator confirmation against a composite identity — never from
  an interface name, carrier state, default route, learned address, or resource
  measurement.
- **Do not add a dependency.** This repository has no package and no manifest;
  adding either is bootstrap work under
  [contract ownership](docs/contract-ownership.md) §6, and it lands with the
  exact Fabric release pin the R0 baseline requires, not ahead of it.
- **Do not add operational code.** No installer, network, enforcement,
  model-fetch, or container-activation code until the corresponding program
  gate opens.
- **Do not name a rugged PC as supported, qualified, or a candidate.** The
  hardware compatibility list in [support matrix](docs/support-matrix.md) is
  empty on purpose, and a reader who sees a machine named will treat it as
  tested. An entry requires owner ratification and a linked evidence record.

## Branch naming

`<type>/<short-description>`, e.g. `docs/update-channel-offline-bundle`,
`fix/link-check-anchors`.

## Commit message format

`<type>(<scope>): <summary>`

Scopes in use today: `docs`, `ci`, `tools`, `meta`. Japanese or English body
text is fine; say what changed and why. If a change alters a documented
contract, the document is revised in the **same** commit — never left to
diverge silently.

## Pull request rules

- 1 PR = 1 purpose.
- CI passes. Today that is the documentation internal-link check.
- Run it locally before pushing:

  ```bash
  python3 tools/check_docs_links.py
  ```

  It needs only Python 3 from the standard library.
- If you add a document, link it from `README.md`. An unreferenced document
  drifts.
- Cite, do not restate. When a rule comes from the program plan or from another
  Nexus document, link it and name the section rather than paraphrasing it into
  a second, subtly different copy.
- State explicitly, in the PR body, what your change does **not** establish.
  "Written down" and "true" are different, and the PR is where that difference
  is recorded.

## What not to do

- No claim that Azazel-Nexus observes, decides, enforces, commissions,
  activates, updates, or recovers anything today. None of it exists.
- No hardware entry in [support matrix](docs/support-matrix.md) without owner
  ratification and a linked evidence record. The list is empty on purpose.
- No security report in a public issue — use [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the project's MIT license ([LICENSE](LICENSE)).
