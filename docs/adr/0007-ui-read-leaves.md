# ADR-0007 — The read-only UI reads byte-identical snapshot copies its writers put in `azui`-group leaves; `operator_view` reaches status and the UI as a versioned section

Status: **proposed (2026-10-30)**, with defaults adopted by the implementing
change; the owner may change any of them · Decides
[owner-decisions](../owner-decisions.md) H9 and M23, implements M22's default
for the UI, M24's enabling path, L8 and L9 · Leaves the
[operator UI](../operator-ui.md)'s browser boundary, the activation
controller and every daemon's socket permissions unchanged

## Context

The read-only UI (`az-ui`, [operator-ui.md](../operator-ui.md)) runs as `azui`,
an account in no group but its own. It builds its page from `azazel-nexus
status --json`, run in its own process. Every operator snapshot that status
reads (U2, U3: `knowledge-status`, `mio-status`, `units-status`,
`noc-status`, and the Edge loop's `edge-intake-status`,
`incident-explain-status` with `recent.json`, auditd's `audit-status`) lives
in a leaf `2750 <writer>:azazel-operator`. On a real node `azui` could open
none of them: the systemd rehearsal of #372 showed fifteen cards as
**権限なし** (permission denied). The page said so honestly, but the person
on duty could not learn from it whether communication was kept or what was
happening (goal 2 【5】A; Codex survey S-03).

Separately, [`operator_view`](../../src/azazel_nexus/operator_view.py)
(`gather_facts` / `build_view`, the catalog, import stages, admission and
confirmations screen of #99) had no caller in the product (S-04), and its
provider row was fixed text ("refuses for having no implementation") that
no longer matched how admission is actually decided.

The owner's direction (goal 2 【5】A) is fixed: give the UI the minimum display
data through a read path designed for it, and **do not** solve this by giving
`azui` broad operator rights or any daemon's operating rights.

## Options compared

| Option | What `azui` gains | Against it |
| --- | --- | --- |
| A. `azui` joins `azazel-operator` | every operator leaf **and every operator socket** (commission, watchdog, fetch, M.I.O., Knowledge, remote) | Rejected by the owner's direction: daemon operating rights. A fault in a web server would reach every operator verb. |
| B. A new read group (`azstatus-read`) on the existing leaves | the same files | Every existing operator must be added to the new group or loses `status`; the leaves' group stops being the operator group the layout tests pin; membership churn on every node. |
| C. POSIX ACLs (`g:azui:r`) on the existing leaves | the same files | Invisible in `ls -l`, not modelled by `layout.py`'s declaration, not checked by any installer test, and default ACLs interact with each writer's `fchmod`. |
| D. A projector service (oneshot + timer) in `azazel-operator` writing one UI file | one file | A new principal that reads **everything** an operator reads (and holds the operator group, so it could reach operator sockets); one more timer to enable; the UI's freshness becomes the timer's, not the writer's. |
| E. A fixed query socket served by a new daemon | answers to fixed queries | A new listener and protocol, and `azui` would need a socket group: the very thing the unit forbids (`RestrictAddressFamilies=AF_UNIX` with no group is what keeps it from every daemon). |
| **F. Each writer also writes a UI copy into its own `azui`-group leaf** (adopted) | read access to those copies only | One more leaf per writer, declared in the layout and the installer; each writer writes one more file. |

## Decision

**D1. Each snapshot writer puts a byte-identical copy of its snapshot into
its own UI read leaf.** The leaves are
`/var/lib/azazel/run/ui-read/<leaf>`, `2750 <writer>:azui`, under a parent
`ui-read` that is `0711 root:root` (traversal only, like `run/`):

| Snapshot | Writer (account) | UI leaf |
| --- | --- | --- |
| `audit-status/v1` | `az-auditd` (`azaudit`) | `ui-read/audit` |
| `edge-intake-status/v1` | `az-edge-intaked` (`azintake`) | `ui-read/edge-intake` |
| `incident-explain-status/v1`, recent incidents | `az-incident-explaind` (`azexplain`) | `ui-read/incident-explain` |
| `knowledge-status/v1` | `az-knowledge-lited` (`azknowledge`) | `ui-read/knowledge` |
| `mio-status/v1` | `az-mio-entryd` (`azmioentry`) | `ui-read/mio` |
| `units-status/v1` | `az-units-observe` (`azprobe`) | `ui-read/units` |
| `noc-status/v1` | `az-noc-observe` (`aznoc`) | `ui-read/noc` |

The copy is written right after the operator snapshot, from the same bytes,
by temp file and rename, mode `0640` (`status_snapshot.UiCopy`); the setgid
leaf hands the file to group `azui`. A copy that cannot be written is logged
once and never fails the daemon or the operator snapshot (each unit lists
the leaf as an optional `ReadWritePaths=-`), so a node upgraded without
re-running `install.sh` keeps running and the UI shows that snapshot as
absent, never as healthy. `azui` gains no group, no socket and no write
access; the writers gain one leaf each and nothing else.

**D2. Why a copy and not a narrower projection.** Every snapshot in the table
is already a closed shape of codes, counts and fixed vocabulary, written for
an unprivileged reader (`operator_snapshots`, `noc_status`, `edge_intake`,
`incident_explain`, `audit_status`): no interface name or address, no path,
no key, no digest of a secret, no exception text. A byte-identical copy lets
the UI use the **same strict readers** and the **same freshness** (`written_at`
of the same write); a second, narrower shape would be a second reader to keep
in step. Because the copy is the same bytes, whatever the UI must not see is
removed **in the shared builder, before either file is written**, never only
in the read model: the explainer's recent list withholds a Knowledge citation
that holds **any path separator** (`/`, `\`, after NFKC so the full-width
forms too, and the look-alike slashes NFKC keeps) -- whatever comes before
it, `source=/srv/...` or `source:./...` included -- in
`incident_explain.build_recent_incidents` and `explanation_summary`, rows
restored from an older checkpoint included (Codex review R389-01, R389b-01).
A displayed citation is a short name; the rule is narrow on purpose, and the
read model applies the same rule again (`citation_names_a_path`). A test
writes a citation with such a path through the explainer and reads the
**raw** UI file. The remaining free text in the copied shapes is the AI
summary and the fixed notices, which the UI shows as such anyway. Snapshots that are *not* in this shape get no copy: the Edge probe
result (it carries the package digest and free-text reasons, M22) and every
store `status` reads directly (the Knowledge Lite store, the route ledger,
the commissioning record, the model store, the remote consent). The UI shows
those as **権限なし** with the access probe, as before.

**D3. The terminal-only items (M22) stay on the terminal.** Interface
descriptions and names, the Edge package root, Edge finding reasons, the
issuer's name, revocation sequence and floor version, and `--ledger` details
are in no UI copy (none of the copied snapshots holds them) and in no UI
document (`status_view` withholds them, `ui_model` copies by allowlist). A
test reads every copied snapshot's shape for them (`tests/unit/test_ui_read_leaves.py`).

**D4. The reader is chosen by the caller.** `azazel-nexus status` takes a
hidden `--snapshot-reader {operator,ui}` (default `operator`); `az-ui` passes
`ui`. It selects which leaf each snapshot path names and nothing else: no
environment variable, no fallback from one leaf to the other, and file
permissions decide what is read. Each snapshot section names the copy it read
(`source.leaf`), and the view names the reader (`snapshot_reader`).

**D5. `operator_view` is connected as read adapter → versioned status
section → UI projection.** `operator_view_source.read_section` gathers the
facts read-only (the model store through `ModelImport`'s read verbs, the Core
reserve record, entryd's snapshot, the build switch), and status carries the
result as the section `operator_view` with its own schema
`azazel-nexus/status-view/operator-view/1`. A source the reading account
cannot open is passed as *not read* and every row built from it says so with
a code (`catalog_permission_denied`, `not_read`): never `absent`, `empty` or
zero. A catalog that is refused keeps its fixed code (`catalog_unsigned`,
`catalog_invalid`, `catalog_unreadable`, `catalog_permission_denied`) and is
never turned into "not presented" (R389-06). The adapter **never opens or
hashes an artifact** (R389-04): an installed model is described from the
signed catalog and the current generation record as "installed; its digest
was checked when it was promoted; not re-verified here", and never as
`present`, which would claim a verification this screen did not make.
Re-verifying integrity stays an explicit operation. The provider row now follows the gates that decide admission -- the
build switch `LOCAL_MODEL_ADMISSION_ENABLED`, the measured Core reserve
(HG-05), and the local route's admission reason as entryd recorded it --
listing each gate that refuses (`reason_codes`). No combination this build can
read shows a provider as admitted.

**D6. Versions (M23).** `status-view/1` is **additive**: a new section or a
new field inside a section is compatible, because every reader copies by
allowlist (`ui_model.UI_SECTIONS`, `status_view`'s field lists) and ignores
what it does not list; a section a reader expects and does not find is
`pending` with `section_absent_from_read_model`, never healthy. A new word in
a closed vocabulary is compatible only because the page shows an unknown word
as **未定義の語** in the unknown tone. Removing a field, changing a field's
meaning or type, or changing what a word means is a new major version
(`status-view/2`), which `ui_model` refuses (`read_model_refused`) rather than
misreads. A section with a schema of its own (`operator-view/1`) follows the
same rule on its own: `ui_model` checks that schema and copies only the
fields of the version it knows, one by one; any other version of the section
is `pending` with `section_version_unsupported` and is not shown (R389-05). A snapshot copy carries its snapshot's schema
(`.../v1`); a snapshot that changes shape bumps its own schema and its reader
lists exactly the versions it accepts (`operator_snapshots`, unchanged).

**D7. The normal screen answers four questions; the rest is the detail
screen.** `ui_model.summarize` projects, from the sections above and nothing
else: is communication being kept (the passive NOC observation's default
route and link, and the Edge unit's state; reachability is not measured, so
the best word is information, never "ok"), what is happening (open
incidents, only while the intake that feeds the list is shown running), what
is handled automatically (Edge's decisions as `would`, the execution result
`none`: this node accepts observe-only decisions only), and what the person
on duty does next (an ordered list of codes, each with the screen or the
terminal command). Each answer's basis keeps observed facts, AI inference,
Edge's decision and the execution result apart. Unknown, stale, absent, not
enabled and not readable are each said as such.

**D8. Observers (M24) stay disabled by the installer.** SPEC 2.3 and the
preset are unchanged: `install.sh` enables neither observer timer. `setup`
gains the step `operator-observers`, `needed` with the exact command (`sudo
systemctl enable --now azazel-noc-observe.timer azazel-units-observe.timer`)
until both wants links exist; the UI reads the same links (`lstat` only, no
service-manager call) and shows a section whose observer is not enabled as
**観測なし（未有効化）**, with the command in its next steps.

**D9. L8, L9.** The text `status` screen prints the operator snapshot lines
and the operator view (the same words and codes as `--json`), and the UI
labels GetUnit's `not-loaded` as "読込なし（未導入とは限らない）".

## Consequences

* On a node installed by this `install.sh`, `azui` reads the seven copies
  and nothing else it could not read before. It still reaches no daemon
  socket, writes only its login-code leaf, and every daemon verb stays out of
  its reach (tested with the installer's uid/gid and modes).
* A node upgraded without re-running `install.sh` keeps working; the UI says
  absent for each copy until the leaves exist.
* A copy whose rewrite fails is removed when possible, so the UI says absent at
  once; when even that fails, the old copy carries the `written_at` of the
  write that produced it and is stale past its snapshot's limit (30 s for the
  Edge loop, 120-300 s for the observers). Within that window the UI shows the
  last good copy with its time, as it would after a daemon stopped.
* "No open incident" is said only when the intake (which owns the incident
  ledger) is fresh, running and reports zero, and the explainer's list shows
  none open: the list holds twenty rows and can lag, fail to store or break,
  and a disagreement with the intake's count is said, by direction: fewer
  rows than the count (the list misses some) or more (the list has not caught
  up with a closure) (R389-02, R389b-02).
* Copy writes and removals of one snapshot are serialised (`UiCopy` holds a
  lock), so the intake's worker and its shutdown path cannot interleave a
  failure's removal with another write: the outcome is the last call's copy
  or none, never an older copy left looking current.
* The operator view on the UI shows the admission gates it can read and says
  *not read* for the model store and the consent, which `azui` cannot read.
  Publishing those to the UI would need a writer that owns them; none runs in
  this build, and this change does not add one.
* Each writer writes two files per snapshot. The sizes are bounded by the
  existing reader limits (at most 64 KiB for NOC, 256 KiB for the recent
  incidents).

## Not decided here

* Remote access to the UI (TLS and strong authentication, M20). Loopback HTTP
  stays loopback.
* Whether interface names may ever be shown (inventory-confidentiality §6):
  they are not.
* Whether the Edge probe result should get a UI projection without its
  digest and reasons; until then the Edge card reads the package directly and
  shows the probe as not readable.
