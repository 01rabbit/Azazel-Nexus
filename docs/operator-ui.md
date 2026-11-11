# Read-only operator UI (`az-ui`)

Status: **implemented (first stage, read-only); checked in a browser and under
systemd in containers only, not on a VM or hardware.** In-process and
real-process tests cover the server, the browser boundary and the unit files
(`tests/unit/test_ui_serve.py`, `tests/unit/test_ui_model_and_login.py`).
Headless Chromium 156 in a container without a network (aarch64, and one
state on x86_64 under Rosetta) logged in with a real code and rendered the
five screens in the normal, degraded (absent, broken, stale, future-dated,
symlinked, oversized snapshot), recovered, 360 px and XSS-fixture states;
a container whose PID 1 is systemd ran the unit by socket activation as
`azui` and showed unreadable sections as permission denied, and stopping the
UI stopped nothing else. The record, its screenshots and what it does **not**
show (no VM, no hardware, no hands-on Chrome session on a Mac) are in
[ui-browser-2026-10-29.md](evidence/ui-browser-2026-10-29.md).

Since [ADR-0007](adr/0007-ui-read-leaves.md) (S-03, S-04) the UI reads the
operator snapshots from **byte-identical copies** their writers put in
`azui`-group leaves, so on a node it shows them instead of **権限なし**, and
its first screen answers four questions (below). The record of that change,
with the installer's own uids, gids and modes, is
[ui-read-2026-10-30.md](evidence/ui-read-2026-10-30.md).

The UI is a local web page that shows what `azazel-nexus status --json`
(schema `azazel-nexus/status-view/1`) and `azazel-nexus setup --json` show,
on six screens. It has **no action**: no button confirms, approves, starts
or stops anything, and it calls no daemon. Edge decides and enforces; Nexus
observes, explains and advises. Edge's decisions reach this node only as
`would` (observe-only, not executed), and the page says so on every incident.

## Defaults adopted for the first stage

Each of these is a default the owner can change later (see
[the assessment's open questions](#open-questions-for-the-owner)).

| Topic | Default |
| --- | --- |
| Technology | Python standard library (`http.server`, `socketserver`) and four static files shipped in the runtime package (`ui_static/`). No CDN, web font, external request or new dependency. Same code on Arm and amd64. |
| Listening | systemd socket activation: `azazel-ui.socket` has `ListenStream=127.0.0.1:8443` and passes the socket (fd 3) to `azazel-ui.service`, which only accepts on it. |
| Transport | Loopback HTTP, no TLS. The session cookie therefore cannot carry `Secure`. |
| Activation | Not governed by the activation controller (no grant marker, never masked or unmasked by a pass, in no lease). The preset says `disable`; an operator enables the socket explicitly. No unit requires, binds to or wants the UI. |
| Account | `azui`, no shell, no home, **no supplementary group** (not `azazel-operator`, no daemon socket group). No new read group: `azui` is the setgid group of the UI read leaves (`run/ui-read/<leaf>`, `2750 <writer>:azui`, [ADR-0007](adr/0007-ui-read-leaves.md)), which it reads and never writes. |
| Login | `azazel-nexus ui-login` (read-only, operator group) prints a one-use code valid for 60 seconds. |
| Screens | Overview (the four answers), incidents, NOC, Knowledge, details, setup and recovery. |

## How it runs

```
azazel-ui.socket (systemd, IPv4 loopback only, IPAddressAllow=localhost)
        |  fd 3 (LISTEN_FDS=1)
        v
azazel-ui.service -> /usr/libexec/azazel/az-ui  (azui; AF_UNIX only; PrivateNetwork=yes)
        |  in process, read only
        +-- azazel-nexus --snapshot-reader ui status --json
        |       (the status read model, its snapshots from run/ui-read/<leaf>)
        +-- azazel-nexus setup --json    (the setup guide)
        +-- stat() of the files status reads (permission or absence)
        +-- lstat() of the observer timers' wants links (enabled or not)
        |
        +-- writes only /var/lib/azazel/run/ui-login/login-code.json (2750 azui:azazel-operator)
```

* **It never creates a socket of an internet family.** `az-ui` adopts the
  descriptor systemd passes (`socket.socket(fileno=3)`; the family comes from
  the descriptor) and refuses to start unless it is one listening IPv4 stream
  socket bound to `127.0.0.1`. It subclasses `socketserver.BaseServer`, not
  `TCPServer`, so no standard-library server builds a socket for it. The
  runtime boundary test pins this: `ui_serve.py` is the one module that may
  construct a socket from a descriptor without naming a family, and it may
  name no `AF_INET`, `bind`, `listen`, `connect` or server class
  (`tests/unit/test_runtime_boundary.py`, `ADOPTED_LISTENER`). The listener
  exemption (`LISTENER_EXEMPT`) was **not** widened.
* **The unit** (`packaging/systemd/azazel-ui.service`, generated from
  `hardening.UI_PROFILES`) is `RestrictAddressFamilies=AF_UNIX`,
  `PrivateNetwork=yes`, `IPAddressDeny=any`, the shared sandbox, no
  capability, `ProtectProc=invisible`, bounded memory and tasks, and writes
  only the login-code leaf. A socket-activated service's own IP lists cover
  only sockets it creates; the accepted connections are covered by the
  socket unit's `IPAddressDeny=any` / `IPAddressAllow=localhost`.
* **Stopping the UI stops nothing else.** No unit names `azazel-ui.*` in
  `Requires=`, `BindsTo=`, `Wants=`, `PartOf=` or any ordering, and no daemon
  reads anything the UI writes (test:
  `test_nothing_depends_on_the_ui_so_stopping_it_stops_nothing`).

### What the UI account can read

`azui` is in no group but its own. The operator snapshots are
`2750 <daemon>:azazel-operator`, which `azui` cannot open; since
[ADR-0007](adr/0007-ui-read-leaves.md) each of their writers also puts a
byte-identical copy into its own `run/ui-read/<leaf>` (`2750 <writer>:azui`),
and `az-ui` runs `status` with `--snapshot-reader ui`, which reads those
copies with the same strict readers and the same freshness:

| Copy | Writer | UI leaf |
| --- | --- | --- |
| `audit-status/v1` | `az-auditd` | `run/ui-read/audit` |
| `edge-intake-status/v1` | `az-edge-intaked` | `run/ui-read/edge-intake` |
| `incident-explain-status/v1`, recent incidents | `az-incident-explaind` | `run/ui-read/incident-explain` |
| `knowledge-status/v1` | `az-knowledge-lited` | `run/ui-read/knowledge` |
| `mio-status/v1` | `az-mio-entryd` | `run/ui-read/mio` |
| `units-status/v1` | `az-units-observe` | `run/ui-read/units` |
| `noc-status/v1` | `az-noc-observe` | `run/ui-read/noc` |

The recent incident card renders a complete slow M.I.O. result in its own
block, labelled `model_proposed_unverified` and advisory only. It never merges
that text into observed facts, Edge's decision, or the fast M.I.O. assessment.
Queued and terminal states carry status only; an expired recent snapshot does
not display slow-result text.

What has no copy -- the Edge probe result (it carries the package digest and
free-text reasons), the Knowledge Lite store, the route ledger, the model
store, the Core reserve record, the remote consent -- is still read directly
and shown as **権限なし (`permission_denied`)** with the reason
`access_permission_denied`, never as absent and never as healthy: the server
`stat()`s each path and sends what it found (`access`). A copy that is not
there yet (a node upgraded without re-running `install.sh`, or a writer that
has not run) is **absent**; one whose observer timer is not enabled is
**観測なし（未有効化）**.

## Browser boundary

| Rule | How |
| --- | --- |
| Login | `azazel-nexus ui-login` prints a one-use code (10 symbols, about 49 bits) that the UI wrote to `/var/lib/azazel/run/ui-login/login-code.json`, readable only by `azazel-operator`. Each code is redeemable once, for 60 seconds from issue; a new code appears every 30 seconds and at once after a login. At most 10 wrong codes are evaluated per 30-second window, from anyone; past that, every login attempt in the window is refused **unevaluated** (`429 login_throttled`), the correct code included, and no code is withdrawn. Guessing is thus bounded at 20 tries a minute against a 49-bit code that lives 60 seconds. The code is typed into a form and sent in a POST body, never in a URL. |
| Session | Cookie `azui_session`: `HttpOnly; SameSite=Strict; Path=/; Max-Age=3600`, no `Secure` (loopback HTTP). Held in memory only; idle 10 minutes, at most 60 minutes, at most 8 sessions; a restart ends all. A clock step backwards ends a session. |
| Host | `Host` must be exactly `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding); anything else is `421`. |
| CSRF | A POST (login, logout) needs `Origin` equal to `http://<Host>`, `Content-Type: application/json`, a body of at most 1024 bytes, no `Sec-Fetch-Site` other than `same-origin`, and a token: the session's synchroniser token for logout, a signed double-submit token (`azui_login` cookie, 5 minutes) for login. |
| GET | Changes no state on the server. |
| Slow or broken clients | Each read has a 5-second timeout and each connection a 10-second total deadline from accept, after which the server shuts the socket down and frees the slot (at most 16 at once). A `Content-Length` that is not ASCII digits is `411`; a body that is shorter than declared or stops arriving is `400 body_unreadable`. A handler failure is journalled as the one word `request_error`, never a traceback or a client address. |
| URL | No query string or fragment is accepted anywhere (`400`), so no token can travel in a URL. |
| Headers | Every response, refusals included: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Cross-Origin-Opener-Policy` and `-Resource-Policy: same-origin`, a `Permissions-Policy` that disables device features. |
| Static files | Five request paths mapped to four files read once at start; a request path is never joined to a filesystem path. |
| XSS | The page writes with `textContent` only. `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` and the `Function` constructor are absent (tested by scanning `app.js`). JSON is escaped (`<`, `>`, `&`, U+2028, U+2029). An AI summary or a Knowledge name is shown as text and never linked. |
| Not sent | Keys, credentials, the login code (only the operator's terminal shows it), raw logs, journal lines, exception text, interface names or addresses. The document (`azazel-nexus/ui-model/1`, `azazel_nexus.ui_model`) is an allowlist over the status read model, which is itself an allowlist; the interface list is not copied at all. |

### What another account on the same host can do

Loopback is shared by every account on the host, so the boundary above is
against reading, not against interference:

* **Login interference.** Any local account can send wrong codes and so keep
  the login throttled (`login_throttled`) for as long as it keeps sending.
  It cannot learn or invalidate the operator's code, and sessions already
  open are unaffected. The page tells the operator that another account on
  the host may be sending codes; `journalctl -u azazel-ui.service` shows
  `az-ui: login_throttled`, and stopping the UI ends it. A local account can
  likewise hold the 16 connection slots, each for at most 10 seconds at a
  time. Neither touches anything but the UI.
* **Cookies are not isolated by port.** A browser sends `127.0.0.1` cookies
  to every port on `127.0.0.1`, and a page served from another port on this
  host is same-site for `SameSite=Strict`. A local account that serves a page
  on another port can therefore overwrite or delete the UI's cookies in the
  operator's browser (log the operator out, or plant a login token so the
  next login attempt fails). It cannot read the `HttpOnly` session cookie
  through the page, and the `Origin` check refuses its POSTs, so the limit
  is login interference, not access.
* **Check the listener before typing a code.** 8443 is not a privileged
  port: if the UI's socket is not active, another local account could listen
  there and show a look-alike login page to collect a code. Before typing a
  code, check `systemctl is-active azazel-ui.socket` (it must say `active`).
  A collected code is one use and expires in 60 seconds, and the page it
  would open shows only what `status --json` shows.

## Screens and vocabulary

The Japanese labels are one table, `runtime/src/azazel_nexus_runtime/ui_static/labels.json`.
Every word is shown with its English enum value beside it in small type, so a
reader can match it against the documents
([integration-display.md](integration-display.md),
[noc-observation.md](noc-observation.md)). Each state is shown by colour,
word and mark together (● 正常, ▲ 注意, ■ 異常, ？ 不明, ◆ 情報), never by
colour alone. Unknown, unmeasured, stale, not collected and permission
denied are never green and never "正常"; only `attested`, `available`,
`current`, `done`, `fresh`, `running`, `verified-ready` and `ok` are (tested).
What a section says it read -- `observed` (NOC), `read` (services),
`recorded` (M.I.O.), `measured` (storage) -- is shown as information, not as
health. So are the M.I.O. card's unchanged period (`age_s`) and its writer's
liveness (`evidenced`, `counted`: information; `not_evidenced`,
`not_counted`: unknown). Inside a section, every value under `status`, `state`, `freshness`
or `collection` goes through the label table and every `reason_code`,
`reason` and `conditions` entry through the reason table (`app.js`
`WORD_KEYS`/`REASON_KEYS`, kept equal to the tests).
Each card shows when it was observed and how long ago.
Field names in a card's table are shown in Japanese with the field name
beside them (`labels.json` `keys`); fixed English sentences (the M.I.O.
notice, the setup notice, the handoff notice, what Knowledge Lite's
"functional" means and does not mean, the external modules' reasons) are
shown in Japanese with the original in small type (`texts`); any other
English sentence is shown as the original, labelled so. A field name or a
fixed sentence without a label fails the tests. Storage and the units list
are tables, one row per location or unit, sizes in readable units.

Knowledge Lite and the M.I.O. route are each shown twice: as read directly
by `azui`, and as the owning daemon's snapshot. Each card says which path it
is; a direct read `azui` may not make says so and points at the snapshot;
and when the two disagree, both cards say they disagree rather than leaving
one of them to look wrong.

| Screen | Shows | Source |
| --- | --- | --- |
| 概況 (overview, the four answers) | **Is communication being kept?** What the passive NOC observation saw of the default route and its link (IPv4, IPv6), the Edge unit's state, and that reachability is not measured: the best word is `path_observed` (information), never "正常". **What is happening?** The number of open incidents as the intake (which owns the incident ledger) reports it, the explainer's list beside it (at most twenty rows; a disagreement, a broken chain, a storage failure or a lag is said), the most severe (a smaller number is more severe) and how many carry an AI explanation (inference, shown apart); "none open" only when the intake is fresh, running and reports zero and the list shows none open. **What is handled automatically?** Edge's decisions as *would, not executed*, by action, and the execution result `none` (Nexus accepts observe-only decisions only). **What does the person on duty do next?** An ordered list: check the uplink, review the incidents and hand off to an expert, check failed units, enable the observers (the command), check unreadable or stale sources, continue setup, or keep monitoring. Each answer separates observed facts, AI inference, Edge's decision and the execution result, and says unknown, stale, absent, not enabled or permission denied as such. | `summary` (`ui_model.summarize`, from the sections below) |
| 専門情報 (details; tab id `detail`) | Edge's state and readiness, the fixed observe-only mode (there is no "running/enforcing" box), communication (NOC), AI route (M.I.O., and its operator snapshot), Knowledge Lite (and its operator snapshot), services, storage, the Edge loop and what continues regardless. | `edge_core`, `enforcement`, `mio`, `mio_status`, `knowledge_lite`, `knowledge_status`, `noc`, `services`, `storage`, `edge_loop`, `health`, `fabric`, `integration`, `operator_view` (the admission gates by code, what was read, the catalog, import stages and confirmations; a store `azui` cannot open says *not read*) |
| インシデント (incidents) | Per incident, in separate blocks: observed facts; Edge's decision as *would, not executed*; the actual execution result, fixed as "none (Nexus accepts observe-only decisions only)"; the advice and its kind (AI, deterministic reference, deterministic notice); the citations, each with its bundle (shortened digest), generation, freshness, lookup time and source (`citation_state` `shown` / `none` / `withheld`; a row written before #362 says those were not recorded) and the count of citations recorded but not shown. Edge's own forwarding counts and Nexus's own decoy observation are kept apart. | `edge_loop.intake`, `edge_loop.recent` |
| NOC | The passive observation as the read model carries it: its word (`observed`, or `unknown` with the collection's reason), freshness, each item's state and reason (an active check is `not_measured` / `active_check_not_performed`, never "down"), counts by ifindex. No interface name or address. | `noc` |
| Knowledge | Knowledge Lite state, freshness, generation, what "functional" does and does not mean, the verified bundle's facts (shortened digest, signing key ids, static and dated claim counts, nearest expiry; a withheld fact says so), the cryptographic implementation status, the operator snapshot of `knowledge.status`, the external peer (absent by design) and the citations of recent incidents. | `knowledge_lite`, `knowledge_status`, `external_modules`, `edge_loop.recent` |
| セットアップ・復旧 (setup and recovery) | The setup guide's steps and their next commands **as text** (the page runs nothing), provider admission, health, each unit's state and each storage location, the explainer's chain recovery hint and status's next actions. | `setup --json`, `health`, `services`, `storage`, `next_actions`, `enforcement` |

### Reading the explainer right after a restart

Shortly after `azazel-incident-explaind` restarts with a checkpoint, the
explainer list may show it as behind (pending work) while the time of the last
explanation does not move. That is the designed 60-second wait of the rolling
rate budget, not a fault, and the rows already shown do not change. If it
continues well beyond a minute, treat it as a different cause and look at the
chain, storage and M.I.O. indicators and the recovery steps in
[operations](operations.md). The page does not estimate the remaining time.

### When a refresh fails

The page refreshes `/api/view` every 5 seconds (a request that has not answered within 8 seconds counts as timed out). What stays on screen depends on why it failed:

| Response | Screen |
| --- | --- |
| 401 | Back to the login screen; panels, open/closed state and live text are discarded. |
| 403, 421 | The previous content is discarded and a refusal notice is shown; polling continues and a later 200 restores the screens. |
| Timeout, no connection, 5xx, 408, 429 | The previous content stays, under a prominent "更新停止" notice with the time the page last got a valid answer. That time is when this page fetched, not an observation time inside the data. |
| 404, 410, other 4xx | Same notice, worded as "not found" / "rejected"; it is not read as "no data" or "healthy", and a missing endpoint is not called deleted. |
| 200 with an invalid body | Not used; the previous content stays under the "応答の形式が不正" notice. |
| Failure before the first valid answer | "表示できる前回データはありません". |

The last-fetch time moves only on a valid 200. The notice names the cause with fixed wording; response bodies and exception text are never shown. A response that arrives after logout or a refusal is ignored. Server-side authentication, authorization and the allowlist are unchanged.

### The operator snapshot and NOC sections

`knowledge_status`, `mio_status`, `services` and `noc` are the snapshots the
owning daemons and observers write into operator-readable leaves (U2, U3,
[operations.md](operations.md)); `storage` is measured when status runs.
The UI reads their copies in `run/ui-read` (ADR-0007); each card's source
says `leaf: ui`. `azui` does not join `azazel-operator`. A read model that lacks one of these
sections (an older one, or a fixture saved before them) lists it under
`pending` with `section_absent_from_read_model`, and the page says
**未取得**. Any other new section is not passed through until it is listed
in `ui_model.UI_SECTIONS`.

## Enabling it on a node

```sh
sudo sh packaging/install.sh                   # creates run/ui-read/<leaf> (re-run after an upgrade)
sudo systemctl enable --now azazel-noc-observe.timer azazel-units-observe.timer
                                               # the observers (M24): not enabled by the installer
sudo systemctl enable --now azazel-ui.socket   # listens on 127.0.0.1:8443
systemctl is-active azazel-ui.socket           # must say "active" before a code is typed
azazel-nexus ui-login                          # as a member of azazel-operator
# open http://127.0.0.1:8443/ on this host and type the code
```

`azazel-nexus setup` shows the observer step (`operator-observers`) as
`needed` with the same command until both timers are enabled, and the UI
shows their sections as **観測なし（未有効化）** with the command among its next
steps. The daemons that write the other copies start with the activation
controller as before; until they run, the UI says absent for their copies.

`systemctl disable --now azazel-ui.socket azazel-ui.service` stops it. Nothing
else depends on it.

## Demonstration with a fixture

A fixture is a saved status read model. Every screen then carries the banner
"fixture 表示：保存済みの read model を表示しています。このノードの現在の状態ではありません。"
and the setup screen says `not_in_fixture`, so a demonstration cannot be
mistaken for a node's state. The repository ships one:
`tests/fixtures/ui/demo-status-view.json` (the `loop` scenario of
`tests/unit/test_status_view.py`: fresh snapshots, three incidents, a broken
chain).

With systemd's tool (Debian package `systemd`):

```sh
mkdir -p ~/ui-demo
systemd-socket-activate -l 127.0.0.1:8443 \
  az-ui --fixture tests/fixtures/ui/demo-status-view.json \
        --login-file ~/ui-demo/login-code.json
```

Without it, the repository's helper does the same thing (binds 127.0.0.1
only, places the socket at fd 3, sets `LISTEN_PID`/`LISTEN_FDS` and execs
the command):

```sh
python3 tools/ui_socket_activate.py --port 8443 -- \
  python3 -m azazel_nexus_runtime.ui_serve \
  --fixture tests/fixtures/ui/demo-status-view.json \
  --login-file ~/ui-demo/login-code.json
```

Then read the code and log in:

```sh
python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["code"])' ~/ui-demo/login-code.json
# open http://127.0.0.1:8443/ and type it
```

`--login-file` only moves where the code is written, for a demonstration
without the installed leaf; the unit passes no argument. In a container,
publish the port to the host's loopback only (`-p 127.0.0.1:8443:8443`) and
note that the UI then sees the host as `127.0.0.1:8443` in `Host`.

## Open questions for the owner

* TLS and stronger authentication (WebAuthn or client certificates, as the
  specification describes for 8443) for a later stage; loopback HTTP is the
  first stage, and `Secure` cookies are therefore not possible.
* ~~Whether `azui` should read snapshots through a dedicated read-only group~~:
  decided by default in [ADR-0007](adr/0007-ui-read-leaves.md) (proposed):
  per-writer copies in `azui`-group leaves, no new group.
* Whether to keep the UI ungoverned (the default here, so the setup and
  recovery screen works before activation) or to govern it.
* The unit name (`azazel-ui.service`; the specification says
  `azazel-uid.service`).
* Whether interface names may ever be shown (inventory-confidentiality §6;
  they are not).
* Japanese fonts for a kiosk (`fonts-noto-cjk`) are a deployment choice.

The UI also assumes the change that removes `azui` from the default
`SERVICE` principal resolution (Nexus#355): without it, daemons that accept
`SERVICE` would classify `azui` as a service account. `azui` is given no
group, so it cannot reach those daemons' sockets in either case.
