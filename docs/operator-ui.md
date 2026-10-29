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

The UI is a local web page that shows what `azazel-nexus status --json`
(schema `azazel-nexus/status-view/1`) and `azazel-nexus setup --json` show,
on five screens. It has **no action**: no button confirms, approves, starts
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
| Account | `azui`, no shell, no home, **no supplementary group** (not `azazel-operator`, no daemon socket group). No new read group. |
| Login | `azazel-nexus ui-login` (read-only, operator group) prints a one-use code valid for 60 seconds. |
| Screens | Overview, incidents, NOC, Knowledge, setup and recovery. |

## How it runs

```
azazel-ui.socket (systemd, IPv4 loopback only, IPAddressAllow=localhost)
        |  fd 3 (LISTEN_FDS=1)
        v
azazel-ui.service -> /usr/libexec/azazel/az-ui  (azui; AF_UNIX only; PrivateNetwork=yes)
        |  in process, read only
        +-- azazel-nexus status --json   (the status read model)
        +-- azazel-nexus setup --json    (the setup guide)
        +-- stat() of the snapshot files status reads (permission or absence)
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

`azui` is in no group but its own, so it reads only what any account may.
Today the snapshots `status` reads are `2750 <daemon>:azazel-operator`, so on
a real node most sections are unreadable to `azui`. The page shows such a
section as **権限なし (`permission_denied`)** with the reason
`access_permission_denied`, never as absent and never as healthy: the server
`stat()`s each snapshot path and sends what it found (`access`). Widening
what `azui` may read (a read-only group such as `azstatus-read`) is an owner
decision and is not part of this change.

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

| Screen | Shows | Source |
| --- | --- | --- |
| 概況 (overview) | Edge's state and readiness, the fixed observe-only mode (there is no "running/enforcing" box), communication (NOC), AI route (M.I.O., and its operator snapshot), Knowledge Lite (and its operator snapshot), services, storage, the Edge loop and what continues regardless. | `edge_core`, `enforcement`, `mio`, `mio_status`, `knowledge_lite`, `knowledge_status`, `noc`, `services`, `storage`, `edge_loop`, `health`, `fabric`, `integration` |
| インシデント (incidents) | Per incident, in separate blocks: observed facts; Edge's decision as *would, not executed*; the actual execution result, fixed as "none (Nexus accepts observe-only decisions only)"; the advice and its kind (AI, deterministic reference, deterministic notice); the citations, each with its bundle (shortened digest), generation, freshness, lookup time and source (`citation_state` `shown` / `none` / `withheld`; a row written before #362 says those were not recorded) and the count of citations recorded but not shown. Edge's own forwarding counts and Nexus's own decoy observation are kept apart. | `edge_loop.intake`, `edge_loop.recent` |
| NOC | The passive observation as the read model carries it: its word (`observed`, or `unknown` with the collection's reason), freshness, each item's state and reason (an active check is `not_measured` / `active_check_not_performed`, never "down"), counts by ifindex. No interface name or address. | `noc` |
| Knowledge | Knowledge Lite state, freshness, generation, what "functional" does and does not mean, the verified bundle's facts (shortened digest, signing key ids, static and dated claim counts, nearest expiry; a withheld fact says so), the cryptographic implementation status, the operator snapshot of `knowledge.status`, the external peer (absent by design) and the citations of recent incidents. | `knowledge_lite`, `knowledge_status`, `external_modules`, `edge_loop.recent` |
| セットアップ・復旧 (setup and recovery) | The setup guide's steps and their next commands **as text** (the page runs nothing), provider admission, health, each unit's state and each storage location, the explainer's chain recovery hint and status's next actions. | `setup --json`, `health`, `services`, `storage`, `next_actions`, `enforcement` |

### The operator snapshot and NOC sections

`knowledge_status`, `mio_status`, `services` and `noc` are the snapshots the
owning daemons and observers write into operator-readable leaves (U2, U3,
[operations.md](operations.md)); `storage` is measured when status runs.
The UI's account `azui` is in no group, so on a node it cannot open those
leaves (`2750 <writer>:azazel-operator`): the access probe reports
`permission_denied` for `knowledge_status`, `mio_status`, `units_status` and
`noc_status`, and the page shows **権限なし** rather than "absent" or a
healthy word. Whether `azui` should join `azazel-operator` is an owner
decision; this UI does not widen it. A read model that lacks one of these
sections (an older one, or a fixture saved before them) lists it under
`pending` with `section_absent_from_read_model`, and the page says
**未取得**. Any other new section is not passed through until it is listed
in `ui_model.UI_SECTIONS`.

## Enabling it on a node

```sh
sudo systemctl enable --now azazel-ui.socket   # listens on 127.0.0.1:8443
systemctl is-active azazel-ui.socket           # must say "active" before a code is typed
azazel-nexus ui-login                          # as a member of azazel-operator
# open http://127.0.0.1:8443/ on this host and type the code
```

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
* Whether `azui` should read snapshots through a dedicated read-only group
  (for example `azstatus-read`), and how existing operators are then
  handled. Until then most sections show `permission_denied` on a real node.
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
