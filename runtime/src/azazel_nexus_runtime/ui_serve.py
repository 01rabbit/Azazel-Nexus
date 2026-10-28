"""`az-ui`: the read-only operator UI, served on an inherited loopback socket (U5).

What it is
----------
A small HTTP server on Python's standard library that serves five read-only
screens (overview, incidents, NOC, Knowledge, setup and recovery) from the
status read model (`azazel-nexus status --json`, schema
`azazel-nexus/status-view/1`) and the setup guide (`azazel-nexus setup
--json`). It has **no action**: no button confirms, approves, starts or
stops anything, and no endpoint changes state on this node beyond the UI's
own in-memory login sessions. Edge decides and enforces; Nexus observes,
explains and advises; the page says so on every screen.

How it listens
--------------
It never creates an internet socket. `azazel-ui.socket` (systemd) listens on
`127.0.0.1:8443` and passes the listening socket to this process (the
`LISTEN_FDS` protocol, fd 3). This process only accepts on it, so its unit
can be `RestrictAddressFamilies=AF_UNIX` and `PrivateNetwork=yes`: it cannot
open a socket of any internet family, and it has no network of its own. An
inherited socket that is not a loopback IPv4 stream socket is refused.

Browser boundary
----------------
* Login: a one-use code (`azazel_nexus.ui_login`) that only the
  `azazel-operator` group can read; a session cookie (`HttpOnly`,
  `SameSite=Strict`, `Path=/`; no `Secure`, the first stage is loopback
  HTTP) held in memory only and short-lived. A restart ends every session.
* `Host` must be exactly `127.0.0.1:<port>` or `localhost:<port>` (DNS
  rebinding). A POST (login, logout) also needs `Origin` equal to
  `http://<Host>`, `Content-Type: application/json`, a body of at most
  `MAX_BODY` bytes and a CSRF token: the session's synchroniser token for
  logout, a signed double-submit token for login. A GET changes nothing.
* No query string is accepted anywhere, so no token can travel in a URL.
* Every response carries a strict CSP (no inline script or style),
  `nosniff`, `no-referrer`, `no-store` and `frame-ancestors 'none'`.
* Static files are four fixed names read once at start; a request path is
  looked up in a table and never joined to a filesystem path.
* JSON is escaped (`browser_json`) and the page writes with `textContent`
  only.

What the browser never receives: keys, credentials, the login code itself
(only the operator's terminal shows it), raw logs, journal lines, exception
text, interface names or addresses. The document is an allowlist
(`azazel_nexus.ui_model`) over an allowlist (`azazel_nexus.status_view`).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
import secrets
import socket
import socketserver
import stat
import sys
import threading
import time
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler
from importlib import resources
from pathlib import Path
from typing import Callable, Optional

from azazel_nexus.ui_login import (
    CODE_ALPHABET, CODE_LENGTH, CODE_TTL_S, SCHEMA as LOGIN_SCHEMA, login_code_path,
    normalize_code,
)
from azazel_nexus.ui_model import browser_json, project

__all__ = ["main"]

#: systemd's first passed descriptor (`SD_LISTEN_FDS_START`).
LISTEN_FD = 3

#: A fresh code is published when the current one is this old; each code
#: stays redeemable for `CODE_TTL_S` (60 s) from issue, so an operator who
#: read the newest code always has at least 30 seconds.
ROTATE_S = 30
#: Wrong codes evaluated in one `FAILURE_WINDOW_S` window, from anyone.
#: Beyond them every login attempt in that window is refused **without being
#: evaluated** (`login_throttled`), so guessing is bounded at 20 tries a
#: minute against a 49-bit code that lives 60 seconds. Nothing is withdrawn:
#: another local account that sends wrong codes can delay an operator's login
#: until the window ends, and cannot invalidate the code the operator holds.
MAX_FAILED_PER_WINDOW = 10
FAILURE_WINDOW_S = 30

SESSION_IDLE_S = 600
SESSION_MAX_S = 3600
MAX_SESSIONS = 8
LOGIN_TOKEN_TTL_S = 300

MAX_BODY = 1024
MAX_CONNECTIONS = 16
#: Per receive. A connection also has `REQUEST_DEADLINE_S` in total, from
#: accept to close, so a client that sends one byte at a time (slowloris)
#: frees its slot by then however slowly it sends.
REQUEST_TIMEOUT_S = 5
REQUEST_DEADLINE_S = 10.0
VIEW_CACHE_S = 2.0
FIXTURE_BYTES = 1 << 20

SESSION_COOKIE = "azui_session"
LOGIN_COOKIE = "azui_login"

SECURITY_HEADERS = (
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
     "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy",
     "camera=(), microphone=(), geolocation=(), usb=(), serial=(), bluetooth=(), "
     "payment=(), clipboard-read=(), clipboard-write=()"),
)

#: The only files served, by request path. Read once at start.
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/labels.json": ("labels.json", "application/json; charset=utf-8"),
}


def _now_iso(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z")


def _log(code: str) -> None:
    """One fixed word per event to the journal. Never a path, code or address."""
    print(f"az-ui: {code}", file=sys.stderr, flush=True)


# -- the inherited listener --------------------------------------------------


class ListenerRefused(Exception):
    """The service manager did not hand over exactly one loopback listener."""


def adopt_listener(environ, pid: int):
    """The one listening socket systemd passed (fd 3), checked; else refused.

    The `LISTEN_PID`/`LISTEN_FDS` pair is the socket-activation protocol, not
    configuration: it names a descriptor this process already holds and
    cannot widen what the unit allows. The socket must be a listening IPv4
    stream socket bound to 127.0.0.1. Its family is taken from the
    descriptor itself; nothing here can make an internet socket.
    """

    if environ.get("LISTEN_PID") != str(pid) or environ.get("LISTEN_FDS") != "1":
        raise ListenerRefused("no_inherited_listener")
    try:
        sock = socket.socket(fileno=LISTEN_FD)
    except OSError:
        raise ListenerRefused("inherited_descriptor_not_a_socket") from None
    try:
        address = sock.getsockname()
        listening = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        if (sock.type != socket.SOCK_STREAM or not isinstance(address, tuple)
                or len(address) != 2 or address[0] != "127.0.0.1" or not listening):
            raise ListenerRefused("listener_not_loopback_ipv4_stream")
    except BaseException:
        sock.detach()
        raise
    for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        environ.pop(name, None)
    return sock


class AdoptedServer(socketserver.ThreadingMixIn, socketserver.BaseServer):
    """`BaseServer` over an already-listening socket. It never binds or listens.

    `socketserver.TCPServer` would construct a socket itself; this server is
    given one, so the unit's `RestrictAddressFamilies=AF_UNIX` holds.
    """

    daemon_threads = True
    block_on_close = False

    def __init__(self, sock, handler, app: "UiApp"):
        super().__init__(sock.getsockname(), handler)
        self.socket = sock
        self.app = app
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def fileno(self):
        return self.socket.fileno()

    def get_request(self):
        return self.socket.accept()

    def verify_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            return False
        return True

    def process_request_thread(self, request, client_address):
        # The total deadline: shutting the socket down makes a blocked read
        # return at once, so the handler ends and the slot is released.
        deadline = threading.Timer(REQUEST_DEADLINE_S, self._cut, args=(request,))
        deadline.daemon = True
        deadline.start()
        try:
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            self._slots.release()

    @staticmethod
    def _cut(request) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def handle_error(self, request, client_address):
        """One fixed word: never a traceback or the client's address."""
        _log("request_error")

    def shutdown_request(self, request):
        try:
            request.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        request.close()

    def close_request(self, request):
        request.close()

    def server_close(self):
        self.socket.close()


# -- login codes, sessions, tokens ---------------------------------------------


class LoginCodes:
    """One-use login codes, published to the operator-readable file.

    Each code is redeemable for `CODE_TTL_S` from its issue, once. A new code
    is published every `ROTATE_S` and at once after a redemption. Wrong codes
    are bounded per window (`MAX_FAILED_PER_WINDOW`); past the bound attempts
    are refused unevaluated until the window ends, and no code is withdrawn.
    Only this process holds the codes; the file shows the newest one to the
    operator group and nobody else.
    """

    def __init__(self, publish: Callable[[dict], None], url: str):
        self._publish = publish
        self._url = url
        self._lock = threading.Lock()
        self._codes: dict[str, float] = {}
        self._newest_at: Optional[float] = None
        self._failures = 0
        self._window_start: Optional[float] = None

    def _issue(self, now: float) -> None:
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
        self._codes[code] = now + CODE_TTL_S
        self._newest_at = now
        try:
            self._publish({"schema": LOGIN_SCHEMA, "code": code, "issued_at": now,
                           "expires_at": now + CODE_TTL_S, "url": self._url})
        except OSError:
            _log("login_code_not_published")

    def tick(self, now: float) -> None:
        with self._lock:
            self._codes = {code: until for code, until in self._codes.items() if until > now}
            if self._newest_at is None or now - self._newest_at >= ROTATE_S or now < self._newest_at:
                self._issue(now)

    def redeem(self, typed, now: float) -> str:
        """`"accepted"`, `"refused"` or `"throttled"` (not evaluated)."""
        code = normalize_code(typed)
        with self._lock:
            if (self._window_start is None or now - self._window_start >= FAILURE_WINDOW_S
                    or now < self._window_start):
                self._window_start, self._failures = now, 0
            if self._failures >= MAX_FAILED_PER_WINDOW:
                return "throttled"
            match = None
            for candidate, until in list(self._codes.items()):
                if until <= now:
                    del self._codes[candidate]
                elif code is not None and hmac.compare_digest(candidate, code):
                    match = candidate
            if match is not None:
                del self._codes[match]
                self._issue(now)
                return "accepted"
            self._failures += 1
            if self._failures == MAX_FAILED_PER_WINDOW:
                _log("login_throttled")
            return "refused"


class Sessions:
    """In-memory sessions: id -> (csrf, created, last seen). Lost on restart."""

    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, list] = {}

    def create(self, now: float) -> tuple[str, str]:
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self._lock:
            self._expire(now)
            while len(self._sessions) >= MAX_SESSIONS:
                oldest = min(self._sessions, key=lambda key: self._sessions[key][1])
                del self._sessions[oldest]
            self._sessions[sid] = [csrf, now, now]
        return sid, csrf

    def _expire(self, now: float) -> None:
        for sid, (_, created, seen) in list(self._sessions.items()):
            if now - created > SESSION_MAX_S or now - seen > SESSION_IDLE_S or now < created:
                del self._sessions[sid]

    def get(self, sid: Optional[str], now: float) -> Optional[str]:
        """The session's CSRF token if `sid` is a live session (and touch it)."""
        if not sid:
            return None
        with self._lock:
            self._expire(now)
            entry = self._sessions.get(sid)
            if entry is None:
                return None
            entry[2] = now
            return entry[0]

    def delete(self, sid: Optional[str]) -> None:
        with self._lock:
            self._sessions.pop(sid or "", None)

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)


class LoginTokens:
    """Signed double-submit tokens for the login POST. No server state.

    `GET /api/session` returns one and sets it as a cookie; the login POST
    must carry the same value in `X-CSRF-Token` and in the cookie, and its
    signature (a per-process key) and age must hold.
    """

    def __init__(self):
        self._key = secrets.token_bytes(32)

    def _mac(self, body: str) -> str:
        return hmac.new(self._key, body.encode("ascii"), hashlib.sha256).hexdigest()

    def issue(self, now: float) -> str:
        body = f"{int(now)}.{secrets.token_urlsafe(16)}"
        return f"{body}.{self._mac(body)}"

    def check(self, token: Optional[str], now: float) -> bool:
        if not token or len(token) > 200 or token.count(".") != 2:
            return False
        issued, nonce, mac = token.split(".")
        if not (issued.isascii() and issued.isdigit()) or not hmac.compare_digest(mac, self._mac(f"{issued}.{nonce}")):
            return False
        return 0 <= now - int(issued) <= LOGIN_TOKEN_TTL_S


def publish_to(path: Path) -> Callable[[dict], None]:
    """Write the login code file atomically inside its own directory."""

    def publish(record: dict) -> None:
        data = json.dumps(record, sort_keys=True).encode("utf-8")
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    return publish


# -- what the page shows ---------------------------------------------------------


def _probe_access(path: Path) -> str:
    try:
        info = os.stat(path, follow_symlinks=False)
    except PermissionError:
        return "permission_denied"
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unreadable"
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        return "not_regular"
    return "readable" if os.access(path, os.R_OK) else "permission_denied"


def access_paths() -> dict[str, Path]:
    """The files `status` reads that this account may or may not open."""

    from azazel_nexus import runtime_paths
    from azazel_nexus.cli import KNOWLEDGE_LITE_ROOT
    from azazel_nexus.edge_package import PROBE_STATE_PATH
    from azazel_nexus.mio_status import ROUTE_SEGMENTS

    root = Path(os.environ.get("AZAZEL_ROOT", "/"))

    def rooted(path) -> Path:
        return root / str(path).lstrip("/")

    return {
        "edge_intake_status": runtime_paths.edge_intake_status_path(),
        "incident_explain_status": runtime_paths.incident_explain_status_path(),
        "incident_recent": runtime_paths.incident_recent_path(),
        "audit_status": runtime_paths.audit_status_path(),
        "edge_probe": rooted(PROBE_STATE_PATH),
        "knowledge_lite": rooted(KNOWLEDGE_LITE_ROOT),
        "mio_route_ledger": rooted(ROUTE_SEGMENTS),
    }


class LiveSource:
    """The read model, read in this process exactly as `status --json` reads it."""

    kind = "live"

    def __init__(self, cli_main=None):
        if cli_main is None:
            from azazel_nexus.cli import main as cli_main
        self._main = cli_main

    def _run(self, argv) -> Optional[dict]:
        out, err = io.StringIO(), io.StringIO()
        try:
            if self._main(argv, out=out, err=err) != 0:
                return None
            return json.loads(out.getvalue())
        except (Exception, SystemExit):  # noqa: BLE001 - shown as a fixed code
            return None

    def read(self) -> dict:
        view = self._run(["status", "--json"])
        setup = self._run(["setup", "--json"])
        return {
            "view": view,
            "read_reason": None if view is not None else "status_read_failed",
            "setup": setup,
            "setup_reason": None if setup is not None else "setup_read_failed",
            "access": {name: _probe_access(path) for name, path in access_paths().items()},
            "origin": {"kind": "live", "reader": "azazel-nexus status --json",
                       "account": "azui"},
        }


class FixtureSource:
    """A saved read model, for a demonstration. Every screen says so."""

    kind = "fixture"

    def __init__(self, path: Path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("fixture is not a regular file")
            raw = stream.read(FIXTURE_BYTES + 1)
        if len(raw) > FIXTURE_BYTES:
            raise ValueError("fixture oversized")
        value = json.loads(raw.decode("utf-8"))
        from azazel_nexus.status_view import SCHEMA

        if not isinstance(value, dict) or value.get("schema") != SCHEMA:
            raise ValueError("fixture is not a status read model")
        self._view = value

    def read(self) -> dict:
        return {"view": self._view, "read_reason": None, "setup": None,
                "setup_reason": "not_in_fixture", "access": {},
                "origin": {"kind": "fixture",
                           "notice": "fixture: a saved read model, not this node's state"}}


class UiApp:
    """Everything a request may touch: sessions, codes, tokens, the view."""

    def __init__(self, *, source, codes: LoginCodes, port: int,
                 clock: Callable[[], float] = time.time):
        self.source = source
        self.codes = codes
        self.sessions = Sessions()
        self.tokens = LoginTokens()
        self.clock = clock
        self.hosts = frozenset({f"127.0.0.1:{port}", f"localhost:{port}"})
        self.static = {
            route: (resources.files(__package__).joinpath("ui_static", name).read_bytes(), kind)
            for route, (name, kind) in STATIC_FILES.items()}
        self._view_lock = threading.Lock()
        self._view_cache: Optional[tuple[float, bytes]] = None

    def view_document(self) -> bytes:
        now = self.clock()
        with self._view_lock:
            if self._view_cache and 0 <= now - self._view_cache[0] < VIEW_CACHE_S:
                return self._view_cache[1]
            try:
                read = self.source.read()
                document = browser_json(project(
                    read["view"], origin=read["origin"], served_at=_now_iso(now),
                    setup=read["setup"], setup_reason=read["setup_reason"],
                    access=read["access"], read_reason=read["read_reason"]))
            except Exception:  # noqa: BLE001 - shown as a fixed code
                document = browser_json(project(
                    None, origin={"kind": self.source.kind}, served_at=_now_iso(now),
                    read_reason="internal_error"))
            self._view_cache = (now, document)
            return document


# -- HTTP --------------------------------------------------------------------------


class Refused(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status, self.code = status, code


class UiHandler(BaseHTTPRequestHandler):
    server_version = "azazel-ui"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = REQUEST_TIMEOUT_S

    @property
    def app(self) -> UiApp:
        return self.server.app

    # Every response, success or refusal, goes through here.
    def _send(self, status: int, body: bytes, content_type: str,
              set_cookies: tuple[str, ...] = ()) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)
        for cookie in set_cookies:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value, set_cookies=()) -> None:
        self._send(status, browser_json(value), "application/json; charset=utf-8", set_cookies)

    def _refuse(self, refused: Refused) -> None:
        self._json(refused.status, {"error": refused.code})

    def send_error(self, code, message=None, explain=None):  # noqa: D401 - stdlib hook
        """The stdlib's malformed-request path: same headers, a fixed code."""
        self.close_connection = True
        try:
            self._json(code, {"error": "malformed_request"})
        except OSError:
            pass

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        return  # request lines and client ports are not journalled

    def version_string(self):
        return self.server_version

    # -- checks ------------------------------------------------------------------

    def _host(self) -> str:
        hosts = self.headers.get_all("Host") or []
        if len(hosts) != 1 or hosts[0] not in self.app.hosts:
            raise Refused(421, "host_refused")
        return hosts[0]

    def _route(self) -> str:
        if "?" in self.path or "#" in self.path or not self.path.startswith("/"):
            raise Refused(400, "query_or_fragment_refused")
        return self.path

    def _cookie(self, name: str) -> Optional[str]:
        values = self.headers.get_all("Cookie") or []
        jar = cookies.SimpleCookie()
        try:
            for value in values:
                jar.load(value)
        except cookies.CookieError:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel is not None else None

    def _post_body(self, host: str) -> dict:
        origins = self.headers.get_all("Origin") or []
        if len(origins) != 1 or origins[0] != f"http://{host}":
            raise Refused(403, "origin_refused")
        site = self.headers.get("Sec-Fetch-Site")
        if site is not None and site != "same-origin":
            raise Refused(403, "cross_site_refused")
        if (self.headers.get("Content-Type") or "").split(";")[0].strip() != "application/json":
            raise Refused(415, "json_required")
        if self.headers.get("Transfer-Encoding") is not None:
            raise Refused(411, "length_required")
        length = self.headers.get("Content-Length")
        if length is None or not (length.isascii() and length.isdigit()) or len(length) > 6:
            raise Refused(411, "length_required")
        if int(length) > MAX_BODY:
            raise Refused(413, "body_too_large")
        try:
            raw = self.rfile.read(int(length))
        except (OSError, ValueError):
            self.close_connection = True
            raise Refused(400, "body_unreadable") from None
        if len(raw) != int(length):
            self.close_connection = True
            raise Refused(400, "body_unreadable")
        try:
            value = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise Refused(400, "json_refused") from None
        if not isinstance(value, dict):
            raise Refused(400, "json_refused")
        return value

    def _session_cookie(self, sid: str) -> str:
        return (f"{SESSION_COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; "
                f"Max-Age={SESSION_MAX_S}")

    @staticmethod
    def _clear(name: str) -> str:
        return f"{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

    # -- methods ---------------------------------------------------------------------

    def do_GET(self):  # noqa: N802 - stdlib name
        try:
            self._host()
            route = self._route()
            now = self.app.clock()
            if route in self.app.static:
                body, kind = self.app.static[route]
                self._send(200, body, kind)
            elif route == "/api/session":
                csrf = self.app.sessions.get(self._cookie(SESSION_COOKIE), now)
                if csrf is not None:
                    self._json(200, {"authenticated": True, "csrf": csrf})
                else:
                    token = self.app.tokens.issue(now)
                    self._json(200, {"authenticated": False, "login_token": token},
                               set_cookies=(f"{LOGIN_COOKIE}={token}; Path=/; HttpOnly; "
                                            f"SameSite=Strict; Max-Age={LOGIN_TOKEN_TTL_S}",))
            elif route == "/api/view":
                if self.app.sessions.get(self._cookie(SESSION_COOKIE), now) is None:
                    raise Refused(401, "login_required")
                self._send(200, self.app.view_document(), "application/json; charset=utf-8")
            else:
                raise Refused(404, "not_found")
        except Refused as refused:
            self._refuse(refused)

    def do_POST(self):  # noqa: N802 - stdlib name
        try:
            host = self._host()
            route = self._route()
            if route not in ("/api/login", "/api/logout"):
                raise Refused(404, "not_found")
            body = self._post_body(host)
            now = self.app.clock()
            header = self.headers.get("X-CSRF-Token")
            if route == "/api/login":
                cookie = self._cookie(LOGIN_COOKIE)
                if (header is None or cookie is None or not hmac.compare_digest(header, cookie)
                        or not self.app.tokens.check(cookie, now)):
                    raise Refused(403, "csrf_refused")
                outcome = self.app.codes.redeem(body.get("code"), now)
                if outcome == "throttled":
                    raise Refused(429, "login_throttled")
                if outcome != "accepted":
                    raise Refused(403, "login_refused")
                sid, csrf = self.app.sessions.create(now)
                _log("login")
                self._json(200, {"authenticated": True, "csrf": csrf},
                           set_cookies=(self._session_cookie(sid), self._clear(LOGIN_COOKIE)))
            else:
                sid = self._cookie(SESSION_COOKIE)
                csrf = self.app.sessions.get(sid, now)
                if csrf is None:
                    raise Refused(401, "login_required")
                if header is None or not hmac.compare_digest(header, csrf):
                    raise Refused(403, "csrf_refused")
                self.app.sessions.delete(sid)
                _log("logout")
                self._json(200, {"authenticated": False},
                           set_cookies=(self._clear(SESSION_COOKIE),))
        except Refused as refused:
            self._refuse(refused)

    def _method_refused(self):
        self.close_connection = True
        self._json(405, {"error": "method_refused"})

    do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _method_refused


# -- the process ---------------------------------------------------------------------


def _rotate(app: UiApp, stop: threading.Event) -> None:
    while not stop.wait(1.0):
        app.codes.tick(app.clock())


def build_app(sock, *, fixture: Optional[Path], login_file: Path,
              clock: Callable[[], float] = time.time) -> UiApp:
    port = sock.getsockname()[1]
    source = FixtureSource(fixture) if fixture is not None else LiveSource()
    codes = LoginCodes(publish_to(login_file), f"http://127.0.0.1:{port}/")
    return UiApp(source=source, codes=codes, port=port, clock=clock)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="az-ui",
        description="Read-only operator UI on the loopback socket systemd passes "
                    "(azazel-ui.socket). Performs no action.")
    parser.add_argument("--fixture", type=Path, default=None,
                        help="show a saved status read model instead of this node "
                             "(demonstration; every screen says so)")
    parser.add_argument("--login-file", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        sock = adopt_listener(os.environ, os.getpid())
    except ListenerRefused as refused:
        _log(f"refused: {refused}")
        return 2
    try:
        app = build_app(sock, fixture=args.fixture,
                        login_file=args.login_file or login_code_path())
    except (OSError, ValueError):
        _log("refused: source_or_assets_unreadable")
        sock.close()
        return 2
    app.codes.tick(app.clock())
    stop = threading.Event()
    threading.Thread(target=_rotate, args=(app, stop), daemon=True).start()
    server = AdoptedServer(sock, UiHandler, app)
    _log("serving" if args.fixture is None else "serving_fixture")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
