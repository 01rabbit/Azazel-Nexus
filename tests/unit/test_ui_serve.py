"""The read-only operator UI (U5): server, browser boundary, units and process.

Three kinds of evidence, kept apart in the names:

* in-process: the real `UiApp`/`UiHandler`/`AdoptedServer` on a loopback
  socket this test binds, driven with `http.client` (headers, Host, Origin,
  CSRF, sessions, login codes, static files, XSS);
* real process: `az-ui` started as `azazel-ui.socket` would start it, with
  the listening socket at fd 3 (`tools/ui_socket_activate.py`), driven with
  `http.client`; and the refusals of a wrong inherited descriptor;
* declaration: the unit files, the preset and the installer.

What none of this shows: what systemd enforces (`PrivateNetwork=`,
`RestrictAddressFamilies=`, the socket's IP filter) or how a browser
renders the page. Those are a systemd host's and a browser's to show (U6).
"""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from azazel_nexus import ui_login, ui_model
from azazel_nexus_runtime import ui_serve

REPO = Path(__file__).resolve().parents[2]
STATIC = REPO / "runtime" / "src" / "azazel_nexus_runtime" / "ui_static"
DEMO = REPO / "tests" / "fixtures" / "ui" / "demo-status-view.json"
UNIT_DIR = REPO / "packaging" / "systemd"
ACTIVATE = REPO / "tools" / "ui_socket_activate.py"

REQUIRED_HEADERS = {
    "content-security-policy": ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                "img-src 'self'; connect-src 'self'; base-uri 'none'; "
                                "form-action 'self'; frame-ancestors 'none'"),
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Response:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def header(self, name):
        values = [v for k, v in self.headers if k.lower() == name.lower()]
        return values[0] if values else None

    def cookies(self):
        return [v for k, v in self.headers if k.lower() == "set-cookie"]

    def json(self):
        return json.loads(self.body)


def _request(port, method, path, *, body=None, headers=(), host="default"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        if host == "default":
            connection.putheader("Host", f"127.0.0.1:{port}")
        elif host is not None:
            for value in (host if isinstance(host, tuple) else (host,)):
                connection.putheader("Host", value)
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            connection.putheader("Content-Length", str(len(data)))
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(data)
        response = connection.getresponse()
        return Response(response.status, response.getheaders(), response.read())
    finally:
        connection.close()


def _cookie_value(set_cookie, name):
    match = re.match(rf"{name}=([^;]*)", set_cookie)
    return match.group(1) if match else None


class Harness:
    """The real app, handler and server on a socket this test bound."""

    def __init__(self, tmp_path, source=None):
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.login_file = tmp_path / "login-code.json"
        self.clock = Clock()
        codes = ui_serve.LoginCodes(ui_serve.publish_to(self.login_file),
                                    f"http://127.0.0.1:{self.port}/")
        self.app = ui_serve.UiApp(source=source or ui_serve.FixtureSource(DEMO), codes=codes,
                                  port=self.port, clock=self.clock)
        self.app.codes.tick(self.clock())
        self.server = ui_serve.AdoptedServer(self.listener, ui_serve.UiHandler, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.port}"

    def request(self, method, path, **kwargs):
        return _request(self.port, method, path, **kwargs)

    def code(self):
        return ui_login.read_login_code(self.login_file.read_bytes())["code"]

    def login_token(self):
        response = self.request("GET", "/api/session")
        token = response.json()["login_token"]
        assert _cookie_value(response.cookies()[0], "azui_login") == token
        return token

    def post(self, path, body, *, token, cookie, origin="default", content_type="application/json",
             extra=()):
        headers = [("Content-Type", content_type), *extra]
        if origin == "default":
            headers.append(("Origin", self.origin))
        elif origin is not None:
            headers.append(("Origin", origin))
        if token is not None:
            headers.append(("X-CSRF-Token", token))
        if cookie is not None:
            headers.append(("Cookie", cookie))
        return self.request("POST", path, body=body, headers=headers)

    def login(self):
        self.app.codes.tick(self.clock())  # what the rotation thread does each second
        token = self.login_token()
        response = self.post("/api/login", {"code": self.code()}, token=token,
                             cookie=f"azui_login={token}")
        assert response.status == 200, response.body
        sid = _cookie_value(response.cookies()[0], "azui_session")
        return sid, response.json()["csrf"]

    def view(self, sid):
        return self.request("GET", "/api/view", headers=[("Cookie", f"azui_session={sid}")])

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def ui(tmp_path):
    harness = Harness(tmp_path)
    yield harness
    harness.close()


def _assert_security_headers(response):
    for name, value in REQUIRED_HEADERS.items():
        assert response.header(name) == value, (name, response.headers)
    assert "camera=()" in response.header("permissions-policy")
    assert response.header("server") == "azazel-ui"


# -- headers on every kind of response (in-process) ----------------------------


def test_every_response_kind_carries_the_security_headers(ui):
    sid, _ = ui.login()
    responses = [
        ui.request("GET", "/"), ui.request("GET", "/static/app.js"),
        ui.request("GET", "/static/app.css"), ui.request("GET", "/static/labels.json"),
        ui.request("GET", "/api/session"), ui.view(sid), ui.request("GET", "/api/view"),
        ui.request("GET", "/nothing"), ui.request("PUT", "/api/view"),
        ui.request("DELETE", "/"), ui.request("OPTIONS", "/api/login"),
        ui.request("GET", "/", host="evil.example"), ui.request("GET", "/?x=1"),
    ]
    for response in responses:
        _assert_security_headers(response)
    # The stdlib's own malformed-request path goes through the same sender.
    raw = socket.create_connection(("127.0.0.1", ui.port), timeout=5)
    raw.sendall(b"BREW / HTTP/1.1\r\nHost: x\r\n\r\n")
    answer = raw.recv(65536).decode("latin-1")
    raw.close()
    assert "Content-Security-Policy: default-src 'none'" in answer
    assert "nosniff" in answer and '"malformed_request"' in answer


def test_static_types_and_no_inline_resources(ui):
    index = ui.request("GET", "/")
    assert index.status == 200 and index.header("content-type") == "text/html; charset=utf-8"
    assert ui.request("GET", "/static/app.js").header("content-type").startswith("text/javascript")
    assert ui.request("GET", "/static/app.css").header("content-type").startswith("text/css")
    assert ui.request("GET", "/static/labels.json").header(
        "content-type").startswith("application/json")


# -- Host, query, method -----------------------------------------------------------


@pytest.mark.parametrize("host", [
    None, "evil.example", "127.0.0.1", "localhost", "127.0.0.1:1", "[::1]:8443",
    "127.0.0.1.nip.io", ("127.0.0.1:PORT", "evil.example"), ("127.0.0.1:PORT", "127.0.0.1:PORT"),
])
def test_a_host_other_than_this_loopback_listener_is_refused(ui, host):
    if isinstance(host, tuple):
        host = tuple(h.replace("PORT", str(ui.port)) for h in host)
    for path in ("/", "/api/session", "/static/app.js"):
        response = ui.request("GET", path, host=host)
        assert response.status == 421, (host, path)
        assert response.json() == {"error": "host_refused"}


def test_localhost_with_the_port_is_accepted(ui):
    assert ui.request("GET", "/", host=f"localhost:{ui.port}").status == 200


@pytest.mark.parametrize("path", ["/?token=x", "/api/view?code=ABCDE", "/static/app.js?v=1",
                                  "/#x", "*"])
def test_no_query_string_or_fragment_is_accepted(ui, path):
    """A token or a code can never travel in a URL: no URL may carry one."""
    response = ui.request("GET", path)
    assert response.status == 400
    assert response.json() == {"error": "query_or_fragment_refused"}


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"])
def test_methods_other_than_get_and_post_are_refused(ui, method):
    assert ui.request(method, "/api/view").status == 405


# -- static files: a table, never a path -------------------------------------------


@pytest.mark.parametrize("path", [
    "/static/../ui_serve.py", "/static/%2e%2e/ui_serve.py", "/static/..%2fui_serve.py",
    "/static/", "/static", "/static/app.js/", "/STATIC/app.js",
    "/static/./app.js", "/static/ui_static/app.js", "/ui_serve.py", "/etc/passwd",
    "/static/../../../../etc/passwd", "/static/app.js%00.css", "/index.html/",
    "/static/labels.json.bak", "/api/login", "/api", "/api/",
])
def test_only_the_named_static_files_and_routes_exist(ui, path):
    response = ui.request("GET", path)
    assert response.status == 404, path
    assert response.json() == {"error": "not_found"}


def test_a_doubled_leading_slash_is_the_stdlib_s_and_still_a_table_lookup(ui):
    """`http.server` turns a leading `//` into `/` (gh-87389) before routing."""
    response = ui.request("GET", "//static/app.js")
    assert response.status in (200, 404)
    if response.status == 200:
        assert response.body == (STATIC / "app.js").read_bytes()
    assert ui.request("GET", "//etc/passwd").status == 404


def test_static_files_are_the_packaged_bytes(ui):
    for route, (name, _) in ui_serve.STATIC_FILES.items():
        assert ui.request("GET", route).body == (STATIC / name).read_bytes()
    assert sorted(path.name for path in STATIC.iterdir()) == sorted(
        {name for name, _ in ui_serve.STATIC_FILES.values()})


# -- login, CSRF, Origin -------------------------------------------------------------


def test_the_view_needs_a_session_and_login_issues_a_strict_cookie(ui):
    assert ui.request("GET", "/api/view").status == 401
    token = ui.login_token()
    response = ui.post("/api/login", {"code": ui.code()}, token=token,
                       cookie=f"azui_login={token}")
    assert response.status == 200
    session = next(c for c in response.cookies() if c.startswith("azui_session="))
    attributes = {part.strip().split("=")[0] for part in session.split(";")[1:]}
    assert {"Path", "HttpOnly", "SameSite", "Max-Age"} <= attributes
    assert "SameSite=Strict" in session and "Secure" not in attributes  # loopback HTTP
    assert any(c.startswith("azui_login=;") and "Max-Age=0" in c for c in response.cookies())
    sid = _cookie_value(session, "azui_session")
    view = ui.view(sid)
    assert view.status == 200
    assert view.json()["schema"] == ui_model.SCHEMA
    assert response.json()["csrf"] != sid


def test_a_login_cookie_and_token_must_match_and_be_signed_and_young(ui):
    token = ui.login_token()
    code = ui.code()
    other = ui.login_token()
    cases = [
        dict(token=None, cookie=f"azui_login={token}"),
        dict(token=token, cookie=None),
        dict(token=other, cookie=f"azui_login={token}"),
        dict(token=token[:-1] + ("0" if token[-1] != "0" else "1"),
             cookie=f"azui_login={token[:-1] + ('0' if token[-1] != '0' else '1')}"),
        dict(token="1.2.3", cookie="azui_login=1.2.3"),
    ]
    for case in cases:
        response = ui.post("/api/login", {"code": code}, **case)
        assert response.status == 403 and response.json() == {"error": "csrf_refused"}, case
    ui.clock.advance(ui_serve.LOGIN_TOKEN_TTL_S + 1)
    ui.app.codes.tick(ui.clock())
    response = ui.post("/api/login", {"code": ui.code()}, token=token, cookie=f"azui_login={token}")
    assert response.json() == {"error": "csrf_refused"}


@pytest.mark.parametrize("origin", [None, "null", "http://evil.example", "http://127.0.0.1",
                                    "https://127.0.0.1:PORT", "http://localhost:PORT",
                                    "http://127.0.0.1:PORT/"])
def test_a_post_needs_the_exact_origin_of_its_host(ui, origin):
    token = ui.login_token()
    if origin is not None:
        origin = origin.replace("PORT", str(ui.port))
    response = ui.post("/api/login", {"code": ui.code()}, token=token,
                       cookie=f"azui_login={token}", origin=origin)
    assert response.status == 403 and response.json() == {"error": "origin_refused"}


def test_a_post_needs_json_a_length_and_a_small_body_and_same_site(ui):
    token = ui.login_token()
    cookie = f"azui_login={token}"
    for content_type in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        response = ui.post("/api/login", {"code": ui.code()}, token=token, cookie=cookie,
                           content_type=content_type)
        assert response.status == 415, content_type
    big = {"code": "A" * (ui_serve.MAX_BODY + 10)}
    assert ui.post("/api/login", big, token=token, cookie=cookie).status == 413
    assert ui.post("/api/login", b"[1]", token=token, cookie=cookie).status == 400
    assert ui.post("/api/login", b"{", token=token, cookie=cookie).status == 400
    response = ui.post("/api/login", {"code": ui.code()}, token=token, cookie=cookie,
                       extra=[("Sec-Fetch-Site", "cross-site")])
    assert response.status == 403 and response.json() == {"error": "cross_site_refused"}
    # A login that fails these is not counted against the code: it still works.
    assert ui.post("/api/login", {"code": ui.code()}, token=token, cookie=cookie).status == 200


def test_logout_needs_the_session_csrf_token_and_ends_the_session(ui):
    sid, csrf = ui.login()
    cookie = f"azui_session={sid}"
    for token in (None, "", "x" * 43, ui.login_token()):
        response = ui.post("/api/logout", {}, token=token, cookie=cookie)
        assert response.status == 403, token
    assert ui.view(sid).status == 200
    assert ui.post("/api/logout", {}, token=csrf, cookie=cookie, origin="http://evil.example"
                   ).status == 403
    response = ui.post("/api/logout", {}, token=csrf, cookie=cookie)
    assert response.status == 200
    assert any(c.startswith("azui_session=;") and "Max-Age=0" in c for c in response.cookies())
    assert ui.view(sid).status == 401
    assert ui.post("/api/logout", {}, token=csrf, cookie=cookie).status == 401


def test_get_changes_nothing(ui):
    sid, _ = ui.login()
    before = (ui.app.sessions.count(), dict(ui.app.codes._codes), ui.login_file.read_bytes())
    for path in ("/", "/api/session", "/api/view", "/static/app.js", "/api/login", "/api/logout"):
        ui.request("GET", path, headers=[("Cookie", f"azui_session={sid}")])
        ui.request("GET", path)
    assert (ui.app.sessions.count(), dict(ui.app.codes._codes),
            ui.login_file.read_bytes()) == before
    assert ui.request("GET", "/api/logout").status == 404
    assert ui.view(sid).status == 200


# -- login codes -------------------------------------------------------------------------


def test_a_code_is_one_use(ui):
    first = ui.code()
    ui.login()
    assert ui.code() != first, "a redeemed code is replaced at once"
    token = ui.login_token()
    response = ui.post("/api/login", {"code": first}, token=token, cookie=f"azui_login={token}")
    assert response.status == 403 and response.json() == {"error": "login_refused"}


def test_a_code_expires_after_its_lifetime_and_rotation_keeps_one_valid(ui):
    code = ui.code()
    record = ui_login.read_login_code(ui.login_file.read_bytes())
    assert record["expires_at"] - record["issued_at"] == ui_login.CODE_TTL_S
    ui.clock.advance(ui_serve.ROTATE_S)
    ui.app.codes.tick(ui.clock())
    newer = ui.code()
    assert newer != code
    ui.clock.advance(ui_login.CODE_TTL_S - ui_serve.ROTATE_S)  # the first is 60 s old
    token = ui.login_token()
    assert ui.post("/api/login", {"code": code}, token=token, cookie=f"azui_login={token}"
                   ).json() == {"error": "login_refused"}
    token = ui.login_token()
    assert ui.post("/api/login", {"code": newer}, token=token, cookie=f"azui_login={token}"
                   ).status == 200


def test_wrong_codes_throttle_logins_and_withdraw_nothing(ui):
    """Guessing is bounded; another local account can delay, not invalidate.

    After `MAX_FAILED_PER_WINDOW` wrong codes every attempt in the window is
    refused unevaluated (`429 login_throttled`), the correct code included.
    When the window ends, the operator's code -- still within its 60 s --
    works: nothing was withdrawn.
    """
    code = ui.code()
    token = ui.login_token()
    cookie = f"azui_login={token}"
    for _ in range(ui_serve.MAX_FAILED_PER_WINDOW):
        assert ui.post("/api/login", {"code": "ZZZZZ-ZZZZZ"}, token=token, cookie=cookie
                       ).status == 403
    throttled = ui.post("/api/login", {"code": code}, token=token, cookie=cookie)
    assert throttled.status == 429 and throttled.json() == {"error": "login_throttled"}
    assert code in ui.app.codes._codes, "a throttled window withdraws no code"
    ui.clock.advance(ui_serve.FAILURE_WINDOW_S)
    assert ui_serve.FAILURE_WINDOW_S < ui_login.CODE_TTL_S
    assert ui.post("/api/login", {"code": code}, token=token, cookie=cookie).status == 200


def test_throttled_attempts_are_not_evaluated_or_counted(ui):
    codes = ui.app.codes
    for _ in range(ui_serve.MAX_FAILED_PER_WINDOW):
        assert codes.redeem("ZZZZZZZZZZ", ui.clock()) == "refused"
    for _ in range(50):
        assert codes.redeem(ui.code(), ui.clock()) == "throttled"
    assert codes._failures == ui_serve.MAX_FAILED_PER_WINDOW
    ui.clock.advance(ui_serve.FAILURE_WINDOW_S)
    assert codes.redeem(ui.code(), ui.clock()) == "accepted"


def test_the_guessing_bound_per_code_lifetime_is_small():
    evaluated = ui_serve.MAX_FAILED_PER_WINDOW * (ui_login.CODE_TTL_S // ui_serve.FAILURE_WINDOW_S
                                                  + 1)
    assert evaluated / len(ui_login.CODE_ALPHABET) ** ui_login.CODE_LENGTH < 1e-12


@pytest.mark.parametrize("typed", [None, 123, ["A"], "", "abcde", "ABCDE-FGHJ", "ABCDE-FGHJKL",
                                   "0O1IL-UUUUU"])
def test_what_is_not_a_code_is_never_a_match(ui, typed):
    token = ui.login_token()
    response = ui.post("/api/login", {"code": typed}, token=token, cookie=f"azui_login={token}")
    assert response.status == 403


def test_a_typed_code_may_carry_spaces_hyphens_and_lower_case(ui):
    code = ui.code().lower()
    token = ui.login_token()
    typed = f" {code[:5]} - {code[5:]} "
    assert ui.post("/api/login", {"code": typed}, token=token, cookie=f"azui_login={token}"
                   ).status == 200


def test_the_code_file_is_group_readable_only_and_not_a_symlink_target(tmp_path):
    path = tmp_path / "login-code.json"
    ui_serve.publish_to(path)({"schema": ui_login.SCHEMA, "code": "ABCDEFGHJK",
                               "issued_at": 1.0, "expires_at": 61.0,
                               "url": "http://127.0.0.1:8443/"})
    assert (path.stat().st_mode & 0o777) & ~0o640 == 0
    assert [p.name for p in tmp_path.iterdir()] == ["login-code.json"]


# -- malformed bodies and slow clients ----------------------------------------------------


def _raw(port, data, *, close_write=False, timeout=5):
    connection = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        connection.sendall(data)
        if close_write:
            connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            try:
                chunk = connection.recv(65536)
            except (TimeoutError, ConnectionResetError):
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        connection.close()


def _login_request(ui, length, body=b"", token="t"):
    head = (f"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:{ui.port}\r\n"
            f"Origin: {ui.origin}\r\nContent-Type: application/json\r\n"
            f"X-CSRF-Token: {token}\r\nCookie: azui_login={token}\r\n"
            f"Content-Length: {length}\r\n\r\n")
    try:
        encoded = head.encode("latin-1")  # how the stdlib decodes header bytes
    except UnicodeEncodeError:
        encoded = head.encode("utf-8")
    return encoded + body


@pytest.mark.parametrize("length", ["\u00b2", "\uff11\uff12", "\u0663", "-1", "+5", "1e3",
                                    " 5", "5 ", "0x10", "99999999999"])
def test_a_content_length_that_is_not_ascii_digits_is_refused_quietly(ui, length, capsys):
    answer = _raw(ui.port, _login_request(ui, length, b'{"code": "x"}'), close_write=True)
    status = int(answer.split(b" ", 2)[1])
    assert status in (400, 411, 413), answer[:80]
    assert b"Content-Security-Policy" in answer
    err = capsys.readouterr().err
    assert "Traceback" not in err and "127.0.0.1" not in err


def test_a_body_shorter_than_its_length_is_refused_quietly(ui, capsys):
    answer = _raw(ui.port, _login_request(ui, 200, b'{"code"'), close_write=True)
    assert b" 400 " in answer.split(b"\r\n", 1)[0]
    assert b'"body_unreadable"' in answer
    err = capsys.readouterr().err
    assert "Traceback" not in err and "127.0.0.1" not in err


def test_a_body_that_stops_arriving_is_refused_quietly(tmp_path, monkeypatch, capsys):
    """A read that times out mid-body is a 400, not an unhandled error."""
    monkeypatch.setattr(ui_serve.UiHandler, "timeout", 0.3)
    harness = Harness(tmp_path)
    try:
        answer = _raw(harness.port, _login_request(harness, 200, b'{"code"'))
    finally:
        harness.close()
    assert b" 400 " in answer.split(b"\r\n", 1)[0]
    assert b'"body_unreadable"' in answer
    err = capsys.readouterr().err
    assert "Traceback" not in err and "request_error" not in err


def test_a_handler_error_is_one_fixed_word_without_traceback_or_address(ui, capsys):
    ui.server.handle_error(None, ("127.0.0.1", 40000))
    err = capsys.readouterr().err
    assert err == "az-ui: request_error\n"


def test_slow_clients_are_cut_at_the_total_deadline_and_free_their_slots(tmp_path, monkeypatch):
    """Slowloris: one byte at a time, never idle long enough for the per-read
    timeout. Every slot is freed at the total deadline and a real request is
    then served."""
    monkeypatch.setattr(ui_serve, "REQUEST_DEADLINE_S", 1.0)
    harness = Harness(tmp_path)
    stop = threading.Event()
    slow = []
    try:
        for _ in range(ui_serve.MAX_CONNECTIONS):
            connection = socket.create_connection(("127.0.0.1", harness.port), timeout=5)
            connection.sendall(b"GET / HTTP/1.1\r\n")
            slow.append(connection)
        closed = []

        def trickle(connection):
            started = time.monotonic()
            try:
                while not stop.is_set() and time.monotonic() - started < 6:
                    connection.sendall(b"X")
                    time.sleep(0.2)
            except OSError:
                closed.append(time.monotonic() - started)
        threads = [threading.Thread(target=trickle, args=(c,), daemon=True) for c in slow]
        for thread in threads:
            thread.start()
        time.sleep(0.3)
        # Every slot is held: a new connection is closed without an answer.
        assert _raw(harness.port, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{harness.port}\r\n\r\n"
                    .encode()) == b""
        time.sleep(1.5)  # past the deadline
        response = harness.request("GET", "/")
        assert response.status == 200
        for thread in threads:
            thread.join(timeout=10)
        assert len(closed) == ui_serve.MAX_CONNECTIONS
        assert max(closed) < 4, closed
    finally:
        stop.set()
        for connection in slow:
            connection.close()
        harness.close()


# -- sessions --------------------------------------------------------------------------------


def test_a_session_expires_when_idle_and_at_its_maximum_age(ui):
    sid, _ = ui.login()
    ui.clock.advance(ui_serve.SESSION_IDLE_S + 1)
    assert ui.view(sid).status == 401
    sid, _ = ui.login()
    start = ui.clock()
    for _ in range(ui_serve.SESSION_MAX_S // (ui_serve.SESSION_IDLE_S - 1) + 1):
        ui.clock.advance(ui_serve.SESSION_IDLE_S - 1)
        status = ui.view(sid).status
        if ui.clock() - start > ui_serve.SESSION_MAX_S:
            assert status == 401
            break
        assert status == 200
    else:
        pytest.fail("the session outlived its maximum age")


def test_a_clock_step_backwards_ends_a_session(ui):
    sid, _ = ui.login()
    ui.clock.advance(-10)
    assert ui.view(sid).status == 401


def test_a_restart_ends_every_session(ui, tmp_path):
    sid, _ = ui.login()
    other = Harness(tmp_path / "second")
    try:
        assert other.view(sid).status == 401
    finally:
        other.close()


def test_sessions_are_bounded(ui):
    sids = [ui.login()[0] for _ in range(ui_serve.MAX_SESSIONS + 2)]
    assert ui.app.sessions.count() == ui_serve.MAX_SESSIONS
    assert ui.view(sids[0]).status == 401
    assert ui.view(sids[-1]).status == 200


# -- the document: allowlist, escaping, XSS ----------------------------------------------------


def _hostile_fixture(tmp_path):
    view = json.loads(DEMO.read_text(encoding="utf-8"))
    incidents = view["sections"]["edge_loop"]["recent"]["snapshot"]["incidents"]
    explanation = incidents[0]["explanation"]
    explanation["summary"] = "<script>alert('summary')</script> </p><img src=x onerror=alert(1)>"
    explanation["knowledge_refs"][0]["name"] = "<img src=x onerror=alert('name')>&amp;"
    incidents[0]["policy_reason"] = "</script><script>alert(2)</script>"
    view["sections"]["next_actions"][0]["summary"] = "<a href=javascript:alert(3)>x</a>"
    path = tmp_path / "hostile.json"
    path.write_text(json.dumps(view), encoding="utf-8")
    return path, view


def test_hostile_text_reaches_the_page_only_as_escaped_json(tmp_path):
    path, view = _hostile_fixture(tmp_path)
    harness = Harness(tmp_path / "h", source=ui_serve.FixtureSource(path))
    try:
        sid, _ = harness.login()
        response = harness.view(sid)
    finally:
        harness.close()
    assert response.status == 200
    assert response.header("content-type") == "application/json; charset=utf-8"
    for raw in (b"<", b">", b"&", " ".encode()):
        assert raw not in response.body
    model = response.json()
    rows = model["sections"]["edge_loop"]["recent"]["snapshot"]["incidents"]
    original = view["sections"]["edge_loop"]["recent"]["snapshot"]["incidents"]
    assert rows[0]["explanation"]["summary"] == original[0]["explanation"]["summary"]
    assert rows[0]["explanation"]["knowledge_refs"][0]["name"].startswith("<img")


def _code(text: str) -> str:
    """The script without its block comments (which name what it avoids)."""
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def test_the_page_script_writes_text_only():
    script = _code((STATIC / "app.js").read_text(encoding="utf-8"))
    for forbidden in (r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"document\.write",
                      r"\beval\s*\(", r"\bFunction\s*\(", r"new\s+Function", r"setInterval",
                      r"setTimeout\s*\(\s*['\"`]", r"\.src\s*=", r"\.href\s*=", r"srcdoc",
                      r"createContextualFragment", r"DOMParser", r"javascript:", r"\.style\b",
                      r"localStorage", r"sessionStorage", r"document\.cookie", r"import\s*\(",
                      r"XMLHttpRequest", r"WebSocket", r"postMessage", r"window\.open",
                      r"location\s*="):
        assert not re.search(forbidden, script), forbidden
    attributes = set(re.findall(r"setAttribute\(\s*\"([^\"]+)\"", script))
    assert attributes == {"aria-hidden", "aria-selected"}
    assert "setAttribute(" not in re.sub(r"setAttribute\(\s*\"(aria-hidden|aria-selected)\"", "",
                                         script)
    assert "textContent" in script
    # Every request goes to this origin by an absolute path, never a full URL.
    assert not re.search(r"https?://(?!127\.0\.0\.1\b)", script)
    assert set(re.findall(r"request\(\"(?:GET|POST)\", \"([^\"]+)\"", script)) == {
        "/api/session", "/api/view", "/api/login", "/api/logout", "/static/labels.json"}


def test_the_page_has_no_inline_code_style_or_outside_resource():
    page = (STATIC / "index.html").read_text(encoding="utf-8")
    scripts = re.findall(r"<script\b([^>]*)>(.*?)</script>", page, flags=re.S)
    assert scripts == [(' src="/static/app.js" defer', "")]
    assert "<style" not in page and " style=" not in page
    assert not re.search(r"\son[a-z]+\s*=", page, flags=re.I)
    assert not re.search(r"https?://|//[a-z]", page.replace("http://127.0.0.1", ""))
    assert re.findall(r'(?:src|href)="([^"]+)"', page) == ["/static/app.css", "/static/app.js"]
    # The login form posts a body; without the script it is refused (415),
    # and the code never goes into a URL.
    assert '<form id="login-form" method="post" action="/api/login"' in page
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert "url(" not in css and "@import" not in css and "http" not in css


# -- labels: one table, unknown never healthy ---------------------------------------------------


def _labels():
    return json.loads((STATIC / "labels.json").read_text(encoding="utf-8"))


UNKNOWNISH = ("unknown", "stale", "degraded", "too_large", "unavailable", "not_measured", "not_collected",
              "permission_denied", "pending", "absent", "unattempted/skipped", "none_read",
              "not_inspected", "not_installed", "unreadable", "not_probed", "unmeasured",
              "not-established", "refused", "expired", "missing", "corrupt", "failed")


def test_unknown_unmeasured_and_stale_words_are_never_healthy():
    labels = _labels()
    assert set(labels["tones"]) == {"ok", "warn", "bad", "unknown", "info"}
    assert len({tone["mark"] for tone in labels["tones"].values()}) == 5
    for word, (japanese, tone) in labels["words"].items():
        assert tone in labels["tones"], word
        assert japanese and re.search(r"[぀-ヿ一-鿿]", japanese) or word in (
            "FULL", "LITE", "CORE"), word
    for word in UNKNOWNISH:
        assert labels["words"][word][1] != "ok", word
    healthy = {w for w, (_, tone) in labels["words"].items() if tone == "ok"}
    assert healthy == {"attested", "available", "current", "done", "fresh", "running",
                       "verified-ready", "ok"}


def _vocabulary():
    from azazel_nexus.incident_explain import CONTENT_LABELS
    from azazel_nexus.integration import EdgePresence
    from azazel_nexus.lite_service import LiteState
    from azazel_nexus.operator import ModuleState

    return ({e.value for e in EdgePresence} | {e.value for e in LiteState}
            | {e.value for e in ModuleState} | set(CONTENT_LABELS)
            | {"done", "needed", "blocked", "not-applicable"} | set(ui_model.ACCESS_WORDS)
            | {"observe", "notify", "throttle", "redirect", "isolate", "open", "closed",
               "explained", "notice_shown", "reference_shown", "pending", "fixture", "live"})


def test_every_word_of_the_vocabulary_has_a_label():
    words = _labels()["words"]
    assert sorted(_vocabulary() - set(words)) == []


def _words_in(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("status", "freshness", "state", "content_kind", "result") and isinstance(
                    item, str):
                found.add(item)
            _words_in(item, found)
    elif isinstance(value, list):
        for item in value:
            _words_in(item, found)
    return found


def test_every_status_word_a_read_model_scenario_produces_has_a_label(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).parent))
    from test_status_view import SCENARIOS, run_scenario

    words = _labels()["words"]
    seen = set()
    for name in sorted(SCENARIOS):
        with monkeypatch.context() as patch:
            scenario = tmp_path / name
            scenario.mkdir()
            code, out, _ = run_scenario(name, scenario, patch, json_flag=True)
            assert code == 0
            sections = json.loads(out)["sections"]
            sections.pop("interfaces")  # not sent to the page (ui_model.UI_SECTIONS)
            seen |= _words_in(sections, set())
    # `edge_core.probe.result` codes and M.I.O. ledger states are shown as
    # codes beside their section's word; everything else is labelled.
    unlabelled = {word for word in seen - set(words)
                  if word not in {"loaded", "absent", "refused", "not_read"}}
    assert sorted(unlabelled) == []


def test_every_reason_code_in_the_demo_has_a_label():
    reasons = _labels()["reasons"]
    found = set()

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "reason_code" and isinstance(item, str):
                    found.add(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(json.loads(DEMO.read_text(encoding="utf-8")))
    # Every code the read model can carry (status_view's closed sets, #358).
    from azazel_nexus.status_view import KNOWLEDGE_REASONS, REASON_CODES
    found |= set(REASON_CODES) | set(KNOWLEDGE_REASONS)
    found |= {"section_absent_from_read_model", "read_model_refused", "status_read_failed",
              "setup_read_failed", "not_in_fixture", "access_permission_denied"}
    assert sorted(found - set(reasons)) == []


#: The keys whose string value the page shows through the label table, and
#: the keys whose value it shows as a reason code (`app.js`, `WORD_KEYS` and
#: `REASON_KEYS`); `conditions` is a list of reason codes.
PAGE_WORD_KEYS = {"status", "state", "freshness", "collection"}
PAGE_REASON_KEYS = {"reason_code", "reason"}


def test_the_page_labels_exactly_the_keys_these_tests_check():
    script = (STATIC / "app.js").read_text(encoding="utf-8")

    def keys(name):
        match = re.search(r"var " + name + r" = \{([^}]*)\};", script)
        assert match, name
        return set(re.findall(r"(\w+): true", match.group(1)))
    assert keys("WORD_KEYS") == PAGE_WORD_KEYS
    assert keys("REASON_KEYS") == PAGE_REASON_KEYS


def _page_vocabulary(value, words, reasons):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in PAGE_WORD_KEYS and isinstance(item, str):
                words.add(item)
            elif key in PAGE_REASON_KEYS and isinstance(item, str):
                reasons.add(item)
            elif key == "conditions" and isinstance(item, list):
                reasons.update(code for code in item if isinstance(code, str))
            _page_vocabulary(item, words, reasons)
    elif isinstance(value, list):
        for item in value:
            _page_vocabulary(item, words, reasons)


def _operator_sections(root, monkeypatch):
    """Every state the U2/U3 sections reach, built by `status_view` itself.

    Each snapshot is written in the shape its writer writes and read back
    through the strict readers: fresh, stale, dated in the future, under an
    unknown clock, absent and damaged; Knowledge Lite in each of its states,
    M.I.O. before a record and while uncertain, units read, failed and
    unread, every storage refusal, and NOC observed and failed.
    """
    from types import SimpleNamespace

    from azazel_nexus import noc_status, status_view
    from azazel_nexus import operator_snapshots as snap
    from azazel_nexus import runtime_paths as paths

    now = 1_790_000_000.0
    monkeypatch.setenv("AZAZEL_ROOT", str(root))

    def place(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())

    def every_clock(build):
        return [build(t) for t in (now + 1, now + 100_000, now - 60, None)]

    built = []
    for path, section in ((paths.knowledge_status_path(), status_view._knowledge_status),
                          (paths.mio_status_path(), status_view._mio_status),
                          (paths.units_status_path(), status_view._services),
                          (paths.noc_status_path(), status_view._noc)):
        built += every_clock(section)                       # absent
        place(path, b'{"schema":')
        built += every_clock(section)                       # damaged
    for summary in ({"state": "available", "reason_code": "available", "generation": 5,
                     "freshness": "current"},
                    {"state": "quarantined", "reason_code": "revoked", "generation": 5,
                     "freshness": "current"},
                    {"state": "stale", "reason_code": "stale", "generation": 5,
                     "freshness": "stale"},
                    {"state": "unavailable", "reason_code": "state_untrusted",
                     "generation": None, "freshness": "absent"},
                    {"state": "unavailable", "reason_code": "no_bundle", "generation": None,
                     "freshness": "absent"},
                    {"state": "not-a-state"}):
        place(paths.knowledge_status_path(), snap.knowledge_snapshot(summary, now))
        built += every_clock(status_view._knowledge_status)
    place(paths.knowledge_status_path(), snap.knowledge_snapshot(None, now, reason="internal_error"))
    built += every_clock(status_view._knowledge_status)
    reading = {"state": "CORE", "reasons": {
        "profile": "LITE", "resource": "core_reserve_unmeasured", "trust": "not-checked",
        "topology": "no_verified_egress",
        "health": {"local": "not_admitted", "remote": "unavailable"}}}
    for value in (snap.mio_snapshot(None, None, uncertain=False, written_at=now),
                  snap.mio_snapshot(reading, "2026-09-21T04:00:00+00:00", uncertain=True,
                                    written_at=now),
                  snap.mio_snapshot(reading, "2026-09-21T04:00:00+00:00", uncertain=False,
                                    written_at=now)):
        place(paths.mio_status_path(), value)
        built += every_clock(status_view._mio_status)
    good = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
    for change in ({}, {"azazel-auditd.service": {**good, "ActiveState": "failed",
                                                   "SubState": "failed"}},
                   {"azazel-auditd.service": "bus_unavailable"},
                   {"azazel-ui.service": "read_refused"}):
        states = {unit: dict(good) for unit in snap.OBSERVED_UNITS}
        states.update(change)
        place(paths.units_status_path(), snap.units_snapshot(states, now))
        built += every_clock(status_view._services)
    demo = json.loads(DEMO.read_text(encoding="utf-8"))["sections"]["noc"]["snapshot"]
    for value in (dict(demo, written_at=now), *(noc_status.failed(now, reason)
                                                 for reason in noc_status.COLLECTION_REASONS)):
        place(paths.noc_status_path(), value)
        built += every_clock(status_view._noc)
    usage = SimpleNamespace(f_blocks=1000, f_bfree=600, f_bavail=500, f_frsize=4096, f_flag=0)
    for error in (None, FileNotFoundError, PermissionError, OSError):
        def statvfs(path, error=error):
            if error is not None:
                raise error("SECRET")
            return usage
        monkeypatch.setattr(status_view, "_storage_probes",
                            (statvfs, lambda path: SimpleNamespace(st_dev=7)))
        built.append(status_view._storage(now))
    return built


def test_every_word_and_code_of_the_operator_and_noc_sections_has_a_label(tmp_path, monkeypatch):
    """#363/#364 added these sections; the page must never say 未定義の語 for
    them, and none of their words but Knowledge Lite's `available` (and the
    snapshot's own `fresh`/`current`) may be shown as healthy."""
    labels = _labels()
    words, reasons = set(), set()
    built = _operator_sections(tmp_path, monkeypatch)
    for section in built:
        _page_vocabulary(section, words, reasons)
    assert sorted(words - set(labels["words"])) == []
    assert sorted(reasons - set(labels["reasons"])) == []
    # What each section says it read is a fact, not health.
    for word in ("observed", "read", "recorded", "measured"):
        assert word in words and labels["words"][word][1] == "info", word
    for word in ("degraded", "unknown", "unavailable", "stale", "not_measured"):
        assert word in words and labels["words"][word][1] != "ok", word
    assert {w for w in words if labels["words"][w][1] == "ok"} <= {"available", "current", "fresh"}
    statuses = {section["status"] for section in built}
    assert statuses == {"available", "degraded", "recorded", "read", "observed", "measured",
                        "unknown", "unavailable", "stale"}
    assert all(labels["words"][word][1] != "ok" for word in statuses - {"available"})
    # Every code these sections can carry, not only the ones reached above.
    from azazel_nexus import noc_status
    from azazel_nexus import operator_snapshots as snap
    every = (set(snap.KNOWLEDGE_REASONS) | set(snap.UNIT_REASONS) | set(snap.STORAGE_REASONS)
             | set(noc_status.UNKNOWN_REASONS) | set(noc_status.COLLECTION_REASONS))
    assert sorted(every - set(labels["reasons"])) == []
    assert "SECRET" not in json.dumps(built)


def test_the_document_carries_the_operator_and_noc_sections(tmp_path, monkeypatch):
    """A non-root UI reads these sections, not the root-only sources."""
    view = json.loads(DEMO.read_text(encoding="utf-8"))
    model = ui_model.project(view, origin={"kind": "fixture"}, served_at="t")
    for name in ("knowledge_status", "mio_status", "services", "storage", "noc"):
        assert model["sections"][name] == view["sections"][name], name
    assert model["pending"] == {}


# -- the live source and the permission probe ---------------------------------------------------


def test_the_access_probe_tells_permission_from_absence(tmp_path, monkeypatch):
    present = tmp_path / "present.json"
    present.write_text("{}", encoding="utf-8")
    assert ui_serve._probe_access(present) == "readable"
    assert ui_serve._probe_access(tmp_path / "absent.json") == "absent"
    link = tmp_path / "link"
    link.symlink_to(present)
    assert ui_serve._probe_access(link) == "not_regular"

    def denied(path, **kwargs):
        raise PermissionError(13, "denied")
    monkeypatch.setattr(ui_serve.os, "stat", denied)
    assert ui_serve._probe_access(present) == "permission_denied"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every file; the uid-1001 run checks it")
def test_the_access_probe_reports_a_directory_this_account_cannot_enter(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "status.json").write_text("{}", encoding="utf-8")
    private.chmod(0o700 & ~0o100)
    try:
        assert ui_serve._probe_access(private / "status.json") == "permission_denied"
    finally:
        private.chmod(0o700)


def test_the_live_source_reads_status_and_setup_as_their_commands_print_them(tmp_path, monkeypatch):
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    calls = []

    def fake_main(argv, out, err):
        calls.append(list(argv))
        if argv == ["status", "--json"]:
            out.write(DEMO.read_text(encoding="utf-8"))
        else:
            out.write(json.dumps({"schema": "azazel-nexus/setup/1", "steps": [
                {"name": "commissioning", "status": "needed", "reason": "missing",
                 "next_command": "azazel-nexus commission --help", "extra": "dropped"}],
                "provider_admission": "blocked", "hg05": "unmeasured", "read_only": True,
                "enforcement_readiness": "not-established", "notice": "n", "mio": {"x": 1}}))
        return 0
    read = ui_serve.LiveSource(fake_main).read()
    assert calls == [["status", "--json"], ["setup", "--json"]]
    assert read["origin"] == {"kind": "live", "reader": "azazel-nexus status --json",
                              "account": "azui"}
    assert set(read["access"]) == {"edge_intake_status", "incident_explain_status",
                                   "incident_recent", "audit_status", "edge_probe",
                                   "knowledge_lite", "mio_route_ledger", "knowledge_status",
                                   "mio_status", "units_status", "noc_status"}
    assert set(read["access"].values()) == {"absent"}
    model = ui_model.project(read["view"], origin=read["origin"], served_at="t",
                             setup=read["setup"], access=read["access"])
    assert model["setup"]["steps"] == [{"name": "commissioning", "status": "needed",
                                        "reason": "missing",
                                        "next_command": "azazel-nexus commission --help"}]
    assert "mio" not in model["setup"]


def test_a_failing_read_is_a_fixed_code_never_exception_text():
    def broken(argv, out, err):
        raise RuntimeError("SECRET /var/lib/azazel/state 192.0.2.1")
    read = ui_serve.LiveSource(broken).read()
    assert read["view"] is None and read["read_reason"] == "status_read_failed"
    model = ui_model.project(read["view"], origin=read["origin"], served_at="t",
                             read_reason=read["read_reason"])
    text = json.dumps(model)
    assert "SECRET" not in text and "192.0.2.1" not in text
    assert model["read_model"] == {"status": "unavailable", "reason_code": "status_read_failed"}


def test_the_live_source_runs_the_real_status_command(tmp_path, monkeypatch):
    """No stand-in: the CLI's own `status --json` and `setup --json`."""
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    read = ui_serve.LiveSource().read()
    assert read["view"]["schema"] == "azazel-nexus/status-view/1"
    assert read["setup"]["schema"] == "azazel-nexus/setup/1"
    model = ui_model.project(read["view"], origin=read["origin"], served_at="t",
                             setup=read["setup"], access=read["access"])
    assert model["read_model"]["status"] == "read"
    assert "interfaces" not in model["sections"]


def test_an_internal_failure_while_building_is_a_fixed_code(tmp_path):
    class Broken:
        kind = "live"

        def read(self):
            raise RuntimeError("SECRET")
    harness = Harness(tmp_path, source=Broken())
    try:
        sid, _ = harness.login()
        model = harness.view(sid).json()
    finally:
        harness.close()
    assert model["read_model"] == {"status": "unavailable", "reason_code": "internal_error"}
    assert "SECRET" not in json.dumps(model)


@pytest.mark.parametrize("content, error", [
    (b"{", ValueError), (json.dumps({"schema": "other"}).encode(), ValueError),
    (b" " * (ui_serve.FIXTURE_BYTES + 1), ValueError),
])
def test_a_fixture_that_is_not_a_read_model_is_refused(tmp_path, content, error):
    path = tmp_path / "fixture.json"
    path.write_bytes(content)
    with pytest.raises(error):
        ui_serve.FixtureSource(path)


def test_a_fixture_symlink_is_refused(tmp_path):
    link = tmp_path / "link.json"
    link.symlink_to(DEMO)
    with pytest.raises(OSError):
        ui_serve.FixtureSource(link)


def test_a_fixture_says_it_is_a_fixture_on_every_document(ui):
    sid, _ = ui.login()
    model = ui.view(sid).json()
    assert model["origin"]["kind"] == "fixture"
    assert model["setup"] == {"status": "not_collected", "reason_code": "not_in_fixture"}
    assert model["access"] == {}


# -- the declaration: units, preset, installer --------------------------------------------------


def _unit(name):
    return (UNIT_DIR / name).read_text(encoding="utf-8")


def test_the_service_unit_is_unprivileged_and_networkless():
    text = _unit("azazel-ui.service")
    lines = text.splitlines()
    for line in ("User=azui", "RestrictAddressFamilies=AF_UNIX", "PrivateNetwork=yes",
                 "IPAddressDeny=any", "CapabilityBoundingSet=", "AmbientCapabilities=",
                 "NoNewPrivileges=yes", "ProtectSystem=strict", "ExecStart=/usr/libexec/azazel/az-ui",
                 "Requires=azazel-ui.socket", "After=azazel-ui.socket",
                 "ReadWritePaths=/var/lib/azazel/run/ui-login"):
        assert line in lines, line
    assert not any(line.startswith(("SupplementaryGroups=", "Group=", "WantedBy=",
                                    "ConditionPathExists=", "BindsTo=", "AmbientCapabilities=CAP"))
                   for line in lines)
    assert "[Install]" not in text
    assert sum(line.startswith("ReadWritePaths=") for line in lines) == 1


def test_the_socket_listens_on_ipv4_loopback_only():
    from azazel_nexus_runtime.hardening import render_ui_socket

    text = _unit("azazel-ui.socket")
    assert text == render_ui_socket()
    lines = text.splitlines()
    assert [line for line in lines if line.startswith("Listen")] == [
        "ListenStream=127.0.0.1:8443"]
    for line in ("Accept=no", "IPAddressDeny=any", "IPAddressAllow=localhost",
                 "Service=azazel-ui.service", "WantedBy=sockets.target"):
        assert line in lines, line


def test_nothing_depends_on_the_ui_so_stopping_it_stops_nothing():
    """No unit requires, binds to, wants, is part of or is triggered by the UI.

    Only the UI service names its own socket. With nothing ordered on it,
    stopping or failing the UI cannot stop a daemon, a pass or Edge's loop.
    """

    dependency = re.compile(r"^(Requires|BindsTo|Wants|PartOf|Requisite|Upholds|"
                            r"PropagatesStopTo|StopPropagatedFrom|OnFailure|OnSuccess|"
                            r"Before|After|Also|Conflicts)=(.*)$")
    for path in sorted(UNIT_DIR.iterdir()):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = dependency.match(line)
            if match and "azazel-ui" in match.group(2):
                assert path.name == "azazel-ui.service" and line in (
                    "Requires=azazel-ui.socket", "After=azazel-ui.socket"), (path.name, line)


def test_the_ui_is_not_governed_and_holds_no_grant():
    from azazel_nexus.activation import CORE_UNITS
    from azazel_nexus_runtime.hardening import (
        GRANT_MARKER_UNITS, PROFILES, UI_PROFILES, governed_units,
    )
    from azazel_nexus_runtime.units import UNIT_NAMES

    for unit in ("azazel-ui.service", "azazel-ui.socket"):
        assert unit not in governed_units()
        assert unit not in {d.name for d in CORE_UNITS}
        assert unit not in GRANT_MARKER_UNITS
        assert unit not in UNIT_NAMES.values()
        assert unit not in {p.unit for p in PROFILES}
    assert [p.unit for p in UI_PROFILES] == ["azazel-ui.service"]


@pytest.mark.parametrize("change", [
    dict(supplementary_groups=("azazel-operator",)),
    dict(account="azexplain"),
    dict(address_families=("AF_UNIX", "AF_NETLINK")),
    dict(extra=(("ProtectProc", "invisible"),)),
    dict(requires=("azazel-ui.socket", "azazel-activated.service")),
    dict(binds_to=("azazel-activated.service",)),
    dict(wanted_by=("multi-user.target",)),
    dict(read_write_paths=("/var/lib/azazel/run/ui-login", "/var/lib/azazel/run/audit")),
    dict(capability_bounding_set=("CAP_NET_BIND_SERVICE",)),
])
def test_the_ui_declaration_refuses_each_widening(change):
    from azazel_nexus_runtime.hardening import UI_PROFILES

    with pytest.raises(ValueError):
        replace(UI_PROFILES[0], **change)


def test_azui_is_created_without_shell_home_or_any_group_but_its_own():
    from azazel_nexus.layout import LAYOUT
    from azazel_nexus_runtime.hardening import ALL_PROFILES, SYSTEM_ACCOUNTS

    installer = (REPO / "packaging" / "install.sh").read_text(encoding="utf-8")
    assert "azui" in SYSTEM_ACCOUNTS
    loop = re.search(r"for account in ([^;]+); do", installer).group(1).split()
    assert "azui" in loop
    # No membership is ever added: not azazel-operator, not a socket group.
    assert not re.search(r"(usermod|gpasswd|adduser)[^\n]*azui", installer)
    assert not re.search(r"azui[^\n]*(usermod|gpasswd)", installer)
    assert [p.unit for p in ALL_PROFILES if "azui" in p.supplementary_groups] == []
    assert [(s.path, s.group) for s in LAYOUT if "azui" in (s.owner, s.group)] == [
        ("/var/lib/azazel/run/ui-login", "azazel-operator")]
    assert "make_owned_dir 2750 azui azazel-operator /var/lib/azazel/run/ui-login" in installer
    assert 'install -m 0644 "$HERE"/systemd/azazel-ui.socket "$UNIT_DIR"' in installer
    commands = "\n".join(line for line in installer.splitlines()
                          if not line.lstrip().startswith("#"))
    assert not re.search(r"systemctl (enable|start|mask|unmask)[^\n]*azazel-ui", commands)


# -- the real process -------------------------------------------------------------------------------


def _free_port():
    with socket.create_server(("127.0.0.1", 0)) as probe:
        return probe.getsockname()[1]


def _wait_for(path, process, seconds=20.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise AssertionError(f"az-ui exited: {process.stderr.read()}")
        time.sleep(0.05)
    raise AssertionError("az-ui published no login code")


def _environment():
    env = {key: value for key, value in os.environ.items() if not key.startswith("LISTEN_")}
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO / "src"), str(REPO / "runtime" / "src"), env.get("PYTHONPATH", "")])
    return env


def test_the_real_process_serves_the_screens_on_the_socket_it_is_given(tmp_path):
    port = _free_port()
    login_file = tmp_path / "login-code.json"
    process = subprocess.Popen(
        [sys.executable, str(ACTIVATE), "--port", str(port), "--", sys.executable, "-m",
         "azazel_nexus_runtime.ui_serve", "--fixture", str(DEMO), "--login-file", str(login_file)],
        env=_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _wait_for(login_file, process)
        index = _request(port, "GET", "/")
        assert index.status == 200
        _assert_security_headers(index)
        assert b'<script src="/static/app.js" defer></script>' in index.body
        assert _request(port, "GET", "/", host="evil.example").status == 421
        assert _request(port, "GET", "/api/view").status == 401
        session = _request(port, "GET", "/api/session")
        token = session.json()["login_token"]
        code = ui_login.read_login_code(login_file.read_bytes())["code"]
        origin = f"http://127.0.0.1:{port}"
        login = _request(port, "POST", "/api/login", body={"code": code}, headers=[
            ("Content-Type", "application/json"), ("Origin", origin), ("X-CSRF-Token", token),
            ("Cookie", f"azui_login={token}")])
        assert login.status == 200
        sid = _cookie_value(login.cookies()[0], "azui_session")
        view = _request(port, "GET", "/api/view", headers=[("Cookie", f"azui_session={sid}")])
        assert view.status == 200
        model = view.json()
        assert model["origin"]["kind"] == "fixture"
        assert model["authority"]["edge_decisions"] == "would_not_executed"
        assert model["pending"] == {}
        rows = model["sections"]["edge_loop"]["recent"]["snapshot"]["incidents"]
        assert {row["edge_decision"]["executed"] for row in rows} == {False}
        replay = _request(port, "POST", "/api/login", body={"code": code}, headers=[
            ("Content-Type", "application/json"), ("Origin", origin), ("X-CSRF-Token", token),
            ("Cookie", f"azui_login={token}")])
        assert replay.status == 403
        logout = _request(port, "POST", "/api/logout", body={}, headers=[
            ("Content-Type", "application/json"), ("Origin", origin),
            ("X-CSRF-Token", login.json()["csrf"]), ("Cookie", f"azui_session={sid}")])
        assert logout.status == 200
        assert _request(port, "GET", "/api/view",
                        headers=[("Cookie", f"azui_session={sid}")]).status == 401
        for length in ("\u00b2", "50"):
            raw = socket.create_connection(("127.0.0.1", port), timeout=10)
            raw.sendall((f"POST /api/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                         f"Origin: {origin}\r\nContent-Type: application/json\r\n"
                         f"Content-Length: {length}\r\n\r\n{{").encode("latin-1"))
            raw.shutdown(socket.SHUT_WR)
            assert raw.recv(65536).split(b" ", 2)[1] in (b"400", b"411")
            raw.close()
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=10)
    err = process.stderr.read()
    assert "az-ui: serving_fixture" in err
    assert "Traceback" not in err and "127.0.0.1" not in err, err


_LAUNCH = r"""
import os, socket, sys
kind, fixture, login = sys.argv[1], sys.argv[2], sys.argv[3]
if kind == "file":
    fd = os.open(fixture, os.O_RDONLY)
elif kind != "none":
    family = socket.AF_UNIX if kind == "unix" else (
        socket.AF_INET6 if kind == "ipv6" else socket.AF_INET)
    kind_type = socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM
    s = socket.socket(family, kind_type)
    s.bind(login + ".sock" if kind == "unix" else (
        ("::1", 0) if kind == "ipv6" else ("0.0.0.0" if kind == "any" else "127.0.0.1", 0)))
    if kind not in ("udp", "bound"):
        s.listen(1)
    fd = s.fileno()
if kind != "none":
    os.dup2(fd, 3)
    os.set_inheritable(3, True)
    os.environ["LISTEN_PID"] = "1" if kind == "wrong-pid" else str(os.getpid())
    os.environ["LISTEN_FDS"] = "2" if kind == "two" else "1"
os.execv(sys.executable, [sys.executable, "-m", "azazel_nexus_runtime.ui_serve",
                          "--fixture", fixture, "--login-file", login])
"""


@pytest.mark.parametrize("kind, reason", [
    ("none", "no_inherited_listener"),
    ("wrong-pid", "no_inherited_listener"),
    ("two", "no_inherited_listener"),
    ("file", "inherited_descriptor_not_a_socket"),
    ("any", "listener_not_loopback_ipv4_stream"),
    ("bound", "listener_not_loopback_ipv4_stream"),
    ("udp", "listener_not_loopback_ipv4_stream"),
    ("unix", "listener_not_loopback_ipv4_stream"),
    ("ipv6", "listener_not_loopback_ipv4_stream"),
])
def test_the_real_process_refuses_anything_but_one_loopback_listener(tmp_path, kind, reason):
    if kind == "ipv6" and not socket.has_ipv6:
        pytest.skip("no IPv6 in this kernel")
    login = tmp_path / "login-code.json"
    result = subprocess.run([sys.executable, "-c", _LAUNCH, kind, str(DEMO), str(login)],
                            env=_environment(), capture_output=True, text=True, timeout=30)
    if kind == "ipv6" and "Cannot assign requested address" in result.stderr:
        pytest.skip("no ::1 in this network namespace")
    assert result.returncode == 2, result.stderr
    assert f"az-ui: refused: {reason}" in result.stderr
    assert not login.exists()
