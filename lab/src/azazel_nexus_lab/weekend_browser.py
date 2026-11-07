"""Reserved container browser lab. No model, systemd or production gate changes."""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time


def http_files(output, receipt):
    """Read fixed ordinary export files once; never join a request to a path."""
    from azazel_nexus_lab.weekend_process import verify_handoff
    files = {}
    for case in ('NOC1', 'SOC1'):
        parent = output / ('noc-handoff' if case == 'NOC1' else 'handoff')
        checked = verify_handoff(parent, receipt['handoffs'][case]['incident_id'])
        assert checked['files'] == receipt['handoffs'][case]['files']
        directory = output / checked['directory']
        for name in ('manifest.json', 'handoff.json', 'handoff.ja.md'):
            kind = 'text/markdown; charset=utf-8' if name.endswith('.md') else 'application/json'
            files[f'/lab/handoff/{case}/{name}'] = ((directory / name).read_bytes(), kind)
    from azazel_nexus_lab.weekend_ui import panels
    control = dict(schema='weekend-browser-control/v1', panels=panels(receipt),
        p3={k: receipt['cases']['P04'][k] for k in ('broker_ingress', 'knowledge_ingress', 'generated_sends')},
        noc={k: receipt['noc_incident'][k] for k in ('broker_ingress', 'knowledge_ingress', 'generated_sends')},
        same_cap_control=receipt['same_cap_control'], model_sends=receipt['model_sends'],
        network=receipt['network'], handoffs=receipt['handoffs'],
        process_roles=[p['role'] for p in receipt['processes']],
        deception_execution='not_started', external_communication='no_default_route; no_external_provider_configured',
        scope='synthetic receipts; human DOM/meaning/browser-network review required')
    files['/lab/checks'] = (json.dumps(control).encode(), 'application/json')
    return files


def serve(args):
    from azazel_nexus.ui_model import browser_json
    from azazel_nexus_runtime import ui_serve as ui
    from azazel_nexus_lab.weekend_ui import supplement
    listener = ui.adopt_listener(os.environ, os.getpid())
    receipt = json.loads(args.receipt.read_text())

    class App(ui.UiApp):
        def view_document(self):
            value = json.loads(super().view_document())
            value['weekend_lab'] = self.weekend_data
            return browser_json(value)

    class Handler(ui.UiHandler):
        def do_GET(self):
            if self.path.startswith('/lab/'):
                try:
                    self._host()
                    route = self._route()
                    if self.app.sessions.get(self._cookie(ui.SESSION_COOKIE), self.app.clock()) is None:
                        raise ui.Refused(401, 'login_required')
                    if route not in self.app.exports:
                        raise ui.Refused(404, 'not_found')
                    body, kind = self.app.exports[route]
                    self._send(200, body, kind)
                except ui.Refused as refused:
                    self._refuse(refused)
            else:
                super().do_GET()

    port = listener.getsockname()[1]
    app = App(source=ui.FixtureSource(args.fixture), port=port,
        codes=ui.LoginCodes(ui.publish_to(args.login_file), f'http://127.0.0.1:{port}/'))
    app.weekend_data = supplement(app, receipt)
    app.exports = http_files(args.receipt.parent, receipt)
    app.codes.tick(app.clock())
    stop = threading.Event()
    threading.Thread(target=ui._rotate, args=(app, stop), daemon=True).start()
    server = ui.AdoptedServer(listener, Handler, app)
    try:
        server.serve_forever(poll_interval=.25)
    finally:
        stop.set()
        server.server_close()


class Relay(socketserver.BaseRequestHandler):
    """TCP relay only: preserve Host, Origin, authentication and bytes verbatim."""
    def handle(self):
        with socket.create_connection(('127.0.0.1', self.server.server_address[1]), timeout=3) as peer:
            self.request.setblocking(False)
            peer.setblocking(False)
            with selectors.DefaultSelector() as ready:
                ready.register(self.request, selectors.EVENT_READ, peer)
                ready.register(peer, selectors.EVENT_READ, self.request)
                end = time.monotonic() + 12
                while time.monotonic() < end:
                    events = ready.select(.25)
                    for key, _ in events:
                        body = key.fileobj.recv(65536)
                        if not body:
                            return
                        # Small bounded HTTP exchanges, no connection pooling.
                        target = key.data
                        target.settimeout(3)
                        target.sendall(body)
                        target.setblocking(False)


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def hold(args, receipt, children):
    from azazel_nexus_lab.weekend_process import REPO
    control = args.control
    private = control / 'private'
    private.mkdir(mode=0o700)
    base = json.loads((args.output / 'status-view.json').read_text())
    unknown = copy.deepcopy(base)
    unknown['clock'] = dict(status='unknown', reason_code='clock_unknown')
    stale = copy.deepcopy(base)
    for name in ('intake', 'explainer', 'recent'):
        stale['sections']['edge_loop'][name]['source']['freshness'] = 'stale'
    variants = {'primary': base, 'clock-unknown': unknown, 'loop-stale': stale}
    # Address supplied by Docker inspect, never discovered by contacting a peer.
    import fcntl
    import struct
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        bridge_ip = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), 0x8915,
            struct.pack('256s', b'eth0'))[20:24])
    servers, threads, processes, logs = [], [], {}, []
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())

    def launch(name, port):
        log = (control / f'{name}.log').open('ab')
        logs.append(log)
        child = subprocess.Popen([sys.executable, '-B', str(REPO / 'tools/ui_socket_activate.py'),
            '--port', str(port), '--', sys.executable, '-B', '-m', __name__, 'serve',
            '--fixture', str(control / f'{name}.json'), '--receipt', str(args.output / 'paired.json'),
            '--login-file', str(private / f'{name}.json')], stdout=log, stderr=log)
        processes[name] = child
        end = time.monotonic() + 5
        while time.monotonic() < end:
            assert child.poll() is None, 'UI child exited before ready'
            if (private / f'{name}.json').exists():
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        return
                except OSError:
                    pass
            time.sleep(.05)
        raise AssertionError('UI listener not ready')

    try:
        urls = {}
        for offset, (name, value) in enumerate(variants.items()):
            port = args.port + offset
            (control / f'{name}.json').write_text(json.dumps(value) + '\n')
            launch(name, port)
            relay = RelayServer((bridge_ip, port), Relay)
            servers.append(relay)
            thread = threading.Thread(target=relay.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
            urls[name] = f'http://127.0.0.1:{port}/'
        document = dict(schema='weekend-ready-ui/v1', urls=urls, url=urls['primary'],
            checks=['NOC1/SOC1 evidence, unknowns, next checks, handoff', 'incident/trace',
                    'clock-unknown', 'loop-stale', 'reload/restart', 'JSON/Markdown/digest',
                    'secret scan', 'Deception not executed', 'P3 full-egress zero'],
            login_files={name: f'private/{name}.json' for name in variants},
            stop_file='STOP', restart_file='RESTART', maximum_wait_seconds=1800,
            human_acceptance='NOT_RUN')
        ready = control / 'CONTAINER-READY'
        temporary = control / 'CONTAINER-READY.new'
        temporary.write_text(json.dumps(document, indent=2) + '\n')
        temporary.replace(ready)
        end = time.monotonic() + 1800
        handled = None
        while time.monotonic() < end and not stopped.is_set() and not (control / 'STOP').exists():
            # The intentionally terminated original broker is replaced by recovery.
            assert all(c.poll() is None for c in children if c.pid not in {p['pid'] for p in receipt['processes'] if p['role'] == 'broker'})
            assert all(p.poll() is None for p in processes.values()), 'UI child died'
            marker = control / 'RESTART'
            stamp = marker.stat().st_mtime_ns if marker.exists() else None
            if stamp is not None and stamp != handled:
                old = processes['primary']
                old.terminate()
                old.wait(timeout=5)
                launch('primary', args.port)
                (control / 'RESTARTED').write_text(json.dumps(dict(old_pid=old.pid,
                    new_pid=processes['primary'].pid, marker=stamp)) + '\n')
                handled = stamp
            stopped.wait(.25)
        (control / 'ENDED').write_text('STOP' if (control / 'STOP').exists() else 'signal_or_1800s_deadline')
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        cleanup = []
        for name, child in processes.items():
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
                raise AssertionError('UI required kill; cleanup not accepted')
            cleanup.append(dict(role=name, exit=child.returncode))
        for log in logs:
            log.close()
        (control / 'ui-cleanup.json').write_text(json.dumps(cleanup) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    serve_parser = sub.add_parser('serve')
    for flag in ('fixture', 'receipt', 'login-file'):
        serve_parser.add_argument('--' + flag, type=Path, required=True)
    reserve = sub.add_parser('reserve')
    reserve.add_argument('--output', type=Path, required=True)
    reserve.add_argument('--control', type=Path, required=True)
    reserve.add_argument('--port', type=int, default=8843)
    args = parser.parse_args(argv)
    if args.mode == 'serve':
        serve(args)
    else:
        if not 1024 <= args.port <= 65533:
            parser.error('port range is 1024..65533')
        from azazel_nexus_lab.weekend_process import run_pair
        run_pair(args.output, ui_network=True, on_ready=lambda r, c: hold(args, r, c))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
