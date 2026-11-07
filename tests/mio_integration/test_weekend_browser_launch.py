"""Exercise the real -m entry point without starting a listener or process chain."""
import json
import runpy
import socket
import subprocess
import sys

from unittest.mock import patch


def test_module_entry_launches_resolvable_ui_children(tmp_path, monkeypatch):
    from azazel_nexus_lab import weekend_process

    output, control = tmp_path / 'paired', tmp_path / 'control'
    output.mkdir()
    control.mkdir()
    from azazel_nexus.status_view import LOOP_STALE_S, _component
    part = _component({'schema': 'lab-header/v1', 'written_at': 100}, 100,
                      LOOP_STALE_S, ('schema', 'written_at'), schema='lab-header/v1')
    (output / 'status-view.json').write_text(json.dumps({
        'sections': {'edge_loop': {'evaluated_at': 100, **{name: part for name in
                                 ('intake', 'explainer', 'recent')}}}}))
    (control / 'STOP').touch()
    commands = []

    class Child:
        returncode = None

        def __init__(self, argv, **kwargs):
            commands.append(argv)
            self.pid = 100 + len(commands)
            login = argv[argv.index('--login-file') + 1]
            from pathlib import Path
            Path(login).write_text('{}')

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, **kwargs):
            return self.returncode

    class Server:
        def __init__(self, *args):
            pass

        def serve_forever(self):
            pass

        def shutdown(self):
            pass

        def server_close(self):
            pass

    def run_pair(output, *, ui_network, on_ready):
        assert ui_network is True
        # Callback globals are those of the real module executed as __main__.
        namespace = on_ready.__globals__
        assert namespace['__name__'] == '__main__'
        with patch.dict(namespace, RelayServer=Server), \
                patch('fcntl.ioctl', return_value=b'\0' * 20 + socket.inet_aton('192.0.2.1')), \
                patch('signal.signal'), patch('socket.create_connection'), \
                patch('subprocess.Popen', side_effect=Child):
            on_ready({'processes': []}, [])

    monkeypatch.setattr(weekend_process, 'run_pair', run_pair)
    monkeypatch.setattr(sys, 'argv', ['weekend_browser', 'reserve', '--output', str(output),
                                     '--control', str(control), '--port', '8843'])
    import pytest
    with pytest.raises(SystemExit) as ended:
        runpy.run_module('azazel_nexus_lab.weekend_browser', run_name='__main__')
    assert ended.value.code == 0
    assert len(commands) == 3
    for argv in commands:
        module = argv[argv.index('-m') + 1]
        # Resolving serve --help exercises module dispatch, without opening a socket.
        result = subprocess.run([sys.executable, '-B', '-m', module, 'serve', '--help'],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert '--login-file' in result.stdout
    assert (control / 'CONTAINER-READY').is_file()
    assert json.loads((control / 'ui-cleanup.json').read_text()) == [
        {'role': name, 'exit': -15} for name in ('primary', 'clock-unknown', 'loop-stale')]


def test_stale_variant_agrees_with_production_cards_and_summary(tmp_path):
    """U02-F1: exercise FixtureSource/UiApp without a listener or child process."""
    import copy
    from pathlib import Path
    from azazel_nexus.status_view import LOOP_STALE_S, _component
    from azazel_nexus_runtime.ui_serve import FixtureSource, UiApp
    from azazel_nexus_lab.weekend_browser import fixture_variants

    repo = Path(__file__).resolve().parents[2]
    base = json.loads((repo / 'tests/fixtures/ui/demo-status-view.json').read_text())
    before = copy.deepcopy(base)
    variants = fixture_variants(base)
    assert base == before and variants['primary'] is base
    assert variants['clock-unknown']['sections'] == base['sections']
    assert variants['clock-unknown']['clock']['status'] == 'unknown'
    value = variants['loop-stale']
    loop = value['sections']['edge_loop']
    for name in ('intake', 'explainer', 'recent'):
        part = loop[name]
        assert part['snapshot'] == base['sections']['edge_loop'][name]['snapshot']
        assert part['status'] == part['source']['freshness'] == 'stale'
        assert part['reason_code'] == part['source']['reason_code'] == 'snapshot_expired'
        assert part['source']['age_s'] > LOOP_STALE_S
        # Independent raw-header projection: the production stale decision.
        header = {key: part['source'][key] for key in ('schema', 'written_at')}
        production = _component(header, loop['evaluated_at'], LOOP_STALE_S,
                                tuple(header), schema=header['schema'])
        assert (part['status'], part['reason_code'], part['source']) == (
            production['status'], production['reason_code'], production['source'])
    path = tmp_path / 'stale.json'
    path.write_text(json.dumps(value))
    app = UiApp(source=FixtureSource(path), codes=None, port=8843, clock=lambda: 100)
    model = json.loads(app.view_document())
    assert model['summary']['events']['status'] == 'stale'
    assert any(item['code'] == 'check_stale_sources' for item in model['summary']['next']['items'])
    # These are exactly the status values consumed by incidents() card badges.
    assert all(model['sections']['edge_loop'][name]['status'] == 'stale'
               for name in ('intake', 'explainer', 'recent'))
    labels = json.loads(app.static['/static/labels.json'][0])
    assert labels['words']['stale'][1] != 'ok'
