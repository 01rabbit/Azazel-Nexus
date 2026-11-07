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
    (output / 'status-view.json').write_text(json.dumps({
        'sections': {'edge_loop': {name: {'source': {}} for name in
                                 ('intake', 'explainer', 'recent')}}}))
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
