"""Test-only locald composition for the weekend synthetic process lab.

This launcher preserves production deadlines and gates. The controller must
stage the synthetic root, service identities and sockets before dropping to
azmio. It does not create trust, start a model, or operate systemd.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys
import threading
import json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lite', action='store_true',
                        help='use the ordinary authenticated Knowledge Lite socket client')
    args = parser.parse_args(argv)
    if (not sys.platform.startswith('linux') or not Path('/.dockerenv').is_file()
            or not os.environ.get('AZAZEL_ROOT')):
        parser.error('requires the isolated Linux Docker lab and an explicit synthetic AZAZEL_ROOT')
    root = Path(os.environ['AZAZEL_ROOT'])
    if (not root.is_absolute() or not root.is_dir() or root.resolve() != root
            or root.parent != Path('/tmp') or not root.name.startswith('weekend-')):
        parser.error('synthetic root must be a non-symlink /tmp/weekend-* directory inside the container')
    import pwd
    if os.geteuid() != pwd.getpwnam('azmio').pw_uid:
        parser.error('controller must drop to the isolated azmio identity')
    from azazel_nexus_runtime.knowledge_client import lookup_context
    from azazel_nexus_runtime.mio_locald import LocalRuntimeService, REGISTRY, SOCKET_NAME
    from azazel_nexus_runtime.principal import PrincipalPolicy
    from azazel_nexus_runtime.runtime_paths import socket_path
    from azazel_nexus_runtime.serve import serve_forever

    service = LocalRuntimeService(knowledge_lookup=lookup_context if args.lite else None)
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    return serve_forever(
        path=socket_path(SOCKET_NAME), registry=REGISTRY,
        policy=PrincipalPolicy.resolve(service_accounts=('azmioentry',)),
        audit=lambda event: None, handler=service.handle, stop=stopping.is_set,
        ready=lambda: print(json.dumps({'ready': True, 'role': 'locald',
                                       'pid': os.getpid(), 'lite': args.lite}), flush=True))


if __name__ == '__main__':
    raise SystemExit(main())
