#!/usr/bin/env python3
"""Start `az-ui` the way `azazel-ui.socket` does, without systemd (demo, tests).

    python tools/ui_socket_activate.py [--port 8443] -- az-ui --fixture FILE

Binds a listening TCP socket on **127.0.0.1 only** (no option names another
address), places it at descriptor 3, sets `LISTEN_PID`/`LISTEN_FDS` as the
socket-activation protocol does and replaces itself with the command, so the
UI receives exactly what systemd would hand it. On a host with systemd,
`systemd-socket-activate -l 127.0.0.1:8443 az-ui --fixture FILE` is the same.

This is a development and demonstration tool. It is not installed, no unit
runs it, and the UI itself still never binds or listens.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command to run is required after --")
    if not 0 < args.port < 65536:
        parser.error("port out of range")
    listener = socket.create_server(("127.0.0.1", args.port), backlog=16)
    if listener.fileno() != 3:
        os.dup2(listener.fileno(), 3)
        listener.close()
    os.set_inheritable(3, True)
    os.environ["LISTEN_PID"] = str(os.getpid())
    os.environ["LISTEN_FDS"] = "1"
    os.environ.pop("LISTEN_FDNAMES", None)
    os.execvp(command[0], command)
    return 1  # pragma: no cover - execvp does not return


if __name__ == "__main__":
    sys.exit(main())
