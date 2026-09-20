#!/bin/sh
# Install Azazel-Nexus: files, directories, and nothing running.
#
# IMPLEMENTATION_SPEC 2.3: installation MUST NOT start an operational network
# service. This script therefore masks every governed unit and starts none.
# The only unit it enables is the activation controller, which opens no socket
# and reaches no interface; on the next boot the controller revalidates the
# current generation and unmasks what that generation admits.
#
# The directory list below is checked against src/azazel_nexus/layout.py by
# tests/unit/test_packaging.py. Editing one without the other fails CI, so the
# mandatory defaults in IMPLEMENTATION_SPEC 3 cannot drift away from the
# installer that is supposed to apply them.
set -eu

# This slice ships the activation controller's *logic* and its unit files. It
# does not ship the daemon executables the units name: the package imports
# nothing that can spawn a process (tests/unit/test_boundary_static.py), and
# the entry points arrive with the operator interface.
#
# So the installer refuses rather than leaving a host with an enabled unit
# whose ExecStart does not exist. An installer that "succeeds" into a boot
# loop is the failure this check exists to prevent, and saying so here is
# cheaper than discovering it on a rugged PC.
LIBEXEC=/usr/libexec/azazel
for binary in az-activated az-commissiond az-auditd az-watchdog; do
    if [ ! -x "$LIBEXEC/$binary" ]; then
        echo "refusing to install: $LIBEXEC/$binary is missing." >&2
        echo "The unit files name it; enabling a unit whose ExecStart does" >&2
        echo "not exist would fail at boot with nothing masked in return." >&2
        exit 1
    fi
done

UNIT_DIR=/lib/systemd/system
PRESET_DIR=/lib/systemd/system-preset
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -d -m 0755 /etc/azazel
install -d -m 0755 /etc/azazel/commissioning
install -d -m 0755 /etc/azazel/systemd
install -d -m 0750 /var/lib/azazel
install -d -m 0750 /var/lib/azazel/run
install -d -m 0750 /var/lib/azazel/state
install -d -m 0700 /var/lib/azazel/generations
install -d -m 0700 /var/lib/azazel/secrets

install -d -m 0755 "$UNIT_DIR" "$PRESET_DIR"
install -m 0644 "$HERE"/systemd/azazel-activated.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-commissiond.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-auditd.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-watchdog.service "$UNIT_DIR"
install -m 0644 "$HERE"/azazel-nexus.preset "$PRESET_DIR"/99-azazel-nexus.preset

systemctl daemon-reload

# Masked, not merely disabled. A disabled unit is one `systemctl start` away
# from running; a masked one refuses until the activation controller unmasks
# it, which it does only against a generation whose digest it just re-derived.
systemctl mask azazel-commissiond.service
systemctl mask azazel-auditd.service
systemctl mask azazel-watchdog.service

# Enabled, not started: the controller runs at the next boot, which is where
# revalidation belongs. Starting it here would activate against a generation
# that the operator has not yet promoted.
systemctl enable azazel-activated.service

echo "Azazel-Nexus installed. Operational units are masked."
echo "Run commissioning, promote a generation, then reboot."
