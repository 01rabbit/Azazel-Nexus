#!/bin/sh
# Install Azazel-Nexus: accounts, directories, units, and nothing running.
#
# IMPLEMENTATION_SPEC 2.3: installation MUST NOT start an operational network
# service. This script masks every governed unit and starts none. The only
# unit it enables is the activation controller, which opens no socket and
# reaches no interface; on the next boot the controller revalidates the
# current generation and unmasks what that generation admits.
#
# Everything below is checked against a declaration:
#   - the accounts against azazel_nexus_runtime.hardening.SYSTEM_ACCOUNTS
#   - the directories, modes and owners against azazel_nexus.layout.LAYOUT
#   - the units against what the hardening table renders
# by tests/unit/test_packaging.py and test_runtime_hardening.py. Editing one
# without the other fails CI, so the mandatory defaults in IMPLEMENTATION_SPEC
# 3 cannot drift away from the installer that is supposed to apply them.
set -eu

UNIT_DIR="${DESTDIR:-}/lib/systemd/system"
PRESET_DIR="${DESTDIR:-}/lib/systemd/system-preset"
LIBEXEC="${DESTDIR:-}/usr/libexec/azazel"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Files and accounts are installed either way. The service-manager half --
# daemon-reload, mask, enable -- needs a running systemd, and there is no
# honest way to perform it without one.
#
# `--without-service-manager` performs everything else and says loudly that
# the rest did not happen. It is for a packaging or integration run, and the
# marker it prints is what keeps "did not run" from being read as "passed":
# tests/unit/test_e2e_harness.py refuses a report that counts a stage it
# skipped as a success.
WITH_SERVICE_MANAGER=yes
for argument in "$@"; do
    case "$argument" in
        --without-service-manager) WITH_SERVICE_MANAGER=no ;;
        *) echo "unknown option: $argument" >&2; exit 2 ;;
    esac
done

if [ "$WITH_SERVICE_MANAGER" = yes ] && [ ! -d /run/systemd/system ]; then
    echo "refusing to install: systemd is not running on this host." >&2
    echo "Pass --without-service-manager to install the files and accounts" >&2
    echo "only. The units will not be masked or enabled, and this script" >&2
    echo "will say so rather than reporting a completed install." >&2
    exit 3
fi

# The unit files name these. An installer that enabled a unit whose ExecStart
# does not exist would "succeed" into a boot failure, which is later and on
# someone else's hardware.
for binary in az-activated az-commissiond az-auditd az-watchdog; do
    if [ ! -x "$LIBEXEC/$binary" ]; then
        echo "refusing to install: $LIBEXEC/$binary is missing." >&2
        echo "Install the azazel-nexus-runtime distribution first and place" >&2
        echo "its console scripts under $LIBEXEC." >&2
        exit 1
    fi
done

# Non-login accounts with no shell and no home. Each daemon gets its own, so
# that a fault in one does not run with another's access.
for account in azcommission azaudit azwatch; do
    if ! getent passwd "$account" >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$account"
    fi
done
if ! getent group azazel-operator >/dev/null 2>&1; then
    groupadd --system azazel-operator
fi

install -d -m 0755 -o root -g root "${DESTDIR:-}"/etc/azazel
install -d -m 0750 -o root -g azcommission "${DESTDIR:-}"/etc/azazel/commissioning
install -d -m 0755 -o root -g root "${DESTDIR:-}"/etc/azazel/systemd
install -d -m 0750 -o root -g root "${DESTDIR:-}"/var/lib/azazel
install -d -m 0750 -o root -g azazel-operator "${DESTDIR:-}"/var/lib/azazel/run
install -d -m 0750 -o root -g azaudit "${DESTDIR:-}"/var/lib/azazel/state
install -d -m 0700 -o root -g root "${DESTDIR:-}"/var/lib/azazel/generations
install -d -m 0700 -o root -g root "${DESTDIR:-}"/var/lib/azazel/secrets

install -d -m 0755 "$UNIT_DIR" "$PRESET_DIR"
install -m 0644 "$HERE"/systemd/azazel-activated.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-commissiond.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-auditd.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-watchdog.service "$UNIT_DIR"
install -m 0644 "$HERE"/azazel-nexus.preset "$PRESET_DIR"/99-azazel-nexus.preset

if [ "$WITH_SERVICE_MANAGER" = no ]; then
    echo "SERVICE-MANAGER STAGE NOT EXECUTED: no unit was masked or enabled."
    echo "Files and accounts are installed. The node is not configured to"
    echo "start anything, and nothing here established that it would not."
    exit 0
fi

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
