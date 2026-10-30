#!/bin/sh
# Install Azazel-Nexus: accounts, directories, units, and nothing running.
#
# IMPLEMENTATION_SPEC 2.3: installation MUST NOT start an operational network
# service. This script masks every governed unit and starts none. The only
# unit it enables is the activation controller, which opens no network
# socket and reaches no interface. On the next boot it runs one fail-closed
# activation pass over the system D-Bus. Production authenticated evidence
# loaders are not implemented yet, so this pass admits no governed unit.
#
# Everything below is checked against a declaration:
#   - the accounts against azazel_nexus_runtime.hardening.SYSTEM_ACCOUNTS
#   - the directories, modes and owners against azazel_nexus.layout.LAYOUT
#   - the units against what the hardening table renders
# by tests/unit/test_packaging.py and test_runtime_hardening.py. Editing one
# without the other fails CI, so the mandatory defaults in IMPLEMENTATION_SPEC
# 3 cannot drift away from the installer that is supposed to apply them.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

# Files and accounts are installed either way. The service-manager half --
# daemon-reload, mask, enable -- needs a running systemd, and there is no
# honest way to perform it without one.
#
# `--without-service-manager` performs everything else and says loudly that
# the rest did not happen. It is for a packaging or integration run, and the
# marker it prints is what keeps "did not run" from being read as "passed":
# tests/unit/test_e2e_harness.py refuses a report that counts a stage it
# skipped as a success.
#
# `--without-accounts` is the same idea for the half that needs root. Creating
# a system account and setting a directory's owner both do; a packaging or
# integration run on a machine where the caller is not root can do neither,
# and pretending otherwise would install directories whose ownership is
# whoever ran the script.
WITH_SERVICE_MANAGER=yes
WITH_ACCOUNTS=yes
LLAMA_RUNTIME=
while [ "$#" -gt 0 ]; do
    argument=$1
    shift
    case "$argument" in
        --llama-runtime)
            [ "$#" -gt 0 ] && [ -n "$1" ] && [ -z "$LLAMA_RUNTIME" ] || { echo "--llama-runtime needs one path, once" >&2; exit 2; }
            LLAMA_RUNTIME=$1
            shift ;;
        --without-service-manager) WITH_SERVICE_MANAGER=no ;;
        --without-accounts) WITH_ACCOUNTS=no ;;
        *) echo "unknown option: $argument" >&2; exit 2 ;;
    esac
done

# DESTDIR redirects installed files; it does not redirect systemctl. Refuse
# before any host mutation unless the caller explicitly selects the staging
# mode. Account creation is controlled separately below because account and
# group tools likewise operate on the host even when files go to DESTDIR.
if [ -n "${DESTDIR:-}" ] && [ "$WITH_SERVICE_MANAGER" = yes ]; then
    echo "refusing to install: DESTDIR stages files but cannot stage systemd state." >&2
    echo "Pass --without-service-manager to avoid changing the host manager." >&2
    exit 2
fi

if [ "$WITH_ACCOUNTS" = yes ] && [ "$(id -u)" -ne 0 ]; then
    echo "refusing to install: accounts and directory ownership need root." >&2
    echo "Pass --without-accounts to install the files at their declared" >&2
    echo "modes without owners. The daemons will not have accounts to run" >&2
    echo "as, and this script will say so rather than reporting a" >&2
    echo "completed install." >&2
    exit 4
fi

if [ "$WITH_SERVICE_MANAGER" = yes ] && [ ! -d /run/systemd/system ]; then
    echo "refusing to install: systemd is not running on this host." >&2
    echo "Pass --without-service-manager to install the files and accounts" >&2
    echo "only. The units will not be masked or enabled, and this script" >&2
    echo "will say so rather than reporting a completed install." >&2
    exit 3
fi

# The runtime floor, checked before anything is written. 3.11 is where
# `tomllib` enters the standard library, and `tomllib` is the canonical reader
# for the trust anchor a Knowledge Lite bundle is verified against (Nexus#67).
#
# An explicit refusal, not a fallback. A node that installed on 3.10 and then
# could not read a trust anchor would be a node that fails at the moment it is
# asked to verify something -- later, and with less of an explanation.
PYTHON="${PYTHON:-python3}"
if ! PYTHON=$(command -v "$PYTHON"); then
    echo "refusing to install: the selected Python interpreter was not found." >&2
    exit 1
fi
STAGING_PATH=/usr/sbin:/usr/bin:/sbin:/bin
python_fixed() {
    /usr/bin/env -i PATH="$STAGING_PATH" LANG=C.UTF-8 LC_ALL=C.UTF-8 "$PYTHON" "$@"
}
python_stager() {
    if [ -n "${DESTDIR:-}" ]; then
        /usr/bin/env -i PATH="$STAGING_PATH" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
            DESTDIR="$DESTDIR" "$PYTHON" "$@"
    else
        python_fixed "$@"
    fi
}
if ! python_fixed -IS -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "refusing to install: Azazel-Nexus requires Python 3.11 or newer." >&2
    echo "Found: $(python_fixed --version 2>&1)" >&2
    echo "3.11 is where tomllib enters the standard library, and tomllib is" >&2
    echo "what reads the trust anchor a Knowledge Lite bundle verifies" >&2
    echo "against. There is no fallback parser and no partial mode." >&2
    exit 1
fi

# Validate optional prebuilt input before any installation mutation; no network.
if [ -n "$LLAMA_RUNTIME" ]; then
    python_fixed -IS "$REPO_ROOT/tools/install_llama_runtime.py" \
        "$LLAMA_RUNTIME" "${DESTDIR:-}/usr/libexec/azazel/llama-server" --check-only
fi

# Select a declared install profile before writing any files. This is a pure
# os-release/layout projection; it does not inspect HIL compatibility or
# operate the service manager. Unknown platforms are refused, and new physical
# targets are enabled only by adding a reviewed profile rather than a broad
# fallback.
PROFILE_FIELDS="$REPO_ROOT/tools/install_profile_fields.py"
if [ ! -f "$PROFILE_FIELDS" ]; then
    echo "refusing to install: install platform profile tool is missing." >&2
    exit 1
fi
profile_field() {
    set -- --field "$1"
    [ "$WITH_ACCOUNTS" = yes ] || set -- "$@" --without-accounts
    [ "$WITH_SERVICE_MANAGER" = yes ] || set -- "$@" --without-service-manager
    python_fixed -IS "$PROFILE_FIELDS" "$@"
}
if ! INSTALL_PROFILE_ID=$(profile_field profile_id); then
    echo "refusing to install: this host has no reviewed install profile." >&2
    exit 1
fi
# The CPU, read from this host and evaluated against the reviewed platform
# profiles (ADR-0003 R6), before anything is written. An unknown CPU, a dpkg
# userland of another architecture, a non-LP64 libc or another byte order is
# refused with its reason code, and so is a dpkg that cannot be read
# (DPKG_UNOBSERVED): every target is Debian. arm64 is *identified* as the
# lab-software-verification profile and installs exactly as before (the VM
# software rehearsals); that identification admits nothing, and no record,
# admission or hardware gate accepts it as the amd64 deployment baseline.
if ! PLATFORM=$(profile_field platform); then
    echo "refusing to install: this host's CPU is not in a reviewed platform profile." >&2
    exit 1
fi
PLATFORM_ARCHITECTURE=${PLATFORM%% *}
PLATFORM_PURPOSE=${PLATFORM#* }
echo "platform: $PLATFORM_ARCHITECTURE ($PLATFORM_PURPOSE)"
if [ "$PLATFORM_PURPOSE" != deployment-baseline ]; then
    echo "NOTE: $PLATFORM_ARCHITECTURE is a lab-software-verification platform, not the" \
        "deployment baseline. What this install runs is VM software-integration" \
        "evidence only, never hardware-gate evidence or a production admission."
fi
UNIT_DIR=$(profile_field unit_directory) || exit 1
PRESET_DIR=$(profile_field preset_directory) || exit 1
LIBEXEC=$(profile_field libexec_directory) || exit 1
SERVICE_MANAGER=$(profile_field service_manager) || exit 1
REQUIRED_TOOLS=$(profile_field required_tools) || exit 1
if [ "$SERVICE_MANAGER" != systemd ]; then
    echo "refusing to install: this profile has no supported service-manager adapter." >&2
    exit 1
fi
while IFS= read -r tool; do
    [ -n "$tool" ] || continue
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "refusing to install: reviewed profile requires missing tool $tool." >&2
        exit 1
    fi
done <<EOF
$REQUIRED_TOOLS
EOF

# The Deception Lite AppArmor profiles (#196 G3) must compile before anything
# is written: each exposure unit names its profile without `-`, so a profile
# apparmor.service cannot load is a unit that cannot start. Compiled only,
# never loaded here (the package's apparmor.service loads /etc/apparmor.d at
# boot); with the service manager only, since apparmor_parser is required
# only then. No unit is granted by this, and the pass never grants them yet.
if [ "$WITH_SERVICE_MANAGER" = yes ]; then
    # The decoy namespace unit runs the system's iproute2 ip by this fixed
    # path from its unit file (#196 G4 follow-up; hardening.DECOY_NAMESPACE_IP,
    # a test keeps them equal). Nexus does not stage it, so check it here.
    if [ ! -x /usr/bin/ip ]; then
        echo "refusing to install: /usr/bin/ip is missing (install the Debian package iproute2)." >&2
        exit 1
    fi
    for profile in azazel-decoy-nsd azazel-decoy-netd azazel-decoy-verify azazel-decoyd; do
        if ! apparmor_parser --skip-kernel-load --skip-cache --quiet "$HERE/apparmor/$profile"; then
            echo "refusing to install: AppArmor profile $profile does not compile." >&2
            exit 1
        fi
    done
    # A kernel without AppArmor ignores AppArmorProfile=; the three units'
    # AssertSecurity=apparmor then fails their start, so they never run
    # unconfined. Say so now rather than at the first start.
    lsm=
    if [ -r /sys/kernel/security/lsm ]; then
        read -r lsm < /sys/kernel/security/lsm || true
    fi
    case ",$lsm," in
        *,apparmor,*) ;;
        *)
            echo "WARNING: AppArmor is not enabled in this kernel. The Deception Lite" >&2
            echo "units (azazel-decoy-nsd, azazel-decoy-netd, azazel-decoy-verify," >&2
            echo "azazel-decoyd) cannot" >&2
            echo "start here, and their tier is never granted. Nothing else changes." >&2
            ;;
    esac
    # A child profile or hat of a decoy profile still loaded in the kernel
    # (the former azazel-decoy-nsd//ip of before the G4 follow-up) survives
    # a replacement of its parent; the pass is to withhold the tier while one
    # is listed (decoy_apparmor). Detected only: nothing is loaded,
    # replaced or removed here (docs/operations.md, "Removing a stale decoy
    # child profile").
    if [ -r /sys/kernel/security/apparmor/profiles ] && grep -qE \
        '^azazel-decoy(-nsd|-netd|-verify|d)//' /sys/kernel/security/apparmor/profiles; then
        echo "NOTICE: a child profile of a Deception Lite AppArmor profile is still"
        echo "loaded in the kernel. The Deception Lite tier is withheld until it is"
        echo "gone: reboot, or, with the decoy units stopped, remove the parent"
        echo "profile from the kernel and load it again (docs/operations.md,"
        echo "\"Removing a stale decoy child profile\"). Nothing was loaded or removed."
    fi
    # end of the stale child check
fi
UNIT_DIR="${DESTDIR:-}$UNIT_DIR"
PRESET_DIR="${DESTDIR:-}$PRESET_DIR"
LIBEXEC="${DESTDIR:-}$LIBEXEC"

# The venv's ordinary console scripts live in its bin/ directory, while the
# packaged units use fixed paths under /usr/libexec/azazel. Generate those
# wrappers from the source/runtime declarations, and verify every import
# before changing accounts, Nexus state directories, or systemd state.
STAGER="$REPO_ROOT/tools/stage_runtime_entrypoints.py"
if [ ! -f "$STAGER" ]; then
    echo "refusing to install: runtime entrypoint staging tool is missing." >&2
    exit 1
fi
if ! python_stager -IS "$STAGER" --python "$PYTHON" \
    --platform-profile "$INSTALL_PROFILE_ID"; then
    echo "refusing to install: runtime entrypoints could not be staged." >&2
    exit 1
fi

# The unit files name these. An installer that enabled a unit whose ExecStart
# does not exist would "succeed" into a boot failure, which is later and on
# someone else's hardware.
for binary in az-activated az-commissiond az-auditd az-auditd-loop az-watchdog az-edge-intaked az-incident-explaind az-edge-probed az-model-fetchd az-mio-locald az-mio-identity az-mio-remoted az-mio-entryd az-mio-referenced az-knowledge-lited az-decoy-netd az-decoyd az-units-observe az-noc-observe az-ui; do
    if [ ! -x "$LIBEXEC/$binary" ]; then
        echo "refusing to install: $LIBEXEC/$binary is missing." >&2
        echo "Install azazel-nexus and azazel-nexus-runtime into the stable" >&2
        echo "Python environment, then stage the fixed wrappers with" >&2
        echo "tools/stage_runtime_entrypoints.py under $LIBEXEC." >&2
        exit 1
    fi
done

# The decoy wrappers' interpreter and import paths must be what the
# Deception Lite AppArmor profiles allow (#196 G3): /usr/bin/python3.13 and
# code under /usr/lib/python3.13 or /opt/azazel-nexus/venv. A wrapper outside
# them would be refused by its profile at the first start, so the install is
# refused here: after the wrappers are staged, before any account or unit is
# touched (a refused run leaves only the staged wrappers). A DESTDIR staging run (no service manager) uses another
# interpreter, so there it only warns.
if [ "$WITH_SERVICE_MANAGER" = yes ]; then
    python_fixed -IS "$REPO_ROOT/tools/check_decoy_apparmor_wrappers.py" "$LIBEXEC" || exit 1
else
    python_fixed -IS "$REPO_ROOT/tools/check_decoy_apparmor_wrappers.py" --warn-only "$LIBEXEC"
fi

# Non-login accounts with no shell and no home. Each daemon gets its own, so
# that a fault in one does not run with another's access.
if [ "$WITH_ACCOUNTS" = yes ]; then
    for account in azcommission azaudit azwatch azprobe azintake azexplain azedge azfetch azmio azmioentry azmioref azremote azknowledge azdecoy aznoc azui; do
        if ! getent passwd "$account" >/dev/null 2>&1; then
            # Each account's own group is relied on (azedge for the intake
            # socket, azknowledge for lite-trust), so it is made explicitly
            # rather than left to the distribution's USERGROUPS_ENAB default.
            if getent group "$account" >/dev/null 2>&1; then
                useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$account" "$account"
            else
                useradd --system --no-create-home --shell /usr/sbin/nologin --user-group "$account"
            fi
        fi
    done
    if ! getent group azincident-read >/dev/null 2>&1; then
        groupadd --system azincident-read
    fi
    if ! getent group azknowledge-read >/dev/null 2>&1; then
        groupadd --system azknowledge-read
    fi
    if ! getent group azmission-read >/dev/null 2>&1; then
        groupadd --system azmission-read
    fi
    # The explainer's own audit and M.I.O. entry listeners. Nobody is added
    # to them: the explainer unit carries them as SupplementaryGroups, so it
    # needs no azazel-operator membership to reach those two daemons. The
    # Knowledge Lite and commissioning units carry azaudit-submit the same
    # way, for their import and revocation records.
    if ! getent group azaudit-submit >/dev/null 2>&1; then
        groupadd --system azaudit-submit
    fi
    if ! getent group azmio-advise >/dev/null 2>&1; then
        groupadd --system azmio-advise
    fi
    if ! getent group azazel-operator >/dev/null 2>&1; then
        groupadd --system azazel-operator
    fi
else
    echo "ACCOUNT STAGE NOT EXECUTED: no account or group was created, and"
    echo "no directory was given an owner. The modes below are applied; the"
    echo "ownership the layout declares is not."
fi

# One declaration, two ways of applying it. The ownership is what needs root,
# so it is the part that varies; the mode never does.
make_dir() {  # mode group path
    if [ "$WITH_ACCOUNTS" = yes ]; then
        install -d -m "$1" -o root -g "$2" "${DESTDIR:-}$3"
    else
        install -d -m "$1" "${DESTDIR:-}$3"
    fi
}
make_owned_dir() {  # mode owner group path
    if [ "$WITH_ACCOUNTS" = yes ]; then
        install -d -m "$1" -o "$2" -g "$3" "${DESTDIR:-}$4"
    else
        install -d -m "$1" "${DESTDIR:-}$4"
    fi
}

make_dir 0755 root /etc/azazel
make_dir 0750 azcommission /etc/azazel/commissioning
make_dir 0700 root /etc/azazel/mio-profile
# Earlier releases left the raw-identity proposal copies here (#244). Remove
# only those two fixed ordinary files; the reviewed signature stays.
python_fixed -IS "$REPO_ROOT/tools/purge_mio_profile_copies.py" "${DESTDIR:-}/etc/azazel/mio-profile"
make_dir 0700 root /etc/azazel/bootstrap
make_dir 0700 root /etc/azazel/activation
make_dir 0755 root /etc/azazel/systemd
# Common parents allow traversal only. Operators get to each socket by group;
# daemon accounts write only their own service-owned leaf directory.
make_dir 0711 root /var/lib/azazel
make_owned_dir 0700 azedge root /var/lib/azazel/edge-core
# The Deception Lite decoy's private state (#196 P1). Created like every
# other governed unit's leaf; the unit itself stays masked.
make_owned_dir 0700 azdecoy root /var/lib/azazel/decoy
make_dir 0711 root /var/lib/azazel/run
# Linux setgid-directory semantics make each service's socket inherit the
# operator GID while retaining the daemon's primary GID for SO_PEERCRED. The
# runtime verifies the resulting socket GID and refuses if the filesystem or
# host does not provide the declared behavior.
make_owned_dir 2710 azaudit azazel-operator /var/lib/azazel/run/audit
make_owned_dir 2710 azaudit azaudit-submit /var/lib/azazel/run/audit-submit
# auditd's capacity snapshot (#211): sizes and counts only, never records.
make_owned_dir 2750 azaudit azazel-operator /var/lib/azazel/run/audit-status
# Operator-readable snapshots (U2): codes and counts only, each written by
# the one daemon that owns the facts. Same pattern as audit-status.
make_owned_dir 2750 azknowledge azazel-operator /var/lib/azazel/run/knowledge-status
make_owned_dir 2750 azmioentry azazel-operator /var/lib/azazel/run/mio-status
make_owned_dir 2750 azprobe azazel-operator /var/lib/azazel/run/units-status
make_owned_dir 2750 aznoc azazel-operator /var/lib/azazel/run/noc-status
make_owned_dir 2710 azcommission azazel-operator /var/lib/azazel/run/commission
make_owned_dir 2710 azwatch azazel-operator /var/lib/azazel/run/watchdog
# Not a socket leaf: the Edge probe's result, renamed into place inside it.
# Group-readable (not traversal-only) so `azazel-nexus status` can read it.
make_owned_dir 2750 azprobe azazel-operator /var/lib/azazel/run/edge-probe
# The read-only UI's copies (ADR-0007): each snapshot writer puts a
# byte-identical copy of its operator snapshot into its own leaf here, and the
# setgid group azui reads it. azui joins no group; nothing here is a socket.
make_dir 0711 root /var/lib/azazel/run/ui-read
make_owned_dir 2750 azaudit azui /var/lib/azazel/run/ui-read/audit
make_owned_dir 2750 azintake azui /var/lib/azazel/run/ui-read/edge-intake
make_owned_dir 2750 azexplain azui /var/lib/azazel/run/ui-read/incident-explain
make_owned_dir 2750 azknowledge azui /var/lib/azazel/run/ui-read/knowledge
make_owned_dir 2750 azmioentry azui /var/lib/azazel/run/ui-read/mio
make_owned_dir 2750 azprobe azui /var/lib/azazel/run/ui-read/units
make_owned_dir 2750 aznoc azui /var/lib/azazel/run/ui-read/noc
# The read-only UI's login code (U5): azui writes it, the operator group reads
# it with `azazel-nexus ui-login`. azui itself is in no group but its own.
make_owned_dir 2750 azui azazel-operator /var/lib/azazel/run/ui-login
make_owned_dir 2750 azintake azincident-read /var/lib/azazel/edge-incidents
make_owned_dir 0700 azexplain root /var/lib/azazel/incident-explain
make_owned_dir 2750 azexplain azazel-operator /var/lib/azazel/run/incident-explain-status
make_owned_dir 0700 azintake root /var/lib/azazel/edge-intake
make_owned_dir 2710 azintake azedge /var/lib/azazel/run/edge-intake
# The decoy's interactions reach the intake here (#196 P2), on a leaf of its
# own and with the decoy's own group: no new group, and the decoy never gets
# Edge's socket.
make_owned_dir 2710 azintake azdecoy /var/lib/azazel/run/decoy-intake
make_owned_dir 2750 azintake azazel-operator /var/lib/azazel/run/edge-intake-status
make_dir 0711 root /var/lib/azazel/state
make_owned_dir 0700 azaudit root /var/lib/azazel/state/audit
make_owned_dir 0700 azaudit root /var/lib/azazel/state/auditd
make_owned_dir 0700 azcommission root /var/lib/azazel/state/commission
make_owned_dir 0700 azwatch root /var/lib/azazel/state/watchdog
make_dir 0700 root /var/lib/azazel/state/bootstrap
make_dir 0700 root /var/lib/azazel/state/bootstrap-overlay
make_dir 0700 root /var/lib/azazel/generations
make_dir 0700 root /var/lib/azazel/bootstrap-generations
make_dir 0750 azfetch /var/lib/azazel/fetch
make_dir 0750 azmio /etc/azazel/model-admission
make_dir 0750 azmio /etc/azazel/model-admission/evidence
make_dir 0750 azmio /etc/azazel/model-admission/evidence/artifacts
make_dir 0750 azmio /var/lib/azazel/models
make_dir 2750 azmio /var/lib/azazel/models/staging
make_dir 2750 azmio /var/lib/azazel/models/store
make_dir 0750 azfetch /var/lib/azazel/fetch/commission
make_owned_dir 0750 azfetch azfetch /var/lib/azazel/fetch/partial
make_owned_dir 0750 azfetch azfetch /var/lib/azazel/fetch/ready
make_owned_dir 2710 azfetch azazel-operator /var/lib/azazel/run/fetch
make_owned_dir 0750 azmio azmio /var/lib/azazel/mio
make_dir 0750 azremote /var/lib/azazel/remote
make_owned_dir 2750 azcommission azknowledge /var/lib/azazel/lite-trust
make_owned_dir 0700 azmioentry root /var/lib/azazel/state/mio
make_owned_dir 0700 azknowledge root /var/lib/azazel/state/knowledge
make_owned_dir 0700 azmioref root /var/lib/azazel/state/mio-reference
make_owned_dir 2710 azmioentry azazel-operator /var/lib/azazel/run/mio-entry
make_owned_dir 2710 azmioentry azmio-advise /var/lib/azazel/run/mio-advise
make_owned_dir 2710 azmio azazel-operator /var/lib/azazel/run/mio
make_owned_dir 2710 azmioref azazel-operator /var/lib/azazel/run/mio-reference
make_owned_dir 2710 azremote azazel-operator /var/lib/azazel/run/remote
make_owned_dir 2710 azknowledge azazel-operator /var/lib/azazel/run/knowledge
make_owned_dir 2710 azknowledge azknowledge-read /var/lib/azazel/run/knowledge-read
make_owned_dir 2750 azknowledge azazel-operator /var/lib/azazel/knowledge
make_dir 0700 root /var/lib/azazel/secrets

# No pack data is created on an unverified backing volume. DESTDIR is only a
# staging projection; production uses the same LUKS check as the pack CLI.
set --
[ "$WITH_ACCOUNTS" = yes ] || set -- --without-accounts
python_stager -IS "$REPO_ROOT/tools/provision_mission_read.py" "$@"

if [ -n "$LLAMA_RUNTIME" ]; then
    python_fixed -IS "$REPO_ROOT/tools/install_llama_runtime.py" \
        "$LLAMA_RUNTIME" "${DESTDIR:-}/usr/libexec/azazel/llama-server"
fi

install -d -m 0755 "$UNIT_DIR" "$PRESET_DIR"
install -m 0644 "$HERE"/systemd/azazel-activated.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-commissiond.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-auditd.service "$UNIT_DIR"
# The integrated loop's audit writer (ADR 0008): az-auditd again, granted by
# the ordinary pass. Masked below like every governed unit.
install -m 0644 "$HERE"/systemd/azazel-auditd-loop.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-watchdog.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-edge-core.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-edge-probed.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-edge-probe-preflight.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-incident-explaind.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-edge-intaked.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-model-fetchd.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-mio-locald.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-mio-remoted.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-mio-entryd.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-mio-referenced.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-knowledge-lited.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-decoy-nsd.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-decoy-netd.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-decoyd.service "$UNIT_DIR"
# The Deception Lite watch (#196 G2): the verify unit, its timer and the trip
# unit. No [Install] section and never masked or enabled: the decoy pulls the
# first two in, and the verify unit's failure starts the third. Each can only
# read or stop.
install -m 0644 "$HERE"/systemd/azazel-decoy-verify.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-decoy-verify.timer "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-decoy-trip.target "$UNIT_DIR"
# The operator observers (U2): a oneshot and its timer. Not governed, never
# masked, and not enabled here: an operator enables the timer. Nothing
# requires or binds to them, so stopping them stops nothing else.
install -m 0644 "$HERE"/systemd/azazel-units-observe.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-units-observe.timer "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-noc-observe.service "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-noc-observe.timer "$UNIT_DIR"
# The read-only operator UI (U5): its socket and service. Not governed, not
# masked and not enabled here (the preset says disable); an operator who wants
# it enables azazel-ui.socket itself (docs/operator-ui.md). Nothing requires it.
install -m 0644 "$HERE"/systemd/azazel-ui.socket "$UNIT_DIR"
install -m 0644 "$HERE"/systemd/azazel-ui.service "$UNIT_DIR"
install -m 0644 "$HERE"/azazel-nexus.preset "$PRESET_DIR"/99-azazel-nexus.preset
install -d -m 0755 "${DESTDIR:-}/usr/lib/tmpfiles.d"
install -m 0644 "$HERE"/tmpfiles.d/azazel-nexus-bootstrap.conf "${DESTDIR:-}/usr/lib/tmpfiles.d/azazel-nexus-bootstrap.conf"
# The Deception Lite AppArmor profiles (#196 G3), one per exposure unit and
# one for the verify unit (#196 G2), each named by its unit's
# AppArmorProfile=. Placed, not loaded: apparmor.service loads them at the
# next boot, before any unit could start.
install -d -m 0755 "${DESTDIR:-}/etc/apparmor.d"
install -m 0644 "$HERE"/apparmor/azazel-decoy-nsd "${DESTDIR:-}/etc/apparmor.d/azazel-decoy-nsd"
install -m 0644 "$HERE"/apparmor/azazel-decoy-netd "${DESTDIR:-}/etc/apparmor.d/azazel-decoy-netd"
install -m 0644 "$HERE"/apparmor/azazel-decoy-verify "${DESTDIR:-}/etc/apparmor.d/azazel-decoy-verify"
install -m 0644 "$HERE"/apparmor/azazel-decoyd "${DESTDIR:-}/etc/apparmor.d/azazel-decoyd"
# The policy hash of each placed profile as compiled (#196 G6 prep K;
# docs/deception-exposure-wiring.md 5.2): each compiled with -Q -o into a
# private temporary file (skip the kernel load, no other flag), its SHA-256
# recorded in /etc/azazel/activation/apparmor-compiled.json (root, 0644,
# written atomically). Nothing is loaded; apparmor.service loads the profiles
# at the next boot. With the service manager only: a DESTDIR or
# --without-service-manager run writes no record. Nothing reads it in this
# build (G6's generation-publish will). A failure refuses the install.
if [ "$WITH_SERVICE_MANAGER" = yes ]; then
    python_fixed -IS "$REPO_ROOT/tools/record_apparmor_compiled.py" || exit 1
fi

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
systemctl mask azazel-auditd-loop.service
systemctl mask azazel-watchdog.service
systemctl mask azazel-edge-core.service
systemctl mask azazel-edge-probed.service
systemctl mask azazel-incident-explaind.service
systemctl mask azazel-edge-intaked.service
systemctl mask azazel-model-fetchd.service
systemctl mask azazel-mio-locald.service
systemctl mask azazel-mio-remoted.service
systemctl mask azazel-mio-entryd.service
systemctl mask azazel-mio-referenced.service
systemctl mask azazel-knowledge-lited.service
# Deception Lite exposure (#196 P1, and the namespace unit of option (a)):
# masked like every governed unit. No pass grants them in this build, so they
# stay masked.
systemctl mask azazel-decoy-nsd.service
systemctl mask azazel-decoy-netd.service
systemctl mask azazel-decoyd.service

# Resolve this fixed rule name through tmpfiles configuration precedence so
# administrator overrides are not bypassed. The vendor rule preserves existing
# mode/ownership and has no cleanup or helper publication/unmask operation.
# DESTDIR staging exits before this point and never invokes host tmpfiles.
systemd-tmpfiles --create azazel-nexus-bootstrap.conf

# Enabled, not started: the controller runs at the next boot, which is where
# revalidation belongs. Starting it here would activate against a generation
# that the operator has not yet promoted.
systemctl enable azazel-activated.service

# The Edge probe's boot preflight (#206 P5) is not governed and not masked:
# it runs the same fixed, read-only, AF_UNIX-only probe as azprobe before the
# controller, so the pass sees Edge health from this boot. It opens no
# network socket and can only narrow what a pass grants. Enabled, not started.
systemctl enable azazel-edge-probe-preflight.service

echo "Azazel-Nexus installed. Operational units are masked."
echo "The next boot records a fail-closed activation decision; no unit is"
echo "admitted until the required admission and health evidence is available."
