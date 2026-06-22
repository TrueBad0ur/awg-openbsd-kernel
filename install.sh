#!/bin/sh
# AmneziaWG for OpenBSD — install script
# Run as root on OpenBSD 7.x amd64
#
# Usage:
#   sh install.sh --tools-only   # build awg + awg-quick (no reboot needed)
#   sh install.sh --kernel-only  # build and install AWG kernel
#   sh install.sh --all          # everything (default)

set -e

SCRIPT=$(readlink -f "$0")
REPODIR=$(dirname "$SCRIPT")
DEPSDIR="$REPODIR/dependencies"
SRCDIR=/usr/src/sys
LOGFILE=/tmp/awg-install.log

log()  { echo "==> $*"; echo "==> $*" >> "$LOGFILE"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
step() { echo ""; echo "──── $* ────"; }

check_root() {
    [ "$(id -u)" -eq 0 ] || die "Run as root"
}

# ── 1. System packages ────────────────────────────────────────────────────────

install_packages() {
    step "System packages"

    if ! command -v git >/dev/null 2>&1; then
        log "Installing git"; pkg_add git
    fi
    if ! command -v bash >/dev/null 2>&1; then
        log "Installing bash"; pkg_add bash
    fi
    if ! command -v ginstall >/dev/null 2>&1; then
        log "Installing coreutils (ginstall)"; pkg_add coreutils
    fi
    if ! command -v gmake >/dev/null 2>&1; then
        log "Installing gmake"; pkg_add gmake
    fi

    log "Packages OK"
}

install_kernel_packages() {
    step "Kernel build packages"

    # kernel sources — needed to build AWG.MP
    # Validate sources are not corrupted (files.rasops being all-zero is a known bad-extraction symptom)
    if [ ! -f "$SRCDIR/net/if_wg.c" ] || ! grep -q 'OpenBSD' "$SRCDIR/dev/rasops/files.rasops" 2>/dev/null; then
        local ver mirror url
        ver=$(uname -r)
        mirror="https://cdn.openbsd.org/pub/OpenBSD/${ver}"
        url="${mirror}/sys.tar.gz"
        log "Fetching kernel sources from $url"
        # Verify the file exists before downloading
        ftp -o /dev/null "$url" 2>/dev/null \
            || die "Kernel sources not found at $url — CDN only carries 7.7+. For older versions, download sys.tar.gz manually from a mirror and extract to /usr/src"
        mkdir -p /usr/src
        ftp -o /tmp/sys.tar.gz "$url" \
            || die "Failed to download sys.tar.gz"
        tar -C /usr/src -xzf /tmp/sys.tar.gz \
            || die "Failed to extract sys.tar.gz"
        rm -f /tmp/sys.tar.gz
        [ -f "$SRCDIR/net/if_wg.c" ] \
            || die "sys.tar.gz extracted but $SRCDIR/net/if_wg.c not found"
        log "Kernel sources installed to /usr/src"
    fi

    # python3 — used to patch conf/files idempotently
    if ! command -v python3 >/dev/null 2>&1; then
        log "Installing python3"; pkg_add python3
    fi

    log "Kernel packages OK"
}

# ── 2. Submodules ─────────────────────────────────────────────────────────────

fetch_submodules() {
    step "Git submodules"

    cd "$REPODIR"

    if [ -d "$REPODIR/.git" ]; then
        # Allow git to operate in this repo regardless of directory ownership
        git config --global --add safe.directory "$REPODIR"
        git config --global --add safe.directory "$DEPSDIR/amneziawg-tools"
        git config --global --add safe.directory "$DEPSDIR/amneziawg-go"
        if [ ! -f "$DEPSDIR/amneziawg-tools/src/Makefile" ]; then
            log "Initialising submodules"
            git submodule update --init --recursive
        else
            log "Updating submodules"
            git submodule update --recursive
        fi
    else
        log "No .git found — skipping submodule update (run 'git submodule update --init --recursive' after git init)"
    fi

    [ -f "$DEPSDIR/amneziawg-tools/src/Makefile" ] \
        || die "amneziawg-tools not found at $DEPSDIR/amneziawg-tools/src/Makefile — populate submodules first"

    log "Submodules OK"
}

# ── 3. amneziawg-tools (awg + awg-quick) ─────────────────────────────────────

install_tools() {
    step "amneziawg-tools (awg + awg-quick)"

    cd "$DEPSDIR/amneziawg-tools/src"
    gmake clean 2>/dev/null || true
    gmake
    # Install to /usr/bin so awg takes priority over any pre-existing /usr/local/bin binary
    gmake install \
        PREFIX=/usr \
        WITH_WGQUICK=yes \
        SYSCONFDIR=/etc

    # awg-quick is a bash script — fix shebang if needed
    if ! head -1 /usr/bin/awg-quick | grep -q bash; then
        log "Fixing awg-quick shebang"
        sed -i 's|#!/.*bash|#!/usr/local/bin/bash|' /usr/bin/awg-quick
    fi

    log "awg + awg-quick installed to /usr/bin/"
}

# ── 4. AWG kernel driver ──────────────────────────────────────────────────────

install_kernel() {
    step "AWG kernel driver"

    # Copy driver files into kernel source tree
    log "Copying driver files to $SRCDIR/net/"
    cp "$REPODIR/src/if_awg.h" "$SRCDIR/net/if_awg.h"
    cp "$REPODIR/src/if_awg.c" "$SRCDIR/net/if_awg.c"
    cp "$REPODIR/src/AWG.MP"   "$SRCDIR/arch/amd64/conf/AWG.MP"

    # Patch conf/files to register the pseudo-device (idempotent)
    if grep -q 'pseudo-device awg' "$SRCDIR/conf/files"; then
        log "conf/files already patched"
    else
        log "Patching $SRCDIR/conf/files"
        python3 - <<'PYEOF'
path = "/usr/src/sys/conf/files"
with open(path) as f:
    c = f.read()
c = c.replace(
    "pseudo-device wg: ifnet\n",
    "pseudo-device wg: ifnet\npseudo-device awg: ifnet\n"
)
c = c.replace(
    "file net/if_wg.c\t\t\twg\n",
    "file net/if_wg.c\t\t\twg\nfile net/if_awg.c\t\t\tawg\n"
)
assert "pseudo-device awg" in c, "patch failed — wg entry not found in conf/files"
with open(path, "w") as f:
    f.write(c)
PYEOF
    fi

    # Generate kernel build directory
    log "Configuring AWG.MP"
    cd "$SRCDIR/arch/amd64/conf"
    config AWG.MP

    # Build (takes ~15 min)
    log "Building kernel — this takes ~15 minutes"
    cd "$SRCDIR/arch/amd64/compile/AWG.MP"
    make -j"$(sysctl -n hw.ncpu)" 2>&1 | tee -a "$LOGFILE"
    make install

    log "Kernel installed to /bsd — reboot to activate"
}

# ── 5. Config directory ───────────────────────────────────────────────────────

setup_confdir() {
    if [ ! -d /etc/amnezia/amneziawg ]; then
        log "Creating /etc/amnezia/amneziawg"
        mkdir -p /etc/amnezia/amneziawg
        chmod 700 /etc/amnezia/amneziawg
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $0 [--tools-only | --kernel-only | --all]

  --tools-only   Install awg + awg-quick CLI tools (no reboot needed)
  --kernel-only  Build and install AWG kernel (requires reboot)
  --all          Install everything: tools + kernel (default)

After --all or --kernel-only: reboot to activate the AWG kernel.
Place your config in /etc/amnezia/amneziawg/<name>.conf, then:
  awg-quick up <name>
  awg-quick down <name>
EOF
    exit 0
}

MODE=all
case "${1:-}" in
    --tools-only)  MODE=tools ;;
    --kernel-only) MODE=kernel ;;
    --all|"")      MODE=all ;;
    -h|--help)     usage ;;
    *) die "Unknown option: $1. Run $0 --help for usage." ;;
esac

check_root
: > "$LOGFILE"

case "$MODE" in
    tools)
        install_packages
        fetch_submodules
        install_tools
        setup_confdir
        ;;
    kernel)
        install_kernel_packages
        install_kernel
        ;;
    all)
        install_packages
        install_kernel_packages
        fetch_submodules
        install_tools
        setup_confdir
        install_kernel
        ;;
esac

echo ""
echo "=========================================="
echo " AmneziaWG install complete"
echo "=========================================="
echo ""

if [ "$MODE" = "tools" ]; then
    echo "Tools installed. Place your config:"
    echo "  /etc/amnezia/amneziawg/<name>.conf"
    echo ""
    echo "Then: awg-quick up <name>"
else
    echo "REBOOT REQUIRED to load the AWG kernel."
    echo ""
    echo "After reboot:"
    echo "  uname -v                   # verify AWG.MP kernel"
    echo "  ifconfig awg0 create       # verify awg device"
    echo ""
    echo "Place your config:"
    echo "  /etc/amnezia/amneziawg/<name>.conf"
    echo ""
    echo "Then: awg-quick up <name>"
fi

echo ""
echo "Log: $LOGFILE"
