#!/bin/sh
# AmneziaWG for OpenBSD — install script
# Run as root on OpenBSD 7.x amd64
#
# Usage:
#   sh install.sh --tools-only   # patch + rebuild ifconfig, install awg-quick (no reboot)
#   sh install.sh --kernel-only  # build and install AWG kernel (requires reboot)
#   sh install.sh --all          # everything (default)

set -e

SCRIPT=$(readlink -f "$0")
REPODIR=$(dirname "$SCRIPT")
SRCDIR=/usr/src/sys
IFCFG_SRC=/usr/src/sbin/ifconfig
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

    if ! command -v bash >/dev/null 2>&1; then
        log "Installing bash"; pkg_add bash
    fi

    log "Packages OK"
}

# ── 2. Kernel sources ─────────────────────────────────────────────────────────

fetch_sys_sources() {
    step "Kernel sources"

    # Validate sources (files.rasops being empty is a known bad-extraction symptom)
    if [ ! -f "$SRCDIR/net/if_wg.c" ] || ! grep -q 'OpenBSD' "$SRCDIR/dev/rasops/files.rasops" 2>/dev/null; then
        local ver url
        ver=$(uname -r)
        url="https://cdn.openbsd.org/pub/OpenBSD/${ver}/sys.tar.gz"
        log "Fetching kernel sources from $url"
        ftp -o /dev/null "$url" 2>/dev/null \
            || die "sys.tar.gz not found at $url — CDN only carries 7.7+. Download manually and extract to /usr/src"
        mkdir -p /usr/src
        ftp -o /tmp/sys.tar.gz "$url" || die "Failed to download sys.tar.gz"
        tar -C /usr/src -xzf /tmp/sys.tar.gz || die "Failed to extract sys.tar.gz"
        rm -f /tmp/sys.tar.gz
        [ -f "$SRCDIR/net/if_wg.c" ] || die "sys.tar.gz extracted but $SRCDIR/net/if_wg.c not found"
        log "Kernel sources installed to /usr/src/sys"
    else
        log "Kernel sources already present"
    fi
}

# ── 3. ifconfig patch ─────────────────────────────────────────────────────────

install_ifconfig() {
    step "ifconfig — AWG support patch"

    local PATCH="$REPODIR/sbin/ifconfig/ifconfig_awg.patch"
    [ -f "$PATCH" ] || die "Patch not found: $PATCH"

    # Fetch ifconfig sources from CDN if not present
    if [ ! -f "$IFCFG_SRC/ifconfig.c" ]; then
        local ver url
        ver=$(uname -r)
        url="https://cdn.openbsd.org/pub/OpenBSD/${ver}/src.tar.gz"
        log "Fetching userland sources (streaming sbin/ifconfig only) from $url"
        ftp -o - "$url" 2>/dev/null \
            | tar -C /usr/src -xzf - sbin/ifconfig \
            || die "Failed to extract sbin/ifconfig from src.tar.gz"
        [ -f "$IFCFG_SRC/ifconfig.c" ] || die "ifconfig.c not found after extraction"
        log "ifconfig sources extracted to $IFCFG_SRC"
    fi

    # Install if_awg.h into system include path (needed to compile ifconfig)
    cp "$REPODIR/src/if_awg.h" /usr/include/net/if_awg.h

    # Apply patch (idempotent: check if already patched)
    if grep -q 'A_AMNEZIAWG' "$IFCFG_SRC/ifconfig.c" 2>/dev/null; then
        log "ifconfig.c already patched"
    else
        log "Patching ifconfig.c"
        cp "$IFCFG_SRC/ifconfig.c" "$IFCFG_SRC/ifconfig.c.orig"
        patch "$IFCFG_SRC/ifconfig.c" "$PATCH" \
            || die "patch failed — ifconfig.c may differ from expected version"
    fi

    # Build and install
    log "Building ifconfig"
    cd "$IFCFG_SRC"
    make || die "ifconfig build failed"
    install -c -s -o root -g bin -m 555 ifconfig /sbin/ifconfig
    install -c -o root -g bin -m 444 ifconfig.8 /usr/share/man/man8/ifconfig.8
    log "ifconfig installed to /sbin/ifconfig"
}

# ── 4. awg-quick ─────────────────────────────────────────────────────────────

install_awg_quick() {
    step "awg-quick"

    install -m 755 "$REPODIR/sbin/awg-quick" /usr/bin/awg-quick
    log "awg-quick installed to /usr/bin/awg-quick"
}

# ── 5. AWG kernel driver ──────────────────────────────────────────────────────

install_kernel() {
    step "AWG kernel driver"

    log "Copying driver files to $SRCDIR/net/"
    cp "$REPODIR/src/if_awg.h" "$SRCDIR/net/if_awg.h"
    cp "$REPODIR/src/if_awg.c" "$SRCDIR/net/if_awg.c"
    cp "$REPODIR/src/AWG.MP"   "$SRCDIR/arch/amd64/conf/AWG.MP"

    # Patch conf/files to register the pseudo-device (idempotent)
    if grep -q 'pseudo-device awg' "$SRCDIR/conf/files"; then
        log "conf/files already patched"
    else
        log "Patching $SRCDIR/conf/files"
        awk '
            /^pseudo-device wg: ifnet$/ { print; print "pseudo-device awg: ifnet"; next }
            /^file net\/if_wg\.c/ { print; print "file net/if_awg.c\t\t\tawg"; next }
            { print }
        ' "$SRCDIR/conf/files" > "$SRCDIR/conf/files.tmp" \
            && mv "$SRCDIR/conf/files.tmp" "$SRCDIR/conf/files"
        grep -q 'pseudo-device awg' "$SRCDIR/conf/files" \
            || die "conf/files patch failed — wg entry not found"
    fi

    log "Configuring AWG.MP"
    cd "$SRCDIR/arch/amd64/conf"
    config AWG.MP

    log "Building kernel — this takes ~15 minutes"
    cd "$SRCDIR/arch/amd64/compile/AWG.MP"
    make -j"$(sysctl -n hw.ncpu)" 2>&1 | tee -a "$LOGFILE"
    make install

    log "Kernel installed to /bsd — reboot to activate"
}

# ── 6. Config directory ───────────────────────────────────────────────────────

setup_confdir() {
    if [ ! -d /etc/amnezia/amneziawg ]; then
        log "Creating /etc/amnezia/amneziawg"
        mkdir -p /etc/amnezia/amneziawg
        chmod 700 /etc/amnezia/amneziawg
    fi
}

# ── 7. pf MSS clamping ────────────────────────────────────────────────────────

setup_pf_mss() {
    step "pf MSS clamping for awg interfaces"

    local PF_CONF=/etc/pf.conf
    local RULE='match on awg scrub (max-mss 1380)'

    if grep -q 'max-mss.*1380' "$PF_CONF" 2>/dev/null; then
        log "pf MSS clamp already present in $PF_CONF"
        return
    fi

    if [ ! -f "$PF_CONF" ]; then
        log "Creating $PF_CONF with MSS clamp rule"
        printf 'set skip on lo\n\n# Clamp TCP MSS to awg MTU (1420 - 40 = 1380)\n%s\n\nblock return\npass\n' "$RULE" > "$PF_CONF"
    else
        log "Adding MSS clamp rule to $PF_CONF"
        if grep -q '^set skip' "$PF_CONF"; then
            awk -v rule="$RULE" '
                /^set skip/ { print; found=1; next }
                found && !/^set skip/ { print "\n# Clamp TCP MSS to awg MTU (1420 - 40 = 1380)"; print rule; found=0 }
                { print }
            ' "$PF_CONF" > "$PF_CONF.tmp" && mv "$PF_CONF.tmp" "$PF_CONF"
        else
            { printf '# Clamp TCP MSS to awg MTU (1420 - 40 = 1380)\n%s\n\n' "$RULE"; cat "$PF_CONF"; } > "$PF_CONF.tmp" \
                && mv "$PF_CONF.tmp" "$PF_CONF"
        fi
    fi

    if pfctl -nf "$PF_CONF" 2>/dev/null; then
        pfctl -f "$PF_CONF" && log "pf reloaded with MSS clamp" || log "WARNING: pf reload failed — check $PF_CONF"
    else
        log "WARNING: pf syntax check failed — rule not loaded, check $PF_CONF manually"
    fi
}

# ── main ──────────────────────────────────────────────────────────────────────

usage() {
    cat <<EOF
Usage: $0 [--tools-only | --kernel-only | --all]

  --tools-only   Patch ifconfig + install awg-quick (no reboot needed)
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
        fetch_sys_sources
        install_ifconfig
        install_awg_quick
        setup_confdir
        setup_pf_mss
        ;;
    kernel)
        fetch_sys_sources
        install_kernel
        ;;
    all)
        install_packages
        fetch_sys_sources
        install_ifconfig
        install_awg_quick
        setup_confdir
        setup_pf_mss
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
