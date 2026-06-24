#!/bin/sh
# Generate awg-openbsd.patch from current src/ files.
# Run before commit/push to keep the patch in sync with sources.

set -e

REPODIR=$(dirname "$(readlink -f "$0")")
OUT="$REPODIR/awg-openbsd.patch"
TAB="$(printf '\t')"

patch_file() {
    local src="$1" dst_name="$2"
    local ts
    ts=$(date '+%a %b %e %T %Y')
    diff -u /dev/null "$src" | awk \
        -v ts="$ts" \
        -v name="$dst_name" \
        'NR==1 { print "--- /dev/null" "\t" ts; next }
         NR==2 { print "+++ " name "\t" ts; next }
         { print }'
}

> "$OUT"
patch_file "$REPODIR/src/if_awg.h" "net/if_awg.h"   >> "$OUT"
printf '\n'                                           >> "$OUT"
patch_file "$REPODIR/src/if_awg.c" "net/if_awg.c"   >> "$OUT"
printf '\n'                                          >> "$OUT"

cat >> "$OUT" <<EOF
--- sys/conf/files.orig
+++ sys/conf/files
@@ pseudo-device wg: ifnet
+pseudo-device awg: ifnet
@@ file net/if_wg.c
+file net/if_awg.c${TAB}${TAB}${TAB}awg
EOF

echo "Generated $OUT ($(wc -l < "$OUT" | tr -d ' ') lines)"
