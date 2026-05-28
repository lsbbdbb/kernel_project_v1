#!/bin/bash
SRC=/kernel-src/linux-6.6.102-5.2.an23.x86_64
PATCHDIR=/app/patches_real
cd $SRC

for patch in $PATCHDIR/CVE-*.patch $PATCHDIR/nf_reject.patch; do
    name=$(basename $patch .patch)
    echo "========== $name =========="
    
    if patch --dry-run -R -p1 < $patch 2>&1 | grep -q 'FAILED'; then
        echo "REVERSE dry-run FAILED - skip"
        continue
    fi
    
    # Backup and reverse
    files=$(grep '^+++' $patch | sed 's|^+++ [^/]*/||')
    for f in $files; do cp $SRC/$f /tmp/$(basename $f).bak 2>/dev/null; done
    
    patch -R -p1 < $patch > /dev/null 2>&1
    echo "REVERSE: OK"
    
    if patch --dry-run -p1 < $patch 2>&1 | grep -qE 'FAILED|Reversed'; then
        echo "FORWARD dry-run: FAILED"
    else
        echo "FORWARD dry-run: OK - building..."
        mkdir -p /tmp/out_$name
        timeout 180 kpatch-build --sourcedir $SRC --vmlinux $SRC/vmlinux $patch -o /tmp/out_$name 2>&1 | tail -3
        if [ -f /tmp/out_$name/livepatch*.ko ]; then
            ls -lh /tmp/out_$name/livepatch*.ko
            echo "BUILD: SUCCESS"
        else
            echo "BUILD: FAILED/timeout"
        fi
    fi
    
    # Restore
    for f in $files; do [ -f /tmp/$(basename $f).bak ] && cp /tmp/$(basename $f).bak $SRC/$f; done
    echo ""
done
