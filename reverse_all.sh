#!/bin/bash
# Reverse-apply all CVE patches to un-fix the kernel source tree
SRC=/home/lee/kernel-livepatch-agent/acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
PATCHDIR=/home/lee/kernel-livepatch-agent/run_20260528_092607

echo "=== Reversing all CVE fixes from kernel source ==="
echo "Source: $SRC"
echo ""

success=0
failed=0
for cve_dir in $PATCHDIR/CVE-*; do
    cve=$(basename $cve_dir)
    patch=$cve_dir/patches/original.patch
    
    if [ ! -f "$patch" ]; then
        echo "$cve: NO PATCH FILE"
        ((failed++))
        continue
    fi
    
    cd $SRC
    
    # Try reverse dry-run first
    if patch --dry-run -R -p1 < "$patch" 2>&1 | grep -q 'FAILED'; then
        echo "$cve: REVERSE DRY-RUN FAILED"
        ((failed++))
        continue
    fi
    
    # Actually reverse
    result=$(patch -R -p1 < "$patch" 2>&1)
    if [ $? -eq 0 ]; then
        echo "$cve: REVERSED OK"
        ((success++))
    else
        echo "$cve: REVERSE FAILED - $result"
        ((failed++))
    fi
done

echo ""
echo "=== Done: $success reversed, $failed failed ==="
