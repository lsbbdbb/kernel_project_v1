#!/bin/bash
# =============================================================================
# Kernel CVE Patch Manager — git-based demo preparation tool
#   manage_patches.sh reverse   → git apply -R all CVE fixes (demo prep)
#   manage_patches.sh restore   → git checkout . (instant restore to baseline)
#   manage_patches.sh status    → git diff --stat (show current modifications)
# =============================================================================

SRC="${KERNEL_SRC:-/home/lee/kernel-livepatch-agent/acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23}"
PATCHDIR="${PATCHDIR:-/home/lee/kernel-livepatch-agent/run_20260528_092607}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

die() { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

[ -d "$SRC" ] || die "Kernel source not found: $SRC"
[ -d "$SRC/.git" ] || die "Not a git repo. Run: cd $SRC && git init && git add -A && git commit -m baseline"

CVE_IDS=(
    CVE-2024-46733 CVE-2024-53156 CVE-2024-56659 CVE-2024-56763
    CVE-2024-56764 CVE-2025-21638 CVE-2025-21646 CVE-2025-21656
    CVE-2025-21767 CVE-2025-21799
)

get_patch() {
    local patch="$PATCHDIR/$1/patches/original.patch"
    [ -f "$patch" ] && echo "$patch" && return 0
    return 1
}

cmd_status() {
    echo "=== CVE Patch Status ==="
    echo "Source: $SRC"
    echo ""
    cd "$SRC"
    local changes
    changes=$(git diff --stat 2>/dev/null)
    if [ -z "$changes" ]; then
        echo -e "  ${GREEN}Clean — all CVE fixes are APPLIED${NC}"
    else
        echo "$changes"
        echo ""
        echo -e "  ${YELLOW}Files above have CVE fixes REVERSED${NC}"
    fi
}

cmd_reverse() {
    echo "=== Reversing CVE Patches (git apply -R) ==="
    echo "Source: $SRC"
    echo ""
    local ok=0 fail=0 skip=0
    for cve in "${CVE_IDS[@]}"; do
        local patch
        patch=$(get_patch "$cve" 2>/dev/null)
        if [ -z "$patch" ]; then
            echo -e "  ${cve}: ${YELLOW}SKIP (no patch)${NC}"
            ((skip++))
            continue
        fi
        cd "$SRC"
        if git apply --check "$patch" 2>&1 | grep -qE "already applied|reversed"; then
            # Already applied, try to reverse with git apply -R
            if git apply -R --check "$patch" 2>/dev/null; then
                git apply -R "$patch" 2>/dev/null
                echo -e "  ${cve}: ${GREEN}REVERSED${NC}"
                ((ok++))
            else
                # Fall back to patch -R
                if patch --dry-run -R -p1 < "$patch" 2>&1 | grep -q "FAILED"; then
                    echo -e "  ${cve}: ${RED}FAIL (cannot reverse)${NC}"
                    ((fail++))
                else
                    patch -R -p1 < "$patch" > /dev/null 2>&1
                    echo -e "  ${cve}: ${GREEN}REVERSED (patch)${NC}"
                    ((ok++))
                fi
            fi
        elif git apply --check "$patch" 2>/dev/null; then
            echo -e "  ${cve}: ${YELLOW}SKIP (already reversed)${NC}"
            ((skip++))
        else
            echo -e "  ${cve}: ${RED}FAIL (patch does not match)${NC}"
            ((fail++))
        fi
    done
    echo ""
    echo "Reversed: $ok | Failed: $fail | Skipped: $skip"
}

cmd_restore() {
    echo "=== Restoring to Baseline (git checkout .) ==="
    echo "Source: $SRC"
    cd "$SRC"
    git checkout . 2>&1
    git clean -fd 2>/dev/null
    echo -e "${GREEN}All files restored to baseline.${NC}"
    cmd_status
}

case "${1:-}" in
    reverse)  cmd_reverse ;;
    restore)  cmd_restore ;;
    status)   cmd_status ;;
    *)
        echo "Usage: $0 {reverse|restore|status}"
        echo ""
        echo "  reverse  — git apply -R all CVE fixes (demo prep)"
        echo "  restore  — git checkout . (instant restore to baseline)"
        echo "  status   — git diff --stat (show current modifications)"
        exit 1
        ;;
esac
