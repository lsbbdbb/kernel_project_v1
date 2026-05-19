#!/bin/bash
set -e

echo "=== Kernel Livepatch Agent - Anolis OS Environment ==="
echo ""

# --- Check kpatch-build ---
if command -v kpatch-build &>/dev/null; then
    echo "[OK] kpatch-build: $(command -v kpatch-build)"
elif [ -x /usr/local/bin/kpatch-build ]; then
    echo "[OK] kpatch-build: /usr/local/bin/kpatch-build (from source)"
else
    echo "[WARN] kpatch-build NOT found in PATH"
fi

# --- Check kernel source ---
KERNEL_VERSION="${KERNEL_VERSION:-6.6.102-5.2.an23.x86_64}"
KERNEL_BASE="$(echo "$KERNEL_VERSION" | cut -d. -f1)"
SRC_DIR="${KERNEL_SRC:-/kernel-src/linux-${KERNEL_VERSION}}"

if [ -d "$SRC_DIR" ] && [ -f "$SRC_DIR/vmlinux" ]; then
    echo "[OK] Kernel source: $SRC_DIR"
    echo "[OK] vmlinux: $SRC_DIR/vmlinux"
elif [ -d "$SRC_DIR" ]; then
    echo "[WARN] Kernel source found but vmlinux NOT built"
    echo "       Run: cd $SRC_DIR && make defconfig && make -j\$(nproc) vmlinux modules_prepare"
else
    echo "[WARN] Kernel source NOT found at $SRC_DIR"
    echo "       Run: bash scripts/download_kernel_src.sh"
fi

echo ""
case "${1:-test}" in
    test)
        echo ">>> Running tests..."
        exec python3 -m pytest tests/ -v
        ;;
    shell)
        echo ">>> Starting shell..."
        exec /bin/bash
        ;;
    run)
        echo ">>> Running agent with sample CVEs..."
        exec python3 -m agent --cves sample_cves.txt \
            --workdir "${WORKDIR:-/tmp/test_workspace}" \
            --kernel-version "$KERNEL_VERSION"
        ;;
    *)
        exec "$@"
        ;;
esac
