#!/bin/bash
# ============================================================
# Download and prepare Anolis OS kernel source tree
# for kpatch-build in the Docker environment
# ============================================================
# Usage: bash scripts/download_kernel_src.sh [kernel_version]
#
# This downloads the cloud-kernel from Gitee (Anolis official repo)
# and builds vmlinux + modules_prepare for kpatch-build.
#
# Prerequisites: git, make, gcc, bc, bison, flex
# Disk space: ~5 GB
# Time: ~20-40 minutes for vmlinux
# ============================================================
set -euo pipefail

KERNEL_VERSION="${1:-6.6.102-5.2.an23.x86_64}"
# Extract version for branch: 6.6.102-5.2.an23.x86_64 → 6.6.102-5.2
KERNEL_RELEASE="$(echo "${KERNEL_VERSION}" | sed 's/\.an23.*//' | sed 's/\.x86_64.*//')"
GIT_BRANCH="release/release-${KERNEL_RELEASE}.y"  # release/release-6.6.102-5.2.y

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SRC_DIR="${PROJECT_DIR}/kernel-src/linux-${KERNEL_VERSION}"
GIT_URL="https://gitee.com/anolis/cloud-kernel.git"

echo "============================================"
echo " Kernel Source Download & Build"
echo "============================================"
echo " Target: ${KERNEL_VERSION}"
echo " Source: ${GIT_URL}"
echo " Branch: ${GIT_BRANCH}"
echo " Output: ${SRC_DIR}"
echo ""

# --- Check disk space ---
if [ -d "$SRC_DIR" ]; then
    echo "[SKIP] Kernel source already exists: $SRC_DIR"
    if [ -f "$SRC_DIR/vmlinux" ]; then
        echo "[OK] vmlinux already built"
        exit 0
    else
        echo "[INFO] vmlinux not found, will build..."
    fi
else
    echo "[1/3] Cloning cloud-kernel (shallow, branch=${GIT_BRANCH})..."
    mkdir -p "$(dirname "$SRC_DIR")"
    git clone --depth=1 --branch "${GIT_BRANCH}" "${GIT_URL}" "${SRC_DIR}"
fi

# --- Configure kernel ---
echo "[2/3] Configuring kernel..."
cd "${SRC_DIR}"

# Use default config as base
make defconfig 2>&1 | tail -1

# Enable livepatch support
scripts/config -e LIVEPATCH 2>/dev/null || true
scripts/config -e HAVE_LIVEPATCH 2>/dev/null || true
scripts/config -e KALLSYMS_ALL 2>/dev/null || true
scripts/config -e DEBUG_INFO 2>/dev/null || true
# Enable NUMA_BALANCING (required for cpu_load declaration in fair.c, GCC 15)
scripts/config -e NUMA_BALANCING 2>/dev/null || true
# Disable -Werror (GCC 15 is stricter than the kernel expects)
scripts/config -d WERROR 2>/dev/null || true

# Re-generate .config
yes "" | make oldconfig 2>&1 | tail -1

# --- Build vmlinux ---
echo "[3/4] Building vmlinux + modules_prepare..."
NPROC=$(nproc 2>/dev/null || echo 4)
# Cap at 8 to avoid fixdep race conditions with newer GCC
if [ "${NPROC}" -gt 8 ]; then NPROC=8; fi
echo "       Using ${NPROC} parallel jobs..."

make -j"${NPROC}" vmlinux 2>&1 | tail -5
echo "[4/4] Building modules (for Module.symvers)..."
make -j"${NPROC}" modules_prepare 2>&1 | tail -5
make -j"${NPROC}" modules 2>&1 | tail -5

# --- Verify ---
if [ -f "${SRC_DIR}/vmlinux" ]; then
    echo ""
    echo "============================================"
    echo " [OK] Kernel source ready!"
    echo "============================================"
    echo " vmlinux:   ${SRC_DIR}/vmlinux"
    echo " size:      $(du -sh "${SRC_DIR}/vmlinux" | cut -f1)"
    echo " modules:   $(ls "${SRC_DIR}/Module.symvers" 2>/dev/null && echo 'ready' || echo 'not found')"
    echo ""
    echo " Next: docker compose build agent && docker compose up agent"
else
    echo "[FAIL] vmlinux not found after build"
    exit 1
fi
