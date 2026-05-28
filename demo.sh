#!/bin/bash
# =============================================================================
# 一键演示脚本 — kernel-livepatch-agent
# 用法: bash demo.sh
# =============================================================================
set -e
cd ~/kernel-livepatch-agent

echo "=============================================="
echo "  Kernel Livepatch Agent — Demo Pipeline"
echo "  $(date)"
echo "=============================================="
echo ""

# ---- 1. 清理 ----
echo "[1/3] 清理旧容器和 volume..."
docker ps -q --filter name=agent | xargs -r docker kill 2>/dev/null || true
docker compose down -v 2>/dev/null || true

# ---- 2. 恢复内核源码树 ----
echo "[2/3] 恢复内核源码树..."
cd acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
git checkout . 2>/dev/null || true
git clean -fd 2>/dev/null || true
cd ~/kernel-livepatch-agent

# ---- 3. 运行 ----
echo "[3/3] 启动 Agent Pipeline (LLM 模式)..."
echo "----------------------------------------------"
docker compose run --rm \
    -v ~/.cache/kpatch-agent:/root/.cache/kpatch-agent:z \
    -e VM_HOST=kxr@10.99.2.182 \
    -e PYTHONUNBUFFERED=1 \
    agent-run bash -c "
python3 -m agent --cves demo_cves.txt \
    --kernel-version 6.6.102-5.2.an23.x86_64 \
    --vm-host kxr@10.99.2.182 2>&1
"
echo ""
echo "=============================================="
echo "  Demo Complete — $(date)"
echo "=============================================="
