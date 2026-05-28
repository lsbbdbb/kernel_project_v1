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
echo "[1/4] 清理旧容器和 volume..."
docker ps -q --filter name=agent | xargs -r docker kill 2>/dev/null || true
docker compose down -v 2>/dev/null || true

# ---- 2. 恢复内核源码树 ----
echo "[2/4] 恢复内核源码树到干净状态..."
cd acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
git checkout . 2>/dev/null || true
git clean -fd 2>/dev/null || true

# 撤销 CVE-2026-0011 的 null check（让演示能展示修复过程）
sed -i '654,655d' net/core/dev.c
sed -i '653{ /^$/d; }' net/core/dev.c
echo "  CVE-2026-0011 null check reverted"

cd ~/kernel-livepatch-agent

# ---- 3. 确保 demo_cves.txt 存在 ----
if [ ! -f demo_cves.txt ]; then
    cat > demo_cves.txt << 'CVELIST'
CVE-2026-0011
CVE-2026-0012
CVE-2026-0013
CVE-2026-0014
CVE-2026-0015
CVE-2026-0016
CVELIST
fi
echo "[3/4] CVE 列表: $(wc -l < demo_cves.txt) 个"
cat demo_cves.txt

# ---- 4. 运行 ----
echo ""
echo "[4/4] 启动 Agent Pipeline (LLM 模式)..."
echo "----------------------------------------------"
docker compose run --rm \
    -v ~/.cache/kpatch-agent:/root/.cache/kpatch-agent:z \
    -e VM_HOST=kxr@10.99.2.182 \
    -e PYTHONUNBUFFERED=1 \
    agent-run bash -c "
python3 -m agent --cves demo_cves.txt \
    --workdir /tmp/test_workspace \
    --kernel-version 6.6.102-5.2.an23.x86_64 \
    --vm-host kxr@10.99.2.182 2>&1
"
echo ""
echo "=============================================="
echo "  Demo Complete — $(date)"
echo "=============================================="
