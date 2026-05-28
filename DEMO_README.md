# kernel-livepatch-agent 演示操作手册

## 环境

| 组件 | 地址 | 说明 |
|------|------|------|
| 构建服务器 | lee@100.64.162.82 | Docker, 项目代码 |
| 目标 VM | kxr@10.99.2.182 | Anolis OS 23, kernel 6.6.102-5.2.an23 |

---

## 一键演示

```bash
ssh lee@100.64.162.82
cd ~/kernel-livepatch-agent
bash demo.sh
```

## 预期结果

```
Total: 6 | Success: 2 | Manual: 4
```

| CVE | .ko | VM验证 | LLM | 演示看点 |
|-----|:--:|:--:|:--:|------|
| 0011 | 2.2MB | patching complete | - | CVE→补丁→编译→VM 全链路 |
| 0012 | 1.3MB | patching complete | - | 同上 |
| 0013 | - | - | classify+rewrite | AI 识别 header-only |
| 0014 | - | - | classify+rewrite | AI 检测已合入 |
| 0015 | - | - | classify+rewrite | AI 上下文改写 |
| 0016 | - | - | classify | AI 判定不可恢复 |

---

## 手动清理（重新演示前）

```bash
# 停止容器
docker ps -q --filter name=agent | xargs -r docker kill

# 清理数据
cd ~/kernel-livepatch-agent && docker compose down -v

# 恢复源码树
cd ~/kernel-livepatch-agent/acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
git checkout . && git clean -fd

# 撤销0011修复（演示需要）
sed -i '654,655d' net/core/dev.c
sed -i '653{ /^$/d; }' net/core/dev.c

# 确认VM在线
ssh -o StrictHostKeyChecking=no kxr@10.99.2.182 "uname -r"
```

---

## 手动运行（不用 demo.sh）

```bash
cd ~/kernel-livepatch-agent
docker compose run --rm \
    -v ~/.cache/kpatch-agent:/root/.cache/kpatch-agent:z \
    -e VM_HOST=kxr@10.99.2.182 \
    -e PYTHONUNBUFFERED=1 \
    agent-run bash -c '
python3 -m agent --cves demo_cves.txt \
    --kernel-version 6.6.102-5.2.an23.x86_64 \
    --vm-host kxr@10.99.2.182
'
```

加 `--no-llm` 用规则模式（无 AI）。不加则 LLM 模式。

---

## Git 恢复（出问题随时回滚）

```bash
# 项目代码
cd ~/kernel-livepatch-agent && git checkout .

# 内核源码树
cd ~/kernel-livepatch-agent/acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
git checkout .
```

---

## 故障排查

| 问题 | 检查 |
|------|------|
| build 失败 | `ls -lh vmlinux` 应为 347MB |
| VM 超时 | `ssh kxr@10.99.2.182 uname -r` |
| LLM 超时 | Docker 内 `curl api.deepseek.com` |
| 缓存失效 | `ls ~/.cache/kpatch-agent/nvd/CVE-2026-*.json` |
