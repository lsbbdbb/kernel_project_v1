# 明天演示操作手册

## 一、一键启动

```bash
cd ~/kernel-livepatch-agent
bash demo.sh
```

这一个命令会自动完成：清理 → 恢复源码树 → 撤销 0011 修复 → 启动 LLM Agent。

## 二、预期结果

| CVE | 流程 | 演示看点 |
|-----|------|---------|
| CVE-2026-0011 | resolve → fetch → analyze → check → **apply OK → build → .ko → VM 验证** | AI 自动生成热补丁、SCP 到 VM、insmod/patching complete |
| CVE-2026-0012 | resolve → fetch → analyze → check → apply OK → build → verify | 同上 |
| CVE-2026-0013 | resolve → ... → apply 失败 → **LLM 分类** → **LLM 改写** | AI 分析 header-only 补丁，决定是否需要 rewrite |
| CVE-2026-0014 | resolve → ... → apply 失败 → **LLM 分类** → **LLM 改写** | AI 识别补丁已合入 |
| CVE-2026-0015 | resolve → ... → apply 失败 → **LLM 分类** → **LLM 改写** | AI 发现上下文不匹配，尝试改写 |
| CVE-2026-0016 | resolve → ... → apply 失败 → classify（不可改写） | AI 识别不可恢复错误 |

## 三、手动清理

```bash
# 停止所有 agent 容器
docker ps -q --filter name=agent | xargs -r docker kill

# 清空数据
cd ~/kernel-livepatch-agent && docker compose down -v

# 恢复内核源码树
cd ~/kernel-livepatch-agent/acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
git checkout .
```

## 四、重复演示

直接再跑 `bash demo.sh` 即可。每次自动清理干净。

## 五、常见问题

**Q: DeepSeek API 超时？**
A: Docker 内网络正常（已验证可达 api.deepseek.com）。timeout 120s 足够。

**Q: kpatch-build 失败？**
A: 检查 vmlinux 不是空文件（`ls -lh vmlinux` 应为 347MB）

**Q: VM 连不上？**
A: 从服务器 `ssh kxr@10.99.2.182` 确认可达

**Q: .ko 没生成？**
A: 仅有 0011 和 0012 会产出 .ko，其他都是分类/改写场景
