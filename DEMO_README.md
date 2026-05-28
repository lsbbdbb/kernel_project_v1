# kernel-livepatch-agent 演示操作手册

## 一键启动

```bash
ssh lee@100.64.162.82
cd ~/kernel-livepatch-agent
bash demo.sh
```

自动完成：清理 → 恢复源码树 → 启动 LLM Agent Pipeline。

## 预期结果

```
Total: 6 | Success: 1 | Manual: 5
CVE-2026-0012: success + livepatch.ko
```

| CVE | 结果 | 演示看点 |
|-----|:--:|------|
| 0012 | **success** .ko 1.3MB | 全链路：CVE→补丁→编译→SCP→insmod→patching complete |
| 0011 | manual | AI 识别补丁已合入 Anolis 内核 |
| 0013 | manual | AI 分类 header-only，LLM 改写尝试 |
| 0014 | manual | AI 识别补丁已合入 |
| 0015 | manual | AI 发现上下文不匹配，LLM 改写 |
| 0016 | manual | AI 判断不可恢复 |

## 手动清理（重新演示）

```bash
docker ps -q --filter name=agent | xargs -r docker kill
cd ~/kernel-livepatch-agent && docker compose down -v
cd ~/kernel-livepatch-agent/acceptance_vm_20260525/source_tree/linux-6.6.102-5.2.an23
git checkout . && git clean -fd
```

## 重复演示

直接再跑 `bash demo.sh`。

## 故障排查

| 问题 | 检查 |
|------|------|
| VM 不通 | `ssh kxr@10.99.2.182 uname -r` |
| build 失败 | vmlinux 是否 347MB |
| 0012 不 success | VM 必须在运行，LLM API 可达 |
