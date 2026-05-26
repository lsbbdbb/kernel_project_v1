# Kernel CVE Livepatch Auto-Generation Agent

Anolis OS 内核 CVE 热补丁自动生成智能体。自动解析 CVE → 获取补丁 → 分析 → 构建 → 验证。

## 当前状态 (2026-05-26)

**Docker 全流程已跑通。** 目标内核 Anolis 6.6.102-5.2.an23 已合入当前 3 个 sample CVE 的补丁，agent 正确识别并跳过/报告。

### 本轮修复

| 修复 | 文件 | 说明 |
|------|------|------|
| Source tree 清理 |  | 新增非 git 树的 .orig 恢复 |
| 三阶段补丁检查 |  | forward → reverse → fuzz |
| Docker entrypoint |  | run 模式传递 LLM 参数 |

### 上次运行结果 (Docker)

| CVE | 状态 | 原因 |
|-----|------|------|
| CVE-2026-43284 | failed | Docker 网络不可达 git.kernel.org |
| CVE-2026-43018 | skipped | 补丁已合入 Anolis 内核 |
| CVE-2025-38182 | manual_required | kpatch-build: no functional changes found |

### 已验证通过

- CVE-2026-43284 livepatch.ko 在 Anolis VM 上 insmod → patching complete → rmmod 全生命周期
- 110 单元测试全部通过
- Agent Docker 全流程 pipeline 正常运行

## 快速使用



## 环境

| 组件 | 说明 |
|------|------|
| 构建服务器 | lee@100.64.162.82 (Fedora 43, Docker) |
| 目标 VM | kxr@10.99.2.182 (Anolis OS 23, kernel 6.6.102-5.2.an23) |
| kpatch-build | upstream dynup/kpatch @ 6e58fed |
| GCC (Docker) | 12.3.0-16.an23 (匹配内核编译器) |

## 待解决

1. **需要未合入的 CVE** — 当前 3 个 sample 均已合入 Anolis，需新测试集验证完整 build → .ko 路径
2. **Docker 网络** — 容器内偶尔无法访问 git.kernel.org
3. **失败分类** —  应归类为 

## 项目结构


