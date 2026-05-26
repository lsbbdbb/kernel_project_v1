# kernel-livepatch-agent 使用指南

## 项目简介

自动化 CVE 内核热补丁生命周期管理智能体。输入 CVE 编号 → 自动完成补丁解析、构建、失败归因、改写重试、验证 → 输出报告。

### 核心能力

- **CVE 检索**: 从 NVD API（带重试+本地缓存）定位修复 commit
- **补丁解析**: 结构化解析 diff，提取文件、hunk、函数、kpatch 风险标签
- **目标检查**: 自动检测目标内核 config 是否禁用相关模块（如 `CONFIG_BT=m`）
- **kpatch 构建**: 调用 kpatch-build 生成 livepatch .ko 模块
- **失败归因**: 自动分类 16 种失败模式（通过 YAML 规则引擎）
- **自动改写**: 规则优先 + LLM 辅助，5 种改写策略，最多 5 轮重试
- **RAG 知识库**: 122 条内核 API/热补丁知识，BM25 检索注入改写
- **运行验证**: 远程 VM 加载/卸载验证 + dmesg 收集
- **报告输出**: 结构化 report.json + 事件日志

---

## 快速开始

### 环境要求

| 组件 | 版本/说明 |
|------|-----------|
| Python | 3.10+（3.13 测试通过）|
| 目标内核 | Anolis OS ANCK 6.6.102-5.2.an23.x86_64 |
| 构建环境 | Anolis OS 23.4 container（Docker） |
| 验证环境 | Anolis OS 23.4 VM |

### 1. 克隆 + 安装

```bash
git clone <repo-url>
cd kernel-livepatch-agent
pip install -r requirements.txt && pip install -e .
```

### 2. 运行测试

```bash
python -m pytest tests/ -v
# 108 passed ✅
```

### 3. 运行完整流水线（单机快速验证）

```bash
# 规则模式（无需 API key）
python -m agent --cves sample_cves.txt --no-llm
```

### 4. 运行完整流水线（Docker，含内核编译）

```bash
docker compose up agent-run-no-llm
```

---

## CLI 参考

### 基本用法

```bash
python -m agent [--cves FILE | --cve CVE_ID] [options]
```

### 完整参数

| 参数 | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--cves FILE` | ❌ | `sample_cves.txt` | CVE 列表文件（每行一个） |
| `--workdir DIR` | ❌ | `./run_<timestamp>` | 工作目录 |
| `--kernel-version` | ❌ | `6.6.102-5.2.an23.x86_64` | 目标内核版本 |
| `--no-llm` | ❌ | `False` | 强制规则模式，不调 LLM |
| `--llm-provider` | ❌ | `deepseek` | LLM 后端（deepseek/openai/ollama） |
| `--llm-model` | ❌ | `deepseek-v4-pro` | LLM 模型名 |
| `--target-vm` | ❌ | - | 远程验证 VM（SSH 主机名） |

### 环境变量

| 变量 | 用途 |
|------|------|
| `DEEPSEEK_API_KEY` | DeepSeek API key（LLM 模式必需） |
| `OPENAI_API_KEY` | OpenAI API key |
| `KERNEL_SRC` | 内核源码路径（手动指定，覆盖自动检测） |
| `VMLINUX_PATH` | 目标内核 debuginfo 中的只读 `vmlinux` 路径（运行加载验收时应显式提供） |
| `KERNEL_DEVEL_PATH` | 与目标内核精确版本匹配的 `kernel-devel` 路径（可选，传递给 `kpatch-build -d`） |
| `KPATCH_BUILD_BIN` | 指定已审核的 `kpatch-build` 可执行文件路径（工具链兼容实验用） |
| `LANG / LC_ALL` | 设为 `C` 可避免 locale 相关 make 错误 |

### 运行模式

```
              ┌──────────────┐
              │  --no-llm    │  规则模式（零外部依赖）
              │  (default)   │
              └──────┬───────┘
                     │
              ┌──────▼───────┐
              │  有 API key  │  LLM 模式
              │   --llm-*    │  启用 RAG + LLM 改写
              └──────────────┘
```

---

## 架构概览

```
CVE 列表
    │
    ▼
┌──────────────┐     ┌─────────────────┐
│  CVEResolver │────▶│  PatchFetcher    │
│  (NVD + 缓存) │     │  (HTTP + 磁盘缓存)│
└──────────────┘     └────────┬────────┘
                              ▼
┌──────────────┐     ┌─────────────────┐
│  PatchParser │◀────│  check_target   │
│  (IR 结构化)  │     │  (config 检查)   │
└──────┬───────┘     └─────────────────┘
       │
       ▼
┌──────────────┐     ┌─────────────────┐
│  KpatchBuilder│────▶│ FailureClassifier│
│  (kpatch-build)│     │  (YAML 规则引擎) │
└──────────────┘     └────────┬────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
      ┌────────────┐  ┌────────────┐  ┌────────────┐
      │ fix_env    │  │ rewrite    │  │ manual     │
      │ (环境修复)  │  │ (LLM/规则)  │  │ (人工介入)  │
      └────────────┘  └─────┬──────┘  └────────────┘
                            │
                     ┌──────▼──────┐
                     │  Verifier    │
                     │  (VM 验证)   │
                     └──────┬──────┘
                            │
                     ┌──────▼──────┐
                     │  Reporter   │
                     │  (JSON 输出) │
                     └─────────────┘
```

### 核心模块

| 模块 | 类/文件 | 职责 |
|------|---------|------|
| CVE 解析 | `CVEResolver` | 查询 NVD API（指数退避重试，本地 JSON 缓存） |
| 补丁获取 | `PatchFetcher` | 从 kernel.org/NVD 下载 patch（HTTP 缓存） |
| 补丁解析 | `PatchParser` | 结构化解析 diff → change_units.json |
| 目标检查 | `KernelConfigChecker` | 检查目标内核 config 是否禁用相关模块 |
| 构建 | `KpatchBuilder` | 调用 kpatch-build（超时 7200s） |
| 失败分类 | `FailureClassifier` | 16 种 YAML 规则 + fallback |
| 改写 | `RewriteAdvisor` | LLM + 5 种规则策略 + RAG 检索 |
| 语义验证 | `SemanticValidator` | 安全检查：边界保留、错误路径、全局变量 |
| 验证 | `Verifier` | SSH 远程加载/卸载 + dmesg 检查 |
| 报告 | `Reporter` | 生成结构化 report.json |
| 决策 | `Planner` / `LLMPlanner` | 状态机 17 状态，决策点 LLM/规则 |
| 状态 | `StateManager` | 持久化状态 + 事件日志 |
| RAG | `KnowledgeBase` / `KnowledgeRetriever` | 122 条知识，BM25 检索 |
| 知识加载 | `KnowledgeLoader` | YAML 规则 → Python 对象 |

---

## Docker 部署

### 服务一览

| 服务 | 命令 | 用途 |
|------|------|------|
| `agent` | `docker compose up agent` | 运行测试 |
| `agent-run` | `docker compose up agent-run` | 全链路（LLM 模式） |
| `agent-run-no-llm` | `docker compose up agent-run-no-llm` | 全链路（规则模式） |
| `agent-dev` | `docker compose run --rm agent-dev` | 交互式 shell |

详细说明见 [README_Docker.md](README_Docker.md)。

---

## 输出产物

```
run_<timestamp>/CVE-2026-XXXXX/
├── patches/
│   ├── original.patch        # 原始上游补丁
│   └── attempt_N.patch       # 第 N 轮改写补丁
├── metadata/
│   ├── raw_nvd.json          # NVD API 原始响应
│   └── cve_metadata.json     # 合并元数据
├── logs/
│   └── build_N.log           # 第 N 轮构建日志
├── artifacts/
│   └── livepatch.ko          # 编译产物（成功时）
├── events.json               # 状态机事件时间线
├── failure.json              # 失败分类（如有）
├── change_units.json         # 补丁结构化 IR
└── summary.json              # 批量汇总报告
```

### status 含义

| 状态 | 含义 |
|------|------|
| `manual_required` | 环境问题（如 syncconfig），需 Docker 环境 |
| `skipped` | 目标内核 config 已禁用相关模块 |
| `failed` | 不可恢复的失败（如非重试错误） |
| `success` | 构建成功（待补全验证步骤） |

---

## 目录结构

```
kernel-livepatch-agent/
├── agent/
│   ├── __main__.py              # CLI 入口 + _action_* 编排
│   ├── state.py                 # StateManager（17 状态）
│   ├── planner.py               # Planner + LLMPlanner
│   ├── knowledge/
│   │   ├── loader.py            # YAML → Python 加载器
│   │   ├── rules/               # YAML 规则文件
│   │   │   ├── failure_patterns.yaml     # 16 种失败模式
│   │   │   └── rewrite_strategies.yaml   # 6 种改写策略
│   │   ├── kernel_api/          # 内核 API 知识
│   │   └── rag_knowledge/       # 6 篇 RAG 文档
│   ├── llm/
│   │   ├── config.py            # LLMConfig（多 provider）
│   │   ├── client.py            # LLMClient（ping/chat）
│   │   └── prompts/templates.py # 4 个提示词模板
│   ├── rag/
│   │   ├── knowledge_base.py    # KnowledgeBase（122 docs）
│   │   └── retriever.py         # BM25 检索
│   └── tools/
│       ├── cve_resolver.py      # CVE 解析（重试+缓存）
│       ├── patch_fetcher.py     # 补丁获取（磁盘缓存）
│       ├── patch_parser.py      # 补丁结构化解析
│       ├── kernel_config_checker.py  # 内核 config 检查
│       ├── kpatch_builder.py    # kpatch-build 封装
│       ├── failure_classifier.py    # 失败归因（YAML）
│       ├── rewrite_advisor.py   # 补丁改写（LLM+规则）
│       ├── semantic_validator.py    # 改写语义验证
│       ├── verifier.py          # VM 远程验证
│       └── reporter.py          # 报告生成
├── tests/                       # 108 个测试
├── Dockerfile                   # Anolis OS 23 镜像
├── docker-compose.yml           # 4 服务编排
├── docker-entrypoint.sh         # 容器入口
├── .gitignore
├── requirements.txt
├── README.md                    # 详细设计
├── README_PLAN.md               # 实现路线图
├── README_Docker.md             # Docker 部署说明
└── USAGE.md                     # 本文件
```

---

## 常见问题

### Q: 构建报 syncconfig 错误？

**原因**: 主机环境缺少 kpatch 工具链的 srctree 环境变量传递。

**解决**: 使用 Docker 运行 `docker compose up agent-run-no-llm`。

### Q: NVD API 超时/SSL 错误？

Agent 自动重试 3 次（指数退避），并将成功的 NVD 和 patch 缓存到 `~/.cache/kpatch-agent/`。

### Q: 如何添加新的失败模式？

编辑 `agent/knowledge/rules/failure_patterns.yaml`，添加新的 pattern，重启 agent 即可。

### Q: 支持哪些 LLM 后端？

DeepSeek（默认）、OpenAI、Ollama（本地）。通过 `--llm-provider` 和 `--llm-model` 指定。

### Q: 运行测试失败，缺少 rank-bm25？

```bash
pip install -r requirements.txt
```

`rank-bm25` 在 requirements.txt 中，不在 setup.py 的 install_requires 中。
