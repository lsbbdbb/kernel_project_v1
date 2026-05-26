# 内核 CVE 热补丁自动生成智能体 — 项目要求

## 1. 基本信息

| 字段 | 内容 |
|------|------|
| **赛题名称** | 内核 CVE 热补丁自动生成智能体 |
| **英文名称** | Kernel CVE Livepatch Auto-Generation Agent |
| **大赛名称** | 2026年全国大学生计算机系统能力大赛-操作系统设计赛(全国)-OS功能挑战赛道 |
| **赛题难度** | A |
| **赛题类型** | 工程型 |
| **维护单位** | 龙蜥社区、阿里云计算有限公司 |
| **维护人** | 高向阳（xiangyang.gxy@alibaba-inc.com） |
| **发布日期** | 2026-01-30 |

---

## 2. 赛题背景

云计算基础设施中，内核漏洞（CVE）修复需要兼顾**及时性、稳定性、不中断**。内核热补丁技术（livepatch）可在不停机条件下修复内核缺陷。社区常用的 kpatch 工具集可以完成内核补丁的构建和管理，但其对补丁的修改有诸多限制：

- ❌ 不能修改初始化函数
- ❌ 不能修改静态分配数据
- ❌ 不能修改缺少 fentry 调用的函数
- ❌ 不能修改全局数据（导致"unreconcilable difference"）
- ❌ 结构体 ABI 变化导致 CRC 校验失败

上游社区的修复补丁**并不总能直接转化为可加载的热补丁**。本赛题以"智能体（Agent）"为核心，要求构建一个面向上游 CVE 修复补丁的自动化系统：自动获取/解析补丁、理解修复意图、在保持语义等价的前提下改写补丁以满足热补丁机制约束，并形成可验证的热补丁产物。

---

## 3. 赛题任务

实现一个**内核 CVE 热补丁自动生成智能体**，对给定的上游 CVE 修复补丁集合进行自动化处理，利用 kpatch 工具链产出可加载的 livepatch 内核热补丁，并提供可追溯的过程与验证结果。

### 3.1 任务内容

| 阶段 | 任务 | 说明 |
|------|------|------|
| **1. CVE 查询与补丁获取** | 输入上游 CVE 编号集合 | Agent 查询 CVE 数据源，定位上游修复提交，确定针对目标内核版本的补丁，获取 patch 文件 |
| **2. 自动改写与适配（核心）** | 结构化改写，保持语义等价 | 使补丁满足 kpatch 构建约束并能在目标源码树上应用与编译。允许多轮迭代，基于构建错误日志自动驱动下一轮改写 |
| **3. 自动构建与热补丁生成** | 调用 kpatch-build 构建 | 对失败原因进行归因分类（patch apply 失败、编译失败、kpatch 限制等），并驱动下一轮改写 |
| **4. 输出产物与报告** | 结构化报告 | 每个 CVE 的尝试次数、最终结果、构建日志、改写前后的 patch 文件、构建产物等。同一输入在相同环境下可得到一致结果 |

### 3.2 预期技术指标

| 指标 | 要求 |
|------|------|
| **热补丁生成成功率** | 在规定的 CVE 修复补丁集合上，成功生成并通过加载验证的比例达到 **60% 以上** |
| **语义一致性** | 改写补丁保持与上游修复意图一致，不引入回归或风险操作 |
| **效率指标** | 平均每个补丁的尝试轮次 **不超过 5 次** |

---

## 4. 赛题特征

### 4.1 目标内核与工具链

| 组件 | 说明 |
|------|------|
| **目标内核** | 龙蜥操作系统（Anolis OS）的 ANCK 内核 |
| **目标版本** | `6.6.102-5.2.an23.x86_64` |
| **构建工具** | kpatch 工具链（Linux livepatch 机制） |

### 4.2 软件包与镜像获取

| 资源 | 下载地址 |
|------|----------|
| kernel source | `https://mirrors.openanolis.cn/anolis/23.4/os/source/Packages/kernel-6.6.102-5.2.an23.src.rpm` |
| kernel | `https://mirrors.openanolis.cn/anolis/23.4/os/x86_64/os/Packages/kernel-6.6.102-5.2.an23.x86_64.rpm` |
| kernel-devel | `https://mirrors.openanolis.cn/anolis/23.4/os/x86_64/os/Packages/kernel-devel-6.6.102-5.2.an23.x86_64.rpm` |
| kernel-debuginfo | `https://mirrors.openanolis.cn/anolis/23.4/os/x86_64/debug/Packages/kernel-debuginfo-6.6.102-5.2.an23.x86_64.rpm` |
| Anolis OS 23.4 镜像 | `https://cr.openanolis.cn/mirror/detail_info/27` |

### 4.3 测例与数据集设计

| 数据集 | 来源 | 用途 | 覆盖难点 |
|--------|------|------|----------|
| **公开数据集（Challenge）** | 上游社区针对目标内核版本的 CVE 修复补丁 | 智能体开发过程中打通流程 | 删除静态局部变量导致 section 变化；编译器优化导致 init 函数变化；结构体 ABI 变化；缺少 fentry 调用；全局数据导致 unreconcilable difference |
| **最终评测集（Final）** | 最新上游针对目标内核版本的 CVE 修复补丁 | 最终排名，避免针对性调参 | 未知，考察泛化能力 |

### 4.4 上游 CVE 修复补丁来源

| 来源 | 地址 |
|------|------|
| Linux stable 仓库 | `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/` |
| Linux CVE 公告邮件列表 | `https://lore.kernel.org/linux-cve-announce/` |
| NVD CVE 数据库 | `https://nvd.nist.gov/` |

### 4.5 智能体与 MCP 推荐

| 组件 | 推荐方案 | 文档 |
|------|----------|------|
| **智能体平台** | LLM 平台搭建智能体应用 | `https://help.aliyun.com/zh/model-studio/single-agent-application` |
| **MCP 服务** | LLM 平台创建自定义 MCP 服务 | `https://help.aliyun.com/zh/model-studio/custom-mcp` |
| **函数计算** | 函数计算 FC 使用自定义镜像 | `https://help.aliyun.com/zh/functioncompute/fc/user-guide/custom-container/` |
| **大语言模型** | DeepSeek 系列 | - |

---

## 5. 交付产物

| 产物 | 说明 |
|------|------|
| **a) LLM 平台应用链接** | 可在LLM 平台上运行的智能体应用 |
| **b) 代码仓库** | 完整的源代码、构建脚本、测试用例 |
| **c) 完整文档说明** | 详细设计、部署方法、使用说明、测试说明、失败案例分析 |

---

## 6. 验收方式

| 验收项 | 标准 |
|--------|------|
| **构建验收** | 修改后的 patch 可通过 kpatch 工具构建为热补丁模块 |
| **运行验收** | 模块可加载/卸载；通过功能验证和回归测试 |
| **结果产出** | 每个补丁的结构化 JSON 报告 + 日志 + 生成的产物 |

---

## 7. 评审要点

| 维度 | 权重 | 说明 |
|------|------|------|
| **核心效果** | 50% | 在最终评测集上成功生成并通过加载验证的数量/比例（主排名依据） |
| **正确性与安全性** | 30% | 改写保持修复语义；不引入回归或风险操作；验证步骤可靠 |
| **工程完整度与可复现性** | 10% | 环境一键部署（容器/脚本）；输入输出规范；可在评测环境稳定运行 |
| **文档与 Demo 表现** | 10% | README、架构说明、测试说明、失败案例分析；录屏 Demo 清晰可复现 |

---

## 8. 参考资料

### 8.1 Livepatch/kpatch

| 资源 | 地址 |
|------|------|
| kpatch 仓库与文档 | `https://github.com/dynup/kpatch` |
| Linux 内核 livepatch 文档 | `https://docs.kernel.org/livepatch/livepatch.html` |
| Kpatch 补丁作者指南 | `https://github.com/dynup/kpatch/blob/master/doc/patch-author-guide.md` |

---

## 9. 项目实现对照

### 9.1 已完成能力

| 赛题要求 | 实现状态 | 对应模块 |
|----------|----------|----------|
| CVE 查询与补丁获取 | ✅ 已实现 | `cve_resolver.py`, `patch_fetcher.py` |
| 补丁结构化解析 | ✅ 已实现 | `patch_parser.py` |
| kpatch-build 自动构建 | ✅ 已实现 | `kpatch_builder.py` |
| 失败归因分类 | ✅ 已实现 | `failure_classifier.py` |
| 自动改写（规则+LLM） | ✅ 已实现 | `rewrite_advisor.py` |
| 运行验证 | ✅ 已实现 | `verifier.py` |
| 报告生成 | ✅ 已实现 | `reporter.py` |
| 状态机与多轮重试 | ✅ 已实现 | `planner.py`, `state.py` |
| CLI 入口 | ✅ 已实现 | `__main__.py`, `run` |
| Docker 容器化 | ✅ 已实现 | `Dockerfile`, `docker-compose.yml` |
| 环境安装脚本 | ✅ 已实现 | `setup_env.sh` |
| 测试用例 | ✅ 108 个测试通过 | `tests/` |
| 详细设计文档 | ✅ 已实现 | `README.md` |
| 使用指南 | ✅ 已实现 | `USAGE.md` |
| YAML 规则引擎 | ✅ 已实现 | `knowledge/loader.py`, `rules/*.yaml` |
| LLM 集成（框架） | ✅ 已实现 | `llm/` |
| RAG 知识库 | ✅ 122 条知识 | `rag/` |
| 补丁语义验证 | ✅ 已实现 | `tools/semantic_validator.py` |
| 内核 config 检查 | ✅ 已实现 | `tools/kernel_config_checker.py` |
| NVD 缓存 | ✅ 已实现 | `cve_resolver.py`（磁盘缓存）|
| Patch 缓存 | ✅ 已实现 | `patch_fetcher.py`（磁盘缓存）|

### 9.2 待完善能力

| 赛题要求 | 当前状态 | 说明 |
|----------|----------|------|
| LLM 平台应用链接 | ⏳ 待部署 | 需要在LLM 平台创建智能体应用 |
| MCP 服务 | ⏳ 待开发 | 需要封装 MCP 接口供LLM 调用 |
| 函数计算 FC 部署 | ⏳ 待部署 | 需要制作自定义镜像并部署到 FC |
| 最终评测集验证 | ⏳ 待测试 | 需要获取 Final 数据集进行验证 |
| 录屏 Demo | ⏳ 待制作 | 需要录制完整流程演示视频 |

---

## 10. 核心流水线

```
CVE输入 → 检索 → 获取补丁 → 解析patch → 构建kpatch → 验证 → 报告
  ↓        ↓        ↓         ↓         ↓        ↓       ↓
resolver parser  fetcher   builder  verifier reporter
                    ↕ planner (状态机调度, 最多5轮重试) ↕
              失败 → classifier → advisor → 改写重试/人工
```

---

## 11. 输出产物结构

```
work/CVE-YYYY-NNNN/
├── state.json                # 状态机当前状态
├── metadata/
│   ├── cve_metadata.json     # CVE 元数据（NVD）
│   └── candidate_commits.json # 候选修复 commit
├── patches/
│   ├── original.patch        # 原始补丁
│   └── attempt_N.patch       # 第 N 轮改写补丁
├── logs/
│   ├── build_N.log           # 第 N 轮构建日志
│   └── verify_N.log          # 验证日志
├── artifacts/
│   └── livepatch.ko          # 编译产物
├── patch_ir.json             # 补丁解析结果
├── failure.json              # 失败分类记录
├── rewrite_plan.json         # 重写建议
├── attempt_N.json            # 第 N 轮尝试记录
├── verification.json         # 验证结果
├── events.json               # 全流程事件日志
└── report.json               # 最终报告
```

---

*本文档基于 2026 年全国大学生计算机系统能力大赛操作系统设计赛赛题要求编写，用于明确项目目标、交付标准和评审依据。*
