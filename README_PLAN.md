# kernel-livepatch-agent AI 化实施方案

## 当前状态

项目是一套**内核 CVE 热补丁流水线框架**，包含完整的状态机、工具封装和测试覆盖（30 个测试全部通过），Docker 部署已就绪。

但是核心的 AI 部分还没实现：

| 问题                  | 说明                                                                    |
| --------------------- | ----------------------------------------------------------------------- |
| RewriteAdvisor 是骨架 | `apply_rewrite()` 只做 `shutil.copy2()`，不真正改写补丁             |
| 零 LLM 集成           | 整个代码库没有调用任何 AI 模型                                          |
| RAG 目录为空          | `agent/rag/` 只有空的 `__init__.py`                                 |
| YAML 知识文件未连接   | `failure_patterns.yaml` 和 `rewrite_strategies.yaml` 写了但没被加载 |
| 有一个 bug            | `kpatch_builder.py` 用了 `shutil.copy2` 但没 `import shutil`      |

## 为什么当前只能输出 manual_required

USAGE.md 明确要求：

> | 构建环境 | Fedora x86_64 / Anolis OS 23.4 container |
> | 目标内核 | Anolis OS ANCK 6.6.102-5.2.an23.x86_64 |
> | 验证环境 | Anolis OS 23.4 VM |

当前 Dockerfile 只有 `python:3.11-slim` + 几个 apt 包，缺失：
- **kpatch-build** 工具链（USAGE.md Step 3）
- **龙蜥内核源码树** `kernel-src/linux-6.6.102-5.2.an23.x86_64/`（USAGE.md Step 4）
- **vmlinux**（kpatch-build 的 `-v` 参数必需）

所以 `run_build` 检测不到源码树直接跳过 → 无编译产物 → `classify_failure` 赶上 log_not_found → `manual_required`。

## 目标

1. **Phase 0**: 搭建龙蜥内核编译环境，让 kpatch-build 能真正产出 .ko
2. **Phase 1-6**: 将确定性流水线升级为 **LLM 驱动的智能 agent**：

- Planner 做 AI 推理决策（重试/放弃/改写）
- RewriteAdvisor 调用 LLM 真正生成改写后的补丁
- RAG 系统检索内核知识辅助 LLM
- YAML 知识文件成为规则来源

同时保持 `--no-llm` 模式，无 LLM 也能运行。

LLM 后端选择：**通义千问/百炼**（DashScope OpenAI 兼容 API）。

---

## 总体架构

```
┌────────────────────────────────────────────────────┐
│                  __main__.py (CLI)                  │
│  --no-llm / --llm-provider / --llm-model           │
├────────────────────────────────────────────────────┤
│              LLMPlanner (planner.py)                │
│  决策点用 LLM，否则用规则 fallback                    │
├────────────────────────────────────────────────────┤
│                  Tools Layer                        │
│  ┌──────────┬──────────┬──────────┬─────────────┐ │
│  │Resolver  │Fetcher   │Parser    │Builder      │ │
│  ├──────────┼──────────┼──────────┼─────────────┤ │
│  │Classifier│Advisor   │Verifier  │Reporter     │ │
│  │ (YAML)   │ (LLM)    │          │             │ │
│  └──────────┴──────────┴──────────┴─────────────┘ │
├────────────────────────────────────────────────────┤
│              LLM Layer (agent/llm/)                 │
│  ┌────────────┬────────────┬────────────────────┐ │
│  │ config.py  │ client.py  │ prompts/templates  │ │
│  │ LLMConfig  │ LLMClient  │ generate_rewrite_   │ │
│  │            │ .chat()    │ diff() etc.        │ │
│  └────────────┴────────────┴────────────────────┘ │
├────────────────────────────────────────────────────┤
│              RAG Layer (agent/rag/)                 │
│  ┌──────────────┬──────────────┬────────────────┐ │
│  │knowledge_base│ retriever.py │ YAML knowledge │ │
│  │.py           │ BM25 search  │ files          │ │
│  └──────────────┴──────────────┴────────────────┘ │
└────────────────────────────────────────────────────┘
```

---

## Phase 0: 龙蜥内核编译环境

### 问题

当前 Docker 是 Debian-based，没有 kpatch-build、没有龙蜥内核源码，流水线在 `run_build` 步骤跳过编译，永远 `manual_required`。

### 方案

换用 **Anolis OS 23** 作为基础镜像，在容器内安装 kpatch-build + 拉取龙蜥内核源码 + 编译 vmlinux。

#### 0.1 重写 Dockerfile

**文件:** `Dockerfile`

```dockerfile
# 基础镜像换为 Anolis OS 23（龙蜥官方镜像）
FROM registry.openanolis.cn/openanolis/anolisos:23

LABEL description="Kernel CVE Livepatch Agent - Anolis OS Build Environment"

# Anolis OS 用 yum/dnf
RUN dnf install -y --setopt=tsflags=nodocs \
    gcc gcc-c++ make git patch diffutils binutils \
    elfutils-libelf-devel openssl-devel kmod \
    python3 python3-pip \
    bc bison flex ncurses-devel \
    kernel-devel \
    && dnf clean all

# 安装 kpatch 工具链
RUN dnf install -y --setopt=tsflags=nodocs \
    kpatch kpatch-build \
    || (git clone https://github.com/dynup/kpatch.git /tmp/kpatch \
        && cd /tmp/kpatch && make && make install)

# Python 依赖（清华镜像）
RUN pip3 config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

WORKDIR /app
COPY . .
RUN pip3 install --no-cache-dir -r requirements.txt pytest

# 准备内核源码目录（运行时 mount 或下载）
RUN mkdir -p /kernel-src

# 默认启动脚本：检查环境然后跑测试
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["test"]
```

#### 0.2 内核源码准备脚本

**新文件:** `scripts/download_kernel_src.sh`

```bash
#!/bin/bash
# 下载龙蜥内核源码并编译 vmlinux
# 用法: bash scripts/download_kernel_src.sh [kernel_version]

KERNEL_VERSION="${1:-6.6.102-5.2.an23.x86_64}"
KERNEL_BASE="${KERNEL_VERSION%%.*}"
SRC_DIR="$(dirname "$0")/../kernel-src/linux-${KERNEL_VERSION}"

if [ -d "$SRC_DIR" ]; then
    echo "内核源码已存在: $SRC_DIR"
    exit 0
fi

mkdir -p "$SRC_DIR"
cd "$SRC_DIR"

# 从龙蜥 Gitee 克隆 cloud-kernel
git clone --depth=1 --branch linux-${KERNEL_BASE} \
    https://gitee.com/anolis/cloud-kernel.git .

# 配置内核
make defconfig
# 启用 livepatch 相关选项
scripts/config -e LIVEPATCH
scripts/config -e HAVE_LIVEPATCH
scripts/config -e KALLSYMS_ALL

# 编译 vmlinux（kpatch-build 需要）
make -j$(nproc) vmlinux modules_prepare

echo "内核源码就绪: $SRC_DIR"
echo "vmlinux: $SRC_DIR/vmlinux"
```

#### 0.3 docker-compose.yml 更新

```yaml
services:
  agent:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - .:/app
      - ./kernel-src:/kernel-src  # 挂载内核源码
    working_dir: /app
    environment:
      - KERNEL_SRC=/kernel-src/linux-6.6.102-5.2.an23.x86_64

  agent-dev:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - .:/app
      - ./kernel-src:/kernel-src
    working_dir: /app
    stdin_open: true
    tty: true
    entrypoint: ["/bin/bash"]

  agent-run:
    build:
      context: .
      dockerfile: Dockerfile
    volumes:
      - .:/app
      - ./kernel-src:/kernel-src
      - agent-output:/tmp/test_workspace
    working_dir: /app
    command: ["python3", "-m", "agent", "--cves", "sample_cves.txt",
              "--workdir", "/tmp/test_workspace",
              "--kernel-version", "6.6.102-5.2.an23.x86_64"]
```

#### 0.4 容器启动入口

**新文件:** `docker-entrypoint.sh`

```bash
#!/bin/bash
set -e

echo "=== Kernel Livepatch Agent - Anolis OS Environment ==="

# 检查内核源码
SRC_DIR="${KERNEL_SRC:-/kernel-src/linux-6.6.102-5.2.an23.x86_64}"
if [ -d "$SRC_DIR" ] && [ -f "$SRC_DIR/vmlinux" ]; then
    echo "[OK] Kernel source: $SRC_DIR"
    echo "[OK] vmlinux found"
else
    echo "[WARN] Kernel source NOT found at $SRC_DIR"
    echo "       Run: bash scripts/download_kernel_src.sh"
fi

# 检查 kpatch-build
if command -v kpatch-build &>/dev/null; then
    echo "[OK] kpatch-build: $(which kpatch-build)"
else
    echo "[WARN] kpatch-build NOT found"
fi

case "${1:-test}" in
    test)
        exec python3 -m pytest tests/ -v
        ;;
    shell)
        exec /bin/bash
        ;;
    run)
        exec python3 -m agent --cves sample_cves.txt --workdir /tmp/test_workspace
        ;;
    *)
        exec "$@"
        ;;
esac
```

### Phase 0 验证

```bash
# Step 1: 下载内核源码（一次性，约 20 分钟）
bash scripts/download_kernel_src.sh

# Step 2: 构建镜像
docker compose build agent

# Step 3: 运行测试
docker compose up agent
# 预期: 30 个测试通过 + 环境检查显示 [OK]

# Step 4: 进入容器验证环境
docker compose run --rm agent-dev
# 在容器内:
#   kpatch-build --version
#   ls /kernel-src/linux-6.6.102-5.2.an23.x86_64/vmlinux
#   python3 -m agent --cves sample_cves.txt --workdir /tmp/test_run
```

---

## Phase 1: 修 bug + 加载 YAML

### 1.1 修复 kpatch_builder.py

**文件:** `agent/tools/kpatch_builder.py`
**改动:** import 区加一行 `import shutil`
**原因:** 第 53 行调用了 `shutil.copy2()` 但从未 import

### 1.2 创建 YAML 知识加载器

**新文件:** `agent/knowledge/__init__.py`、`agent/knowledge/loader.py`

```python
class KnowledgeLoader:
    _cache = {}
  
    @classmethod
    def load_failure_patterns(cls) -> list:
        # 从 rules/failure_patterns.yaml 加载，内存缓存
  
    @classmethod
    def load_rewrite_strategies(cls) -> list:
        # 从 rules/rewrite_strategies.yaml 加载，内存缓存
```

### 1.3 重构 failure_classifier.py

**文件:** `agent/tools/failure_classifier.py`
**改动:** `FAILURE_PATTERNS` 优先从 `KnowledgeLoader.load_failure_patterns()` 加载，硬编码列表作为 fallback
**规范化:** YAML 的 `action: rewrite` → Python 的 `retryable: True, next_action: "rewrite"`

### 1.4 重构 rewrite_advisor.py

**文件:** `agent/tools/rewrite_advisor.py`
**改动:** `REWRITE_STRATEGIES` 优先从 `KnowledgeLoader.load_rewrite_strategies()` 加载，YAML 不可用时 fallback 到硬编码

### 1.5 补全 YAML

**文件:** `agent/knowledge/rules/failure_patterns.yaml`**改动:** 添加 Python 中有但 YAML 缺失的 4 个模式：

- `apply.file_missing`（文件缺失，不可自动修复）
- `compile.implicit_decl`（隐式声明，可重写）
- `compile.unknown_field`（结构体字段不匹配，不可自动修复）
- `compile.undefined_symbol`（未定义符号，可重写）

### Phase 1 验证

```bash
python -m pytest tests/ -v
# 30 个测试全部通过

python -c "from agent.knowledge.loader import KnowledgeLoader; print(len(KnowledgeLoader.load_failure_patterns()))"
# 输出: 9
```

---

## Phase 2: LLM 集成基础

### 2.1 LLM 配置

**新文件:** `agent/llm/__init__.py`、`agent/llm/config.py`

```python
@dataclass
class LLMConfig:
    provider: str = "qwen"          # qwen | openai | anthropic | ollama
    model: str = "qwen-max"         # qwen-max / qwen-plus / qwen-turbo
    api_key: Optional[str] = None   # 从环境变量 DASHSCOPE_API_KEY 读取
    base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    temperature: float = 0.3
    max_tokens: int = 4096
    timeout: int = 120
  
    @classmethod
    def from_env(cls) -> "LLMConfig":
        # 从环境变量自动配置
```

### 2.2 LLM 客户端

**新文件:** `agent/llm/client.py`

```python
class LLMClient:
    def __init__(self, config: LLMConfig):
        # 用 OpenAI SDK 连接 DashScope
        self.client = openai.OpenAI(
            api_key=config.api_key,
            base_url=config.base_url
        )
  
    def chat(self, messages: List[Dict]) -> str:
        # 发送 chat completion，返回响应文本
  
    def ping(self) -> bool:
        # 健康检查，无 key 或无网络返回 False
```

**依赖新增:** `openai>=1.0.0` 加入 `requirements.txt`

### 2.3 提示词模板

**新文件:** `agent/llm/prompts/__init__.py`、`agent/llm/prompts/templates.py`

每个模板是 Python 函数，返回 `List[Dict]`（messages 格式）：

| 模板                                                                | 用途                      |
| ------------------------------------------------------------------- | ------------------------- |
| `diagnose_failure(build_log, patch_ir)`                           | 诊断 kpatch-build 失败    |
| `plan_rewrite_strategy(failure, change_units, history)`           | 决定用哪种改写策略        |
| `generate_rewrite_diff(patch, failure, units, strategy, context)` | 生成改写后的 unified diff |
| `decide_retry(state, failure, attempt, max_attempts)`             | 决定继续重试还是放弃      |

### Phase 2 验证

```bash
# 无 API key 时 graceful degradation
python -c "from agent.llm.client import LLMClient; from agent.llm.config import LLMConfig; c=LLMClient(LLMConfig()); print(c.ping())"
# 输出: False

# 提示词模板可导入
python -c "from agent.llm.prompts.templates import *; print('OK')"
```

---

## Phase 3: 智能 Planner

### 3.1 LLMPlanner

**文件:** `agent/planner.py`（新增类）

```python
class LLMPlanner(Planner):
    def __init__(self, state_mgr, llm_client=None):
        super().__init__(state_mgr)
        self.llm = llm_client
  
    def decide_next(self, cve_id):
        # 线性转换用规则（TaskCreated→CveResolved→...）
        # 决策点用 LLM（FailureClassified → 重试/改写/放弃?）
        # LLM 不可用时完全回退到父类逻辑
```

LLM 介入的三个决策点：

- `FailureClassified`: 这个失败值得重试吗？用什么策略？
- `BuildFailed`: 错误原因是什么？
- `VerifyFailed`: 继续还是放弃？

### 3.2 CLI 接入

**文件:** `agent/__main__.py`

新增参数：

- `--no-llm` 强制规则模式
- `--llm-provider qwen` 指定后端
- `--llm-model qwen-max` 指定模型

LLM 初始化 → 传给 LLMPlanner → 进入流水线。

### Phase 3 验证

```bash
# 无 LLM 模式行为不变
python -m agent --cves sample_cves.txt --workdir /tmp/test --no-llm
# 输出应与原来完全一致

python -m pytest tests/ -v
# 全部通过
```

---

## Phase 4: 真正的补丁改写

### 4.1 重写 apply_rewrite()

**文件:** `agent/tools/rewrite_advisor.py`

```python
def apply_rewrite(self, original_patch_path, rewrite_plan, target_source_dir, attempt):
    with open(original_patch_path) as f:
        original_patch = f.read()
  
    if self.llm and self.llm.ping():
        rewritten = self._llm_rewrite(original_patch, ...)  # 调用 LLM
        if rewritten and self._validate_rewrite(rewritten, target_source_dir):
            # 写入 attempt_N.patch
            return {"success": True, "output_path": ...}
  
    # LLM 不可用 → 规则回退
    return self._rule_based_rewrite(original_patch, ...)
```

新增三个方法：

- `_llm_rewrite()`: 调提示词模板 → 发 LLM 请求 → 从响应提取 diff
- `_validate_rewrite()`: 跑 `git apply --check` 验证 diff 合法性
- `_rule_based_rewrite()`: 简单规则（调整 hunk 行号偏移等）

### 4.2 语义验证器

**新文件:** `agent/tools/semantic_validator.py`

验证改写后的补丁质量：

- 安全检查边界保留（`if (!ptr)`, `if (len > MAX)` 等）
- 错误返回路径保留（`return -EINVAL` 等）
- 未引入新全局变量
- `__init` 函数未被修改
- 语义角色未漂移

### Phase 4 验证

```bash
# 单元测试: mock LLM 返回改写后的 diff
python -m pytest tests/ -v
# 验证 attempt_N.patch ≠ original.patch
```

---

## Phase 5: RAG 系统

### 5.1 知识库

**新文件:** `agent/rag/__init__.py`、`agent/rag/knowledge_base.py`

```python
class KnowledgeChunk:
    id: str
    content: str
    metadata: dict

class KnowledgeBase:
    def __init__(self):
        self.documents: List[KnowledgeChunk] = []
  
    def load_yaml_rules(self):
        # 从失败模式/改写策略 YAML 构建 chunks
  
    def add_kernel_api_doc(self, symbol, signature, description):
        # 添加内核 API 变更记录
```

新增 `agent/knowledge/kernel_api/kernel_6.6_api.yaml`：记录 6.6 内核相对于旧版本的 API 变化。

### 5.2 检索引擎

**新文件:** `agent/rag/retriever.py`

```python
class KnowledgeRetriever:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
  
    def retrieve(self, query: str, top_k: int = 5) -> List[KnowledgeChunk]:
        # BM25 检索（rank_bm25 库，纯 Python，零外部依赖）
```

为什么选 BM25 而不是向量数据库：知识库只有几十条记录，BM25 对关键词（内核错误信息、函数名）匹配效果足够好，且不需要 embedding API 或模型。

### 5.3 注入到 LLM 提示词

RewriteAdvisor 在 `_llm_rewrite()` 中：

1. 从 failure 提取查询关键词（reason_code + 函数名 + 错误信息）
2. `retriever.retrieve(query)` 获取 top-3 相关 chunks
3. 拼接到 LLM 提示词最前面作为参考知识

### Phase 5 验证

```bash
python -c "
from agent.rag.knowledge_base import KnowledgeBase
kb = KnowledgeBase()
kb.load_yaml_rules()
print(len(kb.documents))  # > 0
"

python -c "
from agent.rag.retriever import KnowledgeRetriever
# 检索 'api mismatch function arguments' 应返回相关 chunk
"
```

---

## Phase 6: 测试与完善

### 6.1 新增测试

| 文件                              | 内容                                                   |
| --------------------------------- | ------------------------------------------------------ |
| `tests/test_llm_client.py`      | 客户端初始化、各 provider 配置、ping()、mock chat 响应 |
| `tests/test_prompts.py`         | 各模板函数产出的 messages 格式正确、包含应有的内容     |
| `tests/test_rag.py`             | 知识库加载、BM25 检索相关性、空库边界                  |
| `tests/test_integration_llm.py` | mock LLM 走完整流水线、LLM 不可用时 fallback           |

### 6.2 Docker 更新

- `Dockerfile`: 添加 `ENV DASHSCOPE_API_KEY=""`
- `docker-compose.yml`: 支持从 `.env` 文件读入 API key

### 6.3 E2E 验证（需要真实 API key）

```bash
export DASHSCOPE_API_KEY="your-key"
python -m agent --cves sample_cves.txt --workdir /tmp/e2e --llm-provider qwen
# 验证:
# - attempt_N.patch 内容不同于 original.patch
# - report.json 中显示 source: "llm"
# - 改写后的补丁能过 git apply --check
```

---

## 文件变更总览

### 新建 (17 个)

```
scripts/download_kernel_src.sh           # Phase 0: 龙蜥内核源码下载脚本
docker-entrypoint.sh                     # Phase 0: 容器启动环境检查
agent/knowledge/__init__.py
agent/knowledge/loader.py
agent/knowledge/kernel_api/kernel_6.6_api.yaml
agent/llm/__init__.py
agent/llm/config.py
agent/llm/client.py
agent/llm/prompts/__init__.py
agent/llm/prompts/templates.py
agent/rag/knowledge_base.py
agent/rag/retriever.py
agent/tools/semantic_validator.py
tests/test_llm_client.py
tests/test_prompts.py
tests/test_rag.py
tests/test_integration_llm.py
```

### 修改 (11 个)

```
Dockerfile                              # Phase 0: 换 Anolis OS 基础镜像 + kpatch 工具链
docker-compose.yml                      # Phase 0: 挂载内核源码卷 + 环境变量
agent/tools/kpatch_builder.py           # Phase 1: 添加 import shutil
agent/tools/failure_classifier.py       # Phase 1: YAML 加载 + fallback
agent/tools/rewrite_advisor.py          # Phase 1+4: YAML 加载 + LLM 改写 + RAG 检索
agent/planner.py                        # Phase 3: 新增 LLMPlanner
agent/__main__.py                       # Phase 3: LLM 初始化 + 新 CLI 参数
agent/rag/__init__.py                   # Phase 5: 替换空壳
agent/knowledge/rules/failure_patterns.yaml  # Phase 1: 补全缺失模式
requirements.txt                        # Phase 2: 添加 openai, rank-bm25
```

---

## 核心设计原则

1. **无 LLM 也能跑** — 每个 LLM 路径都有规则 fallback，`--no-llm` 保持原有行为
2. **通义千问优先** — DashScope API 国内访问快，OpenAI 兼容协议
3. **BM25 做检索** — 知识库小（几十条），不需要向量数据库或 embedding API
4. **YAML 为知识源** — 改规则只需编辑 YAML 文件，不碰 Python 代码
5. **提示词是 Python 函数** — 类型安全、可直接单测、参数清晰
6. **Phase 1 零风险** — 只修 bug + 连接已有文件，不改业务逻辑
