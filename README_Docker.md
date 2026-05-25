# Docker 部署说明

## 概述

项目 Docker 环境基于 **Anolis OS 23**（龙蜥操作系统），预装 `kpatch` / `kpatch-build` 工具链和 Python 依赖，挂载本机内核源码树，开箱即用。

---

## 环境要求

- Docker 24+ / Docker Desktop 28.1.1+
- 内核源码树 `kernel-src/linux-6.6.102-5.2.an23.x86_64/`（含预编译 `vmlinux`）
- 建议磁盘剩余空间 10 GB+

---

## 快速开始

```bash
# 1. 确保内核源码就绪（约 5 GB）
ls kernel-src/linux-6.6.102-5.2.an23.x86_64/vmlinux

# 2. 构建镜像（首次约 5 分钟）
docker compose build agent

# 3. 运行测试
docker compose up agent
```

---

## 服务说明

| 服务 | 命令 | 用途 |
|------|------|------|
| `agent` | `docker compose up agent` | 运行单元测试（默认） |
| `agent-run` | `docker compose up agent-run` | 全链路流水线（需 `DEEPSEEK_API_KEY`） |
| `agent-run-no-llm` | `docker compose up agent-run-no-llm` | 全链路流水线（规则模式，无需 API key） |
| `agent-dev` | `docker compose run --rm agent-dev` | 交互式开发 shell |

### 流水线模式

```bash
# 规则模式（推荐，首次运行）
docker compose up agent-run-no-llm

# LLM 模式（需要 API key）
export DEEPSEEK_API_KEY=sk-xxx
docker compose up agent-run
```

### 交互式开发

```bash
docker compose run --rm agent-dev shell

# 进入容器后：
pytest tests/ -v
python -m agent --cves sample_cves.txt --no-llm
exit
```

---

## 架构说明

```
容器内 (/)
├── /app                    # 项目源码（宿主挂载）
│   ├── agent/              # Python 主模块
│   ├── tests/              # 测试套件
│   └── sample_cves.txt     # 示例输入
├── /kernel-src/            # 内核源码树（宿主挂载）
│   └── linux-6.6.102-5.2.an23.x86_64/
│       ├── vmlinux         # kpatch-build 必需
│       └── .config         # 已配置的内核编译配置
└── /tmp/test_workspace/    # 流水线输出（持久卷）
```

---

## 流水线输出

每个 CVE 在 `/tmp/test_workspace/` 下的独立目录包含：

| 文件 | 说明 |
|------|------|
| `patches/original.patch` | 原始上游补丁 |
| `patches/attempt_N.patch` | 第 N 次改写后的补丁 |
| `logs/build_N.log` | 第 N 次构建日志 |
| `metadata/` | NVD 原始数据、CVE 元数据 |
| `events.json` | 状态机事件时间线 |
| `summary.json` | 批量汇总报告 |

---

## Dockerfile 说明

```dockerfile
FROM registry.openanolis.cn/openanolis/anolisos:23
# 安装 gcc, make, kpatch, kpatch-build, python3, 内核编译依赖
# 配置清华 PyPI 镜像
# 安装 python 依赖（requirements.txt + pytest）
```

---

## 注意事项

1. **内核源码**: 容器通过 volume 挂载宿主 `./kernel-src` 到 `/kernel-src`，不复制避免镜像体积膨胀
2. **编译耗时**: `kpatch-build` 编译 vmlinux 需数小时（取决于 CPU 核数），`-j$(nproc)` 自动并行
3. **网络**: `dnf` 和 `pip` 已配置国内镜像，首次构建需联网
4. **权限**: 容器内 `kpatch-build` 以 root 运行，挂载卷的文件权限可能变为 root，用 `chown` 恢复
