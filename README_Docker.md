# Docker 部署说明

## 做了什么

本项目 `kernel-livepatch-agent` 已通过 Docker Desktop 完成容器化部署，包含：

- 构建 Docker 镜像（基于 `python:3.11-slim`）
- 配置国内镜像源（解决网络问题）
- 运行单元测试（30/30 通过）
- 运行完整 agent 流水线（2 个 CVE 示例）

## 环境要求

- Docker Desktop（28.1.1+）
- 任意终端（PowerShell / Git Bash / CMD）

## 部署

```bash
# 进入项目目录
cd kernel-livepatch-agent

# 构建镜像（已构建过可跳过）
docker compose build agent

# 运行测试
docker compose up agent
```

## 三个服务

| 服务 | 命令 | 用途 |
|------|------|------|
| agent | `docker compose up agent` | 运行单元测试（默认） |
| agent-run | `docker compose up agent-run` | 用 sample_cves.txt 运行完整流水线 |
| agent-dev | `docker compose run --rm agent-dev` | 交互式开发 shell（/bin/bash） |

## 进入开发环境

```bash
docker compose run --rm agent-dev
```

进入容器后在 `/app` 目录下可以执行：

```bash
# 运行测试
pytest tests/ -v

# 模块导入验证
python -c "from agent.state import StateManager; print('state OK')"
python -c "from agent.planner import Planner; print('planner OK')"

# 运行 agent
python -m agent --cves sample_cves.txt --workdir /tmp/test_workspace

# 退出
exit
```

## 修改的文件

### Dockerfile

原文件使用 `python:3.10-slim` 并从 `deb.debian.org` 和 PyPI 官方源下载依赖，在国内网络下超时。

修改内容：
1. 基础镜像改为 `python:3.11-slim`（本地已有，无需拉取）
2. `apt` 源替换为清华镜像 `mirrors.tuna.tsinghua.edu.cn`
3. `pip` 源替换为清华镜像 `pypi.tuna.tsinghua.edu.cn`

### docker-compose.yml

移除已废弃的 `version: "3.8"` 字段。

## 流水线流程

每个 CVE 经过 7 个步骤：

```
resolve_cve → fetch_patch → analyze_patch → check_target
→ apply_patch → run_build → classify_failure
```

最终输出到 `/tmp/test_workspace/`，包括：
- 各 CVE 的独立工作目录
- `summary.json` — 批量汇总报告

## 当前局限

- 容器内无真实 Linux 内核源码树，`kpatch-build` 无法实际编译，状态为 `manual_required`
- 需要真实的 CVE 编号配合网络访问才能拉取补丁
