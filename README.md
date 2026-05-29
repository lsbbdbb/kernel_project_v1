# kernel_project_v1 — 仓库主分支使用说明

本文档说明本仓库 `main` 分支的当前状态、如何启动（本地）以及已上传/排除的文件策略。

**一、项目总体**

- 仓库包含若干源码、脚本与示例（例如根目录下的 `_run_demo.py`、`_patch_server.py` 等），以及一个较大的子目录 `kernel-livepatch-agent`（包含内核源码、构建产物与测试用例）。
- 注意：`kernel-livepatch-agent` 内部包含大量构建产物与二进制（内核镜像、模块、rpm 等），有多个文件大于 100MB，已在根目录 `.gitignore` 中将这些构建产物排除，避免直接将大文件推送到 GitHub。

**二、启动说明（本地）**

- 快速查看/运行示例脚本（请先进入仓库根目录）：

	- 查看演示脚本：`python _run_demo.py`（仅示例，仅在有 Python 依赖时运行）
	- agent 相关脚本与说明位于 `kernel-livepatch-agent/README.md`，运行前请先阅读该文件并按其中要求准备环境（例如 Docker、依赖安装等）。

注意：仓库中未包含运行环境（虚拟机映像或容器镜像），运行前请确保本地环境满足脚本文档要求。

**三、已上传 / 已排除的文件**

- 已上传到远程分支：`v3`（包含仓库的当前元数据与 README、脚本等）。
- 已排除的内容：内核构建产物（`*.o`、`*.ko`、`vmlinux*`）、RPM 包、`kernel-livepatch-agent` 下的 `kernel-src`、`packages`、`acceptance_vm_20260525` 等大文件目录，见 `.gitignore`。
- 嵌套仓库：`kernel-livepatch-agent` 目录包含自己的 `.git`（嵌套仓库）。如果需要保留该子仓库的提交历史，建议将其作为 git submodule 引入；否则可在根仓库中仅保留其文件快照并移除嵌套 `.git`。

**四、常用 Git 操作（示例）**

克隆仓库并切换分支：

```bash
git clone https://github.com/lsbbdbb/kernel_project_v1.git
cd kernel_project_v1
git checkout v3    # 查看已上传的 v3 分支内容
git checkout main  # 切回主分支
```

如果你希望我把子仓库改为 submodule 或把某些大文件改为 Git LFS，请告知，我可以执行相应操作或生成详细命令。

---
更新记录：重写 `main` 分支 README，说明启动情况与上传/排除策略。
