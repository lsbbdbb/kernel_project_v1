# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kernel CVE Livepatch Auto-Generation Agent for Anolis OS. Takes CVE IDs as input, automatically resolves patches from NVD, parses diffs into structured IR, builds livepatch `.ko` modules via kpatch-build, classifies failures, rewrites patches (rule-based + LLM-assisted), and verifies on a remote VM. Targets kernel 6.6.102-5.2.an23.x86_64.

## Common Commands

```bash
# Run all tests (pytest, ~110 tests)
python3 -m pytest tests/ -v

# Run a single test file
python3 -m pytest tests/test_failure_classifier.py -v

# Run a single test by name
python3 -m pytest tests/test_planner.py::test_specific -v

# Install for development
pip install -r requirements.txt && pip install -e .

# Run pipeline (rule-only, no LLM)
python3 -m agent --cves sample_cves.txt --no-llm

# Run pipeline with LLM
python3 -m agent --cves sample_cves.txt --llm-provider deepseek

# Web control panel
python3 -m agent.web.server

# Docker: run tests
docker compose up agent

# Docker: full pipeline (no LLM)
docker compose up agent-run-no-llm

# Docker: interactive shell
docker compose run agent-dev

# Clean build artifacts
make clean
```

## Architecture

### State Machine Pipeline

The core is a per-CVE state machine managed by `StateManager` (`agent/state.py`). Each CVE progresses through:

```
TaskCreated → CveResolved → PatchFetched → PatchAnalyzed → TargetChecked
→ PatchApplied → BuildRunning → BuildSucceeded/BuildFailed
→ (on failure) FailureClassified → RewritePrepared → (retry from PatchApplied)
→ LoadTesting → Verified → ReportWritten
```

Terminal states: `ManualRequired`, `Failed`, `Skipped`. Final statuses: `success`, `failed`, `manual_required`, `skipped`.

`Planner` (`agent/planner.py`) maps each state to the next action. `LLMPlanner` extends it with LLM consultation at the `FailureClassified` decision point only — all other transitions are deterministic.

### Pipeline Tools (`agent/tools/`)

| Module | Purpose |
|--------|---------|
| `cve_resolver.py` | NVD API 2.0 query with retry + disk cache, extracts git.kernel.org patch URLs |
| `patch_fetcher.py` | Downloads patches with persistent file caching |
| `patch_parser.py` | Parses unified diffs → `patch_ir.json`, `change_units.json`; extracts risk tags and semantic summaries |
| `kernel_config_checker.py` | Resolves patched files through Kbuild Makefiles to check if kernel config disables them |
| `kpatch_builder.py` | Wraps kpatch-build execution, environment setup, artifact collection |
| `failure_classifier.py` | 18 hardcoded + YAML-loaded patterns; classifies into: `compile`, `kpatch_limit`, `env_missing`, `patch_apply` |
| `rewrite_advisor.py` | 6 strategies: `context_drift`, `api_mismatch`, `missing_include`, `no_fentry`, `struct_abi`, `data_change`. LLM-based rewrite with RAG context or rule-based fallback |
| `semantic_validator.py` | Validates rewrites preserve security checks, error paths, no new globals, init functions, allocation/free balance |
| `verifier.py` | Remote VM verification via SSH: scp → insmod → sysfs check → optional PoC → rmmod |
| `reporter.py` | Structured JSON + human-readable Markdown reports |

### LLM Integration (`agent/llm/`)

Uses OpenAI-compatible API. Three providers configured in `agent/llm/config.py`:
- **DeepSeek** (default): model `deepseek-v4-pro`
- **OpenAI**: model `gpt-4o-mini`
- **Ollama**: model `llama3.1`

Config via env vars: `DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_API_KEY`, `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`.

### RAG System (`agent/rag/`)

`KnowledgeBase` loads YAML rules (`agent/knowledge/rules/`), kernel API docs (`agent/knowledge/kernel_api/kernel_6.6_api.yaml`), and markdown knowledge chunks (`agent/knowledge/rag_knowledge/`). `KnowledgeRetriever` uses BM25 (`rank-bm25`) with TF-based fallback. Injected into LLM rewrite prompts.

### Web Control Panel (`agent/web/`)

Flask app (`agent/web/server.py`) with SSE event streaming. Key endpoints: `/api/status`, `/api/cves`, `/api/cve/<id>/trace`, `/api/events` (SSE), `/api/run`, `/api/stop`.

### State & Output Structure

Each CVE gets a subdirectory under the workdir (default `./run_<timestamp>/`):
```
workdir/
  run_config.json          # batch config (kernel version, max attempts)
  <CVE-ID>/
    state.json             # current state, attempt count, status
    events.json            # timestamped event log
    metadata/              # NVD metadata, cve_metadata.json
    patches/               # original.patch, patch_source.json
    patch_ir.json          # structured intermediate representation
    change_units.json      # parsed change units
    logs/                  # build_N.log files
    report.json            # final report (when complete)
```

## Key Conventions

- **Target kernel**: Anolis OS ANCK 6.6.102-5.2.an23.x86_64 (hardcoded default in CLI and state manager)
- **Build environment**: Requires Anolis OS 23 container with GCC 12.3.0-16.an23 (must match kernel compiler)
- **kpatch-build**: From upstream `dynup/kpatch` at commit `6e58fed`
- **Kernel source**: Mount at `KERNEL_SRC` env var or `kernel-src/linux-<version>` directory
- **Rewrite loop**: Max 5 attempts by default (`--max-attempts`), cycles through `BuildFailed → FailureClassified → RewritePrepared → PatchApplied`
- **Language**: Code is in English, comments/docs mix Chinese and English
- **No linting/formatting tools configured** — no ruff, flake8, mypy, or pre-commit hooks

## Test Data

`tests/conftest.py` defines 10 real CVE test cases (CVE-2025-21638 through CVE-2025-21646) covering all failure categories. Test fixtures in:
- `tests/testdata/patches/` — 16 patch files (10 real + 6 synthetic)
- `tests/testdata/build_logs/` — 20 build log fixtures
- `tests/testdata/metadata/` — 16 CVE metadata JSON files
- `tests/testdata/expected/` — expected output files
