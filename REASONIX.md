# Kernel CVE Livepatch Agent — Project Knowledge

## Stack
- **Language** — Python 3.10+ (3.13 tested)
- **LLM** — OpenAI-compatible client, default provider DeepSeek (v4-pro)
- **RAG** — BM25 keyword retrieval over Markdown knowledge files
- **Key deps** — requests, pyyaml, openai, rank-bm25, flask
- **Config** — env vars: `DEEPSEEK_API_KEY`, `LLM_MODEL`, `LLM_PROVIDER`, `KERNEL_SRC`

## Layout
- `agent/` — main package: state machine, planner, pipeline tools, LLM client, RAG KB
- `tests/` — pytest tests, colocated `test_*.py` naming
- `docs/` — project / research documentation
- `scripts/` — utility scripts (download kernel src, fetch CVE data, verify env)
- `agent/knowledge/rules/` — YAML failure-pattern & rewrite-strategy rule engine
- `agent/knowledge/rag_knowledge/` — Markdown knowledge files for BM25 retrieval
- `agent/llm/prompts/` — prompt templates (`templates.py`)
- `agent/tools/` — pipeline tool classes, re-exported via `__init__.py`
- `acceptance_vm_20260525/` — Anolis 6.6.102-5.2.an23 kernel source tree (reference, ~4 GB)
- `patches_real/` — sample CVE patches
- `docker_*/` — generated run output directories (not tracked, safe to delete)

## Commands
- `make test` — run all pytest tests (`python3 -m pytest tests/ -v`)
- `make clean` — remove `__pycache__`, `.pytest_cache`, egg-info
- `python3 setup.py install` — install CLI (`run`) and web (`web`) entry points

## Conventions
- YAML rule files in `agent/knowledge/rules/` drive failure classification & rewrite strategy — rule-based before LLM fallback
- LLM prompt templates are Python string-format functions in `templates.py`, not standalone files
- Pipeline state persisted as `state.json` + `events.json` per run directory
- Target kernel: Anolis OS ANCK 6.6.102-5.2.an23.x86_64 (both build and verify)

## Watch out for
- `acceptance_vm_20260525/` is a full kernel tree — do NOT edit, it's a reference / build source
- `kernel-src/linux-6.6.102-5.2.an23.x86_64` is a symlink to the build kernel source, expected at runtime
- `.env` contains API keys — excluded from VCS; `DEEPSEEK_API_KEY` required for LLM features
- LLM defaults to `deepseek-v4-pro`; set `LLM_PROVIDER=openai` or `LLM_PROVIDER=ollama` to switch
- kpatch-build is an external binary required for livepatch .ko generation
- Docker workflows mount kernel source at `/kernel-src/linux-6.6.102-5.2.an23.x86_64`
- syncconfig fix: touch `include/config/auto.conf` to skip kpatch-build's `$(shell,...)` parsing issue
