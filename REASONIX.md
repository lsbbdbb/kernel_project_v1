# REASONIX.md — kernel-livepatch-agent

## Stack

- **Language:** Python 3.10+ (requires 3.6+ per setup.py, 3.10+ per USAGE.md)
- **Framework:** Custom state machine orchestration (no web framework)
- **Key deps:** `requests`, `pyyaml`, `openai>=1.0.0`, `rank-bm25>=0.2.2`
- **Target kernel:** Anolis OS ANCK `6.6.102-5.2.an23.x86_64`
- **Build tool:** `kpatch-build` (installed in Docker image from `anolisos:23`)

## Layout

| Path | Purpose |
|------|---------|
| `agent/` | Main Python package — CLI entry (`__main__.py`), state machine, tools |
| `agent/tools/` | Pipeline stages: resolver, fetcher, parser, builder, classifier, advisor, verifier, reporter, validator |
| `agent/knowledge/` | YAML rule files (`failure_patterns.yaml`, `rewrite_strategies.yaml`) + kernel API knowledge |
| `agent/llm/` | LLM client, config, prompt templates |
| `agent/rag/` | Knowledge base + retriever (RAG injection into rewrite step) |
| `tests/` | pytest suite (111 tests, all passing) |
| `kernel-src/` | Full Anolis OS 6.6 kernel source tree — do NOT edit or traverse |
| `scripts/` | Shell helpers for env setup and verification |
| `docs/` | Documentation and plans |

## Commands

| Action | Command |
|--------|---------|
| Install | `pip install -r requirements.txt && pip install -e .` |
| Test | `python3 -m pytest tests/ -v` (or `make test`) |
| Run | `python3 -m agent --cves sample_cves.txt` |
| Docker build | `docker compose build agent` |
| Docker run | `docker compose up agent` |
| Clean | `make clean` |

## Conventions

- **snake_case** for functions/variables; **CamelCase** for classes
- Tests use pytest, no `unittest.TestCase` — plain assert + pytest fixtures
- State machine with 18 predefined `VALID_STATES` in `agent/state.py` (includes `FixEnvironment`); transitions logged as JSON events
- Pipeline actions named with `_action_` prefix, mapped in `ACTION_MAP` dict
- Per-CVE state persisted as JSON: `state.json`, `events.json`, `run_config.json`
- YAML knowledge files in `agent/knowledge/rules/` define failure patterns and rewrite strategies
- CLI accepts `--no-llm` flag to run without LLM (rule-only mode)
- Rewrite attempts numbered `attempt_N.patch` under per-CVE `patches/` directory

## Watch out for

- **`kernel-src/` is a full kernel tree** (many thousands of files). Never read or traverse it unless explicitly asked. The `.gitignore` already excludes it from searches.
- **LLM integration is production-grade.** `agent/llm/client.py` wraps the OpenAI-compatible SDK with 3 providers (DeepSeek/OpenAI/Ollama), auto-detection from env vars, and graceful fallback to rule-only mode. `agent/llm/prompts/templates.py` has 4 prompt templates for diagnosis, rewrite planning, diff generation, and retry decisions. The `LLMPlanner` in `agent/planner.py` consults the LLM at key decision points with safety overrides.
- **RAG is a full BM25 implementation.** `agent/rag/knowledge_base.py` loads from 3 sources: YAML failure patterns/strategies, kernel API YAML, and `agent/knowledge/rag_knowledge/*.md` chunked documents. `agent/rag/retriever.py` uses `rank_bm25` (with a simple TF fallback). The retriever is wired into `RewriteAdvisor` for RAG-injected LLM rewrites.
- **No lint/format config in the repo.** No `.flake8`, `.pylintrc`, `.editorconfig`, or `setup.cfg` — the project has no enforced code style tooling.
- **Docker build is Anolis OS 23-based** (not `python:3.11-slim` — that's only in the old README_Docker.md). The Dockerfile installs `kpatch` and `kpatch-build` via `dnf`.
- **`setup.py` used to miss `rank-bm25`.** As of commit `98a87828b` it's in both `install_requires` and `requirements.txt` — `pip install -e .` alone now installs everything.
