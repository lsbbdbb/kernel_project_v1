#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== Phase5 RAG verification ==="

echo "-- Loading RAG knowledge base --"
python3 - <<'PY'
from agent.rag.knowledge_base import KnowledgeBase

kb = KnowledgeBase()
loaded_yaml = kb.load_yaml_rules()
loaded_api = kb.load_kernel_api_yaml()
print(f"Loaded YAML rule chunks: {loaded_yaml}")
print(f"Loaded kernel API chunks: {loaded_api}")
print(f"Total knowledge chunks: {len(kb.documents)}")
if loaded_yaml <= 0:
    raise SystemExit("No YAML knowledge chunks loaded")
PY

echo "-- Testing retrieval for kernel API / failure rule query --"
python3 - <<'PY'
from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever

kb = KnowledgeBase()
kb.load_yaml_rules()
kb.load_kernel_api_yaml()
retriever = KnowledgeRetriever(kb)
query = "api mismatch function arguments"
results = retriever.retrieve(query, top_k=5)
print(f"Query: {query}")
print(f"Results count: {len(results)}")
for chunk in results:
    print(f"- {chunk.id} [{chunk.metadata.get('type')}] {chunk.content[:200].replace('\n', ' ')}")
if not results:
    raise SystemExit("No RAG retrieval results")
PY

echo "=== Phase5 RAG verification completed successfully ==="
