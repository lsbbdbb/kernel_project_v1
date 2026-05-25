import re

from agent.rag.knowledge_base import KnowledgeBase
from agent.rag.retriever import KnowledgeRetriever


def test_load_yaml_rules_creates_failure_and_strategy_chunks():
    kb = KnowledgeBase()
    count = kb.load_yaml_rules()

    assert count > 0
    assert any(chunk.metadata.get("type") == "failure_pattern" for chunk in kb.documents)
    assert any(chunk.metadata.get("type") == "rewrite_strategy" for chunk in kb.documents)


def test_retriever_finds_relevant_chunks_for_query():
    kb = KnowledgeBase()
    kb.load_yaml_rules()
    retriever = KnowledgeRetriever(kb)

    assert kb.documents, "Knowledge base should contain documents after YAML load"
    first_text = kb.documents[0].content
    token_match = re.findall(r"[a-z0-9_]+", first_text.lower())
    assert token_match, "First document should contain searchable tokens"

    query = token_match[0]
    results = retriever.retrieve(query, top_k=3)

    assert isinstance(results, list)
    assert len(results) >= 1
    assert any(query in chunk.content.lower() for chunk in results)


def test_load_kernel_api_yaml_adds_api_documents():
    kb = KnowledgeBase()
    count = kb.load_kernel_api_yaml()

    assert count >= 0
    assert len([chunk for chunk in kb.documents if chunk.metadata.get("type") == "kernel_api"]) == count


def test_retriever_finds_kernel_api_chunk():
    kb = KnowledgeBase()
    kb.load_yaml_rules()
    kb.load_kernel_api_yaml()
    retriever = KnowledgeRetriever(kb)

    results = retriever.retrieve("sock_create", top_k=3)

    assert isinstance(results, list)
    assert len(results) >= 1
    assert any(chunk.metadata.get("type") == "kernel_api" for chunk in results)


def test_load_rag_knowledge_loads_chunked_files():
    kb = KnowledgeBase()
    count = kb.load_rag_knowledge()

    assert count > 0, "Should load knowledge chunks from rag_knowledge/ directory"
    types_found = {chunk.metadata.get("type") for chunk in kb.documents}
    assert "kpatch_limit" in types_found or "failure_pattern" in types_found
    assert any("no_fentry" in chunk.content for chunk in kb.documents)


def test_load_all_loads_all_sources():
    kb = KnowledgeBase()
    total = kb.load_all()

    assert total > 0
    types_found = {chunk.metadata.get("type") for chunk in kb.documents}
    # Should have chunks from all three sources
    assert "failure_pattern" in types_found or "kpatch_limit" in types_found
    assert any(chunk.metadata.get("type") in ("rewrite_strategy", "general") for chunk in kb.documents)


def test_rag_knowledge_is_retrievable_by_failure_reason_code():
    kb = KnowledgeBase()
    kb.load_all()
    retriever = KnowledgeRetriever(kb)

    # Query patterns that mirror _build_rag_context() in rewrite_advisor.py
    for query in ["no_fentry esp_input", "api_mismatch", "syncconfig", "shadow variable", "data structure"]:
        results = retriever.retrieve(query, top_k=3)
        assert isinstance(results, list)
        # At least one result for common terms
        if query in ("shadow variable", "data structure", "syncconfig"):
            assert len(results) >= 1, f"Query '{query}' should return results"


def test_rag_knowledge_chunks_have_rich_metadata():
    kb = KnowledgeBase()
    kb.load_rag_knowledge()

    for chunk in kb.documents:
        assert chunk.id, "Each RAG chunk must have an id"
        assert chunk.metadata.get("type"), "Each RAG chunk must have a type"
        if chunk.metadata.get("type") in ("kpatch_limit", "failure_pattern", "rewrite_strategy"):
            assert chunk.metadata.get("tags"), f"Chunk {chunk.id} of type {chunk.metadata['type']} should have tags"
