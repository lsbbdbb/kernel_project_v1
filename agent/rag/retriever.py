"""Knowledge retriever — simple keyword-based retrieval.

Uses BM25 when the rank_bm25 library is available; falls back to a
naive TF-based scorer that works for small collections. An empty
knowledge base returns no results without error.
"""
import re
from typing import Dict, List, Optional

from agent.rag.knowledge_base import KnowledgeBase, KnowledgeChunk


class KnowledgeRetriever:
    """Retrieve relevant knowledge chunks for a query.

    Prioritises BM25 when rank_bm25 is installed, otherwise uses a
    lightweight TF scorer. Designed to work with small KBs (dozens
    of entries) where vector embedding is unnecessary overhead.
    """

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self._bm25 = None
        self._corpus: List[str] = []
        self._known_doc_count = 0
        self._try_load_bm25()

    def _ensure_index_fresh(self):
        """Rebuild BM25 index when documents have been added since init."""
        current_count = len(self.kb.documents)
        if current_count != self._known_doc_count:
            self._rebuild_bm25()
            self._known_doc_count = current_count

    def _try_load_bm25(self):
        try:
            from rank_bm25 import BM25Okapi
            self._rebuild_bm25()
        except ImportError:
            self._bm25 = None

    def _rebuild_bm25(self):
        self._known_doc_count = len(self.kb.documents)
        docs = self.kb.documents
        if not docs:
            self._bm25 = None
            self._corpus = []
            return
        self._corpus = [d.content for d in docs]
        try:
            from rank_bm25 import BM25Okapi
            tokenized = [self._tokenize(c) for c in self._corpus]
            self._bm25 = BM25Okapi(tokenized)
        except ImportError:
            self._bm25 = None

    def retrieve(self, query: str, top_k: int = 5) -> List[KnowledgeChunk]:
        """Return top-k chunks matching the query.

        Rebuilds BM25 index automatically if documents have been added
        since the retriever was created.
        """
        self._ensure_index_fresh()
        docs = self.kb.documents
        if not docs:
            return []

        if self._bm25 is not None:
            tokenized_query = self._tokenize(query)
            scores = self._bm25.get_scores(tokenized_query)
            ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)
            return [docs[i] for i, _ in ranked[:top_k] if scores[i] > 0]

        # Fallback: simple TF scoring
        query_tokens = set(self._tokenize(query))
        scored = []
        for i, doc in enumerate(docs):
            doc_tokens = self._tokenize(doc.content)
            tf = sum(1 for t in doc_tokens if t in query_tokens)
            if tf > 0:
                scored.append((i, tf))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [docs[i] for i, _ in scored[:top_k]]

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Split text into lowercase alphanumeric tokens."""
        return re.findall(r'[a-z0-9_]+', text.lower())
