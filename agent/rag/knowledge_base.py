"""Knowledge base - stores documents and provides retrieval interface."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class KnowledgeChunk:
    """A retrievable document chunk with metadata."""
    id: str
    content: str
    metadata: Dict = field(default_factory=dict)


class KnowledgeBase:
    """In-memory knowledge base for RAG retrieval.

    Currently empty — documents are loaded from YAML rule files
    and kernel API docs when available. The retriever gracefully
    handles an empty KB by returning no results.
    """

    def __init__(self):
        self.documents: List[KnowledgeChunk] = []

    def load_yaml_rules(self) -> int:
        """Load failure patterns and rewrite strategies as knowledge chunks.

        Returns:
            Number of chunks loaded (0 if no YAML source is configured).
        """
        try:
            from agent.knowledge.loader import KnowledgeLoader
        except ImportError:
            return 0

        chunks: List[KnowledgeChunk] = []
        patterns = KnowledgeLoader.load_failure_patterns()
        for p in (patterns if isinstance(patterns, list) else []):
            chunk_id = p.get("id", p.get("reason_code", ""))
            chunk_text = f"{p.get('category', '')} {p.get('description', '')} "
            chunk_text += f"action: {p.get('action', p.get('retryable', ''))}"
            if chunk_id:
                chunks.append(KnowledgeChunk(
                    id=f"failure_{chunk_id}",
                    content=chunk_text,
                    metadata={"type": "failure_pattern", **p},
                ))

        strategies = KnowledgeLoader.load_rewrite_strategies()
        for s in (strategies if isinstance(strategies, list) else []):
            sid = s.get("id", s.get("strategy", ""))
            if sid:
                chunks.append(KnowledgeChunk(
                    id=f"strategy_{sid}",
                    content=s.get("description", ""),
                    metadata={"type": "rewrite_strategy", **s},
                ))

        self.documents.extend(chunks)
        return len(chunks)

    def add_kernel_api_doc(self, symbol: str, signature: str,
                           description: str) -> KnowledgeChunk:
        """Add a kernel API documentation entry."""
        chunk = KnowledgeChunk(
            id=f"api_{symbol}",
            content=f"{symbol}: {signature} — {description}",
            metadata={"type": "kernel_api", "symbol": symbol},
        )
        self.documents.append(chunk)
        return chunk

    def load_kernel_api_yaml(self, path: Optional[str] = None) -> int:
        """Load kernel API documentation from a YAML file.

        If path is None, tries the default location under agent/knowledge/.
        Currently a no-op — file does not exist yet.
        """
        # Placeholder: kernel_6.6_api.yaml not yet created
        # Will be populated in Phase 5 completion
        return 0
