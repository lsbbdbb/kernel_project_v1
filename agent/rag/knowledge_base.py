"""Knowledge base - stores documents and provides retrieval interface."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import os
import yaml


@dataclass
class KnowledgeChunk:
    """A retrievable document chunk with metadata."""
    id: str
    content: str
    metadata: Dict = field(default_factory=dict)


class KnowledgeBase:
    """In-memory knowledge base for RAG retrieval.

    Loads YAML rule files (failure patterns, rewrite strategies) and
    kernel API documentation. The retriever searches over chunk content
    with BM25 or TF-based scoring.
    """

    def __init__(self):
        self.documents: List[KnowledgeChunk] = []

    # ------------------------------------------------------------------
    # YAML rule loading
    # ------------------------------------------------------------------

    def load_yaml_rules(self) -> int:
        """Load failure patterns and rewrite strategies as knowledge chunks.

        Returns:
            Number of chunks loaded.
        """
        try:
            from agent.knowledge.loader import KnowledgeLoader
        except ImportError:
            return 0

        chunks: List[KnowledgeChunk] = []

        # --- failure patterns ---
        patterns = KnowledgeLoader.load_failure_patterns()
        for p in (patterns if isinstance(patterns, list) else []):
            pid = p.get("pattern_id", "")
            reason = p.get("reason_code", "")
            category = p.get("category", "")

            # Build rich searchable text from all relevant fields
            text_parts = [
                p.get("pattern_id", ""),
                p.get("reason_code", ""),
                p.get("category", ""),
            ]
            matchers = p.get("matchers", [])
            if isinstance(matchers, list):
                text_parts.extend(matchers)
            description = p.get("description", "")
            if description:
                text_parts.append(description)

            content = " | ".join(part for part in text_parts if part)
            if pid:
                chunks.append(KnowledgeChunk(
                    id=f"failure_{reason or pid}",
                    content=content,
                    metadata={
                        "type": "failure_pattern",
                        "pattern_id": pid,
                        "reason_code": reason,
                        "category": category,
                    },
                ))

        # --- rewrite strategies ---
        strategies = KnowledgeLoader.load_rewrite_strategies()
        if isinstance(strategies, dict):
            for sid, s in strategies.items():
                if sid:
                    text = f"{sid}: {s.get('description', '')}"
                    chunks.append(KnowledgeChunk(
                        id=f"strategy_{sid}",
                        content=text,
                        metadata={"type": "rewrite_strategy", "strategy_id": sid},
                    ))
        elif isinstance(strategies, list):
            for s in strategies:
                sid = s.get("strategy_id", s.get("id", ""))
                if sid:
                    text = f"{sid}: {s.get('description', '')}"
                    chunks.append(KnowledgeChunk(
                        id=f"strategy_{sid}",
                        content=text,
                        metadata={"type": "rewrite_strategy", "strategy_id": sid},
                    ))

        self.documents.extend(chunks)
        return len(chunks)

    # ------------------------------------------------------------------
    # Kernel API documentation
    # ------------------------------------------------------------------

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
        """Load kernel API documentation from kernel_6.6_api.yaml.

        The YAML file records API changes between kernel versions:
        renamed functions, changed signatures, removed symbols, etc.
        """
        if path is None:
            base = os.path.dirname(os.path.abspath(__file__))  # .../agent/rag
            agent_dir = os.path.dirname(base)                   # .../agent
            path = os.path.join(
                agent_dir, "knowledge", "kernel_api", "kernel_6.6_api.yaml"
            )

        if not os.path.exists(path):
            return 0

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or []
        except (yaml.YAMLError, OSError):
            return 0

        count = 0
        for entry in data if isinstance(data, list) else []:
            symbol = entry.get("symbol", "")
            old_sig = entry.get("old_signature", "")
            new_sig = entry.get("new_signature", "")
            note = entry.get("note", "")
            category = entry.get("category", "")

            text_parts = [symbol]
            if old_sig:
                text_parts.append(f"old: {old_sig}")
            if new_sig:
                text_parts.append(f"new: {new_sig}")
            if note:
                text_parts.append(note)
            if category:
                text_parts.append(f"category: {category}")

            content = " | ".join(text_parts)
            self.documents.append(KnowledgeChunk(
                id=f"api_{symbol}",
                content=content,
                metadata={
                    "type": "kernel_api",
                    "symbol": symbol,
                    "category": category,
                },
            ))
            count += 1

        return count
