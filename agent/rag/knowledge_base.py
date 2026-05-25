"""Knowledge base - stores documents and provides retrieval interface."""
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import os
import re
import yaml


@dataclass
class KnowledgeChunk:
    """A retrievable document chunk with metadata."""
    id: str
    content: str
    metadata: Dict = field(default_factory=dict)


_KNOWN_DIRS = None


def _rag_knowledge_dirs() -> List[str]:
    """Return candidate directories containing chunked knowledge files."""
    global _KNOWN_DIRS
    if _KNOWN_DIRS is not None:
        return _KNOWN_DIRS
    base = os.path.dirname(os.path.abspath(__file__))   # agent/rag/
    agent_dir = os.path.dirname(base)                    # agent/
    cand = os.path.join(agent_dir, "knowledge", "rag_knowledge")
    dirs = []
    if os.path.isdir(cand):
        dirs.append(cand)
    _KNOWN_DIRS = dirs
    return dirs


_CHUNK_SPLIT_RE = re.compile(r'\n---\n')


def _parse_chunk_frontmatter(text: str):
    """Parse inline YAML-like frontmatter lines at top of a chunk.

    Lines like:
        type: foo
        tags: bar, baz
    are extracted as metadata. Everything after blank line is content.
    """
    meta: Dict[str, str] = {}
    lines = text.split('\n', 10)
    content_start = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            content_start = i + 1
            break
        if ':' in stripped:
            key, _, val = stripped.partition(':')
            meta[key.strip()] = val.strip()
    content = '\n'.join(lines[content_start:]).strip()
    return meta, content


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
    # RAG chunked knowledge loading (from rag_knowledge/ directory)
    # ------------------------------------------------------------------

    def load_rag_knowledge(self, directory: Optional[str] = None) -> int:
        """Load chunked knowledge .md files from a directory.

        Each .md file is split by '---' separators. Each chunk should
        start with frontmatter lines (type / id / tags / title) followed
        by a blank line and then the content body.

        Example chunk:
            type: kpatch_limit
            id: no_fentry_explained
            tags: fentry, ftrace, notrace, livepatch
            title: no fentry call — explanation and workaround
            <blank line>
            When kpatch-build reports "no fentry call" ...

        Returns:
            Number of chunks loaded.
        """
        if directory is None:
            dirs = _rag_knowledge_dirs()
            if not dirs:
                return 0
            directory = dirs[0]

        if not os.path.isdir(directory):
            return 0

        count = 0
        for fname in sorted(os.listdir(directory)):
            if not fname.endswith('.md'):
                continue
            fpath = os.path.join(directory, fname)
            try:
                with open(fpath, 'r', encoding='utf-8') as f:
                    raw = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            raw_chunks = _CHUNK_SPLIT_RE.split(raw)
            for chunk_text in raw_chunks:
                chunk_text = chunk_text.strip()
                if not chunk_text:
                    continue
                meta, content = _parse_chunk_frontmatter(chunk_text)
                if not content:
                    continue

                chunk_id = meta.get('id', '') or f"rag_{fname}_{count}"
                chunk_type = meta.get('type', 'general')
                tags_str = meta.get('tags', '')
                tags = [t.strip() for t in tags_str.split(',') if t.strip()]

                # Build searchable content: id + tags + body (duplicate key words)
                searchable = f"{chunk_id} {' '.join(tags)} {content}"
                self.documents.append(KnowledgeChunk(
                    id=chunk_id,
                    content=searchable,
                    metadata={
                        "type": chunk_type,
                        "source_file": fname,
                        "tags": tags,
                        "title": meta.get('title', ''),
                    },
                ))
                count += 1

        return count

    def load_all(self) -> int:
        """Convenience: load YAML rules + kernel API + RAG knowledge.

        Returns:
            Total number of chunks loaded.
        """
        total = 0
        total += self.load_yaml_rules()
        total += self.load_kernel_api_yaml()
        total += self.load_rag_knowledge()
        return total

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
