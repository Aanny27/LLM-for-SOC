"""
shared_rag.py — embedding model + ChromaDB vectorstore, loaded ONCE.

Problem this fixes: gateway.py, retriever.py and vulns.py each used to
call HuggingFaceEmbeddings(...) independently, so the model weights were
loaded 3 separate times on every server start (slow, wastes RAM).
retriever.py also pointed at "../chroma_db" (one folder up) instead of
the same chroma_db that gateway.py and vulns.py use — a different,
possibly stale vector store.

This module is the single source of truth: import get_vectorstore() (and
`embeddings` / CHROMA_PATH if needed) from here in every other file
instead of constructing HuggingFaceEmbeddings/Chroma directly.
"""

import os
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_PATH = os.path.join(BASE_DIR, "chroma_db")
COLLECTION_NAME = "soc_knowledge"

# Loaded once at import time — every module that imports this file
# reuses the same instance via Python's module cache.
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
)

_vectorstore = None


def get_vectorstore() -> Chroma:
    """Returns a single shared Chroma vectorstore instance."""
    global _vectorstore
    if _vectorstore is None:
        _vectorstore = Chroma(
            persist_directory=CHROMA_PATH,
            embedding_function=embeddings,
            collection_name=COLLECTION_NAME,
        )
    return _vectorstore
