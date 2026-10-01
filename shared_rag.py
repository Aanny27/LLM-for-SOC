"""
shared_rag.py — mô hình nhúng văn bản + kho vector ChromaDB, chỉ nạp MỘT LẦN.

Bản này dùng Ollama để nhúng văn bản (thay cho HuggingFace + torch), vì
torch bị Windows chặn (Application Control policy). Ollama đã chạy sẵn cho
phần phân tích cảnh báo nên không cần cài thêm thư viện nặng nào.

Giao diện giữ nguyên: get_vectorstore(), embeddings, CHROMA_PATH,
COLLECTION_NAME. Các tệp khác (gateway.py, vulns.py, retriever.py) không
cần đổi cách gọi.

LƯU Ý QUAN TRỌNG: mô hình nhúng khác thì vector cũ KHÔNG dùng được.
Phải xóa (hoặc đổi tên) thư mục chroma_db cũ rồi nạp lại toàn bộ tài liệu.
"""

import os
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_PATH = os.path.join(BASE_DIR, "chroma_db_ollama")
COLLECTION_NAME = "soc_knowledge"

# Có thể đổi bằng biến môi trường trong tệp .env nếu cần.
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
EMBED_MODEL = os.getenv("EMBED_MODEL", "bge-m3")

# Nạp một lần khi import — mọi tệp import module này dùng chung một đối tượng.
embeddings = OllamaEmbeddings(
    model=EMBED_MODEL,
    base_url=OLLAMA_BASE_URL,
)

_vectorstore = None


def get_vectorstore() -> Chroma:
    """Trả về một đối tượng kho vector Chroma dùng chung."""
    global _vectorstore
    if _vectorstore is None:
        _vectorstore = Chroma(
            persist_directory=CHROMA_PATH,
            embedding_function=embeddings,
            collection_name=COLLECTION_NAME,
        )
    return _vectorstore