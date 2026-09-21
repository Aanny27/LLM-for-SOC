from sentence_transformers import SentenceTransformer
import chromadb

# Model và client
model = SentenceTransformer('all-MiniLM-L6-v2')
client = chromadb.Client()
collection = client.create_collection("docs")

# Dữ liệu mẫu
texts = [
    "Bizfly cung cấp hệ sinh thái Martech & Salestech.",
    "AI Agent sử dụng Vector DB để lưu giữ ngữ cảnh.",
    "ChromaDB phù hợp cho dự án AI nhỏ."
]

emb = model.encode(texts)

collection.add(
    documents=texts,
    embeddings=emb,
    ids=["1", "2", "3"]
)
