from langchain_ollama import ChatOllama
from soc_verdict_escalation import build_verdict_prompt, parse_verdict_response
from shared_rag import CHROMA_PATH, get_vectorstore

DB_PATH = CHROMA_PATH
vectorstore = get_vectorstore()

# Chỉ WARN, không sys.exit()
_count = vectorstore._collection.count()
if _count == 0:
    print(f"[!] CẢNH BÁO: ChromaDB rỗng tại {DB_PATH}. Chạy ingest.py trước khi dùng /analyze.")

retriever = vectorstore.as_retriever(
    search_type="mmr",
    search_kwargs={"k": 3, "fetch_k": 10}
)
llm = ChatOllama(model="qwen2.5:7b", temperature=0.1)


def analyze_alert(alert_data: str, retrieval_query: str):
    """
    Retrieval + verdict/escalation classification, dùng chung 1 lần gọi LLM
    thay vì gọi 2 lần riêng (1 lần phân tích + 1 lần verdict) để tiết kiệm
    thời gian inference — quan trọng vì Ollama chạy local vốn đã chậm.
    """
    # 1. Truy xuất playbook liên quan từ ChromaDB
    docs = retriever.invoke(retrieval_query)
    context = "\n\n".join([d.page_content for d in docs])
    sources = list(set([d.metadata.get("source", "Unknown") for d in docs]))

    # 2. Build prompt chuẩn từ soc_verdict_escalation.py — ép LLM trả về
    #    đúng format JSON (verdict, verdict_reasoning, escalation_level, escalation_reason)
    prompt_text = build_verdict_prompt(
        alert_data={"raw_alert": alert_data},
        rag_context=context,
    )

    # 3. Gọi LLM trực tiếp bằng .invoke() với string prompt (không cần PromptTemplate
    #    vì build_verdict_prompt() đã trả về string hoàn chỉnh)
    response = llm.invoke(prompt_text)

    # 4. Parse JSON an toàn — fallback về Uncertain/L2 nếu LLM trả sai format
    verdict_result = parse_verdict_response(response.content)

    return {
        "answer": verdict_result.verdict_reasoning,
        "sources": sources,
        "verdict_type": verdict_result.verdict.value,
        "escalation": verdict_result.escalation_level.value,
        "escalation_reason": verdict_result.escalation_reason,
        "should_escalate": verdict_result.should_escalate,
    }


if __name__ == "__main__":
    if _count == 0:
        print("[!] Không có dữ liệu, thoát.")
        exit(1)