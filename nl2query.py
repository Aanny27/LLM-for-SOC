# nl2query.py
from langchain_ollama import ChatOllama
import json
import re
import httpx

# TRƯỚC: llm = ChatOllama(model="qwen2.5:7b", temperature=0.1)
# Thiếu 2 thứ quan trọng:
#  1. format="json"  -> không ép Ollama trả đúng JSON, model dễ chèn thêm
#     chữ thừa quanh JSON dù prompt đã dặn "CHỈ trả JSON".
#  2. timeout         -> nếu Ollama đang bận (vd. đang phân tích alert khác),
#     lời gọi này có thể treo vô thời hạn, không bao giờ fallback.
llm = ChatOllama(
    model="qwen2.5:7b",
    temperature=0.1,
    format="json",
    num_predict=400,  # query DSL + giải thích ngắn, không cần dài
    client_kwargs={"timeout": 60.0},
)

WAZUH_SCHEMA_HINT = """
Schema chính của index `wazuh-alerts-*` trên Wazuh Indexer (OpenSearch):
- @timestamp: thời gian alert (ISO 8601)
- rule.id, rule.level (0-16), rule.description, rule.groups (array), rule.mitre.id
- agent.name, agent.id, agent.ip
- data.srcip, data.dstip, data.srcuser, data.dstuser
- data.win.eventdata.* (Sysmon: Image, CommandLine, ParentImage, TargetUserName...)
- data.win.system.eventID
- full_log: log gốc dạng text
- decoder.name
"""

PROMPT = """Bạn là chuyên gia OpenSearch Query DSL cho hệ thống Wazuh SIEM.

{schema}

Nhiệm vụ: chuyển câu hỏi tiếng Việt của SOC analyst thành OpenSearch Query DSL JSON hợp lệ để query index wazuh-alerts-*.

QUY TẮC:
- CHỈ trả JSON, không thêm chữ ngoài JSON, không dùng markdown code fence.
- Format bắt buộc: {{"query": {{...}}, "explanation": "giải thích ngắn gọn"}}
- Dùng "range" cho thời gian (vd "now-24h"), "match"/"match_phrase" cho text, "term" cho keyword field chính xác, "bool"/"must" để kết hợp điều kiện.

Ví dụ:
Câu hỏi: "Tìm cảnh báo brute force RDP trong 24 giờ qua"
{{"query": {{"bool": {{"must": [{{"match": {{"rule.description": "brute force"}}}}, {{"match": {{"rule.description": "RDP"}}}}, {{"range": {{"@timestamp": {{"gte": "now-24h"}}}}}}]}}}}, "explanation": "Tìm alert liên quan brute force RDP trong 24h gần nhất"}}

Câu hỏi của SOC analyst: {question}

JSON:"""


def _extract_json(text: str) -> dict:
    text = re.sub(r"^```json\s*|\s*```$", "", text.strip(), flags=re.I)
    text = re.sub(r"^```\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("Không tìm thấy JSON trong output.")
    return json.loads(text[start:end + 1])


def generate_query(question: str) -> dict:
    prompt = PROMPT.format(schema=WAZUH_SCHEMA_HINT, question=question)
    try:
        raw = llm.invoke(prompt).content
        parsed = _extract_json(raw)
        if "query" not in parsed:
            raise ValueError("Output thiếu field 'query'.")
        return parsed
    except httpx.TimeoutException:
        # Bắt riêng lỗi timeout để báo rõ nguyên nhân thay vì thông báo
        # chung chung — timeout thường nghĩa là Ollama đang bận việc khác
        # (vd. đang phân tích alert), không phải do câu hỏi sai.
        return {
            "query": {},
            "explanation": "[Lỗi sinh query] Ollama không phản hồi trong 60s, có thể đang bận xử lý việc khác. Thử lại sau ít giây.",
            "error": True,
        }
    except Exception as e:
        return {
            "query": {},
            "explanation": f"[Lỗi sinh query] {type(e).__name__}: {e}. Thử diễn đạt câu hỏi cụ thể hơn.",
            "error": True,
        }