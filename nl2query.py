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

LƯU Ý QUAN TRỌNG khi chọn field cho loại tấn công:
- rule.description là mô tả tự do, KHÔNG đoán chữ người dùng gõ có xuất hiện y nguyên trong đó hay không
  (vd: Wazuh có thể ghi "Multiple Windows Logon Failures" chứ không ghi chữ "brute force")
- ƯU TIÊN dùng rule.groups (term, vì đây là mảng nhãn chuẩn hóa) khi câu hỏi nói về LOẠI tấn công chung chung,
  ví dụ: authentication_failed, authentication_success, web, sql_injection, attack, invalid_login
- Nếu người dùng cho số rule_id cụ thể thì dùng rule.id (term)
- Chỉ dùng match trên rule.description khi câu hỏi có từ khóa rất đặc thù không thuộc nhóm chuẩn nào ở trên
"""

PROMPT = """Bạn là chuyên gia OpenSearch Query DSL cho hệ thống Wazuh SIEM.

{schema}

Nhiệm vụ: chuyển câu hỏi tiếng Việt của SOC analyst thành OpenSearch Query DSL JSON hợp lệ để query index wazuh-alerts-*.

QUY TẮC:
- CHỈ trả JSON, không thêm chữ ngoài JSON, không dùng markdown code fence.
- Format bắt buộc: {{"query": {{...}}, "explanation": "giải thích ngắn gọn"}}
- Nếu có khối [ALERT ĐANG CHỌN], hãy dùng đúng rule.id, agent.name, IP nguồn, đường dẫn, tên người dùng trong đó để tạo điều kiện lọc cụ thể. Không bịa giá trị ngoài khối đó.
- Dùng "range" cho thời gian (vd "now-24h"), "match"/"match_phrase" cho text, "term" cho keyword field chính xác, "bool"/"must" để kết hợp điều kiện.

Ví dụ:
Câu hỏi: "Tìm cảnh báo brute force RDP trong 24 giờ qua"
{{"query": {{"bool": {{"must": [{{"term": {{"rule.groups": "authentication_failed"}}}}, {{"range": {{"@timestamp": {{"gte": "now-24h"}}}}}}]}}}}, "explanation": "Tìm alert thuộc nhóm authentication_failed trong 24h gần nhất"}}

{alert_block}Câu hỏi của SOC analyst: {question}

JSON:"""


def _extract_json(text: str) -> dict:
    text = re.sub(r"^```json\s*|\s*```$", "", text.strip(), flags=re.I)
    text = re.sub(r"^```\s*|\s*```$", "", text)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("Không tìm thấy JSON trong output.")
    return json.loads(text[start:end + 1])


def generate_query(question: str, alert_context: str = "") -> dict:
    alert_block = f"[ALERT ĐANG CHỌN]:\n{alert_context}\n\n" if alert_context else ""
    if not question.strip() and alert_context:
        question = "Viết câu truy vấn để điều tra tiếp alert đang chọn (tìm các alert liên quan cùng nguồn, cùng máy, quanh thời điểm này)"
    prompt = PROMPT.format(schema=WAZUH_SCHEMA_HINT, alert_block=alert_block, question=question)
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