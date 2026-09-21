"""
soc_verdict_escalation.py

Adds a True/False Positive verdict and an L1/L2/L3 escalation recommendation
on top of the existing SOC AI analysis pipeline (severity, confidence,
risk_score, mitre_technique, recommended_actions).

Import this into gateway.py and call `build_verdict_prompt()` +
`parse_verdict_response()` around your existing Ollama call.
"""

from enum import Enum
import json
import re

from pydantic import BaseModel, Field, model_validator


class Verdict(str, Enum):
    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    UNCERTAIN = "Uncertain"


class EscalationLevel(str, Enum):
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    NONE = "None"  # rõ ràng False Positive, không cần ai xử lý tiếp


class VerdictEscalation(BaseModel):
    verdict: Verdict
    verdict_reasoning: str = Field(..., min_length=1)
    escalation_level: EscalationLevel
    escalation_reason: str = Field(..., min_length=1)
    should_escalate: bool = False

    @model_validator(mode="after")
    def sync_should_escalate(self):
        self.should_escalate = self.escalation_level != EscalationLevel.NONE
        return self


VERDICT_ESCALATION_PROMPT = """Bạn là SOC Analyst AI hỗ trợ phân loại alert.

ALERT DATA:
{alert_json}

CONTEXT PLAYBOOK (từ RAG retrieval):
{rag_context}

Dựa CHỈ trên context ở trên, hãy đánh giá và trả lời THEO ĐÚNG định dạng JSON sau,
không thêm text nào khác ngoài JSON:

{{
  "verdict": "True Positive" | "False Positive" | "Uncertain",
  "verdict_reasoning": "<giải thích ngắn gọn, dựa trên investigation steps trong playbook>",
  "escalation_level": "L1" | "L2" | "L3" | "None",
  "escalation_reason": "<vì sao cần/không cần escalate lên mức này>"
}}

QUY TẮC:
1. verdict = "True Positive" CHỈ khi có bằng chứng rõ ràng khớp điều kiện Investigation
   trong playbook (vd: login thành công sau brute-force, event ID khớp pattern tấn công đã biết).
2. verdict = "False Positive" khi có dấu hiệu benign rõ ràng (IP nội bộ tin cậy, hành vi
   định kỳ đã biết, không khớp điều kiện investigation).
3. Nếu KHÔNG đủ thông tin trong context để kết luận chắc chắn, PHẢI trả về
   verdict = "Uncertain". TUYỆT ĐỐI KHÔNG ép chọn True Positive hoặc False Positive
   khi thiếu bằng chứng.
4. escalation_level dựa trên Remediation steps trong playbook:
   - "L1": có thể tự xử lý theo playbook (vd chỉ cần block IP)
   - "L2": cần điều tra sâu hơn (nghi ngờ account compromise, cần thêm forensic)
   - "L3": mức độ nghiêm trọng cao nhất, cần Incident Response team ngay
   - "None": False Positive rõ ràng, không cần escalate ai xử lý
5. Nếu context playbook KHÔNG đề cập alert loại này (không tìm thấy playbook phù hợp),
   PHẢI trả verdict = "Uncertain" và escalation_level = "L2" với lý do
   "Chưa có playbook, cần chuyên gia đánh giá thủ công". KHÔNG tự suy diễn ngoài context.

CHỈ trả JSON, không markdown code fence, không giải thích gì thêm ngoài JSON.
"""


def build_verdict_prompt(alert_data: dict, rag_context: str) -> str:
    """
    alert_data: raw/normalized Wazuh alert dict
    rag_context: concatenated text of retrieved playbook chunks
                 (pass "" if retriever found nothing above your similarity threshold)
    """
    if not rag_context or not rag_context.strip():
        rag_context = "[Không tìm thấy playbook nào phù hợp với alert này trong knowledge base]"

    return VERDICT_ESCALATION_PROMPT.format(
        alert_json=json.dumps(alert_data, ensure_ascii=False, indent=2),
        rag_context=rag_context,
    )


def parse_verdict_response(llm_raw_output: str) -> VerdictEscalation:
    """
    Parse the LLM's raw text into a validated VerdictEscalation.
    On any parse/validation failure, falls back to Uncertain + L2 rather than
    silently treating a broken response as a resolved/False-Positive alert.
    """
    cleaned = llm_raw_output.strip()
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.MULTILINE).strip()

    try:
        data = json.loads(cleaned)
        return VerdictEscalation(**data)
    except Exception as e:
        return VerdictEscalation(
            verdict=Verdict.UNCERTAIN,
            verdict_reasoning=f"Không parse được response từ LLM ({type(e).__name__}) — cần review thủ công.",
            escalation_level=EscalationLevel.L2,
            escalation_reason="Fallback an toàn do lỗi parse JSON từ model.",
        )


if __name__ == "__main__":
    # quick smoke test
    sample_alert = {"rule": {"id": "5710", "level": 10}, "agent": {"name": "WIN10-VICTIM"}}
    sample_context = "## KỊCH BẢN 1: BRUTE-FORCE\n- IoC: Event ID 4625 > 10 lần/phút..."
    prompt = build_verdict_prompt(sample_alert, sample_context)
    print(prompt)

    fake_llm_output = '''```json
    {"verdict": "True Positive", "verdict_reasoning": "test",
     "escalation_level": "L2", "escalation_reason": "test"}
    ```'''
    print(parse_verdict_response(fake_llm_output))
