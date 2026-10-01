from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx
import sqlite3
import json
import re
import pandas as pd
from datetime import datetime
import os
import time
from vulns import router as vulns_router
# Thư viện để dịch NL2Query
from nl2query import generate_query
# RAG: embedding model + vectorstore dùng chung (xem shared_rag.py) —
# tránh load model 3 lần (gateway.py / retriever.py / vulns.py mỗi file
# từng tự tạo HuggingFaceEmbeddings riêng)
from shared_rag import get_vectorstore
from incident_correlator import IncidentCorrelator, DEBOUNCE_SECONDS
print("Kiem tra WAZUH_INDEXER_URL:", os.getenv("WAZUH_INDEXER_URL"))

app = FastAPI()
# LƯU Ý: cve_module.py đã bị gỡ khỏi đây. Nó và vulns.py cùng đăng ký
# path /api/v1/soc/vulns — vì cve_module được include trước nên nó che
# mất vulns_router, khiến request luôn rơi vào bảng cve_analysis (không
# tồn tại) thay vì vuln_analysis mà vulns.py quản lý đúng.
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b"
# Công tắc RAG để chạy so sánh có RAG / không RAG trên cùng mô hình:
#   Windows (PowerShell):  $env:USE_RAG="false"; uvicorn gateway:app --port 8080
#   Linux / macOS:         USE_RAG=false uvicorn gateway:app --port 8080
# Mặc định (không đặt biến) là bật RAG. Có thể đặt trong file .env.
USE_RAG = os.getenv("USE_RAG", "true").strip().lower() not in ("0", "false", "no", "off")
RAG_MODE = "rag" if USE_RAG else "no_rag"
print(f"[*] Chế độ RAG: {'BẬT' if USE_RAG else 'TẮT (đường cơ sở, không dùng Playbook)'}")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_results.db")
HTML_PATH = os.path.join(BASE_DIR, "index.html")

# --- KẾT NỐI CHROMADB DÙNG CHUNG (xem shared_rag.py) ---
try:
    vectorstore = get_vectorstore()
    retriever = vectorstore.as_retriever(search_type="mmr", search_kwargs={"k": 3, "fetch_k": 10})
    print(f"[*] Đã kết nối Database Playbook thành công ({vectorstore._collection.count()} đoạn văn bản).")
except Exception as e:
    print(f"[!] Lỗi kết nối Database Playbook: {e}. AI sẽ phân tích chay (không có Playbook).")
    retriever = None

if not USE_RAG:
    retriever = None   # bỏ qua bước truy xuất Playbook hoàn toàn

# --- KHỞI TẠO SQLITE VÀ BẢNG ANALYSIS ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            rule_id TEXT,
            rule_description TEXT,
            rule_level INTEGER,
            agent_name TEXT,
            full_log TEXT,
            severity TEXT,
            analysis TEXT,
            verdict TEXT,
            confidence INTEGER,
            risk_score INTEGER,
            mitre_technique TEXT,
            recommended_actions TEXT
        )
    """)
    cols = [row[1] for row in conn.execute("PRAGMA table_info(analysis)").fetchall()]
    new_cols = {
        "verdict": "TEXT", "confidence": "INTEGER", "risk_score": "INTEGER",
        "mitre_technique": "TEXT", "recommended_actions": "TEXT",
        "sources_used": "TEXT", # THÊM CỘT NÀY ĐỂ WEB VÀ STREAMLIT HIỂN THỊ ĐƯỢC TRÍCH DẪN
        "source_ip": "TEXT", "alert_count": "INTEGER",
        "incident_start": "TEXT", "incident_end": "TEXT",
        # Phán quyết do AI tự đưa ra — TÁCH RIÊNG với cột "verdict" (nhãn do
        # người bấm nút). Nếu dùng chung một cột thì nhãn của người sẽ đè mất
        # phán quyết của AI và không còn gì để so sánh khi đánh giá độ chính xác.
        "ai_verdict": "TEXT", "ai_verdict_reason": "TEXT",
        # Ghi lại kết quả này sinh ra khi bật hay tắt RAG ("rag" / "no_rag")
        "rag_mode": "TEXT"
    }
    for col, col_type in new_cols.items():
        if col not in cols:
            conn.execute(f"ALTER TABLE analysis ADD COLUMN {col} {col_type}")
    conn.commit()
    conn.close()

init_db()

class Rule(BaseModel):
    description: str = "Unknown"
    level: int = 0
    id: str = "0"
    mitre: dict = {}

class WazuhAlert(BaseModel):
    rule: Rule = Rule()
    agent: dict = {}
    full_log: str = "Log Windows EventChannel không có full_log"
    # Wazuh đặt IP nguồn ở data.srcip (hoặc data.win.eventdata.ipAddress với
    # Windows). Thiếu field này thì pydantic bỏ mất, correlator không có IP để gom.
    data: dict = {}

def guess_severity(level: int) -> str:
    if level >= 12: return "CRITICAL"
    if level >= 9: return "HIGH"
    if level >= 7: return "MEDIUM"
    return "LOW"

def quick_risk_score(alert: "WazuhAlert") -> int:
    """
    Điểm rủi ro nhanh (0-100) cho các nhánh KHÔNG qua AI (benchmark, level thấp,
    hoặc AI lỗi phải fallback). Nhánh có AI phân tích thì risk_score lấy trực
    tiếp từ JSON model trả về (đã ở thang 0-100), không qua hàm này.

    Trước đây công thức là `level * 5`, tối đa chỉ 80 dù level kịch trần (16),
    lệch với guess_severity() (level>=12 đã là CRITICAL nhưng risk_score mới 60).
    Giờ nhân hệ số 6 để chạm gần 100 ở level cao, và cộng thêm điểm nếu đây là
    một cuộc tấn công web ĐÃ THÀNH CÔNG (mã trả về 200) thay vì bị chặn.
    """
    base = alert.rule.level * 6
    attack_succeeded = (
        str(alert.data.get("id", "")) == "200"
        and "attack" in alert.rule.description.lower()
    )
    bonus = 10 if attack_succeeded else 0
    return min(100, base + bonus)

# Cập nhật hàm lưu DB để tiếp nhận nguồn Playbook
def save_result(alert: WazuhAlert, parsed: dict, ui_sources: list = None, incident: dict = None):
    if ui_sources is None:
        ui_sources = []
        
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO analysis
           (timestamp, rule_id, rule_description, rule_level, agent_name, full_log,
            severity, analysis, confidence, risk_score, mitre_technique, recommended_actions, sources_used,
            source_ip, alert_count, incident_start, incident_end,
            ai_verdict, ai_verdict_reason, rag_mode)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().isoformat(timespec="seconds"), alert.rule.id, alert.rule.description,
            alert.rule.level, alert.agent.get("name", "unknown"), alert.full_log,
            parsed.get("severity") or guess_severity(alert.rule.level), parsed.get("analysis_text", ""),
            parsed.get("confidence"), parsed.get("risk_score"), parsed.get("mitre_technique"),
            json.dumps(parsed.get("recommended_actions", []), ensure_ascii=False),
            json.dumps(ui_sources, ensure_ascii=False), # Ghi nguồn vào Database
            (incident or {}).get("source_ip"), (incident or {}).get("alert_count", 1),
            (incident or {}).get("first_seen"), (incident or {}).get("last_seen"),
            # None (NULL) với alert không qua AI (CIS/SCA, level < 5) để khi
            # tính chỉ số các dòng này tự bị loại, không lẫn với "unknown".
            parsed.get("ai_verdict"), parsed.get("ai_verdict_reason"), RAG_MODE,
        ),
    )
    conn.commit()
    conn.close()

# --- API GIAO DIỆN WEB (GIỮ NGUYÊN) ---
@app.get("/")
def serve_html():
    return FileResponse(HTML_PATH)

@app.get("/api/v1/soc/stats")
def get_stats():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM analysis ORDER BY id DESC", conn)
    except Exception:
        df = pd.DataFrame()
    conn.close()
    
    total = len(df)
    critical = int((df["severity"] == "CRITICAL").sum()) if not df.empty else 0
    agents = df["agent_name"].nunique() if not df.empty else 0
    
    evaluated = df[df["verdict"].notna()] if not df.empty else pd.DataFrame()
    tp_rate = int((evaluated["verdict"] == "true_positive").sum() / len(evaluated) * 100) if len(evaluated) > 0 else 0
    
    return {"total_alerts": total, "critical_alerts": critical, "agents_count": agents, "tp_rate": tp_rate}

from fastapi import Query
from typing import Optional

@app.get("/api/v1/soc/alerts")
def get_alerts(
    severity: Optional[str] = Query(None, description="Lọc theo CRITICAL, HIGH, MEDIUM, LOW"),
    hide_sca: bool = Query(True, description="Ẩn các log quét CIS Benchmark và SCA"),
    search: Optional[str] = Query(None, description="Tìm kiếm theo mô tả hoặc Rule ID"),
    # THÊM: lọc theo khoảng thời gian, cùng định dạng với cột timestamp
    # (datetime.now().isoformat(timespec="seconds"), giờ local, không có 'Z').
    from_ts: Optional[str] = Query(None, description="Chỉ lấy alert có timestamp >= giá trị này"),
    to_ts: Optional[str] = Query(None, description="Chỉ lấy alert có timestamp <= giá trị này"),
    # PHÂN TRANG: limit mặc định 20/trang, offset xác định trang nào.
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0, description="Số bản ghi bỏ qua, dùng cho phân trang")
):
    conn = sqlite3.connect(DB_PATH)
    try:
        conditions = []
        params = []

        # 1. Lọc theo Severity nếu có chọn
        if severity and severity.upper() != "ALL":
            conditions.append("severity = ?")
            params.append(severity.upper())

        # 2. Ẩn bớt các log kiểm tra tuân thủ CIS Benchmark / SCA định kỳ
        if hide_sca:
            conditions.append("rule_description NOT LIKE '%CIS Microsoft%' AND rule_description NOT LIKE '%SCA summary%'")

        # Ẩn luôn các alert CVE (vulnerability-detector, dạng "CVE-YYYY-NNNNN
        # affects ...") đã lỡ lưu vào DB TRƯỚC KHI có bộ lọc chặn ở
        # /wazuh-alert — luôn bật, không phụ thuộc hide_sca, vì dữ liệu CVE
        # đầy đủ hơn đã có ở tab "Lỗ hổng (CVE)" riêng, dashboard không cần
        # hiển thị trùng nữa.
        conditions.append("rule_description NOT LIKE 'CVE-%affects%'")

        # 3. Tìm kiếm từ khóa nếu người dùng nhập
        if search:
            conditions.append("(rule_description LIKE ? OR rule_id LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        # 4. Lọc theo khoảng thời gian — trước đây việc lọc theo ngày chỉ làm
        # ở frontend, trên đúng 50 dòng đã fetch, nên chọn "Hôm nay" hay
        # "7 ngày gần nhất" không thay đổi gì nếu 50 dòng mới nhất đã rơi ra
        # ngoài khoảng đó.
        if from_ts:
            conditions.append("timestamp >= ?")
            params.append(from_ts)
        if to_ts:
            conditions.append("timestamp <= ?")
            params.append(to_ts)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Tính tổng số bản ghi khớp filter (không phân trang) — dùng để suy ra
        # tổng số trang, và để tính KPI (tổng/critical/agents/tp_rate) đúng
        # theo TOÀN BỘ tập dữ liệu đang lọc, chứ không chỉ 20 dòng của trang
        # hiện tại.
        agg_query = f"SELECT severity, agent_name, verdict FROM analysis {where_clause}"
        full_df = pd.read_sql_query(agg_query, conn, params=params)
        total = len(full_df)
        critical = int((full_df["severity"] == "CRITICAL").sum()) if total else 0
        agents_count = int(full_df["agent_name"].nunique()) if total else 0
        evaluated = full_df[full_df["verdict"].notna()] if total else pd.DataFrame()
        tp_rate = int((evaluated["verdict"] == "true_positive").sum() / len(evaluated) * 100) if len(evaluated) > 0 else 0

        # Dữ liệu của đúng 1 trang
        page_query = f"SELECT * FROM analysis {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        page_params = params + [limit, offset]
        df = pd.read_sql_query(page_query, conn, params=page_params)
        df = df.fillna("")
        alerts = df.to_dict(orient="records")
    except Exception as e:
        print(f"[!] Lỗi API alerts: {e}")
        alerts, total, critical, agents_count, tp_rate = [], 0, 0, 0, 0
    finally:
        conn.close()

    return {
        "alerts": alerts,
        "total": total,
        "limit": limit,
        "offset": offset,
        "stats": {
            "total_alerts": total,
            "critical_alerts": critical,
            "agents_count": agents_count,
            "tp_rate": tp_rate,
        },
    }
class VerdictUpdate(BaseModel):
    alert_id: int
    verdict: str
@app.post("/api/v1/soc/verdict")
async def set_verdict(data: VerdictUpdate):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE analysis SET verdict = ? WHERE id = ?", (data.verdict, data.alert_id))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.get("/api/v1/soc/eval-metrics")
def eval_metrics():
    """So sánh phán quyết của AI (ai_verdict) với nhãn của người (verdict),
    tách theo chế độ rag / no_rag. Chỉ tính các sự cố đã được người gán nhãn."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT COALESCE(rag_mode, 'rag'), ai_verdict, verdict FROM analysis "
        "WHERE verdict IN ('true_positive','false_positive') AND ai_verdict IS NOT NULL"
    ).fetchall()
    conn.close()

    def ratio(x, y):
        return round(x / y, 4) if y else None

    out = {}
    for mode in sorted({r[0] for r in rows}):
        sub = [(a, h) for m, a, h in rows if m == mode]
        tp = sum(1 for a, h in sub if a == "true_positive" and h == "true_positive")
        fp = sum(1 for a, h in sub if a == "true_positive" and h == "false_positive")
        fn = sum(1 for a, h in sub if a == "false_positive" and h == "true_positive")
        tn = sum(1 for a, h in sub if a == "false_positive" and h == "false_positive")
        unknown = sum(1 for a, _ in sub if a not in VALID_AI_VERDICTS)
        precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
        f1 = ratio(2 * precision * recall, precision + recall) if precision and recall else None
        out[mode] = {
            "so_su_co_da_gan_nhan": len(sub),
            "dương_tính_thật": tp, "dương_tính_giả": fp, "âm_tính_giả": fn, "âm_tính_thật": tn,
            "ai_chưa_kết_luận": unknown,
            "độ_chính_xác_chung": ratio(tp + tn, tp + fp + fn + tn),
            "độ_chuẩn": precision, "độ_phủ": recall, "f1": f1,
        }
    return out

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    question: str
    history: list[ChatMessage] = []
    alert_id: int | None = None

@app.post("/api/v1/soc/chat")
async def chat(req: ChatRequest):
    conn = sqlite3.connect(DB_PATH)
    focus_context = ""
    if req.alert_id is not None:
        row = conn.execute("SELECT rule_description, severity, analysis, mitre_technique, full_log FROM analysis WHERE id = ?", (req.alert_id,)).fetchone()
        if row:
            desc, severity, analysis, mitre, full_log = row
            focus_context = f"[ALERT ĐANG CHỌN]:\nMô tả: {desc}\nLevel: {severity}\nMITRE: {mitre}\nPhân tích: {analysis}\nLog: {full_log}"

    rows = conn.execute("SELECT rule_description, severity, analysis FROM analysis ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    
    background_context = "\n".join(f"- [{sev}] {desc}: {str(ana)[:200] if ana else 'Chưa có phân tích'}" for desc, sev, ana in rows) or "Chưa có cảnh báo."
    history_text = "\n".join(f"{m.role}: {m.content}" for m in req.history[-6:])
    
    prompt = f"Bạn là SOC AI.\n{focus_context}\n[NỀN]:\n{background_context}\n[LỊCH SỬ]:\n{history_text}\n[HỎI]: {req.question}\nTrả lời ngắn gọn tiếng Việt."

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            r = await client.post(OLLAMA_URL, json={"model": MODEL_NAME, "prompt": prompt, "stream": False})
            if r.status_code != 200:
                return {"answer": f"⚠️ Lỗi từ Ollama (Mã {r.status_code}): {r.text}"}
            answer = r.json().get("response", "")
            if not answer.strip():
                return {"answer": f"⚠️ Ollama chạy thành công nhưng trả về chuỗi rỗng. Raw: {r.text}"}
            return {"answer": answer}
    except httpx.ReadTimeout:
        return {"answer": "⚠️ Lỗi Timeout: Ollama đang bận xử lý dữ liệu cảnh báo khác, không kịp phản hồi chat trong 120s."}
    except Exception as e:
        return {"answer": f"⚠️ Lỗi kết nối Ollama: {str(e)}"}

class NL2QueryRequest(BaseModel):
    question: str

@app.post("/api/v1/soc/nl2query")
def nl2query_endpoint(req: NL2QueryRequest):
    return generate_query(req.question)
# --- TÍNH NĂNG: TẠO KẾ HOẠCH KHẮC PHỤC CVE (REMEDIATION PLAN) ---
class CVERemediationRequest(BaseModel):
    cve_id: str
    severity: str
    cvss: float
    package: str

def build_cve_prompt(cve_id, severity, cvss, package):
    # RÚT GỌN prompt + yêu cầu output ngắn: trước đây yêu cầu 3 đoạn văn đầy
    # đủ (dễ vượt 400-500 token) khiến model 7B mất nhiều thời gian sinh chữ.
    # Giữ nguyên model 7B (chất lượng phân tích) nhưng ép output súc tích,
    # dạng gạch đầu dòng, có giới hạn số từ rõ ràng để model dừng sớm hơn.
    return f"""Bạn là chuyên gia SOC. CVE: {cve_id} | Mức độ: {severity} (CVSS {cvss}) | Gói: {package}

Lập kế hoạch khắc phục NGẮN GỌN bằng tiếng Việt, dùng HTML cơ bản (<b>, <ul>, <li>), KHÔNG lời dẫn, KHÔNG lặp lại thông tin CVE ở trên, tổng cộng dưới 100 từ, đúng cấu trúc:
<b>Rủi ro:</b> đúng 1 câu ngắn.
<b>Vá lỗi:</b> tối đa 2 gạch đầu dòng, mỗi dòng dưới 15 từ.
<b>Giảm thiểu tạm thời:</b> tối đa 2 gạch đầu dòng, mỗi dòng dưới 15 từ."""

@app.post("/api/v1/soc/cve/remediation")
async def generate_remediation_plan(req: CVERemediationRequest):
    prompt = build_cve_prompt(req.cve_id, req.severity, req.cvss, req.package)
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        # Output giờ ngắn (dưới ~100 từ) nên num_predict thấp là đủ, đồng
        # thời buộc model dừng sớm thay vì lan man -> nhanh hơn rõ rệt.
        "options": {"num_predict": 300}
    }
    try:
        # Prompt+output đã rút gọn nên hạ timeout xuống 90s (từ 240s) — vẫn
        # có biên an toàn nếu Ollama đang bận với alert khác, nhưng không
        # bắt người dùng chờ quá lâu khi có lỗi thật sự (model treo, Ollama
        # down...).
        async with httpx.AsyncClient(timeout=90.0) as client:
            response = await client.post(OLLAMA_URL, json=payload)
            response.raise_for_status()
            ai_response = response.json().get("response", "")
            if not ai_response.strip():
                raise ValueError("Ollama trả về response rỗng (có thể do bị cắt hoặc model lỗi)")
            return {"status": "success", "remediation_plan": ai_response}
    except httpx.ReadTimeout:
        # TRƯỚC: rơi vào except Exception chung, str(e) rỗng -> hiện đúng
        # "Lỗi khi gọi AI:" không kèm gì, không biết là do đâu.
        msg = "Timeout: Ollama không phản hồi trong 90s (có thể đang bận xử lý các alert khác cùng lúc)."
        print(f"[!] Lỗi lập kế hoạch CVE {req.cve_id}: ReadTimeout - {msg}")
        return {"status": "error", "remediation_plan": f"<span class='text-red-400'>Lỗi khi gọi AI: {msg}</span>"}
    except Exception as e:
        # In kèm type(e).__name__ để biết chính xác lỗi gì (ConnectError,
        # HTTPStatusError, ValueError response rỗng, v.v.) thay vì im lặng.
        print(f"[!] Lỗi lập kế hoạch CVE {req.cve_id}: {type(e).__name__}: {e}")
        return {"status": "error", "remediation_plan": f"<span class='text-red-400'>Lỗi khi gọi AI: {type(e).__name__}: {e}</span>"}
app.include_router(vulns_router)

# --- HÀM BỔ TRỢ CỦA GROK THÊM VÀO ---
def playbook_filter(rule_id: str, description: str) -> dict | None:
    rid = str(rule_id or "")
    d = (description or "").lower()
    
    # web
    if rid.startswith("311") or any(x in d for x in ("sql injection", "xss", "path traversal", "command injection", "file inclusion", "web attack", "common web")):
        return {"source": {"$contains": "Web_vulnebrality.md"}}
    # windows identity
    if rid in {"18152", "60154", "60109", "60110", "60111", "60115"} or any(x in d for x in ("logon", "login failure", "administrators group", "user account", "account locked")):
        return {"source": {"$contains": "windows_identity_playbook.md"}}
    # linux package
    if rid in {"2902", "2904"} or "dpkg" in d:
        return {"source": {"$contains": "linux_system_playbook.md"}}
    # CIS/SCA: khong tim playbook
    if "cis microsoft" in d or "sca summary" in d:
        return None
    return None

_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

def is_valid_mitre_technique(value: str | None) -> bool:
    """Kiểm tra chuỗi mitre_technique có đúng định dạng 'Txxxx - Tên' (hoặc nhiều mã nối dấu phẩy)."""
    if not value or not isinstance(value, str):
        return False
    parts = [p.strip() for p in value.split(",")]
    for part in parts:
        code = part.split(" - ", 1)[0].strip()
        if not _MITRE_ID_RE.match(code):
            return False
    return True

def mitre_from_wazuh(alert) -> str | None:
    m = getattr(alert.rule, "mitre", None) or {}
    ids = m.get("id") or []
    names = m.get("technique") or []
    if isinstance(ids, str):
        ids = [ids]
    if isinstance(names, str):
        names = [names]
    if not ids:
        return None
    # "T1190 - Exploit Public-Facing Application"
    parts = []
    for i, tid in enumerate(ids):
        name = names[i] if i < len(names) else ""
        parts.append(f"{tid} - {name}".strip(" -"))
    return ", ".join(parts)


# --- XỬ LÝ NHẬN ALERT + RAG PLAYBOOK (PHẦN QUAN TRỌNG NHẤT) ---
SYSTEM_PROMPT_ANALYSIS = """Bạn là chuyên gia SOC Blue-team. Hãy phân tích cảnh báo này dựa vào PLAYBOOK được cung cấp.
Trả lời DUY NHẤT bằng định dạng JSON sau, không xuất hiện text dư thừa:
{ "severity": "CRITICAL/HIGH/MEDIUM/LOW", "confidence": 90, "risk_score": 85, "mitre_technique": "Txxxx - Tên kỹ thuật", "analysis_text": "Giải thích chi tiết vì sao đây là mối đe dọa dựa trên playbook...", "recommended_actions": ["Hành động 1", "Hành động 2"], "ai_verdict": "true_positive hoặc false_positive", "ai_verdict_reason": "Một câu nêu căn cứ trong log" }

Quy tắc cho trường "ai_verdict" (chỉ được dùng đúng một trong hai giá trị):
- "true_positive": log cho thấy hành vi tấn công hoặc xâm nhập thật sự (ví dụ: payload chèn SQL/XSS/đi xuyên thư mục/chèn lệnh trong yêu cầu web, nhiều lần đăng nhập sai liên tiếp từ cùng một nguồn rồi thành công).
- "false_positive": cảnh báo phát sinh từ hoạt động bình thường hoặc do cấu hình, không có dấu hiệu tấn công trong log.
Chỉ dựa vào log và playbook, không suy đoán thêm.
Không tự sinh mã Txxxx. Để trống nếu không chắc."""

def _fallback_analysis(alert: WazuhAlert) -> dict:
    # Dù AI lỗi, vẫn lấy mã MITRE chính thức từ Wazuh nếu có, thay vì luôn để "Chưa xác định".
    official_mitre = mitre_from_wazuh(alert) or "Chưa xác định"
    return {"severity": guess_severity(alert.rule.level), "confidence": 30, "risk_score": quick_risk_score(alert), "mitre_technique": official_mitre, "analysis_text": "AI xử lý lỗi hoặc thiếu format JSON, đây là kết quả an toàn mặc định.", "recommended_actions": ["Kiểm tra thủ công trên Kibana"]}

# Bản câu lệnh hệ thống cho chế độ KHÔNG RAG: bỏ mọi chỗ nhắc tới playbook,
# nếu không mô hình sẽ bị bảo "dựa vào playbook" trong khi không có playbook nào.
_NO_RAG_SUBS = [
    ("Hãy phân tích cảnh báo này dựa vào PLAYBOOK được cung cấp.", "Hãy phân tích cảnh báo này."),
    ("vì sao đây là mối đe dọa dựa trên playbook...", "vì sao đây là mối đe dọa..."),
    ("Chỉ dựa vào log và playbook, không suy đoán thêm.", "Chỉ dựa vào log, không suy đoán thêm."),
]
SYSTEM_PROMPT_NO_RAG = SYSTEM_PROMPT_ANALYSIS
for _old, _new in _NO_RAG_SUBS:
    assert _old in SYSTEM_PROMPT_NO_RAG, f"Câu lệnh hệ thống đã đổi, cần cập nhật _NO_RAG_SUBS: {_old!r}"
    SYSTEM_PROMPT_NO_RAG = SYSTEM_PROMPT_NO_RAG.replace(_old, _new)

VALID_AI_VERDICTS = {"true_positive", "false_positive"}

def normalize_ai_verdict(parsed: dict):
    """Chỉ chấp nhận 2 giá trị hợp lệ. Mô hình trả sai định dạng hoặc AI lỗi
    (dùng kết quả dự phòng) thì ghi "unknown" — TUYỆT ĐỐI không đoán mặc định
    là tấn công thật, vì sẽ làm sai lệch số liệu đánh giá."""
    v = str(parsed.get("ai_verdict", "")).strip().lower().replace(" ", "_").replace("-", "_")
    if v not in VALID_AI_VERDICTS:
        v = "unknown"
    reason = str(parsed.get("ai_verdict_reason", "") or "")[:500]
    return v, reason

# Wazuh vulnerability-detector sinh alert dạng "CVE-YYYY-NNNNN affects <package>"
# đổ vào CÙNG pipeline alert thường (rule.id ~23504-23507), khiến LLM phải
# xử lý thêm hàng nghìn alert trùng lặp với dữ liệu đã có sẵn, đầy đủ hơn,
# ở index wazuh-states-vulnerabilities-* (chính là nguồn tab "Lỗ hổng (CVE)"
# đang dùng qua vulns.py). Nhận diện bằng regex trên rule.description để
# chặn sớm, không tốn tài nguyên Ollama và không lưu trùng vào dashboard.
CVE_ALERT_RE = re.compile(r"^CVE-\d{4}-\d{4,}\s+affects\b", re.I)

# --- PHÂN TÍCH 1 INCIDENT (RAG + LLM + LƯU DB) ---
async def analyze_and_save(alert: WazuhAlert, incident: dict = None):
    """alert = alert đại diện (level cao nhất). incident = tóm tắt cả cụm alert
    đã gom (None nếu không gom). Gọi Ollama đúng 1 lần cho cả cụm."""
    multi = bool(incident) and incident.get("alert_count", 1) > 1

    # 1. TRUY XUẤT PLAYBOOK TỪ CHROMA DB
    rag_context = "Chưa có kịch bản playbook nào phù hợp trong Database."
    ui_sources = []

    if retriever:
        if multi:
            retrieval_query = "; ".join(incident["rule_descriptions"]) + f". {alert.full_log}"
        else:
            retrieval_query = f"{alert.rule.description}. {alert.full_log}"
        try:
            # Code mới của Grok: Lọc đúng file playbook
            filt = playbook_filter(alert.rule.id, alert.rule.description)
            search_kwargs = {"k": 3}
            if filt:
                search_kwargs["filter"] = filt
                
            docs = vectorstore.as_retriever(
                search_type="mmr", 
                search_kwargs=search_kwargs
            ).invoke(retrieval_query)
            
            if docs:
                rag_context = "\n\n".join([d.page_content for d in docs])
                seen = set()
                for doc in docs:
                    file_path = doc.metadata.get("source", "Unknown").split("\\")[-1]
                    heading = doc.metadata.get("h2") or doc.metadata.get("h1") or doc.metadata.get("h3") or "Trích xuất Playbook"
                    identifier = f"{file_path}-{heading}"
                    if identifier not in seen:
                        seen.add(identifier)
                        ui_sources.append({
                            "file": file_path,
                            "source_type": doc.metadata.get("source_type", "Playbook"),
                            "heading": heading
                        })
        except Exception as e:
            print(f"[!] Lỗi tìm kiếm Playbook: {e}")

    # 2. GHÉP PLAYBOOK (+ TỔNG HỢP INCIDENT NẾU CÓ) VÀO PROMPT
    incident_block = ""
    task = "Dựa CHỈ VÀO PLAYBOOK ở trên, hãy đưa ra đánh giá `severity`, `mitre_technique`, `analysis_text` và `recommended_actions`. Nếu Playbook không khớp, hãy tự đánh giá độc lập."
    if not USE_RAG:
        task = "Hãy đưa ra đánh giá `severity`, `mitre_technique`, `analysis_text` và `recommended_actions` dựa trên dữ liệu cảnh báo."
    if multi:
        samples = "\n".join(
            f"- [Cảnh báo #{i+1}] [L{a.get('rule', {}).get('level', 0)}] "
            f"nhóm: {', '.join(a.get('rule', {}).get('groups', []) or ['(không rõ)'])} | "
            f"{a.get('rule', {}).get('description', '')} | "
            f"MITRE: {', '.join(a.get('rule', {}).get('mitre', {}).get('id', []) or ['(không có)'])} | "
            f"log: {str(a.get('full_log', ''))[:300]}"
            for i, a in enumerate(incident["sample_alerts"])
        )
        incident_block = f"""
[TỔNG HỢP INCIDENT]:
{incident['alert_count']} cảnh báo liên quan (nguồn: {incident['key']}) trong {incident['duration_seconds']:.0f} giây.
Rule liên quan: {', '.join(incident['rule_ids'])}
Host bị nhắm tới: {', '.join(incident['target_hosts']) or 'unknown'}
LƯU Ý QUAN TRỌNG: các cảnh báo dưới đây CÓ THỂ thuộc bản chất khác nhau (ví dụ một cảnh báo
chỉ là thay đổi tệp cấu hình vô hại, cảnh báo khác là tấn công thật đã thành công). Hãy đánh
giá TỪNG cảnh báo riêng, sau đó chốt severity/mitre_technique/analysis_text theo cảnh báo
NGHIÊM TRỌNG NHẤT trong nhóm — không được bỏ qua cảnh báo nào chỉ vì nó liệt kê sau cùng.
Các cảnh báo trong sự cố này:
{samples}
"""
        task = "Đánh giá TOÀN BỘ chuỗi sự kiện trên như MỘT incident duy nhất (severity, mitre_technique, analysis_text, recommended_actions), dựa vào PLAYBOOK. Nếu Playbook không khớp, hãy tự đánh giá độc lập."
        if not USE_RAG:
            task = "Đánh giá TOÀN BỘ chuỗi sự kiện trên như MỘT incident duy nhất (severity, mitre_technique, analysis_text, recommended_actions)."

    playbook_block = f"[PLAYBOOK HƯỚNG DẪN XỬ LÝ SOC]:\n{rag_context}\n" if USE_RAG else ""
    system_prompt = SYSTEM_PROMPT_ANALYSIS if USE_RAG else SYSTEM_PROMPT_NO_RAG

    user_prompt = f"""{playbook_block}{incident_block}
[DỮ LIỆU CẢNH BÁO TỪ WAZUH]:
Rule ID: {alert.rule.id}
Rule Mô tả: {alert.rule.description} (level {alert.rule.level})
Agent: {alert.agent.get('name', 'unknown')}
Log gốc: {alert.full_log}

Nhiệm vụ: {task}"""

    # 3. GỌI LLM XỬ LÝ
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            r = await client.post(OLLAMA_URL, json={
                "model": MODEL_NAME,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.1, "num_predict": 900}
            })
            r.raise_for_status()
            raw_response = r.json().get("response", "{}")
            parsed = json.loads(raw_response)
            assert "analysis_text" in parsed and "severity" in parsed, \
                f"JSON thiếu field bắt buộc. Raw: {raw_response[:300]!r}"
            
            # Code mới của Grok: Ép mã MITRE chuẩn từ Wazuh (tránh AI tự bịa)
            if multi and incident.get("mitre_techniques"):
                # Sự cố gộp nhiều cảnh báo -> lấy HỢP mã MITRE của TẤT CẢ cảnh báo,
                # không chỉ của alert đại diện (top_alert), để không mất mã như T1190
                # khi top_alert là cảnh báo file-integrity còn cảnh báo khác mới là
                # tấn công thật.
                parsed["mitre_technique"] = ", ".join(incident["mitre_techniques"])
            else:
                official = mitre_from_wazuh(alert)
                if official:
                    parsed["mitre_technique"] = official
                elif not is_valid_mitre_technique(parsed.get("mitre_technique")):
                    # Wazuh không gắn mã, và mã AI tự đưa ra không đúng định dạng Txxxx -> không tin, để trống.
                    parsed["mitre_technique"] = "Chưa xác định"
                
    except Exception as e:
        print(f"[!] Lỗi phân tích LLM: {type(e).__name__}: {e}")
        parsed = _fallback_analysis(alert)

    # Chuẩn hóa phán quyết của AI trước khi lưu (thiếu/sai định dạng -> "unknown")
    parsed["ai_verdict"], parsed["ai_verdict_reason"] = normalize_ai_verdict(parsed)

    # 4. LƯU DỮ LIỆU VÀ NGUỒN PLAYBOOK VÀO SQLITE
    save_result(alert, parsed, ui_sources, incident)
    n = incident["alert_count"] if incident else 1
    print(f"[+] Phân tích xong incident ({n} alert, level cao nhất {alert.rule.level}) - {len(ui_sources)} mục Playbook.")
    return parsed


# Theo dõi tiến trình xử lý để hiển thị trên bảng điều khiển
ANALYZING: dict = {}   # các sự cố mà AI đang phân tích
LAST_DONE: dict = {}   # sự cố vừa xử lý xong gần nhất


async def handle_incident_ready(incident_ctx: dict):
    """Callback của correlator: chạy nền, nên phải tự bắt lỗi để không bị nuốt im lặng."""
    job_id = id(incident_ctx)
    ANALYZING[job_id] = {
        "key": incident_ctx["key"],
        "alert_count": incident_ctx["alert_count"],
        "started": time.time(),
    }
    print(f"[*] Bắt đầu phân tích sự cố {incident_ctx['key']} ({incident_ctx['alert_count']} cảnh báo)...")
    try:
        top = WazuhAlert(**incident_ctx["top_alert"])
        parsed = await analyze_and_save(top, incident_ctx)
        LAST_DONE.update({
            "key": incident_ctx["key"],
            "alert_count": incident_ctx["alert_count"],
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "took": int(time.time() - ANALYZING[job_id]["started"]),
            # AI lỗi thì hàm dự phòng trả về kết quả mặc định độ tin cậy 30
            "ai_failed": parsed.get("mitre_technique") == "Chưa xác định" and parsed.get("confidence") == 30,
        })
    except Exception as e:
        print(f"[!] Lỗi xử lý incident: {type(e).__name__}: {e}")
        LAST_DONE.update({
            "key": incident_ctx["key"],
            "alert_count": incident_ctx["alert_count"],
            "finished_at": datetime.now().isoformat(timespec="seconds"),
            "took": 0,
            "ai_failed": True,
        })
    finally:
        ANALYZING.pop(job_id, None)


correlator = IncidentCorrelator(on_incident_ready=handle_incident_ready)


@app.get("/api/v1/soc/pipeline-status")
def pipeline_status():
    now = time.time()
    return {
        "debounce_seconds": DEBOUNCE_SECONDS,
        "grouping": correlator.status(),
        "analyzing": [
            {"key": j["key"], "alert_count": j["alert_count"], "elapsed": int(now - j["started"])}
            for j in ANALYZING.values()
        ],
        "last_done": LAST_DONE or None,
    }


@app.post("/api/v1/soc/wazuh-alert")
async def receive_alert(alert: WazuhAlert):
    if CVE_ALERT_RE.match(alert.rule.description.strip()):
        return {"status": "skipped", "reason": "CVE vulnerability-detector alert — xem ở tab CVE"}

    desc_lower = alert.rule.description.lower()
    is_benchmark = "cis microsoft" in desc_lower or "sca summary" in desc_lower

    # CIS benchmark / cảnh báo level < 6: lưu nhanh, không gom, không gọi Ollama
    if is_benchmark or alert.rule.level < 6:
        quick_analysis = {
            "severity": guess_severity(alert.rule.level),
            "confidence": 100,
            "risk_score": quick_risk_score(alert),
            "mitre_technique": "N/A",
            "analysis_text": "Cảnh báo kiểm tra tuân thủ/cấu hình định kỳ từ hệ thống.",
            "recommended_actions": ["Xem chi tiết khuyến nghị cấu hình trong tài liệu CIS."]
        }
        save_result(alert, quick_analysis, [])
        return {"status": "ok", "analysis": quick_analysis}

    # Alert đáng chú ý: đưa vào correlator, LLM chỉ được gọi khi incident "chốt"
    payload = alert.model_dump() if hasattr(alert, "model_dump") else alert.dict()
    await correlator.ingest(payload)
    return {"status": "queued", "note": "đang gom nhóm incident, kết quả xuất hiện sau khoảng debounce"}