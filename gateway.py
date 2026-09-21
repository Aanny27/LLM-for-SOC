from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import httpx
import sqlite3
import json
import pandas as pd
from datetime import datetime
import os
from vulns import router as vulns_router

# Thư viện để dịch NL2Query
from nl2query import generate_query

# Thư viện để nạp RAG (ChromaDB)
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

app = FastAPI()

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_results.db")
HTML_PATH = os.path.join(BASE_DIR, "index.html")
CHROMA_PATH = os.path.join(BASE_DIR, "chroma_db")

# --- KHỞI TẠO CHROMADB (TỰ ĐỘNG ĐỌC PLAYBOOK) ---
try:
    embeddings = HuggingFaceEmbeddings(
        model_name="sentence-transformers/paraphrase-multilingual-mpnet-base-v2"
    )
    vectorstore = Chroma(
        persist_directory=CHROMA_PATH,
        embedding_function=embeddings,
        collection_name="soc_knowledge"
    )
    retriever = vectorstore.as_retriever(search_type="mmr", search_kwargs={"k": 3, "fetch_k": 10})
    print(f"[*] Đã kết nối Database Playbook thành công ({vectorstore._collection.count()} đoạn văn bản).")
except Exception as e:
    print(f"[!] Lỗi kết nối Database Playbook: {e}. AI sẽ phân tích chay (không có Playbook).")
    retriever = None

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
        "sources_used": "TEXT" # THÊM CỘT NÀY ĐỂ WEB VÀ STREAMLIT HIỂN THỊ ĐƯỢC TRÍCH DẪN
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

class WazuhAlert(BaseModel):
    rule: Rule = Rule()
    agent: dict = {}
    full_log: str = "Log Windows EventChannel không có full_log"

def guess_severity(level: int) -> str:
    if level >= 12: return "CRITICAL"
    if level >= 9: return "HIGH"
    if level >= 7: return "MEDIUM"
    return "LOW"

# Cập nhật hàm lưu DB để tiếp nhận nguồn Playbook
def save_result(alert: WazuhAlert, parsed: dict, ui_sources: list = None):
    if ui_sources is None:
        ui_sources = []
        
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO analysis
           (timestamp, rule_id, rule_description, rule_level, agent_name, full_log,
            severity, analysis, confidence, risk_score, mitre_technique, recommended_actions, sources_used)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now().isoformat(timespec="seconds"), alert.rule.id, alert.rule.description,
            alert.rule.level, alert.agent.get("name", "unknown"), alert.full_log,
            parsed.get("severity") or guess_severity(alert.rule.level), parsed.get("analysis_text", ""),
            parsed.get("confidence"), parsed.get("risk_score"), parsed.get("mitre_technique"),
            json.dumps(parsed.get("recommended_actions", []), ensure_ascii=False),
            json.dumps(ui_sources, ensure_ascii=False) # Ghi nguồn vào Database
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

@app.get("/api/v1/soc/alerts")
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM analysis ORDER BY id DESC LIMIT 50", conn)
        df = df.fillna("") 
        alerts = df.to_dict(orient="records")
    except Exception as e:
        print(f"[!] Lỗi API alerts: {e}") 
        alerts = []
    conn.close()
    return {"alerts": alerts}

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

app.include_router(vulns_router)
# --- XỬ LÝ NHẬN ALERT + RAG PLAYBOOK (PHẦN QUAN TRỌNG NHẤT) ---
SYSTEM_PROMPT_ANALYSIS = """Bạn là chuyên gia SOC Blue-team. Hãy phân tích cảnh báo này dựa vào PLAYBOOK được cung cấp.
Trả lời DUY NHẤT bằng định dạng JSON sau, không xuất hiện text dư thừa:
{ "severity": "CRITICAL/HIGH/MEDIUM/LOW", "confidence": 90, "risk_score": 85, "mitre_technique": "Txxxx - Tên kỹ thuật", "analysis_text": "Giải thích chi tiết vì sao đây là mối đe dọa dựa trên playbook...", "recommended_actions": ["Hành động 1", "Hành động 2"] }"""

def _fallback_analysis(alert: WazuhAlert) -> dict:
    return {"severity": guess_severity(alert.rule.level), "confidence": 30, "risk_score": alert.rule.level * 5, "mitre_technique": "Chưa xác định", "analysis_text": "AI xử lý lỗi hoặc thiếu format JSON, đây là kết quả an toàn mặc định.", "recommended_actions": ["Kiểm tra thủ công trên Kibana"]}

@app.post("/api/v1/soc/wazuh-alert")
async def receive_alert(alert: WazuhAlert):
    # 1. TRUY XUẤT PLAYBOOK TỪ CHROMA DB
    rag_context = "Chưa có kịch bản playbook nào phù hợp trong Database."
    ui_sources = []
    
    if retriever:
        retrieval_query = f"{alert.rule.description}. {alert.full_log}"
        try:
            docs = retriever.invoke(retrieval_query)
            if docs:
                rag_context = "\n\n".join([d.page_content for d in docs])
                
                # Trích xuất metadata để hiển thị đẹp lên Giao diện web
                seen = set()
                for doc in docs:
                    file_path = doc.metadata.get("source", "Unknown").split("\\")[-1] # Chỉ lấy tên file
                    # Ưu tiên lấy Header Markdown làm tiêu đề
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

    # 2. GHÉP PLAYBOOK VÀO PROMPT CHO OLLAMA
    user_prompt = f"""[PLAYBOOK HƯỚNG DẪN XỬ LÝ SOC]:
{rag_context}

[DỮ LIỆU CẢNH BÁO TỪ WAZUH]:
Rule ID: {alert.rule.id}
Rule Mô tả: {alert.rule.description} (level {alert.rule.level})
Agent: {alert.agent.get('name', 'unknown')}
Log gốc: {alert.full_log}

Nhiệm vụ: Dựa CHỈ VÀO PLAYBOOK ở trên, hãy đưa ra đánh giá `severity`, `mitre_technique`, `analysis_text` và `recommended_actions`. Nếu Playbook không khớp, hãy tự đánh giá độc lập."""

    # 3. GỌI LLM XỬ LÝ
    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            r = await client.post(OLLAMA_URL, json={
                "model": MODEL_NAME, 
                "prompt": f"{SYSTEM_PROMPT_ANALYSIS}\n\n{user_prompt}", 
                "stream": False, 
                "format": "json", 
                "options": {"temperature": 0.1}
            })
            r.raise_for_status() 
            parsed = json.loads(r.json().get("response", "{}"))
            assert "analysis_text" in parsed and "severity" in parsed
    except Exception as e:
        print(f"[!] Lỗi phân tích LLM: {e}")
        parsed = _fallback_analysis(alert)

    # 4. LƯU DỮ LIỆU VÀ CẢ NGUỒN PLAYBOOK VÀO SQLITE
    save_result(alert, parsed, ui_sources)
    print(f"[+] Phân tích thành công Alert (Level {alert.rule.level}) - Nguồn lấy từ {len(ui_sources)} mục Playbook.")
    
    return {"status": "ok", "analysis": parsed}