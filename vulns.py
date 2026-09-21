"""
vulns.py - CVE / lỗ hổng từ Wazuh Vulnerability Detection (Wazuh >= 4.8)

Gắn vào gateway.py:
    from vulns import router as vulns_router
    app.include_router(vulns_router)

Endpoint (prefix /api/v1/soc):
    GET  /vulns                 danh sách CVE (gộp theo CVE ID), kèm đánh giá AI nếu đã có
    POST /vulns/explain         nhờ LLM tóm tắt + ưu tiên hóa 1 CVE   body: {"cve_id": "CVE-2024-1234"}
    POST /vulns/explain-top     chạy nền: phân tích top N CVE Critical/High chưa có đánh giá

Nguyên tắc: CVE ID, CVSS, tên gói, phiên bản, mô tả lấy trực tiếp từ Wazuh.
LLM chỉ viết tóm tắt, mức ưu tiên và gợi ý khắc phục, không được sinh ra các trường dữ liệu trên.

ENV:
    WAZUH_INDEXER_URL     mặc định https://localhost:9200
    WAZUH_INDEXER_USER    mặc định admin
    WAZUH_INDEXER_PASS    bắt buộc
    WAZUH_INDEXER_VERIFY  "true" nếu indexer có cert hợp lệ (lab cert tự ký thì để false)
    OLLAMA_URL            mặc định http://localhost:11434
    OLLAMA_MODEL          mặc định qwen2.5:7b
    SOC_DB_PATH           trỏ tới cùng file SQLite mà gateway.py đang dùng
"""
import json
import logging
import os
import re
import sqlite3
import time
from typing import Optional
import requests
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import os

log = logging.getLogger("vulns")

INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200").rstrip("/")
INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("WAZUH_INDEXER_PASS", "")
INDEXER_VERIFY = os.getenv("WAZUH_INDEXER_VERIFY", "false").lower() == "true"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
DB_PATH = os.getenv("SOC_DB_PATH", "soc.db")

INDEX = "wazuh-states-vulnerabilities-*"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
DEFAULT_PRIORITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

if not INDEXER_VERIFY:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

router = APIRouter(prefix="/api/v1/soc", tags=["vulns"])


# ---------------------------------------------------------------- SQLite
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS vuln_analysis (
               cve_id     TEXT PRIMARY KEY,
               summary    TEXT,
               priority   TEXT,
               action     TEXT,
               model      TEXT,
               created_at TEXT
           )"""
    )
    return conn


def _get_cached(cve_ids: list[str]) -> dict:
    if not cve_ids:
        return {}
    conn = _db()
    try:
        marks = ",".join("?" * len(cve_ids))
        rows = conn.execute(
            f"SELECT * FROM vuln_analysis WHERE cve_id IN ({marks})", cve_ids
        ).fetchall()
        return {r["cve_id"]: dict(r) for r in rows}
    finally:
        conn.close()


def _save(cve_id: str, ai: dict) -> dict:
    row = {
        "cve_id": cve_id,
        "summary": ai["summary"],
        "priority": ai["priority"],
        "action": ai["action"],
        "model": OLLAMA_MODEL,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    conn = _db()
    try:
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO vuln_analysis "
                "(cve_id, summary, priority, action, model, created_at) "
                "VALUES (:cve_id, :summary, :priority, :action, :model, :created_at)",
                row,
            )
    finally:
        conn.close()
    return row


# ---------------------------------------------------------------- Wazuh indexer
def fetch_vulns(severity=None, agent=None, cve_id=None, size=1000) -> list[dict]:
    filters = []
    if severity:
        filters.append({"terms": {"vulnerability.severity": severity}})
    if agent:
        filters.append({"term": {"agent.name": agent}})
    if cve_id:
        filters.append({"term": {"vulnerability.id": cve_id}})

    body = {
        "size": size,
        "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}}],
        "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
    }
    try:
        r = requests.post(
            f"{INDEXER_URL}/{INDEX}/_search",
            json=body,
            auth=(INDEXER_USER, INDEXER_PASS),
            verify=INDEXER_VERIFY,
            timeout=30,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        raise HTTPException(502, f"Không truy vấn được Wazuh indexer: {e}")
    return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]


def group_by_cve(hits: list[dict]) -> list[dict]:
    """Một CVE có thể xuất hiện nhiều dòng (nhiều gói, nhiều agent) nên gộp lại theo CVE ID."""
    out: dict[str, dict] = {}
    for s in hits:
        v = s.get("vulnerability") or {}
        a = s.get("agent") or {}
        p = s.get("package") or {}
        cve = v.get("id")
        if not cve:
            continue
        item = out.setdefault(
            cve,
            {
                "cve_id": cve,
                "severity": v.get("severity"),
                "score": (v.get("score") or {}).get("base"),
                "description": v.get("description"),
                "published_at": v.get("published_at"),
                "reference": v.get("reference"),
                "agents": [],
                "packages": [],
            },
        )
        if a.get("name") and a["name"] not in item["agents"]:
            item["agents"].append(a["name"])
        pkg = f'{p.get("name", "")} {p.get("version", "")}'.strip()
        if pkg and pkg not in item["packages"]:
            item["packages"].append(pkg)

    items = list(out.values())
    items.sort(key=lambda i: (SEVERITY_ORDER.get(i["severity"], 9), -(i["score"] or 0)))
    return items


# ---------------------------------------------------------------- LLM
PROMPT = """Bạn là chuyên viên SOC. Hãy đánh giá lỗ hổng dưới đây CHỈ dựa trên dữ liệu do Wazuh cung cấp.
KHÔNG được tự thêm, sửa hoặc bịa mã CVE, điểm CVSS, tên gói, phiên bản.
KHÔNG khẳng định lỗ hổng đang bị khai thác trong thực tế nếu dữ liệu không nói vậy.

Dữ liệu:
- CVE: {cve_id}
- Mức độ: {severity} (CVSS {score})
- Gói bị ảnh hưởng: {packages}
- Máy bị ảnh hưởng: {agents}
- Mô tả: {description}
{context}
Trả về JSON đúng dạng sau, không thêm gì khác:
{{"summary": "<2-3 câu tiếng Việt: lỗ hổng là gì, rủi ro với hệ thống>", "priority": "P1|P2|P3|P4", "action": "<1-2 câu tiếng Việt: cách khắc phục, ví dụ cập nhật gói lên bản đã vá>"}}
Quy ước ưu tiên: P1 = vá ngay, P2 = trong tuần, P3 = theo lịch bảo trì, P4 = theo dõi."""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMA_PATH = os.path.join(BASE_DIR, "chroma_db")

try:
    embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/paraphrase-multilingual-mpnet-base-v2")
    vectorstore = Chroma(persist_directory=CHROMA_PATH, embedding_function=embeddings, collection_name="soc_knowledge")
    vuln_retriever = vectorstore.as_retriever(search_type="mmr", search_kwargs={"k": 2})
except Exception as e:
    vuln_retriever = None
    log.warning(f"Lỗi khởi tạo RAG cho Vulns: {e}")

def _rag_context(item: dict) -> str:
    """Lấy Playbook hướng dẫn xử lý lỗ hổng (nếu có) từ ChromaDB"""
    if not vuln_retriever:
        return ""
        
    query = f"{item['cve_id']} {item.get('description', '')}"
    try:
        docs = vuln_retriever.invoke(query)
        if docs:
            context = "\n\n".join([d.page_content for d in docs])
            return f"\n[TÀI LIỆU HƯỚNG DẪN XỬ LÝ (RAG)]:\n{context}\n"
    except Exception as e:
        log.warning(f"Lỗi truy vấn RAG cho {item['cve_id']}: {e}")
    return ""


def _explain(item: dict) -> dict:
    prompt = PROMPT.format(
        cve_id=item["cve_id"],
        severity=item["severity"] or "N/A",
        score=item["score"] if item["score"] is not None else "N/A",
        packages=", ".join(item["packages"][:10]) or "N/A",
        agents=", ".join(item["agents"][:10]) or "N/A",
        description=(item["description"] or "N/A")[:1500],
        context=_rag_context(item),
    )
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.2},
            },
            timeout=180,
        )
        r.raise_for_status()
        data = json.loads(r.json()["response"])
    except (requests.RequestException, ValueError, KeyError) as e:
        raise HTTPException(502, f"LLM không trả về kết quả hợp lệ: {e}")

    priority = str(data.get("priority", "")).upper()
    if priority not in {"P1", "P2", "P3", "P4"}:
        priority = DEFAULT_PRIORITY.get(item["severity"], "P3")
    ai = {
        "summary": str(data.get("summary", "")).strip(),
        "priority": priority,
        "action": str(data.get("action", "")).strip(),
    }
    if not ai["summary"]:
        raise HTTPException(502, "LLM trả về JSON nhưng thiếu phần summary")
    return _save(item["cve_id"], ai)


# ---------------------------------------------------------------- API
class ExplainReq(BaseModel):
    cve_id: str


@router.get("/vulns")
def list_vulns(
    severity: Optional[list[str]] = Query(None),
    agent: Optional[str] = None,
    limit: int = Query(200, ge=1, le=1000),
):
    sev = [s.capitalize() for s in severity] if severity else None
    items = group_by_cve(fetch_vulns(severity=sev, agent=agent))
    total = len(items)
    items = items[:limit]
    cached = _get_cached([i["cve_id"] for i in items])
    for i in items:
        i["ai"] = cached.get(i["cve_id"])
    return {"total": total, "items": items}


@router.post("/vulns/explain")
def explain_vuln(req: ExplainReq):
    cve = req.cve_id.strip().upper()
    if not CVE_RE.match(cve):
        raise HTTPException(400, "cve_id không đúng định dạng CVE-YYYY-NNNN")
    items = group_by_cve(fetch_vulns(cve_id=cve))
    if not items:
        raise HTTPException(404, f"Wazuh không có {cve} trong dữ liệu lỗ hổng")
    return {"cve_id": cve, "ai": _explain(items[0])}


def _explain_batch(items: list[dict]):
    for it in items:
        try:
            _explain(it)
        except Exception as e:  # chạy nền: một CVE lỗi không được làm dừng cả lô
            log.warning("explain %s thất bại: %s", it["cve_id"], e)


@router.post("/vulns/explain-top")
def explain_top(background: BackgroundTasks, n: int = Query(5, ge=1, le=20)):
    items = group_by_cve(fetch_vulns(severity=["Critical", "High"]))
    cached = _get_cached([i["cve_id"] for i in items])
    todo = [i for i in items if i["cve_id"] not in cached][:n]
    background.add_task(_explain_batch, todo)
    return {"queued": [i["cve_id"] for i in todo]}
