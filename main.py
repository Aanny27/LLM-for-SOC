import uuid
import sqlite3
import json
from datetime import datetime, timezone

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import os
from retriever import analyze_alert

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_results.db")


class AlertModel(BaseModel):
    rule_id: str
    description: str
    raw_log: str
    source_ip: str


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS soc_results (
            id TEXT PRIMARY KEY,
            rule_id TEXT,
            description TEXT,
            source_ip TEXT,
            answer TEXT,
            sources TEXT,
            verdict TEXT,
            escalation_level TEXT,
            status TEXT,
            created_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


def process_alert_background(alert_id: str, alert: AlertModel):
    """
    Runs AFTER the HTTP response has already been sent back to Wazuh.
    This is where the slow RAG retrieval + Ollama LLM call actually happens,
    so it no longer blocks the integration script's urllib timeout.
    """
    conn = sqlite3.connect(DB_PATH)
    try:
        alert_data = (
            f"Rule: {alert.rule_id} - {alert.description}. "
            f"Log: {alert.raw_log}. IP: {alert.source_ip}"
        )
        retrieval_query = f"{alert.description}. {alert.raw_log}"

        result = analyze_alert(alert_data, retrieval_query=retrieval_query)

        # Lay verdict/escalation THAT tu retriever.py
        ai_verdict = result.get("verdict_type", "Uncertain")
        ai_escalation = result.get("escalation", "L2")

        conn.execute(
            """UPDATE soc_results
               SET answer = ?, sources = ?, verdict = ?, escalation_level = ?, status = ?
               WHERE id = ?""",
            (
                result["answer"],
                json.dumps(result["sources"], ensure_ascii=False),
                ai_verdict,
                ai_escalation,
                "done",
                alert_id,
            ),
        )
    except Exception as e:
        conn.execute(
            "UPDATE soc_results SET status = ?, answer = ? WHERE id = ?",
            ("error", str(e), alert_id),
        )
    finally:
        conn.commit()
        conn.close()


@app.post("/analyze")
def analyze(alert: AlertModel, background_tasks: BackgroundTasks):
    alert_id = str(uuid.uuid4())

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO soc_results
           (id, rule_id, description, source_ip, answer, sources, verdict, escalation_level, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            alert_id,
            alert.rule_id,
            alert.description,
            alert.source_ip,
            None,
            None,
            None,
            None,
            "processing",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()

    # Response is returned to the Wazuh integration script BEFORE this runs
    background_tasks.add_task(process_alert_background, alert_id, alert)

    return {"status": "queued", "alert_id": alert_id, "rule_id": alert.rule_id}


@app.get("/result/{alert_id}")
def get_result(alert_id: str):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, rule_id, status, answer, sources, verdict, escalation_level FROM soc_results WHERE id = ?",
        (alert_id,),
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="alert_id not found")

    return {
        "id": row[0],
        "rule_id": row[1],
        "status": row[2],
        "answer": row[3],
        "sources": json.loads(row[4]) if row[4] else [],
        "verdict": row[5],
        "escalation_level": row[6],
    }