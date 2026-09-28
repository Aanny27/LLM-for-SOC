"""
replay_eval.py — chạy lại phân tích AI trên CÙNG các sự cố đã được người gán nhãn,
ở cả hai chế độ (có RAG / không RAG), để so sánh công bằng.

Vì sao cần tập lệnh này: nếu tấn công hai lần (một lần bật RAG, một lần tắt) thì việc
gộp cảnh báo thành sự cố phụ thuộc thời gian nên hai tập sự cố không trùng nhau, và
phải gán nhãn hai lần. Ở đây mỗi sự cố chỉ cần gán nhãn MỘT lần (nút Dương tính thật /
Dương tính giả trên bảng điều khiển); tập lệnh đọc lại dữ liệu đã lưu rồi cho AI phân
tích lại ở từng chế độ, ghi kết quả vào bảng replay_runs (không đụng tới bảng
analysis nên bảng điều khiển không bị trùng thẻ).

Cách dùng (chạy trong thư mục chứa gateway.py, Ollama phải đang chạy):
    python replay_eval.py                     # cả 2 chế độ, 1 lần chạy
    python replay_eval.py --runs 3            # lặp 3 lần rồi lấy trung bình
    python replay_eval.py --modes no_rag      # chỉ chạy chế độ không RAG
    python replay_eval.py --temperature 0     # gần như tất định
    python replay_eval.py --limit 5           # thử nhanh với 5 sự cố

Chạy lại lệnh sau khi bị ngắt là an toàn: các (sự cố, chế độ, lần chạy) đã có sẽ được bỏ qua.
Xem kết quả: mở /api/v1/soc/eval-metrics (mục "chay_lai").
"""
import argparse
import asyncio
import json
import sqlite3
import time
from datetime import datetime

# Nạp gateway.py: việc này kết nối ChromaDB và tạo/nâng cấp bảng trong SQLite
# (gồm replay_runs) nhưng KHÔNG khởi động máy chủ.
import gateway
from gateway import DB_PATH, Rule, WazuhAlert, run_analysis


def load_labeled_incidents(limit=None):
    """Các sự cố đã được người gán nhãn và trước đó từng qua AI (ai_verdict khác NULL)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    sql = (
        "SELECT id, rule_id, rule_description, rule_level, agent_name, full_log, "
        "alert_count, incident_json FROM analysis "
        "WHERE verdict IN ('true_positive','false_positive') AND ai_verdict IS NOT NULL "
        "ORDER BY id"
    )
    if limit:
        sql += f" LIMIT {int(limit)}"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return rows


def rebuild_input(row):
    """Dựng lại (alert, incident, thiếu_ngữ_cảnh) từ một dòng đã lưu."""
    alert = WazuhAlert(
        rule=Rule(id=str(row["rule_id"] or "0"),
                  description=row["rule_description"] or "Unknown",
                  level=int(row["rule_level"] or 0)),
        agent={"name": row["agent_name"] or "unknown"},
        full_log=row["full_log"] or "",
    )
    incident, degraded = None, False
    if (row["alert_count"] or 1) > 1:
        if row["incident_json"]:
            try:
                incident = json.loads(row["incident_json"])
            except Exception:
                degraded = True
        else:
            # Dòng cũ lưu trước khi có cột incident_json: chỉ còn cảnh báo đại diện,
            # không dựng lại được các cảnh báo mẫu của cả cụm.
            degraded = True
    return alert, incident, degraded


def already_done(conn, source_id, mode, run_no):
    return conn.execute(
        "SELECT 1 FROM replay_runs WHERE source_id=? AND rag_mode=? AND run_no=?",
        (source_id, mode, run_no),
    ).fetchone() is not None


def save_run(conn, source_id, mode, run_no, parsed, ui_sources, degraded, temperature):
    conn.execute(
        """INSERT INTO replay_runs
           (source_id, rag_mode, run_no, ai_verdict, ai_verdict_reason, severity,
            mitre_technique, confidence, risk_score, analysis, recommended_actions,
            sources_used, input_degraded, temperature, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            source_id, mode, run_no,
            parsed.get("ai_verdict"), parsed.get("ai_verdict_reason"),
            parsed.get("severity"), parsed.get("mitre_technique"),
            parsed.get("confidence"), parsed.get("risk_score"),
            parsed.get("analysis_text", ""),
            json.dumps(parsed.get("recommended_actions", []), ensure_ascii=False),
            json.dumps(ui_sources, ensure_ascii=False),
            1 if degraded else 0, temperature,
            datetime.now().isoformat(timespec="seconds"),
        ),
    )
    conn.commit()


async def main():
    ap = argparse.ArgumentParser(description="Chạy lại phân tích AI trên các sự cố đã gán nhãn")
    ap.add_argument("--runs", type=int, default=1, help="số lần lặp cho mỗi chế độ (mặc định 1)")
    ap.add_argument("--modes", default="rag,no_rag", help="rag, no_rag hoặc rag,no_rag")
    ap.add_argument("--temperature", type=float, default=0.1,
                    help="nhiệt độ sinh văn bản (mặc định 0.1, giống hệ thống chạy thật)")
    ap.add_argument("--limit", type=int, default=None, help="chỉ chạy N sự cố đầu tiên (để thử)")
    args = ap.parse_args()

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    for m in modes:
        if m not in ("rag", "no_rag"):
            raise SystemExit(f"Chế độ không hợp lệ: {m!r} (chỉ nhận rag hoặc no_rag)")
    if "rag" in modes and gateway.retriever is None:
        raise SystemExit("Không kết nối được cơ sở dữ liệu Playbook nên không chạy được chế độ rag. "
                         "Kiểm tra lại ChromaDB hoặc chạy riêng --modes no_rag.")

    rows = load_labeled_incidents(args.limit)
    if not rows:
        raise SystemExit("Chưa có sự cố nào được gán nhãn (bấm Dương tính thật/giả trên bảng điều khiển) "
                         "hoặc các sự cố đó chưa có phán quyết của AI.")

    total_jobs = len(rows) * len(modes) * args.runs
    print(f"[*] {len(rows)} sự cố đã gán nhãn × {len(modes)} chế độ × {args.runs} lần = {total_jobs} lượt phân tích")
    if args.runs > 1 and args.temperature == 0:
        print("[!] Nhiệt độ 0 nên các lần chạy sẽ gần như giống hệt nhau, lặp nhiều lần ít có ý nghĩa.")

    conn = sqlite3.connect(DB_PATH)
    done = skipped = failed = degraded_count = 0
    t_start = time.time()

    for run_no in range(1, args.runs + 1):
        for row in rows:
            alert, incident, degraded = rebuild_input(row)
            for mode in modes:
                if already_done(conn, row["id"], mode, run_no):
                    skipped += 1
                    continue
                try:
                    parsed, ui_sources = await run_analysis(
                        alert, incident, use_rag=(mode == "rag"), temperature=args.temperature)
                except Exception as e:
                    failed += 1
                    print(f"[!] Sự cố #{row['id']} ({mode}, lần {run_no}) lỗi: {type(e).__name__}: {e}")
                    continue
                save_run(conn, row["id"], mode, run_no, parsed, ui_sources, degraded, args.temperature)
                done += 1
                degraded_count += 1 if degraded else 0
                n_done = done + skipped + failed
                print(f"[{n_done}/{total_jobs}] #{row['id']} {mode:6s} lần {run_no} -> "
                      f"{parsed.get('ai_verdict'):14s} (người gán: {_human(conn, row['id'])})"
                      + ("  [thiếu ngữ cảnh gộp]" if degraded else ""))

    conn.close()
    took = int(time.time() - t_start)
    print(f"\n[+] Xong sau {took} giây: chạy mới {done}, bỏ qua (đã có) {skipped}, lỗi {failed}.")
    if degraded_count:
        print(f"[!] {degraded_count} lượt dùng dữ liệu cũ chưa có ngữ cảnh gộp (chỉ có cảnh báo đại diện). "
              "Hai chế độ vẫn nhận cùng đầu vào nên so sánh vẫn công bằng, "
              "nhưng nên nêu điều này trong luận văn hoặc chạy lại kịch bản tấn công để có dữ liệu đầy đủ.")
    print("[>] Xem chỉ số: mở /api/v1/soc/eval-metrics (mục \"chay_lai\").")


def _human(conn, source_id):
    r = conn.execute("SELECT verdict FROM analysis WHERE id=?", (source_id,)).fetchone()
    return r[0] if r else "?"


if __name__ == "__main__":
    asyncio.run(main())
