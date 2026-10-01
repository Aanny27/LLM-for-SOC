"""
incident_correlator.py

Gom các alert Wazuh thành "incident" trước khi đưa vào RAG/LLM.

- Khoá gom: IP nguồn (data.srcip / data.win.eventdata.ipAddress). Alert không
  có IP (Sysmon, tạo account...) rơi về khoá theo host: "host:<agent.name>".
- Alert cùng khoá trong CORRELATION_WINDOW_SECONDS -> cùng incident.
- Debounce: DEBOUNCE_SECONDS không có alert mới -> chốt incident, gọi LLM 1 lần.
- MAX_INCIDENT_DURATION_SECONDS: ép chốt để tấn công kéo dài không treo mãi.

Giới hạn cần ghi vào báo cáo:
- State nằm trong memory 1 process: chạy uvicorn nhiều worker sẽ không share
  state (hướng mở rộng: Redis).
- Gom theo IP có thể gộp 2 kiểu tấn công khác nhau từ cùng IP vào 1 incident;
  khoá theo host có thể gộp các sự kiện không liên quan trên cùng máy.
- Incident chỉ hiện trên dashboard sau khoảng debounce (mặc định 30s).
  Khi test/demo có thể đặt biến môi trường INCIDENT_DEBOUNCE_SECONDS=10.
"""

import asyncio
import os
from datetime import datetime, timedelta
from typing import Awaitable, Callable, Optional

CORRELATION_WINDOW_SECONDS = int(os.getenv("INCIDENT_WINDOW_SECONDS", "300"))
DEBOUNCE_SECONDS = int(os.getenv("INCIDENT_DEBOUNCE_SECONDS", "30"))
MAX_INCIDENT_DURATION_SECONDS = int(os.getenv("INCIDENT_MAX_SECONDS", "600"))
MAX_SAMPLE_ALERTS = 5

_IGNORED_IPS = {"", "-", "::1", "127.0.0.1", "0.0.0.0"}


def _now() -> datetime:
    # Giờ địa phương, cùng kiểu với cột timestamp của bảng analysis
    return datetime.now()


def _extract_ip(alert: dict) -> Optional[str]:
    data = alert.get("data") or {}
    ip = data.get("srcip") or ((data.get("win") or {}).get("eventdata") or {}).get("ipAddress")
    if ip and str(ip) not in _IGNORED_IPS:
        return str(ip)
    return None


def _extract_key(alert: dict) -> str:
    ip = _extract_ip(alert)
    if ip:
        return ip
    return "host:" + str((alert.get("agent") or {}).get("name", "unknown"))


def _alert_priority(alert: dict) -> tuple:
    """
    Điểm ưu tiên để chọn 'cảnh báo đại diện' (top_alert) của sự cố.
    So sánh theo tuple, phần tử đầu quan trọng nhất:
      1) rule.level  — càng cao càng ưu tiên
      2) có phải cảnh báo tấn công thật không (rule.groups chứa "attack"/"exploit"/...)
         — hòa level thì cảnh báo tấn công thật luôn thắng cảnh báo "có thể vô hại"
         như file integrity/syscheck.
      3) có mã MITRE hay không — cảnh báo có gắn kỹ thuật MITRE cụ thể thường
         đáng chú ý hơn cảnh báo chung chung.
    """
    rule = alert.get("rule") or {}
    level = rule.get("level", 0)
    groups = set(rule.get("groups") or [])
    is_real_attack = 1 if groups & {"attack", "exploit", "web", "sqli", "xss"} else 0
    has_mitre = 1 if (rule.get("mitre") or {}).get("id") else 0
    return (level, is_real_attack, has_mitre)


class Incident:
    def __init__(self, key: str, first_alert: dict):
        self.key = key
        self.alerts: list[dict] = [first_alert]
        self.first_seen = _now()
        self.last_seen = self.first_seen
        self.debounce_task: Optional[asyncio.Task] = None
        self.deadline: Optional[datetime] = None  # lúc sự cố sẽ được chốt

    def add_alert(self, alert: dict) -> None:
        self.alerts.append(alert)
        self.last_seen = _now()

    def is_expired_by_max_duration(self) -> bool:
        return (_now() - self.first_seen).total_seconds() >= MAX_INCIDENT_DURATION_SECONDS

    def to_context(self) -> dict:
        rules = [a.get("rule") or {} for a in self.alerts]
        top_alert = max(self.alerts, key=_alert_priority)
        return {
            "key": self.key,
            "source_ip": None if self.key.startswith("host:") else self.key,
            "alert_count": len(self.alerts),
            "rule_ids": sorted({str(r.get("id")) for r in rules if r.get("id")}),
            "rule_descriptions": sorted({r.get("description") for r in rules if r.get("description")}),
            "mitre_techniques": sorted({
                f"{tid} - {tname}"
                for r in rules
                for tid, tname in zip((r.get("mitre") or {}).get("id", []), (r.get("mitre") or {}).get("technique", []))
            }),
            "target_hosts": sorted({(a.get("agent") or {}).get("name") for a in self.alerts if (a.get("agent") or {}).get("name")}),
            "max_level": max((r.get("level", 0) for r in rules), default=0),
            "first_seen": self.first_seen.isoformat(timespec="seconds"),
            "last_seen": self.last_seen.isoformat(timespec="seconds"),
            "duration_seconds": (self.last_seen - self.first_seen).total_seconds(),
            "top_alert": top_alert,                       # alert đại diện (level cao nhất)
            "sample_alerts": self.alerts[-MAX_SAMPLE_ALERTS:],
        }


class IncidentCorrelator:
    def __init__(self, on_incident_ready: Callable[[dict], Awaitable[None]]):
        self._incidents: dict[str, Incident] = {}
        self._on_incident_ready = on_incident_ready

    async def ingest(self, alert: dict) -> None:
        key = _extract_key(alert)
        now = _now()
        incident = self._incidents.get(key)

        if incident and (now - incident.last_seen).total_seconds() <= CORRELATION_WINDOW_SECONDS:
            incident.add_alert(alert)
        else:
            incident = Incident(key, alert)
            self._incidents[key] = incident

        if incident.is_expired_by_max_duration():
            await self._finalize(key)
            return

        if incident.debounce_task and not incident.debounce_task.done():
            incident.debounce_task.cancel()
        incident.debounce_task = asyncio.create_task(self._debounce_and_finalize(key))
        incident.deadline = _now() + timedelta(seconds=DEBOUNCE_SECONDS)

    async def _debounce_and_finalize(self, key: str) -> None:
        try:
            await asyncio.sleep(DEBOUNCE_SECONDS)
        except asyncio.CancelledError:
            return
        await self._finalize(key)

    async def _finalize(self, key: str) -> None:
        incident = self._incidents.pop(key, None)
        if incident is None:
            return
        current = asyncio.current_task()
        if incident.debounce_task and incident.debounce_task is not current and not incident.debounce_task.done():
            incident.debounce_task.cancel()
        try:
            await self._on_incident_ready(incident.to_context())
        except Exception as e:
            print(f"[!] Lỗi callback incident {key}: {type(e).__name__}: {e}")

    def status(self) -> list:
        """Các sự cố đang chờ gom: dùng cho thanh trạng thái trên bảng điều khiển."""
        now = _now()
        return [
            {
                "key": i.key,
                "alert_count": len(i.alerts),
                "seconds_left": max(0, int((i.deadline - now).total_seconds())) if i.deadline else 0,
            }
            for i in self._incidents.values()
        ]