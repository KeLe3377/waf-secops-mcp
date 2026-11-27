"""
统一 WAF 日志解析器：
支持本地 Nginx Access Log (.log/.gz) 与 雷池 SafeLine / 通用 JSON WAF 日志 (.json/.gz)。
"""

from __future__ import annotations

import gzip
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict


class WafEvent(TypedDict):
    line: int
    timestamp: str
    hour: str
    client_ip: str
    method: str
    uri: str
    status: int
    action: str  # ALLOW | BLOCK
    rule: str
    user_agent: str
    country: str


NGINX_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+\d+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)


def _open_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"日志文件不存在: {path}")
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return [ln.strip() for ln in f if ln.strip()]
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def _parse_nginx_hour(raw_time: str) -> str:
    # 示例: 27/Nov/2026:10:01:05 +0800 -> 2026-11-27 10:00
    try:
        dt = datetime.strptime(raw_time.split()[0], "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:00")
    except ValueError:
        return "unknown"


def _normalize_json_event(line_no: int, obj: dict[str, Any]) -> WafEvent:
    # 兼容 SafeLine / 通用 JSON WAF 日志与 AWS WAF JSON 字段
    http_req = obj.get("httpRequest") or {}
    ts_raw = obj.get("timestamp")
    if isinstance(ts_raw, (int, float)):
        sec = ts_raw / 1000 if ts_raw > 1e12 else ts_raw
        dt = datetime.fromtimestamp(sec)
        ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        hour_str = dt.strftime("%Y-%m-%d %H:00")
    else:
        ts_str = str(ts_raw or "")
        hour_str = ts_str[:13] + ":00" if len(ts_str) >= 13 else "unknown"

    action_raw = str(obj.get("action") or ("BLOCK" if int(obj.get("status", 200)) == 403 else "ALLOW")).upper()
    return {
        "line": line_no,
        "timestamp": ts_str,
        "hour": hour_str,
        "client_ip": str(obj.get("client_ip") or http_req.get("clientIp") or obj.get("src_ip") or "0.0.0.0"),
        "method": str(obj.get("method") or http_req.get("httpMethod") or "GET"),
        "uri": str(obj.get("uri") or http_req.get("uri") or "/"),
        "status": int(obj.get("status") or (403 if action_raw == "BLOCK" else 200)),
        "action": "BLOCK" if action_raw in ("BLOCK", "DENY", "DROP") else "ALLOW",
        "rule": str(obj.get("rule") or obj.get("terminatingRuleId") or obj.get("attack_type") or "-"),
        "user_agent": str(obj.get("user_agent") or "-"),
        "country": str(obj.get("country") or http_req.get("country") or "CN"),
    }


def load_waf_events(file_path: str | Path) -> list[WafEvent]:
    """加载并归一化 WAF / Nginx 日志事件列表。"""
    lines = _open_lines(Path(file_path))
    events: list[WafEvent] = []

    for idx, line in enumerate(lines, start=1):
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                events.append(_normalize_json_event(idx, obj))
                continue
            except json.JSONDecodeError:
                pass

        m = NGINX_RE.match(line)
        if m:
            status = int(m.group("status"))
            raw_time = m.group("time")
            events.append(
                {
                    "line": idx,
                    "timestamp": raw_time,
                    "hour": _parse_nginx_hour(raw_time),
                    "client_ip": m.group("ip"),
                    "method": m.group("method"),
                    "uri": m.group("uri"),
                    "status": status,
                    "action": "BLOCK" if status == 403 else "ALLOW",
                    "rule": "nginx-waf-403" if status == 403 else "-",
                    "user_agent": m.group("ua") or "-",
                    "country": "LOCAL",
                }
            )
    return events
