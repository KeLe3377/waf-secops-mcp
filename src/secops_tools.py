"""
SecOps 确定性工具集：WAF 日志统计、攻击特征检测、IP 溯源、Nginx 反向代理审计与 Docker 容器诊断。
所有统计计算均由 Python 确定性完成，返回内容经过防注入清洗与敏感信息脱敏。
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .log_parser import WafEvent, load_waf_events
from .sanitizer import detect_prompt_injection, sanitize_log_text

ATTACK_RULES: dict[str, re.Pattern[str]] = {
    "SQL注入(SQLi)": re.compile(r"(union\s+select|'\s*or\s+1=1|--\s*$|sleep\(|benchmark\()", re.IGNORECASE),
    "路径穿越(PathTraversal)": re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)", re.IGNORECASE),
    "敏感文件探测(.env/.git)": re.compile(r"(/\.env|/\.git|/wp-config\.php|/actuator)", re.IGNORECASE),
    "跨站脚本(XSS)": re.compile(r"(<script|onerror=|alert\(|javascript:)", re.IGNORECASE),
    "Webshell探测": re.compile(r"(cmd=|eval\(|shell\.php|antsword|behinder)", re.IGNORECASE),
}


def analyze_waf_summary(file_path: str | Path, top_n: int = 5) -> dict[str, Any]:
    """确定性汇总 WAF 流量、拦截率、状态码分布、Top 异常 IP 与触发规则。"""
    events = load_waf_events(file_path)
    total = len(events)
    if total == 0:
        return {"total_requests": 0, "message": "未解析到有效日志记录"}

    actions = Counter(e["action"] for e in events)
    statuses = Counter(str(e["status"]) for e in events)
    blocked_ips = Counter(e["client_ip"] for e in events if e["action"] == "BLOCK")
    error_5xx_ips = Counter(e["client_ip"] for e in events if e["status"] >= 500)
    rules = Counter(e["rule"] for e in events if e["rule"] != "-")
    hourly = Counter(e["hour"] for e in events)

    blocked = actions.get("BLOCK", 0)
    return {
        "total_requests": total,
        "allowed_count": actions.get("ALLOW", 0),
        "blocked_count": blocked,
        "block_rate_pct": round((blocked / total) * 100, 2),
        "status_distribution": dict(statuses),
        "top_blocked_ips": [{"ip": ip, "count": cnt} for ip, cnt in blocked_ips.most_common(top_n)],
        "top_5xx_ips": [{"ip": ip, "count": cnt} for ip, cnt in error_5xx_ips.most_common(top_n)],
        "top_rules": [{"rule": r, "count": cnt} for r, cnt in rules.most_common(top_n)],
        "hourly_traffic": dict(sorted(hourly.items())),
    }


def detect_attack_patterns(file_path: str | Path, limit: int = 30) -> dict[str, Any]:
    """扫描已知攻击特征及藏在日志中的 Prompt Injection 载荷（结果已脱敏清洗）。"""
    events = load_waf_events(file_path)
    category_counts: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []

    for e in events:
        raw_payload = unquote(f"{e['uri']} {e['user_agent']}")
        matched_types = [name for name, pat in ATTACK_RULES.items() if pat.search(raw_payload)]
        if detect_prompt_injection(raw_payload):
            matched_types.append("日志Prompt注入(LogInjection)")

        if matched_types:
            for t in matched_types:
                category_counts[t] += 1
            if len(findings) < limit:
                findings.append(
                    {
                        "line": e["line"],
                        "time": e["timestamp"],
                        "ip": e["client_ip"],
                        "status": e["status"],
                        "action": e["action"],
                        "categories": matched_types,
                        "sanitized_uri": sanitize_log_text(e["uri"]),
                    }
                )

    return {
        "total_scanned": len(events),
        "matched_events_count": sum(category_counts.values()),
        "category_summary": dict(category_counts),
        "sample_findings": findings,
    }


def investigate_ip(file_path: str | Path, ip: str, limit: int = 20) -> dict[str, Any]:
    """按客户端 IP 溯源请求时间线，自动清洗注入与敏感凭证。"""
    events = load_waf_events(file_path)
    matched: list[WafEvent] = [e for e in events if e["client_ip"] == ip]
    timeline = [
        {
            "line": e["line"],
            "time": e["timestamp"],
            "method": e["method"],
            "status": e["status"],
            "action": e["action"],
            "rule": e["rule"],
            "sanitized_uri": sanitize_log_text(e["uri"]),
            "sanitized_ua": sanitize_log_text(e["user_agent"]),
        }
        for e in matched[:limit]
    ]
    return {
        "target_ip": ip,
        "total_requests": len(matched),
        "blocked_requests": sum(1 for e in matched if e["action"] == "BLOCK"),
        "timeline_sample": timeline,
    }


def audit_nginx_proxy(conf_path: str | Path) -> dict[str, Any]:
    """只读审计 Nginx 反向代理配置，检查源 IP 透传头与超时配置。"""
    text = Path(conf_path).read_text(encoding="utf-8")
    findings: list[dict[str, str]] = []
    has_proxy = "proxy_pass" in text

    if has_proxy:
        if "X-Real-IP" not in text and "X-Forwarded-For" not in text:
            findings.append(
                {
                    "severity": "HIGH",
                    "issue": "反向代理缺少 X-Real-IP / X-Forwarded-For 透传配置",
                    "impact": "后端安全设备与业务审计日志将全记录为 127.0.0.1，导致攻击溯源与按 IP 限流失效",
                    "fix_suggestion": "建议人工在 location 块补充: proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                }
            )
        if "proxy_read_timeout" not in text:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "issue": "未显式配置 proxy_read_timeout",
                    "impact": "SSE 长连接或慢查询可能在默认 60s 被中断，导致客户端收到 504 Gateway Timeout",
                    "fix_suggestion": "建议人工配置: proxy_read_timeout 180s;",
                }
            )

    return {
        "config_file": str(conf_path),
        "has_proxy_pass": has_proxy,
        "issue_count": len(findings),
        "findings": findings,
    }


def inspect_docker_snapshot(snapshot_path: str | Path) -> dict[str, Any]:
    """只读诊断容器运行快照，识别 OOM (Exit 137)、非正常退出与错误日志。"""
    data = json.loads(Path(snapshot_path).read_text(encoding="utf-8"))
    containers = data.get("containers", [])
    unhealthy: list[dict[str, Any]] = []

    for c in containers:
        exit_code = int(c.get("exit_code", 0))
        state = str(c.get("state", "unknown"))
        issues: list[str] = []

        if state != "running":
            issues.append(f"容器未处于运行态 (state={state}, exit_code={exit_code})")
        if exit_code == 137:
            issues.append("疑似 OOM Kill（Exit Code 137：内存超限被内核强杀）")
        elif exit_code != 0:
            issues.append(f"异常退出码: {exit_code}")

        err_logs = [
            sanitize_log_text(ln)
            for ln in c.get("recent_logs", [])
            if any(k in ln.upper() for k in ("ERROR", "FATAL", "TIMEOUT", "REFUSED"))
        ]
        if issues or err_logs:
            unhealthy.append(
                {
                    "name": c.get("name"),
                    "state": state,
                    "exit_code": exit_code,
                    "issues": issues,
                    "sanitized_error_logs": err_logs,
                    "suggested_action": f"建议人工检查容器日志与内存配额: docker logs --tail 200 {c.get('name')}",
                }
            )

    return {
        "total_containers": len(containers),
        "unhealthy_count": len(unhealthy),
        "unhealthy_containers": unhealthy,
    }
