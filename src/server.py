"""
waf-secops-mcp Server 入口（基于 FastMCP）。
面向 WAF / 安全运维 / 容器交付场景暴露 6 个只读 MCP 工具。
"""

from __future__ import annotations

import json
from fastmcp import FastMCP

from .report_html import generate_security_html_report
from .secops_tools import (
    analyze_waf_summary,
    audit_nginx_proxy,
    detect_attack_patterns,
    inspect_docker_snapshot,
    investigate_ip,
)

mcp = FastMCP("waf-secops-mcp")


@mcp.tool()
def analyze_waf_logs(file_path: str, top_n: int = 5) -> str:
    """确定性统计 WAF/Nginx 日志（支持 .log/.json/.gz）：流量总览、拦截率、状态码分布与 Top 异常 IP。"""
    return json.dumps(analyze_waf_summary(file_path, top_n=top_n), ensure_ascii=False, indent=2)


@mcp.tool()
def detect_attacks(file_path: str, limit: int = 30) -> str:
    """扫描 SQLi / XSS / 路径穿越 / .env 扫描 / Webshell 及日志 Prompt Injection，返回脱敏证据。"""
    return json.dumps(detect_attack_patterns(file_path, limit=limit), ensure_ascii=False, indent=2)


@mcp.tool()
def search_by_ip(file_path: str, ip: str, limit: int = 20) -> str:
    """按客户端 IP 溯源请求时间线（结果自动做注入清洗与凭证脱敏）。"""
    return json.dumps(investigate_ip(file_path, ip=ip, limit=limit), ensure_ascii=False, indent=2)


@mcp.tool()
def audit_nginx_proxy_config(conf_path: str) -> str:
    """只读审计 Nginx 反向代理配置：检查 X-Real-IP / X-Forwarded-For 源 IP 透传与超时配置。"""
    return json.dumps(audit_nginx_proxy(conf_path), ensure_ascii=False, indent=2)


@mcp.tool()
def inspect_docker_status(snapshot_path: str) -> str:
    """只读检查容器运行快照：识别 OOM (Exit 137)、非正常退出及日志错误。"""
    return json.dumps(inspect_docker_snapshot(snapshot_path), ensure_ascii=False, indent=2)


@mcp.tool()
def generate_html_report(log_path: str, output_html_path: str) -> str:
    """生成带 Chart.js 交互式图表的中文 WAF 安全态势 HTML 报告。"""
    out = generate_security_html_report(log_path, output_html_path)
    return json.dumps({"ok": True, "report_path": out}, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
