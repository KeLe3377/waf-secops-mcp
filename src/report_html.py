"""
汉化升级版 Chart.js 交互式安全态势 HTML 报告生成器（借鉴 aws-waf-mcp-server 可视化报告形态）。
"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .secops_tools import analyze_waf_summary, detect_attack_patterns


def generate_security_html_report(log_path: str | Path, output_html_path: str | Path) -> str:
    """生成带 Chart.js 交互式图表的中文 WAF 安全态势报告。"""
    summary = analyze_waf_summary(log_path, top_n=8)
    attacks = detect_attack_patterns(log_path, limit=25)

    hours = list(summary.get("hourly_traffic", {}).keys())
    hour_counts = list(summary.get("hourly_traffic", {}).values())
    cat_labels = list(attacks.get("category_summary", {}).keys()) or ["暂无告警"]
    cat_counts = list(attacks.get("category_summary", {}).values()) or [0]

    rows_html = ""
    for f in attacks.get("sample_findings", []):
        cats = ", ".join(html.escape(c) for c in f["categories"])
        rows_html += (
            f"<tr><td>{f['line']}</td><td>{html.escape(f['time'])}</td>"
            f"<td><code>{html.escape(f['ip'])}</code></td>"
            f"<td>{f['status']} ({html.escape(f['action'])})</td>"
            f"<td><span class='badge'>{cats}</span></td>"
            f"<td><code>{html.escape(f['sanitized_uri'])}</code></td></tr>"
        )

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>WAF 安全态势与运维分析报告</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Microsoft YaHei", sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }}
  .container {{ max-width: 1120px; margin: 0 auto; }}
  .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }}
  .card {{ background: #fff; padding: 16px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card .label {{ font-size: 13px; color: #64748b; }}
  .card .val {{ font-size: 26px; font-weight: 800; color: #1e3a8a; margin-top: 4px; }}
  .charts {{ display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-bottom: 20px; }}
  .panel {{ background: #fff; padding: 16px; border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ padding: 10px; border-bottom: 1px solid #e2e8f0; text-align: left; }}
  th {{ background: #f1f5f9; color: #334155; }}
  .badge {{ background: #fee2e2; color: #b91c1c; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ WAF 安全态势与日志取证报告</h1>
  <p style="color:#64748b">数据源：<code>{html.escape(str(log_path))}</code>（已开启防提示词注入清洗与敏感凭证脱敏）</p>
  <div class="cards">
    <div class="card"><div class="label">总请求数</div><div class="val">{summary.get("total_requests", 0)}</div></div>
    <div class="card"><div class="label">已拦截请求</div><div class="val" style="color:#dc2626">{summary.get("blocked_count", 0)}</div></div>
    <div class="card"><div class="label">拦截率</div><div class="val">{summary.get("block_rate_pct", 0)}%</div></div>
    <div class="card"><div class="label">高危特征命中</div><div class="val" style="color:#d97706">{attacks.get("matched_events_count", 0)}</div></div>
  </div>
  <div class="charts">
    <div class="panel"><h3>每小时请求趋势</h3><canvas id="trafficChart"></canvas></div>
    <div class="panel"><h3>攻击类型分布</h3><canvas id="attackChart"></canvas></div>
  </div>
  <div class="panel">
    <h3>高危告警与脱敏证据明细</h3>
    <table>
      <thead><tr><th>行号</th><th>时间</th><th>来源 IP</th><th>状态</th><th>告警类型</th><th>脱敏后 URI</th></tr></thead>
      <tbody>{rows_html or "<tr><td colspan='6'>暂无高危告警样本</td></tr>"}</tbody>
    </table>
  </div>
</div>
<script>
  new Chart(document.getElementById('trafficChart'), {{
    type: 'bar',
    data: {{ labels: {json.dumps(hours, ensure_ascii=False)}, datasets: [{{ label: '请求数', data: {json.dumps(hour_counts)}, backgroundColor: '#2563eb' }}] }}
  }});
  new Chart(document.getElementById('attackChart'), {{
    type: 'doughnut',
    data: {{ labels: {json.dumps(cat_labels, ensure_ascii=False)}, datasets: [{{ data: {json.dumps(cat_counts)}, backgroundColor: ['#dc2626','#ea580c','#d97706','#2563eb','#7c3aed','#0d9488'] }}] }}
  }});
</script>
</body>
</html>"""

    out = Path(output_html_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    return str(out)
