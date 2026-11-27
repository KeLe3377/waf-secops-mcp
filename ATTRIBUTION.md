# 开源致谢与二开说明 (Attribution)

本项目 `waf-secops-mcp` 基于以下开源项目的架构与安全工程设计进行了二次开发、本土化适配与安全增强：

1. **[VillaviH/aws-waf-mcp-server](https://github.com/VillaviH/aws-waf-mcp-server)**
   - 借鉴其基于 FastMCP 的 WAF 日志取证工具体系与 Chart.js 交互式 HTML 报告生成设计；
   - 本项目移除了 AWS S3/boto3 强绑定，重构为支持通用 **Nginx Access Log** 与 **长亭雷池 SafeLine WAF JSON 日志** 的本地只读 MCP 服务。

2. **[zorak1103/dlia](https://github.com/zorak1103/dlia)**
   - 借鉴其容器日志安全边界设计，在本项目中落地了 **防日志 Prompt Injection 清洗（Sanitizer）**、**敏感凭证自动脱敏（Anonymizer）** 以及 **容器 OOM (Exit 137) 只读诊断**。
