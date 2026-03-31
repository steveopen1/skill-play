#!/usr/bin/env python3
"""
Report Generator - 安全测试报告生成器

功能:
- 生成 Markdown 报告
- 生成 JSON 报告
- 生成 HTML 报告
- 按漏洞类型和严重程度分类
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ReportFormat(Enum):
    """报告格式"""
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"


class SeverityLevel(Enum):
    """严重程度级别"""
    CRITICAL = ("Critical", 1)
    HIGH = ("High", 2)
    MEDIUM = ("Medium", 3)
    LOW = ("Low", 4)
    INFO = ("Info", 5)

    def __init__(self, label: str, order: int):
        self.label = label
        self.order = order


@dataclass
class VulnerabilityFinding:
    """漏洞发现"""
    type: str
    severity: str
    endpoint: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0
    remediation: str = ""


@dataclass
class ScanMetadata:
    """扫描元数据"""
    target: str
    scan_start: datetime
    scan_end: datetime
    duration_seconds: float
    endpoints_tested: int
    total_requests: int
    tools_version: str = "3.0"


class ReportGenerator:
    """
    报告生成器

    生成格式:
    - Markdown: 人类可读的报告
    - JSON: 机器可读的报告
    - HTML: 可视化报告
    """

    def __init__(self, metadata: ScanMetadata):
        self.metadata = metadata
        self.findings: List[VulnerabilityFinding] = []

    def add_finding(self, finding: VulnerabilityFinding):
        """添加漏洞发现"""
        self.findings.append(finding)

    def add_findings(self, findings: List[Dict]):
        """批量添加漏洞发现"""
        for f in findings:
            self.findings.append(VulnerabilityFinding(
                type=f.get('type', 'unknown'),
                severity=f.get('severity', 'medium'),
                endpoint=f.get('endpoint', ''),
                parameter=f.get('parameter', ''),
                payload=f.get('payload', ''),
                evidence=f.get('evidence', ''),
                confidence=f.get('confidence', 0.0),
                remediation=f.get('remediation', '')
            ))

    def _sort_findings_by_severity(self) -> List[VulnerabilityFinding]:
        """按严重程度排序"""
        severity_order = {
            'critical': 1,
            'high': 2,
            'medium': 3,
            'low': 4,
            'info': 5
        }
        return sorted(
            self.findings,
            key=lambda x: severity_order.get(x.severity.lower(), 999)
        )

    def _group_by_severity(self) -> Dict[str, List[VulnerabilityFinding]]:
        """按严重程度分组"""
        grouped = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in grouped:
                grouped[severity].append(finding)
        return grouped

    def _group_by_type(self) -> Dict[str, List[VulnerabilityFinding]]:
        """按类型分组"""
        grouped = {}
        for finding in self.findings:
            if finding.type not in grouped:
                grouped[finding.type] = []
            grouped[finding.type].append(finding)
        return grouped

    def generate_markdown(self) -> str:
        """生成 Markdown 报告"""
        sorted_findings = self._sort_findings_by_severity()
        by_severity = self._group_by_severity()
        by_type = self._group_by_type()

        report = f"""# API 安全渗透测试报告

## 执行摘要

| 项目 | 值 |
|------|-----|
| **目标** | {self.metadata.target} |
| **扫描开始** | {self.metadata.scan_start.strftime('%Y-%m-%d %H:%M:%S')} |
| **扫描结束** | {self.metadata.scan_end.strftime('%Y-%m-%d %H:%M:%S')} |
| **持续时间** | {self.metadata.duration_seconds:.2f} 秒 |
| **测试端点数** | {self.metadata.endpoints_tested} |
| **总请求数** | {self.metadata.total_requests} |
| **工具版本** | {self.metadata.tools_version} |

## 漏洞统计

"""

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            findings = by_severity.get(severity, [])
            if findings:
                emoji = {
                    'critical': '🔴',
                    'high': '🟠',
                    'medium': '🟡',
                    'low': '🔵',
                    'info': 'ℹ️'
                }.get(severity, '')
                report += f"- **{emoji} {severity.upper()}**: {len(findings)} 个\n"
            else:
                report += f"- **🔵 {severity.upper()}**: 0 个\n"

        report += f"\n## 漏洞详情\n\n"

        if not sorted_findings:
            report += "*未发现漏洞*\n\n"
        else:
            for i, finding in enumerate(sorted_findings, 1):
                report += f"""### {i}. [{finding.severity.upper()}] {finding.type}

- **端点**: `{finding.endpoint}`
- **参数**: `{finding.parameter}`
- **置信度**: {finding.confidence * 100:.0f}%

**Payload**:
```json
{finding.payload}
```

**证据**: {finding.evidence}

"""
                if finding.remediation:
                    report += f"**修复建议**: {finding.remediation}\n"
                report += "\n---\n\n"

        report += f"""## 技术分析

### 按类型分布

"""
        for vuln_type, findings in by_type.items():
            report += f"- **{vuln_type}**: {len(findings)} 个\n"

        report += f"""
### 修复建议

"""
        report += self._generate_remediation_section()

        report += f"""
---
*报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

        return report

    def _generate_remediation_section(self) -> str:
        """生成修复建议章节"""
        remediation = """
1. **通用修复建议**
   - 使用参数化查询防止 SQL 注入
   - 对用户输入进行严格的输入验证和过滤
   - 实现适当的访问控制机制
   - 启用速率限制防止暴力攻击
   - 使用 HTTPS 加密所有通信

2. **认证与授权**
   - 实现强密码策略
   - 使用 JWT 时选择安全的算法（RS256）
   - 实施会话超时机制
   - 定期轮换密钥和令牌

3. **错误处理**
   - 不要在响应中泄露敏感信息
   - 使用通用的错误消息
   - 记录详细日志但仅向客户端返回必要信息

4. **速率限制**
   - 实施请求速率限制
   - 使用验证码防止自动化攻击
   - 监控异常流量模式
"""
        return remediation

    def generate_json(self) -> Dict:
        """生成 JSON 报告"""
        return {
            'metadata': {
                'target': self.metadata.target,
                'scan_start': self.metadata.scan_start.isoformat(),
                'scan_end': self.metadata.scan_end.isoformat(),
                'duration_seconds': self.metadata.duration_seconds,
                'endpoints_tested': self.metadata.endpoints_tested,
                'total_requests': self.metadata.total_requests,
                'tools_version': self.metadata.tools_version
            },
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': {
                    severity: len(findings)
                    for severity, findings in self._group_by_severity().items()
                    if findings
                },
                'by_type': {
                    vuln_type: len(findings)
                    for vuln_type, findings in self._group_by_type().items()
                }
            },
            'findings': [
                {
                    'type': f.type,
                    'severity': f.severity,
                    'endpoint': f.endpoint,
                    'parameter': f.parameter,
                    'payload': f.payload,
                    'evidence': f.evidence,
                    'confidence': f.confidence,
                    'remediation': f.remediation
                }
                for f in self._sort_findings_by_severity()
            ]
        }

    def generate_html(self) -> str:
        """生成 HTML 报告"""
        json_data = self.generate_json()
        summary = json_data['summary']
        findings = json_data['findings']

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API 安全渗透测试报告 - {self.metadata.target}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .summary table {{ width: 100%; }}
        .summary td {{ padding: 8px; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #17a2b8; font-weight: bold; }}
        .finding {{ background: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 4px; color: white; font-size: 12px; }}
        .badge-critical {{ background: #dc3545; }}
        .badge-high {{ background: #fd7e14; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #17a2b8; }}
        .badge-info {{ background: #6c757d; }}
        pre {{ background: #f4f4f4; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 36px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; opacity: 0.9; }}
    </style>
</head>
<body>
    <h1>API 安全渗透测试报告</h1>

    <div class="summary">
        <h2>执行摘要</h2>
        <table>
            <tr><td><strong>目标</strong></td><td>{self.metadata.target}</td></tr>
            <tr><td><strong>扫描时间</strong></td><td>{self.metadata.scan_start.strftime('%Y-%m-%d %H:%M:%S')} - {self.metadata.scan_end.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><td><strong>持续时间</strong></td><td>{self.metadata.duration_seconds:.2f} 秒</td></tr>
            <tr><td><strong>测试端点</strong></td><td>{self.metadata.endpoints_tested}</td></tr>
        </table>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{summary['total_findings']}</div>
            <div class="stat-label">总发现数</div>
        </div>
        <div class="stat-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
            <div class="stat-number">{summary['by_severity'].get('critical', 0)}</div>
            <div class="stat-label">严重</div>
        </div>
        <div class="stat-card" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <div class="stat-number">{summary['by_severity'].get('high', 0)}</div>
            <div class="stat-label">高危</div>
        </div>
        <div class="stat-card" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
            <div class="stat-number">{summary['by_severity'].get('medium', 0)}</div>
            <div class="stat-label">中危</div>
        </div>
    </div>

    <h2>漏洞详情</h2>
"""

        for i, finding in enumerate(findings, 1):
            severity_class = f"badge-{finding['severity'].lower()}"
            html += f"""
    <div class="finding">
        <h3>{i}. {finding['type']} <span class="badge {severity_class}">{finding['severity'].upper()}</span></h3>
        <p><strong>端点:</strong> <code>{finding['endpoint']}</code></p>
        <p><strong>参数:</strong> <code>{finding['parameter']}</code></p>
        <p><strong>置信度:</strong> {finding['confidence'] * 100:.0f}%</p>
        <p><strong>证据:</strong> {finding['evidence']}</p>
        <p><strong>Payload:</strong></p>
        <pre>{finding['payload']}</pre>
    </div>
"""

        html += f"""
</body>
</html>
"""
        return html

    def save(self, filepath: str, format: ReportFormat = ReportFormat.MARKDOWN):
        """保存报告到文件"""
        if format == ReportFormat.MARKDOWN:
            content = self.generate_markdown()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        elif format == ReportFormat.JSON:
            content = json.dumps(self.generate_json(), indent=2, ensure_ascii=False)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        elif format == ReportFormat.HTML:
            content = self.generate_html()
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)


def create_report_generator(metadata: ScanMetadata) -> ReportGenerator:
    """创建报告生成器"""
    return ReportGenerator(metadata)


if __name__ == "__main__":
    from datetime import datetime, timedelta

    metadata = ScanMetadata(
        target="http://example.com",
        scan_start=datetime.now() - timedelta(minutes=30),
        scan_end=datetime.now(),
        duration_seconds=1800,
        endpoints_tested=50,
        total_requests=500
    )

    generator = create_report_generator(metadata)

    generator.add_finding(VulnerabilityFinding(
        type="SQL Injection",
        severity="critical",
        endpoint="/api/users",
        parameter="id",
        payload="' OR '1'='1",
        evidence="SQL syntax error in response",
        confidence=0.9,
        remediation="Use parameterized queries"
    ))

    generator.add_finding(VulnerabilityFinding(
        type="XSS",
        severity="high",
        endpoint="/api/search",
        parameter="q",
        payload="<script>alert(1)</script>",
        evidence="Payload reflected in response",
        confidence=0.85,
        remediation="Sanitize and encode user input"
    ))

    print(generator.generate_markdown())
