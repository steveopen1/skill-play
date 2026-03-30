# Payloader Skill - 渗透测试辅助平台 v2.0

## 概述

本 skill 提供**自动化接口渗透测试**能力，包含 payload 知识库、自动化测试引擎和智能决策系统。

## 快速开始

### 基础使用
```bash
# 1. 信息收集
skill security-testing discover --target https://target.com

# 2. 自动化测试
skill security-testing scan --target https://target.com --type api

# 3. 生成报告
skill security-testing report --output ./reports/
```

### 作为 Skill 调用
```python
# 在 OpenClaw 中调用
skill security-testing sqli --target https://target.com/api/user
skill security-testing xss --target https://target.com/search
skill security-testing auth --target https://target.com/login
```

## 核心能力

| 能力 | 说明 | 状态 |
|------|------|------|
| 自动化测试 | 一键执行完整渗透测试流程 | ✅ |
| 智能决策 | 根据响应自动调整测试策略 | ✅ |
| WAF 绕过 | 自动检测并绕过 WAF 防护 | ✅ |
| 上下文感知 | 记住测试状态和进度 | ✅ |
| 报告生成 | 自动生成详细测试报告 | ✅ |
| 并行测试 | 同时测试多个目标 | ✅ |

## 目录结构

```
security-testing/
├── SKILL.md                          # 本文件 - 入口与索引
├── core/                             # 核心引擎
│   ├── api_tester.py                # API 测试引擎
│   ├── payload_loader.py            # Payload 加载器
│   ├── response_analyzer.py         # 响应分析器
│   └── report_generator.py          # 报告生成器
├── payloads/                         # 结构化 payload 库
│   ├── sqli.json
│   ├── xss.json
│   ├── rce.json
│   ├── auth.json
│   └── business_logic.json
├── workflows/                        # 测试流程定义
│   ├── api_discovery.yaml
│   ├── auth_test.yaml
│   └── vulnerability_scan.yaml
├── data/                             # 原始数据（兼容旧版）
│   ├── web/                         # Web 应用攻防
│   └── intranet/                    # 内网渗透
└── reports/                          # 测试报告输出
```

## 自动化测试流程

### 阶段 1: 信息收集
```yaml
name: 信息收集
tasks:
  - scan_endpoints: 扫描 API 端点
  - identify_methods: 识别 HTTP 方法
  - detect_auth: 检测认证机制
  - fingerprint_tech: 识别技术栈
```

### 阶段 2: 认证测试
```yaml
name: 认证测试
tasks:
  - test_default_credentials: 测试默认密码
  - test_auth_bypass: 测试认证绕过
  - test_jwt_weakness: 测试 JWT 弱点
  - test_session_management: 测试会话管理
```

### 阶段 3: 漏洞测试
```yaml
name: 漏洞测试
tasks:
  - test_sqli: SQL 注入测试
  - test_xss: XSS 测试
  - test_command_injection: 命令注入
  - test_path_traversal: 路径遍历
  - test_idor: IDOR 测试
  - test_rate_limiting: 速率限制测试
```

### 阶段 4: 报告生成
```yaml
name: 报告生成
tasks:
  - generate_summary: 生成执行摘要
  - export_results: 导出结果
  - create_remediation: 生成修复建议
```

## Payload 库

### SQL 注入 Payload
```json
{
  "category": "SQL Injection",
  "payloads": [
    {
      "name": "OR 1=1",
      "payload": "' OR '1'='1",
      "type": "boolean_based",
      "detection_pattern": ["welcome", "admin", "success"],
      "waf_bypass": ["' OR 1=1--", "' OR 1=1#"]
    },
    {
      "name": "UNION SELECT",
      "payload": "' UNION SELECT NULL,NULL,NULL--",
      "type": "union_based",
      "columns_test": [1, 2, 3, 4, 5, 10, 20]
    }
  ]
}
```

### XSS Payload
```json
{
  "category": "XSS",
  "payloads": [
    {
      "name": "Basic Script",
      "payload": "<script>alert(1)</script>",
      "type": "reflected"
    },
    {
      "name": "Image OnError",
      "payload": "<img src=x onerror=alert(1)>",
      "type": "reflected",
      "waf_bypass": ["<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]
    }
  ]
}
```

## 智能决策系统

### WAF 检测与绕过
```python
def detect_waf(response):
    waf_signatures = {
        '360': '360waf',
        'aliyun': 'aliyuncs.com',
        'tencent': 'tencent-cloud.net'
    }
    for waf, signature in waf_signatures.items():
        if signature in response.text:
            return waf
    return None

def get_bypass_methods(waf_name):
    bypass_db = {
        '360': ['%20', '%09', '%0a', '/**/'],
        'aliyun': ['%2520', '%2509', 'unicode']
    }
    return bypass_db.get(waf_name, [])
```

### 响应分析
```python
def analyze_response(response, baseline):
    diff = {
        'status_code_changed': response.status_code != baseline['status_code'],
        'content_length_diff': abs(len(response.content) - baseline['content_length']),
        'content_changed': response.text != baseline['text']
    }
    
    if diff['content_length_diff'] > 100 or diff['status_code_changed']:
        return 'potential_vulnerability'
    return 'normal'
```

## 使用示例

### 示例 1: 单接口测试
```bash
skill security-testing sqli \
  --target https://target.com/api/user \
  --param id \
  --method GET
```

### 示例 2: 完整扫描
```bash
skill security-testing scan \
  --target https://target.com \
  --type full \
  --output ./reports/ \
  --threads 5
```

### 示例 3: 认证测试
```bash
skill security-testing auth \
  --target https://target.com/login \
  --username admin \
  --password-list ./passwords.txt
```

## 工具集成

### SQLMap 集成
```yaml
integration:
  name: sqlmap
  command: "sqlmap -u {url} --data={data} --batch --output-dir={output}"
  parser: sqlmap_output_parser
```

### Nuclei 集成
```yaml
integration:
  name: nuclei
  command: "nuclei -u {url} -t {templates} -o {output}"
  parser: nuclei_output_parser
```

## 报告格式

### Markdown 报告
```markdown
# 渗透测试报告

## 执行摘要
- 测试目标：https://target.com
- 测试时间：2026-03-30
- 测试接口数：50

## 漏洞统计
- 🔴 严重：2
- 🟠 高危：5
- 🟡 中危：10
- 🟢 低危：20

## 详细结果
...
```

### JSON 报告
```json
{
  "target": "https://target.com",
  "timestamp": "2026-03-30T12:00:00Z",
  "vulnerabilities": [
    {
      "type": "sqli",
      "severity": "critical",
      "endpoint": "/api/user",
      "payload": "' OR '1'='1",
      "evidence": "..."
    }
  ]
}
```

## 快速索引

### 按漏洞类型

| 漏洞类型 | Payload 文件 | 测试流程 | WAF 绕过 |
|----------|-------------|---------|---------|
| SQL 注入 | `payloads/sqli.json` | `workflows/sqli_test.yaml` | ✅ |
| XSS | `payloads/xss.json` | `workflows/xss_test.yaml` | ✅ |
| RCE | `payloads/rce.json` | `workflows/rce_test.yaml` | ✅ |
| 认证绕过 | `payloads/auth.json` | `workflows/auth_test.yaml` | ✅ |
| IDOR | `payloads/business_logic.json` | `workflows/idor_test.yaml` | ✅ |

### 按测试阶段

| 阶段 | 流程文件 | 说明 |
|------|---------|------|
| 信息收集 | `workflows/api_discovery.yaml` | 发现 API 端点 |
| 认证测试 | `workflows/auth_test.yaml` | 测试认证机制 |
| 漏洞扫描 | `workflows/vulnerability_scan.yaml` | 全面漏洞扫描 |
| 报告生成 | `workflows/report_gen.yaml` | 生成测试报告 |

## 配置示例

### 配置文件
```yaml
# config.yaml
target: https://target.com
threads: 5
timeout: 30
user_agent: "Mozilla/5.0 (compatible; SecurityTesting/2.0)"
rate_limit: 10  # 每秒请求数
waf_bypass: true
save_state: true
output:
  format: [markdown, json]
  directory: ./reports/
```

## 更新日志

### v2.0 (2026-03-30)
- ✅ 添加自动化测试引擎
- ✅ 添加智能决策系统
- ✅ 添加结构化 payload 库
- ✅ 添加 WAF 检测与绕过
- ✅ 添加报告生成器
- ✅ 添加并行测试支持
- ✅ 集成 SQLMap/Nuclei

### v1.0 (原始版本)
- 基础 payload 知识库
- 攻击链模板
- 内网渗透指南

---

*Skill 版本：v2.0*
*更新时间：2026-03-30*
*维护者：Security Team*
*GitHub: https://github.com/steveopen1/skill-play*
