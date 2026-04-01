---
name: api-security-testing
description: 针对授权目标进行结构化的 REST/GraphQL API 安全评估。当用户提到安全测试、漏洞检测、渗透测试或需要生成安全报告时自动触发。
trigger:
  # 触发短语
  phrases:
    - "安全测试"
    - "安全审计"
    - "渗透测试"
    - "漏洞检测"
    - "安全评估"
    - "api 安全"
    - "接口安全"
    - "rest api 安全"
    - "graphql 安全"
    - "swagger 安全"
    - "openapi 安全"
    - "帮我检测漏洞"
    - "检查安全问题"
    - "api 漏洞"
    - "安全报告"
    - "安全发现"
    - "全流程测试"
    - "完整测试"
  # 触发模式（正则）
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|rest|graphql|安全|渗透)?(?:测试|审计|检测|扫描|评估)"
    - "(?:帮我)?(?:检查?|发现?|识别?)(?:api|接口|rest|graphql|安全)?(?:漏洞|风险|问题)"
    - "(?:生成|输出)(?:api|安全)?报告"
    - "(?:rest|graphql|api)(?:端点|接口)(?:测试|安全)"
    - "(?:openapi|swagger)(?:规范|文件)(?:分析|审计|检测)"
  # 自动触发
  auto_trigger: true
---

# API 安全测试

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

## 核心能力架构

```
SKILL.md (指导框架)
    ↓ 调用
core/ (执行能力)
    ├── orchestrator.py      # 智能编排器 - 协调所有测试
    ├── advanced_recon.py     # 高级侦察 - 资产发现
    ├── browser_tester.py     # 浏览器测试 - SPA/JS分析
    ├── deep_api_tester.py    # API 深度测试
    ├── api_fuzzer.py         # 模糊测试
    ├── reasoning_engine.py   # 推理引擎 - 洞察生成
    └── strategy_pool.py      # 策略池 - 测试策略
```

## 执行模式

### 模式 A: 快速测试 (默认)
```bash
cd /workspace/API-Security-Testing-Optimized
python -m core.orchestrator --target http://target.com --mode quick
```

### 模式 B: 完整测试
```bash
python -m core.orchestrator --target http://target.com --mode full
```

### 模式 C: 深度测试
```bash
python -m core.orchestrator --target http://target.com --mode deep
```

---

## 阶段执行流程

### 阶段 0: 初始化 (自动执行)

**触发**: Skill 激活后立即执行

**执行**:
```bash
# 使用高级侦察模块初始化
python -c "
from core.advanced_recon import AdvancedRecon
recon = AdvancedRecon()
result = recon.init_target('http://target.com')
print(result)
"
```

**决策点**:
| 发现特征 | 选择策略 |
|---------|---------|
| Vue/React/Angular SPA | → 启用 browser_tester.py |
| 静态 HTML | → 目录扫描 + 指纹识别 |
| 直接返回 JSON | → deep_api_tester.py |
| GraphQL | → GraphQL 专用探测 |

---

### 阶段 1: 资产发现

**触发**: 阶段 0 完成后自动触发

**执行**:
```bash
# 使用编排器执行侦察
python -c "
from core.orchestrator import AgenticOrchestrator

orch = AgenticOrchestrator()
orch.setup_target('http://target.com')

# 执行侦察阶段
result = orch.run_phase('recon')
print(result.endpoints)  # 发现的端点
print(result.tech_stack)  # 技术栈
print(result.api_base)  # API Base URL
"
```

**能力调用**:
- `core/advanced_recon.py` - 端口扫描、指纹识别、路径发现
- `core/browser_tester.py` - SPA JS 分析、API 路径提取
- `core/deep_api_tester.py` - OpenAPI/Swagger 解析

**迭代触发**:
- 发现 `/prod-api` baseURL → 深入端点枚举
- 发现 Swagger 文档 → 完整 API 解析
- 发现 SPA → 启用无头浏览器分析 JS

---

### 阶段 2: 认证与授权测试

**触发**: 发现 API 端点后自动触发

**执行**:
```bash
python -c "
from core.orchestrator import AgenticOrchestrator

orch = AgenticOrchestrator()
orch.setup_target('http://target.com')
orch.run_phase('recon')

# 执行认证测试
result = orch.run_phase('auth')

# 检查发现的漏洞
for vuln in result.vulnerabilities:
    print(f'{vuln.severity}: {vuln.name}')
    print(f'  Evidence: {vuln.evidence}')
"
```

**能力调用**:
- `core/deep_api_tester.py` - 登录接口测试
- `core/api_fuzzer.py` - 暴力破解检测
- 内置 CORS 检测

**决策点**:
| 发现 | 风险 | 行动 |
|------|------|------|
| CORS: Origin=* + Credentials | Critical | 立即记录 |
| 登录无验证码 | High | 暴力破解测试 |
| 敏感端点公开 | High | 记录配置问题 |

---

### 阶段 3: 漏洞验证

**触发**: 阶段 2 完成或发现新资产

**执行**:
```bash
python -c "
from core.orchestrator import AgenticOrchestrator

orch = AgenticOrchestrator()
orch.setup_target('http://target.com')
orch.run_phase('recon')
orch.run_phase('auth')

# 执行漏洞测试
result = orch.run_phase('vulns')

print('Findings:')
for finding in result.findings:
    print(f'  [{finding.severity}] {finding.title}')
    print(f'    Confidence: {finding.confidence}')
    print(f'    Remediation: {finding.remediation}')
"
```

**能力调用**:
- `core/api_fuzzer.py` - SQL注入、XSS、命令注入
- `core/deep_api_tester.py` - IDOR、越权测试
- `core/browser_tester.py` - DOM XSS、CSRF

---

### 阶段 4: 深度测试

**触发**: 基础测试完成，时间允许则继续

**执行**:
```bash
python -c "
from core.orchestrator import AgenticOrchestrator

orch = AgenticOrchestrator()
orch.setup_target('http://target.com')
orch.run_phase('full')  # 执行所有阶段

# 生成报告
report = orch.generate_report(format='markdown')
print(report)
"
```

---

### 阶段 5: 报告生成

**触发**: 测试完成或用户确认结束

**执行**:
```bash
python -c "
from core.orchestrator import AgenticOrchestrator

orch = AgenticOrchestrator()
orch.setup_target('http://target.com')
orch.run_phase('full')

# 生成结构化报告
print(orch.report)
" > security-report.md
```

---

## 核心模块详解

### core/orchestrator.py - 智能编排器

```python
from core.orchestrator import AgenticOrchestrator

# 初始化
orch = AgenticOrchestrator()

# 配置
orch.setup_target(
    url='http://target.com',
    auth_token='Bearer xxx',  # 可选
    headers={},  # 自定义头
    cookies={}  # 自定义 cookie
)

# 执行测试
orch.run_phase('recon')      # 侦察阶段
orch.run_phase('auth')      # 认证测试
orch.run_phase('vulns')     # 漏洞验证
orch.run_phase('full')      # 完整测试

# 获取结果
print(orch.report)          # 完整报告
print(orch.findings)        # 发现列表
print(orch.endpoints)        # 端点列表
```

### core/browser_tester.py - 浏览器测试

```python
from core.browser_tester import BrowserAutomationTester, BrowserEngine

# 初始化 (自动选择可用引擎)
tester = BrowserAutomationTester(
    target_url='http://target.com',
    engine=BrowserEngine.AUTO,  # 自动选择 Playwright/Puppeteer/Selenium
    headless=True
)

# 执行测试
result = tester.test_spa_api_discovery()

# 测试 XSS
xss_results = tester.test_dom_xss()

# 测试表单
form_results = tester.test_form_submission()
```

### core/deep_api_tester.py - API 深度测试

```python
from core.deep_api_tester import DeepAPITester

tester = DeepAPITester(
    base_url='http://target.com/prod-api',
    auth=None
)

# 测试认证绕过
auth_results = tester.test_auth_bypass()

# 测试 IDOR
idor_results = tester.test_idor()

# 测试业务逻辑
biz_results = tester.test_business_logic()
```

### core/api_fuzzer.py - 模糊测试

```python
from core.api_fuzzer import APIFuzzer

fuzzer = APIFuzzer(
    base_url='http://target.com/api',
    fuzz_params=True
)

# SQL注入模糊测试
sqli_results = fuzzer.fuzz_sqli()

# XSS 模糊测试
xss_results = fuzzer.fuzz_xss()

# 命令注入测试
cmd_results = fuzzer.fuzz_cmd_injection()
```

---

## 工具选择决策表

| 场景 | 首选工具 | 备选工具 |
|------|---------|---------|
| SPA + JS 分析 | browser_tester.py | 手动 curl + JS 下载 |
| OpenAPI/Swagger | deep_api_tester.py | swagger-parser |
| 认证测试 | deep_api_tester.py | curl 手动测试 |
| SQL注入 | api_fuzzer.py | sqlmap |
| XSS | api_fuzzer.py + browser_tester.py | burp |
| CORS | 内置检测 | curl |
| 暴力破解 | api_fuzzer.py | hydra |
| 端点发现 | advanced_recon.py | ffuf/dirb |

---

## 严重性校准

### 严重性级别

| 级别 | 触发条件 | 示例 |
|------|----------|------|
| Critical | 直接导致未授权访问或账户劫持 | CORS + credentials、SQL注入 |
| High | 可导致权限提升或用户数据访问 | IDOR、垂直越权、敏感端点泄露 |
| Medium | 可导致有限影响或信息泄露 | 信息枚举、暴力防护缺失 |
| Low | 影响有限的信息披露 | 调试头暴露、版本信息泄露 |
| Informational | 非安全问题 | 最佳实践建议 |

### 置信度级别

| 级别 | 标准 | 要求证据 |
|------|------|----------|
| Confirmed | 完全验证，有 PoC | 完整请求/响应 |
| High | 强指标 | 请求+响应+影响分析 |
| Medium | 中等指标 | 观察到的行为 |
| Low | 弱指标 | 单一响应 |
| Hypothesis | 理论推断 | 需要进一步调查 |

---

## 输出格式

### 必须包含的章节

```markdown
## Scope
- Target: [目标 URL]
- Assessment Mode: [文档驱动/被动/主动]
- Authorization: [授权范围]
- Tech Stack: [识别的技术栈]

## Asset Summary
- Base URLs: [发现的所有 base URL]
- API Type: [REST/GraphQL/SPA+API]
- Auth Schemes: [认证方式]
- Discovered Endpoints: [端点列表]
- Sensitive Objects: [敏感对象]

## Test Matrix
| Category | Test Item | Priority | Status | Finding |
|----------|----------|----------|--------|---------|

## Findings
### Finding N: [标题]
**Severity**: [Critical/High/Medium/Low/Informational]
**Confidence**: [Confirmed/High/Medium/Low/Hypothesis]
**Affected Asset**: [endpoint]
**Description**: [问题描述]
**Evidence**: [请求/响应样本]
**Reproduction**: [复现步骤]
**Impact**: [影响评估]
**Remediation**: [修复建议]

## Coverage Gaps
| Gap | Impact | Recommendation |
|-----|--------|-----------------|

## Overall Risk Summary
| Risk Level | Count | Findings |
|------------|-------|----------|
| Critical | N | [列表] |
| High | N | [列表] |
```

---

## 快速开始

### 方式 1: 命令行 (推荐)
```bash
cd /workspace/API-Security-Testing-Optimized
python -m core.orchestrator --target http://58.216.179.90:8031/ --mode full
```

### 方式 2: Python 脚本
```python
from core.orchestrator import AgenticOrchestrator

orch = AgenticOrchestrator()
orch.setup_target('http://target.com')
orch.run_phase('full')
print(orch.report)
```

### 方式 3: Jupyter Notebook
```python
%run core/orchestrator.py
orch = AgenticOrchestrator()
orch.setup_target('http://target.com')
orch.run_phase('full')
```

---

## 参考文档

| 模块 | 参考文档 |
|------|---------|
| orchestrator | `core/orchestrator.py` (内嵌文档) |
| browser_tester | `core/browser_tester.py` (内嵌文档) |
| deep_api_tester | `core/deep_api_tester.py` (内嵌文档) |
| api_fuzzer | `core/api_fuzzer.py` (内嵌文档) |
| advanced_recon | `core/advanced_recon.py` (内嵌文档) |
