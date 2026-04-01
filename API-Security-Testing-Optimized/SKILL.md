---
name: api-security-testing
description: 针对授权目标进行结构化的 REST/GraphQL API 安全评估。当用户提到安全测试、漏洞检测、渗透测试或需要生成安全报告时自动触发。
trigger:
  phrases:
    - "安全测试"
    - "安全审计"
    - "渗透测试"
    - "漏洞检测"
    - "安全评估"
    - "api 安全"
    - "接口安全"
    - "帮我检测漏洞"
    - "检查安全问题"
    - "安全报告"
    - "全流程测试"
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全)?(?:漏洞|问题)"
    - "(?:生成|输出)(?:安全)?报告"
  auto_trigger: true
---

# API 安全测试 Skill

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

---

## 核心理念

| 理念 | 说明 |
|------|------|
| **框架指导** | SKILL.md 是决策框架，不是执行脚本 |
| **能力池** | core/ 是能力池，Agent 按需调用 |
| **动态组合** | 根据目标特征动态选择工具组合 |
| **实时定制** | 每一步都根据上一步结果调整策略 |

---

## 能力池 (core/)

Agent 根据情况从能力池中选择合适的模块：

| 模块 | 能力 | 何时使用 |
|------|------|---------|
| `advanced_recon.py` | 端口扫描、指纹识别、路径发现 | 初始探测阶段 |
| `browser_tester.py` | SPA 动态分析、JS 提取、DOM XSS | 发现 Vue/React 等 SPA |
| `deep_api_tester.py` | 认证测试、IDOR、业务逻辑 | 发现 API 端点后 |
| `api_fuzzer.py` | SQL注入、XSS、命令注入 | 漏洞验证阶段 |
| `reasoning_engine.py` | 洞察生成、模式识别 | 需要理解发现时 |
| `context_manager.py` | 上下文跟踪、状态管理 | 复杂测试场景 |

---

## 决策流程

### 阶段 0: 初始化 → 能力选择

**问题**: 目标是什么类型？

**探测动作**:
```bash
# 1. 检查目标响应特征
curl -s -I http://target/

# 2. 分析响应判断类型
# - HTML + Vue/React → SPA 类型
# - JSON 直接返回 → API 类型  
# - HTML 静态页面 → Web 类型
# - GraphQL 特征 → GraphQL 类型
```

**能力选择决策**:

```
发现响应类型?
    │
    ├── HTML + (Vue|React|Angular) 特征
    │       └── → browser_tester.py (分析 SPA + JS)
    │              → advanced_recon.py (补充侦察)
    │
    ├── JSON 直接响应
    │       └── → deep_api_tester.py (API 测试)
    │              → api_fuzzer.py (漏洞测试)
    │
    ├── GraphQL 特征
    │       └── → graphql-guidance (专用探测)
    │              → api_fuzzer.py (GraphQL 注入)
    │
    └── 未知/混合
            └── → 组合使用多个模块
```

---

### 阶段 1: 侦察 → 资产发现

**问题**: 发现了什么资产？有哪些攻击面？

**侦察策略** (根据阶段0选择的能力组合):

#### 策略 A: SPA 类型
```bash
# 组合: browser_tester + advanced_recon
python -c "
from core.browser_tester import BrowserAutomationTester
from core.advanced_recon import AdvancedRecon

# 1. 浏览器分析 SPA
browser = BrowserAutomationTester(target_url='http://target.com')
spa_result = browser.analyze_spa()

# 2. 从 JS 提取 API 路径
api_paths = spa_result.extract_api_paths()

# 3. 补充侦察
recon = AdvancedRecon()
recon_result = recon.scan(target='http://target.com', paths=api_paths)

print('Endpoints:', recon_result.endpoints)
print('Tech Stack:', recon_result.tech_stack)
"
```

#### 策略 B: API 类型
```bash
# 组合: deep_api_tester + api_fuzzer
python -c "
from core.deep_api_tester import DeepAPITester
from core.api_fuzzer import APIFuzzer

# 1. API 指纹识别
tester = DeepAPITester(base_url='http://target.com/api')
api_result = tester.fingerprint()

# 2. 端点发现
endpoints = tester.discover_endpoints()

# 3. 漏洞探测
fuzzer = APIFuzzer(base_url='http://target.com/api')
vulns = fuzzer.scan(endpoints=endpoints)
"
```

**迭代触发**:
- 发现新端点 → 返回继续侦察
- 发现新技术栈 → 调整测试策略
- 发现认证机制 → 进入阶段 2

---

### 阶段 2: 认证分析 → 风险识别

**问题**: 认证机制是否安全？有哪些绕过风险？

**分析策略** (根据发现的资产类型组合能力):

```bash
# 动态组合分析
python -c "
from core.deep_api_tester import DeepAPITester
from core.reasoning_engine import Reasoner

tester = DeepAPITester(base_url='http://target.com/api')
reasoner = Reasoner()

# 1. 测试认证端点
auth_result = tester.test_auth_endpoints()

# 2. 分析认证模式
auth_analysis = reasoner.analyze_auth_pattern(auth_result)

# 3. 识别风险
for risk in auth_analysis.risks:
    print(f'Risk: {risk.type}')
    print(f'  Evidence: {risk.evidence}')
    print(f'  Severity: {risk.severity}')
"
```

**关键检测项**:

| 检测项 | 风险等级 | 调用模块 |
|--------|---------|---------|
| CORS 配置错误 | Critical | reasoning_engine |
| 暴力攻击无防护 | High | api_fuzzer |
| 敏感端点公开 | High | deep_api_tester |
| Token 弱加密 | Medium | reasoning_engine |
| 会话管理缺陷 | Medium | deep_api_tester |

---

### 阶段 3: 漏洞验证 → 利用测试

**问题**: 发现的风险是否可利用？严重性如何？

**验证策略** (根据风险类型动态选择):

```bash
# 按风险类型选择验证方式
python -c "
from core.api_fuzzer import APIFuzzer
from core.browser_tester import BrowserAutomationTester

fuzzer = APIFuzzer(base_url='http://target.com/api')
browser = BrowserAutomationTester(target_url='http://target.com')

# 根据发现的风险选择验证模块
if risk.type == 'SQL_INJECTION':
    result = fuzzer.test_sqli(endpoint=risk.endpoint, param=risk.param)
elif risk.type == 'XSS':
    result = browser.test_dom_xss(endpoint=risk.endpoint)
elif risk.type == 'IDOR':
    result = tester.test_idor(endpoint=risk.endpoint)
elif risk.type == 'CORS':
    result = tester.test_cors_exploit(risk.configuration)
"
```

**迭代触发**:
- 验证成功 → 提升严重性，生成 PoC
- 验证失败 → 降级或标记为 Hypothesis
- 发现新漏洞 → 添加到发现列表，返回阶段 1

---

### 阶段 4: 洞察生成 → 模式识别

**问题**: 这些发现意味着什么？有什么深层模式？

```bash
# 使用推理引擎分析模式
python -c "
from core.reasoning_engine import Reasoner

reasoner = Reasoner()

# 1. 聚合所有发现
all_findings = [...端点, ...漏洞, ...配置问题]

# 2. 生成洞察
insights = reasoner.generate_insights(all_findings)

# 3. 识别攻击路径
attack_paths = reasoner.identify_attack_paths(insights)

# 4. 生成建议
recommendations = reasoner.prioritize_remediation(attack_paths)
"
```

---

### 阶段 5: 报告生成 → 结构化输出

**根据用户要求生成报告**:

```bash
python -c "
from core.context_manager import ContextManager

ctx = ContextManager()
ctx.load_findings([...])
ctx.load_asset_summary({...})

# 生成符合模板的报告
report = ctx.generate_report(
    format='markdown',
    template='references/report-template.md',
    severity_calibration='references/severity-model.md'
)
print(report)
"
```

---

## 动态决策树

```
开始测试
    │
    ▼
[阶段0: 初始化]
    │  curl -I http://target/
    ▼
发现目标类型?
    │
    ├── SPA (Vue/React) ─────────────────────────┐
    │       │                                    │
    │       ▼                                    │
    │   browser_tester.py                        │
    │       │                                    │
    │       ├── 发现 API baseURL? ──→ 记录       │
    │       │                                    │
    │       └── JS 分析 ──→ 更多端点? ──→ 阶段1  │
    │                                                │
    ├── 直接 JSON API ──────────────────────────────┤
    │       │                                        │
    │       ▼                                        │
    │   deep_api_tester.py                           │
    │       │                                        │
    │       ├── 端点枚举 ──→ 阶段2                  │
    │       └── 指纹识别 ──→ 阶段3                  │
    │                                                │
    └── 混合/未知 ──────────────────────────────────┤
            │                                        │
            ▼                                        │
        组合多个模块                                  │
            │                                        │
            ▼                                        │
    [阶段1: 侦察] ◄─────────────────────────────────┘
        │
        ├── 发现新端点? ──→ 继续侦察
        ├── 发现认证机制? ──→ 阶段2
        └── 端点穷尽? ──→ 阶段3
            │
            ▼
    [阶段2: 认证分析]
        │
        ├── 发现高风险? ──→ 立即记录
        ├── 需要验证? ──→ 阶段3
        └── 完成? ──→ 阶段4
            │
            ▼
    [阶段3: 漏洞验证]
        │
        ├── 验证成功? ──→ 提升严重性
        ├── 发现新风险? ──→ 添加到列表 ──→ 阶段1
        └── 完成? ──→ 阶段4
            │
            ▼
    [阶段4: 洞察生成]
        │
        ├── 识别攻击路径
        └── 优先级排序
            │
            ▼
    [阶段5: 报告]
```

---

## 能力调用示例

### 示例 1: Vue SPA 目标

```
目标: http://target.com (Vue.js SPA)
发现的特征: HTML 返回 Vue 特征, JS 中有 baseURL: '/api'

动态组合:
1. browser_tester.py → 分析 SPA, 提取 /api 路径
2. advanced_recon.py → 补充侦察 /api 端点
3. deep_api_tester.py → 测试认证接口
4. api_fuzzer.py → 验证发现的端点
5. reasoning_engine.py → 生成洞察
```

### 示例 2: 纯 API 目标

```
目标: http://api.target.com (直接返回 JSON)
发现的特征: 直接 JSON 响应, 无前端

动态组合:
1. deep_api_tester.py → 指纹识别 + 端点发现
2. api_fuzzer.py → 漏洞扫描
3. reasoning_engine.py → 模式分析
```

### 示例 3: GraphQL 目标

```
目标: http://target.com/graphql
发现的特征: GraphQL 特征

动态组合:
1. graphql-guidance → GraphQL 专用探测
2. api_fuzzer.py → GraphQL 注入测试
3. reasoning_engine.py → 嵌套遍历分析
```

---

## 严重性校准

### 严重性级别

| 级别 | 触发条件 |
|------|----------|
| Critical | 直接导致未授权访问或账户劫持 |
| High | 可导致权限提升或数据泄露 |
| Medium | 可导致有限影响或信息泄露 |
| Low | 影响有限的信息披露 |
| Informational | 非安全问题 |

### 置信度级别

| 级别 | 标准 |
|------|------|
| Confirmed | 完全验证，有完整 PoC |
| High | 强指标，可合理推断 |
| Medium | 中等指标 |
| Low | 弱指标，可能是误报 |
| Hypothesis | 理论推断，需进一步调查 |

---

## 报告结构

```
## Scope
- Target:
- Assessment Mode:
- Authorization:

## Asset Summary
- Base URLs:
- API Type:
- Tech Stack:
- Discovered Endpoints:

## Test Matrix
| Category | Test Item | Priority | Status | Finding |

## Findings
[按严重性排序]

## Coverage Gaps

## Overall Risk Summary
```

---

## 快速参考

```bash
# 查看可用能力
ls core/*.py

# 查看模块文档
python -c "from core.module_name import *; help(module_name)"

# 动态导入使用
python -c "
import importlib
module = importlib.import_module('core.browser_tester')
tester = module.BrowserAutomationTester(...)
"
```
