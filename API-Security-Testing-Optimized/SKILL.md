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
    - "完整测试"
    - "云存储安全"
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全|云存储|oss)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全|oss|云存储|bucket)?(?:漏洞|问题)"
  auto_trigger: true
---

# API 安全测试 Skill

> **核心定位**：这是一个模块化的 API 安全测试框架，而非固定脚本。
>
> **必须使用无头浏览器**：
> - **禁止降级为 requests/curl**：现代 SPA 应用使用 JavaScript 动态加载 API，requests/curl 无法执行 JS，无法发现真实 API
> - **必须使用 Playwright**：无头浏览器可执行完整 JavaScript，获取实际调用的 API 端点和参数
>
> **核心理念**：
> - 各模块独立，可单独使用也可组合
> - 根据目标站点特点选择合适的模块组合
> - 脚本仅作流程参考和能力池，实际使用应灵活组合

---

## 执行决策流程

```
[阶段 0] 前置检查
    │
    ├─ playwright 可用? ─┬─ 否 → [跳过动态分析/API Hook]
    │                   │
    │                   └─ 是 → 继续
    │
    └─ requests 可用? ─┬─ 否 → [FATAL]
                       │
                       └─ 是 → [阶段 1]

[阶段 1] 资产发现
    │
    ├─ [1.1] 静态分析 (api_parser) - 始终执行
    │       └─ 发现端点 > 0?
    │           ├─ 是 → 继续
    │           └─ 否 → [扩大JS搜索范围]
    │
    ├─ [1.2] 父路径探测
    │       └─ JSON API > 0?
    │           ├─ 是 → [阶段 2] 漏洞分析
    │           └─ 否 → 检查 nginx fallback
    │                   ├─ 是 → 报告配置问题，跳过漏洞测试
    │                   └─ 否 → [阶段 2] 继续测试
    │
    ├─ [1.3] 动态分析 (dynamic_api_analyzer) - SPA必备
    │       └─ 补充发现更多端点
    │       └─ 注意: 较慢，耐心等待
    │
    └─ [1.4] API Hook (api_interceptor) - 需要登录时
            └─ 获取真实调用参数

[阶段 2] 漏洞分析
    │
    ├─ JSON API > 0? ─┬─ 否 → [SKIP] 避免误报
    │                  │
    │                  └─ 是 → 执行测试
    │
    ├─ [2.1] SQL 注入
    ├─ [2.2] XSS
    ├─ [2.3] 路径遍历
    ├─ [2.4] 敏感信息泄露
    └─ [2.5] 认证绕过

[阶段 3] 云存储测试
    │
    └─ 始终执行 (cloud_storage_tester)

[阶段 4] 报告生成
```

---

## 模块选择决策表

### 根据前置检查结果选择

| 检查项 | 可用 | 跳过模块 | 说明 |
|-------|------|---------|------|
| playwright | ❌ | 动态分析、API Hook | 使用静态解析作为主要发现方式 |
| playwright | ✅ | 无 | 可执行完整测试流程 |

### 根据父路径探测结果选择

| 探测结果 | JSON API | HTML Fallback | 后续行动 |
|---------|---------|---------------|---------|
| JSON API > 0 | ✅ | ❌ | 正常执行漏洞测试 |
| JSON API = 0 | ❌ | ✅ | 报告配置问题，跳过漏洞测试 |
| JSON API = 0 | ❌ | ❌ | 可能是内网API，执行测试 |

### 根据站点类型选择

| 站点类型 | 静态解析 | 动态分析 | API Hook | 说明 |
|---------|---------|---------|---------|------|
| **纯 HTML** | ✅ | ❌ | ❌ | 内容在服务端生成 |
| **jQuery 传统 SPA** | ✅ | ⚠️ | ❌ | JS 简单，可选动态 |
| **Vue/React 现代 SPA** | ✅ | ✅ | ⚠️ | 必须动态分析 |
| **需要登录系统** | ✅ | ✅ | ✅ | 需要获取认证后的API |

### 根据测试目标选择

| 测试目标 | 静态 | 动态 | Hook | Fuzzer | Cloud |
|---------|------|------|------|--------|-------|
| **快速侦察** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **全面发现** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **深度测试** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 核心模块详解

### 1. 端点发现模块

#### `core/api_parser.py` - 静态 API 解析

**能力**：JS 文件正则匹配、RESTful 路径推断、父路径生成

**耗时**：快 (5-10s)

**使用**：
```python
from core.api_parser import APIEndpointParser

parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
endpoints = parser.parse_js_files(js_files)
parent_paths = parser.probe_parent_paths()
```

#### `core/dynamic_api_analyzer.py` - 动态网络分析

**能力**：Playwright 浏览器捕获、触发交互、识别来源

**耗时**：较慢 (30s-几分钟)

**适用**：Vue/React SPA，API 动态加载

**注意**：必须使用无头浏览器，禁止降级

```python
from core.dynamic_api_analyzer import DynamicAPIAnalyzer

analyzer = DynamicAPIAnalyzer(target)
results = analyzer.analyze_full()
```

#### `core/api_interceptor.py` - API Hook

**能力**：JavaScript 拦截 fetch/XHR、获取真实参数、识别敏感操作

**耗时**：较慢 (30s-几分钟)

**适用**：需要登录的系统

```python
from core.api_interceptor import APIInterceptor

interceptor = APIInterceptor(target)
results = interceptor.hook_all_apis()
```

### 2. 漏洞测试模块

#### `core/api_fuzzer.py` - 模糊测试

```python
from core.api_fuzzer import APIFuzzer

fuzzer = APIFuzzer(target, session)
results = fuzzer.fuzz_endpoints(endpoints, parent_paths)
```

#### `core/cloud_storage_tester.py` - 云存储测试

**注意**：会自动识别 nginx fallback，避免误报

```python
from core.cloud_storage_tester import CloudStorageTester

tester = CloudStorageTester(target)
tester.session = session
findings, storage_url = tester.full_test(target)
```

---

## 智能判断规则

### 1. nginx fallback 判断

```
IF 所有父路径返回 HTML (Content-Type: text/html)
THEN 
    IF JSON API 数量 > 0
        继续测试
    ELSE
        报告 "nginx fallback 配置问题"
        跳过漏洞测试 (避免误报)
```

### 2. 误报避免规则

#### SQL 注入检测
```
IF 响应是 HTML (nginx fallback)
    SKIP (避免误报)

IF 响应是 JSON 但不包含 SQL 关键字
    SKIP (可能是正常业务逻辑)

IF 响应是 JSON 且包含 SQL 关键字
    报告可疑 (需要人工确认)
```

#### 云存储检测
```
IF Content-Type 不是 xml/application
    且响应包含 <!DOCTYPE
    THEN SKIP (是 HTML，不是 XML)

IF 响应大小 < 100 bytes
    THEN SKIP (太短，无意义)
```

---

## 组合使用示例

### 示例 1：快速侦察

```python
"""目标：快速了解资产，跳过耗时长模块"""
from core.api_parser import APIEndpointParser

parser = APIEndpointParser(target, session)
endpoints = parser.parse_js_files(parser.discover_js_files())
parent_paths = parser.probe_parent_paths()

# 立即获得端点清单，耗时短
```

### 示例 2：Vue SPA 全面测试

```python
"""目标：全面发现所有 API"""
from core.api_parser import APIEndpointParser
from core.dynamic_api_analyzer import DynamicAPIAnalyzer

# 1. 静态解析
parser = APIEndpointParser(target, session)
static_eps = parser.parse_js_files(parser.discover_js_files())

# 2. 动态分析 (较慢但必须)
analyzer = DynamicAPIAnalyzer(target)
dynamic_results = analyzer.analyze_full()

# 3. 合并结果
all_endpoints = static_eps + dynamic_results['endpoints']
```

### 示例 3：nginx fallback 检测

```python
"""目标：检测配置问题，避免误报"""
parent_paths = parser.probe_parent_paths()

json_api_count = sum(1 for p in parent_paths.values() if p.get('is_api'))
html_fallback_count = len(parent_paths) - json_api_count

if json_api_count == 0 and html_fallback_count > 0:
    report.add({
        'type': 'nginx fallback',
        'severity': 'HIGH',
        'suggestion': '后端 API 服务不可达'
    })
    # 跳过漏洞测试
else:
    run_vulnerability_tests()
```

---

## 模块能力池

| 模块 | 能力 | 耗时 | 依赖 | 必须 |
|-----|------|-----|------|------|
| `api_parser` | 静态解析 | 快 | requests | ✅ |
| `dynamic_api_analyzer` | 浏览器捕获 | 慢 | playwright | ⚠️ SPA必备 |
| `api_interceptor` | 参数拦截 | 慢 | playwright | ⚠️ 登录系统 |
| `api_fuzzer` | 模糊测试 | 中 | requests | ❌ |
| `cloud_storage_tester` | 云存储检测 | 快 | requests | ✅ |
| `browser_tester` | 浏览器自动化 | 中 | playwright | ⚠️ 登录系统 |

---

## 最佳实践

1. **渐进式测试**：先快速侦察，再根据发现决定深入测试
2. **智能跳过**：nginx fallback 时跳过漏洞测试，避免误报
3. **参数验证**：Hook 到的参数比猜测的参数更可靠
4. **认证处理**：需要登录的系统优先使用 browser_tester 或 api_interceptor
5. **耐心等待**：动态分析和 API Hook 较慢，等待完成

## 异常处理

| 异常 | 处理方式 |
|-----|---------|
| **Playwright 不可用** | 按以下顺序检测平替：<br>1. 检查其他无头浏览器 (pyppeteer、selenium)<br>2. 检查无头浏览器 MCP<br>3. 检查无头浏览器相关 Skill<br>4. 自动下载安装 Playwright 依赖<br>5. 直到 Playwright 可用 |
| 动态分析超时 | 继续使用已捕获结果 |
| API Hook 失败 | 使用静态端点 + 猜测参数 |
| 云存储检测误报 | 检查 Content-Type + 响应格式 |

---

## 前置检查与依赖修复流程

```
[前置检查] playwright 不可用?
    │
    ├─ 检测平替方案
    │   ├─ pyppeteer (异步无头浏览器)
    │   ├─ selenium (多浏览器支持)
    │   ├─ puppeteer (Node.js)
    │   ├─ headless_browser MCP
    │   └─ headless_browser skill
    │
    ├─ 尝试自动修复
    │   ├─ playwright install-deps
    │   ├─ playwright install chromium
    │   └─ pip install playwright
    │
    └─ 若仍不可用
        ├─ 记录警告
        └─ 建议手动安装
```

---

## 环境要求

### 必需依赖
- **requests**: HTTP 客户端
- **playwright**: 无头浏览器 (必须)

### 可选平替
- **pyppeteer**: pyppeteer (异步版本)
- **selenium**: 多浏览器自动化
- **MCP**: headless_browser MCP
- **Skill**: headless_browser skill
