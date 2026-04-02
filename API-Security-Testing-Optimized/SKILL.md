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
> - **必须使用无头浏览器**：Playwright 等无头浏览器可以执行完整 JavaScript，获取实际调用的 API 端点和参数
> - **真实环境模拟**：无头浏览器更接近真实用户行为，能发现动态加载的 API
>
> **核心理念**：
> - 各模块独立，可单独使用也可组合
> - 根据目标站点特点选择合适的模块组合
> - 脚本仅作流程参考和能力池，实际使用应灵活组合

---

## 测试流程框架

```
阶段 0: 前置检查
    └── 检查环境依赖 (playwright 必须, requests 必须)

阶段 1: 资产发现
    ├── 静态分析 - JS 文件解析 (core.api_parser)
    ├── 动态分析 - Playwright 网络捕获 (core.dynamic_api_analyzer) [必须]
    ├── API Hook - Playwright 获取真实调用参数 (core.api_interceptor)
    └── 父路径探测 - 发现可访问路径

阶段 2: 漏洞分析
    ├── SQL 注入
    ├── XSS
    ├── 路径遍历
    ├── 敏感信息泄露
    ├── 认证绕过
    └── 业务逻辑漏洞

阶段 3: 云存储安全测试 (core.cloud_storage_tester)

阶段 4: 报告生成
```

**重要**：阶段 1 必须使用 Playwright 无头浏览器，禁止使用 requests/curl 降级替代。

---

## 模块选择策略

### 根据站点类型选择

| 站点类型 | 特点 | 推荐模块组合 |
|---------|------|-------------|
| **纯 HTML + 后端渲染** | 页面内容在服务端生成 | `api_parser` (简单解析) |
| **jQuery/Bootstrap 传统 SPA** | JS 较简单，API 较明显 | `api_parser` + 父路径探测 |
| **Vue/React 现代 SPA** | 动态加载，API 隐藏 | `api_parser` + `dynamic_api_analyzer` + 父路径探测 |
| **需要登录的系统** | API 需要认证 | `api_parser` + `api_interceptor` + `browser_tester` |
| **复杂交互系统** | 多步骤流程 | 全部模块组合 |

### 根据测试目标选择

| 测试目标 | 推荐模块 | 说明 |
|---------|---------|------|
| **快速侦察** | `api_parser` | 5-10 秒完成端点发现 |
| **全面发现** | `api_parser` + `dynamic_api_analyzer` | 静态+动态结合，发现更多端点 |
| **参数推断** | `api_parser` + `api_interceptor` | 获取真实参数名和类型 |
| **认证测试** | `browser_tester` | 自动化登录和会话测试 |
| **云存储安全** | `cloud_storage_tester` | 检测 OSS/S3/MinIO |

### 根据网络环境选择

| 环境 | 建议 |
|-----|------|
| **目标网络较慢** | 减少动态分析的交互次数 |
| **目标网络稳定** | 完整执行所有模块 |
| **内网环境** | 可完整执行，性能更好 |

---

## 核心模块详解

### 1. 端点发现模块

#### `core/api_parser.py` - 静态 API 解析

**能力**：
- 从 JS 文件提取 API 端点
- 正则匹配 axios/fetch 调用
- RESTful 路径参数推断
- 父路径生成

**适用**：所有站点，尤其是纯 HTML 或传统 SPA

**使用**：
```python
from core.api_parser import APIEndpointParser

parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
endpoints = parser.parse_js_files(js_files)
parent_paths = parser.probe_parent_paths()
```

#### `core/dynamic_api_analyzer.py` - 动态网络分析

**能力**：
- Playwright 浏览器自动化
- 捕获所有网络请求
- 识别请求来源 (fetch/axios/xhr)
- 触发多种交互 (登录/搜索/导航/表单)

**适用**：Vue/React 等现代 SPA，API 动态加载

**注意**：需要较长时间执行 (30s-几分钟)

**使用**：
```python
from core.dynamic_api_analyzer import DynamicAPIAnalyzer

analyzer = DynamicAPIAnalyzer(target)
results = analyzer.analyze_full()
# results['endpoints'] - 发现的端点
# results['requests'] - 原始请求
```

#### `core/api_interceptor.py` - API Hook

**能力**：
- 注入 JavaScript 拦截 fetch/XHR
- 获取真实的 API 调用参数
- 识别敏感操作 (登录/支付/修改)
- 生成测试向量

**适用**：需要登录的系统，获取认证后的真实 API

**注意**：需要 Playwright，执行时间较长

**使用**：
```python
from core.api_interceptor import APIInterceptor

interceptor = APIInterceptor(target)
results = interceptor.hook_all_apis()
# results['sensitive'] - 敏感操作
# results['test_vectors'] - 测试向量
```

### 2. 漏洞测试模块

#### `core/api_fuzzer.py` - 模糊测试

```python
from core.api_fuzzer import APIFuzzer

fuzzer = APIFuzzer(target, session)
results = fuzzer.fuzz_endpoints(endpoints, parent_paths)
```

#### `core/cloud_storage_tester.py` - 云存储测试

```python
from core.cloud_storage_tester import CloudStorageTester

tester = CloudStorageTester(target)
tester.session = session
findings = tester.run()
```

### 3. 浏览器测试模块

#### `core/browser_tester.py` - 自动化浏览器测试

**能力**：
- 自动化登录流程
- 会话保持测试
- UI 交互测试

**适用**：需要认证的系统

---

## 组合使用示例

### 示例 1：快速侦察（传统站点）

```python
"""
目标：传统站点，页面在服务端生成
策略：只做静态分析，快速完成
"""

import requests
from core.api_parser import APIEndpointParser

session = requests.Session()
parser = APIEndpointParser(target, session)

js_files = parser.discover_js_files()
endpoints = parser.parse_js_files(js_files)

print(f"发现 {len(endpoints)} 个端点")
for ep in endpoints:
    print(f"  {ep.method} {ep.path}")
```

### 示例 2：Vue SPA 全面发现

```python
"""
目标：Vue.js SPA
策略：静态 + 动态组合，发现所有端点
"""

import requests
from core.api_parser import APIEndpointParser
from core.dynamic_api_analyzer import DynamicAPIAnalyzer

session = requests.Session()

# 1. 静态解析
parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
static_endpoints = parser.parse_js_files(js_files)

# 2. 动态分析 (较慢，需要等待)
analyzer = DynamicAPIAnalyzer(target)
dynamic_results = analyzer.analyze_full()

# 3. 合并结果
all_endpoints = static_endpoints + dynamic_results['endpoints']

print(f"静态: {len(static_endpoints)} 端点")
print(f"动态: {len(dynamic_results['endpoints'])} 端点")
print(f"总计: {len(all_endpoints)} 端点")
```

### 示例 3：需要登录的系统

```python
"""
目标：需要登录的系统
策略：使用 API Hook 获取登录后的真实 API
"""

import requests
from core.api_interceptor import APIInterceptor
from core.browser_tester import BrowserAutomationTester

# 1. 使用浏览器自动化登录
browser = BrowserAutomationTester(target)
session = browser.login(username, password)

# 2. Hook 登录后的 API 调用
interceptor = APIInterceptor(target)
hook_results = interceptor.hook_all_apis()

print(f"发现 {len(hook_results['sensitive'])} 个敏感操作")
```

### 示例 4：完整测试流程

```python
"""
完整测试流程：适用于需要全面测试的场景
"""

import requests
from core.api_parser import APIEndpointParser
from core.dynamic_api_analyzer import DynamicAPIAnalyzer
from core.api_fuzzer import APIFuzzer
from core.cloud_storage_tester import CloudStorageTester

session = requests.Session()

# 1. 资产发现
parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
endpoints = parser.parse_js_files(js_files)

analyzer = DynamicAPIAnalyzer(target)
dynamic_results = analyzer.analyze_full()

# 2. 合并端点
all_endpoints = endpoints + dynamic_results['endpoints']

# 3. 漏洞测试
fuzzer = APIFuzzer(target, session)
vulnerabilities = fuzzer.fuzz_endpoints(all_endpoints, parent_paths)

# 4. 云存储测试
cloud = CloudStorageTester(target)
cloud.session = session
cloud_findings = cloud.run()

# 5. 生成报告
generate_report(all_endpoints, vulnerabilities, cloud_findings)
```

---

## 模块能力池

| 模块 | 能力 | 耗时 | 依赖 |
|-----|------|-----|------|
| `api_parser` | 静态解析 JS | 快 (5-10s) | requests |
| `dynamic_api_analyzer` | 浏览器捕获 | 慢 (30s-几分钟) | playwright |
| `api_interceptor` | 参数拦截 | 慢 (30s-几分钟) | playwright |
| `api_fuzzer` | 模糊测试 | 中 (取决于端点数) | requests |
| `cloud_storage_tester` | 云存储检测 | 快 (10-30s) | requests |
| `browser_tester` | 浏览器自动化 | 中 (取决于交互) | playwright |

---

## 最佳实践

1. **渐进式测试**：先快速侦察，再根据发现决定深入测试
2. **智能跳过**：如果静态分析已发现足够端点，可跳过动态分析
3. **误报识别**：注意识别 nginx fallback 等配置问题导致的假阳性
4. **参数验证**：Hook 到的参数比猜测的参数更可靠
5. **认证处理**：需要登录的系统优先使用 browser_tester 或 api_interceptor

---

## 注意事项

1. **授权测试**：仅对已授权的目标进行测试
2. **性能差异**：动态分析和 API Hook 较慢，耐心等待
3. **环境依赖**：确保 playwright 和 requests 可用
4. **SPA 特性**：现代 SPA 需要动态分析才能发现所有端点
