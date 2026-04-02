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
    - "OSS 检测"
    - "bucket 检测"
    - "存储桶检测"
    - "S3 检测"
    - "阿里云安全"
    - "腾讯云安全"
    - "GraphQL 安全"
    - "websocket 安全"
    - "graphql 检测"
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全|云存储|oss)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全|oss|云存储|bucket)?(?:漏洞|问题)"
    - "(?:生成|输出)(?:安全|云存储)?报告"
    - "(?:scan|test)(?:oss|bucket|s3|cloud storage)"
  auto_trigger: true
---

# API 安全测试 Skill

> **核心定位**：这是一个 API 安全测试的模块化框架，而非固定脚本。
> 
> **重要说明**：
> - `core/runner.py` 是**调度参考实现**，展示如何组合使用模块
> - 实际测试应根据目标站点特点**选择性地组合模块**
> - 每个模块可独立使用，也可根据实际情况调整

---

## 测试流程框架

```
阶段 0: 前置检查
    ├── 检查 playwright 可用性
    └── 检查 requests 可用性

阶段 1: 资产发现 (端点发现)
    ├── 静态分析 - 从 JS 文件提取 API
    ├── 动态分析 - Playwright 捕获网络请求 (SPA)
    ├── API Hook - 获取真实调用参数
    └── 父路径探测 - 发现可访问路径

阶段 2: 漏洞分析
    ├── SQL 注入
    ├── XSS
    ├── 路径遍历
    ├── 敏感信息泄露
    ├── 认证绕过
    └── 业务逻辑漏洞

阶段 3: 云存储安全测试
    └── OSS/S3/MinIO 等云存储发现与检测

阶段 4: 报告生成
    └── Markdown 格式报告
```

---

## 核心模块能力

### 1. 端点发现模块

#### `core/api_parser.py` - 静态 API 解析

从 JS 文件中提取 API 端点：

```python
from core.api_parser import APIEndpointParser
import requests

target = "http://target.com"
session = requests.Session()

parser = APIEndpointParser(target, session)

# 发现 JS 文件
js_files = parser.discover_js_files()
print(f"发现 JS 文件: {len(js_files)}")

# 解析端点
endpoints = parser.parse_js_files(js_files)
for ep in endpoints:
    print(f"  {ep.method} {ep.path}")

# 探测父路径
parent_paths = parser.probe_parent_paths()
```

**支持的正则模式：**
- `axios.get/post/put/delete('/api/users')`
- `fetch('/api/users')`
- `/api/v1/users/{id}` - RESTful 路径
- `/users/:id` - 冒号参数
- `/auth-server/api/xxx` - 微服务模式

#### `core/dynamic_api_analyzer.py` - 动态网络分析

使用 Playwright 捕获真实网络请求：

```python
from core.dynamic_api_analyzer import DynamicAPIAnalyzer

analyzer = DynamicAPIAnalyzer(target)
results = analyzer.analyze_full()

print(f"端点: {results.get('unique_endpoints', 0)}")
print(f"请求: {results.get('total_requests', 0)}")
```

**适用场景：** SPA 应用，需要浏览器执行 JS 才能发现 API

#### `core/api_interceptor.py` - API Hook

注入 JavaScript 拦截真实的 API 调用：

```python
from core.api_interceptor import APIInterceptor

interceptor = APIInterceptor(target)
results = interceptor.hook_all_apis()

print(f"Hook API: {len(results.get('endpoints', []))}")
print(f"敏感操作: {len(results.get('sensitive', []))}")
```

**适用场景：** 需要获取 API 调用的真实参数和上下文

---

### 2. 漏洞测试模块

#### `core/api_fuzzer.py` - 模糊测试

```python
from core.api_fuzzer import APIFuzzer, ParsedEndpoint

fuzzer = APIFuzzer(target, session)
results = fuzzer.fuzz_endpoints(endpoints, parent_paths)

for r in results:
    print(f"  {r.vulnerability_type}: {r.endpoint}")
```

#### `core/cloud_storage_tester.py` - 云存储测试

```python
from core.cloud_storage_tester import CloudStorageTester

tester = CloudStorageTester(target, session)
findings = tester.run()
```

---

### 3. 浏览器测试模块

#### `core/browser_tester.py` - 浏览器自动化

```python
from core.browser_tester import BrowserAutomationTester

tester = BrowserAutomationTester(target)
results = tester.run_automated_tests()
```

---

## 模块选择指南

### 根据站点类型选择

| 站点类型 | 推荐模块组合 | 说明 |
|---------|-------------|------|
| 纯 HTML + JS | `api_parser` | 直接解析 JS 文件即可 |
| SPA (Vue/React) | `api_parser` + `dynamic_api_analyzer` | 静态+动态结合 |
| 需要登录 | `api_parser` + `api_interceptor` | 拦截登录后的真实请求 |
| 复杂交互 | 全部模块 | 静态+动态+Hook 组合 |

### 根据测试目标选择

| 测试目标 | 推荐模块 | 优先级 |
|---------|---------|-------|
| 快速侦察 | `api_parser` | 高 |
| 全面发现 | `api_parser` + `dynamic_api_analyzer` | 高 |
| 参数测试 | `api_interceptor` + `api_fuzzer` | 中 |
| 认证测试 | `browser_tester` | 中 |
| 云存储 | `cloud_storage_tester` | 中 |

---

## 实际使用示例

### 示例 1：简单站点（直接解析）

```python
from core.api_parser import APIEndpointParser
from core.runner import VulnerabilityTester, ReportGenerator
import requests

target = "http://target.com"
session = requests.Session()
session.headers.update({'User-Agent': 'Mozilla/5.0'})

# 1. 端点发现
parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
endpoints = parser.parse_js_files(js_files)

# 2. 漏洞测试
ctx = TestContext(target=target)
ctx.session = session
for ep in endpoints:
    ctx.add_endpoints([{'path': ep.path, 'method': ep.method}])

tester = VulnerabilityTester(ctx)
tester.run()

# 3. 生成报告
report = ReportGenerator.generate(vars(ctx))
print(report)
```

### 示例 2：SPA 应用（静态+动态）

```python
from core.api_parser import APIEndpointParser
from core.dynamic_api_analyzer import DynamicAPIAnalyzer
from core.runner import VulnerabilityTester, ReportGenerator
import requests

target = "http://spa-target.com"
session = requests.Session()

# 静态解析
parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
static_endpoints = parser.parse_js_files(js_files)

# 动态分析（如果 playwright 可用）
try:
    analyzer = DynamicAPIAnalyzer(target)
    dynamic_results = analyzer.analyze_full()
    # 合并动态发现的端点...
except:
    pass

# 漏洞测试和报告...
```

### 示例 3：需要登录的系统

```python
from core.api_interceptor import APIInterceptor
from core.browser_tester import BrowserAutomationTester

# 先用 Hook 获取登录后的真实 API
interceptor = APIInterceptor(target)
hook_results = interceptor.hook_all_apis()

# 获取敏感端点
sensitive_apis = hook_results.get('sensitive', [])

# 使用浏览器自动化测试登录流程
browser_tester = BrowserAutomationTester(target)
browser_tester.test_authentication_flow()
```

---

## core/runner.py 调度参考

`core/runner.py` 是本 Skill 的**参考实现**，展示如何组合使用各模块：

```bash
# 使用参考脚本（适用于标准场景）
cd /workspace/skill-play/API-Security-Testing-Optimized
python3 -m core.runner http://target.com

# 参数选项
python3 -m core.runner <target> [选项]
  --no-orchestrator   禁用编排器
  --no-fuzzing        禁用模糊测试
  --no-testing        禁用漏洞测试
```

**注意**：参考脚本可能不适合所有站点，实际使用时应根据目标特点选择模块。

---

## 目录结构

```
API-Security-Testing-Optimized/
├── SKILL.md                    # 本文件 - Skill 框架说明
├── core/
│   ├── runner.py               # 调度参考实现
│   ├── api_parser.py           # 静态 API 解析
│   ├── dynamic_api_analyzer.py # 动态网络分析
│   ├── api_interceptor.py      # API Hook
│   ├── api_fuzzer.py           # 模糊测试
│   ├── browser_tester.py        # 浏览器测试
│   ├── cloud_storage_tester.py # 云存储测试
│   ├── orchestrator.py         # 智能编排器
│   └── ...
```

---

## 最佳实践

1. **先侦察后测试**：先用轻量级模块（api_parser）了解目标，再决定使用哪些模块
2. **关注误报**：nginx fallback 等配置问题可能导致误报，注意识别
3. **渐进式测试**：从静态分析开始，逐步增加动态分析和 Hook
4. **结合实际**：根据站点的技术栈和架构选择合适的模块组合

---

## 注意事项

1. **授权测试**：仅对已授权的目标进行测试
2. **避免影响**：测试前确认不会对目标造成影响
3. **超时处理**：动态分析可能耗时较长，设置合理的超时
4. **Playwright 问题**：如遇 playwright 卡住，可禁用动态分析使用静态解析作为回退
