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

> **本文件是 Skill 的模块能力说明和流程框架文档**
> 
> 核心定位：
> 1. **模块能力说明**: 描述 core/ 目录下各模块的功能和使用方法
> 2. **流程框架**: 定义测试的执行阶段和决策逻辑
> 3. **执行入口**: `run_skill.py` 是自动化执行脚本，会调用 core 模块执行测试

---

## 快速执行 (推荐方式)

**强烈建议**: 使用 `core.runner` 模块执行完整测试流程。

```bash
cd /workspace/skill-play/API-Security-Testing-Optimized

# 方式 1: 命令行 (推荐)
python3 -m core.runner http://target.com

# 方式 2: 导入使用
python3 -c "from core.runner import run_skill; run_skill('http://target.com')"

# 方式 3: 在其他模块中调用
from core.runner import run_skill
result = run_skill('http://target.com')
```

**core.runner 功能:**
- 前置检查 - 自动检查/修复 playwright、requests
- 端点发现 - 整合 V35JSAnalyzer + Swagger + 智能猜测
- 编排执行 - 调用 orchestrator 执行完整流程
- 报告生成 - 输出 Markdown 格式报告

**命令行参数:**
```
python3 -m core.runner <target> [选项]
  --no-orchestrator   禁用编排器
  --no-fuzzing        禁用 fuzzing
  --no-testing        禁用漏洞测试
  --max-iterations N  最大迭代次数 (默认 50)
```

---

## 核心模块能力

| 模块 | 功能 | 关键能力 |
|------|------|---------|
| **core.runner** | SKILL.md 可执行入口 | 整合各模块，协调测试流程 |
| **core.api_parser** | 增强版 API 解析 | 正则+RESTful 参数推断，167+ 模式 |
| **core.dynamic_api_analyzer** | 动态 API 分析 | Playwright 网络请求捕获，交互触发 |
| **core.api_interceptor** | API Hook | 浏览器内 Hook fetch/XHR/axios，实时参数获取 |
| **core.V35JSAnalyzer** | V35 JS 分析 | 从 JS 文件提取 API 端点 |
| **core.browser_tester** | 浏览器测试 | DOM XSS、SPA 路由、表单交互 |
| **core.cloud_storage_tester** | 云存储测试 | OSS/COS/S3/MinIO 漏洞检测 |
| **core.fuzzer** | 模糊测试 | SQL注入、XSS、路径遍历 |

---

## 端点发现能力

### 1. 静态分析 (core.api_parser)

从 JS 文件中使用正则和 AST 模式匹配提取 API 端点：

```python
from core.api_parser import APIEndpointParser

parser = APIEndpointParser(target, session)
js_files = parser.discover_js_files()
endpoints = parser.parse_js_files(js_files)
```

**支持的正则模式:**
- `axios.get/post/put/delete('/api/users')` - axios 调用
- `fetch('/api/users')` - fetch 调用
- `/api/v1/users/{id}` - RESTful 路径
- `/users/:id` - 冒号参数

**参数提取:**
- 路径参数: `{id}`, `:id`
- RESTful 推断: `/users/123` → `id=123`
- 查询参数: `?page=1&limit=10`

### 2. 动态分析 (core.dynamic_api_analyzer)

使用 Playwright 访问页面并捕获网络请求：

```python
from core.dynamic_api_analyzer import DynamicAPIAnalyzer

analyzer = DynamicAPIAnalyzer(target)
results = analyzer.analyze_full()
# results['endpoints'] - 发现的所有端点
# results['requests'] - 原始请求列表
```

**捕获内容:**
- URL、方法、查询参数
- 请求来源 (fetch/axios/xhr)
- 触发操作 (登录/搜索/导航)

### 3. API Hook (core.api_interceptor)

在浏览器中注入 JavaScript Hook真实的 API 调用，获取**调用时的真实参数**：

```python
from core.api_interceptor import APIInterceptor

interceptor = APIInterceptor(target)
results = interceptor.hook_all_apis()
# results['sensitive'] - 敏感操作 (password, auth, etc.)
# results['testable'] - 可测试操作
# results['test_vectors'] - 安全测试向量
```

**Hook 内容:**
- fetch/XHR/axios 拦截
- 请求 URL、方法、参数
- 响应状态码
- 敏感操作识别

### 4. V35JSAnalyzer (legacy)

原始的 V35 版本 JS 分析器，作为回退方案：

```python
from core.deep_api_tester_v55 import V35JSAnalyzer

analyzer = V35JSAnalyzer(target, session)
result = analyzer.analyze_js(js_url)
# result['endpoints'] - 端点列表
# result['secrets'] - 敏感信息
```

---

## 测试流程

```
阶段 0: 前置检查
    └── 检查/修复 playwright, requests

阶段 1: 资产发现
    ├── 1.1 静态分析 (core.api_parser)
    │       └── 正则 + RESTful 参数推断
    ├── 1.2 动态分析 (core.dynamic_api_analyzer)
    │       └── Playwright 网络请求捕获
    ├── 1.3 API Hook (core.api_interceptor)
    │       └── 实时参数获取
    └── 1.4 父路径探测

阶段 2: 漏洞分析
    ├── 2.1 SQL 注入测试
    ├── 2.2 XSS 测试
    ├── 2.3 路径遍历测试
    ├── 2.4 敏感信息泄露
    ├── 2.5 认证绕过
    └── 2.6 GraphQL/IDOR/暴力破解

阶段 2.5: API Fuzzing
    └── 使用 fuzzing 引擎测试端点

阶段 3: 云存储安全测试
    └── OSS/COS/S3/MinIO 特征检测

阶段 4: 报告生成
    └── Markdown 格式报告
```

---

## 安全问题检测

### Backend API Unreachable / nginx fallback

**问题**: 所有 API 路径返回 HTML 而不是 JSON API

**可能原因**:
1. 后端 API 服务未运行 (端口不可达)
2. nginx 未正确配置 API 路径代理
3. API 服务部署在不同的服务器/端口

**影响**: 前端无法连接后端 API，系统功能不可用

**建议**:
1. 检查后端服务是否运行
2. 检查 nginx proxy_pass 配置
3. 检查防火墙/安全组规则

### 敏感操作识别

API Hook 自动识别以下敏感操作：

| 操作类型 | 关键词 | 安全风险 |
|---------|--------|---------|
| password_reset | reset, forgot, recovery | 任意密码重置 |
| auth_login | login, logout, token | 暴力破解 |
| user_operations | user, profile, account | 权限绕过 |
| admin_operations | admin, manage, system | 垂直权限 |
| payment | pay, order, transaction | 金融欺诈 |

---

## 快速执行

```bash
cd /workspace/skill-play/API-Security-Testing-Optimized

# 标准测试
python3 -m core.runner http://target.com

# 只做 API Hook
python3 -c "from core.api_interceptor import run_api_hook; run_api_hook('http://target.com')"

# 只做动态分析
python3 -c "from core.dynamic_api_analyzer import run_full_analysis; run_full_analysis('http://target.com')"
```

**问题**: 原 orchestrator 的端点发现能力较弱

**解决方案**: 整合 V35JSAnalyzer 的 JS 文件分析能力

```
orchestrator._stage_discovery() 执行流程:
    │
    ├── 1. reasoning engine 观察 (原有)
    │
    ├── 2. Swagger/API 文档发现 (原有)
    │
    ├── 3. V35JSAnalyzer JS 分析 (新增整合)
    │       └── 调用 V35JSAnalyzer.analyze_js()
    │           ├── axios 模式提取
    │           ├── fetch 模式提取
    │           ├── 通用路径提取
    │           └── API 路径提取
    │
    └── 4. SPA 智能路径猜测 (新增)
            └── 常见 API 路径探测
```

**V35JSAnalyzer 支持的模式**:
```python
patterns = [
    (r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'axios'),
    (r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', 'fetch'),
    (r'[\'"`](/[a-z]+/[^\'"`\s?#]*)[\'"`]', 'generic_path'),
    (r'[\'"`](/api/[^\'"`\s?#]+)[\'"`]', 'api_path'),
    (r'[\'"`](/users/[^\'"`\s?#]+)[\'"`]', 'users_path'),
    # ... 更多模式
]
```

---

## 强制执行声明

**本 Skill 必须完整执行，不允许跳过任何阶段。**

```
重要：
1. Agent 必须执行所有阶段，不得跳过
2. 前置检查是强制性的，必须完成
3. 发现的模块能力必须调用，除非明确不可用
4. 所有判断必须基于多维度分析，不得仅凭单一指标
```

---

## 阶段 0: 前置检查 (强制执行)

**触发**: Skill 激活后立即执行，不得跳过

### 0.1 环境检查

```bash
# 检查 Python 环境
python3 --version

# 检查 pip 是否可用
pip3 --version
```

### 0.2 依赖检查与安装 (强制性)

```bash
# 检查 requests
python3 -c "import requests; print('requests:', requests.__version__)"

# 如果未安装，执行安装
pip3 install requests

# 检查 playwright
python3 -c "import playwright; print('playwright: OK')"

# 如果未安装，执行安装
pip3 install playwright
playwright install chromium

# 检查 pyppeteer (browser_tester 需要)
python3 -c "import pyppeteer; print('pyppeteer: OK')"

# 如果未安装，执行安装  
pip3 install pyppeteer

# 检查 pytest
python3 -c "import pytest; print('pytest: OK')"

# 如果未安装
pip3 install pytest

# 检查所有 core 模块是否可导入
cd /workspace/API-Security-Testing-Optimized
python3 -c "
import sys
sys.path.insert(0, '.')
from core import browser_tester, deep_api_tester_v55, api_fuzzer, advanced_recon
print('All core modules: OK')
"
```

### 0.3 能力验证

```bash
# 验证 browser_tester 能力
python3 -c "
from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
config = BrowserTestConfig(target_url='http://example.com', engine=BrowserEngine.PUPPETEER)
tester = BrowserAutomationTester(config)
if tester.engine.value == 'none':
    print('[WARN] browser_tester: 浏览器引擎不可用')
    print('[FORCE] 尝试安装 playwright...')
    import subprocess
    subprocess.run(['pip3', 'install', 'playwright'], capture_output=True)
    subprocess.run(['playwright', 'install', 'chromium'], capture_output=True)
else:
    print('[OK] browser_tester: 引擎可用')
"

# 验证 deep_api_tester 能力
python3 -c "
from core.deep_api_tester_v55 import DeepAPITesterV55
tester = DeepAPITesterV55(target='http://example.com')
print('[OK] deep_api_tester_v55: 可用')
"

# 验证 api_fuzzer 能力
python3 -c "
import requests
from core.api_fuzzer import APIfuzzer
fuzzer = APIfuzzer(session=requests.Session())
print('[OK] api_fuzzer: 可用')
"
```

### 0.3.1 无头浏览器能力检测 (强制执行)

当需要使用无头浏览器时（如 SPA 测试、JS 分析、动态交互），必须先执行此检测流程。

**注意**: 本 skill 不预设任何特定的浏览器工具，而是检测整个系统中所有可用的无头浏览器替代方案。

```bash
#!/bin/bash
# ============================================================
# 无头浏览器能力检测脚本
# 检测系统中所有可用的无头浏览器替代方案
# ============================================================

echo "============================================================"
echo "[系统检测] 无头浏览器能力扫描"
echo "============================================================"

AVAILABLE_BROWSERS=""
BROWSER_CAPABILITY=""

# 阶段 1: 检测 Python 无头浏览器包
echo ""
echo "[阶段 1] 检测 Python 无头浏览器包..."
python3 -c "
import importlib
browsers = [
    ('playwright', 'from playwright.sync_api import sync_playwright'),
    ('selenium', 'from selenium import webdriver'),
    ('pyppeteer', 'from pyppeteer import launch'),
    ('requests_html', 'from requests_html import HTMLSession'),
    ('mechanicalsoup', 'from mechanicalsoup import StatefulBrowser'),
    ('splinter', 'from splinter import Browser'),
]
for name, import_stmt in browsers:
    try:
        exec(import_stmt)
        print(f'  [FOUND] {name}')
    except ImportError:
        pass
" 2>/dev/null

# 阶段 2: 检测 Node.js 无头浏览器
echo ""
echo "[阶段 2] 检测 Node.js 无头浏览器包..."
which node >/dev/null && npm list -g --depth=0 2>/dev/null | grep -iE "puppeteer|playwright|selenium|nightmare" || echo "  Node.js 或相关包未安装"

# 阶段 3: 检测系统浏览器可执行文件
echo ""
echo "[阶段 3] 检测系统浏览器..."
SYSTEM_BROWSERS=""
for cmd in chromium chromium-browser google-chrome google-chrome-stable firefox firefox-esr edge; do
    if which $cmd >/dev/null 2>&1; then
        echo "  [FOUND] 系统浏览器: $cmd ($(which $cmd))"
        SYSTEM_BROWSERS="$SYSTEM_BROWSERS $cmd"
    fi
done
[ -z "$SYSTEM_BROWSERS" ] && echo "  未发现系统浏览器"

# 阶段 4: 检测 MCP 工具 (浏览相关)
echo ""
echo "[阶段 4] 检测 MCP 工具..."
# 检查常见 MCP 服务中可能包含的浏览器工具
if [ -d "/root/.claude" ]; then
    echo "  [CHECK] Claude 配置目录存在"
    # 检查 skills 目录
    if [ -d "/root/.claude/skills" ]; then
        SKILL_BROWSER=$(find /root/.claude/skills -name "*.md" -exec grep -l -i "browser\|headless\|puppeteer\|playwright" {} \; 2>/dev/null | head -3)
        [ -n "$SKILL_BROWSER" ] && echo "  [FOUND] Skills 中可能包含浏览器能力:"
        [ -n "$SKILL_BROWSER" ] && echo "$SKILL_BROWSER" | sed 's/^/    /'
    fi
fi

# 检查 MCP 服务相关配置
if [ -d "/root/.config/mcp" ] || [ -d "$HOME/.config/mcp" ]; then
    MCP_CONFIG_DIR=$(find /root ~/.config -name "mcp*" -type d 2>/dev/null | head -5)
    [ -n "$MCP_CONFIG_DIR" ] && echo "  [CHECK] MCP 配置目录: $MCP_CONFIG_DIR"
fi

# 检查是否有 MCP 服务器运行
if command -v mcp >/dev/null 2>&1; then
    echo "  [FOUND] mcp 命令行工具"
    mcp list 2>/dev/null || mcp tools 2>/dev/null | grep -i browser || echo "    无法列出 MCP 工具"
elif [ -f "/usr/local/bin/mcp" ]; then
    echo "  [FOUND] mcp 工具: /usr/local/bin/mcp"
fi

# 阶段 5: 检测 Agent 特有的浏览器能力
echo ""
echo "[阶段 5] 检测 Agent 浏览器工具..."
# 检查 Claude Code 相关
if env | grep -qi "CLAUDE\|ANTHROPIC"; then
    echo "  [CHECK] Claude 环境变量存在"
fi

# 检查可能的 Agent Socket/端口 (某些 agent 可能暴露浏览器服务)
for port in 9222 9223 9224 9225; do
    if timeout 1 bash -c "echo >/dev/tcp/localhost/$port" 2>/dev/null; then
        echo "  [FOUND] 本地端口 $port 开放 (可能是浏览器调试端口)"
    fi
done

# 检查 Docker 容器中的浏览器
if command -v docker >/dev/null 2>&1; then
    DOCKER_BROWSER=$(docker ps --format "{{.Names}}" 2>/dev/null | grep -iE "browser|chrome|firefox|puppeteer" | head -3)
    [ -n "$DOCKER_BROWSER" ] && echo "  [FOUND] Docker 容器: $DOCKER_BROWSER"
fi

# 阶段 6: 验证并尝试修复 playwright 浏览器
echo ""
echo "[阶段 6] 验证并修复 playwright 浏览器..."

BROWSER_FIXED=false

python3 -c "
import subprocess
import sys

test_code = '''
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    browser.close()
'''

result = subprocess.run(
    [sys.executable, '-c', test_code],
    capture_output=True,
    text=True,
    timeout=30
)

if result.returncode == 0:
    print('  [OK] playwright chromium: 可用')
    print('  [MODE] headless=True')
    sys.exit(0)
else:
    error_msg = result.stderr.strip() if result.stderr else 'Unknown error'
    if 'Executable' in error_msg and 'does not exist' in error_msg:
        print('  [FAIL] chromium 未安装')
        print('  [TRY] 尝试安装 chromium...')
        install_result = subprocess.run(
            ['playwright', 'install', 'chromium'],
            capture_output=True,
            text=True,
            timeout=120
        )
        if install_result.returncode == 0:
            print('  [OK] chromium 安装成功')
            sys.exit(2)  # 需要重测
        else:
            print('  [FAIL] chromium 安装失败')
    elif 'libglib' in error_msg or 'libgtk' in error_msg:
        print('  [FAIL] 系统库缺失')
        print('  [TRY] 尝试安装系统依赖...')
        deps_result = subprocess.run(
            ['playwright', 'install-deps', 'chromium'],
            capture_output=True,
            text=True,
            timeout=120
        )
        if deps_result.returncode == 0 or 'apt' in deps_result.stderr.lower() or 'apt' in deps_result.stdout.lower():
            print('  [OK] 系统依赖安装完成')
            sys.exit(2)  # 需要重测
        else:
            print('  [WARN] install-deps 可能需要 root 权限')
    elif 'Permission' in error_msg:
        print('  [FAIL] 权限错误')
    else:
        print(f'  [FAIL] {error_msg[:200]}')
    sys.exit(1)
"

INSTALL_STATUS=$?

if [ $INSTALL_STATUS -eq 2 ]; then
    echo ""
    echo "[重测] 等待安装完成后重新验证..."
    sleep 2
    python3 -c "
import subprocess
import sys
test_code = '''
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    browser.close()
'''
result = subprocess.run([sys.executable, '-c', test_code], capture_output=True, text=True, timeout=30)
if result.returncode == 0:
    print('  [OK] playwright chromium: 修复成功')
    sys.exit(0)
else:
    print('  [FAIL] 修复后仍不可用')
    print(result.stderr[:300] if result.stderr else 'Unknown error')
    sys.exit(1)
"
    RETEST_RESULT=$?
    if [ $RETEST_RESULT -eq 0 ]; then
        BROWSER_FIXED=true
    fi
elif [ $INSTALL_STATUS -eq 0 ]; then
    BROWSER_FIXED=true
fi

if [ "$BROWSER_FIXED" = "true" ]; then
    BROWSER_CAPABILITY="playwright"
    AVAILABLE_BROWSERS="$AVAILABLE_BROWSERS playwright"
fi

# 阶段 7: 生成检测报告
echo ""
echo "============================================================"
echo "[检测报告] 无头浏览器能力汇总"
echo "============================================================"
echo "可用的浏览器能力:"
[ -z "$AVAILABLE_BROWSERS" ] && echo "  (无)" || echo "  $AVAILABLE_BROWSERS"
echo ""
echo "检测到的系统浏览器: $SYSTEM_BROWSERS"
echo "检测到的 MCP 工具: $(env | grep -i 'MCP' | cut -d= -f1 | tr '\n' ' ')"
echo ""
```

**检测结果处理:**

执行上述检测后，根据结果决定下一步：

| 检测结果 | 含义 | 处理方式 |
|---------|------|---------|
| `BROWSER_CAPABILITY` 已设置 | 找到可用的无头浏览器 | 使用该浏览器执行测试 |
| 仅 `SYSTEM_BROWSERS` 有值 | 有系统浏览器但未验证 | 尝试用系统浏览器执行 |
| 仅 `MCP` 工具存在 | MCP 服务可用 | 调用 MCP 浏览器工具 |
| 仅 `SKILL_BROWSER` 有值 | Skills 中有相关能力 | 检查并使用该 skill |
| **均为空** | 没有任何浏览器能力 | **报告致命错误并退出** |

**强制规则:**

1. **禁止降级**: 当无头浏览器能力检测失败时，必须报告错误并终止任务
2. **禁止跳过**: 不得在无头浏览器不可用时降级到 requests/curl/BeautifulSoup 等非浏览器方式
3. **必须完整检测**: 必须执行完整的检测流程，尝试所有可能的替代方案
4. **明确报告**: 必须向用户报告实际可用的浏览器能力

**退出条件**: 如果所有平替方案均失败，必须报告以下信息并终止任务：

```
[FATAL] 无头浏览器能力不可用

已检测的替代方案:
- playwright: 不可用 (原因: ...)
- 系统浏览器: 未安装
- MCP 工具: 未发现
- Skills 浏览器能力: 未找到

当前环境无法执行 SPA 渗透测试。
建议:
1. 安装 playwright: pip install playwright && playwright install chromium
2. 安装系统依赖: playwright install-deps chromium
3. 配置 MCP 浏览器服务
```

---

### 0.4 检查结果处理

执行完 0.3 前置检查后，根据结果处理：

```bash
# 如果无头浏览器能力检测通过
if [ -n "$BROWSER_CAPABILITY" ]; then
    echo "[OK] 无头浏览器: $BROWSER_CAPABILITY"
    echo "[CONTINUE] 继续执行测试..."
else
    echo "[FATAL] 无头浏览器能力不可用"
    echo "[STOP] 任务终止，请先解决浏览器依赖问题"
    exit 1
fi
```

| 检查项 | 状态 | 处理方式 |
|--------|------|---------|
| 无头浏览器能力 | 不可用 | **报告致命错误并退出** |
| requests | 不可用 | **强制安装** `pip install requests` |
| core 模块 | 不可导入 | 检查 core/ 目录，报告错误 |

**强制规则**: 无头浏览器是核心能力，**不可用时必须报错退出，不得跳过或降级**。

---

## 阶段 1: 目标探测与资产发现

**触发**: 前置检查完成后自动执行

### 1.1 基础探测

```bash
# HTTP 头探测
curl -s -I http://target/

# 服务器指纹
curl -s http://target/ | grep -iE "(server:|nginx|apache|tomcat)"

# 技术栈识别
curl -s http://target/ | grep -iE "(vue|react|angular|jquery|elementui)"
```

### 1.2 启用 browser_tester 分析 SPA

**强制执行**: 如果目标是 SPA (Vue/React/Angular)，必须使用 browser_tester

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig

def analyze_spa(target_url):
    """使用浏览器分析 SPA"""
    print(f"[browser_tester] 初始化浏览器，目标: {target_url}")
    
    config = BrowserTestConfig(
        target_url=target_url,
        engine=BrowserEngine.PUPPETEER,
        headless=True,
        timeout=30000
    )
    
    tester = BrowserAutomationTester(config)
    
    if tester.engine.value == "none":
        # 强制安装
        print("[browser_tester] 引擎不可用，强制安装...")
        import subprocess
        subprocess.run(['pip3', 'install', 'playwright', 'pyppeteer'], capture_output=True)
        subprocess.run(['playwright', 'install', 'chromium'], capture_output=True)
        # 重新初始化
        tester = BrowserAutomationTester(config)
        
        if tester.engine.value == "none":
            raise Exception("[browser_tester] 安装后仍然不可用")
    
    print(f"[browser_tester] 引擎状态: {tester.engine.value}")
    
    # 执行分析
    print("[browser_tester] 开始 JS 分析...")
    
    # 获取发现的端点
    if hasattr(tester, 'extract_endpoints'):
        endpoints = tester.extract_endpoints()
        print(f"[browser_tester] 发现端点: {len(endpoints)}")
    
    # 测试 CORS
    if hasattr(tester, 'test_cors'):
        cors_result = tester.test_cors(target_url)
        print(f"[browser_tester] CORS 测试: {cors_result}")
    
    return tester

# 执行
analyze_spa('http://58.215.18.57:91')
```

### 1.2 发现云存储端点? → 触发阶段 5

**核心原则**: 路径模式只是发现线索，**必须通过语义分析确认用途**。

| 发现线索 | 需要分析的语义 | 确认条件 |
|---------|--------------|---------|
| `/file/`, `/upload/` | 这是文件上传接口吗？ | 需要分析参数、响应、Content-Type |
| `oss-`, `cos-` 域名 | 这是云存储服务吗？ | 需要检查响应头或尝试访问 |
| `/minio/` 路径 | 这是 MinIO 服务吗？ | 需要检查响应是否符合存储特征 |
| XML 响应包含 `<ListBucket>` | 这是存储桶吗？ | 确认后可触发阶段 5 |

**错误示例** (机械匹配):
```
发现 /user/profile → 判断为 IDOR 风险 ❌
```

**正确示例** (语义分析):
```
发现 /user/profile
    ↓ 语义分析
    这是获取当前登录用户信息的接口吗？
    ↓
    是 → 当前用户信息，隐私泄露风险
    是 + 无认证 → 认证绕过
    否 → 可能需要进一步测试
```

**触发条件**: 从 JS/响应中发现以下任一模式

| 模式类型 | 检测特征 | 示例 |
|---------|---------|------|
| **URL 域名** | 匹配云厂商域名 | `*.oss-aliyuncs.com`, `*.cos.myqcloud.com` |
| **URL 路径** | 匹配存储路径 | `/minio/`, `/file/`, `/upload/`, `/bucket/` |
| **响应头** | 包含存储 Header | `X-OSS-*`, `X-Amz-*`, `X-Minio-*` |
| **响应内容** | XML 格式特征 | `<ListBucketResult>`, `<AccessControlPolicy>` |

**自动检测代码**:
```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.cloud_storage_tester import CloudStorageTester

def should_trigger_cloud_test(endpoints: List[str], js_content: str = None) -> bool:
    """判断是否应该触发云存储检测"""
    
    # 1. URL 路径模式
    storage_path_patterns = [
        '/minio/', '/minio-api/', '/file/', '/files/',
        '/upload/', '/uploads/', '/storage/', '/bucket/',
        '/oss/', '/cos/', '/s3/', '/obs/',
        '/api/file/', '/api/upload/', '/api/storage/'
    ]
    
    for endpoint in endpoints:
        for pattern in storage_path_patterns:
            if pattern in endpoint.lower():
                return True
    
    # 2. URL 域名模式
    domain_patterns = [
        r'oss-.*\.aliyuncs\.com',
        r'cos\..*\.myqcloud\.com',
        r's3\..*\.amazonaws\.com',
        r'obs\..*\.myhwclouds\.com',
        r'minio',
    ]
    
    for endpoint in endpoints:
        for pattern in domain_patterns:
            if re.search(pattern, endpoint.lower()):
                return True
    
    # 3. JS/响应内容检测
    if js_content:
        tester = CloudStorageTester()
        found = tester.discover_from_text(js_content)
        if found:
            return True
    
    return False

def trigger_cloud_storage_test(target: str, endpoints: List[str], js_content: str = None):
    """触发云存储安全检测"""
    
    if should_trigger_cloud_test(endpoints, js_content):
        print("[Decision] 发现云存储特征，触发阶段 5...")
        
        # 调用云存储检测
        from core.cloud_storage_tester import CloudStorageTester
        tester = CloudStorageTester()
        
        # 优先测试 URL 中的存储端点
        storage_endpoints = []
        for ep in endpoints:
            if any(p in ep.lower() for p in ['/minio/', '/file/', '/upload/', '/bucket/', '/oss/', '/cos/']):
                storage_endpoints.append(ep)
        
        if storage_endpoints:
            for ep in storage_endpoints:
                print(f"[CloudStorage] 测试: {ep}")
                results = tester.full_test(ep)
                # 处理结果...
        
        # 也测试当前域名的常见存储路径
        if 'minio' in str(endpoints).lower():
            # 使用 test_current_domain_storage
            from core.cloud_storage_tester import test_current_domain_storage
            results = test_current_domain_storage(target)
    
    return None
```

### 1.3 启用 deep_api_tester 发现端点

**强制执行**: 必须调用 deep_api_tester 进行端点发现

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.deep_api_tester_v55 import DeepAPITesterV55

def api_discovery(target_url):
    """使用 API 测试器发现端点"""
    print(f"[deep_api_tester] 初始化，目标: {target_url}")
    
    tester = DeepAPITesterV55(target=target_url, headless=True)
    
    print("[deep_api_tester] 执行端点发现和漏洞扫描...")
    result = tester.run_test()
    
    print(f"[deep_api_tester] 扫描完成")
    print(f"[deep_api_tester] 报告已保存")
    
    return tester

# 执行
api_discovery('http://58.215.18.57:91')
```

---

## 阶段 2: 多维度漏洞分析

**触发**: 阶段 1 发现端点后执行

### 2.1 启用 api_fuzzer 进行深度测试

**强制执行**: 发现端点后必须使用 api_fuzzer 验证漏洞

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

import requests
from core.api_fuzzer import APIfuzzer

def vulnerability_testing(api_base):
    """使用 Fuzzer 进行漏洞测试"""
    print(f"[api_fuzzer] 初始化，目标: {api_base}")
    
    session = requests.Session()
    fuzzer = APIfuzzer(session=session)
    
    # 设置目标
    if hasattr(fuzzer, 'set_target'):
        fuzzer.set_target(api_base)
    
    print("[api_fuzzer] 执行漏洞测试...")
    
    # SQL 注入测试
    if hasattr(fuzzer, 'fuzz_sqli'):
        sqli_result = fuzzer.fuzz_sqli()
        print(f"[api_fuzzer] SQL注入测试: {sqli_result}")
    
    # XSS 测试
    if hasattr(fuzzer, 'fuzz_xss'):
        xss_result = fuzzer.fuzz_xss()
        print(f"[api_fuzzer] XSS 测试: {xss_result}")
    
    # 路径遍历测试
    if hasattr(fuzzer, 'fuzz_path_traversal'):
        pt_result = fuzzer.fuzz_path_traversal()
        print(f"[api_fuzzer] 路径遍历测试: {pt_result}")
    
    return fuzzer

# 执行
vulnerability_testing('http://58.215.18.57:91/icp-api')
```

### 2.2 多维度判断框架

#### 判断维度

| 维度 | 权重 | 判断依据 |
|------|------|---------|
| D1: 状态码 | 15% | 200/401/403/404/500 |
| D2: 响应内容 | 20% | 敏感字段、业务数据、错误信息 |
| D3: 认证绕过 | 25% | Token/Cookie/Session 验证 |
| D4: 敏感暴露 | 20% | 密码/密钥/个人数据/配置 |
| D5: 操作影响 | 15% | 增/删/改/查 权限 |
| D6: 业务上下文 | 5% | 端点功能分类 |

### 2.3 发现 GraphQL? → 触发专项测试

**核心原则**: 发现 GraphQL 端点后，**必须通过 introspection 分析 schema 理解其语义**。

| 发现的线索 | 语义分析问题 | 确认条件 |
|-----------|-------------|---------|
| `/graphql` | 这是 GraphQL 端点吗？ | 发送 introspection 查询 |
| `__schema` 响应 | Schema 暴露了哪些类型？ | 分析字段权限 |
| Introspection 禁用 | 为什么禁用？ | 可能有问题 |

**错误示例** (机械匹配):
```
发现 /graphql → 调用 GraphQL 测试清单 ❌
```

**正确示例** (语义分析):
```
发现 /graphql
    ↓ 语义分析
    1. 发送 introspection 查询
       ↓
    2. 分析 Schema 发现了哪些类型和字段
       ↓
    3. 分析字段权限：
       - 哪些字段需要认证？
       - 哪些字段可被未授权访问？
       ↓
    4. 分析嵌套查询风险：
       - 是否有深度限制？
       - 是否有复杂度限制？
       ↓
    5. 分析 mutation 权限：
       - 哪些 mutation 需要 admin？
```

### 2.4 发现 IDOR/越权? → 触发权限测试

**核心原则**: 路径和参数只是线索，**必须通过语义分析判断权限模型**。

| 发现的线索 | 语义分析问题 | 确认条件 |
|-----------|-------------|---------|
| `/user/{id}` | 这是获取他人信息还是当前用户？ | 需要分析参数含义 |
| `id=123` | 这个 ID 是可枚举的吗？ | 需要测试不同 ID |
| 响应包含其他用户数据 | 是否是权限问题？ | 需要对比认证/非认证响应 |

**错误示例** (机械匹配):
```
发现 /user/123 → 判断为 IDOR ❌
```

**正确示例** (语义分析):
```
发现 /user/123
    ↓ 语义分析
    这是一个用户查询接口
    ↓
    分析：使用当前用户的 session token 访问
    ↓
    返回当前用户信息 → 正常
    返回其他用户信息 → IDOR 漏洞 ✅
```

### 2.5 发现暴力破解风险? → 触发登录测试

**核心原则**: 发现登录接口后，**必须分析其防护措施的有效性**。

| 发现的线索 | 语义分析问题 | 确认条件 |
|-----------|-------------|---------|
| `/login` | 有验证码吗？验证码有效吗？ | 需要实际测试 |
| `/auth` | 有 rate limit 吗？ | 需要发送多次请求测试 |
| `captcha` 参数 | 验证码是否可绕过？ | 需要分析验证码逻辑 |
| `lockout` 响应 | 账户锁定机制是否存在？ | 需要测试暴力破解 |

**错误示例** (机械匹配):
```
发现 /login → 判断为暴力破解风险 ❌
```

**正确示例** (语义分析):
```
发现 /login
    ↓ 语义分析
    1. 是否需要验证码？
       - 不需要 → 确认暴力破解风险 ✅
       - 需要验证码 → 验证码是否能防止机器？
           - 可识别 → 低风险
           - 可绕过/无 → 确认暴力破解风险 ✅
    ↓
    2. 是否有 rate limit？
       - 无限制 → 确认暴力破解风险 ✅
       - 有 5 次限制 → 需要测试限制是否严格
```

### 2.6 发现 WebSocket? → 触发 WS 测试

**核心原则**: 发现 WebSocket 端点后，**必须分析其用途和安全机制**。

| 发现的线索 | 语义分析问题 | 确认条件 |
|-----------|-------------|---------|
| `/ws` | 这是什么类型的连接？ | 实时数据？推送？ |
| `Upgrade: websocket` | 连接是否需要认证？ | 分析握手过程 |
| WS 协议 | 传输的数据敏感吗？ | 分析数据内容 |
| WS 响应 | 是否有注入风险？ | 测试特殊字符 |

**错误示例** (机械匹配):
```
发现 /ws → 判断为 WebSocket 测试 ❌
```

**正确示例** (语义分析):
```
发现 /ws
    ↓ 语义分析
    1. 这个 WS 服务的用途是？
       - 实时通知 → 分析通知内容是否敏感
       - 数据推送 → 分析推送的数据类型
       - 双向通信 → 需要测试输入验证
    ↓
    2. 是否有认证？
       - 无认证 → 数据泄露风险 ✅
       - 有 token → 验证 token 是否可伪造
    ↓
    3. 是否有输入验证？
       - 无验证 → 注入风险 ✅
```

### 2.7 阶段间循环

**核心原则**: 根据**接口语义**决定下一步，路径模式只是发现线索。

```
阶段 1: 资产发现
    │
    ├── 发现 /graphql 相关
    │       ↓ 语义分析
    │       这是 GraphQL 端点吗？ → introspection 查询
    │       ↓
    │       分析 Schema 结构和权限 → 阶段 2.3
    │
    ├── 发现 /ws 相关
    │       ↓ 语义分析
    │       这是 WebSocket 服务吗？ → 检查协议升级
    │       ↓
    │       分析连接用途和认证 → 阶段 2.6
    │
    ├── 发现 /login 相关
    │       ↓ 语义分析
    │       这是登录接口吗？ → 检查防护措施
    │       ↓
    │       分析验证码、rate limit → 阶段 2.5
    │
    ├── 发现 /user/{id} 相关
    │       ↓ 语义分析
    │       这会泄露他人信息吗？ → 对比响应
    │       ↓
    │       分析权限模型 → 阶段 2.4
    │
    ├── 发现 /file/, /minio/ 相关
    │       ↓ 语义分析
    │       这是存储服务吗？ → 检查响应特征
    │       ↓
    │       确认后触发 → 阶段 5
    │
    └── 其他
            ↓ 语义分析
            这是什么类型的接口？ → 根据用途分类
            ↓
            继续阶段 2.1
```

**重要**: 路径只是发现线索，**语义分析决定下一步**。
阶段 1: 资产发现
    │
    ├── 发现 /graphql → GraphQL 专项 → 阶段 2.3
    ├── 发现 /ws → WebSocket 专项 → 阶段 2.6
    ├── 发现 /login → 暴力破解测试 → 阶段 2.5
    ├── 发现 /user/{id} → IDOR 测试 → 阶段 2.4
    ├── 发现 /file/, /minio/ → 阶段 5 云存储
    └── 其他 → 继续阶段 2.1

#### 综合评分算法

```
RiskScore = (
    D1_StateCode_Score * 0.15 +
    D2_Content_Score * 0.20 +
    D3_AuthBypass_Score * 0.25 +
    D4_SensitiveExposure_Score * 0.20 +
    D5_UnauthorizedAction_Score * 0.15 +
    D6_BusinessContext_Score * 0.05
)

风险等级:
- Critical: Score >= 80
- High: Score >= 60
- Medium: Score >= 40
- Low: Score >= 20
- Info: Score < 20
```

#### 漏洞判定条件

```
必须满足 P0:
  □ D3: 该端点应该需要认证但不需要
  □ 或 D3: 认证可被绕过

AND 满足以下至少一项 P1:
  □ D2: 响应包含敏感数据
  □ D4: 暴露内部配置/路径
  □ D5: 可进行未授权操作

 辅助条件 P2:
   □ D6: 业务上下文风险高
   □ 利用难度低
   □ 影响范围大
 ```

### 2.2 发现云存储特征? → 触发阶段 5

**核心原则**: 发现存储相关接口后，**必须通过响应分析确认是否为存储服务**。

| 发现的线索 | 语义分析问题 | 确认条件 |
|-----------|-------------|---------|
| `/file/upload` | 这是文件上传接口吗？ | 检查 Content-Type 和响应 |
| 响应包含 XML `<ListBucket>` | 这是存储桶吗？ | 确认后可触发阶段 5 |
| 域名包含 `oss-` | 这是云存储吗？ | 需要尝试访问或检查 Header |

**错误示例** (机械匹配):
```
发现 /file/profile → 判断为云存储 ❌
```

**正确示例** (语义分析):
```
发现 /file/upload
    ↓ 语义分析
    1. 分析响应：
       - Content-Type 是 application/json → 可能是 API，非存储
       - Content-Type 是 XML + 包含 <ListBucket> → 确认是存储桶 ✅
       - 响应为空/403 → 可能是存储服务但受限
    ↓
    2. 检查响应头：
       - 包含 X-OSS-* → 确认是阿里云 OSS ✅
       - 包含 X-Amz-* → 确认是 AWS S3 ✅
    ↓
    3. 尝试根路径访问：
       - 返回文件列表 → 确认公开存储桶 ✅
       - 返回 403 → 可能需要认证
```

**发现线索** (仅作为提示):
```python
CLOUD_INDICATORS = {
    'path_hint': ['/file/', '/upload/', '/storage/', '/bucket/', '/oss/', '/cos/', '/minio/'],
    'domain_hint': ['oss-', 'cos.', 'minio', ':9000'],
    'header_hint': ['x-oss-', 'x-amz-', 'x-minio-'],
    'content_hint': ['<ListBucket', '<AccessControlPolicy']
}
```

**重要**: 这些只是发现线索，**必须通过语义分析确认**。

**决策树**:
```
阶段 2 分析响应
    │
    ├── 发现 /file/, /upload/, /storage/ 等路径?
    │       └── → 触发阶段 5
    │
    ├── 发现 oss-, cos-, minio 等域名?
    │       └── → 触发阶段 5
    │
    ├── 响应包含 X-OSS-*, X-Amz-* Header?
    │       └── → 触发阶段 5
    │
    ├── 响应内容包含 <ListBucket>?
    │       └── → 触发阶段 5
    │
    └── 其他
            └── → 继续分析
```

---

## 阶段 3: 验证与分类

### 3.1 验证发现的漏洞

```python
def validate_vulnerability(endpoint, test_method):
    """多维度验证漏洞"""
    results = {
        'D1_status': None,
        'D2_content': None,
        'D3_auth': None,
        'D4_sensitive': None,
        'D5_action': None,
        'D6_context': None
    }
    
    # D1: 状态码
    response = test_method(endpoint)
    results['D1_status'] = response.status_code
    
    # D2: 响应内容分析
    if 'password' in response.text or 'token' in response.text:
        results['D2_content'] = 'sensitive'
    elif 'user' in response.text or 'email' in response.text:
        results['D2_content'] = 'personal_data'
    else:
        results['D2_content'] = 'normal'
    
    # D3: 认证检查
    if response.status_code == 200:
        results['D3_auth'] = 'bypass'
    elif response.status_code in [401, 403]:
        results['D3_auth'] = 'protected'
    
    # D4: 敏感信息
    sensitive_patterns = ['password', 'secret', 'key', 'token', 'api_key']
    if any(p in response.text.lower() for p in sensitive_patterns):
        results['D4_sensitive'] = 'exposed'
    
    return results
```

### 3.2 误报识别

```
以下情况判定为误报:
- 返回 401/403 (正确拒绝)
- 响应为空或无意义数据
- 端点明确标记为公开 (如 /login, /captcha)
- 业务上下文为公开信息 (如 /health, /version)
```

---

## 阶段 4: 报告生成

### 4.1 强制输出格式

```markdown
## Scope
- Target: [目标 URL]
- Assessment Mode: [文档驱动/被动/主动]
- Authorization: [授权范围]

## Asset Summary
- Base URLs: [发现的所有 base URL]
- API Type: [REST/GraphQL/SPA+API]
- Tech Stack: [识别的技术栈]
- Discovered Endpoints: [端点数量]

## Test Matrix
| Category | Test Item | Priority | Status | Finding |

## Findings

### Finding N: [漏洞标题]

**Severity**: [Critical/High/Medium/Low/Info]
**Confidence**: [Confirmed/High/Medium/Low/Hypothesis]

**Multi-Dimension Analysis**:
| 维度 | 得分 | 分析 |
|------|------|------|
| D1 状态码 | X/15 | [分析] |
| D2 响应内容 | X/20 | [分析] |
| D3 认证绕过 | X/25 | [分析] |
| D4 敏感暴露 | X/20 | [分析] |
| D5 操作影响 | X/15 | [分析] |
| D6 业务上下文 | X/5 | [分析] |
| **总分** | **XX/100** | [风险等级] |

**Evidence**:
```http
[请求]
[响应头]
[响应体 - 脱敏]
```

**Root Cause**: [根本原因]
**Impact**: [影响分析]
**Remediation**: [修复建议]

## Coverage Gaps
## Overall Risk Summary
```

---

## 工具调用规则 (强制执行)

| 场景 | 工具 | 规则 |
|------|------|------|
| SPA 分析 | browser_tester | **必须使用**，除非明确不可用 |
| 端点发现 | deep_api_tester | **必须使用** |
| 漏洞验证 | api_fuzzer | **必须使用** |
| JS 分析 | V35JSAnalyzer | deep_api_tester 内部调用 |

### 调用示例

```python
# 正确的调用方式
from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
from core.deep_api_tester_v55 import DeepAPITesterV55
from core.api_fuzzer import APIfuzzer

# 1. browser_tester (如果目标是 SPA)
config = BrowserTestConfig(target_url=target, engine=BrowserEngine.PUPPETEER)
browser = BrowserAutomationTester(config)
# ... 执行分析 ...

# 2. deep_api_tester (必须调用)
api_tester = DeepAPITesterV55(target=target, headless=True)
api_tester.run_test()

# 3. api_fuzzer (必须调用)
import requests
session = requests.Session()
fuzzer = APIfuzzer(session=session)
fuzzer.set_target(api_base)
# ... 执行测试 ...
```

---

## 阶段 5: 云存储安全检测 (强制执行)

**触发**: 发现 OSS/云存储相关端点时执行

### 5.1 云存储识别

**识别依据**: 从 JS/API 响应中发现以下特征

```python
CLOUD_STORAGE_PATTERNS = {
    # URL 模式
    'aliyun': [
        '.oss-', '.aliyuncs.com', 'aliyun', 'oss-cn-',
        'x-oss-', 'oss.amazonaws.com'
    ],
    'tencent': [
        '.cos.', '.myqcloud.com', 'cos.', 'cos-cn-',
        'tencent', 'gzgrid'
    ],
    'huawei': [
        '.obs.', '.myhwclouds.com', 'hw OBS', 'obs-cn-'
    ],
    'aws': [
        '.s3.', 'amazonaws.com', 'aws-s3', 's3.amazonaws.com',
        's3-external-', 's3.dualstack.'
    ],
    'minio': [
        'minio', ':9000', ':9001', 'play.minio'
    ],
    'azure': [
        '.blob.core.', 'windows.net', 'azure'
    ],
    
    # 端点模式
    'endpoint_patterns': [
        '/oss/', '/bucket/', '/cos/', '/obs/',
        '/file/', '/upload/', '/storage/',
        '/minio/', '/blob/', '/s3/'
    ],
    
    # 响应特征
    'response_patterns': [
        '<ListBucketResult', '<ListAllMyBucketsResult',
        '<?xml version', 'ListBucketResponse',
        'X-OSS-', 'X-Amz-', 'x-oss-metadata'
    ]
}
```

### 5.2 云存储漏洞检测矩阵

| 漏洞类型 | 风险等级 | 检测方法 |
|---------|---------|---------|
| 公开可列目录 | Critical | GET / → 检查是否返回文件列表 |
| 匿名 PUT 上传 | Critical | PUT /test.txt → 检查是否可上传 |
| 匿名 POST 上传 | Critical | POST / → 检查表单上传 |
| 匿名 DELETE | Critical | DELETE /test.txt → 检查删除权限 |
| 敏感文件泄露 | Critical | 扫描 .env, .sql, .bak, .pem 等 |
| 目录遍历 | High | GET /../../etc/passwd |
| CORS 配置过宽 | High | 检查 Access-Control-Allow-Origin |
| 访问日志泄露 | Medium | GET /logs/, /accesslog/ |
| 版本控制泄露 | Medium | 检测 .versioned, /?versions |
| 敏感 HTTP 头 | Low | 检查 X-OSS-Meta-*, X-Amz-* |

### 5.3 云存储检测执行

```python
# -*- coding: utf-8 -*-
"""
云存储安全检测模块
支持: 阿里云 OSS, 腾讯云 COS, 华为云 OBS, AWS S3, MinIO
参考: OSS_scanner (bitboy-sys), BucketTool (libaibaia)
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

class CloudStorageTester:
    """云存储安全测试器"""
    
    # 云厂商 URL 模板
    CLOUD_TEMPLATES = {
        'aliyun': {
            'url': 'http://{bucket}.oss-{region}.aliyuncs.com',
            'https': 'https://{bucket}.oss-{region}.aliyuncs.com'
        },
        'tencent': {
            'url': 'http://{bucket}.cos.{region}.myqcloud.com',
            'https': 'https://{bucket}.cos.{region}.myqcloud.com'
        },
        'huawei': {
            'url': 'http://{bucket}.obs.{region}.myhwclouds.com',
            'https': 'https://{bucket}.obs.{region}.myhwclouds.com'
        },
        'aws': {
            'url': 'http://{bucket}.s3.{region}.amazonaws.com',
            'https': 'https://{bucket}.s3.{region}.amazonaws.com'
        }
    }
    
    # 敏感文件路径
    SENSITIVE_PATHS = [
        '.env', '.git/config', '.git/HEAD', 'id_rsa', 'id_rsa.pub',
        'access_key', 'secret_key', 'credentials', 'aws_key',
        '.sql', '.bak', '.backup', '.db', '.dump',
        '.pem', '.key', '.crt', '.p12', '.pfx',
        'wp-config.php', 'config.php', 'settings.py',
        'database.yml', 'credentials.json',
        'backup.sql', 'db_backup', 'data.sql'
    ]
    
    # 日志路径
    LOG_PATHS = [
        '/logs/', '/log/', '/accesslog/', '/access_log/',
        '/error_log/', '/debug.log', '/app.log'
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.findings: List[Dict] = []
    
    def detect_cloud_provider(self, url: str) -> Optional[str]:
        """检测云厂商类型"""
        for provider, patterns in self.CLOUD_STORAGE_PATTERNS.items():
            if provider == 'endpoint_patterns' or provider == 'response_patterns':
                continue
            for pattern in patterns:
                if pattern in url.lower():
                    return provider
        return None
    
    def test_public_listing(self, bucket_url: str) -> Tuple[bool, str]:
        """测试公开可列目录"""
        try:
            resp = self.session.get(bucket_url, timeout=10)
            
            # 检查是否返回 XML 文件列表
            if resp.status_code == 200:
                content = resp.text
                for pattern in ['<ListBucketResult', '<ListAllMyBucketsResult', 
                               'ListBucketResponse', '<?xml version']:
                    if pattern in content:
                        return True, f"公开可列目录 - 找到文件列表 ({len(content)} bytes)"
            
            # 检查是否返回 AccessDenied
            if 'AccessDenied' in resp.text or resp.status_code == 403:
                return False, "正确拒绝 (403)"
                
            return False, f"状态码: {resp.status_code}"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_put(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 PUT 上传"""
        test_content = f"OSS_TEST_{requests.utils.time.time()}"
        test_key = f"test_{requests.utils.time.time()}.txt"
        
        try:
            resp = self.session.put(
                f"{bucket_url}/{test_key}",
                data=test_content,
                timeout=10
            )
            
            if resp.status_code in [200, 201]:
                # 尝试删除测试文件
                self.session.delete(f"{bucket_url}/{test_key}")
                return True, f"可匿名上传 (状态码: {resp.status_code})"
            
            return False, f"PUT 上传失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_post(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 POST 表单上传"""
        test_content = f"OSS_TEST_{requests.utils.time.time()}"
        
        try:
            files = {'file': ('test.txt', test_content, 'text/plain')}
            resp = self.session.post(bucket_url, files=files, timeout=10)
            
            if resp.status_code in [200, 201]:
                return True, f"可匿名 POST 上传 (状态码: {resp.status_code})"
            
            return False, f"POST 上传失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_delete(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 DELETE 权限"""
        # 先上传测试文件
        test_key = f"test_del_{requests.utils.time.time()}.txt"
        
        try:
            # 上传
            self.session.put(
                f"{bucket_url}/{test_key}",
                data="test",
                timeout=10
            )
            
            # 尝试删除
            resp = self.session.delete(f"{bucket_url}/{test_key}", timeout=10)
            
            if resp.status_code in [200, 204]:
                return True, f"可匿名删除 (状态码: {resp.status_code})"
            
            return False, f"DELETE 失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_sensitive_files(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试敏感文件泄露"""
        found = []
        
        for path in self.SENSITIVE_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    # 检查内容是否是敏感文件
                    content = resp.text[:500].lower()
                    if any(kw in content for kw in ['password', 'secret', 'key', 'aws', 'api_key', 'token']):
                        found.append(f"{path} (可能包含敏感信息)")
                    elif len(resp.content) > 100:  # 有实质内容
                        found.append(f"{path} ({len(resp.content)} bytes)")
                        
            except:
                pass
        
        return len(found) > 0, found
    
    def test_directory_traversal(self, bucket_url: str) -> Tuple[bool, str]:
        """测试目录遍历"""
        traversal_paths = [
            '../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//etc/passwd'
        ]
        
        for path in traversal_paths:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200:
                    if 'root:' in resp.text or 'Administrator' in resp.text:
                        return True, f"目录遍历成功 - 读取了系统文件"
                    elif len(resp.text) > 50:
                        return True, f"可能存在目录遍历 (路径: {path})"
                        
            except:
                pass
        
        return False, "未发现目录遍历"
    
    def test_cors_misconfiguration(self, bucket_url: str) -> Tuple[bool, str]:
        """测试 CORS 配置过宽"""
        try:
            resp = self.session.options(
                bucket_url,
                headers={
                    'Origin': 'http://evil.com',
                    'Access-Control-Request-Method': 'PUT'
                },
                timeout=10
            )
            
            allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            allow_methods = resp.headers.get('Access-Control-Allow-Methods', '')
            
            if allow_origin == '*' or 'http://evil.com' in allow_origin:
                if 'PUT' in allow_methods or 'POST' in allow_methods:
                    return True, f"CORS 过宽 - Allow-Origin: {allow_origin}, Methods: {allow_methods}"
                return True, f"CORS 允许任意 Origin: {allow_origin}"
            
            return False, f"CORS 配置正常"
            
        except Exception as e:
            return False, f"CORS 检测失败: {e}"
    
    def test_log_exposure(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试访问日志泄露"""
        found = []
        
        for log_path in self.LOG_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{log_path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 100:
                    found.append(f"{log_path} ({len(resp.content)} bytes)")
                    
            except:
                pass
        
        return len(found) > 0, found
    
    def full_test(self, bucket_url: str) -> List[Dict]:
        """执行完整云存储安全测试"""
        print(f"[CloudStorage] 开始测试: {bucket_url}")
        
        provider = self.detect_cloud_provider(bucket_url)
        print(f"[CloudStorage] 识别厂商: {provider or '未知'}")
        
        results = []
        
        # 1. 公开可列目录
        print("[CloudStorage] 测试公开可列目录...")
        is_public, msg = self.test_public_listing(bucket_url)
        if is_public:
            results.append({
                'type': 'Public Listing',
                'severity': 'Critical',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 2. 匿名 PUT
        print("[CloudStorage] 测试匿名 PUT 上传...")
        can_put, msg = self.test_anonymous_put(bucket_url)
        if can_put:
            results.append({
                'type': 'Anonymous PUT Upload',
                'severity': 'Critical',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 3. 敏感文件
        print("[CloudStorage] 测试敏感文件泄露...")
        has_sensitive, files = self.test_sensitive_files(bucket_url)
        if has_sensitive:
            results.append({
                'type': 'Sensitive File Exposure',
                'severity': 'Critical',
                'evidence': ', '.join(files[:5]),
                'url': bucket_url
            })
        
        # 4. 目录遍历
        print("[CloudStorage] 测试目录遍历...")
        can_traverse, msg = self.test_directory_traversal(bucket_url)
        if can_traverse:
            results.append({
                'type': 'Directory Traversal',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 5. CORS
        print("[CloudStorage] 测试 CORS...")
        cors_vuln, msg = self.test_cors_misconfiguration(bucket_url)
        if cors_vuln:
            results.append({
                'type': 'CORS Misconfiguration',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 6. 日志泄露
        print("[CloudStorage] 测试日志泄露...")
        has_logs, log_files = self.test_log_exposure(bucket_url)
        if has_logs:
            results.append({
                'type': 'Log Exposure',
                'severity': 'Medium',
                'evidence': ', '.join(log_files[:3]),
                'url': bucket_url
            })
        
        print(f"[CloudStorage] 测试完成，发现 {len(results)} 个问题")
        return results


def discover_and_test_cloud_storage(target: str) -> List[Dict]:
    """发现并测试云存储"""
    print(f"[CloudStorage] 开始云存储安全检测，目标: {target}")
    
    tester = CloudStorageTester()
    all_findings = []
    
    # 从 JS 中发现的存储桶 URL
    bucket_urls = [
        # 需要从实际测试中收集
    ]
    
    for url in bucket_urls:
        findings = tester.full_test(url)
        all_findings.extend(findings)
    
    return all_findings
```

### 5.4 云存储检测调用示例

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.cloud_storage_tester import CloudStorageTester

def test_cloud_storage(target):
    """测试云存储安全"""
    tester = CloudStorageTester()
    
    # 测试已发现的存储桶
    bucket_urls = [
        'http://target.oss-cn-region.aliyuncs.com',
        'http://target.cos.region.myqcloud.com',
        # 添加更多...
    ]
    
    all_results = []
    
    for bucket_url in bucket_urls:
        print(f"\n测试: {bucket_url}")
        results = tester.full_test(bucket_url)
        all_results.extend(results)
        
        for r in results:
            print(f"  [{r['severity']}] {r['type']}: {r['evidence']}")
    
    return all_results

# 执行
test_cloud_storage('http://58.215.18.57:91')
```

---

## 快速执行命令

```bash
cd /workspace/API-Security-Testing-Optimized

# 方式 1: 完整执行 (推荐)
python3 << 'EOF'
import sys
sys.path.insert(0, '.')

# 前置检查
print("="*60)
print("阶段 0: 前置检查")
print("="*60)

# 检查并安装依赖
import subprocess
import importlib

def check_and_install(package, import_name=None):
    name = import_name or package
    try:
        mod = importlib.import_module(name)
        print(f"[OK] {package}")
        return True
    except:
        print(f"[INSTALL] {package}...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', package], capture_output=True)
        return False

check_and_install('requests')
check_and_install('playwright')
check_and_install('pyppeteer')
check_and_install('pytest')

# 导入 core 模块
from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
from core.deep_api_tester_v55 import DeepAPITesterV55
from core.api_fuzzer import APIfuzzer

print("\n" + "="*60)
print("阶段 1: 资产发现")
print("="*60)

target = 'http://58.215.18.57:91'

# 使用 deep_api_tester
api_tester = DeepAPITesterV55(target=target, headless=True)
endpoints = api_tester.run_test()

print("\n" + "="*60)
print("阶段 1.2: 检查云存储触发条件")
print("="*60)

# 云存储触发检测
from core.cloud_storage_tester import CloudStorageTester
cloud_tester = CloudStorageTester(session=session)

# 检测模式
CLOUD_PATH_PATTERNS = ['/minio/', '/file/', '/upload/', '/storage/', '/bucket/', '/oss/', '/cos/', '/s3/']
trigger_cloud = False

for ep in (endpoints or []):
    for pattern in CLOUD_PATH_PATTERNS:
        if pattern in str(ep).lower():
            print(f"[Cloud Trigger] 发现云存储端点: {ep}")
            trigger_cloud = True
            break
    if trigger_cloud:
        break

if trigger_cloud:
    print("[Cloud Trigger] 触发云存储安全检测...")
    print("\n" + "="*60)
    print("阶段 5: 云存储安全检测")
    print("="*60)
    
    # 测试当前域名的存储路径
    for pattern in CLOUD_PATH_PATTERNS:
        storage_url = target.rstrip('/') + pattern
        print(f"[CloudStorage] 测试: {storage_url}")
        try:
            results = cloud_tester.full_test(storage_url)
            if results:
                print(f"[CloudStorage] 发现 {len(results)} 个问题")
        except Exception as e:
            print(f"[CloudStorage] 测试失败: {e}")

print("\n" + "="*60)
print("阶段 2-3: 漏洞测试与验证")
print("="*60)

# 使用 api_fuzzer
import requests
session = requests.Session()
fuzzer = APIfuzzer(session=session)
fuzzer.set_target(target + '/icp-api')

# 云存储检测（如果阶段 1 未触发）
if not trigger_cloud:
    print("\n" + "="*60)
    print("阶段 5: 云存储安全检测")
    print("="*60)
    print("[CloudStorage] 尝试发现云存储...")
    # 从 JS 响应中发现存储 URL
    try:
        resp = session.get(target, timeout=10)
        found = cloud_tester.discover_from_text(resp.text)
        if found:
            for f in found[:5]:
                print(f"[CloudStorage] 发现: {f.get('url')}")
                results = cloud_tester.full_test(f.get('url'))
    except:
        pass

print("\n" + "="*60)
print("完成")
print("="*60)
EOF
```

---

## 参考文档

| 阶段 | 参考文档 | 说明 |
|------|---------|------|
| GraphQL 测试 | `references/graphql-guidance.md` | GraphQL 专项测试指导 |
| REST API 测试 | `references/rest-guidance.md` | REST API 测试指导 |
| 资产发现 | `references/asset-discovery.md` | 资产发现方法 |
| 测试矩阵 | `references/test-matrix.md` | 测试用例矩阵 |
| 验证标准 | `references/validation.md` | 漏洞验证标准 |
| 严重性校准 | `references/severity-model.md` | 严重性分级标准 |
| 报告模板 | `references/report-template.md` | 报告格式模板 |
| 云存储 | `core/cloud_storage_tester.py` | 云存储安全测试模块 |

