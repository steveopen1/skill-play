---
name: api-security-testing
description: 针对授权目标进行结构化的 REST/GraphQL API 安全评估。【触发词】安全测试、安全审计、渗透测试、漏洞检测、安全评估、api安全、接口安全、帮我检测漏洞、检查安全问题、安全报告、全流程测试、完整测试、云存储安全。【强制要求】(1)必须使用Playwright进行JS动态采集 (2)必须拦截所有XHR/Fetch请求 (3)必须模拟用户交互触发动态API (4)必须处理HTTPS证书问题。【重要】必须确认用户拥有该目标的合法授权！
---

## 前置检查与依赖处理

### 【强制】采集模块禁止降级

**【重要】SPA应用JS采集必须使用Playwright，绝对禁止降级！**

```
遇到Playwright不可用时：
1. 首先 pip install playwright
2. 然后 playwright install chromium
3. 最后 playwright install-deps chromium  # 安装系统依赖

自动检测并安装缺失依赖：
try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        browser.close()
except Exception as e:
    if "libglib" in str(e) or "Shared object" in str(e):
        subprocess.run(["playwright", "install-deps", "chromium"], check=True)
    # 重新尝试启动

常见依赖缺失及解决：
| 缺失库 | 解决方案 |
|--------|----------|
| libglib-2.0.so | playwright install-deps chromium |
| libnss3 | 同上 |
| libatk | 同上 |
| libpango | 同上 |

【禁止降级】绝对不允许：
- 不能降级到 selenium
- 不能降级到 pyppeteer  
- 不能降级到 requests 静态解析
- 不能降级到 curl 抓取JS

如果Playwright在修复依赖后仍无法使用，报告环境问题并停止采集阶段。
```

### 其他依赖处理

```
遇到requests不可用：
1. pip install requests

注意：requests降级是允许的，因为它是补充工具。
```

## 发现即测原则

**不要等全部扫描完再测试，发现接口立即测试。**

```
错误做法：
1. 先扫描所有端点
2. 再逐一测试漏洞

正确做法：
1. 发现一个接口 → 立即测试相关漏洞
2. 发现敏感接口 → 立即深入测试
3. 发现认证接口 → 立即测试绕过

发现Swagger → 立即访问获取更多API
发现Actuator → 立即测试敏感端点
发现登录接口 → 立即测试注入/爆破
发现查询接口 → 立即测试IDOR
发现文件上传接口 → 立即测试上传绕过
```

### API 类型对应的测试重点

| API 类型 | 发现后立即测试 |
|----------|---------------|
| 认证类 (login, auth) | SQL注入、暴力破解、用户枚举 |
| 查询类 (list, get, search) | IDOR，信息泄露、注入 |
| 操作类 (add, modify, delete) | 越权、批量操作、业务逻辑 |
| 文件类 (upload, download) | 上传绕过、恶意文件、路径遍历 |
| 支付类 (pay, refund, order) | 金额篡改、支付绕过、退款欺诈 |

## 核心检测思维

### 遇到"查询类"接口时

当你发现一个接口用于查询数据时：

```
思考：这个接口查的是什么数据？需要认证吗？能查到别人的数据吗？
```

**推理步骤：**
1. 这个接口查询需要什么参数？（userId、phone、orderNo...）
2. 不带参数能查到数据吗？
3. 带别人的ID能查到数据吗？（IDOR）
4. 响应中有没有敏感字段？（password、token、余额...）

### 遇到"认证类"接口时

当你发现登录、注册接口时：

```
思考：认证机制安全吗？能绕过吗？能枚举用户吗？
```

**推理步骤：**
1. 不带认证信息能访问吗？
2. 伪造token能通过吗？（JWT alg:none）
3. 用户不存在时的响应有区别吗？（用户枚举）
4. 有短信验证码吗？能轰炸吗？

### 遇到"资金/订单类"接口时

当你发现支付、退款、订单接口时：

```
思考：钱能转走吗？订单能篡改吗？能刷单吗？
```

**推理步骤：**
1. 订单归属校验了吗？（用A的token能操作B的订单吗？）
2. 金额能篡改吗？（改成0.01）
3. 退款接口需要什么权限？能绕过吗？

## 敏感信息识别

### 必须识别这些敏感字段

```
password      → 不应返回前端
token         → 可能存在泄露
secretKey     → 不应暴露
apiKey        → 不应暴露
balance       → 可能存在越权
orderNo       → 可能被篡改
userId        → 可用于越权测试
phone         → 可用于用户枚举
email         → 可用于钓鱼
```

### 响应类型分类

| 响应类型 | 特征 | 含义 |
|----------|------|------|
| JSON对象 | `{"code":200,"data":{...}}` | 真实API响应 |
| JSON数组 | `[{"id":1,...},...]` | 真实数据列表 |
| HTML页面 | `<!DOCTYPE html>...` | SPA路由/WAF/错误页 |
| 空响应 | 长度<50字节 | 可能是错误/空数据 |
| 重定向 | HTTP 301/302 | 需要认证/跳转 |

## 漏洞验证闭环

### 三步验证流程

```
第一步：发现 (Discover)
  - 发现可疑的响应差异
  - 发现异常的状态码
  - 发现敏感信息暴露

第二步：分析 (Analyze)
  - 多次请求确认差异稳定
  - 对比正常请求和异常请求
  - 检查是否是WAF/路由/认证导致

第三步：验证 (Verify)
  - 确认为漏洞 → 收集证据 → 报告
  - 排除为误报 → 记录原因 → 继续扫描
```

### 验证检查清单（10个维度）

```
□ 维度1: 响应类型 - 是JSON还是HTML？（HTML可能是WAF）
□ 维度2: 状态码 - 是否合理？
□ 维度3: 响应长度 - 是否过短？（可能是拦截）
□ 维度4: WAF拦截 - 是否为WAF/安全设备？
□ 维度5: 敏感信息 - 是否包含password/token/secret？
□ 维度6: 一致性 - 多次请求响应是否一致？
□ 维度7: SQL注入 - 是否包含SQL错误特征？
□ 维度8: IDOR - 是否返回用户/业务数据？
□ 维度9: 认证绕过 - 是否返回token/session？
□ 维度10: 信息泄露 - 是否泄露非公开信息？
```

### 常见误报识别

```
这些不是漏洞（识别为误报）：
1. HTTP 200 返回 HTML 页面
   → 可能是WAF拦截页/SPA路由/默认错误页
   → 验证：是否是JSON格式的业务数据？

2. 响应长度完全相同但返回"登录失效"
   → 说明后端有正确的认证检查
   → 不是漏洞，是安全防护有效

3. 所有ID查询返回相同响应
   → 可能是统一错误处理
   → 验证：是否真的返回了不同的业务数据？
```

## 漏洞链构造思维

### 发现用户枚举后的推理

```
你发现的：GET /api/user/check?phone=138xxx 返回 userId

利用链：
1. 收集更多userId → 批量探测手机号
2. 用userId查更多信息 → GET /api/user/info?userId=xxx
3. 尝试修改他人资料 → POST /api/user/update
4. 查看他人订单 → GET /api/order/list?userId=xxx
5. 尝试退款 → POST /api/refund (用他人的orderNo)

最终：用户枚举 → 获取userId → 查订单 → 退款
```

### 发现token泄露后的推理

```
你发现的：{"token": "xxx", "userId": 123}

利用链：
1. token有效吗？ → 用token访问其他接口
2. 能访问admin接口吗？ → GET /api/admin/xxx
3. token能用于其他用户吗？ → 改userId重放

最终：token泄露 → 用token访问敏感接口 → 越权操作
```

## SPA应用完整采集流程

### 阶段1：基础探测
```
1. HTTP探测目标可访问性
   curl -I http://target.com
   
2. 技术栈识别
   - 检查响应头Server字段
   - 检查HTML中是否包含Vue/React/Angular关键词
   - 检查是否包含webpack chunk引用
   
3. 判断是否是SPA应用
   - /api/* 返回HTML → SPA
   - HTML包含JS chunk路径 → Vue/React应用
```

### 阶段2：JS采集【强制·禁止降级】

**【强制要求】必须使用Playwright，禁止降级到其他方案**

```python
# 1. 必须使用Playwright访问目标
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)  # 处理HTTPS证书
    page = context.new_page()
    
    # 2. 访问目标并等待网络空闲
    page.goto(url, wait_until="networkidle", timeout=60000)
    page.wait_for_timeout(5000)  # 等待JS完全执行
    
    # 3. 拦截所有请求
    def log_request(request):
        ALL_TRAFFIC.append({
            'url': request.url,
            'method': request.method,
            'type': request.resource_type
        })
    page.on('request', log_request)
    
    # 4. 模拟用户交互
    page.click('body')  # 点击触发
    page.wait_for_timeout(1000)
    page.evaluate('window.scrollTo(0, document.body.scrollHeight)')  # 滚动触发懒加载
    page.wait_for_timeout(2000)
    
    # 5. 采集敏感信息
    cookies = context.cookies()
    local_storage = page.evaluate('Object.keys(localStorage)')
    
# 【禁止降级采集阶段】
# ❌ 不能使用 selenium 采集JS
# ❌ 不能使用 pyppeteer 采集JS
# ✅ 分析阶段允许使用curl
```

### 阶段3：JS深度分析（AST+正则双模式提取）

**【关键】必须使用AST+正则双模式进行深度分析**

```bash
# 分析阶段允许使用curl进行补充
curl -sk "https://target.com/js/app.js" -o app.js
```

1. 提取baseURL配置（最优先！）
   patterns:
   - r'baseURL\s*[:=]\s*["\']([^"\']+)["\']'
   - r'axios\.create\s*\(\s*\{([^}]+)\}'
   
   重要发现：
   - baseURL:"" 为空 → 使用相对路径 + nginx代理
   - baseURL:"https://api.xxx.com" → 使用配置的域名前缀
   - baseURL不存在 → 使用同源请求

2. 正则模式（快速提取）
   patterns:
   - r'["\'](/(?:user|auth|admin|login|logout|api|v\d|frame)[^"\']*)["\']'
   - r'axios\.[a-z]+\(["\']([^"\']+)["\']'
   - r'fetch\(["\']([^"\']+)["\']'
   - r'\.get\(["\']([^"\']+)["\']'
   - r'\.post\(["\']([^"\']+)["\']'
   
3. 【重要】递归分析所有 chunk 文件
   - webpack 打包的应用会将代码分散到多个 chunk 文件中
   - 大 chunk 文件（>50KB）通常包含更多业务逻辑

4. 敏感信息提取
   - IP地址: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
   - 外部域名: 从URL中提取netloc
   - 凭证信息:
     * api_key, secret_key: r'(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']'
     * token: r'(?:access[_-]?token|Bearer)\s+([a-zA-Z0-9\-_\.]+)'
```

### 阶段4：API测试
```
1. 确定base_path（关键！找不到时使用字典）
   
   base_path获取优先级:
   1. baseURL配置 → 直接使用
   2. nginx反向代理推测 → 从响应头Server字段分析
   3. 使用字典 fallback:
   
   # 常见API前缀/父路径字典
   common_api_prefixes = [
       "/api", "/api/v1", "/api/v2", "/api/v3",
       "/webapi", "/openapi", "/rest", "/rest/api",
       "/admin", "/manager", "/backend", "/server",
       "/user", "/auth", "/oauth", "/public",
   ]
   
2. 逐个测试发现的API端点
   - GET请求：检查Content-Type和响应内容
   - POST请求：测试登录接口（SQL注入/XSS）
   
3. 判断响应类型
   - application/json → 真实API
   - text/html → SPA路由或WAF拦截
```

### 阶段5：漏洞验证
```
□ 维度1: 响应类型 - 是JSON还是HTML？
□ 维度2: 状态码 - 是否合理？
□ 维度3: 响应长度 - 是否过短？
□ 维度4: WAF拦截 - 是否为WAF？
□ 维度5: 敏感信息 - 是否包含password/token？
□ 维度6: 一致性 - 多次请求是否一致？
□ 维度7: SQL注入 - 是否包含SQL错误？
□ 维度8: IDOR - 是否返回用户数据？
□ 维度9: 认证绕过 - 是否返回token？
□ 维度10: 信息泄露 - 是否泄露非公开信息？
```

## 特殊情况处理

### 遇到WAF/安全设备时
```
识别特征：
- 所有请求返回相似的HTML页面
- 响应包含"拦截"、"安全"、"访问受限"等关键词
- 响应内容与实际API无关

处理方法：
1. 识别为WAF拦截，不是漏洞
2. 记录"存在WAF防护"作为安全能力
3. 可以尝试降低请求频率绕过

判断逻辑：
- 请求1: 返回业务JSON = 正常
- 请求2: 返回HTML拦截页 = WAF
- 请求3: 返回业务JSON = 恢复
```

### 遇到SPA应用时
```
识别特征：
- /api/* 路径返回HTML页面
- 响应内容是前端框架代码
- 不是真实的API端点

处理方法：
1. 通过JS源码分析获取真实API配置
2. 使用无头浏览器触发动态API请求
3. 不要对SPA路由的/api/*路径直接测试

判断逻辑：
- GET /api/user/info 返回HTML = SPA前端路由
- GET /api/user/info 返回JSON = 真实API
```

## 核心模块能力池 (core/)

> **重要：能力池只作为参考，不是固定流程**
> - 根据目标站点特点选择合适的模块
> - 根据测试阶段动态调整
> - 可以只用部分模块，也可以组合使用

### 目录结构

```
core/                              # 核心能力池（原子化）
├── collectors/                     # 信息采集能力
│   ├── http_client.py            # HTTP请求能力
│   ├── js_parser.py              # JS源码解析（AST+正则）
│   ├── browser_collect.py         # 无头浏览器采集
│   ├── js_collector.py           # JS采集
│   ├── browser_collector.py       # 浏览器采集
│   ├── url_collector.py          # URL采集
│   └── api_path_finder.py        # API路径发现
├── analyzers/                     # 分析能力
│   ├── api_parser.py             # API端点解析
│   ├── response_analyzer.py       # 响应类型分析
│   └── sensitive_finder.py       # 敏感信息发现
├── testers/                       # 测试能力
│   ├── sqli_tester.py           # SQL注入测试
│   ├── idor_tester.py           # 越权测试
│   ├── auth_tester.py           # 认证测试
│   ├── jwt_tester.py            # JWT测试
│   ├── fuzz_tester.py            # 模糊测试
│   ├── api_fuzzer.py           # API模糊测试
│   └── browser_tester.py        # 浏览器测试
├── verifiers/                    # 验证能力
│   ├── vuln_verifier.py         # 漏洞验证（10维度）
│   └── response_diff.py         # 响应差异对比
├── utils/                        # 工具能力
│   ├── prerequisite.py          # 依赖检查
│   ├── payload_lib.py           # Payload库
│   └── base_path_dict.py        # API base path字典
└── advanced/                     # 高级能力
    ├── advanced_recon.py        # 高级侦察
    ├── agentic_analyzer.py       # 智能分析
    ├── dynamic_api_analyzer.py   # 动态API分析
    ├── cloud_storage_tester.py   # 云存储测试
    ├── context_manager.py        # 上下文管理
    ├── orchestrator.py           # 编排器
    ├── reasoning_engine.py       # 推理引擎
    ├── strategy_pool.py          # 策略池
    ├── scan_engine.py            # 扫描引擎
    └── testing_loop.py           # 测试循环
```

### 能力池模块参考

| 阶段 | 可用模块 | 使用场景 | 必须 |
|------|----------|----------|------|
| **采集【禁止降级】** | | | |
| | `browser_collect.py` | SPA应用必须使用Playwright，禁止降级！ | ✅ |
| | `js_parser.py` | 从JS提取API，使用AST+正则双模式 | ✅ |
| **分析【允许降级】** | | | |
| | `sensitive_finder.py` | 提取password/token/密钥等敏感字段 | |
| | `response_analyzer.py` | 分析响应类型，识别JSON/HTML/WAF | |
| | `curl` | 允许使用curl进行补充分析 | 允许 |
| **测试** | | | |
| | `sqli_tester.py` | SQL注入测试 | |
| | `idor_tester.py` | 越权测试 | |
| | `auth_tester.py` | 认证绕过测试 | |
| | `jwt_tester.py` | JWT漏洞测试 | |
| | `api_fuzzer.py` | API端点fuzzing | |
| | `browser_tester.py` | DOM XSS，浏览器环境测试 | |
| **验证** | | | |
| | `vuln_verifier.py` | 10维度漏洞验证 | ✅ |
| | `response_diff.py` | 响应对比，排除误报 | |
| **辅助** | | | |
| | `base_path_dict.py` | 找不到baseURL时，fuzzing父路径 | ✅ |
| | `prerequisite.py` | 依赖检查，工具可用性验证 | ✅ |

### SPA应用采集流程（必须遵循）

```
阶段1: 基础探测
  ├─ HTTP探测: http_client.py
  ├─ 技术栈识别: browser_collect.py
  ├─ 判断SPA: /api/* 返回HTML
  └─ Swagger探测: /swagger-ui.html, /v2/api-docs

阶段2: JS采集（必须使用Playwright）
  ├─ 启动浏览器: browser_collect.py
  ├─ 访问目标: page.goto(url, wait_until="networkidle")
  ├─ 等待加载: page.wait_for_timeout(5000)
  ├─ 自动交互: 填写登录表单，点击登录按钮
  ├─ 拦截API: 捕获XHR/Fetch请求
  └─ 采集敏感信息: localStorage/响应头

阶段3: JS深度分析（AST+正则双模式）
  ├─ baseURL配置: js_parser.py
  ├─ API路径提取: 正则+AST双模式
  ├─ 敏感信息: sensitive_finder.py
  └─ base_path获取: base_path_dict.py

阶段4: API测试
  ├─ base_path拼接: base_path_dict.py
  ├─ SQL注入: sqli_tester.py
  ├─ 越权测试: idor_tester.py
  ├─ 认证测试: auth_tester.py
  └─ JWT测试: jwt_tester.py

阶段5: 漏洞验证
  └─ vuln_verifier.py → 10维度验证
```

## 参考资源

### references/ 参考文档

| 文档 | 内容 | 使用时机 |
|------|------|----------|
| `workflows.md` | 完整扫描流程 | 整体流程参考 |
| `vulnerabilities/01-sqli-tests.md` | SQL注入测试方法 | 测试SQL注入时 |
| `vulnerabilities/02-user-enum-tests.md` | 用户枚举测试方法 | 测试用户枚举时 |
| `vulnerabilities/03-jwt-tests.md` | JWT认证测试方法 | 测试JWT时 |
| `vulnerabilities/04-idor-tests.md` | IDOR越权测试 | 测试越权时 |
| `vulnerabilities/05-sensitive-data-tests.md` | 敏感信息泄露测试 | 测试信息泄露时 |
| `vulnerabilities/06-biz-logic-tests.md` | 业务逻辑漏洞测试 | 测试业务逻辑时 |
| `vulnerabilities/07-security-config-tests.md` | 安全配置测试(CORS/CSRF) | 测试配置漏洞时 |
| `vulnerabilities/08-brute-force-tests.md` | 暴力破解测试 | 测试认证爆破时 |
| `vulnerabilities/09-vulnerability-chains.md` | 漏洞关联联想 | 阶段5 利用链构造 |
| `vulnerabilities/10-auth-tests.md` | 认证测试扩展 | 测试认证时 |
| `vulnerabilities/11-graphql-tests.md` | GraphQL测试 | 测试GraphQL API时 |
| `vulnerabilities/12-ssrf-tests.md` | SSRF测试 | 测试SSRF时 |
| `fuzzing-patterns.md` | Fuzzing字典 | 阶段3 端点探测 |
| `report-template.md` | 报告模板 | 阶段6 生成报告 |
| `pua-agent.md` | PUA Agent说明 | 自主深入测试 |

### scripts/ 自动化脚本

| 脚本 | 功能 |
|------|------|
| `js_collector.py` | 强制Playwright采集，失败则报错 |
| `auth_bypass_tester.py` | 认证绕过测试矩阵 |

### examples/ 示例

| 示例 | 内容 |
|------|------|
| `security-report-example.md` | 安全报告示例 |
| `detailed-vulnerability-chains.md` | 详细漏洞链案例 |
| `vulnerability-cases.md` | 漏洞案例 |
| `usage-examples.md` | 使用示例 |
| `environment-simulation.md` | 环境模拟 |

### resources/ 资源文件

| 资源 | 内容 |
|------|------|
| `sqli.json` | SQL注入Payload库 |
| `xss.json` | XSS Payload库 |
| `dom_xss.json` | DOM XSS Payload库 |
