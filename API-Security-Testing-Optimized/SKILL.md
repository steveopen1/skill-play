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

---

## 前置检查与依赖处理

### 当依赖不可用时

当你需要进行安全测试，但发现某些工具不可用时：

```
遇到Playwright不可用：
1. 尝试 pip install playwright && playwright install chromium
2. 尝试 playwright install-deps chromium  # 安装系统依赖（容易被忽略）
3. 尝试使用MCP工具: headless_browser
4. 尝试其他方案: selenium, pyppeteer
5. 最后才使用 requests 静态解析

遇到requests不可用：
1. 尝试 pip install requests
2. 尝试curl
3. 报告环境问题

注意：不要轻易回退！优先解决依赖问题。
```

### 发现即测原则

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
```

### 发现即测的例外

**以下情况需要先验证，再深入：**

```
1. 发现返回200但内容异常
   → 不要直接报告漏洞
   → 先验证：是真实数据还是WAF拦截页？

2. 发现可疑的响应差异
   → 不要直接报告漏洞
   → 先多次请求确认差异是否稳定

3. 发现疑似敏感信息
   → 不要直接报告漏洞
   → 先确认：这是业务数据还是测试数据？
```

### 测试优先级

当你发现多个问题时，按这个顺序：

```
1. 立即可利用的漏洞（如SQL注入、认证绕过）
2. 信息泄露（如Swagger、Actuator暴露）
3. 业务逻辑漏洞（如越权、支付篡改）
4. 枚举类漏洞（如用户枚举）
```

---

## 核心检测思维

### 1. 遇到"查询类"接口时这么想

当你发现一个接口用于查询数据时：

```
思考：这个接口查的是什么数据？需要认证吗？能查到别人的数据吗？
```

**推理步骤：**
1. 这个接口查询需要什么参数？（userId、phone、orderNo...）
2. 不带参数能查到数据吗？
3. 带别人的ID能查到数据吗？（IDOR）
4. 响应中有没有敏感字段？（password、token、余额...）

**示例：**
```
你发现：GET /api/user/info?userId=123
思考：
  - 需要认证吗？→ 测试不带token
  - 能查其他用户吗？→ 测试userId=124
  - 响应有敏感字段吗？→ 检查password、token等
```

### 2. 遇到"认证类"接口时这么想

当你发现登录、注册接口时：

```
思考：认证机制安全吗？能绕过吗？能枚举用户吗？
```

**推理步骤：**
1. 不带认证信息能访问吗？
2. 伪造token能通过吗？（JWTalg:none）
3. 用户不存在时的响应有区别吗？（用户枚举）
4. 有短信验证码吗？能轰炸吗？

**示例：**
```
你发现：POST /api/login
思考：
  - SQL注入？→ 测试 username=' OR '1'='1
  - 暴力破解？→ 多次尝试错误密码
  - 用户枚举？→ 测试不存在的用户
```

### 3. 遇到"资金/订单类"接口时这么想

当你发现支付、退款、订单接口时：

```
思考：钱能转走吗？订单能篡改吗？能刷单吗？
```

**推理步骤：**
1. 订单归属校验了吗？（用A的token能操作B的订单吗？）
2. 金额能篡改吗？（改成0.01）
3. 退款接口需要什么权限？能绕过吗？

**示例：**
```
你发现：POST /api/pay/refund
思考：
  - 需要认证吗？→ 不带token测试
  - 需要自己的订单吗？→ 尝试他人的orderNo
  - 金额能改成0吗？→ amount=0测试
```

### 4. 遇到"用户信息"接口时这么想

当你发现返回用户资料的接口时：

```
思考：别人的资料能拿到吗？密码暴露了吗？能修改吗？
```

**推理步骤：**
1. 不带token能拿到吗？
2. 响应里有password吗？
3. 能通过phone/email找到userId吗？
4. 修改接口有校验吗？能改别人的吗？

**示例：**
```
你发现：GET /api/user/info?phone=138xxx
思考：
  - 返回userId了吗？→ 记录
  - 返回password了吗？→ 漏洞
  - userId=124能查到吗？→ IDOR测试
```

---

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

### 响应类型分类（重要）

**不同响应类型代表不同含义：**

| 响应类型 | 特征 | 含义 |
|----------|------|------|
| JSON对象 | `{"code":200,"data":{...}}` | 真实API响应 |
| JSON数组 | `[{"id":1,...},...]` | 真实数据列表 |
| HTML页面 | `<!DOCTYPE html>...` | SPA路由/WAF/错误页 |
| 空响应 | 长度<50字节 | 可能是错误/空数据 |
| 重定向 | HTTP 301/302 | 需要认证/跳转 |

**判断逻辑：**
```
1. 检查Content-Type: 是application/json还是text/html？
2. 检查响应长度: <100字节通常是错误响应
3. 检查响应内容: 是否包含< DOCTYPE html？
4. 对比正常请求: 相同接口的响应应该相似
```

### 响应分析思维

当你看到响应时：
```
1. 这个响应正常吗？ → 检查状态码
2. 有敏感字段吗？ → 搜索password/token/secret
3. 有ID类字段吗？ → 尝试遍历
4. 有手机号吗？ → 尝试用户枚举
5. 有订单号吗？ → 尝试越权操作
```

---

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

---

## 漏洞链构造思维

### 发现用户枚举后的推理

当你发现可以枚举用户时：

```
你发现的：GET /api/user/check?phone=138xxx 返回 userId

思考能做什么：
1. 收集更多userId → 批量探测手机号
2. 用userId查更多信息 → GET /api/user/info?userId=xxx
3. 尝试修改他人资料 → POST /api/user/update
4. 查看他人订单 → GET /api/order/list?userId=xxx
5. 尝试退款 → POST /api/refund (用他人的orderNo)

利用链：
用户枚举 → 获取userId → 查订单 → 退款
```

### 发现token泄露后的推理

当你发现响应中包含token时：

```
你发现的：{"token": "xxx", "userId": 123}

思考能做什么：
1. 这个token有效吗？ → 用这个token访问其他接口
2. 能用这个token访问admin接口吗？ → GET /api/admin/xxx
3. token能用于其他用户吗？ → 改userId重放

利用链：
token泄露 → 用token访问敏感接口 → 越权操作
```

### 发现订单接口后的推理

当你发现订单相关接口时：

```
你发现的：GET /api/order/list

思考能做什么：
1. 不带认证能访问吗？ → 测试
2. 能带userId参数吗？ → 查他人订单
3. 能找到orderNo吗？ → 尝试 /api/order/detail?orderNo=xxx
4. 有退款接口吗？ → 尝试 /api/refund?orderNo=xxx

利用链：
用户枚举 → 获取userId → 查订单 → 获取orderNo → 退款
```

---

## HTTP方法与测试策略

### 不同方法的测试重点

| 方法 | 测试重点 |
|------|----------|
| GET | 参数遍历、IDOR，信息泄露 |
| POST | 认证绕过、业务逻辑、注入 |
| PUT | 资源篡改、越权修改 |
| DELETE | 资源删除、越权删除 |
| PATCH | 部分更新、字段覆盖 |

### 参数测试思维

当你发现一个接口有参数时：

```
接口：GET /api/xxx?param=value

测试顺序：
1. param=空值
2. param=正常值
3. param=特殊字符 (' " < >)
4. param=SQL注入 (1' OR '1'='1)
5. param=XSS (<script>alert(1)</script>)
6. param=路径遍历 (../../../etc/passwd)
7. param=其他用户的值 (IDOR)
```

---

## 认证上下文理解

### 发现登录接口后

```
你发现的：POST /api/login {"username":"xxx","password":"xxx"}

思考：
1. 返回token吗？ → 记录token
2. 返回userId吗？ → 记录userId
3. 响应有什么区别？ → 用户枚举
4. 有验证码吗？ → 暴力破解难度

接下来用这个token：
- 访问 GET /api/user/info
- 访问 GET /api/order/list
- 尝试 GET /api/admin/xxx (测试权限)
```

### 发现token但不知道用法时

```
你发现的：token=eyJhbGciOiJIUzI1NiJ9...

思考：
1. JWT吗？ → 解码看payload
2. 放在哪？ → Authorization: Bearer token
3. 哪个接口用？ → 尝试访问需要认证的接口
4. userId是什么？ → 从token解码获取
```

---

## 常见漏洞模式识别

### 用户相关漏洞模式

```
1. 用户信息泄露
   特征：响应包含password、token
   测试：不带认证访问

2. 用户枚举
   特征：用户存在/不存在响应不同
   测试：探测不存在的手机号/邮箱

3. 密码重置漏洞
   特征：可通过phone/email重置
   测试：尝试修改他人密码

4. 越权访问
   特征：通过参数切换用户
   测试：修改userId/phone等参数
```

### 订单相关漏洞模式

```
1. 订单遍历
   特征：参数化查询订单
   测试：修改userId查他人订单

2. 订单篡改
   特征：订单金额可修改
   测试：尝试amount=0.01

3. 虚假订单
   特征：可创建任意订单
   测试：构造恶意订单数据

4. 退款绕过
   特征：退款接口无校验
   测试：使用他人orderNo退款
```

### 认证相关漏洞模式

```
1. JWT伪造
   特征：alg:None 或不验签
   测试：修改payload重放

2. 暴力破解
   特征：无验证码、无限流
   测试：多次尝试密码

3. 会话固定
   特征：登录后session不变
   测试：登录前后cookie对比

4. 登出后令牌仍有效
   特征：token注销机制缺失
   测试：登出后重放token
```

---

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

### SPA应用完整采集流程（必须按顺序执行）

**阶段1：基础探测**
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

**阶段2：JS采集（必须使用无头浏览器）**
```
1. 使用Playwright访问目标
   from playwright.sync_api import sync_playwright
   
   with sync_playwright() as p:
       browser = p.chromium.launch(headless=True)
       page = browser.new_page()
       page.goto(url, wait_until="networkidle")
       page.wait_for_timeout(5000)  # 等待JS完全执行
       
2. 从DOM提取所有JS文件
   js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', page.content())
   
3. 【新增】拦截所有请求和响应
   - page.on('request') → 捕获所有API请求
   - page.on('response') → 捕获所有响应（提取IP、域名）
   
4. 【新增】采集敏感信息
   - localStorage: 检查token、key等敏感数据
   - 响应头: 提取server版本、IP、域名信息
```

**阶段3：JS深度分析（AST+正则双模式提取）**
```
【关键】必须使用AST+正则双模式进行深度分析

1. 提取baseURL配置（最优先！）
   patterns:
   - r'baseURL\s*[:=]\s*["\']([^"\']+)["\']'
   - r'axios\.create\s*\(\s*\{([^}]+)\}'
   
   重要发现：
   - baseURL:"" 为空 → 使用相对路径 + nginx代理
   - baseURL:"https://api.xxx.com" → 使用配置的域名前缀
   - baseURL不存在 → 使用同源请求

2. AST+正则双模式提取API端点
   
   【正则模式】（快速提取）:
   patterns:
   - r'["\'](/(?:user|auth|admin|login|logout|api|v\d|frame)[^"\']*)["\']'
   - r'axios\.[a-z]+\(["\']([^"\']+)["\']'
   - r'fetch\(["\']([^"\']+)["\']'
   - r'\.get\(["\']([^"\']+)["\']'
   - r'\.post\(["\']([^"\']+)["\']'
   
   【AST模式】（深度提取）:
   - 使用esprima.parse()解析JS AST
   - 提取所有字符串字面量
   - 从字符串字面量中筛选API路径
   
   【重要】发现API后深入分析来源JS:
   → 记录API所在的JS文件名
   → 深度分析该JS文件（用curl下载）:
      - 获取完整JS内容（可能有混淆，需多次提取）
      - 使用AST+正则双模式提取所有API路径
      - 提取敏感信息（API密钥、硬编码凭证等）
      - 提取URL模板（如 /user/${userId}/info）

3. 【新增】敏感信息提取
   从JS/响应中提取:
   - IP地址: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
   - 外部域名: 从URL中提取netloc
   - 凭证信息:
     * api_key, secret_key: r'(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*["\']([^"\']+)["\']'
     * token: r'(?:access[_-]?token|Bearer)\s+([a-zA-Z0-9\-_\.]+)'
     * password: r'password\s*[:=]\s*["\']([^"\']+)["\']'

4. 提取环境变量配置
   patterns:
   - r'VUE_APP_\w+'
   - r'process\.env\.(\w+)'
   
5. 提取URL模板字符串
   patterns:
   - r'`[^`]*(?:api|user|auth|admin)[^`]*`'
```

**阶段3：JS深度分析（AST+正则双模式提取）**
```
【关键】必须使用AST+正则双模式进行深度分析

1. 提取baseURL配置（最优先！）
   patterns:
   - r'baseURL\s*[:=]\s*["\']([^"\']+)["\']'
   - r'axios\.create\s*\(\s*\{([^}]+)\}'
   
   重要发现：
   - baseURL:"" 为空 → 使用相对路径 + nginx代理
   - baseURL:"https://api.xxx.com" → 使用配置的域名前缀
   - baseURL不存在 → 使用同源请求

2. AST+正则双模式提取API端点
   
   正则模式（快速提取）:
   patterns:
   - r'["\'](/(?:user|auth|admin|login|logout|api|v\d|frame)[^"\']*)["\']'
   - r'axios\.[a-z]+\(["\']([^"\']+)["\']'
   - r'fetch\(["\']([^"\']+)["\']'
   - r'\.get\(["\']([^"\']+)["\']'
   - r'\.post\(["\']([^"\']+)["\']'
   
   【重要】发现API后深入分析来源JS:
   → 记录API所在的JS文件名
   → 深度分析该JS文件（用curl下载）:
      - 获取完整JS内容（可能有混淆，需多次提取）
      - 提取所有API路径（不仅限正则匹配到的）
      - 提取敏感信息（API密钥、硬编码凭证等）
      - 提取URL模板（如 /user/${userId}/info）

3. 提取环境变量配置
   patterns:
   - r'VUE_APP_\w+'
   - r'process\.env\.(\w+)'
   
4. 提取URL模板字符串
   patterns:
   - r'`[^`]*(?:api|user|auth|admin)[^`]*`'
```

**阶段4：API测试**
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
   
4. 记录认证要求
   - 401/403 → 需要认证（正常）
   - 200 + JSON → 检查是否未授权

【重要】发现Swagger/接口文档时:
→ 立即访问获取更多API
→ 解析Swagger JSON获取完整API列表
→ 对获取的API立即进行漏洞测试
```

**阶段5：漏洞验证（10维度）**
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

### SPA采集流程检查清单

```
□ 阶段1: 基础探测
   □ 目标可访问
   □ 技术栈识别完成
   □ 判断为SPA应用
   □ 检查Swagger/接口文档

□ 阶段2: JS采集
   □ Playwright无头浏览器启动
   □ wait_until="networkidle"
   □ 额外等待3-5秒
   □ 获取所有JS文件列表
   □ 拦截API请求（XHR/Fetch）
   □ 采集响应头（Server、IP、域名）
   □ 采集localStorage敏感信息

□ 阶段3: JS分析（AST+正则双模式）
   □ 提取baseURL配置
   □ AST模式解析JS字符串字面量
   □ 正则模式提取API路径
   □ 提取环境变量
   □ 提取URL模板
   □ 【新增】提取IP地址
   □ 【新增】提取外部域名
   □ 【新增】提取敏感凭证
   □ 【新增】深度分析来源JS文件

□ 阶段4: API测试
   □ 确定base_path（配置→反推→字典）
   □ 逐个测试API端点
   □ 区分JSON/HTML响应
   □ 测试POST登录接口
   □ 发现Swagger立即解析

□ 阶段5: 漏洞验证
   □ 10维度验证
   □ 排除SPA路由误报
   □ 确认或排除漏洞
```

### 遇到加密/混淆的数据时

```
思考：
- 能解密吗？ → 查看前端JS代码
- 有密钥泄露吗？ → 检查响应、注释
- 能绕过吗？ → 不带加密参数试试
```

### 遇到验证码/限流时

```
思考：
- 验证码能绕过吗？ → 改参数、删cookie
- 限流能绕过吗？ → 改IP、延时
- 有风控吗？ → 行为异常检测
```

### 遇到WAP环境时

```
思考：
- 需要Cookie吗？ → 保持session
- 需要Referer吗？ → 添加来源
- 需要特定Header吗？ → 复制正常请求头
```

---

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
│   ├── js_collector.py           # JS采集（基础版）
│   ├── browser_collector.py      # 浏览器采集（基础版）
│   ├── url_collector.py          # URL采集
│   └── api_path_finder.py        # API路径发现
├── analyzers/                     # 分析能力
│   ├── api_parser.py             # API端点解析
│   ├── response_analyzer.py       # 响应类型分析
│   ├── sensitive_finder.py        # 敏感信息发现
│   └── sensitive_finder.py       # 敏感信息发现
├── testers/                       # 测试能力
│   ├── sqli_tester.py           # SQL注入测试
│   ├── idor_tester.py           # 越权测试
│   ├── auth_tester.py           # 认证测试
│   ├── jwt_tester.py            # JWT测试
│   ├── fuzz_tester.py           # 模糊测试
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
    ├── advanced_recon.py        # 高级侦察（子域名/Swagger）
    ├── agentic_analyzer.py       # 智能分析
    ├── dynamic_api_analyzer.py  # 动态API分析
    ├── deep_api_tester_v35.py  # 深度测试v35
    ├── deep_api_tester_v55.py  # 深度测试v55
    ├── cloud_storage_tester.py  # 云存储测试
    ├── context_manager.py       # 上下文管理
    ├── orchestrator.py          # 编排器
    ├── reasoning_engine.py      # 推理引擎
    ├── strategy_pool.py        # 策略池
    ├── scan_engine.py          # 扫描引擎
    ├── response_classifier.py  # 响应分类
    ├── models.py               # 数据模型
    ├── skill_executor.py       # Skill执行器
    ├── skill_executor_v2.py    # Skill执行器v2
    ├── skill_executor_v3.py    # Skill执行器v3
    └── testing_loop.py          # 测试循环
```

### 能力池模块参考

| 阶段 | 可用模块 | 路径 | 使用场景 | 必须 |
|------|----------|------|----------|------|
| **采集-发现** | | | 发现API端点时 | |
| | `browser_collect.py` | `core/collectors/browser_collect.py` | SPA应用必须使用，采集JS+API+敏感信息 | ✅ |
| | `js_parser.py` | `core/collectors/js_parser.py` | 从JS提取API，使用AST+正则双模式 | ✅ |
| | `js_collector.py` | `core/collectors/js_collector.py` | 简单JS采集，快速提取 | |
| | `browser_collector.py` | `core/collectors/browser_collector.py` | 浏览器基础采集 | |
| | `http_client.py` | `core/collectors/http_client.py` | 快速HTTP探测，获取HTML/响应头 | |
| | `url_collector.py` | `core/collectors/url_collector.py` | 批量URL收集 | |
| | `api_path_finder.py` | `core/collectors/api_path_finder.py` | 从响应/JS中自动发现API路径 | |
| | `advanced_recon.py` | `core/advanced_recon.py` | 发现Swagger/子域名枚举，批量资产发现 | |
| **采集-敏感信息** | | | 发现敏感信息泄露时 | |
| | `sensitive_finder.py` | `core/analyzers/sensitive_finder.py` | 提取password/token/密钥等敏感字段 | |
| | `response_analyzer.py` | `core/analyzers/response_analyzer.py` | 分析响应类型，识别JSON/HTML/WAF | |
| **测试-漏洞** | | | 测试具体漏洞类型时 | |
| | `sqli_tester.py` | `core/testers/sqli_tester.py` | SQL注入测试，检测SQL错误 | |
| | `idor_tester.py` | `core/testers/idor_tester.py` | 越权测试，IDOR漏洞检测 | |
| | `auth_tester.py` | `core/testers/auth_tester.py` | 认证绕过测试，弱密码检测 | |
| | `jwt_tester.py` | `core/testers/jwt_tester.py` | JWT漏洞测试，alg:none等 | |
| | `fuzz_tester.py` | `core/testers/fuzz_tester.py` | 参数fuzzing，模糊测试 | |
| | `api_fuzzer.py` | `core/api_fuzzer.py` | API端点fuzzing，参数挖掘 | |
| | `browser_tester.py` | `core/browser_tester.py` | DOM XSS，浏览器环境测试 | |
| | `cloud_storage_tester.py` | `core/cloud_storage_tester.py` | OSS/Bucket安全测试 | |
| **验证** | | | 验证漏洞确认时 | |
| | `vuln_verifier.py` | `core/verifiers/vuln_verifier.py` | 10维度漏洞验证，确认/排除 | ✅ |
| | `response_diff.py` | `core/verifiers/response_diff.py` | 响应对比，排除误报 | |
| **辅助** | | | 支撑能力 | |
| | `base_path_dict.py` | `core/utils/base_path_dict.py` | 找不到baseURL时，fuzzing父路径 | ✅ |
| | `prerequisite.py` | `core/utils/prerequisite.py` | 依赖检查，工具可用性验证 | ✅ |
| **高级/编排** | | | 复杂测试场景 | |
| | `dynamic_api_analyzer.py` | `core/dynamic_api_analyzer.py` | 动态API分析，运行时分析 | |
| | `deep_api_tester_v35.py` | `core/deep_api_tester_v35.py` | 深度测试v35，综合测试 | |
| | `deep_api_tester_v55.py` | `core/deep_api_tester_v55.py` | 深度测试v55，高级测试 | |
| | `context_manager.py` | `core/context_manager.py` | 管理测试上下文，状态维护 | |
| | `orchestrator.py` | `core/orchestrator.py` | 编排多阶段测试流程 | |
| | `reasoning_engine.py` | `core/reasoning_engine.py` | 攻击链推理，漏洞关联 | |
| | `strategy_pool.py` | `core/strategy_pool.py` | 测试策略选择，自适应测试 | |
| | `scan_engine.py` | `core/scan_engine.py` | 扫描编排，批量测试 | |
| | `response_classifier.py` | `core/response_classifier.py` | 响应分类，模式识别 | |
| | `models.py` | `core/models.py` | 数据模型定义 | |
| | `skill_executor.py` | `core/skill_executor.py` | Skill执行主入口 | |
| | `skill_executor_v2.py` | `core/skill_executor_v2.py` | Skill执行器v2 | |
| | `skill_executor_v3.py` | `core/skill_executor_v3.py` | Skill执行器v3 | |
| | `testing_loop.py` | `core/testing_loop.py` | 测试循环，持续测试 | |

### SPA应用采集流程（必须遵循）

```
┌─────────────────────────────────────────────────────────────┐
│ 阶段1: 基础探测                                              │
├─────────────────────────────────────────────────────────────┤
│ 1. HTTP探测: http_client.py → curl探测                      │
│    参考: core/collectors/http_client.py                      │
│                                                              │
│ 2. 技术栈: browser_collect.py → 检测Vue/React/Angular标识      │
│    参考: core/collectors/browser_collect.py                  │
│                                                              │
│ 3. 判断SPA: /api/* 返回HTML → SPA应用                      │
│                                                              │
│ 4. 检查Swagger: advanced_recon.py → 枚举接口文档          │
│    参考: core/advanced_recon.py                            │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段2: JS采集（必须使用Playwright）                          │
├─────────────────────────────────────────────────────────────┤
│ 1. 启动浏览器: browser_collect.py                           │
│    参考: core/collectors/browser_collect.py                  │
│                                                              │
│ 2. 访问目标: page.goto(url, wait_until="networkidle")      │
│                                                              │
│ 3. 等待加载: page.wait_for_timeout(5000)                   │
│                                                              │
│ 4. 提取JS: js_parser.py → 从HTML提取JS文件列表            │
│    参考: core/collectors/js_parser.py                        │
│                                                              │
│ 5. 拦截API: browser_collect.py → 捕获XHR/Fetch请求        │
│    参考: core/collectors/browser_collect.py                  │
│                                                              │
│ 6. 采集敏感信息: sensitive_finder.py → localStorage/响应头│
│    参考: core/analyzers/sensitive_finder.py                │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段3: JS深度分析（AST+正则双模式）                          │
├─────────────────────────────────────────────────────────────┤
│ 1. baseURL配置: js_parser.py → extract_base_urls()        │
│    参考: core/collectors/js_parser.py                       │
│    patterns:                                                │
│    - r'baseURL\s*[:=]\s*["\']([^"\']+)["\']'             │
│    - r'axios\.create\s*\(\s*\{([^}]+)\}'                  │
│                                                              │
│ 2. API路径提取:                                              │
│    → js_parser.py → extract_api_patterns() (正则)         │
│    → js_parser.py → extract_with_ast() (AST)               │
│    参考: core/collectors/js_parser.py                         │
│                                                              │
│ 3. 敏感信息: sensitive_finder.py → 提取IP/域名/凭证        │
│    参考: core/analyzers/sensitive_finder.py                  │
│                                                              │
│ 4. base_path获取: base_path_dict.py → get_base_path...     │
│    参考: core/utils/base_path_dict.py                        │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段4: API测试                                               │
├─────────────────────────────────────────────────────────────┤
│ 1. base_path拼接: base_path_dict.py → generate_fuzz_paths() │
│    参考: core/utils/base_path_dict.py                        │
│                                                              │
│ 2. SQL注入: sqli_tester.py → 测试SQL注入                    │
│    参考: core/testers/sqli_tester.py                        │
│                                                              │
│ 3. 越权测试: idor_tester.py → 测试IDOR                     │
│    参考: core/testers/idor_tester.py                         │
│                                                              │
│ 4. 认证测试: auth_tester.py → 测试认证绕过                   │
│    参考: core/testers/auth_tester.py                        │
│                                                              │
│ 5. JWT测试: jwt_tester.py → 测试JWT漏洞                    │
│    参考: core/testers/jwt_tester.py                         │
│                                                              │
│ 6. Fuzzing: fuzz_tester.py → 参数fuzzing                  │
│    参考: core/testers/fuzz_tester.py                        │
│                                                              │
│ 7. 发现Swagger: advanced_recon.py → 解析获取完整API       │
│    参考: core/advanced_recon.py                            │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段5: 漏洞验证（10维度）                                     │
├─────────────────────────────────────────────────────────────┤
│ 1. vuln_verifier.py → 10维度验证                            │
│    参考: core/verifiers/vuln_verifier.py                    │
│                                                              │
│ 2. response_diff.py → 响应对比排除误报                     │
│    参考: core/verifiers/response_diff.py                    │
│                                                              │
│ 3. response_analyzer.py → 响应类型分析                     │
│    参考: core/analyzers/response_analyzer.py                │
└─────────────────────────────────────────────────────────────┘
```

### 完整模块参考（按阶段分类）

---

## 一、采集阶段（Collector）

| 模块 | 路径 | 功能描述 |
|------|------|---------|
| `http_client.py` | `core/collectors/http_client.py` | HTTP请求客户端，支持GET/POST/HEAD等，用于快速探测目标、获取响应头 |
| `js_parser.py` | `core/collectors/js_parser.py` | JS源码解析，AST+正则双模式提取API路径、baseURL、敏感信息、IP/域名 |
| `browser_collect.py` | `core/collectors/browser_collect.py` | Playwright无头浏览器采集，捕获XHR/Fetch请求、JS文件、localStorage、响应头 |
| `js_collector.py` | `core/collectors/js_collector.py` | 简单JS采集器，快速提取HTML中的JS文件列表 |
| `browser_collector.py` | `core/collectors/browser_collector.py` | 浏览器采集基础版，模拟浏览器行为 |
| `url_collector.py` | `core/collectors/url_collector.py` | URL采集器，批量收集页面中的链接和URL |
| `api_path_finder.py` | `core/collectors/api_path_finder.py` | API路径发现，从响应/JS中自动发现API端点 |

---

## 二、分析阶段（Analyzer）

| 模块 | 路径 | 功能描述 |
|------|------|---------|
| `api_parser.py` | `core/analyzers/api_parser.py` | API端点解析，提取路径、方法、参数、请求体格式 |
| `response_analyzer.py` | `core/analyzers/response_analyzer.py` | 响应类型分析，区分JSON/HTML/WAF，判断响应是否正常 |
| `sensitive_finder.py` | `core/analyzers/sensitive_finder.py` | 敏感信息发现，提取password/token/密钥/IP/域名/凭证 |
| `dynamic_api_analyzer.py` | `core/dynamic_api_analyzer.py` | 动态API分析，运行时分析和行为追踪 |
| `agentic_analyzer.py` | `core/agentic_analyzer.py` | 智能分析，AI驱动的漏洞模式识别 |
| `smart_analyzer.py` | `core/smart_analyzer.py` | 智能分析，启发式漏洞检测 |
| `response_classifier.py` | `core/response_classifier.py` | 响应分类，模式匹配和分类 |

---

## 三、测试阶段（Tester）

| 模块 | 路径 | 功能描述 |
|------|------|---------|
| `sqli_tester.py` | `core/testers/sqli_tester.py` | SQL注入测试，检测SQL错误、布尔盲注、时间盲注 |
| `idor_tester.py` | `core/testers/idor_tester.py` | 越权测试（IDOR），检测水平/垂直越权漏洞 |
| `auth_tester.py` | `core/testers/auth_tester.py` | 认证测试，检测弱密码、暴力破解、认证绕过 |
| `jwt_tester.py` | `core/testers/jwt_tester.py` | JWT测试，检测alg:none、签名弱密钥、token泄露 |
| `fuzz_tester.py` | `core/testers/fuzz_tester.py` | 参数fuzzing，模糊测试发现隐藏参数 |
| `api_fuzzer.py` | `core/api_fuzzer.py` | API端点fuzzing，参数挖掘和边界测试 |
| `browser_tester.py` | `core/browser_tester.py` | 浏览器测试，DOM XSS、客户端漏洞检测 |
| `cloud_storage_tester.py` | `core/cloud_storage_tester.py` | 云存储测试，OSS/Bucket权限配置错误检测 |
| `deep_api_tester_v35.py` | `core/deep_api_tester_v35.py` | 深度测试v35，综合漏洞测试 |
| `deep_api_tester_v55.py` | `core/deep_api_tester_v55.py` | 深度测试v55，高级测试场景 |
| `testing_loop.py` | `core/testing_loop.py` | 测试循环，持续迭代测试 |

---

## 四、验证阶段（Verifier）

| 模块 | 路径 | 功能描述 |
|------|------|---------|
| `vuln_verifier.py` | `core/verifiers/vuln_verifier.py` | 10维度漏洞验证，确认/排除漏洞，输出验证报告 |
| `response_diff.py` | `core/verifiers/response_diff.py` | 响应差异对比，排除误报，确定真实漏洞 |

---

## 五、辅助阶段（Utils）

| 模块 | 路径 | 功能描述 |
|------|------|---------|
| `base_path_dict.py` | `core/utils/base_path_dict.py` | API base path字典，找不到baseURL时fuzzing父路径 |
| `payload_lib.py` | `core/utils/payload_lib.py` | Payload库，SQL注入、XSS、命令注入等Payload集合 |
| `prerequisite.py` | `core/utils/prerequisite.py` | 依赖检查，验证工具可用性 |

---

## 六、高级能力（Advanced）

| 模块 | 路径 | 功能描述 |
|------|------|---------|
| `advanced_recon.py` | `core/advanced_recon.py` | 高级侦察，Swagger/子域名枚举、批量资产发现 |
| `context_manager.py` | `core/context_manager.py` | 上下文管理，测试状态维护、会话管理 |
| `orchestrator.py` | `core/orchestrator.py` | 编排器，多阶段测试流程编排 |
| `reasoning_engine.py` | `core/reasoning_engine.py` | 推理引擎，攻击链推理、漏洞关联分析 |
| `strategy_pool.py` | `core/strategy_pool.py` | 策略池，测试策略选择、自适应测试 |
| `scan_engine.py` | `core/scan_engine.py` | 扫描引擎，批量扫描编排 |
| `models.py` | `core/models.py` | 数据模型，测试结果/漏洞数据结构定义 |
| `skill_executor.py` | `core/skill_executor.py` | Skill执行器主入口 |
| `skill_executor_v2.py` | `core/skill_executor_v2.py` | Skill执行器v2 |
| `skill_executor_v3.py` | `core/skill_executor_v3.py` | Skill执行器v3 |
| `runner.py` | `core/runner.py` | 测试运行器 |
| `api_interceptor.py` | `core/api_interceptor.py` | API拦截器，请求/响应拦截修改 |

---

### 场景→模块映射（按阶段）

| 阶段 | 场景 | 推荐模块 | 路径 |
|------|------|---------|------|
| **采集** | SPA应用发现API | `browser_collect.py` + `js_parser.py` | `core/collectors/` |
| **采集** | 快速探测目标 | `http_client.py` | `core/collectors/http_client.py` |
| **采集** | JS采集（简单） | `js_collector.py` | `core/collectors/js_collector.py` |
| **采集** | 浏览器采集（简单） | `browser_collector.py` | `core/collectors/browser_collector.py` |
| **采集** | URL批量采集 | `url_collector.py` | `core/collectors/url_collector.py` |
| **采集** | API路径自动发现 | `api_path_finder.py` | `core/collectors/api_path_finder.py` |
| **采集** | Swagger/子域名 | `advanced_recon.py` | `core/advanced_recon.py` |
| **分析** | 响应类型分析 | `response_analyzer.py` | `core/analyzers/response_analyzer.py` |
| **分析** | 敏感信息发现 | `sensitive_finder.py` | `core/analyzers/sensitive_finder.py` |
| **分析** | API端点解析 | `api_parser.py` | `core/analyzers/api_parser.py` |
| **分析** | 动态API分析 | `dynamic_api_analyzer.py` | `core/dynamic_api_analyzer.py` |
| **分析** | 响应分类 | `response_classifier.py` | `core/response_classifier.py` |
| **分析** | 智能分析 | `agentic_analyzer.py` / `smart_analyzer.py` | `core/` |
| **测试** | SQL注入测试 | `sqli_tester.py` | `core/testers/sqli_tester.py` |
| **测试** | 越权测试 | `idor_tester.py` | `core/testers/idor_tester.py` |
| **测试** | 认证绕过测试 | `auth_tester.py` | `core/testers/auth_tester.py` |
| **测试** | JWT漏洞测试 | `jwt_tester.py` | `core/testers/jwt_tester.py` |
| **测试** | 参数fuzzing | `fuzz_tester.py` | `core/testers/fuzz_tester.py` |
| **测试** | API端点fuzzing | `api_fuzzer.py` | `core/api_fuzzer.py` |
| **测试** | DOM XSS测试 | `browser_tester.py` | `core/browser_tester.py` |
| **测试** | OSS/Bucket测试 | `cloud_storage_tester.py` | `core/cloud_storage_tester.py` |
| **测试** | 深度综合测试 | `deep_api_tester_v55.py` | `core/deep_api_tester_v55.py` |
| **测试** | 持续测试循环 | `testing_loop.py` | `core/testing_loop.py` |
| **验证** | 漏洞验证（10维度） | `vuln_verifier.py` | `core/verifiers/vuln_verifier.py` |
| **验证** | 响应对比排除误报 | `response_diff.py` | `core/verifiers/response_diff.py` |
| **辅助** | base_path缺失 | `base_path_dict.py` | `core/utils/base_path_dict.py` |
| **辅助** | Payload库 | `payload_lib.py` | `core/utils/payload_lib.py` |
| **辅助** | 依赖检查 | `prerequisite.py` | `core/utils/prerequisite.py` |
| **编排** | 上下文管理 | `context_manager.py` | `core/context_manager.py` |
| **编排** | 测试编排 | `orchestrator.py` / `scan_engine.py` | `core/` |
| **编排** | 攻击链推理 | `reasoning_engine.py` | `core/reasoning_engine.py` |
| **编排** | 策略选择 | `strategy_pool.py` | `core/strategy_pool.py` |
| **执行** | Skill执行 | `skill_executor*.py` | `core/skill_executor*.py` |
| **执行** | API拦截 | `api_interceptor.py` | `core/api_interceptor.py` |
| **执行** | 批量测试执行 | `runner.py` | `core/runner.py` |
| **数据** | 数据模型 | `models.py` | `core/models.py` |
| **测试** | 深度综合测试v35 | `deep_api_tester_v35.py` | `core/deep_api_tester_v35.py` |

### Base Path获取完整流程

```
【优先级1】从JS配置中获取
├── axios.create配置中的baseURL值
├── VUE_APP_API环境变量
└── process.env.APP_API配置

【优先级2】从nginx反向代理推断
├── 响应头Server字段分析
├── 从已发现API路径反推父路径
└── get_base_path_candidates(discovered_path)

【优先级3】使用base_path_dict字典
├── COMMON_API_PREFIXES: ["/api", "/webapi", "/auth", ...]
├── generate_fuzz_paths(api, prefixes)
└── 对每个候选路径进行测试验证

【使用示例】
from core.utils.base_path_dict import get_base_path_candidates, generate_fuzz_paths

# 从发现的API路径获取候选base_path
candidates = get_base_path_candidates("/api/v1/user/login")
# 结果: ["/api/v1", "/api", "/"]

# 生成fuzzing路径
fuzz_paths = generate_fuzz_paths("user/login")
# 结果: ["/api/user/login", "/webapi/user/login", ...]
```
┌─────────────────────────────────────────────────────────────┐
│ 阶段1: 基础探测                                              │
├─────────────────────────────────────────────────────────────┤
│ 1. HTTP探测: curl -I http://target.com                      │
│ 2. 技术栈: 检查HTML中Vue/React/Angular标识                   │
│ 3. 判断SPA: /api/* 返回HTML → SPA应用                        │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段2: JS采集（必须使用Playwright）                          │
├─────────────────────────────────────────────────────────────┤
│ 1. 启动浏览器: sync_playwright()                             │
│ 2. 访问目标: page.goto(url, wait_until="networkidle")       │
│ 3. 等待加载: page.wait_for_timeout(5000)                    │
│ 4. 提取JS: re.findall(r'<script[^>]+src=["\']([^"\']+)')   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段3: JS深度分析（必须分析每个JS文件）                       │
├─────────────────────────────────────────────────────────────┤
│ 1. baseURL配置:                                             │
│    patterns:                                                │
│    - r'baseURL\s*[:=]\s*["\']([^"\']+)["\']'               │
│    - r'axios\.create\s*\(\s*\{([^}]+)\}'                   │
│    关键发现: baseURL:"" 为空 → 相对路径                      │
│                                                              │
│ 2. API路径:                                                 │
│    patterns:                                                │
│    - r'["\'](/(?:user|auth|admin|login)[^"\']*)["\']'       │
│    - r'axios\.[a-z]+\(["\']([^"\']+)["\']'                 │
│                                                              │
│ 3. 环境变量:                                                 │
│    patterns:                                                 │
│    - r'VUE_APP_\w+'                                         │
│    - r'process\.env\.(\w+)'                                 │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段4: API测试                                               │
├─────────────────────────────────────────────────────────────┤
│ 1. 逐个测试发现的API端点                                      │
│ 2. GET: 检查Content-Type → JSON=真实API, HTML=SPA路由       │
│ 3. POST: 测试登录接口 → SQL注入/XSS                         │
│ 4. 记录: 401/403=需认证, 200+JSON=检查是否未授权             │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 阶段5: 漏洞验证（10维度）                                     │
├─────────────────────────────────────────────────────────────┤
│ □ 维度1: 响应类型    □ 维度2: 状态码     □ 维度3: 响应长度     │
│ □ 维度4: WAF拦截    □ 维度5: 敏感信息    □ 维度6: 一致性      │
│ □ 维度7: SQL注入     □ 维度8: IDOR        □ 维度9: 认证绕过   │
│ □ 维度10: 信息泄露                                              │
└─────────────────────────────────────────────────────────────┘
```

### 关键配置发现对照表

| baseURL值 | 含义 | 架构 |
|-----------|------|------|
| `""` (空) | 相对路径 | nginx反向代理到后端 |
| `"https://api.xxx.com"` | 绝对路径 | 前端直接调用独立API |
| 不存在 | 同源请求 | 后端在同一域名下 |

### 调用原则

```
1. 按需选择：不是所有模块都要用
2. 动态调整：根据目标调整测试策略
3. 灵活组合：发现问题时追加测试模块
4. 渐进式：先轻量后深度
5. 自主编写：特殊情况下可直接编写测试脚本
6. 扩展能力：基于能力池编写扩展脚本
7. 验证优先：发现异常先验证再报告
```

### 能力输入输出规范

**采集能力：**
```
http_client: 输入{url, method, headers, body} → 输出{status, headers, body, elapsed}
js_parser: 输入{html, js_urls, base_url} → 输出{api_patterns, base_urls,tokens, endpoints}
browser_collect: 输入{url, wait_until, interact} → 输出{apis, storage, forms, page_title}
```

**分析能力：**
```
response_analyzer: 输入{response, expected_type} → 输出{type, is_suspicious,sensitive_fields, parsed_json}
sensitive_finder: 输入{content, check_fields} → 输出{found, severity}
```

**测试能力：**
```
sqli_tester: 输入{target_url, method, param_name, payloads} → 输出{vulnerable, payload_used, error_detected}
idor_tester: 输入{target_url, param_name, test_ids, auth_token} → 输出{vulnerable, leaked_ids, severity}
auth_tester: 输入{login_url, test_mode, max_attempts} → 输出{vulnerable, bypass_payload, weak_credential}
```

**验证能力：**
```
vuln_verifier: 输入{type, original_request, suspicious_response} → 输出{verified, is_false_positive, reason, dimensions}
```

### 能力组合模式

```
SPA应用：browser_collect → api_parser → idor_tester → vuln_verifier (10维度验证)
传统Web：http_client → js_parser → sqli_tester → vuln_verifier
高安全目标：browser_collect → response_analyzer → fuzz_tester (低速) → vuln_verifier
快速扫描：http_client → response_analyzer → sqli_tester → vuln_verifier
```

---

## examples/ 目录结构

```
examples/                              # 组合示例
├── usage-examples.md                   # 基础使用示例
├── target-based-combos.md            # 按目标组合示例
│   ├── 示例1: SPA应用完整测试链
│   ├── 示例2: 传统Web API快速扫描
│   ├── 示例3: 高安全性目标测试
│   ├── 示例4: 按漏洞类型选择能力
│   └── 示例5: 自定义能力组合
└── vulnerability-chain.md           # 攻击链组合
```

### 按目标类型组合

| 目标 | 发现 | 分析 | 测试 | 验证 |
|------|------|------|------|------|
| SPA应用 | browser_collect | api_parser, response_analyzer | idor_tester, sqli_tester | vuln_verifier (10维度) |
| 传统Web | http_client, js_parser | api_parser | sqli_tester, auth_tester | vuln_verifier |
| 高安全目标 | browser_collect | response_analyzer | fuzz_tester (低速) | response_diff |
| 快速扫描 | http_client | response_analyzer | sqli_tester | vuln_verifier |
| GraphQL | browser_collect | graphql_parser | sqli_tester (GraphQL专用) | vuln_verifier |

---

## references/ 目录结构

```
references/                              # 参考资料
├── rest-guidance.md                    # REST API测试指导
├── graphql-guidance.md                # GraphQL测试指导
├── severity-model.md                  # 漏洞评级模型
├── validation.md                      # 验证方法论
├── asset-discovery.md                # 资产发现指导
├── test-matrix.md                    # 测试矩阵
└── report-template.md                # 报告模板
```

---

## resources/ 目录结构

```
resources/                              # 资源文件
├── sqli.json                         # SQL注入Payload库
├── xss.json                         # XSS Payload库
└── dom_xss.json                     # DOM XSS Payload库
```

---

## templates/ 目录结构

```
templates/                              # 测试模板
├── api_test.yaml                     # API测试模板
├── auth_test.yaml                    # 认证测试模板
└── vuln_scan.yaml                    # 漏洞扫描模板
```

---

完成测试后，按以下格式报告：

```markdown
## 测试概要

| 项目 | 数量 |
|------|------|
| 扫描目标 | xxx |
| 发现可疑点 | x |
| 验证确认 | x |
| 排除误报 | x |

## 能力使用记录

| 阶段 | 使用能力 | 输入 | 输出 |
|------|----------|------|------|
| 采集 | browser_collect | url=xxx | apis=[...] |
| 分析 | response_analyzer | status=200, body=... | type=json |
| 测试 | idor_tester | userId=[1,2] | vulnerable=true |
| 验证 | vuln_verifier (10维度) | type=idor | verified=true |

## 漏洞列表

| 编号 | 类型 | 严重性 | 端点 | PoC | 验证维度 |
|------|------|--------|------|-----|---------|
| 1 | 敏感信息泄露 | HIGH | /api/user/info | GET /api/user/info 返回password字段 | 维度1,5,10 |
| 2 | IDOR | HIGH | /api/order/list | GET /api/order/list?userId=123 | 维度1,3,6,8 |

## 验证维度详情

| 漏洞 | 维度1响应类型 | 维度3长度 | 维度5敏感信息 | 维度8业务数据 |
|------|-------------|---------|-------------|-------------|
| #1 | json ✓ | 正常 ✓ | password泄露 ✓ | - |
| #2 | json ✓ | 正常 ✓ | - | userId泄露 ✓ |

## 误报记录

| 可疑点 | 初步判断 | 验证维度 | 排除原因 |
|--------|----------|----------|----------|
| /api/admin/users返回200 | 可能未授权 | 维度1,4,6 | 返回HTML页面+WAF特征，是WAF拦截页 |

## 漏洞链构造

### 攻击链1
1. 用户枚举：GET /api/user/check?phone=138xxx → 获取userId
2. 订单查询：GET /api/order/list?userId=xxx → 获取orderNo  
3. 退款操作：POST /api/refund?orderNo=xxx&amount=0.01 → 退款成功

## 修复建议

1. 删除响应中的password字段
2. 添加userId归属校验
3. 退款接口添加权限校验
```

---

## 总结

### 核心思维

1. **不只是测试，要理解** - 理解接口在做什么
2. **不只是单个漏洞，要构造链** - 发现一个点，思考能做什么
3. **不只是工具，要用脑子** - 思考攻击者会怎么做
4. **不只是发现，要验证** - 确认漏洞真实存在（10维度验证）
5. **不只是利用，要闭环** - 发现→分析→验证→确认/排除

### 检测口诀

```
看到接口想认证
看到认证想绕过
看到数据想遍历
看到金额想篡改
看到用户想枚举
看到订单想越权
看到token想泄露
看到修改想权限
看到异常想验证
看到200想确认
```

### 验证口诀（10维度）

```
维度1看类型：JSON业务HTML拦截
维度2看状态：200成功4xx客户端
维度3看长度：过短拦截过长数据
维度4看WAF：安全设备特征识别
维度5看敏感：password token secret
维度6看一致：多次请求是否同
维度7SQL注入：错误特征要确认
维度8用户数据：业务信息才真实
维度9认证绕过：token返回才算
维度10信息泄露：非公开信息才算
```

---

## 参考资源

如有疑问，可参考：
- OWASP API Security Top 10 - `references/`
- REST API测试指导 - `references/rest-guidance.md`
- GraphQL测试指导 - `references/graphql-guidance.md`
- 漏洞评级模型 - `references/severity-model.md`
- 验证方法论 - `references/validation.md`
- Payload库 - `resources/*.json`
- 测试模板 - `templates/*.yaml`
- 使用示例 - `examples/`