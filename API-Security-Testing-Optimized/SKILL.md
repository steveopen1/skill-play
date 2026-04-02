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

> **核心定位**：模块化的 API 安全测试框架，提供检测能力配置而非硬编码脚本。
>
> **AI 指导原则**：
> - 本 Skill 定义了检测思路和配置，AI 应参考配置灵活执行
> - 各模块独立，可根据目标特点选择合适的检测组合
> - 脚本仅作参考，实际使用应灵活组合

---

## 执行决策配置

```yaml
execution_flow:
  - phase: 0_prerequisites
    modules: [prerequisite_checker]
    always: true

  - phase: 1_asset_discovery
    stages:
      - name: static_analysis
        modules: [api_parser]
        always: true
        
      - name: site_type_detection
        modules: [site_type_detector]
        always: true
        
      - name: parent_path_probing
        modules: [api_parser]
        always: true
        
      - name: dynamic_analysis
        modules: [dynamic_api_analyzer]
        condition: "site_type in ['modern_spa', 'jquery_spa'] AND playwright_available"
        
      - name: api_hook
        modules: [api_interceptor]
        condition: "playwright_available AND (has_real_api OR has_dynamic_endpoints)"

  - phase: 2_vulnerability_testing
    modules: [vulnerability_test_suite]
    condition: "has_real_api OR has_dynamic_endpoints"

  - phase: 3_cloud_storage
    modules: [cloud_storage_tester]
    always: true

  - phase: 4_report
    modules: [reporter]
    always: true
```

---

## 漏洞检测配置 (vulnerability_detection_config)

### 1. SQL 注入检测

```yaml
sql_injection:
  name: "SQL Injection"
  severity: CRITICAL
  
  # 检测思路
  approach: |
    1. 识别参数化端点 (id, page, userId 等)
    2. 发送 SQL 注入 payload
    3. 检查响应中的 SQL 错误信息
    
  # 测试 payload
  payloads:
    - "' OR '1'='1"
    - "' OR '1'='1' --"
    - "' OR '1'='1' #"
    - "1' OR '1'='1"
    - "' OR ''='"
    
  # 检测特征
  error_patterns:
    - "sql syntax"
    - "sql error"
    - "mysql"
    - "oracle"
    - "sqlite"
    - "sqlstate"
    - "postgresql"
    - "syntax error"
    - "microsoft sql"
    - "odbc"
    - "ora-"
    - "pgsql"
    
  # 排除规则
  exclude:
    - content_type: "text/html"  # HTML响应跳过
    - status_code: [301, 302, 404]  # 跳转和不存在跳过
      
  # 适用端点
  target_params:
    - id
    - page
    - pageNum
    - pageSize
    - userId
    - type
    - category
    - search
    - q
```

### 2. 未授权访问检测

```yaml
unauthorized_access:
  name: "Unauthorized Access"
  severity: HIGH
  
  approach: |
    1. 识别敏感端点 (admin, user, config, system 等)
    2. 不携带认证信息直接访问
    3. 检查是否返回敏感数据或管理功能
    
  # 敏感路径模式
  sensitive_patterns:
    - "/admin"
    - "/user/list"
    - "/user/export"
    - "/user/delete"
    - "/config"
    - "/system"
    - "/manage"
    - "/dashboard"
    - "/api/users"
    - "/permissions"
    - "/roles"
    - "/menu/tree"
    
  # 检测逻辑
  detection:
    - condition: "status_code == 200"
      check: "响应包含敏感字段 (user, admin, password, email, phone, role)"
      severity: HIGH
      
    - condition: "status_code == 401 OR status_code == 403"
      severity: LOW  # 需要认证，正常
      
    - condition: "status_code == 500"
      severity: MEDIUM  # 可能存在未授权访问
```

### 3. 越权访问检测

```yaml
vertical_privilege_escalation:
  name: "Privilege Escalation"
  severity: HIGH
  
  approach: |
    1. 使用低权限账号获取的 token
    2. 尝试访问高权限资源 (admin endpoints)
    3. 检查是否能突破权限限制
    
  # 权限提升路径
  privilege_escalation_paths:
    - "/admin"
    - "/system/admin"
    - "/manage"
    - "/api/admin"
    - "/user/0"  # IDOR 变种
    
  # 检测方式
  detection_approaches:
    - "使用 guest token 访问 user profile"
    - "使用 user token 访问 admin endpoints"
    - "修改资源 ID 访问他人资源"
```

### 4. 敏感信息泄露检测

```yaml
sensitive_data_exposure:
  name: "Sensitive Data Exposure"
  severity: MEDIUM
  
  approach: |
    1. 检查 API 响应是否泄露敏感信息
    2. 识别错误信息中的敏感内容
    3. 检查调试接口是否开放
    
  # 敏感字段
  sensitive_fields:
    - password
    - passwd
    - secret
    - token
    - api_key
    - apikey
    - access_key
    - private_key
    - jwt
    - session
    - ssn
    - credit_card
    - card_number
    - cvv
    
  # 泄露场景
  exposure_scenarios:
    - "响应包含未脱敏的密码"
    - "错误信息泄露数据库结构"
    - "调试接口返回堆栈信息"
    - "API 版本信息暴露"
    
  # 检测逻辑
  detection:
    - "响应 JSON 中包含敏感字段且值非空"
    - "响应头包含 X-Powered-By, Server 等敏感信息"
    - "调试模式开启 (debug=true)"
```

### 5. API 版本发现

```yaml
api_version_discovery:
  name: "API Version Disclosure"
  severity: LOW
  
  approach: |
    1. 探测常见版本路径
    2. 检查响应头中的版本信息
    3. 识别文档和调试端点
    
  # 版本路径模式
  version_paths:
    - "/v1"
    - "/v2"
    - "/v3"
    - "/api/v1"
    - "/api/v2"
    - "/rest/v1"
    - "/graphql/v1"
    
  # 敏感端点
  sensitive_endpoints:
    - "/swagger"
    - "/swagger-ui"
    - "/api-docs"
    - "/v1/api-docs"
    - "/v2/api-docs"
    - "/actuator"
    - "/actuator/health"
    - "/actuator/info"
    - "/debug"
    - "/trace"
    - "/env"
    - "/heapdump"
    
  # 响应头检测
  version_headers:
    - "X-API-Version"
    - "X-Application-Version"
    - "Server"
    - "Powered-By"
```

### 6. 路径遍历检测

```yaml
path_traversal:
  name: "Path Traversal"
  severity: HIGH
  
  approach: |
    1. 识别文件操作端点 (download, upload, export)
    2. 发送路径遍历 payload
    3. 检查是否能读取系统文件
    
  payloads:
    - "../../../etc/passwd"
    - "..\\..\\..\\windows\\system32\\config\\sam"
    - "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    - "....//....//....//etc/passwd"
    
  # 检测逻辑
  detection:
    - condition: "响应包含 /etc/passwd 内容"
      severity: CRITICAL
    - condition: "响应包含 Windows SAM 文件"
      severity: CRITICAL
    - condition: "status_code == 200 AND 内容包含 root:.*:"
      severity: CRITICAL
```

### 7. 认证绕过检测

```yaml
auth_bypass:
  name: "Authentication Bypass"
  severity: CRITICAL
  
  approach: |
    1. 测试空 token 或无效 token
    2. 测试token篡改 (修改 userId, role)
    3. 测试默认凭据
    4. 测试认证环节缺失
    
  # 测试场景
  test_cases:
    - name: "空Token"
      headers: { "Authorization": "" }
      headers: { "Authorization": "Bearer " }
      
    - name: "无效Token"
      headers: { "Authorization": "Bearer invalid_token_123" }
      
    - name: "Token篡改"
      technique: "修改 payload 中的 userId 为其他用户ID"
      
    - name: "默认凭据"
      common_creds:
        - admin/admin
        - admin/password
        - admin/123456
        - root/root
        - guest/guest
        
    - name: "认证环节缺失"
      check: "敏感操作不需要认证即可执行"
```

### 8. 暴力破解检测

```yaml
brute_force:
  name: "Brute Force Protection"
  severity: MEDIUM
  
  approach: |
    1. 识别登录接口
    2. 发送多次错误密码
    3. 检查是否有账户锁定或验证码
    
  # 登录接口特征
  login_patterns:
    - "/login"
    - "/auth/login"
    - "/signin"
    - "/auth"
    - "/oauth/token"
    
  # 检测逻辑
  detection:
    - "连续5次错误密码后仍可尝试"
      severity: HIGH
    - "无账户锁定机制"
      severity: MEDIUM  
    - "无验证码或IP封锁"
      severity: MEDIUM
```

### 9. CORS 跨域配置错误

```yaml
cors_misconfiguration:
  name: "CORS Misconfiguration"
  severity: MEDIUM
  
  approach: |
    1. 检查 CORS 响应头配置
    2. 测试是否允许任意来源
    3. 检查 credentials 权限过大
    
  # 检测特征
  vulnerable_patterns:
    - "Access-Control-Allow-Origin: *"
    - "Access-Control-Allow-Origin: null"
    - "Access-Control-Allow-Credentials: true"
      combined_with: "Allow-Origin: *"
      
  # 安全配置参考
  secure_config:
    allow_origin: "特定域名"
    allow_credentials: "true (仅当 allow_origin 非 *)"
    allow_methods: "最小必要方法"
    max_age: "合理范围 (如 600)"
```

### 10. 云存储安全检测

```yaml
cloud_storage:
  name: "Cloud Storage Misconfiguration"
  severity: HIGH
  
  approach: |
    1. 识别云存储相关端点
    2. 测试公开访问权限
    3. 检查是否存在敏感数据
    
  # 云存储关键词
  storage_patterns:
    - "oss"
    - "aliyuncs"
    - "aws"
    - "s3"
    - "cos"
    - "qcloud"
    - "bos"
    - "upyun"
    
  # 检测逻辑
  detection:
    - "响应 Content-Type: xml/application"
    - "响应包含 <ListBucketResult>"
    - "响应包含 <AccessControlPolicy>"
      
  # 排除规则
  exclude:
    - content_length < 100  # 太短无意义
    - content_type: "text/html"  # HTML 不是存储响应
```

---

## 认证上下文配置 (authentication_context)

### 支持的认证类型

```yaml
authentication_types:
  - type: "Bearer Token"
    header: "Authorization: Bearer <token>"
    
  - type: "Basic Auth"
    header: "Authorization: Basic <base64(user:pass)>"
    
  - type: "API Key"
    headers:
      - "X-API-Key"
      - "Api-Key"
      - "Authorization"
      
  - type: "JWT"
    detection:
      - "响应包含 JWT token"
      - "token 结构: header.payload.signature"
      
  - type: "Session Cookie"
    detection:
      - "Set-Cookie 头"
      - "JSESSIONID"
      - "SESSION"
```

### 登录流程配置

```yaml
login_flow:
  # 从动态分析获取的登录端点
  login_endpoints_from_dynamic:
    - "/auth/login"
    - "/login"
    - "/api/login"
    - "/personnelWeb/auth/login"
    
  # 登录凭据 (测试用)
  test_credentials:
    - username: "admin"
      password: "admin"
    - username: "admin"  
      password: "123456"
    - username: "test"
      password: "test"
    - username: "guest"
      password: "guest"
      
  # 登录后行为
  post_login_actions:
    - "获取 token/JWT"
    - "保存 session cookie"
    - "提取用户信息"
    - "准备后续认证请求"
```

### 认证上下文使用

```yaml
auth_context_usage:
  # 何时需要认证
  require_auth_for:
    - "/api/user/*"
    - "/api/admin/*"
    - "/api/orders/*"
    - "/api/finance/*"
    
  # 可选认证
  optional_auth_for:
    - "/api/products/*"
    - "/api/articles/*"
    
  # 无需认证
  no_auth_required:
    - "/auth/login"
    - "/public/*"
    - "/health"
```

---

## 端点发现配置 (endpoint_discovery)

### 静态发现

```yaml
static_discovery:
  sources:
    - js_files: "从 JS 文件正则匹配 API 路径"
    - html_files: "从 HTML 提取 href/src"
    - ini_files: "从配置文件提取端点"
    
  # 路径模式
  path_patterns:
    - "/api/[a-z]+"
    - "/v[0-9]/[a-z]+"
    - "/[a-z]+/[a-z]+"
    
  # RESTful 资源推断
  restful_inference:
    - "从 /users 推断: /users/list, /users/add, /users/edit, /users/delete"
    - "从 /orders 推断: /orders/page, /orders/export"
```

### 动态发现

```yaml
dynamic_discovery:
  browser_based: true  # 必须使用 Playwright
  capture_methods:
    - "fetch"
    - "axios"  
    - "xhr"
    - "XMLHttpRequest"
    
  interaction_triggers:
    - "click_login"
    - "click_search"
    - "click_submit"
    - "form_submission"
    - "navigation"
```

### API 前缀提取

```yaml
api_prefix_extraction:
  # 从动态请求自动提取
  from_dynamic:
    - "从 POST /personnelWeb/auth/login 提取 /personnelWeb"
    - "从 GET /api/v1/users 提取 /api/v1"
    
  # 常见前缀
  common_prefixes:
    - "/api"
    - "/api/v1"
    - "/api/v2"
    - "/prod-api"
    - "/admin-api"
    - "/personnelWeb"
    - "/system"
```

---

## 漏洞测试优先级

```yaml
testing_priority:
  critical:
    - sql_injection
    - auth_bypass
    - vertical_privilege_escalation
      
  high:
    - unauthorized_access
    - path_traversal
    - sensitive_data_exposure
    - cloud_storage
      
  medium:
    - brute_force
    - cors_misconfiguration
    - api_version_discovery
```

---

## 执行流程图

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
    ├─ [1.1] 静态分析 → JS解析 + 路径提取
    ├─ [1.2] 站点类型检测
    ├─ [1.3] 父路径探测
    ├─ [1.4] 动态分析 (SPA必备)
    └─ [1.5] API Hook (需要认证时)

[阶段 2] 漏洞检测
    │
    ├─ [高优先级] SQL注入检测
    ├─ [高优先级] 认证绕过检测
    ├─ [高优先级] 越权访问检测
    │
    ├─ [中优先级] 未授权访问检测
    ├─ [中优先级] 敏感信息泄露
    ├─ [中优先级] 路径遍历
    ├─ [中优先级] 暴力破解检测
    ├─ [中优先级] CORS配置错误
    │
    └─ [低优先级] API版本发现

[阶段 3] 云存储测试
    │
    └─ 始终执行

[阶段 4] 报告生成
```

---

## 检测逻辑参考 (供 AI 决策)

### SQL 注入检测流程

```
1. 收集端点
   └─ 合并: static + dynamic + hooked endpoints
   
2. 识别参数化端点
   └─ 查找: id, page, userId, search 等参数
   
3. 构造 payload 测试
   └─ 发送: ' OR '1'='1
   
4. 检查响应
   ├─ SQL 错误关键字? → SQL Injection (CRITICAL)
   ├─ 异常响应码? → Potential SQLi (MEDIUM)
   └─ 正常响应? → 无漏洞
   
5. 报告发现
```

### 未授权访问检测流程

```
1. 识别敏感端点
   └─ 匹配: /admin, /user, /config, /system 等
   
2. 发送未认证请求
   └─ 不带 Authorization/token
   
3. 分析响应
   ├─ 200 + 敏感数据? → Unauthorized Access (HIGH)
   ├─ 200 + 无敏感数据? → 可能公开 (LOW)
   ├─ 401/403? → 正常需要认证
   └─ 500? → Potential Issue (MEDIUM)
```

### 认证绕过检测流程

```
1. 识别登录端点
   └─ /auth/login, /login, /oauth/token
   
2. 测试认证绕过
   ├─ 空token: Authorization: ""
   ├─ 无效token: Authorization: "Bearer xxx"
   └─ token篡改: 修改 userId/role in payload
   
3. 尝试敏感操作 (绕过认证后)
   └─ 访问 /admin/*, /user/delete 等
   
4. 检测结果
   ├─ 成功访问 → Auth Bypass (CRITICAL)
   └─ 被拒绝 → 认证正常
```

---

## 核心模块能力池

| 模块 | 能力 | 耗时 | 依赖 | 优先级 |
|-----|------|-----|------|-------|
| `api_parser` | 静态解析 | 快 | requests | 高 |
| `dynamic_api_analyzer` | 浏览器捕获 | 慢 | playwright | 高 |
| `api_interceptor` | 参数拦截 | 慢 | playwright | 中 |
| `api_fuzzer` | 模糊测试 | 中 | requests | 高 |
| `cloud_storage_tester` | 云存储检测 | 快 | requests | 中 |
| `browser_tester` | 浏览器自动化 | 中 | playwright | 中 |

---

## 最佳实践

1. **渐进式测试**: 先快速侦察，再根据发现决定深入测试
2. **优先级驱动**: 先测高危漏洞 (SQL注入、认证绕过)
3. **上下文感知**: 根据目标特点选择检测组合
4. **避免误报**: 严格遵循 exclude 规则
5. **证据完整**: 记录每个发现的 payload 和响应

---

## 异常处理

| 异常 | 处理方式 |
|-----|---------|
| Playwright 不可用 | 使用静态解析 + requests 测试 |
| 动态分析超时 | 使用已捕获结果继续 |
| API Hook 失败 | 使用静态端点 + 猜测参数 |
| 云存储检测误报 | 检查 Content-Type + 响应格式 |
| 认证失败 | 跳过需要认证的测试，记录警告 |

---

## 环境要求

### 必需依赖
- **requests**: HTTP 客户端
- **playwright**: 无头浏览器 (必须)

### 可选平替
- **pyppeteer**: 异步无头浏览器
- **selenium**: 多浏览器自动化
- **MCP**: headless_browser MCP
- **Skill**: headless_browser skill
