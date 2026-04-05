# API Security Testing Examples

## 快速开始

### 1. 基础扫描

```
@api-cyber-supervisor 对 https://example.com 进行全面安全扫描
```

### 2. 针对特定端点扫描

```
@api-cyber-supervisor 扫描 https://api.example.com/v1 端点
```

### 3. 使用工具直接扫描

```
api_security_scan target="https://api.example.com" scan_type="full"
```

---

## 工具使用示例

### 浏览器采集

```
browser_collect url="https://example.com"
```

### SQL 注入测试

```
sqli_test endpoint="https://api.example.com/user?id=1" param="id"
```

### IDOR 测试

```
idor_test endpoint="https://api.example.com/user/1" resource_id="1"
```

### GraphQL 测试

```
graphql_test endpoint="https://api.example.com/graphql"
```

### 云存储测试

```
cloud_storage_test bucket_url="https://bucket.s3.amazonaws.com"
```

---

## Agent 委派示例

### 使用 Cyber Supervisor

```
@api-cyber-supervisor 
对 https://api.example.com 进行完整的安全测试
包含以下漏洞测试：
- SQL 注入
- IDOR 越权
- JWT 安全
- 敏感数据泄露
```

### 使用资源探测专家

```
@api-resource-specialist
发现 https://example.com 的所有 API 端点
重点关注：
- 认证相关端点
- 用户数据端点
- 支付相关端点
```

### 使用漏洞挖掘专家

```
@api-probing-miner
针对发现的端点进行漏洞挖掘
优先测试：
- SQL 注入
- XSS
- IDOR
```

### 使用漏洞验证专家

```
@api-vuln-verifier
验证以下漏洞：
- 类型: SQL 注入
- 端点: https://api.example.com/user?id=1
```

---

## 报告输出示例

当扫描完成时，会输出类似以下的报告：

```markdown
## 安全测试报告

### 目标信息
- URL: https://api.example.com
- 端点总数: 42
- 发现漏洞: 5

### 漏洞详情
| # | 类型 | 端点 | 严重程度 |
|---|------|------|---------|
| 1 | SQL注入 | /api/user?id=1 | HIGH |
| 2 | IDOR | /api/user/:id | MEDIUM |
| 3 | 敏感数据 | /api/config | LOW |

### PoC
curl "https://api.example.com/api/user?id=1'%20OR%201=1--"
```
