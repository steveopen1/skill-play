# 敏感信息泄露测试

## 1. 概述

敏感信息泄露包括 API 响应中包含不应暴露的敏感数据，以及错误消息中泄露的系统内部信息。

**危险等级**: 中

## 2. 敏感字段分类

### 2.1 认证相关

| 字段 | 风险 |
|------|------|
| password | 密码明文 |
| passwordHash | 密码哈希 |
| token | 会话令牌 |
| sessionId | 会话ID |
| refreshToken | 刷新令牌 |
| secretKey | 密钥 |
| apiKey | API密钥 |
| privateKey | 私钥 |

### 2.2 用户信息

| 字段 | 风险 |
|------|------|
| idCard | 身份证号 |
| phone | 手机号 |
| email | 邮箱 |
| address | 地址 |
| bankCard | 银行卡号 |
| realName | 真实姓名 |

### 2.3 金融相关

| 字段 | 风险 |
|------|------|
| balance | 账户余额 |
| credit | 信用额度 |
| salary | 工资 |
| orderNo | 订单号（可预测） |

## 3. 测试方法

### 3.1 登录响应检查

```bash
POST /api/login
{"username": "admin", "password": "xxx"}

# 检查响应是否包含
{
    "code": 200,
    "token": "xxx",          # ← 泄露
    "refreshToken": "xxx",   # ← 泄露
    "expireTime": 3600
}
```

### 3.2 用户信息响应检查

```bash
GET /api/user/info
Headers: {"Authorization": "Bearer xxx"}

# 检查响应
{
    "userId": 100,
    "username": "admin",
    "password": "明文密码",     # ← 严重泄露
    "passwordHash": "xxx",      # ← 泄露
    "phone": "138****8888",     # ← 脱敏（安全）
    "idCard": "110***********1234"  # ← 脱敏（安全）
}
```

### 3.3 配置文件检查

```bash
GET /api/config
GET /api/system/config
GET /api/settings

# 检查是否返回
{
    "dbPassword": "xxx",
    "apiSecret": "xxx",
    "jwtSecret": "xxx"
}
```

### 3.4 Swagger/API 文档检查

```bash
GET /swagger-ui.html
GET /doc.html
GET /v2/api-docs
GET /swagger.json

# 检查是否可访问
# 可访问 → 存在信息泄露
```

### 3.5 错误信息泄露

```bash
# 触发错误
GET /api/user?id=999

# SQL 错误
{"error": "You have an error in your SQL syntax near 'xxx'"}

# Java 堆栈
{"error": "java.lang.NullPointerException at com.xxx.UserService.getUser(UserService.java:45)"}

# 路径泄露
{"error": "FileNotFoundException: /app/config/production/database.yml"}
```

## 4. 错误信息指纹

| 数据库 | 错误特征 |
|--------|----------|
| MySQL | `You have an error in your SQL syntax` |
| PostgreSQL | `ERROR: syntax error at or near` |
| SQL Server | `Unclosed quotation mark` |
| Oracle | `ORA-01756` |
| MongoDB | `MongoDB.Driver` |
| Redis | `ERR wrong number of arguments` |

| 语言/框架 | 错误特征 |
|-----------|----------|
| Java | `java.lang.*Exception` |
| Python | `Traceback (most recent call last)` |
| Node.js | `ReferenceError: xxx is not defined` |
| .NET | `System.NullReferenceException` |
| Spring | `at com.xxx.controller` |

## 5. 脱敏检测

### 5.1 常见脱敏模式

| 类型 | 示例 |
|------|------|
| 手机号 | `138****8888` |
| 身份证 | `110***********1234` |
| 银行卡 | `**** **** **** 1234` |
| 邮箱 | `t***@example.com` |
| 密码 | `******` |

### 5.2 检测脱敏

```python
import re

def check_sensitive_mask(text):
    # 手机号未脱敏
    if re.search(r'1[3-9]\d{9}', text):
        return False, "手机号未脱敏"
    
    # 身份证未脱敏
    if re.search(r'\d{17}[\dXx]', text):
        return False, "身份证号未脱敏"
    
    # 密码字段存在
    if 'password' in text.lower() and 'null' not in text:
        return False, "密码字段存在"
    
    return True, "已脱敏"
```

## 6. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 账户接管 | 泄露的密码可用于登录 |
| 社工攻击 | 手机号、邮箱用于钓鱼 |
| 横向移动 | 泄露的密钥用于内网渗透 |

## 7. 测试检查清单

```
□ 检查登录响应是否泄露 token/refreshToken
□ 检查用户信息响应是否泄露 password
□ 检查配置文件响应是否泄露密钥
□ 检查 Swagger/API 文档是否可访问
□ 检查错误消息是否泄露技术栈
□ 检查错误消息是否泄露数据库类型
□ 检查错误消息是否泄露文件路径
□ 检查是否对敏感字段进行脱敏
□ 评估泄露的信息可造成的危害
```

## 8. 敏感信息检测脚本

```python
import requests
import re

SENSITIVE_PATTERNS = [
    (r'password["\s:]+["\'][^"\']+["\']', '密码明文'),
    (r'passwordHash["\s:]+["\'][^"\']+["\']', '密码Hash'),
    (r'token["\s:]+["\'][a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+["\']', 'JWT Token'),
    (r'secretKey["\s:]+["\'][^"\']+["\']', '密钥'),
    (r'apiKey["\s:]+["\'][^"\']+["\']', 'API密钥'),
    (r'1[3-9]\d{9}', '手机号'),
    (r'\d{17}[\dXx]', '身份证号'),
]

def scan_response(text):
    findings = []
    for pattern, name in SENSITIVE_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings.append((name, matches))
    return findings

# 使用
resp = requests.get("http://api/user/info")
findings = scan_response(resp.text)
for name, matches in findings:
    print(f"[FINDING] {name}: {matches}")
```

## 9. 误报判断标准

### 9.1 核心判断原则

```
【重要】敏感信息泄露 ≠ 一定是漏洞！

判断逻辑：
1. 先确认接口是否需要认证
2. 再确认数据是否本来就应被该用户访问
3. 最后判断是否为"非预期"的敏感信息泄露

【真实泄露特征】
- 未认证接口返回用户敏感信息
- 响应中包含他人的隐私数据
- 配置文件返回数据库密码/API密钥

【正常情况（不是漏洞）】
- 登录响应返回token是正常功能
- 认证用户获取自己的信息是正常功能
- 公开接口返回公开信息是正常功能
```

### 9.2 curl + 对比验证流程

```bash
# 1. 【必须先执行】获取正常响应基准
curl -s -H "Authorization: Bearer $TOKEN" \
     http://api/user/info > sensitive_baseline.json

# 分析：正常响应应该包含什么？
cat sensitive_baseline.json | jq .

# 2. 检查脱敏情况
# 如果手机号是 138****8888 → 脱敏（安全）
# 如果手机号是 13800138000 → 未脱敏（可能漏洞）

# 3. 检查是否返回了不该返回的字段
# password字段存在 → 漏洞
# token字段存在 → 可能是正常（取决于用途）

# 4. 对比不同用户的响应
curl -s -H "Authorization: Bearer $TOKEN_A" \
     http://api/user/info?userId=101 > user_101.json

curl -s -H "Authorization: Bearer $TOKEN_A" \
     http://api/user/info?userId=102 > user_102.json

diff user_101.json user_102.json
# 如果响应完全相同 → 可能是返回了相同的数据（自己的数据）
# 如果响应中ID不同 → 确认访问了不同用户的数据 → 漏洞
```

### 9.3 敏感信息泄露判断矩阵

| 场景 | 响应内容 | 是否认证 | 判断 |
|------|----------|----------|------|
| 登录返回token | {"token": "xxx"} | 否 | ✅ 正常 |
| 用户查看自己信息 | {"phone": "138****8888"} | 是 | ✅ 脱敏正常 |
| 用户查看自己信息 | {"password": "xxx"} | 是 | ⚠️ 漏洞（不应返回） |
| 未认证获取用户列表 | [{"phone": "138xxx"}, ...] | 否 | ⚠️ 漏洞 |
| 公开接口返回手机号 | {"phone": "138xxx"} | 否 | ⚠️ 漏洞 |
| 配置文件返回密钥 | {"dbPassword": "xxx"} | 是 | ⚠️ 漏洞 |

### 9.4 Python脚本（敏感信息深度检测）

```python
import requests
import re

class SensitiveDataTester:
    def __init__(self, target):
        self.target = target
        
    def check_masking(self, text, field_type='phone'):
        """
        检测敏感信息是否脱敏
        
        判断标准：
        - 手机号：应该是 138****8888 格式
        - 身份证：应该是 110***********1234 格式
        - 邮箱：应该是 t***@example.com 格式
        """
        patterns = {
            'phone': r'1[3-9]\d{9}',  # 未脱敏手机号
            'idcard': r'\d{17}[\dXx]',  # 未脱敏身份证
            'email': r'\w+@\w+\.\w+',  # 未脱敏邮箱
        }
        
        # 检查是否存在未脱敏的敏感信息
        matches = re.findall(patterns.get(field_type, ''), text)
        if matches:
            # 检查是否是脱敏格式
            masked_patterns = {
                'phone': r'1\d{2}\*{4,}\d{4}',  # 138****8888
                'idcard': r'\d{3}\*{10,}\d{4}',  # 110***********1234
            }
            masked = re.findall(masked_patterns.get(field_type, ''), text)
            
            if len(matches) > len(masked):
                return False, f"发现未脱敏的{field_type}: {matches}"
            return True, "已脱敏"
        return True, "未发现该类型信息"
    
    def check_forbidden_fields(self, text):
        """
        检查禁止返回的字段
        
        【判断标准】
        - password: 不应返回前端（无论是否脱敏）
        - passwordHash: 不应返回前端
        - secretKey/apiKey: 不应返回前端
        """
        forbidden = ['password', 'passwordHash', 'secretKey', 'apiKey', 'privateKey']
        found = []
        
        text_lower = text.lower()
        for field in forbidden:
            if field in text_lower:
                # 检查是否有值（不是null或空）
                pattern = f'{field}["\s:]+["\']([^"\']{2,})["\']'
                matches = re.findall(pattern, text_lower)
                if matches:
                    found.append((field, matches))
        
        return found
    
    def scan_endpoint(self, endpoint, token=None):
        """
        扫描接口的敏感信息泄露
        """
        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        resp = requests.get(f"{self.target}/{endpoint}", headers=headers)
        
        findings = []
        text = resp.text
        
        # 检查禁止字段
        forbidden = self.check_forbidden_fields(text)
        if forbidden:
            findings.append(('禁止字段泄露', forbidden))
        
        # 检查脱敏
        phone_status, phone_msg = self.check_masking(text, 'phone')
        if not phone_status:
            findings.append(('手机号未脱敏', phone_msg))
        
        idcard_status, idcard_msg = self.check_masking(text, 'idcard')
        if not idcard_status:
            findings.append(('身份证未脱敏', idcard_msg))
        
        return {
            'endpoint': endpoint,
            'status_code': resp.status_code,
            'findings': findings,
            'is_sensitive': len(findings) > 0
        }
    
    def run_tests(self, endpoints, token=None):
        """批量测试敏感信息泄露"""
        print(f"\n=== 敏感信息泄露测试 ===\n")
        
        results = []
        for endpoint in endpoints:
            result = self.scan_endpoint(endpoint, token)
            results.append(result)
            
            status = "⚠️ 发现问题" if result['is_sensitive'] else "✅ 安全"
            print(f"[{status}] {endpoint}")
            for finding_type, details in result['findings']:
                print(f"  - {finding_type}: {details}")
        
        return results

# 使用示例
if __name__ == "__main__":
    tester = SensitiveDataTester("http://api")
    
    # 测试不需要认证的接口
    public_endpoints = ['/user/info', '/product/list', '/news']
    tester.run_tests(public_endpoints)
    
    # 测试需要认证的接口
    private_endpoints = ['/user/info', '/order/list']
    tester.run_tests(private_endpoints, token="user_token")
```

## 10. 实战判断案例

### 案例1：登录响应返回token是正常的

```
【场景】：登录接口返回token

curl测试：
  curl -X POST /api/login -d '{"username":"admin","password":"xxx"}'
  → {"code":0,"msg":"登录成功","token":"eyJhbGci..."}

判断：
- 登录接口返回token是正常功能
- 不是敏感信息泄露漏洞
- 结论：【正常】不需要修复
```

### 案例2：用户信息包含password是漏洞

```
【场景】：用户信息接口返回password字段

curl测试：
  curl -H "Authorization: Bearer $TOKEN" /api/user/info
  → {"userId":1,"username":"admin","password":"明文密码123"}

判断：
- 响应包含password字段
- password不应返回前端
- 结论：【确认漏洞】密码明文泄露
```

### 案例3：手机号未脱敏是漏洞

```
【场景】：接口返回未脱敏的手机号

curl测试：
  # 场景1：公开接口
  curl /api/user/list
  → [{"name":"张三","phone":"13800138000"}]
  
  # 场景2：个人中心
  curl -H "Authorization: Bearer $TOKEN" /api/user/info
  → {"name":"张三","phone":"13800138000"}

判断：
- 场景1：公开接口返回未脱敏手机号 → 漏洞
- 场景2：个人中心返回未脱敏手机号 → 可能漏洞（取决于业务需求）
- 结论：【需确认】建议脱敏处理
```
