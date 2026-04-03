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
