# 敏感信息泄露

## 测试方法

### 1. 密码明文返回

```bash
# 测试用户信息接口
curl -s "http://api/user/info"

# 检查响应是否包含
grep -i "password" response.txt
grep -i "pwd" response.txt
grep -i "passwd" response.txt
```

### 2. Token泄露

```python
def check_token_leak(response):
    """
    检查响应中是否泄露Token
    """
    sensitive_patterns = [
        r'(?:access_token|token|Token)["\s]*[:=]["\s]*["\']([^"\']+)["\']',
        r'(?:refresh_token|refreshToken)["\s]*[:=]["\s]*["\']([^"\']+)["\']',
    ]
    
    for pattern in sensitive_patterns:
        matches = re.findall(pattern, response, re.IGNORECASE)
        if matches:
            return {"leaked": True, "tokens": matches}
    return {"leaked": False}
```

### 3. 配置文件敏感信息

```python
def check_config_leak(url):
    """
    检查配置文件是否泄露敏感信息
    """
    sensitive_patterns = [
        r'apiKey["\s]*[:=]["\s]*["\']([^"\']+)["\']',
        r'secretKey["\s]*[:=]["\s]*["\']([^"\']+)["\']',
        r'password["\s]*[:=]["\s]*["\']([^"\']+)["\']',
        r'database["\s]*[:=]["\s]*["\{][^}]+["\}]',
    ]
    
    r = requests.get(url)
    for pattern in sensitive_patterns:
        if re.search(pattern, r.text, re.IGNORECASE):
            return {"leaked": True, "url": url}
    return {"leaked": False}
```

## 敏感字段清单

```
password     → 不应返回前端
token        → 可能存在泄露
secretKey    → 不应暴露
apiKey       → 不应暴露
balance      → 可能存在越权
orderNo      → 可能被篡改
userId       → 可用于越权测试
phone        → 可用于用户枚举
email        → 可用于钓鱼
```

## 响应类型判断

| 响应类型 | 特征 | 含义 |
|----------|------|------|
| JSON对象 | `{"code":200,"data":{}}` | 真实API响应 |
| JSON数组 | `[{"id":1},...]` | 真实数据列表 |
| HTML页面 | `<!DOCTYPE html>` | SPA路由/WAF/错误页 |
| 空响应 | 长度<50字节 | 错误/空数据 |
| 重定向 | HTTP 301/302 | 需要认证/跳转 |
