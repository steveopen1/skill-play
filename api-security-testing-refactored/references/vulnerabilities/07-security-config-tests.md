# CORS配置错误测试

## 测试方法

```python
def test_cors_vulnerability(url):
    """
    测试CORS配置错误
    """
    dangerous_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]
    
    results = []
    for origin in dangerous_origins:
        r = requests.get(url, headers={"Origin": origin})
        allow_origin = r.headers.get('Access-Control-Allow-Origin')
        allow_cred = r.headers.get('Access-Control-Allow-Credentials')
        
        if allow_origin == origin or allow_origin == "*":
            if allow_cred == 'true':
                results.append({
                    "vulnerable": True,
                    "origin": origin,
                    "allow_credentials": True,
                    "allow_origin": allow_origin
                })
    
    return results
```

## 识别特征

```
响应头包含：
- Access-Control-Allow-Origin: <任意origin>
- Access-Control-Allow-Credentials: true

危险配置示例：
- Access-Control-Allow-Origin: https://evil.com
- Access-Control-Allow-Credentials: true
```

## 影响分析

```
1. 任意第三方网站可以获取用户的认证token
2. 攻击者可以读取、修改用户的请求和响应
3. 结合用户枚举，确认用户身份后发起针对性攻击

攻击场景：
1. 用户登录目标系统
2. 用户被诱骗访问攻击者控制的恶意页面
3. 恶意页面中的JavaScript发起跨域请求
4. 由于CORS配置错误，攻击者获取完整响应数据
```

## 修复建议

```
1. 使用CORS白名单机制，只允许信任的域名
2. 当设置 Allow-Credentials 时，Origin 必须是具体域名，不能是 *
3. 定期审查CORS配置
```
