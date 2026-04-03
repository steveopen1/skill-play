# 用户枚举测试

## 测试方法

### 1. 手机号枚举

```python
def test_phone_enum():
    """
    测试是否可以通过手机号枚举用户
    """
    test_phones = [
        "13800000001",
        "13800000002",
        "13800000003",
    ]
    
    for phone in test_phones:
        r = requests.post(
            "/api/user/check",
            json={"phone": phone}
        )
        
        # 分析响应差异
        if "userId" in r.text or "exists" in r.text.lower():
            return {
                "vuln": True,
                "type": "用户枚举",
                "detail": f"手机号{phone}存在用户"
            }
    return {"vuln": False}
```

### 2. 邮箱枚举

```python
def test_email_enum():
    """
    测试是否可以通过邮箱枚举用户
    """
    test_emails = [
        "test1@example.com",
        "test2@example.com",
        "test3@example.com",
    ]
    
    for email in test_emails:
        r = requests.post(
            "/api/user/check",
            json={"email": email}
        )
        
        if "exists" in r.text.lower() or "userId" in r.text:
            return {
                "vuln": True,
                "type": "用户枚举",
                "detail": f"邮箱{email}存在用户"
            }
    return {"vuln": False}
```

### 3. 登录响应差异

```python
def test_login_response_diff():
    """
    测试登录接口对存在/不存在的用户响应差异
    """
    # 存在的用户
    r1 = requests.post("/api/login", json={
        "username": "admin",
        "password": "wrongpassword"
    })
    
    # 不存在的用户
    r2 = requests.post("/api/login", json={
        "username": "nonexistentuser12345",
        "password": "wrongpassword"
    })
    
    # 分析响应差异
    if r1.text != r2.text:
        diff_analysis = compare_responses(r1.text, r2.text)
        return {
            "vuln": True,
            "type": "用户枚举",
            "detail": f"登录响应存在差异，可枚举用户: {diff_analysis}"
        }
    return {"vuln": False}

def compare_responses(resp1, resp2):
    """比较两个响应的差异"""
    diff = []
    if "user" in resp1.lower() and "user" not in resp2.lower():
        diff.append("存在用户时响应包含'user'关键词")
    if "not found" in resp2.lower() and "not found" not in resp1.lower():
        diff.append("不存在用户时返回'not found'")
    return "; ".join(diff)
```

## 测试场景

```bash
# 用户存在检查
curl -X POST "http://api/user/check" \
  -H "Content-Type: application/json" \
  -d '{"phone":"13800000001"}'

# 登录尝试
curl -X POST "http://api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'

curl -X POST "http://api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexist123","password":"test"}'
```

## 漏洞模式识别

| 响应特征 | 含义 |
|----------|------|
| 用户存在时返回userId | 可枚举用户 |
| 用户不存在时提示"不存在" | 可枚举用户 |
| 登录响应时间不同 | 可时间推断枚举 |
| 注册接口可探测 | 可枚举已注册用户 |
