# IDOR越权测试

## 测试方法

### 1. 水平越权

```python
def test_horizontal_idor(token, user_id_a, user_id_b):
    """
    测试水平越权：同级用户数据访问
    """
    # 用户A访问自己的数据
    r1 = requests.get(
        f"/api/user/info?userId={user_id_a}",
        headers={'Authorization': f'Bearer {token}'}
    )
    
    # 用户A尝试访问用户B的数据
    r2 = requests.get(
        f"/api/user/info?userId={user_id_b}",
        headers={'Authorization': f'Bearer {token}'}
    )
    
    # 如果两个响应都返回200且数据不同
    if r1.status_code == 200 and r2.status_code == 200:
        if r1.text != r2.text:
            return {
                "vuln": True,
                "type": "水平越权",
                "detail": f"用户{token}可访问用户{user_id_b}的数据"
            }
    return {"vuln": False}
```

### 2. 垂直越权

```python
def test_vertical_idor(user_token, admin_endpoint):
    """
    测试垂直越权：低权限访问高权限
    """
    # 普通用户尝试访问管理员接口
    r = requests.get(
        admin_endpoint,
        headers={'Authorization': f'Bearer {user_token}'}
    )
    
    if r.status_code == 200:
        return {
            "vuln": True,
            "type": "垂直越权",
            "detail": "普通用户可访问管理员接口"
        }
    return {"vuln": False}
```

### 3. ID加密绕过

```python
def test_encrypted_id_bypass(token, encrypted_user_id):
    """
    测试加密ID是否可被篡改
    """
    # 尝试解密并修改
    try:
        original_id = decrypt(encrypted_user_id)
        modified_id = original_id + 1
        encrypted_modified = encrypt(str(modified_id))
        
        r = requests.get(
            f"/api/user/info?userId={encrypted_modified}",
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if r.status_code == 200:
            return {"vuln": True, "type": "加密ID可被篡改"}
    except:
        pass
    return {"vuln": False}
```

## 测试场景

```bash
# 测试用户信息查看
curl -H "Authorization: Bearer $TOKEN" "http://api/user/info?userId=100"

# 测试订单查看
curl -H "Authorization: Bearer $TOKEN" "http://api/order/list?userId=100"

# 测试文件访问
curl -H "Authorization: Bearer $TOKEN" "http://api/file/download?fileId=100"
```

## 误报判断

```
【真实漏洞特征】
- 使用自己的token访问他人的数据
- 返回了不同于自己账户的数据
- 修改了他人的资源

【误报特征】
- 本来就是公开数据
- 返回的是自己的数据（只是ID不同）
- 需要认证但返回了游客数据
```

## 判断步骤

```bash
# 1. 获取当前用户信息
curl -s -H "Authorization: Bearer token_A" \
  "http://api/user/info?userId=101" > user_101.json

# 2. 确认返回的是userId=101的数据
cat user_101.json

# 3. 确认这需要认证且不应该被A访问
```
