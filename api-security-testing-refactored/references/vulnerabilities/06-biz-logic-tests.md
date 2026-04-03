# 业务逻辑漏洞测试

## 1. 概述

业务逻辑漏洞是指利用业务逻辑流程中的缺陷实现的攻击，如支付篡改、条件竞争、业务流程绕过等。

**危险等级**: 高

## 2. 支付篡改

### 2.1 测试点

| 接口 | 示例 |
|------|------|
| 支付下单 | `POST /api/pay` |
| 订单创建 | `POST /api/order` |
| 价格计算 | `GET /api/price` |
| 优惠券 | `POST /api/coupon/apply` |

### 2.2 测试方法

```bash
# 1. 金额篡改
POST /api/pay
{
    "orderId": "ORDER123",
    "amount": "0.01"      # 尝试极小金额
}

# 2. 数量篡改
POST /api/order
{
    "goodsId": "1",
    "count": "-1"          # 负数数量
}

# 3. 单价篡改
POST /api/order
{
    "goodsId": "1",
    "price": "0.01",
    "count": 1
}

# 4. 汇率篡改
POST /api/pay
{
    "orderId": "ORDER123",
    "currency": "USD",
    "amount": "0.01"      # 使用低汇率币种
}

# 5. 状态篡改
POST /api/order/status
{
    "orderId": "ORDER123",
    "status": "paid"      # 直接设为已付款
}
```

### 2.3 防护检查

```bash
# 检查后端是否验证
# 1. 重新计算金额
# 2. 校验数量>0
# 3. 使用服务端汇率
# 4. 状态机校验
```

## 3. 条件竞争

### 3.1 测试场景

| 场景 | 风险 |
|------|------|
| 优惠券领取 | 多次领取 |
| 库存扣减 | 超卖 |
| 余额扣款 | 重复扣款 |
| 积分增加 | 重复增加 |

### 3.2 测试方法

```python
import threading
import requests

def send_request():
    response = requests.post(
        "http://api/coupon/receive",
        json={"couponId": "1"},
        headers={"Authorization": "Bearer xxx"}
    )
    return response.json()

# 100并发请求
threads = []
for i in range(100):
    t = threading.Thread(target=send_request)
    threads.append(t)
    t.start()

for t in threads:
    t.join()

# 检查有多少人成功领取
# 应该只有1个成功
# 如果>1个 → 存在条件竞争漏洞
```

### 3.3 线程池并发

```python
from concurrent.futures import ThreadPoolExecutor

def send_request():
    # 请求逻辑
    pass

with ThreadPoolExecutor(max_workers=100) as executor:
    futures = [executor.submit(send_request) for _ in range(100)]
    results = [f.result() for f in futures]
```

## 4. 业务流程绕过

### 4.1 测试场景

```bash
# 1. 跳过验证步骤
# 正常流程：选择商品 → 填写信息 → 支付 → 验证 → 完成
# 绕过：选择商品 → 支付 → 验证(跳过)

POST /api/order/complete
{"orderId": "ORDER123", "step": "verified"}

# 2. 跳过短信验证
POST /api/register
{
    "username": "test",
    "phone": "13800138000",
    "smsCode": "000000"  # 尝试空或伪造
}

# 3. 跳过图形验证码
POST /api/login
{
    "username": "admin",
    "password": "xxx",
    "captcha": ""          # 尝试为空
}
```

### 4.2 状态机绕过

```bash
# 订单状态：pending → paid → shipped → completed
# 尝试跳过中间状态

POST /api/order/update
{"orderId": "123", "status": "shipped"}  # 未支付就发货
```

## 5. 暴力破解（业务维度）

### 5.1 优惠券码

```python
# 6位数字优惠券：100000-999999
for i in range(100000, 100010):
    code = f"{i:06d}"
    resp = requests.post(
        "http://api/coupon/use",
        json={"code": code}
    )
```

### 5.2 订单号预测

```bash
# 如果订单号是顺序的
# ORDER1234567890
# ORDER1234567891
# ORDER1234567892

for i in range(10):
    order_no = f"ORDER123456789{i}"
    resp = requests.get(f"http://api/order/{order_no}")
```

## 6. 测试检查清单

```
□ 支付篡改测试（金额、数量、状态）
□ 优惠券领取条件竞争测试
□ 库存扣减条件竞争测试
□ 业务流程跳过测试
□ 状态机绕过测试
□ 验证码绕过测试
□ 订单号/优惠券号预测测试
□ 评估漏洞利用难度和影响
```

## 7. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 0元支付 | 篡改金额为0.01 |
| 薅羊毛 | 条件竞争重复领取优惠券 |
| 刷单 | 篡改数量或绕过限制 |
| 盗窃 | 修改他人订单或地址 |
