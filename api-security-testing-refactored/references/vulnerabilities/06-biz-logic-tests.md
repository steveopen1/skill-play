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

## 8. 误报判断标准

### 8.1 核心判断原则

```
【重要】业务逻辑测试的误判率极高！

判断逻辑：
1. 先理解正常的业务逻辑
2. 确认"攻击"的响应是否真的绕过了业务逻辑
3. 很多"攻击"可能是后端的正常防护

【真实漏洞特征】
- 金额被篡改后仍能完成支付
- 负数数量被接受并执行
- 跳过验证步骤仍能完成业务
- 条件竞争真的造成了超卖

【误报特征】
- 后端校验拒绝了异常请求
- 业务逻辑正确地拒绝了异常操作
- 接口返回错误提示而非执行成功
```

### 8.2 curl + 对比验证流程

```bash
# 1. 【必须先执行】获取正常业务流程响应
curl -s -X POST http://api/order \
     -H "Content-Type: application/json" \
     -d '{"goodsId":"1","count":1,"price":100}' > biz_normal.json

# 2. 测试金额篡改
curl -s -X POST http://api/order \
     -H "Content-Type: application/json" \
     -d '{"goodsId":"1","count":1,"price":0.01}' > biz_amount_test.json

# 3. 测试数量篡改
curl -s -X POST http://api/order \
     -H "Content-Type: application/json" \
     -d '{"goodsId":"1","count":-1,"price":100}' > biz_count_test.json

# 4. 对比响应
diff biz_normal.json biz_amount_test.json
diff biz_normal.json biz_count_test.json

# 判断：
# - 如果异常请求被拒绝 → 后端有校验 → 不是漏洞
# - 如果异常请求被接受 → 可能是漏洞
```

### 8.3 业务逻辑漏洞判断矩阵

| 测试场景 | 正常响应 | 漏洞响应 | 判断 |
|----------|----------|----------|------|
| 金额0.01 | "金额不能小于1元" | 支付成功 | ⚠️ 漏洞 |
| 负数数量 | "数量必须大于0" | 订单创建成功 | ⚠️ 漏洞 |
| 跳过验证 | "请先验证" | 业务完成 | ⚠️ 漏洞 |
| 条件竞争 | 只有1人成功 | 多人成功 | ⚠️ 漏洞 |
| 优惠券重复 | "已领取过" | 多次成功 | ⚠️ 漏洞 |

### 8.4 Python脚本（业务逻辑深度测试）

```python
import requests
import json
import time

class BizLogicTester:
    def __init__(self, target):
        self.target = target
        self.token = None
        
    def set_token(self, token):
        self.token = token
    
    def get_headers(self):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    def test_price_tampering(self, order_data, tampered_price):
        """
        测试价格篡改
        
        判断标准：
        1. 如果订单创建成功且价格被篡改 → 漏洞
        2. 如果订单创建失败或价格被纠正 → 安全
        """
        # 构造篡改后的订单
        tampered_data = order_data.copy()
        tampered_data['price'] = tampered_price
        
        resp = requests.post(
            f"{self.target}/order",
            json=tampered_data,
            headers=self.get_headers()
        )
        
        try:
            data = resp.json()
        except:
            return None, "响应非JSON", resp
        
        # 检查是否成功创建订单
        if data.get('code') == 0 or data.get('success'):
            # 检查实际金额
            created_price = data.get('data', {}).get('price')
            if created_price and created_price != tampered_price:
                return False, f"后端纠正了金额: {tampered_price} -> {created_price}"
            elif created_price == tampered_price:
                return True, f"金额篡改成功: {created_price}"
            else:
                return None, "无法确认金额是否被篡改", data
        
        # 检查错误消息
        msg = data.get('msg', '')
        if '价格' in msg or '金额' in msg:
            return False, f"后端校验拒绝: {msg}"
        
        return False, "订单创建失败", data
    
    def test_negative_quantity(self, goods_id, count):
        """
        测试负数数量
        
        判断标准：
        1. 如果订单创建成功 → 漏洞
        2. 如果订单创建失败 → 安全
        """
        resp = requests.post(
            f"{self.target}/order",
            json={"goodsId": goods_id, "count": count},
            headers=self.get_headers()
        )
        
        try:
            data = resp.json()
        except:
            return None, "响应非JSON", resp
        
        if data.get('code') == 0 or data.get('success'):
            return True, "负数数量被接受"
        
        msg = data.get('msg', '')
        if '数量' in msg or '参数' in msg:
            return False, f"后端校验拒绝: {msg}"
        
        return False, "订单创建失败", data
    
    def test_race_condition(self, endpoint, data, concurrency=10):
        """
        测试条件竞争
        
        判断标准：
        1. 并发请求
        2. 检查成功次数
        3. 如果成功次数 > 1 → 漏洞（超卖）
        """
        import threading
        
        success_count = 0
        lock = threading.Lock()
        results = []
        
        def send_request():
            nonlocal success_count
            try:
                resp = requests.post(
                    f"{self.target}/{endpoint}",
                    json=data,
                    headers=self.get_headers(),
                    timeout=10
                )
                result = resp.json()
                results.append(result)
                
                if result.get('code') == 0 or result.get('success'):
                    with lock:
                        success_count += 1
            except Exception as e:
                results.append({'error': str(e)})
        
        # 并发执行
        threads = []
        for _ in range(concurrency):
            t = threading.Thread(target=send_request)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # 判断
        if success_count > 1:
            return True, f"条件竞争漏洞：{concurrency}次请求，{success_count}次成功"
        else:
            return False, f"安全：{concurrency}次请求，{success_count}次成功（正常）"
    
    def run_tests(self):
        """执行完整业务逻辑测试"""
        print(f"\n=== 业务逻辑漏洞测试 ===\n")
        
        results = []
        
        # 1. 价格篡改测试
        print("[1] 测试价格篡改")
        normal_data = {"goodsId": "1", "count": 1, "price": 100}
        is_vuln, reason = self.test_price_tampering(normal_data, 0.01)
        results.append(('价格篡改', is_vuln, reason))
        print(f"  金额0.01: {reason}")
        
        # 2. 负数数量测试
        print("\n[2] 测试负数数量")
        is_vuln, reason = self.test_negative_quantity("1", -1)
        results.append(('负数数量', is_vuln, reason))
        print(f"  数量-1: {reason}")
        
        # 3. 条件竞争测试（优惠券场景）
        print("\n[3] 测试条件竞争（优惠券领取）")
        is_vuln, reason = self.test_race_condition(
            "coupon/receive",
            {"couponId": "1"},
            concurrency=10
        )
        results.append(('条件竞争', is_vuln, reason))
        print(f"  优惠券领取: {reason}")
        
        return results

# 使用示例
if __name__ == "__main__":
    tester = BizLogicTester("http://api")
    tester.set_token("user_token")
    results = tester.run_tests()
    
    print("\n=== 测试结果汇总 ===")
    for vuln_type, is_vuln, reason in results:
        status = "⚠️ 漏洞" if is_vuln else "✅ 安全"
        print(f"[{status}] {vuln_type}: {reason}")
```

## 9. 实战判断案例

### 案例1：后端正确校验金额

```
【场景】：篡改金额被后端拒绝

curl测试：
  curl -X POST /api/order -d '{"goodsId":"1","price":0.01}'
  → {"code":1001,"msg":"金额不能小于1元"}

判断：
- 后端正确校验了金额
- 响应包含错误提示
- 结论：【安全】后端有防护
```

### 案例2：价格篡改漏洞

```
【场景】：篡改金额后订单创建成功

curl测试：
  curl -X POST /api/order -d '{"goodsId":"1","price":0.01}'
  → {"code":0,"msg":"下单成功","orderId":"ORDER123","price":0.01}

判断：
- 订单创建成功
- 金额被篡改为0.01
- 结论：【确认漏洞】价格篡改漏洞
```

### 案例3：负数数量漏洞

```
【场景】：负数数量导致"刷单"

curl测试：
  curl -X POST /api/order -d '{"goodsId":"1","count":-5}'
  → {"code":0,"msg":"下单成功","count":-5}

判断：
- 负数数量被接受
- 可能导致"白嫖"或资金问题
- 结论：【确认漏洞】数量篡改漏洞
```
