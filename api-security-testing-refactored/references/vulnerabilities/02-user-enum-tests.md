# 用户枚举测试

## 1. 概述

用户枚举（User Enumeration）是指通过某些接口可以判断用户名、手机号、邮箱等是否存在于系统中。

**危险等级**: 中

## 2. 测试点识别

### 2.1 常见枚举接口

| 接口模式 | 示例 |
|----------|------|
| 用户查重 | `/user/checkOnlyUser?username=X` |
| 用户存在 | `/user/exist?phone=X` |
| 用户验证 | `/user/validate?email=X` |
| 注册接口 | `/user/register` |
| 登录接口 | `/login` (响应差异) |
| 密码重置 | `/user/resetPassword` |

### 2.2 响应差异点

| 特征 | 说明 |
|------|------|
| 不同错误消息 | "用户不存在" vs "密码错误" |
| 响应码差异 | code=0 vs code=1 |
| 响应时间差异 | 存在用户 vs 不存在 |

## 3. 测试方法

### 3.1 用户名枚举

```bash
# 用户存在
curl "http://api/sys/user/checkOnlyUser?username=admin"
# 响应: {"success":false,"message":"用户账号已存在","code":0,"result":true}

# 用户不存在
curl "http://api/sys/user/checkOnlyUser?username=notexist"
# 响应: {"success":false,"message":"","code":0,"result":false}
```

### 3.2 手机号枚举

```bash
curl "http://api/user/check?phone=13800138000"
curl "http://api/user/existByPhone?phone=13800138000"
curl "http://api/sms/send?phone=13800138000"
```

### 3.3 邮箱枚举

```bash
curl "http://api/user/check?email=test@mail.com"
curl "http://api/user/validateEmail?email=test@mail.com"
```

### 3.4 登录接口响应差异

```bash
# 用户不存在
POST /api/login
{"username": "notexist", "password": "any"}
# 响应: {"message":"用户不存在"}

# 密码错误
POST /api/login
{"username": "admin", "password": "wrong"}
# 响应: {"message":"密码错误"}

# 用户存在但响应相同
POST /api/login
{"username": "notexist", "password": "wrong"}
# 响应: {"message":"用户名或密码错误"}  ← 统一消息（安全）
```

### 3.5 注册接口探测

```bash
POST /api/user/register
{"username": "admin", "password": "test"}
# 响应: {"message":"该用户已注册"}

POST /api/user/register
{"username": "newuser", "password": "test"}
# 响应: {"message":"注册成功"}
```

## 4. 枚举用户名字典

### 4.1 常见管理员账号

```
admin, administrator, root, user, manager
sysadmin, system, security, backup
admin1, admin123, admin888
root1, root123
administrator, adminitrator (拼写错误)
```

### 4.2 常见测试账号

```
test, test1, test123, tester
demo, demo1
guest, visitor
default
```

### 4.3 业务相关账号

```
owner, operator, developer
support, helpdesk
noreply, no-reply
```

## 5. 防护绕过

### 5.1 大小写混淆

```bash
username=Admin
username=ADMIN
username=AdMiN
```

### 5.2 特殊字符

```bash
username=admin
username=admin\
username=admin"
username=admin<>
```

### 5.3 时间差异规避

```bash
# 多次请求间增加延迟
sleep 1
curl "http://api/user/check?username=admin"
```

## 6. 关联漏洞

| 后续漏洞 | 利用路径 |
|----------|----------|
| 暴力破解 | 确认用户名 → 定向爆破密码 |
| 密码重置 | 利用已确认的用户 → 重置密码 |
| 社会工程学 | 利用确认的手机号/邮箱 → 钓鱼攻击 |

## 7. 测试检查清单

```
□ 测试用户查重接口（/user/checkOnlyUser）
□ 测试手机号查重接口
□ 测试邮箱查重接口
□ 测试登录接口响应差异
□ 测试注册接口探测
□ 枚举常见管理员账号
□ 枚举常见测试账号
□ 测试大小写绕过
□ 测试特殊字符绕过
□ 判断响应差异是否可利用
□ 评估漏洞风险和影响
```

## 8. 风险评估

| 风险级别 | 条件 |
|----------|------|
| 高 | 可快速枚举大量用户/邮箱 |
| 中 | 需要等待或有限制但可枚举个 |
| 低 | 有严格限制但仍可枚举报 |
