---
name: api-security-testing
description: 针对授权目标进行结构化的 REST/GraphQL API 安全评估。当用户提到安全测试、漏洞检测、渗透测试或需要生成安全报告时自动触发。
trigger:
  phrases:
    - "安全测试"
    - "安全审计"
    - "渗透测试"
    - "漏洞检测"
    - "安全评估"
    - "api 安全"
    - "接口安全"
    - "帮我检测漏洞"
    - "检查安全问题"
    - "安全报告"
    - "全流程测试"
    - "完整测试"
    - "云存储安全"
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全|云存储|oss)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全|oss|云存储|bucket)?(?:漏洞|问题)"
  auto_trigger: true
---

# API 安全测试 Skill

> **重要说明**：
> 本 Skill 是大模型的"思维指导"，不是执行脚本。
> 大模型应该理解检测思路，自己决定如何执行。

---

## 核心检测思维

### 1. 遇到"查询类"接口时这么想

当你发现一个接口用于查询数据时：

```
思考：这个接口查的是什么数据？需要认证吗？能查到别人的数据吗？
```

**推理步骤：**
1. 这个接口查询需要什么参数？（userId、phone、orderNo...）
2. 不带参数能查到数据吗？
3. 带别人的ID能查到数据吗？（IDOR）
4. 响应中有没有敏感字段？（password、token、余额...）

**示例：**
```
你发现：GET /api/user/info?userId=123
思考：
  - 需要认证吗？→ 测试不带token
  - 能查其他用户吗？→ 测试userId=124
  - 响应有敏感字段吗？→ 检查password、token等
```

### 2. 遇到"认证类"接口时这么想

当你发现登录、注册接口时：

```
思考：认证机制安全吗？能绕过吗？能枚举用户吗？
```

**推理步骤：**
1. 不带认证信息能访问吗？
2. 伪造token能通过吗？（JWTalg:none）
3. 用户不存在时的响应有区别吗？（用户枚举）
4. 有短信验证码吗？能轰炸吗？

**示例：**
```
你发现：POST /api/login
思考：
  - SQL注入？→ 测试 username=' OR '1'='1
  - 暴力破解？→ 多次尝试错误密码
  - 用户枚举？→ 测试不存在的用户
```

### 3. 遇到"资金/订单类"接口时这么想

当你发现支付、退款、订单接口时：

```
思考：钱能转走吗？订单能篡改吗？能刷单吗？
```

**推理步骤：**
1. 订单归属校验了吗？（用A的token能操作B的订单吗？）
2. 金额能篡改吗？（改成0.01）
3. 退款接口需要什么权限？能绕过吗？

**示例：**
```
你发现：POST /api/pay/refund
思考：
  - 需要认证吗？→ 不带token测试
  - 需要自己的订单吗？→ 尝试他人的orderNo
  - 金额能改成0吗？→ amount=0测试
```

### 4. 遇到"用户信息"接口时这么想

当你发现返回用户资料的接口时：

```
思考：别人的资料能拿到吗？密码暴露了吗？能修改吗？
```

**推理步骤：**
1. 不带token能拿到吗？
2. 响应里有password吗？
3. 能通过phone/email找到userId吗？
4. 修改接口有校验吗？能改别人的吗？

**示例：**
```
你发现：GET /api/user/info?phone=138xxx
思考：
  - 返回userId了吗？→ 记录
  - 返回password了吗？→ 漏洞
  - userId=124能查到吗？→ IDOR测试
```

---

## 敏感信息识别

### 必须识别这些敏感字段

```
password      → 不应返回前端
token         → 可能存在泄露
secretKey     → 不应暴露
apiKey        → 不应暴露
balance       → 可能存在越权
orderNo       → 可能被篡改
userId        → 可用于越权测试
phone         → 可用于用户枚举
email         → 可用于钓鱼
```

### 响应分析思维

当你看到响应时：
```
1. 这个响应正常吗？ → 检查状态码
2. 有敏感字段吗？ → 搜索password/token/secret
3. 有ID类字段吗？ → 尝试遍历
4. 有手机号吗？ → 尝试用户枚举
5. 有订单号吗？ → 尝试越权操作
```

---

## 漏洞链构造思维

### 发现用户枚举后的推理

当你发现可以枚举用户时：

```
你发现的：GET /api/user/check?phone=138xxx 返回 userId

思考能做什么：
1. 收集更多userId → 批量探测手机号
2. 用userId查更多信息 → GET /api/user/info?userId=xxx
3. 尝试修改他人资料 → POST /api/user/update
4. 查看他人订单 → GET /api/order/list?userId=xxx
5. 尝试退款 → POST /api/refund (用他人的orderNo)
```

### 发现token泄露后的推理

当你发现响应中包含token时：

```
你发现的：{"token": "xxx", "userId": 123}

思考能做什么：
1. 这个token有效吗？ → 用这个token访问其他接口
2. 能用这个token访问admin接口吗？ → GET /api/admin/xxx
3. token能用于其他用户吗？ → 改userId重放

利用链：
token泄露 → 用token访问敏感接口 → 越权操作
```

### 发现订单接口后的推理

当你发现订单相关接口时：

```
你发现的：GET /api/order/list

思考能做什么：
1. 不带认证能访问吗？ → 测试
2. 能带userId参数吗？ → 查他人订单
3. 能找到orderNo吗？ → 尝试 /api/order/detail?orderNo=xxx
4. 有退款接口吗？ → 尝试 /api/refund?orderNo=xxx

利用链：
用户枚举 → 获取userId → 查订单 → 退款
```

---

## HTTP方法与测试策略

### 不同方法的测试重点

| 方法 | 测试重点 |
|------|----------|
| GET | 参数遍历、IDOR、信息泄露 |
| POST | 认证绕过、业务逻辑、注入 |
| PUT | 资源篡改、越权修改 |
| DELETE | 资源删除、越权删除 |
| PATCH | 部分更新、字段覆盖 |

### 参数测试思维

当你发现一个接口有参数时：

```
接口：GET /api/xxx?param=value

测试顺序：
1. param=空值
2. param=正常值
3. param=特殊字符 (' " < >)
4. param=SQL注入 (1' OR '1'='1)
5. param=XSS (<script>alert(1)</script>)
6. param=路径遍历 (../../../etc/passwd)
7. param=其他用户的值 (IDOR)
```

---

## 认证上下文理解

### 发现登录接口后

```
你发现的：POST /api/login {"username":"xxx","password":"xxx"}

思考：
1. 返回token吗？ → 记录token
2. 返回userId吗？ → 记录userId
3. 响应有什么区别？ → 用户枚举
4. 有验证码吗？ → 暴力破解难度

接下来用这个token：
- 访问 GET /api/user/info
- 访问 GET /api/order/list
- 尝试 GET /api/admin/xxx (测试权限)
```

### 发现token但不知道用法时

```
你发现的：token=eyJhbGciOiJIUzI1NiJ9...

思考：
1. JWT吗？ → 解码看payload
2. 放在哪？ → Authorization: Bearer token
3. 哪个接口用？ → 尝试访问需要认证的接口
4. userId是什么？ → 从token解码获取
```

---

## 常见漏洞模式识别

### 用户相关漏洞模式

```
1. 用户信息泄露
   特征：响应包含password、token
   测试：不带认证访问

2. 用户枚举
   特征：用户存在/不存在响应不同
   测试：探测不存在的手机号/邮箱

3. 密码重置漏洞
   特征：可通过phone/email重置
   测试：尝试修改他人密码

4. 越权访问
   特征：通过参数切换用户
   测试：修改userId/phone等参数
```

### 订单相关漏洞模式

```
1. 订单遍历
   特征：参数化查询订单
   测试：修改userId查他人订单

2. 订单篡改
   特征：订单金额可修改
   测试：尝试amount=0.01

3. 虚假订单
   特征：可创建任意订单
   测试：构造恶意订单数据

4. 退款绕过
   特征：退款接口无校验
   测试：使用他人orderNo退款
```

### 认证相关漏洞模式

```
1. JWT伪造
   特征：alg:None 或不验签
   测试：修改payload重放

2. 暴力破解
   特征：无验证码、无限流
   测试：多次尝试密码

3. 会话固定
   特征：登录后session不变
   测试：登录前后cookie对比

4. 登出后令牌仍有效
   特征：token注销机制缺失
   测试：登出后重放token
```

---

## 推理式测试流程

### 第一步：发现端点

不要急着测试，先理解发现了什么：

```
你发现的端点列表：
- /api/login        → 认证入口
- /api/user/info    → 用户信息
- /api/order/list   → 订单列表
- /api/pay/refund   → 退款接口

思考这些接口的关系：
login → 获取token → 用token访问 user/info, order/list
refund → 需要订单 → 需要先有orderNo
```

### 第二步：理解数据流

```
思考数据怎么流动的：
1. 用户登录 → 获得userId和token
2. 用userId查询用户信息
3. 用userId查询用户订单
4. 用orderNo进行支付/退款

每个环节都可能出问题：
- login可能被绕过
- user/info可能泄露信息
- order/list可能存在越权
- refund可能缺少校验
```

### 第三步：构造攻击链

```
利用发现构造利用链：

发现1：用户枚举
  → 能获取userId列表

发现2：订单接口
  → 用userId查订单

发现3：订单详情泄露
  → 获取orderNo

发现4：退款接口
  → 用orderNo退款

组合成攻击链：
用户枚举 → 查订单 → 获取orderNo → 退款
```

### 第四步：验证并报告

```
验证漏洞时思考：
1. 这个漏洞是真的吗？ → 再测一次确认
2. 影响有多大？ → 能利用吗？有实际危害吗？
3. 怎么利用？ → 提供PoC
4. 如何修复？ → 提出修复建议
```

---

## 特殊情况处理

### 遇到加密/混淆的数据时

```
思考：
- 能解密吗？ → 查看前端JS代码
- 有密钥泄露吗？ → 检查响应、注释
- 能绕过吗？ → 不带加密参数试试
```

### 遇到验证码/限流时

```
思考：
- 验证码能绕过吗？ → 改参数、删cookie
- 限流能绕过吗？ → 改IP、延时
- 有风控吗？ → 行为异常检测
```

### 遇到WAP环境时

```
思考：
- 需要Cookie吗？ → 保持session
- 需要Referer吗？ → 添加来源
- 需要特定Header吗？ → 复制正常请求头
```

---

## 输出格式

完成测试后，按以下格式报告：

```markdown
## 漏洞列表

| 编号 | 类型 | 严重性 | 端点 | 参数 | PoC | 影响 |
|------|------|--------|------|------|-----|------|
| 1 | 敏感信息泄露 | HIGH | /api/user/info | - | GET /api/user/info 返回password | 可获取用户密码 |
| 2 | IDOR | HIGH | /api/order/list | userId | GET /api/order/list?userId=123 | 可查看他人订单 |

## 漏洞链构造

### 攻击链1
1. 用户枚举：GET /api/user/check?phone=138xxx → 获取userId
2. 订单查询：GET /api/order/list?userId=xxx → 获取orderNo  
3. 退款操作：POST /api/refund?orderNo=xxx&amount=0.01 → 退款成功

## 修复建议

1. 删除响应中的password字段
2. 添加userId归属校验
3. 退款接口添加权限校验
```

---

## 总结

### 核心思维

1. **不只是测试，要理解** - 理解接口在做什么
2. **不只是单个漏洞，要构造链** - 发现一个点，思考能做什么
3. **不只是工具，要用脑子** - 思考攻击者会怎么做
4. **不只是发现，要验证** - 确认漏洞真实存在

### 检测口诀

```
看到接口想认证
看到认证想绕过
看到数据想遍历
看到金额想篡改
看到用户想枚举
看到订单想越权
看到token想泄露
看到修改想权限
```

---

## 参考资源

如有疑问，可参考：
- OWASP API Security Top 10
- CVSS 漏洞评分标准
- 各语言 SQL 注入 payload 集
