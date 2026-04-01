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
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全)?(?:漏洞|问题)"
    - "(?:生成|输出)(?:安全)?报告"
  auto_trigger: true
---

# API 安全测试 Skill

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

---

## 核心能力架构

```
SKILL.md (决策框架)
    ↓ 指导
core/ (能力池，按需调用)
    ├── orchestrator.py      # 智能编排
    ├── browser_tester.py     # 浏览器测试 (SPA/JS分析)
    ├── deep_api_tester.py    # API 深度测试
    ├── api_fuzzer.py         # 模糊测试
    └── reasoning_engine.py  # 推理引擎 (多维度分析)
```

---

## 多维度判断框架

### 判断维度总览

| 维度 | 说明 | 判断依据 |
|------|------|---------|
| **D1: 状态码** | HTTP 响应状态 | 200/401/403/404/500 |
| **D2: 响应内容** | 数据有效性 | 业务数据/错误信息/空响应 |
| **D3: 认证要求** | 认证绕过检测 | Token/Cookie/Session |
| **D4: 敏感暴露** | 敏感信息泄露 | 密码/密钥/个人数据/配置 |
| **D5: 操作影响** | 未授权操作 | 增/删/改/查权限 |
| **D6: 业务上下文** | 端点功能分类 | 登录/用户/订单/管理 |

---

## D1: 状态码判断

### 状态码分析表

| 状态码 | 含义 | 判断逻辑 |
|--------|------|---------|
| **200** | 成功 | 需要进一步检查响应内容 |
| **401** | 未认证 | 检查是否应该需要认证 |
| **403** | 未授权 | 认证了但没权限 vs 正确拒绝 |
| **404** | 未找到 | 端点不存在 vs 正确隐藏 |
| **500** | 服务器错误 | 可能泄露内部信息 |
| **302/301** | 重定向 | 检查重定向目标是否可信 |

### 状态码组合判断

```
状态码 = 200 + 响应有数据 → 可能是未授权访问 (需验证)
状态码 = 401 + 响应有提示 → 可能是信息枚举 (如"用户不存在")
状态码 = 403 + 响应过快 → 可能是正确拒绝
状态码 = 200 + 响应空 → 可能是隐藏端点 (需进一步探测)
```

---

## D2: 响应内容判断

### 响应类型分类

| 类型 | 特征 | 风险等级 |
|------|------|---------|
| **业务数据** | 包含用户/订单/配置等结构化数据 | 高 |
| **认证令牌** | 包含 Token/JWT/Session | 高 |
| **错误详情** | 包含堆栈/路径/数据库信息 | 高 |
| **空响应** | 200 但无实质内容 | 中 |
| **重定向** | 跳转到其他页面 | 中 |
| **静态资源** | HTML/CSS/JS/图片 | 低 |

### 敏感字段检测

```python
# 敏感字段模式
SENSITIVE_PATTERNS = {
    # 认证相关
    'password', 'passwd', 'pwd', 'secret', 'token', 'jwt', 
    'session', 'cookie', 'auth',
    
    # 用户信息
    'email', 'phone', 'mobile', 'id_card', '身份证',
    'address', 'birthday', 'ssn',
    
    # 金融相关
    'bank', 'card', 'credit', 'account', 'balance', 'salary',
    
    # 配置相关
    'config', 'secret', 'key', 'api_key', 'private',
    'database', 'db_', 'connection',
    
    # 内部信息
    'internal', 'admin', 'root', 'path', 'filepath',
    'stack', 'trace', 'error', 'exception'
}
```

### 响应内容分析流程

```
响应状态码 = 200?
    │
    ├── 是 → 解析响应内容
    │         │
    │         ├── 包含敏感字段? → 高风险
    │         ├── 包含业务数据? → 中高风险
    │         ├── 错误详情? → 高风险
    │         └── 空/无意义 → 低风险
    │
    └── 否 → 检查其他维度
```

---

## D3: 认证绕过检测

### 认证要求矩阵

| 端点类型 | 期望认证 | 无认证时的风险 |
|---------|---------|---------------|
| `/user/*` | 必须 | 高 - 隐私泄露 |
| `/order/*` | 必须 | 高 - 交易风险 |
| `/admin/*` | 必须 | 高 - 权限提升 |
| `/login/*` | 不需要 | 低 - 正常公开 |
| `/captcha/*` | 不需要 | 低 - 正常公开 |
| `/public/*` | 不需要 | 低 - 设计公开 |
| `/health/*` | 不需要 | 低 - 监控端点 |

### 认证绕过测试方法

```bash
# 测试 1: 无认证访问
curl -s http://target/api/user/info

# 测试 2: 空 Token
curl -s http://target/api/user/info -H "Authorization: "

# 测试 3: 伪造 Token
curl -s http://target/api/user/info -H "Authorization: Bearer fake_token"

# 测试 4: 过期 Token
curl -s http://target/api/user/info -H "Authorization: Bearer expired_token"

# 测试 5: 其他用户 Token
curl -s http://target/api/user/info -H "Authorization: Bearer other_user_token"
```

### 认证判断逻辑

```
访问需要认证的端点:
    │
    ├── 返回 200 + 他人数据 → IDOR (高危)
    ├── 返回 200 + 自己数据 → 可能正常
    ├── 返回 401/403 → 正确拒绝 (低风险)
    └── 返回 200 + 空 → 可能配置错误 (中风险)
```

---

## D4: 敏感信息暴露

### 敏感度分级

| 等级 | 内容 | 示例 |
|------|------|------|
| **P0** | 认证凭据 | password, token, secret |
| **P1** | 个人隐私 | email, phone, id_card, address |
| **P2** | 金融数据 | bank_account, credit_card, balance |
| **P3** | 业务数据 | order_id, business_info |
| **P4** | 配置信息 | internal_path, version, stack_trace |

### 敏感信息判断流程

```
发现响应内容?
    │
    ├── 包含 P0 字段 (password/token/secret)
    │         └── → 严重漏洞 (Critical)
    │
    ├── 包含 P1 字段 (email/phone/id_card)
    │         └── → 高危漏洞 (High)
    │
    ├── 包含 P2 字段 (bank/credit/balance)
    │         └── → 高危漏洞 (High)
    │
    ├── 包含 P3 字段 (order/business)
    │         └── → 中危漏洞 (Medium)
    │
    └── 包含 P4 字段 (path/version/error)
              └── → 低危漏洞 (Low/Info)
```

---

## D5: 未授权操作检测

### 操作类型风险矩阵

| 操作 | HTTP 方法 | 风险 | 说明 |
|------|----------|------|------|
| 查询 | GET | 中 | 可能泄露数据 |
| 创建 | POST | 高 | 未授权创建资源 |
| 修改 | PUT/PATCH | 高 | 未授权修改数据 |
| 删除 | DELETE | 高 | 未授权删除资源 |
| 执行 | POST (action) | 高 | 未授权操作 |

### 未授权操作测试

```bash
# 查询其他用户数据 (IDOR)
curl -s http://target/api/user/1001
curl -s http://target/api/user/1002

# 未授权创建
curl -s http://target/api/user -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","role":"admin"}'

# 未授权修改
curl -s http://target/api/user/1001 -X PUT \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# 未授权删除
curl -s http://target/api/user/1001 -X DELETE

# 批量操作
curl -s http://target/api/users/batch-delete -X POST \
  -d '{"ids":[1,2,3,4,5]}'
```

---

## D6: 业务上下文分析

### 端点业务分类

```python
ENDPOINT_CATEGORIES = {
    # 认证类 - 通常公开
    'auth': ['/login', '/captcha', '/register', '/oauth', '/sms'],
    
    # 用户管理 - 需要认证
    'user': ['/user/', '/profile', '/password', '/avatar'],
    
    # 订单交易 - 需要认证
    'order': ['/order/', '/pay', '/refund', '/invoice'],
    
    # 系统管理 - 需要高权限
    'admin': ['/admin/', '/config', '/role', '/permission', '/system/'],
    
    # 数据操作 - 需要授权
    'data': ['/file/', '/upload', '/download', '/export', '/import'],
    
    # 内部接口 - 不应暴露
    'internal': ['/internal/', '/debug', '/actuator', '/swagger']
}
```

### 上下文风险评分

```python
CONTEXT_RISK_SCORE = {
    # 基础分数
    'base': 5,
    
    # 认证缺失 (应该是需要认证的)
    'no_auth_on_protected': +10,
    
    # 认证存在但可绕过
    'auth_bypass': +15,
    
    # 包含敏感数据
    'sensitive_data': +10,
    
    # 可未授权操作
    'unauthorized_action': +15,
    
    # 内部端点暴露
    'internal_exposed': +20,
    
    # 利用难度低
    'easy_exploit': +5,
}
```

---

## 多维度综合判断算法

### 判断流程

```
步骤 1: 发送测试请求
    ↓
步骤 2: 收集响应
    ├── HTTP 状态码
    ├── 响应头 (CORS, Cookie, etc.)
    ├── 响应体 (JSON/HTML/Error)
    └── 响应时间
    ↓
步骤 3: D1 状态码分析
    ├── 200? → 进入 D2
    ├── 401/403? → 可能正常拒绝
    └── 其他 → 标记异常
    ↓
步骤 4: D2 响应内容分析
    ├── 业务数据? → D3 认证检查
    ├── 敏感字段? → 提升风险等级
    └── 空/错误 → D4 配置检查
    ↓
步骤 5: D3 认证绕过测试
    ├── 应需认证但不需要? → 漏洞
    └── 认证可被绕过? → 漏洞
    ↓
步骤 6: D4-D6 综合评分
    ↓
步骤 7: 输出判断结果
```

### 综合评分公式

```
RiskScore = (
    D1_StateCode_Score * 0.15 +
    D2_Content_Score * 0.20 +
    D3_AuthBypass_Score * 0.25 +
    D4_SensitiveExposure_Score * 0.20 +
    D5_UnauthorizedAction_Score * 0.15 +
    D6_BusinessContext_Score * 0.05
)

风险等级:
- Critical: Score >= 80
- High: Score >= 60
- Medium: Score >= 40
- Low: Score >= 20
- Info: Score < 20
```

### 各维度权重

| 维度 | 权重 | 说明 |
|------|------|------|
| D3: 认证绕过 | 0.25 | 最重要，直接影响安全性 |
| D2: 响应内容 | 0.20 | 数据是否敏感 |
| D4: 敏感暴露 | 0.20 | 是否泄露敏感信息 |
| D1: 状态码 | 0.15 | 基础判断 |
| D5: 操作影响 | 0.15 | 是否可未授权操作 |
| D6: 业务上下文 | 0.05 | 辅助判断 |

---

## 漏洞判断标准

### 判断为"漏洞"的条件

```
必须满足 (P0):
  □ D3: 该端点应该需要认证但不需要
  □ 或 D3: 认证可被绕过

AND 满足以下至少一项 (P1):
  □ D2: 响应包含敏感数据
  □ D4: 暴露内部配置/路径
  □ D5: 可进行未授权操作

辅助条件 (P2):
  □ D6: 业务上下文风险高
  □ 利用难度低
  □ 影响范围大
```

### 判断为"误报"的条件

```
满足以下任一:
  □ D1: 返回 401/403 (正确拒绝)
  □ D2: 响应为空或无意义数据
  □ D3: 端点明确标记为公开
  □ D6: 业务上下文为公开信息
```

---

## 实际测试命令参考

### 完整测试流程

```bash
# 1. 探测端点
curl -s -I http://target/api/endpoint

# 2. 无认证访问
curl -s http://target/api/endpoint

# 3. 带空 Token
curl -s http://target/api/endpoint -H "Authorization: Bearer "

# 4. 带伪造 Token
curl -s http://target/api/endpoint -H "Authorization: Bearer fake"

# 5. 检查响应内容
# - 是否包含敏感字段
# - 是否有其他用户数据
# - 是否暴露内部信息

# 6. 尝试操作 (如果查询成功)
curl -s http://target/api/endpoint -X POST \
  -H "Content-Type: application/json" \
  -d '{"test":"data"}'
```

### CORS 漏洞多维判断

```bash
# 1. 检查 CORS 头
curl -s -i http://target/api/ -H "Origin: http://evil.com" | \
  grep -i "access-control"

# 2. 判断条件
#    Access-Control-Allow-Origin: * → 高风险
#    Access-Control-Allow-Origin: http://evil.com + allow-credentials: true → 严重
#    仅 allowedMethods: GET, POST → 中等
```

---

## 报告输出格式

```markdown
## Findings

### Finding N: [漏洞标题]

**Severity**: [Critical/High/Medium/Low/Info]

**Confidence**: [Confirmed/High/Medium/Low/Hypothesis]

**Affected Asset**: [端点]

**Multi-Dimension Analysis**:
| 维度 | 得分 | 说明 |
|------|------|------|
| D1 状态码 | X/20 | [分析] |
| D2 响应内容 | X/20 | [分析] |
| D3 认证绕过 | X/25 | [分析] |
| D4 敏感暴露 | X/20 | [分析] |
| D5 操作影响 | X/15 | [分析] |
| D6 业务上下文 | X/5 | [分析] |
| **总分** | **XX/100** | [风险等级] |

**Evidence**:
```http
[请求]
[响应头]
[响应体 - 脱敏处理]
```

**Root Cause**: [根本原因]

**Impact**: [影响分析]

**Remediation**: [修复建议]
```

---

## 工具选择

| 场景 | 工具 | 说明 |
|------|------|------|
| SPA 分析 | browser_tester.py | 动态 JS 分析 |
| API 测试 | deep_api_tester.py | 端点发现 + 多维检测 |
| 模糊测试 | api_fuzzer.py | SQL/XSS/注入 |
| 推理分析 | reasoning_engine.py | 综合判断 |
