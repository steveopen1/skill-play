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

> **核心定位**：推理式 API 安全测试框架
>
> **设计理念**：
> - 不硬编码具体接口，而是定义检测思路
> - 从响应中学习，自动推断下一步测试
> - 利用已发现的信息构造新请求
> - 模拟攻击者的思维方式

---

## 核心推理引擎

### 1. 响应推断引擎 (Response Inference)

```yaml
response_inference:
  name: "响应推断引擎"
  
  # 当响应包含敏感字段时，自动触发相关检测
  sensitive_patterns:
    - field: "password"
      action: "标记为敏感接口，测试脱敏"
    - field: "token"
      action: "提取并尝试作为认证token"
    - field: "userId" or "id"
      action: "尝试构造IDOR请求"
    - field: "phone"
      action: "测试手机号相关接口"
    - field: "orderNo" or "serialNumber"
      action: "测试订单相关越权"
    - field: "balance" or "amount"
      action: "测试资金相关漏洞"
      
  # 当响应返回用户信息时
  user_info_detected:
    - "提取所有userId"
    - "提取phone、email等标识符"
    - "构造userId参数测试越权"
    - "测试update/delete接口"
    
  # 当响应返回token时
  token_detected:
    - "提取token值"
    - "添加到认证上下文"
    - "使用token测试受保护接口"
```

### 2. 参数推理引擎 (Parameter Inference)

```yaml
parameter_inference:
  name: "参数推理引擎"
  
  # 从已发现接口推断参数
  common_params:
    user_identifiers:
      - "userId"
      - "uid"
      - "id"
      - "user_id"
      - "username"
      
    order_identifiers:
      - "orderNo"
      - "order_id"
      - "serialNumber"
      - "tradeNo"
      
    auth_identifiers:
      - "token"
      - "sessionId"
      - "Authorization"
      - "ticket"
      
  # 参数穷举策略
  param_enumeration:
    numeric:
      - "1,2,3,10,100,1000..."
      - "范围: 1-10000"
      
    string:
      - "admin"
      - "test"
      - "null"
      - "undefined"
      
    special:
      - "' OR '1'='1"
      - "<script>alert(1)</script>"
      - "../../../etc/passwd"
```

### 3. 认证上下文引擎 (Auth Context Engine)

```yaml
auth_context:
  name: "认证上下文传递"
  
  # 认证类型检测
  auth_types:
    - type: "Bearer Token"
      header: "Authorization: Bearer {token}"
      sources:
        - "响应中的token字段"
        - "X-Access-Token头"
        - "localStorage/sessionStorage"
        
    - type: "JWT"
      header: "Authorization: Bearer {jwt}"
      inference: "JWT格式识别 (header.payload.signature)"
      
    - type: "Session Cookie"
      header: "Cookie: JSESSIONID={sid}"
      
    - type: "API Key"
      header: "X-API-Key: {key}"
      
  # 认证状态传递
  context_propagation:
    when:
      - "发现登录接口"
      - "响应包含token"
      - "发现用户相关接口"
    then:
      - "提取认证信息"
      - "添加到后续请求"
      - "测试受保护资源"
```

### 4. 业务逻辑推理 (Business Logic Inference)

```yaml
business_logic_inference:
  name: "业务逻辑推理"
  
  # 从接口路径推断业务
  path_patterns:
    "/login":
      - "测试认证绕过"
      - "测试暴力破解"
      - "测试SQL注入"
      
    "/user":
      - "测试用户信息泄露"
      - "测试IDOR"
      - "测试越权修改"
      - "测试批量用户枚举"
      
    "/order":
      - "测试订单遍历"
      - "测试订单详情泄露"
      - "测试退款接口"
      
    "/pay" or "/refund":
      - "测试支付篡改"
      - "测试退款绕过"
      - "测试0元支付"
      
    "/register" or "/signup":
      - "测试任意注册"
      - "测试短信轰炸"
      - "测试默认密码"
      
    "/sms" or "/verification":
      - "测试短信轰炸"
      - "测试验证码枚举"
      - "测试验证码重放"
```

### 5. 漏洞链推理 (Vulnerability Chain Inference)

```yaml
vulnerability_chain:
  name: "漏洞链构造"
  
  # 利用已发现的漏洞构造利用链
  chains:
    - name: "用户信息 -> 越权"
      steps:
        - "发现用户查询接口"
        - "提取userId"
        - "尝试修改/删除他人数据"
        
    - name: "短信接口 -> 用户枚举"
      steps:
        - "发现短信接口"
        - "批量探测手机号"
        - "通过手机号获取userId"
        - "利用userId进行越权"
        
    - name: "订单遍历 -> 退款"
      steps:
        - "发现订单列表接口"
        - "遍历userId获取订单"
        - "提取orderNo"
        - "尝试退款"
        
    - name: "Token泄露 -> 账户接管"
      steps:
        - "发现token泄露接口"
        - "获取他人token"
        - "使用token冒充他人"
```

---

## 检测策略 (Detection Strategies)

### 1. SQL注入检测策略

```yaml
sql_injection:
  approach: "参数化模糊测试"
  
  targets:
    - "URL参数"
    - "POST body"
    - "JSON字段"
    - "HTTP头"
    
  payloads:
    error_based:
      - "' OR '1'='1"
      - "' OR '1'='1' --"
      - "1' AND '1'='2"
      
    blind:
      - "' AND 1=1 --"
      - "' AND 1=2 --"
      - "'; WAITFOR DELAY '0:0:5'--"
      
    time_based:
      - "'; SELECT pg_sleep(5)--"
      - "'; BENCHMARK(5000000,MD5(1))--"
      
  detection:
    - "响应包含SQL错误关键字"
    - "响应时间异常"
    - "响应内容差异"
```

### 2. 越权访问检测策略

```yaml
broken_access_control:
  approach: "参数遍历 + 身份切换"
  
  test_cases:
    - name: "IDOR - 资源遍历"
      method: "遍历ID参数访问他人资源"
      ids: "从发现的最小ID开始递增"
      
    - name: "纵向越权"
      method: "使用低权限token访问高权限接口"
      
    - name: "横向越权"
      method: "使用A用户token访问B用户资源"
      
  detection:
    - "返回了他人的敏感数据"
    - "操作成功但不是自己的资源"
```

### 3. 敏感信息泄露检测策略

```yaml
sensitive_data_exposure:
  approach: "响应内容审查"
  
  check_points:
    - "密码字段是否返回"
    - "token/session是否泄露"
    - "手机号/身份证是否完整"
    - "银行卡号是否脱敏"
    - "余额/资金信息是否暴露"
    
  response_analysis:
    - "检查敏感字段名"
    - "检查字段值是否完整"
    - "检查脱敏规则"
```

### 4. 认证绕过检测策略

```yaml
auth_bypass:
  approach: "认证机制测试"
  
  test_cases:
    - "空token测试"
    - "无效token测试"
    - "token过期时间篡改"
    - "JWT算法篡改 (alg: none)"
    - "使用其他用户token"
```

---

## 执行决策配置

```yaml
execution_flow:
  - phase: 0_prerequisites
    modules: [prerequisite_checker]
    always: true

  - phase: 1_asset_discovery
    stages:
      - name: static_analysis
        modules: [api_parser]
        always: true
        
      - name: dynamic_analysis
        modules: [dynamic_api_analyzer]
        condition: "playwright_available"
        
      - name: response_learning
        modules: [response_inference_engine]
        always: true
        # 从响应中学习，收集敏感字段、ID、token等
        
      - name: parameter_inference
        modules: [parameter_inference_engine]
        condition: "has_discovered_endpoints"
        
      - name: auth_context_learning
        modules: [auth_context_engine]
        condition: "found_login_or_token_endpoint"

  - phase: 2_vulnerability_testing
    # 推理式漏洞测试
    stages:
      - name: sql_injection
        modules: [inference_sql_tester]
        approach: "参数化模糊 + 响应推断"
        
      - name: broken_access_control
        modules: [inference_bac_tester]
        approach: "ID遍历 + 身份切换"
        
      - name: sensitive_data_exposure
        modules: [inference_sensitive_tester]
        approach: "响应内容审查"
        
      - name: auth_bypass
        modules: [inference_auth_tester]
        approach: "认证机制测试"
        
      - name: vulnerability_chain
        modules: [vulnerability_chain_engine]
        condition: "has_multiple_findings"
        # 利用已有发现构造漏洞链

  - phase: 3_exploitation
    # 深度利用测试
    stages:
      - name: token_hijacking
        condition: "found_token_leak"
        
      - name: account_takeover
        condition: "can_enumerate_users"
        
      - name: data_manipulation
        condition: "found_idor"
```

---

## 推理式检测示例

### 示例1: 发现用户查询接口

```
输入: GET /api/user/info?userId=1
响应: {"id":1,"name":"张三","phone":"13800138000","password":"xxx"}

推理过程:
1. 响应包含password字段 → 敏感信息泄露
2. 响应包含phone字段 → 测试手机号枚举
3. 响应包含id字段 → 尝试 userId=2,3,4...
4. 路径包含/user → 测试 /user/update, /user/delete

下一步测试:
- GET /api/user/info?userId=2  # 越权查看
- POST /api/user/update?id=2  # 越权修改
```

### 示例2: 发现登录接口

```
输入: POST /api/login
参数: {"username":"test","password":"test"}
响应: {"token":"eyJhbGciOiJIUzI1NiJ9...","userId":123}

推理过程:
1. 响应包含token → 添加到认证上下文
2. 发现登录接口 → 测试SQL注入
3. 发现登录接口 → 测试暴力破解
4. 使用token → GET /api/user/info (验证token有效)

下一步测试:
- POST /api/login {"username":"admin'--","password":"任意"}  # SQL注入
- 批量POST /api/login  # 暴力破解
- GET /api/admin/* (使用发现的token)  # 越权访问
```

### 示例3: 发现订单接口

```
输入: GET /api/order/list
响应: {"orders":[{"orderNo":"PK20240101001","userId":123,"amount":100}]}

推理过程:
1. 响应包含orderNo → 提取订单号
2. 响应包含userId → 测试 userId=其他值
3. 路径包含/order → 测试 /order/refund

下一步测试:
- GET /api/order/list?userId=124  # 越权查看他人订单
- POST /api/order/refund?orderNo=PK20240101001&amount=0.01  # 退款测试
```

---

## 核心模块能力池

| 模块 | 能力 | 推理类型 |
|-----|------|---------|
| `response_inference_engine` | 响应推断 | 学习 |
| `parameter_inference_engine` | 参数推理 | 构造 |
| `auth_context_engine` | 认证上下文传递 | 记忆 |
| `business_logic_engine` | 业务逻辑推断 | 联想 |
| `vulnerability_chain_engine` | 漏洞链构造 | 综合 |
| `inference_sql_tester` | 推理式SQL注入 | 验证 |
| `inference_bac_tester` | 推理式越权测试 | 验证 |
| `inference_auth_tester` | 推理式认证测试 | 验证 |

---

## 执行决策规则

```yaml
decision_rules:
  # 从响应中学习
  when_response_contains:
    "password" or "token" or "userId" or "phone":
      → extract_to_context()
      → trigger_related_tests()
      
  # 利用已有信息
  when_has_context:
    has_userId: → test_idor
    has_token: → test_protected_endpoints
    has_phone: → test_phone_enumeration
    
  # 漏洞链触发
  when_multiple_findings:
    has_userId + has_orderNo: → test_order_chain
    has_phone + can_register: → test_account_takeover
```

---

## 最佳实践

1. **边发现边测试**: 每发现一个新端点，立即进行基础测试
2. **响应即知识**: 响应中包含的信息都是下一步测试的线索
3. **上下文传递**: 发现的token、ID等信息要传递给后续请求
4. **漏洞链思维**: 不要只看单个漏洞，要思考漏洞组合利用
5. **攻击者视角**: 思考"如果我是攻击者，会怎么利用这个接口"

---

## 环境要求

### 必需依赖
- **requests**: HTTP 客户端
- **playwright**: 无头浏览器 (必须)

### 可选平替
- **pyppeteer**: 异步无头浏览器
- **selenium**: 多浏览器自动化
