# 漏洞验证标准

## 漏洞验证流程

```
发现 → 分析 → 验证 → 定级 → 报告

     ┌─────────────────────────────────┐
     │          发现 (Discover)          │
     │  - 可疑响应差异                   │
     │  - 异常状态码                     │
     │  - 敏感信息暴露                   │
     └─────────────┬───────────────────┘
                   ▼
     ┌─────────────────────────────────┐
     │          分析 (Analyze)          │
     │  - 多次请求确认差异稳定           │
     │  - 对比正常/异常请求              │
     │  - 排除 WAF/路由/认证             │
     └─────────────┬───────────────────┘
                   ▼
     ┌─────────────────────────────────┐
     │          验证 (Verify)           │
     │  - 10 维度检查                   │
     │  - 证据收集                      │
     │  - 确认或排除                     │
     └─────────────┬───────────────────┘
                   ▼
     ┌─────────────────────────────────┐
     │          定级 (Severity)         │
     │  - CVSS 评分                     │
     │  - 业务影响评估                   │
     │  - 修复优先级                     │
     └─────────────┬───────────────────┘
                   ▼
     ┌─────────────────────────────────┐
     │          报告 (Report)           │
     │  - 漏洞详情                      │
     │  - 复现步骤                      │
     │  - 修复建议                      │
     └─────────────────────────────────┘
```

---

## 10 维度验证检查表

| 维度 | 检查项 | 通过条件 | 典型误报 |
|------|--------|----------|----------|
| **D1 响应类型** | 是 JSON 还是 HTML? | JSON 响应包含业务数据 | HTML 页面 (WAF/SPA) |
| **D2 状态码** | 状态码是否合理? | 与漏洞场景匹配 | 302 重定向 |
| **D3 响应长度** | 响应长度是否正常? | 长度 > 100 字节 | 过短响应 (拦截) |
| **D4 WAF 识别** | 是否为 WAF 拦截? | 无 WAF 特征 | HTML 拦截页 |
| **D5 敏感信息** | 是否包含敏感字段? | 字段不属于测试数据 | 测试假数据 |
| **D6 一致性** | 多次请求是否一致? | 多次响应相同 | 不稳定响应 |
| **D7 SQL 注入** | 是否包含 SQL 错误? | 无 SQL 错误特征 | 通用错误信息 |
| **D8 IDOR** | 是否返回他人数据? | 返回数据属于他人 | 返回自己的数据 |
| **D9 认证绕过** | 是否返回 token/session? | Token 有效且可用 | 无效/过期 Token |
| **D10 信息泄露** | 是否泄露非公开信息? | 信息非公开 | 公开信息 |

---

## 各类型漏洞验证标准

### SQL 注入

```python
# 验证标准
SQLI_VERIFICATION = {
    # 必须满足
    'required': [
        '响应包含数据库错误信息',
        'UNION 查询有回显',
        '时间盲注有延迟',
    ],
    # 参考指标
    'indicators': [
        '错误信息包含 SQL 关键词',
        '响应时间 > 5秒 (盲注)',
        '页面结构与正常响应不同 (UNION)',
    ],
    # 排除条件
    'exclude': [
        '通用错误信息 (无 SQL 关键词)',
        'WAF 拦截页面',
        '响应时间正常但无其他特征',
    ]
}

# 验证步骤
def verify_sqli(url, param, payload):
    # 1. 原始请求 (基线)
    baseline = requests.get(url, params={param: "1"})
    
    # 2. 注入测试
    inject = requests.get(url, params={param: payload})
    
    # 3. 对比分析
    indicators = {
        'sql_error': contains_sql_error(inject.text),
        'response_diff': baseline.text != inject.text,
        'data_leak': extract_data(inject.text),  # UNION 注入时
        'time_delay': measure_time(inject),  # 盲注时
    }
    
    # 4. 综合判断
    if indicators['sql_error'] or indicators['data_leak'] or indicators['time_delay'] > 5:
        return True, indicators
    return False, indicators
```

### XSS

```python
# 验证标准
XSS_VERIFICATION = {
    'required': [
        'Payload 未经处理回显',
        '可执行 JavaScript',
    ],
    'indicators': [
        'Payload 在响应中完整回显',
        '<script> 标签未转义',
        '事件处理器未被过滤',
    ],
    'exclude': [
        'HTML 实体转义',
        '<script> 被删除/过滤',
        'CSP 阻止执行',
    ]
}

# 验证步骤
def verify_xss(url, param, payload):
    # 1. 发送 XSS Payload
    resp = requests.get(url, params={param: payload})
    
    # 2. 检查回显
    if payload in resp.text:
        # 3. 检查是否是存储型
        # 用另一请求检查是否持久化
        resp2 = requests.get(url)  # 再次访问
        
        if payload in resp2.text:
            return True, {'type': 'stored', 'persisted': True}
        return True, {'type': 'reflected', 'persisted': False}
    
    return False, {'type': None}
```

### IDOR

```python
# 验证标准
IDOR_VERIFICATION = {
    'required': [
        '用自己的 Token 访问他人资源',
        '返回他人敏感数据',
    ],
    'indicators': [
        '资源 ID 可枚举',
        '响应包含不同用户数据',
        '无权限检查错误',
    ],
    'exclude': [
        '返回 401/403',
        '返回空数据',
        '返回自己的数据',
    ]
}

# 验证步骤
def verify_idor(base_url, token, victim_resource_id):
    # 1. 自己的资源 (基线)
    headers = {'Authorization': f'Bearer {token}'}
    my_resource = requests.get(
        f'{base_url}/resource/1',
        headers=headers
    )
    
    # 2. 他人的资源 (测试)
    victim_resource = requests.get(
        f'{base_url}/resource/{victim_resource_id}',
        headers=headers
    )
    
    # 3. 对比分析
    if victim_resource.status_code == 200:
        my_data = my_resource.json()
        victim_data = victim_resource.json()
        
        # 检查是否是不同用户的数据
        if my_data.get('userId') != victim_data.get('userId'):
            return True, {
                'my_user': my_data.get('userId'),
                'victim_user': victim_data.get('userId'),
                'leaked_fields': list(victim_data.keys())
            }
    
    return False, {'status': victim_resource.status_code}
```

### JWT 漏洞

```python
# 验证标准
JWT_VERIFICATION = {
    'alg_none': {
        'required': ['使用 alg:none 的 Token 可正常使用'],
        'test': '去除签名的 Token 可通过验证',
    },
    'key_confusion': {
        'required': ['使用公钥作为对称密钥可伪造 Token'],
        'test': 'RS256 算法可被转换为 HS256',
    },
    'weak_secret': {
        'required': ['弱密钥可被暴力破解'],
        'test': '常见密钥可成功签名',
    },
    'kid_injection': {
        'required': ['kid 参数存在 SQL/NoSQL 注入'],
        'test': '利用 kid 注入读取任意密钥',
    },
}

def verify_jwt_alg_none(token):
    header = decode_header(token)
    if header.get('alg') == 'none':
        # 尝试去除签名
        unsigned_token = create_unsigned_token(header, payload)
        if is_valid(unsigned_token):
            return True, {'alg': 'none', 'exploitable': True}
    return False, {}
```

### 敏感信息泄露

```python
# 验证标准
SENSITIVE_DATA_VERIFICATION = {
    'password': {
        'required': ['响应包含明文密码'],
        'severity': 'Critical',
        'exclude': ['密码已加密/哈希', '测试数据密码'],
    },
    'token': {
        'required': ['响应包含有效 Token'],
        'severity': 'High',
        'exclude': ['过期 Token', '测试 Token'],
    },
    'api_key': {
        'required': ['响应包含有效 API 密钥'],
        'severity': 'High',
        'exclude': ['测试环境密钥'],
    },
    'internal_ip': {
        'required': ['响应包含内网 IP 地址'],
        'severity': 'Medium',
    },
    'internal_url': {
        'required': ['响应包含内部系统 URL'],
        'severity': 'Medium',
    },
}

def verify_sensitive_data(resp, field_name):
    sensitive_fields = {
        'password', 'passwd', 'pwd', 'secret',
        'token', 'api_key', 'apikey', 'private_key',
        'ssn', 'id_card', 'phone', 'email',
    }
    
    if field_name.lower() in sensitive_fields:
        # 检查值是否存在
        value = resp.json().get(field_name)
        if value and value not in ['', 'null', 'undefined']:
            return True, {'field': field_name, 'severity': get_severity(field_name)}
    
    return False, {}
```

---

## 误报排除规则

### 规则 1: WAF 识别

```python
WAF_PATTERNS = [
    # 通用 WAF
    r'(?i)(waf|firewall|attack|blocked|intercepted)',
    r'(?i)(forbidden|access.*denied|security)',
    # 特定 WAF
    r'Aliyun',
    r'Tencet',
    r'AWS.*WAF',
    r'Cloudflare',
    r'Incapsula',
]

def is_waf_response(resp):
    content = resp.text
    for pattern in WAF_PATTERNS:
        if re.search(pattern, content):
            return True
    return False
```

### 规则 2: SPA 路由识别

```python
SPA_PATTERNS = [
    r'<div id="app">',
    r'<div id="root">',
    r'__VUE__',
    r'__NUXT__',
    r'ReactDOM',
    r'webpack',
]

def is_spa_response(resp):
    content = resp.text
    for pattern in SPA_PATTERNS:
        if re.search(pattern, content):
            return True
    return False
```

### 规则 3: 统一错误页识别

```python
ERROR_PAGE_PATTERNS = [
    r'页面不存在|404 Not Found',
    r'服务器错误|500 Internal Server Error',
    r'请求超时|Timeout',
]

def is_error_page(resp):
    for pattern in ERROR_PAGE_PATTERNS:
        if re.search(pattern, resp.text):
            return True
    return False
```

---

## 验证结果记录

### 漏洞验证报告模板

```markdown
## 漏洞验证记录

### 基本信息
- **漏洞类型**: SQL 注入
- **测试目标**: GET /api/user?id=1
- **测试时间**: 2026-04-03 10:30:00
- **验证人员**: Agent

### 验证过程
1. **原始请求**
   - 请求: GET /api/user?id=1
   - 响应: 200 OK, {"userId": 1, "name": "张三"}

2. **Payload 测试**
   - Payload: 1' OR '1'='1
   - 请求: GET /api/user?id=1' OR '1'='1
   - 响应: 200 OK, {"userId": 1, "name": "张三"}
   - 响应: [{"userId": 1}, {"userId": 2}, {"userId": 3}]

3. **对比分析**
   - 原始响应: 1 条记录
   - 注入响应: 3 条记录
   - **差异确认**: 存在 SQL 注入

### 维度评分
| 维度 | 得分 | 说明 |
|------|------|------|
| D1 响应类型 | 15/15 | JSON 响应正常 |
| D2 状态码 | 15/15 | 200 OK |
| D3 响应长度 | 18/20 | 长度增加 |
| D4 WAF | 20/20 | 无 WAF 特征 |
| D5 敏感信息 | 15/20 | 数据泄露 |
| D6 一致性 | 15/15 | 多次一致 |
| D7 SQL注入 | 25/25 | 确认注入 |
| D8 IDOR | 15/15 | N/A |
| D9 认证绕过 | 15/15 | N/A |
| D10 信息泄露 | 10/20 | 泄露用户列表 |

### 最终结论
- **漏洞确认**: ✅ 是
- **CVSS**: 8.6 (High)
- **风险等级**: High
```

---

## 验证检查清单

```
□ 基础验证
  □ 多次请求确认差异稳定
  □ 对比正常/异常响应
  □ 排除 WAF/安全设备
  □ 排除 SPA 路由
  □ 排除测试数据

□ 类型验证
  □ SQL 注入: 数据库错误/数据泄露/时间延迟
  □ XSS: Payload 回显/JavaScript 执行
  □ IDOR: 跨用户数据访问
  □ JWT: 算法攻击/密钥破解
  □ SSRF: 内网访问/元数据获取

□ 证据收集
  □ 请求/响应截图
  □ Payload 记录
  □ 时间戳记录
  □ 关键响应内容

□ 定级评估
  □ CVSS 计算
  □ 业务影响评估
  □ 修复优先级
```
