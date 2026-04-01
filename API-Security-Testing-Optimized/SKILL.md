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
    - "OSS 检测"
    - "bucket 检测"
    - "存储桶检测"
    - "S3 检测"
  - "阿里云安全"
  - "腾讯云安全"
  - "GraphQL 安全"
  - "websocket 安全"
  - "graphql 检测"
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全|云存储|oss)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全|oss|云存储|bucket)?(?:漏洞|问题)"
    - "(?:生成|输出)(?:安全|云存储)?报告"
    - "(?:scan|test)(?:oss|bucket|s3|cloud storage)"
  auto_trigger: true
---

# API 安全测试 Skill

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

---

## 强制执行声明

**本 Skill 必须完整执行，不允许跳过任何阶段。**

```
重要：
1. Agent 必须执行所有阶段，不得跳过
2. 前置检查是强制性的，必须完成
3. 发现的模块能力必须调用，除非明确不可用
4. 所有判断必须基于多维度分析，不得仅凭单一指标
```

---

## 阶段 0: 前置检查 (强制执行)

**触发**: Skill 激活后立即执行，不得跳过

### 0.1 环境检查

```bash
# 检查 Python 环境
python3 --version

# 检查 pip 是否可用
pip3 --version
```

### 0.2 依赖检查与安装 (强制性)

```bash
# 检查 requests
python3 -c "import requests; print('requests:', requests.__version__)"

# 如果未安装，执行安装
pip3 install requests

# 检查 playwright
python3 -c "import playwright; print('playwright: OK')"

# 如果未安装，执行安装
pip3 install playwright
playwright install chromium

# 检查 pyppeteer (browser_tester 需要)
python3 -c "import pyppeteer; print('pyppeteer: OK')"

# 如果未安装，执行安装  
pip3 install pyppeteer

# 检查 pytest
python3 -c "import pytest; print('pytest: OK')"

# 如果未安装
pip3 install pytest

# 检查所有 core 模块是否可导入
cd /workspace/API-Security-Testing-Optimized
python3 -c "
import sys
sys.path.insert(0, '.')
from core import browser_tester, deep_api_tester_v55, api_fuzzer, advanced_recon
print('All core modules: OK')
"
```

### 0.3 能力验证

```bash
# 验证 browser_tester 能力
python3 -c "
from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
config = BrowserTestConfig(target_url='http://example.com', engine=BrowserEngine.PUPPETEER)
tester = BrowserAutomationTester(config)
if tester.engine.value == 'none':
    print('[WARN] browser_tester: 浏览器引擎不可用')
    print('[FORCE] 尝试安装 playwright...')
    import subprocess
    subprocess.run(['pip3', 'install', 'playwright'], capture_output=True)
    subprocess.run(['playwright', 'install', 'chromium'], capture_output=True)
else:
    print('[OK] browser_tester: 引擎可用')
"

# 验证 deep_api_tester 能力
python3 -c "
from core.deep_api_tester_v55 import DeepAPITesterV55
tester = DeepAPITesterV55(target='http://example.com')
print('[OK] deep_api_tester_v55: 可用')
"

# 验证 api_fuzzer 能力
python3 -c "
import requests
from core.api_fuzzer import APIfuzzer
fuzzer = APIfuzzer(session=requests.Session())
print('[OK] api_fuzzer: 可用')
"
```

### 0.4 检查结果处理

| 检查项 | 状态 | 处理方式 |
|--------|------|---------|
| requests | 不可用 | **强制安装** `pip install requests` |
| playwright | 不可用 | **强制安装** `pip install playwright && playwright install chromium` |
| pyppeteer | 不可用 | **强制安装** `pip install pyppeteer` |
| browser_tester | 引擎不可用 | **强制安装** playwright 及其浏览器 |
| deep_api_tester | 不可导入 | 检查 core/ 目录，报告错误 |
| api_fuzzer | 不可导入 | 检查 core/ 目录，报告错误 |

**强制规则**: 任何核心模块不可用，都必须先解决，不得跳过使用该模块的能力。

---

## 阶段 1: 目标探测与资产发现

**触发**: 前置检查完成后自动执行

### 1.1 基础探测

```bash
# HTTP 头探测
curl -s -I http://target/

# 服务器指纹
curl -s http://target/ | grep -iE "(server:|nginx|apache|tomcat)"

# 技术栈识别
curl -s http://target/ | grep -iE "(vue|react|angular|jquery|elementui)"
```

### 1.2 启用 browser_tester 分析 SPA

**强制执行**: 如果目标是 SPA (Vue/React/Angular)，必须使用 browser_tester

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig

def analyze_spa(target_url):
    """使用浏览器分析 SPA"""
    print(f"[browser_tester] 初始化浏览器，目标: {target_url}")
    
    config = BrowserTestConfig(
        target_url=target_url,
        engine=BrowserEngine.PUPPETEER,
        headless=True,
        timeout=30000
    )
    
    tester = BrowserAutomationTester(config)
    
    if tester.engine.value == "none":
        # 强制安装
        print("[browser_tester] 引擎不可用，强制安装...")
        import subprocess
        subprocess.run(['pip3', 'install', 'playwright', 'pyppeteer'], capture_output=True)
        subprocess.run(['playwright', 'install', 'chromium'], capture_output=True)
        # 重新初始化
        tester = BrowserAutomationTester(config)
        
        if tester.engine.value == "none":
            raise Exception("[browser_tester] 安装后仍然不可用")
    
    print(f"[browser_tester] 引擎状态: {tester.engine.value}")
    
    # 执行分析
    print("[browser_tester] 开始 JS 分析...")
    
    # 获取发现的端点
    if hasattr(tester, 'extract_endpoints'):
        endpoints = tester.extract_endpoints()
        print(f"[browser_tester] 发现端点: {len(endpoints)}")
    
    # 测试 CORS
    if hasattr(tester, 'test_cors'):
        cors_result = tester.test_cors(target_url)
        print(f"[browser_tester] CORS 测试: {cors_result}")
    
    return tester

# 执行
analyze_spa('http://58.215.18.57:91')
```

### 1.2 发现云存储端点? → 触发阶段 5

**触发条件**: 从 JS/响应中发现以下任一模式

| 模式类型 | 检测特征 | 示例 |
|---------|---------|------|
| **URL 域名** | 匹配云厂商域名 | `*.oss-aliyuncs.com`, `*.cos.myqcloud.com` |
| **URL 路径** | 匹配存储路径 | `/minio/`, `/file/`, `/upload/`, `/bucket/` |
| **响应头** | 包含存储 Header | `X-OSS-*`, `X-Amz-*`, `X-Minio-*` |
| **响应内容** | XML 格式特征 | `<ListBucketResult>`, `<AccessControlPolicy>` |

**自动检测代码**:
```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.cloud_storage_tester import CloudStorageTester

def should_trigger_cloud_test(endpoints: List[str], js_content: str = None) -> bool:
    """判断是否应该触发云存储检测"""
    
    # 1. URL 路径模式
    storage_path_patterns = [
        '/minio/', '/minio-api/', '/file/', '/files/',
        '/upload/', '/uploads/', '/storage/', '/bucket/',
        '/oss/', '/cos/', '/s3/', '/obs/',
        '/api/file/', '/api/upload/', '/api/storage/'
    ]
    
    for endpoint in endpoints:
        for pattern in storage_path_patterns:
            if pattern in endpoint.lower():
                return True
    
    # 2. URL 域名模式
    domain_patterns = [
        r'oss-.*\.aliyuncs\.com',
        r'cos\..*\.myqcloud\.com',
        r's3\..*\.amazonaws\.com',
        r'obs\..*\.myhwclouds\.com',
        r'minio',
    ]
    
    for endpoint in endpoints:
        for pattern in domain_patterns:
            if re.search(pattern, endpoint.lower()):
                return True
    
    # 3. JS/响应内容检测
    if js_content:
        tester = CloudStorageTester()
        found = tester.discover_from_text(js_content)
        if found:
            return True
    
    return False

def trigger_cloud_storage_test(target: str, endpoints: List[str], js_content: str = None):
    """触发云存储安全检测"""
    
    if should_trigger_cloud_test(endpoints, js_content):
        print("[Decision] 发现云存储特征，触发阶段 5...")
        
        # 调用云存储检测
        from core.cloud_storage_tester import CloudStorageTester
        tester = CloudStorageTester()
        
        # 优先测试 URL 中的存储端点
        storage_endpoints = []
        for ep in endpoints:
            if any(p in ep.lower() for p in ['/minio/', '/file/', '/upload/', '/bucket/', '/oss/', '/cos/']):
                storage_endpoints.append(ep)
        
        if storage_endpoints:
            for ep in storage_endpoints:
                print(f"[CloudStorage] 测试: {ep}")
                results = tester.full_test(ep)
                # 处理结果...
        
        # 也测试当前域名的常见存储路径
        if 'minio' in str(endpoints).lower():
            # 使用 test_current_domain_storage
            from core.cloud_storage_tester import test_current_domain_storage
            results = test_current_domain_storage(target)
    
    return None
```

### 1.3 启用 deep_api_tester 发现端点

**强制执行**: 必须调用 deep_api_tester 进行端点发现

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.deep_api_tester_v55 import DeepAPITesterV55

def api_discovery(target_url):
    """使用 API 测试器发现端点"""
    print(f"[deep_api_tester] 初始化，目标: {target_url}")
    
    tester = DeepAPITesterV55(target=target_url, headless=True)
    
    print("[deep_api_tester] 执行端点发现和漏洞扫描...")
    result = tester.run_test()
    
    print(f"[deep_api_tester] 扫描完成")
    print(f"[deep_api_tester] 报告已保存")
    
    return tester

# 执行
api_discovery('http://58.215.18.57:91')
```

---

## 阶段 2: 多维度漏洞分析

**触发**: 阶段 1 发现端点后执行

### 2.1 启用 api_fuzzer 进行深度测试

**强制执行**: 发现端点后必须使用 api_fuzzer 验证漏洞

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

import requests
from core.api_fuzzer import APIfuzzer

def vulnerability_testing(api_base):
    """使用 Fuzzer 进行漏洞测试"""
    print(f"[api_fuzzer] 初始化，目标: {api_base}")
    
    session = requests.Session()
    fuzzer = APIfuzzer(session=session)
    
    # 设置目标
    if hasattr(fuzzer, 'set_target'):
        fuzzer.set_target(api_base)
    
    print("[api_fuzzer] 执行漏洞测试...")
    
    # SQL 注入测试
    if hasattr(fuzzer, 'fuzz_sqli'):
        sqli_result = fuzzer.fuzz_sqli()
        print(f"[api_fuzzer] SQL注入测试: {sqli_result}")
    
    # XSS 测试
    if hasattr(fuzzer, 'fuzz_xss'):
        xss_result = fuzzer.fuzz_xss()
        print(f"[api_fuzzer] XSS 测试: {xss_result}")
    
    # 路径遍历测试
    if hasattr(fuzzer, 'fuzz_path_traversal'):
        pt_result = fuzzer.fuzz_path_traversal()
        print(f"[api_fuzzer] 路径遍历测试: {pt_result}")
    
    return fuzzer

# 执行
vulnerability_testing('http://58.215.18.57:91/icp-api')
```

### 2.2 多维度判断框架

#### 判断维度

| 维度 | 权重 | 判断依据 |
|------|------|---------|
| D1: 状态码 | 15% | 200/401/403/404/500 |
| D2: 响应内容 | 20% | 敏感字段、业务数据、错误信息 |
| D3: 认证绕过 | 25% | Token/Cookie/Session 验证 |
| D4: 敏感暴露 | 20% | 密码/密钥/个人数据/配置 |
| D5: 操作影响 | 15% | 增/删/改/查 权限 |
| D6: 业务上下文 | 5% | 端点功能分类 |

### 2.3 发现 GraphQL? → 触发专项测试

**触发条件**:

| 特征 | 检测方法 |
|------|---------|
| URL 包含 `/graphql`, `/graphQL` | 路径匹配 |
| 响应包含 `application/graphql` | Content-Type |
| 响应包含 `"__schema"`, `"__type"` | GraphQL Introspection |
| 响应包含 `{"data":` + GraphQL 结构 | JSON 结构 |

**GraphQL 专项测试** (参考 `references/graphql-guidance.md`):

```python
GRAPHQL_TRIGGER_PATTERNS = {
    'path': ['/graphql', '/graphQL', '/api/graphql'],
    'content': ['__schema', '__type', 'application/graphql'],
    'header': ['application/graphql']
}

def is_graphql_endpoint(endpoint, response) -> bool:
    """判断是否为 GraphQL 端点"""
    # 1. 路径匹配
    for pattern in GRAPHQL_TRIGGER_PATTERNS['path']:
        if pattern in endpoint.lower():
            return True
    
    # 2. 响应 Content-Type
    if response and 'application/graphql' in response.headers.get('Content-Type', ''):
        return True
    
    # 3. 响应内容包含 GraphQL 结构
    if response:
        text = response.text
        if '__schema' in text or '__type' in text:
            return True
        if '"data":' in text and '{' in text:
            # 可能是 GraphQL JSON 响应
            pass
    
    return False
```

### 2.4 发现 IDOR/越权? → 触发权限测试

**触发条件**:

| 特征 | 说明 |
|------|------|
| 端点包含 `/user/{id}`, `/order/{id}` | 资源 ID 参数 |
| 响应包含其他用户数据 | 数据泄露 |
| 修改请求可指定资源 ID | 权限检查 |

```python
IDOR_PATTERNS = {
    'path': ['/user/', '/users/', '/order/', '/orders/', '/account/', '/profile/'],
    'param': ['id=', 'userId=', 'orderId=', 'account_id='],
}

def check_idor_indicators(endpoint, response) -> bool:
    """检查 IDOR 风险"""
    # 1. 路径模式
    for pattern in IDOR_PATTERNS['path']:
        if pattern in endpoint:
            return True
    
    # 2. 响应内容泄露其他用户数据
    if response and response.status_code == 200:
        # 检查是否包含其他用户信息
        patterns = ['"id":', '"username":', '"email":', '"phone":']
        if any(p in response.text for p in patterns):
            return True
    
    return False
```

### 2.5 发现暴力破解风险? → 触发登录测试

**触发条件**:

| 特征 | 说明 |
|------|------|
| 端点包含 `/login`, `/auth`, `/signin` | 登录接口 |
| `/register`, `/forgot-password` | 注册/密码重置 |
| 无验证码或 rate limit | 防护缺失 |

```python
BRUTE_FORCE_PATTERNS = {
    'path': ['/login', '/auth', '/signin', '/logon', '/register', '/forgot', '/reset'],
    'keyword': ['password', 'username', 'captcha', 'verify']
}

def check_brute_force_risk(endpoint) -> bool:
    """检查暴力破解风险"""
    endpoint_lower = endpoint.lower()
    
    # 1. 登录相关端点
    for pattern in BRUTE_FORCE_PATTERNS['path']:
        if pattern in endpoint_lower:
            return True
    
    # 2. 包含敏感参数
    for pattern in BRUTE_FORCE_PATTERNS['keyword']:
        if pattern in endpoint_lower:
            return True
    
    return False
```

### 2.6 发现 WebSocket? → 触发 WS 测试

**触发条件**:

| 特征 | 检测方法 |
|------|---------|
| URL 包含 `/ws`, `/websocket` | 路径匹配 |
| 响应头包含 `Upgrade: websocket` | HTTP 升级 |
| 响应包含 `websocket` 关键字 | 内容匹配 |

```python
WEBSOCKET_PATTERNS = {
    'path': ['/ws', '/websocket', '/ws/'],
    'header': ['upgrade', 'websocket'],
    'content': ['websocket', 'ws://', 'wss://']
}

def check_websocket_endpoint(endpoint, response) -> bool:
    """判断是否需要 WebSocket 测试"""
    # 1. 路径匹配
    for pattern in WEBSOCKET_PATTERNS['path']:
        if pattern in endpoint.lower():
            return True
    
    # 2. 响应头
    if response:
        upgrade = response.headers.get('Upgrade', '').lower()
        if 'websocket' in upgrade:
            return True
    
    return False
```

### 2.7 阶段间循环

```
阶段 1: 资产发现
    │
    ├── 发现 /graphql → GraphQL 专项 → 阶段 2.3
    ├── 发现 /ws → WebSocket 专项 → 阶段 2.6
    ├── 发现 /login → 暴力破解测试 → 阶段 2.5
    ├── 发现 /user/{id} → IDOR 测试 → 阶段 2.4
    ├── 发现 /file/, /minio/ → 阶段 5 云存储
    └── 其他 → 继续阶段 2.1

#### 综合评分算法

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

#### 漏洞判定条件

```
必须满足 P0:
  □ D3: 该端点应该需要认证但不需要
  □ 或 D3: 认证可被绕过

AND 满足以下至少一项 P1:
  □ D2: 响应包含敏感数据
  □ D4: 暴露内部配置/路径
  □ D5: 可进行未授权操作

 辅助条件 P2:
   □ D6: 业务上下文风险高
   □ 利用难度低
   □ 影响范围大
 ```

### 2.2 发现云存储特征? → 触发阶段 5

**自动检测决策**: 在阶段 2 分析过程中，发现以下任一情况应立即触发云存储检测

```python
CLOUD_TRIGGER_PATTERNS = {
    # 端点路径特征
    'path': [
        '/file/', '/files/', '/upload/', '/uploads/',
        '/storage/', '/bucket/', '/oss/', '/cos/', '/s3/',
        '/minio/', '/minio-api/', '/api/file/', '/api/upload/'
    ],
    # URL 域名特征
    'domain': [
        'oss-', 'aliyuncs.com', 'cos.', 'myqcloud.com',
        'obs.', 'myhwclouds.com', 's3.', 'amazonaws.com',
        'minio', ':9000', ':9001'
    ],
    # 响应 Header 特征
    'header': [
        'x-oss-', 'x-amz-', 'x-minio-', 'x-cos-', 'x-obs-'
    ],
    # 响应内容特征
    'content': [
        '<ListBucket', '<AccessControlPolicy', 'ListBucketResult'
    ]
}

def check_and_trigger_cloud_storage(response, endpoint) -> bool:
    """检查是否应触发云存储检测"""
    
    # 1. 检查端点路径
    for pattern in CLOUD_TRIGGER_PATTERNS['path']:
        if pattern in endpoint.lower():
            print(f"[Cloud Trigger] 匹配路径模式: {pattern}")
            return True
    
    # 2. 检查 URL 域名
    for pattern in CLOUD_TRIGGER_PATTERNS['domain']:
        if pattern in endpoint.lower():
            print(f"[Cloud Trigger] 匹配域名模式: {pattern}")
            return True
    
    # 3. 检查响应头
    if response:
        headers_text = str(response.headers).lower()
        for pattern in CLOUD_TRIGGER_PATTERNS['header']:
            if pattern in headers_text:
                print(f"[Cloud Trigger] 匹配响应头: {pattern}")
                return True
        
        # 4. 检查响应内容
        content_text = response.text.lower()
        for pattern in CLOUD_TRIGGER_PATTERNS['content']:
            if pattern in content_text:
                print(f"[Cloud Trigger] 匹配响应内容: {pattern}")
                return True
    
    return False
```

**决策树**:
```
阶段 2 分析响应
    │
    ├── 发现 /file/, /upload/, /storage/ 等路径?
    │       └── → 触发阶段 5
    │
    ├── 发现 oss-, cos-, minio 等域名?
    │       └── → 触发阶段 5
    │
    ├── 响应包含 X-OSS-*, X-Amz-* Header?
    │       └── → 触发阶段 5
    │
    ├── 响应内容包含 <ListBucket>?
    │       └── → 触发阶段 5
    │
    └── 其他
            └── → 继续分析
```

---

## 阶段 3: 验证与分类

### 3.1 验证发现的漏洞

```python
def validate_vulnerability(endpoint, test_method):
    """多维度验证漏洞"""
    results = {
        'D1_status': None,
        'D2_content': None,
        'D3_auth': None,
        'D4_sensitive': None,
        'D5_action': None,
        'D6_context': None
    }
    
    # D1: 状态码
    response = test_method(endpoint)
    results['D1_status'] = response.status_code
    
    # D2: 响应内容分析
    if 'password' in response.text or 'token' in response.text:
        results['D2_content'] = 'sensitive'
    elif 'user' in response.text or 'email' in response.text:
        results['D2_content'] = 'personal_data'
    else:
        results['D2_content'] = 'normal'
    
    # D3: 认证检查
    if response.status_code == 200:
        results['D3_auth'] = 'bypass'
    elif response.status_code in [401, 403]:
        results['D3_auth'] = 'protected'
    
    # D4: 敏感信息
    sensitive_patterns = ['password', 'secret', 'key', 'token', 'api_key']
    if any(p in response.text.lower() for p in sensitive_patterns):
        results['D4_sensitive'] = 'exposed'
    
    return results
```

### 3.2 误报识别

```
以下情况判定为误报:
- 返回 401/403 (正确拒绝)
- 响应为空或无意义数据
- 端点明确标记为公开 (如 /login, /captcha)
- 业务上下文为公开信息 (如 /health, /version)
```

---

## 阶段 4: 报告生成

### 4.1 强制输出格式

```markdown
## Scope
- Target: [目标 URL]
- Assessment Mode: [文档驱动/被动/主动]
- Authorization: [授权范围]

## Asset Summary
- Base URLs: [发现的所有 base URL]
- API Type: [REST/GraphQL/SPA+API]
- Tech Stack: [识别的技术栈]
- Discovered Endpoints: [端点数量]

## Test Matrix
| Category | Test Item | Priority | Status | Finding |

## Findings

### Finding N: [漏洞标题]

**Severity**: [Critical/High/Medium/Low/Info]
**Confidence**: [Confirmed/High/Medium/Low/Hypothesis]

**Multi-Dimension Analysis**:
| 维度 | 得分 | 分析 |
|------|------|------|
| D1 状态码 | X/15 | [分析] |
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
[响应体 - 脱敏]
```

**Root Cause**: [根本原因]
**Impact**: [影响分析]
**Remediation**: [修复建议]

## Coverage Gaps
## Overall Risk Summary
```

---

## 工具调用规则 (强制执行)

| 场景 | 工具 | 规则 |
|------|------|------|
| SPA 分析 | browser_tester | **必须使用**，除非明确不可用 |
| 端点发现 | deep_api_tester | **必须使用** |
| 漏洞验证 | api_fuzzer | **必须使用** |
| JS 分析 | V35JSAnalyzer | deep_api_tester 内部调用 |

### 调用示例

```python
# 正确的调用方式
from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
from core.deep_api_tester_v55 import DeepAPITesterV55
from core.api_fuzzer import APIfuzzer

# 1. browser_tester (如果目标是 SPA)
config = BrowserTestConfig(target_url=target, engine=BrowserEngine.PUPPETEER)
browser = BrowserAutomationTester(config)
# ... 执行分析 ...

# 2. deep_api_tester (必须调用)
api_tester = DeepAPITesterV55(target=target, headless=True)
api_tester.run_test()

# 3. api_fuzzer (必须调用)
import requests
session = requests.Session()
fuzzer = APIfuzzer(session=session)
fuzzer.set_target(api_base)
# ... 执行测试 ...
```

---

## 阶段 5: 云存储安全检测 (强制执行)

**触发**: 发现 OSS/云存储相关端点时执行

### 5.1 云存储识别

**识别依据**: 从 JS/API 响应中发现以下特征

```python
CLOUD_STORAGE_PATTERNS = {
    # URL 模式
    'aliyun': [
        '.oss-', '.aliyuncs.com', 'aliyun', 'oss-cn-',
        'x-oss-', 'oss.amazonaws.com'
    ],
    'tencent': [
        '.cos.', '.myqcloud.com', 'cos.', 'cos-cn-',
        'tencent', 'gzgrid'
    ],
    'huawei': [
        '.obs.', '.myhwclouds.com', 'hw OBS', 'obs-cn-'
    ],
    'aws': [
        '.s3.', 'amazonaws.com', 'aws-s3', 's3.amazonaws.com',
        's3-external-', 's3.dualstack.'
    ],
    'minio': [
        'minio', ':9000', ':9001', 'play.minio'
    ],
    'azure': [
        '.blob.core.', 'windows.net', 'azure'
    ],
    
    # 端点模式
    'endpoint_patterns': [
        '/oss/', '/bucket/', '/cos/', '/obs/',
        '/file/', '/upload/', '/storage/',
        '/minio/', '/blob/', '/s3/'
    ],
    
    # 响应特征
    'response_patterns': [
        '<ListBucketResult', '<ListAllMyBucketsResult',
        '<?xml version', 'ListBucketResponse',
        'X-OSS-', 'X-Amz-', 'x-oss-metadata'
    ]
}
```

### 5.2 云存储漏洞检测矩阵

| 漏洞类型 | 风险等级 | 检测方法 |
|---------|---------|---------|
| 公开可列目录 | Critical | GET / → 检查是否返回文件列表 |
| 匿名 PUT 上传 | Critical | PUT /test.txt → 检查是否可上传 |
| 匿名 POST 上传 | Critical | POST / → 检查表单上传 |
| 匿名 DELETE | Critical | DELETE /test.txt → 检查删除权限 |
| 敏感文件泄露 | Critical | 扫描 .env, .sql, .bak, .pem 等 |
| 目录遍历 | High | GET /../../etc/passwd |
| CORS 配置过宽 | High | 检查 Access-Control-Allow-Origin |
| 访问日志泄露 | Medium | GET /logs/, /accesslog/ |
| 版本控制泄露 | Medium | 检测 .versioned, /?versions |
| 敏感 HTTP 头 | Low | 检查 X-OSS-Meta-*, X-Amz-* |

### 5.3 云存储检测执行

```python
# -*- coding: utf-8 -*-
"""
云存储安全检测模块
支持: 阿里云 OSS, 腾讯云 COS, 华为云 OBS, AWS S3, MinIO
参考: OSS_scanner (bitboy-sys), BucketTool (libaibaia)
"""

import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

class CloudStorageTester:
    """云存储安全测试器"""
    
    # 云厂商 URL 模板
    CLOUD_TEMPLATES = {
        'aliyun': {
            'url': 'http://{bucket}.oss-{region}.aliyuncs.com',
            'https': 'https://{bucket}.oss-{region}.aliyuncs.com'
        },
        'tencent': {
            'url': 'http://{bucket}.cos.{region}.myqcloud.com',
            'https': 'https://{bucket}.cos.{region}.myqcloud.com'
        },
        'huawei': {
            'url': 'http://{bucket}.obs.{region}.myhwclouds.com',
            'https': 'https://{bucket}.obs.{region}.myhwclouds.com'
        },
        'aws': {
            'url': 'http://{bucket}.s3.{region}.amazonaws.com',
            'https': 'https://{bucket}.s3.{region}.amazonaws.com'
        }
    }
    
    # 敏感文件路径
    SENSITIVE_PATHS = [
        '.env', '.git/config', '.git/HEAD', 'id_rsa', 'id_rsa.pub',
        'access_key', 'secret_key', 'credentials', 'aws_key',
        '.sql', '.bak', '.backup', '.db', '.dump',
        '.pem', '.key', '.crt', '.p12', '.pfx',
        'wp-config.php', 'config.php', 'settings.py',
        'database.yml', 'credentials.json',
        'backup.sql', 'db_backup', 'data.sql'
    ]
    
    # 日志路径
    LOG_PATHS = [
        '/logs/', '/log/', '/accesslog/', '/access_log/',
        '/error_log/', '/debug.log', '/app.log'
    ]
    
    def __init__(self, session: requests.Session = None):
        self.session = session or requests.Session()
        self.findings: List[Dict] = []
    
    def detect_cloud_provider(self, url: str) -> Optional[str]:
        """检测云厂商类型"""
        for provider, patterns in self.CLOUD_STORAGE_PATTERNS.items():
            if provider == 'endpoint_patterns' or provider == 'response_patterns':
                continue
            for pattern in patterns:
                if pattern in url.lower():
                    return provider
        return None
    
    def test_public_listing(self, bucket_url: str) -> Tuple[bool, str]:
        """测试公开可列目录"""
        try:
            resp = self.session.get(bucket_url, timeout=10)
            
            # 检查是否返回 XML 文件列表
            if resp.status_code == 200:
                content = resp.text
                for pattern in ['<ListBucketResult', '<ListAllMyBucketsResult', 
                               'ListBucketResponse', '<?xml version']:
                    if pattern in content:
                        return True, f"公开可列目录 - 找到文件列表 ({len(content)} bytes)"
            
            # 检查是否返回 AccessDenied
            if 'AccessDenied' in resp.text or resp.status_code == 403:
                return False, "正确拒绝 (403)"
                
            return False, f"状态码: {resp.status_code}"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_put(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 PUT 上传"""
        test_content = f"OSS_TEST_{requests.utils.time.time()}"
        test_key = f"test_{requests.utils.time.time()}.txt"
        
        try:
            resp = self.session.put(
                f"{bucket_url}/{test_key}",
                data=test_content,
                timeout=10
            )
            
            if resp.status_code in [200, 201]:
                # 尝试删除测试文件
                self.session.delete(f"{bucket_url}/{test_key}")
                return True, f"可匿名上传 (状态码: {resp.status_code})"
            
            return False, f"PUT 上传失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_post(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 POST 表单上传"""
        test_content = f"OSS_TEST_{requests.utils.time.time()}"
        
        try:
            files = {'file': ('test.txt', test_content, 'text/plain')}
            resp = self.session.post(bucket_url, files=files, timeout=10)
            
            if resp.status_code in [200, 201]:
                return True, f"可匿名 POST 上传 (状态码: {resp.status_code})"
            
            return False, f"POST 上传失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_anonymous_delete(self, bucket_url: str) -> Tuple[bool, str]:
        """测试匿名 DELETE 权限"""
        # 先上传测试文件
        test_key = f"test_del_{requests.utils.time.time()}.txt"
        
        try:
            # 上传
            self.session.put(
                f"{bucket_url}/{test_key}",
                data="test",
                timeout=10
            )
            
            # 尝试删除
            resp = self.session.delete(f"{bucket_url}/{test_key}", timeout=10)
            
            if resp.status_code in [200, 204]:
                return True, f"可匿名删除 (状态码: {resp.status_code})"
            
            return False, f"DELETE 失败 (状态码: {resp.status_code})"
            
        except Exception as e:
            return False, f"请求失败: {e}"
    
    def test_sensitive_files(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试敏感文件泄露"""
        found = []
        
        for path in self.SENSITIVE_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 0:
                    # 检查内容是否是敏感文件
                    content = resp.text[:500].lower()
                    if any(kw in content for kw in ['password', 'secret', 'key', 'aws', 'api_key', 'token']):
                        found.append(f"{path} (可能包含敏感信息)")
                    elif len(resp.content) > 100:  # 有实质内容
                        found.append(f"{path} ({len(resp.content)} bytes)")
                        
            except:
                pass
        
        return len(found) > 0, found
    
    def test_directory_traversal(self, bucket_url: str) -> Tuple[bool, str]:
        """测试目录遍历"""
        traversal_paths = [
            '../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//etc/passwd'
        ]
        
        for path in traversal_paths:
            try:
                resp = self.session.get(f"{bucket_url}/{path}", timeout=10)
                
                if resp.status_code == 200:
                    if 'root:' in resp.text or 'Administrator' in resp.text:
                        return True, f"目录遍历成功 - 读取了系统文件"
                    elif len(resp.text) > 50:
                        return True, f"可能存在目录遍历 (路径: {path})"
                        
            except:
                pass
        
        return False, "未发现目录遍历"
    
    def test_cors_misconfiguration(self, bucket_url: str) -> Tuple[bool, str]:
        """测试 CORS 配置过宽"""
        try:
            resp = self.session.options(
                bucket_url,
                headers={
                    'Origin': 'http://evil.com',
                    'Access-Control-Request-Method': 'PUT'
                },
                timeout=10
            )
            
            allow_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            allow_methods = resp.headers.get('Access-Control-Allow-Methods', '')
            
            if allow_origin == '*' or 'http://evil.com' in allow_origin:
                if 'PUT' in allow_methods or 'POST' in allow_methods:
                    return True, f"CORS 过宽 - Allow-Origin: {allow_origin}, Methods: {allow_methods}"
                return True, f"CORS 允许任意 Origin: {allow_origin}"
            
            return False, f"CORS 配置正常"
            
        except Exception as e:
            return False, f"CORS 检测失败: {e}"
    
    def test_log_exposure(self, bucket_url: str) -> Tuple[bool, List[str]]:
        """测试访问日志泄露"""
        found = []
        
        for log_path in self.LOG_PATHS:
            try:
                resp = self.session.get(f"{bucket_url}/{log_path}", timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 100:
                    found.append(f"{log_path} ({len(resp.content)} bytes)")
                    
            except:
                pass
        
        return len(found) > 0, found
    
    def full_test(self, bucket_url: str) -> List[Dict]:
        """执行完整云存储安全测试"""
        print(f"[CloudStorage] 开始测试: {bucket_url}")
        
        provider = self.detect_cloud_provider(bucket_url)
        print(f"[CloudStorage] 识别厂商: {provider or '未知'}")
        
        results = []
        
        # 1. 公开可列目录
        print("[CloudStorage] 测试公开可列目录...")
        is_public, msg = self.test_public_listing(bucket_url)
        if is_public:
            results.append({
                'type': 'Public Listing',
                'severity': 'Critical',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 2. 匿名 PUT
        print("[CloudStorage] 测试匿名 PUT 上传...")
        can_put, msg = self.test_anonymous_put(bucket_url)
        if can_put:
            results.append({
                'type': 'Anonymous PUT Upload',
                'severity': 'Critical',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 3. 敏感文件
        print("[CloudStorage] 测试敏感文件泄露...")
        has_sensitive, files = self.test_sensitive_files(bucket_url)
        if has_sensitive:
            results.append({
                'type': 'Sensitive File Exposure',
                'severity': 'Critical',
                'evidence': ', '.join(files[:5]),
                'url': bucket_url
            })
        
        # 4. 目录遍历
        print("[CloudStorage] 测试目录遍历...")
        can_traverse, msg = self.test_directory_traversal(bucket_url)
        if can_traverse:
            results.append({
                'type': 'Directory Traversal',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 5. CORS
        print("[CloudStorage] 测试 CORS...")
        cors_vuln, msg = self.test_cors_misconfiguration(bucket_url)
        if cors_vuln:
            results.append({
                'type': 'CORS Misconfiguration',
                'severity': 'High',
                'evidence': msg,
                'url': bucket_url
            })
        
        # 6. 日志泄露
        print("[CloudStorage] 测试日志泄露...")
        has_logs, log_files = self.test_log_exposure(bucket_url)
        if has_logs:
            results.append({
                'type': 'Log Exposure',
                'severity': 'Medium',
                'evidence': ', '.join(log_files[:3]),
                'url': bucket_url
            })
        
        print(f"[CloudStorage] 测试完成，发现 {len(results)} 个问题")
        return results


def discover_and_test_cloud_storage(target: str) -> List[Dict]:
    """发现并测试云存储"""
    print(f"[CloudStorage] 开始云存储安全检测，目标: {target}")
    
    tester = CloudStorageTester()
    all_findings = []
    
    # 从 JS 中发现的存储桶 URL
    bucket_urls = [
        # 需要从实际测试中收集
    ]
    
    for url in bucket_urls:
        findings = tester.full_test(url)
        all_findings.extend(findings)
    
    return all_findings
```

### 5.4 云存储检测调用示例

```python
# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, '/workspace/API-Security-Testing-Optimized')

from core.cloud_storage_tester import CloudStorageTester

def test_cloud_storage(target):
    """测试云存储安全"""
    tester = CloudStorageTester()
    
    # 测试已发现的存储桶
    bucket_urls = [
        'http://target.oss-cn-region.aliyuncs.com',
        'http://target.cos.region.myqcloud.com',
        # 添加更多...
    ]
    
    all_results = []
    
    for bucket_url in bucket_urls:
        print(f"\n测试: {bucket_url}")
        results = tester.full_test(bucket_url)
        all_results.extend(results)
        
        for r in results:
            print(f"  [{r['severity']}] {r['type']}: {r['evidence']}")
    
    return all_results

# 执行
test_cloud_storage('http://58.215.18.57:91')
```

---

## 快速执行命令

```bash
cd /workspace/API-Security-Testing-Optimized

# 方式 1: 完整执行 (推荐)
python3 << 'EOF'
import sys
sys.path.insert(0, '.')

# 前置检查
print("="*60)
print("阶段 0: 前置检查")
print("="*60)

# 检查并安装依赖
import subprocess
import importlib

def check_and_install(package, import_name=None):
    name = import_name or package
    try:
        mod = importlib.import_module(name)
        print(f"[OK] {package}")
        return True
    except:
        print(f"[INSTALL] {package}...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', package], capture_output=True)
        return False

check_and_install('requests')
check_and_install('playwright')
check_and_install('pyppeteer')
check_and_install('pytest')

# 导入 core 模块
from core.browser_tester import BrowserAutomationTester, BrowserEngine, BrowserTestConfig
from core.deep_api_tester_v55 import DeepAPITesterV55
from core.api_fuzzer import APIfuzzer

print("\n" + "="*60)
print("阶段 1: 资产发现")
print("="*60)

target = 'http://58.215.18.57:91'

# 使用 deep_api_tester
api_tester = DeepAPITesterV55(target=target, headless=True)
endpoints = api_tester.run_test()

print("\n" + "="*60)
print("阶段 1.2: 检查云存储触发条件")
print("="*60)

# 云存储触发检测
from core.cloud_storage_tester import CloudStorageTester
cloud_tester = CloudStorageTester(session=session)

# 检测模式
CLOUD_PATH_PATTERNS = ['/minio/', '/file/', '/upload/', '/storage/', '/bucket/', '/oss/', '/cos/', '/s3/']
trigger_cloud = False

for ep in (endpoints or []):
    for pattern in CLOUD_PATH_PATTERNS:
        if pattern in str(ep).lower():
            print(f"[Cloud Trigger] 发现云存储端点: {ep}")
            trigger_cloud = True
            break
    if trigger_cloud:
        break

if trigger_cloud:
    print("[Cloud Trigger] 触发云存储安全检测...")
    print("\n" + "="*60)
    print("阶段 5: 云存储安全检测")
    print("="*60)
    
    # 测试当前域名的存储路径
    for pattern in CLOUD_PATH_PATTERNS:
        storage_url = target.rstrip('/') + pattern
        print(f"[CloudStorage] 测试: {storage_url}")
        try:
            results = cloud_tester.full_test(storage_url)
            if results:
                print(f"[CloudStorage] 发现 {len(results)} 个问题")
        except Exception as e:
            print(f"[CloudStorage] 测试失败: {e}")

print("\n" + "="*60)
print("阶段 2-3: 漏洞测试与验证")
print("="*60)

# 使用 api_fuzzer
import requests
session = requests.Session()
fuzzer = APIfuzzer(session=session)
fuzzer.set_target(target + '/icp-api')

# 云存储检测（如果阶段 1 未触发）
if not trigger_cloud:
    print("\n" + "="*60)
    print("阶段 5: 云存储安全检测")
    print("="*60)
    print("[CloudStorage] 尝试发现云存储...")
    # 从 JS 响应中发现存储 URL
    try:
        resp = session.get(target, timeout=10)
        found = cloud_tester.discover_from_text(resp.text)
        if found:
            for f in found[:5]:
                print(f"[CloudStorage] 发现: {f.get('url')}")
                results = cloud_tester.full_test(f.get('url'))
    except:
        pass

print("\n" + "="*60)
print("完成")
print("="*60)
EOF
```

---

## 参考文档

| 阶段 | 参考文档 | 说明 |
|------|---------|------|
| GraphQL 测试 | `references/graphql-guidance.md` | GraphQL 专项测试指导 |
| REST API 测试 | `references/rest-guidance.md` | REST API 测试指导 |
| 资产发现 | `references/asset-discovery.md` | 资产发现方法 |
| 测试矩阵 | `references/test-matrix.md` | 测试用例矩阵 |
| 验证标准 | `references/validation.md` | 漏洞验证标准 |
| 严重性校准 | `references/severity-model.md` | 严重性分级标准 |
| 报告模板 | `references/report-template.md` | 报告格式模板 |
| 云存储 | `core/cloud_storage_tester.py` | 云存储安全测试模块 |

