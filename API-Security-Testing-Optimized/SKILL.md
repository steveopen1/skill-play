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
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|安全)?(?:测试|检测|扫描)"
    - "(?:帮我)?(?:检查?|发现?)(?:api|安全)?(?:漏洞|问题)"
    - "(?:生成|输出)(?:安全)?报告"
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
api_tester.run_test()

print("\n" + "="*60)
print("阶段 2-3: 漏洞测试与验证")
print("="*60)

# 使用 api_fuzzer
import requests
session = requests.Session()
fuzzer = APIfuzzer(session=session)
fuzzer.set_target(target + '/icp-api')

print("\n" + "="*60)
print("完成")
print("="*60)
EOF
```
