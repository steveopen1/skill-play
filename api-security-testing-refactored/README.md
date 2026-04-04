# API Security Testing - Refactored Version

符合 skill-creator 规范的 API 安全测试 Skill。

## 核心设计

| 理念 | 说明 |
|------|------|
| **Skill 是框架** | SKILL.md 定义决策流程，core/ 提供执行能力 |
| **语义分析优先** | 路径模式只是线索，需要分析接口语义 |
| **模块化能力池** | core/ 是能力池，根据目标特征动态组合 |
| **多维度判断** | 不依赖单一指标，综合评估漏洞风险 |

## 目录结构

```
api-security-testing-refactored/
├── SKILL.md                      # Skill 入口
├── v55_perfect_report.md        # 完美报告模板
├── core/                         # 核心能力模块
│   ├── deep_api_tester_v55.py  # API 深度测试
│   ├── browser_tester.py       # 浏览器测试
│   ├── orchestrator.py          # 智能编排器
│   └── ...
├── references/                  # 参考文档
├── examples/                     # 使用示例
└── templates/                   # 报告模板
```

## 触发词

当用户提到以下关键词时自动激活：
- 安全测试、安全审计、渗透测试
- 漏洞检测、安全评估
- api安全、接口安全
- 帮我检测漏洞、检查安全问题
- 安全报告、全流程测试

## 强制要求

1. **必须使用 Playwright** 进行 JS 动态采集
2. **必须拦截所有 XHR/Fetch 请求**
3. **必须模拟用户交互** 触发动态 API
4. **必须处理 HTTPS 证书问题**

## 执行流程

```
Phase 1: JS 动态采集 (禁止降级)
Phase 2: API 端点发现
Phase 3: 漏洞检测
Phase 4: 利用链构造
Phase 5: 自动报告生成
```

## 漏洞检测

| 类型 | 说明 |
|------|------|
| SQL 注入 | 布尔盲注、时间盲注、报错注入 |
| XSS | 反射型、存储型、DOM 型 |
| IDOR | 水平越权、垂直越权 |
| 敏感数据 | 密码、密钥、个人信息 |
| 安全配置 | CORS、HSTS、头部 |

## 使用方式

### 作为 Skill 使用

```
请对这个 API 进行全面的安全测试
帮我检测 OSS 存储桶安全
检查 GraphQL 有什么漏洞
生成一份完整的安全测试报告
```

### 作为 Python 模块

```python
import sys
sys.path.insert(0, '/workspace/api-security-testing-refactored')

from core.deep_api_tester_v55 import DeepAPITesterV55

tester = DeepAPITesterV55(target='http://target.com', headless=True)
tester.run_test()
```

## 重要

- 仅限授权测试使用
- 测试前确认拥有合法授权
