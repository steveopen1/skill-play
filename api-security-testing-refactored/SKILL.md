---
name: api-security-testing
description: 针对授权目标进行专业的 REST/GraphQL API 安全评估与漏洞检测。当用户提供URL并要求测试时自动触发：【触发词】"安全测试"、"渗透测试"、"漏洞检测"、"API安全扫描"、"帮我检测漏洞"、"全流程测试"、"完整测试"。【强制要求】(1)必须使用Playwright进行JS动态采集 (2)必须拦截所有XHR/Fetch请求 (3)必须模拟用户交互触发动态API (4)必须处理HTTPS证书问题。【重要】必须确认用户拥有该目标的合法授权！
---

# API 安全测试

## 执行流程

```
阶段1: 基础探测
  → HTTP/HTTPS探测、技术栈识别、SPA判断
  → 识别为SPA应用 → 进入阶段2
  → 非SPA应用 → 直接进入阶段3

阶段2: 【强制】JS动态采集 (SPA应用必须执行)
  → Playwright全流量采集
  → 拦截所有XHR/Fetch请求
  → 模拟用户交互触发
  → 提取API端点和敏感信息
  → 输出: API端点清单 + 敏感信息

阶段3: Fuzzing测试
  → 使用core/api_fuzzer.py进行批量端点探测
  → 使用references/fuzzing-patterns.md的字典
  → 多base_path验证
  → 输出: 完整API端点列表

阶段4: 漏洞验证
  → SQL注入测试 → 使用references/vulnerabilities/01-sqli-tests.md
  → 用户枚举测试 → 使用references/vulnerabilities/02-user-enum-tests.md
  → JWT测试 → 使用references/vulnerabilities/03-jwt-tests.md
  → IDOR测试 → 使用references/vulnerabilities/04-idor-tests.md
  → 敏感信息泄露 → references/vulnerabilities/05-sensitive-data-tests.md
  → 业务逻辑漏洞 → references/vulnerabilities/06-biz-logic-tests.md
  → CORS/CSRF配置 → references/vulnerabilities/07-security-config-tests.md
  → 暴力破解 → references/vulnerabilities/08-brute-force-tests.md
  → 使用core/testers/下的专用测试脚本
  → 输出: 漏洞清单 + 验证证据

阶段5: 利用链构造
  → 使用references/vulnerabilities/09-vulnerability-chains.md
  → 串联独立漏洞构建攻击路径
  → 输出: 完整利用链

阶段6: 报告输出
  → 使用references/report-template.md生成报告
  → 使用examples/security-report-example.md作为参考
```

## 【强制】前置条件

### 授权确认（必须）
- 用户是否拥有目标的合法授权
- 测试范围是否明确

### 依赖安装（必须成功）
```bash
pip install playwright && playwright install chromium && playwright install-deps chromium
```
**不允许降级**：如果Playwright安装失败，必须报告环境问题，不能使用其他方案替代。

## 核心检测思维

### 发现即测原则

发现接口后立即根据类型测试相关漏洞：

| API类型 | 发现后立即测试 |
|---------|--------------|
| 认证类 (login, auth) | SQL注入、暴力破解、用户枚举 |
| 查询类 (list, get) | IDOR、信息泄露、参数注入 |
| 操作类 (add, modify) | 越权、批量操作、业务逻辑 |
| 文件类 (upload) | 上传绕过、路径遍历 |
| 支付类 (pay, refund) | 金额篡改、退款欺诈 |

### 推理思维

**查询类接口**：需要认证吗？能查到别人的数据吗？响应有敏感字段吗？
**认证类接口**：伪造token能通过吗？用户不存在响应有区别吗？
**资金类接口**：订单归属校验了吗？金额能篡改吗？

### 三步验证流程

```
发现(Discover) → 分析(Analyze) → 验证(Verify)
- 可疑响应差异、异常状态码 → 多次请求确认 → 收集证据报告
```

### 验证检查清单（10维度）

```
□ 响应类型 - JSON还是HTML？
□ 状态码 - 是否合理？
□ 响应长度 - 是否过短？
□ WAF拦截 - 是否为安全设备？
□ 敏感信息 - 是否包含password/token？
□ 一致性 - 多次请求是否一致？
□ SQL注入 - 是否包含SQL错误？
□ IDOR - 是否返回他人数据？
□ 认证绕过 - 是否返回token？
□ 信息泄露 - 是否泄露非公开信息？
```

## 【强制】SPA应用采集流程

**【禁止降级】本阶段必须使用Playwright，不允许使用curl/requests替代**

```
1. Playwright全流量采集（必须）
   - 使用scripts/js_collector.py或core/collectors/browser_collector.py
   - 拦截所有XHR/Fetch/文档/静态资源
   - 使用ignore_https_errors=True处理证书问题

2. 模拟用户交互（必须）
   - 点击页面触发加载
   - 滚动触发懒加载
   - 填写登录表单
   - 导航到其他页面

3. HTTPS处理（必须）
   - 使用ignore_https_errors=True处理证书问题

4. JS深度分析
   - 使用core/collectors/js_parser.py提取API路径
   - 使用core/analyzers/api_parser.py解析端点
   - 使用core/analyzers/sensitive_finder.py查找敏感信息

5. 配置文件发现
   - /_app.config.js, VITE_GLOB_API_URL等
   - 使用core/collectors/url_collector.py

6. 多目标队列管理
   - 发现新域名/路径→加入测试队列
   - 使用core/collectors/api_path_finder.py
```

**【重要】base_path可能是多个！**
- 从JS中提取所有可能的base_path
- 分别用不同前缀验证哪个返回正确JSON

## 能力模块映射

### core/ 核心模块

| 模块 | 功能 | 使用场景 |
|------|------|----------|
| `collectors/browser_collector.py` | Playwright浏览器采集 | 阶段2 SPA应用采集 |
| `collectors/js_parser.py` | JS代码解析 | 阶段2 提取API路径 |
| `collectors/api_path_finder.py` | API路径发现 | 阶段2 发现新端点 |
| `analyzers/api_parser.py` | API端点解析 | 阶段3 分析端点格式 |
| `analyzers/response_analyzer.py` | 响应分析 | 阶段4 漏洞验证 |
| `analyzers/sensitive_finder.py` | 敏感信息查找 | 阶段4 敏感信息泄露 |
| `testers/sqli_tester.py` | SQL注入测试 | 阶段4 SQL注入漏洞 |
| `testers/auth_tester.py` | 认证测试 | 阶段4 认证绕过 |
| `testers/idor_tester.py` | IDOR测试 | 阶段4 越权漏洞 |
| `api_fuzzer.py` | API模糊测试 | 阶段3 Fuzzing探测 |
| `dynamic_api_analyzer.py` | 动态API分析 | 全流程 动态分析 |
| `cloud_storage_tester.py` | 云存储测试 | 阶段4 OSS凭证泄露 |

### references/ 参考文档

| 文档 | 内容 | 使用时机 |
|------|------|----------|
| `workflows.md` | 完整扫描流程 | 整体流程参考 |
| `vulnerabilities/01-sqli-tests.md` | SQL注入测试方法 | 测试SQL注入时 |
| `vulnerabilities/02-user-enum-tests.md` | 用户枚举测试方法 | 测试用户枚举时 |
| `vulnerabilities/03-jwt-tests.md` | JWT认证测试方法 | 测试JWT时 |
| `vulnerabilities/04-idor-tests.md` | IDOR越权测试 | 测试越权时 |
| `vulnerabilities/05-sensitive-data-tests.md` | 敏感信息泄露测试 | 测试信息泄露时 |
| `vulnerabilities/06-biz-logic-tests.md` | 业务逻辑漏洞测试 | 测试业务逻辑时 |
| `vulnerabilities/07-security-config-tests.md` | 安全配置测试(CORS/CSRF) | 测试配置漏洞时 |
| `vulnerabilities/08-brute-force-tests.md` | 暴力破解测试 | 测试认证爆破时 |
| `vulnerabilities/09-vulnerability-chains.md` | 漏洞关联联想 | 阶段5 利用链构造 |
| `vulnerabilities/10-auth-tests.md` | 认证测试扩展 | 测试认证时 |
| `vulnerabilities/11-graphql-tests.md` | GraphQL测试 | 测试GraphQL API时 |
| `vulnerabilities/12-ssrf-tests.md` | SSRF测试 | 测试SSRF时 |
| `fuzzing-patterns.md` | Fuzzing字典 | 阶段3 端点探测 |
| `report-template.md` | 报告模板 | 阶段6 生成报告 |
| `pua-agent.md` | PUA Agent说明 | 自主深入测试 |

### scripts/ 自动化脚本

| 脚本 | 功能 |
|------|------|
| `js_collector.py` | 强制Playwright采集，失败则报错 |
| `auth_bypass_tester.py` | 认证绕过测试矩阵 |

## Fuzzing测试策略

```bash
# 使用api_fuzzer.py进行批量探测
python core/api_fuzzer.py --target https://target.com

# 或使用fuzzing-patterns.md中的字典手动探测
前缀字典: /api, /admin, /gateway, /auth, /oauth, /v1, /v2, /rest
端点字典: login, logout, user, list, add, delete, getInfo, detail
组合测试: prefix + endpoint，逐个探测
```

## 敏感信息识别

**必须识别**：password、token、secretKey、apiKey、balance、userId、phone、email

**响应类型判断**：
| 类型 | 特征 | 含义 |
|------|------|------|
| JSON对象 | `{"code":200}` | 真实API |
| JSON数组 | `[{"id":1}]` | 真实数据列表 |
| HTML | `<!DOCTYPE html>` | SPA/WAF/错误页 |

## 特殊情况处理

**WAF识别**：所有请求返回相似HTML页面 → 记录WAF防护，不是漏洞
**SPA路由**：/api/* 返回HTML → 通过JS分析获取真实API
**WAP环境**：需要Cookie/Referer → 使用requests.Session()维持会话

## 漏洞链构造

```
用户枚举 → 获取userId → 查订单 → 退款
token泄露 → 访问敏感接口 → 越权操作
详见 references/vulnerabilities/09-vulnerability-chains.md
```

## 执行检查清单

```
□ 阶段1: 基础探测完成
□ 阶段2: Playwright采集完成（如为SPA）
□ 阶段3: Fuzzing探测完成
□ 阶段4: 所有漏洞类型验证完成
□ 阶段5: 利用链构造完成
□ 阶段6: 报告生成完成
```

## 参考资源

详细测试方法和脚本请查阅：
- [references/workflows.md](references/workflows.md) - 完整扫描流程
- [references/vulnerabilities/](references/vulnerabilities/) - 漏洞测试详情（12个文档）
- [references/fuzzing-patterns.md](references/fuzzing-patterns.md) - Fuzzing字典
- [references/report-template.md](references/report-template.md) - 报告模板
- [references/pua-agent.md](references/pua-agent.md) - PUA Agent说明
- [scripts/](scripts/) - 自动化脚本
- [core/](core/) - 核心测试模块
