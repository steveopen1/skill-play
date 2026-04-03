---
name: api-security-testing
description: 针对授权目标进行专业的 REST/GraphQL API 安全评估与漏洞检测。当用户提供URL并要求测试时自动触发：【触发词】"安全测试"、"渗透测试"、"漏洞检测"、"API安全扫描"、"帮我检测漏洞"、"全流程测试"、"完整测试"。【强制要求】(1)必须使用Playwright进行JS动态采集 (2)必须拦截所有XHR/Fetch请求 (3)必须模拟用户交互触发动态API (4)必须处理HTTPS证书问题。【重要】必须确认用户拥有该目标的合法授权！
---

# API 安全测试

## 执行流程

```
1. 基础探测 → HTTP/HTTPS探测、技术栈识别、SPA判断
2. 【强制】JS深度分析 → Playwright全流量采集(必须)、XHR/Fetch拦截、用户交互触发
3. Fuzzing测试 → 前缀+端点组合测试、base_path多维度验证
4. 漏洞验证 → SQL注入、越权、认证绕过、用户枚举、CORS等
5. 利用链分析 → 串联独立漏洞构建攻击路径
6. 报告输出 → 结构化安全评估报告
```

## 【强制】前置条件

### 授权确认（必须）
- 用户是否拥有目标的合法授权
- 测试范围是否明确

### 依赖安装（必须成功）
```
playwright → pip install playwright && playwright install chromium && playwright install-deps chromium
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
1. Playwright全流量采集（必须）- 拦截所有XHR/Fetch/文档/静态资源
2. 模拟用户交互（必须）- 点击、滚动、表单填写、导航
3. HTTPS处理（必须）- 使用ignore_https_errors=True处理证书问题
4. JS深度分析 - 从捕获的流量和JS文件中提取API路径
5. 配置文件发现 - /_app.config.js, VITE_GLOB_API_URL等
6. 多目标队列管理 - 发现新域名/路径→加入测试队列
```

**【重要】base_path可能是多个！**
- 从JS中提取所有可能的base_path
- 分别用不同前缀验证哪个返回正确JSON

## Fuzzing测试策略

```
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
| JSON数组 | `[{"id":1}]` | 数据列表 |
| HTML | `<!DOCTYPE html>` | SPA/WAF/错误页 |

## 特殊情况处理

**WAF识别**：所有请求返回相似HTML页面 → 记录WAF防护，不是漏洞
**SPA路由**：/api/* 返回HTML → 通过JS分析获取真实API
**WAP环境**：需要Cookie/Referer → 使用requests.Session()维持会话

## 漏洞链构造

```
用户枚举 → 获取userId → 查订单 → 退款
token泄露 → 访问敏感接口 → 越权操作
```

## 参考资源

详细测试方法和脚本请查阅：
- [references/workflows.md](references/workflows.md) - 完整扫描流程
- [references/vulnerabilities/](references/vulnerabilities/) - 漏洞测试详情
- [references/fuzzing-patterns.md](references/fuzzing-patterns.md) - Fuzzing字典
- [references/report-template.md](references/report-template.md) - 报告模板
- [scripts/](scripts/) - 自动化脚本
