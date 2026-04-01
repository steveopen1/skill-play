---
name: api-security-testing
description: 针对授权目标进行结构化的 REST/GraphQL API 安全评估。当用户提到安全测试、漏洞检测、渗透测试或需要生成安全报告时自动触发。
trigger:
  # 触发短语
  phrases:
    - "安全测试"
    - "安全审计"
    - "渗透测试"
    - "漏洞检测"
    - "安全评估"
    - "api 安全"
    - "接口安全"
    - "rest api 安全"
    - "graphql 安全"
    - "swagger 安全"
    - "openapi 安全"
    - "帮我检测漏洞"
    - "检查安全问题"
    - "api 漏洞"
    - "安全报告"
    - "安全发现"
  # 触发模式（正则）
  patterns:
    - "(?:帮我)?(?:进行?|做)(?:api|接口|rest|graphql|安全|渗透)?(?:测试|审计|检测|扫描|评估)"
    - "(?:帮我)?(?:检查?|发现?|识别?)(?:api|接口|rest|graphql|安全)?(?:漏洞|风险|问题)"
    - "(?:生成|输出)(?:api|安全)?报告"
    - "(?:rest|graphql|api)(?:端点|接口)(?:测试|安全)"
    - "(?:openapi|swagger)(?:规范|文件)(?:分析|审计|检测)"
  # 自动触发
  auto_trigger: true
---

# API 安全测试

针对授权目标进行结构化的 REST/GraphQL API 安全评估。

## 触发条件

当用户提到以下内容时自动触发：
- 安全相关关键词（安全测试、漏洞检测等）
- API 相关关键词（api、rest、graphql、swagger、openapi）
- 报告生成请求

## 工作流程

### 1. 确认输入和评估模式

**触发后自动执行**：
```markdown
识别用户提供的内容：
- [ ] 目标 URL 或 base URL
- [ ] OpenAPI / Swagger 规范
- [ ] GraphQL schema
- [ ] 认证方式
- [ ] 测试账号
```

**评估模式判断**：
- 文档驱动审查：只有规范可用
- 被动审查：存在目标但认证受限
- 主动评估：授权明确

参考：`references/intake.md`

### 2. 自动构建资产摘要

**自动提取**：
- [ ] 解析 URL 获取 API 端点
- [ ] 分析 Swagger/OpenAPI 发现隐藏端点
- [ ] 识别认证方式（Bearer/JWT/Session）
- [ ] 识别信任边界

```markdown
## 资产摘要
- Base URLs:
- API 类型:
- 认证方案:
- 高风险端点:
```

参考：`references/asset-discovery.md`

### 3. 自动构建测试矩阵

**自动生成测试用例**：
```markdown
| 测试项 | 优先级 | 测试方法 |
|-------|---------|---------|
| SQL注入 | Critical | 参数化查询验证 |
| 认证绕过 | Critical | Token/JWT 分析 |
```

参考：`references/test-matrix.md`

### 4. 漏洞验证和分类

**自动判断严重性**：
```markdown
| 级别 | 标准 |
|------|------|
| Critical | 未授权访问 |
| High | 权限绕过 |
| Medium | 信息泄露 |
| Low | 配置问题 |
```

参考：`references/validation.md`

### 5. 生成结构化报告

**自动填充模板**：
```markdown
## 发现
### Finding 1: [标题]
**严重性**: Critical
**置信度**: High
**影响资产**: /api/users/{id}
```

参考：`references/report-template.md`

### 6. 测试循环迭代

**当发现新的攻击面或需要深入验证时，循环执行以下步骤**：

```
循环条件：
- 发现新的端点或参数 → 返回步骤 2
- 发现新的认证机制 → 返回步骤 3
- 需要验证假设 → 返回步骤 4
- 发现新的风险类型 → 更新测试矩阵

循环终止条件：
- 所有发现已验证
- 测试矩阵已完整覆盖
- 用户确认完成评估
```

**循环流程**：
```
[步骤 2: 资产摘要] 
       ↓
[步骤 3: 测试矩阵] → 发现新资产 → 返回步骤 2
       ↓
[步骤 4: 漏洞验证] → 需要深入验证 → 返回步骤 4
       ↓
[步骤 5: 生成报告] → 发现新风险 → 更新矩阵 → 返回步骤 3
       ↓
    [循环结束]
```

## 严重性校准

**完整标准参考**：`references/severity-model.md`

### 严重性级别

| 级别 | 触发条件 | 示例 |
|------|----------|------|
| Critical | 直接导致未授权访问或数据泄露 | 认证绕过、SQL注入导致数据库泄露 |
| High | 可导致权限提升或用户数据访问 | IDOR、垂直越权、API密钥泄露 |
| Medium | 可导致有限影响或信息泄露 | 敏感信息暴露、账户枚举 |
| Low | 影响有限的信息披露或配置问题 | 调试头暴露、版本信息泄露 |
| Informational | 非安全问题，最佳实践建议 | 文档改进建议 |

### 置信度级别

| 级别 | 标准 | 要求证据 |
|------|------|----------|
| Confirmed | 完全验证，有 PoC | 完整请求/响应 |
| High | 强指标 | 请求+响应+影响分析 |
| Medium | 中等指标 | 观察到的行为 |
| Low | 弱指标 | 单一响应 |
| Hypothesis | 理论推断 | 需要进一步调查 |

### 校准原则

1. **保守校准**：证据不确定时，倾向较低严重性
2. **基于影响**：考虑真实世界影响
3. **可利用性**：考虑利用难度和前提条件
4. **业务上下文**：考虑受影响资产的价值

## 协议处理

### REST API

**自动检测**：
- 路径参数 `/users/{id}`
- 查询参数 `?page=1&limit=10`
- Header 认证 `Authorization: Bearer xxx`

参考：`references/rest-guidance.md`

### GraphQL

**自动检测**：
- Query/Mutation 分析
- 字段级权限
- 嵌套遍历风险

参考：`references/graphql-guidance.md`

## 输出格式

**完整模板参考**：`references/report-template.md`

### 必须包含的章节

```markdown
## Scope
- Target: [目标 URL]
- Assessment Mode: [文档驱动/被动/主动]
- Authorization: [授权范围]

## Asset Summary
- Base URLs:
- API Type: [REST/GraphQL/混合]
- Auth Schemes: [认证方式]
- Discovered Endpoints: [端点列表]
- Sensitive Objects: [敏感对象]
- Trust Boundaries: [信任边界]

## Test Matrix
| Category | Test Item | Priority | Status |

## Findings
### Finding N: [标题]
**Severity**: [Critical/High/Medium/Low/Informational]
**Confidence**: [Confirmed/High/Medium/Low/Hypothesis]
**Affected Asset**: [endpoint]
**Description**: [问题描述]
**Evidence**: [请求/响应样本]
**Reproduction**: [复现步骤]
**Impact**: [影响评估]
**Remediation**: [修复建议]

## Coverage Gaps
| Gap | Impact | Recommendation |

## Overall Risk Summary
| Risk Level | Count | Findings |
|------------|-------|----------|
```

### 报告质量要求

- **Evidence**：必须包含请求/响应样本
- **Reproduction**：清晰的复现步骤
- **Remediation**：具体可操作的修复建议
- **Coverage Gaps**：明确说明未覆盖区域及原因
