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

## 严重性校准

| 级别 | 触发条件 |
|------|----------|
| Critical | 直接导致未授权访问 |
| High | 可导致权限绕过 |
| Medium | 信息泄露风险 |
| Low | 配置问题 |

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

**始终使用标准化报告格式**：
- 简洁的资产摘要
- 优先化测试矩阵
- 结构化发现列表
- 清晰的修复建议
