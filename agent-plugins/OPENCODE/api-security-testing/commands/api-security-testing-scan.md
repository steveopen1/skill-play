---
description: API 安全测试 - 启动安全扫描任务
---

<command-instruction>
启动 API 安全测试扫描任务。

## 使用方法

```
/api-security-testing-scan <目标URL>
```

## 示例

```
/api-security-testing-scan https://example.com/api
```

## 工作流程

1. **Phase 1**: 端点发现 - 采集所有 API 端点
2. **Phase 2**: 漏洞挖掘 - 针对每个端点测试漏洞
3. **Phase 3**: 报告生成 - 输出安全报告

## 可用 Agent

| Agent | 说明 |
|-------|------|
| @cyber-supervisor | 赛博监工 - 监督整个测试流程 |
| @probing-miner | 探测挖掘专家 - 漏洞挖掘 |
| @resource-specialist | 资源探测专家 - 端点发现 |

## 漏洞类型

- SQL 注入 (SQLi)
- 用户枚举
- JWT 安全
- IDOR 越权
- 敏感数据泄露
- 业务逻辑漏洞
- 安全配置错误
- 暴力破解
- GraphQL 安全
- SSRF

## 报告格式

生成 Markdown 格式的安全报告，包含：
- 测试目标信息
- 发现的端点列表
- 漏洞详情（严重程度、位置、验证步骤）
- 利用链说明
- 修复建议

## 注意

仅用于合法授权的安全测试，测试前确保有书面授权。
</command-instruction>
