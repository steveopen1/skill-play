# API Security Testing Plugin

API 安全测试插件，为 OpenCode 提供自动化漏洞扫描和渗透测试能力。

## 安装

```bash
npm install opencode-api-security-testing
```

## 配置

在 `opencode.json` 中添加：

```json
{
  "plugin": ["opencode-api-security-testing"]
}
```

## 使用方法

### 使用 Agents

```
@cyber-supervisor 对 https://example.com 进行 API 安全测试
```

```
@probing-miner 测试 /api/login 端点的 SQL 注入
```

```
@resource-specialist 发现所有 API 端点
```

## Agents

### cyber-supervisor
**赛博监工** - 永不停止任何线索，自动循环执行，遇到失败自动委派 probing-miner 和 resource-specialist 进行探测。

### probing-miner
**探测挖掘专家** - 使用专业测试技术，引用漏洞测试指南进行针对性漏洞挖掘和验证。

### resource-specialist
**资源探测专家** - 专注于采集和发现 API 端点，使用动态和静态分析技术提取所有可能的攻击面。

## 漏洞测试参考

详细测试指南位于 `references/vulnerabilities/` 目录：

| 文件 | 漏洞类型 |
|------|---------|
| 01-sqli-tests.md | SQL 注入测试 |
| 02-user-enum-tests.md | 用户枚举测试 |
| 03-jwt-tests.md | JWT 认证测试 |
| 04-idor-tests.md | IDOR 越权测试 |
| 05-sensitive-data-tests.md | 敏感数据泄露 |
| 06-biz-logic-tests.md | 业务逻辑漏洞 |
| 07-security-config-tests.md | 安全配置漏洞 |
| 08-brute-force-tests.md | 暴力破解测试 |
| 09-vulnerability-chains.md | 漏洞关联联想 |
| 10-auth-tests.md | 认证漏洞测试 |
| 11-graphql-tests.md | GraphQL 安全测试 |
| 12-ssrf-tests.md | SSRF 安全测试 |

## 重要

**仅用于合法授权的安全测试，测试前确保有书面授权。**
