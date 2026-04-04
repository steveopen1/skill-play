---
description: API 安全测试 - 主入口
---

<command-instruction>
API Security Testing - API 安全测试插件

## 简介

全自动 API 安全测试插件，支持漏洞扫描、渗透测试、API检测。

## 可用命令

| 命令 | 说明 |
|------|------|
| `/api-security-testing-scan` | 完整扫描模式 |
| `/api-security-testing-test` | 快速测试特定端点 |

## 可用 Agent

| Agent | 说明 |
|-------|------|
| `@cyber-supervisor` | 赛博监工 - 永不停止的测试监督 |
| `@probing-miner` | 探测挖掘专家 - 针对性漏洞挖掘 |
| `@resource-specialist` | 资源探测专家 - 端点发现和采集 |

## 核心能力

1. **端点发现** - Playwright 动态采集 + JS 静态分析
2. **漏洞检测** - SQLi、XSS、IDOR、敏感数据、安全头部
3. **智能分析** - 自动判断技术栈，选择最佳测试策略
4. **压力升级** - 失败时自动切换测试方法 (L1-L4)

## 快速开始

### 1. 启动完整扫描

```
delegate_task @cyber-supervisor
```

### 2. 发现端点

```
delegate_task @resource-specialist
```

### 3. 挖掘漏洞

```
delegate_task @probing-miner
```

## 漏洞测试参考

详细的漏洞测试指南位于 `references/vulnerabilities/` 目录：

- 01-sqli-tests.md - SQL 注入测试
- 02-user-enum-tests.md - 用户枚举测试
- 03-jwt-tests.md - JWT 认证测试
- 04-idor-tests.md - IDOR 越权测试
- 05-sensitive-data-tests.md - 敏感数据泄露
- 06-biz-logic-tests.md - 业务逻辑漏洞
- 07-security-config-tests.md - 安全配置漏洞
- 08-brute-force-tests.md - 暴力破解测试
- 11-graphql-tests.md - GraphQL 安全测试
- 12-ssrf-tests.md - SSRF 安全测试

## 注意

**仅用于合法授权的安全测试，测试前确保有书面授权。**
</command-instruction>
