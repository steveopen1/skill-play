# API Security Testing Plugin

OpenCode 插件，提供完整的 API 安全测试能力。

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

## Agents (5个)

| Agent | 角色 | 说明 |
|-------|------|------|
| `@api-cyber-supervisor` | 编排者 | 协调完整扫描流程，永不停止 |
| `@api-probing-miner` | 漏洞挖掘 | 专注发现和验证 API 漏洞 |
| `@api-resource-specialist` | 资源探测 | 专注采集和发现 API 端点 |
| `@api-orchestrator` | 测试编排 | 协调完整测试流程 |
| `@api-vuln-verifier` | 漏洞验证 | 验证和确认安全漏洞 |

## Tools (9个)

| Tool | 功能 |
|------|------|
| `api_security_scan` | 完整 API 安全扫描 |
| `api_fuzz_test` | API 模糊测试 |
| `vuln_verify` | 漏洞验证 |
| `browser_collect` | 浏览器采集动态内容 |
| `js_parse` | JavaScript 文件解析 |
| `cloud_storage_test` | 云存储安全测试 |
| `graphql_test` | GraphQL 安全测试 |
| `idor_test` | IDOR 越权测试 |
| `sqli_test` | SQL 注入测试 |

## 使用方式

### 方式一：使用 Agent

```
@api-cyber-supervisor 对 https://example.com 进行全面安全测试
```

### 方式二：直接使用 Tool

```
api_security_scan target="https://example.com" scan_type="full"
```

## 依赖

Python 依赖会自动安装（如果需要手动安装）：
```bash
pip install -r skills/api-security-testing/requirements.txt
```

## 重要

**仅用于合法授权的安全测试，测试前确保有书面授权。**
