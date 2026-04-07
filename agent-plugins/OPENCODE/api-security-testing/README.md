# API Security Testing Plugin

OpenCode 插件，提供完整的 API 安全测试能力。

## 安装

### 方式一：npm 安装（推荐）

```bash
npm install opencode-api-security-testing
```

在 `opencode.json` 中添加插件配置：

```json
{
  "plugin": ["opencode-api-security-testing"]
}
```

### 方式二：本地安装

如果从源码安装：

```bash
# 克隆仓库
git clone https://github.com/steveopen1/skill-play

# 进入插件目录
cd skill-play/agent-plugins/OPENCODE/api-security-testing

# 使用 npm link 链接到全局
npm link

# 在项目中使用
npm link opencode-api-security-testing
```

### 方式三：直接复制到项目

将插件目录复制到项目的 `.opencode` 目录：

```bash
cp -r agent-plugins/OPENCODE/api-security-testing <your-project>/.opencode/skills/api-security-testing
```

确保插件目录放在 `.opencode/skills/` 下，OpenCode 会自动发现。
```

## Agents (4个)

| Agent | 模式 | 描述 |
|-------|------|------|
| `@api-cyber-supervisor` | Primary | 编排者，协调完整扫描流程，永不停止 |
| `@api-probing-miner` | Subagent | 漏洞挖掘专家 |
| `@api-resource-specialist` | Subagent | 资源探测专家 |
| `@api-vuln-verifier` | Subagent | 漏洞验证专家 |

## Tools (10个)

| Tool | 功能 | 调用方式 |
|------|------|---------|
| `api_security_scan` | 完整 API 安全扫描 | `api_security_scan target="url"` |
| `api_fuzz_test` | API 模糊测试 | `api_fuzz_test endpoint="url"` |
| `browser_collect` | 浏览器采集动态内容 | `browser_collect url="url"` |
| `js_parse` | JavaScript 文件解析 | `js_parse file_path="/path/to/file.js"` |
| `graphql_test` | GraphQL 安全测试 | `graphql_test endpoint="url"` |
| `cloud_storage_test` | 云存储安全测试 | `cloud_storage_test bucket_url="url"` |
| `vuln_verify` | 漏洞验证 | `vuln_verify vuln_type="sqli" endpoint="url"` |
| `sqli_test` | SQL 注入测试 | `sqli_test endpoint="url" param="id"` |
| `idor_test` | IDOR 越权测试 | `idor_test endpoint="url" resource_id="1"` |
| `auth_test` | 认证安全测试 | `auth_test endpoint="url"` |

## 使用方式

### 方式一：使用 Agent（推荐）

```
@api-cyber-supervisor 对 https://example.com 进行全面安全测试
```

### 方式二：使用 Skill

```
skill({ name: "api-security-testing" })
```

### 方式三：直接使用 Tool

```
api_security_scan target="https://example.com" scan_type="full"
```

## 依赖

Python 依赖会自动安装。也可手动安装：
```bash
pip install -r skills/api-security-testing/requirements.txt
```

## 重要

**仅用于合法授权的安全测试，测试前确保有书面授权。**
