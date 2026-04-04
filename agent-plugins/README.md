# Agent Plugins

开箱即用的 Claude Code 和 OpenCode 插件。

## 目录结构

```
agent-plugins/
├── CLAUDE-CODE/                     # Claude Code 插件
└── OPENCODE/                        # OpenCode 插件
```

## Claude Code 插件

路径: `CLAUDE-CODE/api-security-testing/`

### 安装

```bash
# 方式一: 使用插件目录
claude --plugin-dir ./agent-plugins/CLAUDE-CODE/api-security-testing

# 方式二: 复制到插件目录
cp -r agent-plugins/CLAUDE-CODE/api-security-testing ~/.claude/plugins/
```

### 使用方式

```
/api-security-testing:scan https://target.com
/api-security-testing:hook on
```

### 特点

- **Hooks 自动监测** - PostToolUse, PostToolUseFailure, Stop
- **赛博监工 Agent** - 自主压力升级 (L1-L4)
- **6 阶段测试流程** - JS采集 → API发现 → 漏洞检测 → 利用链 → 报告

---

## OpenCode 插件

路径: `OPENCODE/api-security-testing/`

### 安装

```bash
# 复制到项目 .opencode 目录
cp -r OPENCODE/api-security-testing <project>/.opencode/
```

### 使用方式

```
@cyber-supervisor 对 https://target.com 进行完整 API 安全测试
```

或者使用 Skill：

```
skills_api_security_testing https://target.com
```

### 特点

- **Plugin Hook 机制** - session.created, tool.execute.after, session.idle
- **Task.launch 委派** - 真正的 agent spawn
- **强制 Playwright** - 无头浏览器动态内容采集
- **Skills 目录结构** - `.opencode/skills/*/SKILL.md`

---

## 架构模式

### Agent 角色

| Agent | 职责 |
|-------|------|
| cyber-supervisor | 主协调器，Task.launch 委派子 agent |
| probing-miner | 深度漏洞挖掘，攻击链构造 |
| resource-specialist | 资源采集，Playwright 强制使用 |

### Task.launch 委派 (OpenCode)

```javascript
await Task.launch("resource-specialist", {
  description: "采集目标 JS 文件",
  prompt: `目标: ${targetUrl}\n使用 Playwright 采集动态内容。`
})
```

---

## 漏洞测试覆盖

| 类别 | 漏洞 |
|------|------|
| Injection | SQL注入、XSS、SSRF |
| Auth | JWT、认证绕过、暴力破解 |
| Access | IDOR、未授权访问 |
| Data | 敏感数据暴露 |
| Config | 安全头部、CORS |

---

## License

MIT
