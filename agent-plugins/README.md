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

### 命令

| 命令 | 说明 |
|------|------|
| `/api-security-testing:scan [URL]` | 完整扫描 |
| `/api-security-testing:hook on/off` | 开启/关闭赛博监工 |
| `/api-security-testing:status` | 查看状态 |
| `/api-security-testing:off` | 关闭 |

### 特点

- **Hooks 自动监测** - PostToolUse, PostToolUseFailure, Stop
- **赛博监工 Agent** - 自主压力升级 (L1-L4)
- **6 阶段测试流程** - JS采集 → API发现 → 漏洞检测 → 利用链 → 报告
- **参考 oh-my-openagent** 的 Sisyphus orchestration 模式

---

## OpenCode 插件

路径: `OPENCODE/api-security-testing/`

### 安装

```bash
# 复制到项目 .opencode 目录
cp -r OPENCODE/api-security-testing <project>/.opencode/
```

### 命令

| 命令 | 说明 |
|------|------|
| `/api-security-testing` | 主命令 - 显示帮助 |
| `/api-security-testing-scan` | 完整扫描 |
| `/api-security-testing-test` | 快速测试 |
| `/api-security-testing-hook` | 赛博监工控制 |
| `/api-security-testing-status` | 查看状态 |

### 特点

- **Plugin Hook 机制** - session.created, tool.execute.after, session.idle
- **Task.launch 委派** - 真正的 agent spawn，不是简单的 @提及
- **参考 oh-my-openagent** 的 Hephaestus 深度工作模式
- **强制 Playwright** - 无头浏览器动态内容采集
- **Skills 目录结构** - `.opencode/skills/*/SKILL.md`

---

## 架构模式

### Agent 角色

| Agent | 模式参考 | 职责 |
|-------|---------|------|
| cyber-supervisor | oh-my-openagent/Sisyphus | 主协调器，Task.launch 委派子 agent |
| probing-miner | oh-my-openagent/Hephaestus | 深度漏洞挖掘，攻击链构造 |
| resource-specialist | oh-my-openagent/Hephaestus | 资源采集，Playwright 强制使用 |

### Task.launch 委派

cyber-supervisor 使用 Task.launch 真正 spawn 子 agent：

```javascript
// 委派资源采集
await Task.launch("resource-specialist", {
  description: "采集目标 JS 文件",
  prompt: `目标: ${targetUrl}\n使用 Playwright 无头浏览器采集动态内容。`
})

// 委派漏洞挖掘
await Task.launch("probing-miner", {
  description: "挖掘 SQL 注入",
  prompt: `端点: ${endpoint}\n参考漏洞指南进行针对性测试。`
})
```

---

## 赛博监工 (Cyber Supervisor)

自主监督机制，失败时自动压力升级：

| 失败次数 | 等级 | 动作 |
|---------|------|------|
| 2次 | L1 | 切换方法 |
| 3次 | L2 | Task.launch 委派 resource-specialist 重新采集 |
| 5次 | L3 | Task.launch 委派 probing-miner 针对性挖掘 |
| 7次+ | L4 | 组合委派两个 agent |

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
