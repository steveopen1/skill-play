# Agent Plugins

开箱即用的 Claude Code 和 OpenCode 插件。

## 目录结构

```
agent-plugins/
├── CLAUDE-CODE/                     # Claude Code 插件
├── OPENCODE/                        # OpenCode 插件
└── opencode/                       # OpenCode 插件 (旧)
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

---

## OpenCode 插件

路径: `OPENCODE/api-security-testing/`

### 安装

```bash
# 复制到项目
cp -r agent-plugins/OPENCODE/api-security-testing <project>/.opencode/

# 或复制到全局
cp -r agent-plugins/OPENCODE/api-security-testing ~/.config/opencode/
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

- **Plugins 自动监测** - session.created, tool.execute.after
- **赛博监工** - 自动激活，无需手动开启
- **Skills 目录结构** - `.opencode/skills/*/SKILL.md`

---

## 赛博监工 (Cyber Supervisor)

自主监督机制，失败时自动压力升级：

| 失败次数 | 等级 | 动作 |
|---------|------|------|
| 2次 | L1 | 切换方法 |
| 3次 | L2 | 深度分析 |
| 5次 | L3 | 7点检查清单 |
| 7次+ | L4 | 绝望模式 |

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
