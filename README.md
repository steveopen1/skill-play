# Agent Plugins

多平台 AI Coding Agent 插件集合。

## 目录结构

```
agent-plugins/
├── CLAUDE-CODE/
│   └── api-security-testing/       # Claude Code API 安全测试插件
├── OPENCODE/
│   └── api-security-testing/        # OpenCode API 安全测试插件
└── README.md
```

## 插件列表

### Claude Code 插件

#### api-security-testing

全自动 API 安全测试插件 - 内置赛博监工持续监督循环执行。

```bash
# 安装
git clone https://github.com/steveopen1/skill-play.git
cd skill-play/agent-plugins

# 使用插件目录
claude --plugin-dir ./claude-code/api-security-testing

# 或复制到插件目录
cp -r claude-code/api-security-testing ~/.claude/plugins/
```

**使用方式:**
```
/api-security-testing scan https://target.com   # 完整扫描
/api-security-testing:hook on                   # 开启赛博监工
/api-security-testing:status                    # 查看状态
/api-security-testing:off                     # 关闭
```

**功能:**
- Playwright 强制 JS 动态采集
- 6 阶段完整测试流程
- 赛博监工持续监督
- 10 维度漏洞验证
- 利用链构造

### OpenCode 插件

#### api-security-testing

全自动 API 安全测试插件，专为 OpenCode 设计。

```bash
# 复制到项目 .opencode 目录
cp -r agent-plugins/OPENCODE/api-security-testing <your-project>/.opencode/

# 或复制到全局配置
cp -r agent-plugins/OPENCODE/api-security-testing ~/.config/opencode/
```

**使用方式:**
```
/api-security-testing                  # 主命令 - 显示帮助
/api-security-testing-scan            # 完整扫描
/api-security-testing-test            # 快速测试
/api-security-testing-hook            # 赛博监工控制
/api-security-testing-status           # 查看状态
```

**功能:**
- SKILL.md 基于 OpenCode Agent Skills 规范
- `.opencode/commands/` 定义自定义命令
- `.opencode/plugins/cyber-supervisor.js` 实现自动监督
- 事件钩子: session.created, tool.execute.after, session.idle
- 赛博监工自动激活监测

**安装后:**
```bash
opencode
# 然后输入命令
/api-security-testing-scan https://target.com
```

## License

MIT