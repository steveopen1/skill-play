# Agent Plugins

多平台 AI Coding Agent 插件集合。

## 目录结构

```
agent-plugins/
├── CLAUDE-CODE/
│   └── api-security-testing/       # API 安全测试插件
├── OPENCODE/
│   └── (future plugins)
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

(开发中...)

## License

MIT