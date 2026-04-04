# API Security Testing - Claude Code 插件

全自动 API 安全测试插件，专为 Claude Code 设计。

## 安装方式

### 方式一：使用插件目录
```bash
claude --plugin-dir ./agent-plugins/CLAUDE-CODE/api-security-testing
```

### 方式二：复制到插件目录
```bash
cp -r agent-plugins/CLAUDE-CODE/api-security-testing ~/.claude/plugins/
```

## 使用命令

| 命令 | 说明 |
|------|------|
| `/api-security-testing:scan [URL]` | 完整扫描 |
| `/api-security-testing:test [URL]` | 快速测试 |
| `/api-security-testing:hook on/off` | 开启/关闭赛博监工 |
| `/api-security-testing:status` | 查看状态 |
| `/api-security-testing:off` | 关闭 |

### 示例

```
/api-security-testing:scan https://target.com
/api-security-testing scan https://target.com
```

## 目录结构

```
api-security-testing/
├── .claude-plugin/
│   └── plugin.json                  # 插件清单
├── commands/                        # 命令定义
│   ├── api-security-testing.md
│   ├── api-security-testing-scan.md
│   ├── api-security-testing-test.md
│   ├── api-security-testing-hook.md
│   └── api-security-testing-status.md
├── agents/
│   └── cyber-supervisor.md         # 赛博监工 Agent
├── hooks/
│   └── hooks.json                 # Hook 配置
├── skills/
│   └── api-security-testing/
│       └── SKILL.md              # Skill 定义
├── core/                          # Python 测试引擎
│   ├── deep_api_tester_v55.py
│   ├── collectors/
│   ├── analyzers/
│   └── testers/
├── references/                    # 参考文档
│   └── vulnerabilities/           # 漏洞测试 (12个)
├── examples/                      # 使用示例
├── templates/                    # 测试模板
├── resources/                    # Payload 资源
└── README.md
```

## 功能特性

- ✅ **Playwright JS 动态采集** - 无头浏览器执行 JavaScript
- ✅ **API 端点智能发现** - JS 解析 + 流量拦截
- ✅ **漏洞检测** - SQLi/XSS/IDOR/敏感数据/安全头部
- ✅ **赛博监工自动监督** - 自动监测进度、失败升级
- ✅ **Markdown 报告生成** - 自动生成测试报告
- ✅ **Python 测试引擎** - core/ 提供完整测试能力

## 赛博监工

**自动激活**：当执行扫描命令时赛博监工自动开启监督。

| 失败次数 | 等级 | 动作 |
|---------|------|------|
| 2次 | L1 | 切换方法 |
| 3次 | L2 | 深度分析 |
| 5次 | L3 | 7点检查清单 |
| 7次+ | L4 | 绝望模式 |

## 使用 Python 测试引擎

```bash
cd api-security-testing
python3 core/deep_api_tester_v55.py https://target.com output.md
```

## 漏洞测试覆盖

| 类别 | 说明 |
|------|------|
| SQL 注入 | 布尔盲注，时间盲注、报错注入 |
| XSS | 反射型、存储型、DOM 型 |
| IDOR | 水平越权、垂直越权 |
| JWT | Token 伪造、算法绕过 |
| 敏感数据 | 密码、密钥、个人信息 |
| 安全配置 | CORS、HSTS、头部 |

## 重要

- 仅用于合法授权的安全测试
- 测试前确保有书面授权

## License

MIT
