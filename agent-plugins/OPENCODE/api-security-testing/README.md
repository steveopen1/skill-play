# API Security Testing - OpenCode 插件

全自动 API 安全测试插件，专为 OpenCode 设计。

## 安装方式

### 方式一：复制到项目
```bash
cp -r api-security-testing <your-project>/.opencode/
```

### 方式二：复制到全局配置
```bash
cp -r api-security-testing ~/.config/opencode/
```

### 方式三：克隆仓库
```bash
git clone https://github.com/steveopen1/skill-play.git
cd skill-play/agent-plugins/OPENCODE
cp -r api-security-testing ~/.config/opencode/
```

## 使用方法

### 激活扫描
```
/api-security-testing scan https://target.com
```

### 赛博监工

**自动激活**：执行扫描时赛博监工自动开启监督，无需手动激活。

手动控制：
```
/cyber-supervisor on    # 开启监督
/cyber-supervisor off   # 关闭监督
/cyber-supervisor status  # 查看状态
/cyber-supervisor reset  # 重置状态
```

## 目录结构

```
api-security-testing/
├── .opencode/
│   ├── commands/                    # 命令定义
│   │   ├── api-security-testing.md
│   │   ├── scan.md
│   │   ├── test.md
│   │   ├── hook.md
│   │   └── status.md
│   ├── plugins/
│   │   └── cyber-supervisor.js     # 赛博监工插件
│   └── skills/
│       └── api-security-testing/
│           └── SKILL.md            # Agent Skill 定义
├── bin/
│   └── session-start.sh             # 会话启动脚本
├── scripts/
│   └── js_collector.py             # JS 采集脚本
├── references/                      # 参考文档 (12 种漏洞测试)
├── examples/                        # 使用示例
├── templates/                       # 测试模板
├── resources/                       # 资源文件
├── opencode.json                   # 配置
└── README.md
```

## 功能特性

- ✅ **Playwright JS 动态采集** - 无头浏览器执行 JavaScript
- ✅ **API 端点智能发现** - JS 解析 + 流量拦截
- ✅ **漏洞检测** - SQLi/XSS/IDOR/敏感数据等
- ✅ **赛博监工自动监督** - 自动监测进度、失败升级
- ✅ **Markdown 报告生成** - 自动生成测试报告

## 赛博监工机制

当执行扫描时自动激活，监控：

| 事件 | 动作 |
|------|------|
| 工具执行 | 检测失败、发现新漏洞 |
| 失败累积 | 自动压力升级 (L1→L4) |
| 进度过低 | 警告提示 |
| 测试完成 | 通知报告 |

## 权限配置

在 `opencode.json` 中已配置，无需额外设置。

## License

MIT