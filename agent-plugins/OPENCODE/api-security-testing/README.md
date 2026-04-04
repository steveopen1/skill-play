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

### 命令

| 命令 | 说明 |
|------|------|
| `/api-security-testing` | 主命令 - 显示帮助 |
| `/api-security-testing-scan` | 完整扫描 |
| `/api-security-testing-test` | 快速测试 |
| `/api-security-testing-hook` | 赛博监工控制 |
| `/api-security-testing-status` | 查看状态 |

### 示例

```
/api-security-testing-scan https://target.com
```

## 目录结构

```
api-security-testing/
├── .opencode/
│   ├── commands/                        # 命令定义
│   │   ├── api-security-testing.md
│   │   ├── api-security-testing-scan.md
│   │   ├── api-security-testing-test.md
│   │   ├── api-security-testing-hook.md
│   │   └── api-security-testing-status.md
│   ├── plugins/
│   │   └── cyber-supervisor.js          # 赛博监工插件
│   └── skills/
│       └── api-security-testing/
│           └── SKILL.md                # Agent Skill 定义
├── core/                               # Python 测试引擎
│   ├── deep_api_tester_v55.py         # API 深度测试
│   ├── browser_tester.py              # 浏览器测试
│   ├── collectors/                      # 采集器
│   │   ├── js_collector.py
│   │   ├── browser_collector.py
│   │   └── api_path_finder.py
│   ├── analyzers/                      # 分析器
│   │   ├── api_parser.py
│   │   ├── response_analyzer.py
│   │   └── sensitive_finder.py
│   └── cloud_storage_tester.py        # 云存储测试
├── references/                        # 参考文档
│   ├── vulnerabilities/                # 漏洞测试 (12个)
│   ├── workflows.md                   # 工作流
│   ├── rest-guidance.md              # REST API 测试
│   ├── graphql-guidance.md           # GraphQL 测试
│   ├── test-matrix.md                # 测试矩阵
│   └── severity-model.md             # 严重性模型
├── bin/
│   └── session-start.sh              # 会话启动脚本
├── scripts/
│   └── js_collector.py               # JS 采集脚本
├── examples/                         # 使用示例
├── templates/                        # 测试模板
├── resources/                        # 资源文件
├── opencode.json                    # 配置
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

**自动激活**：执行扫描时赛博监工自动开启监督。

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
| SQL 注入 | 布尔盲注、时间盲注、报错注入 |
| XSS | 反射型、存储型、DOM 型 |
| IDOR | 水平越权、垂直越权 |
| JWT | Token 伪造、算法绕过 |
| 敏感数据 | 密码、密钥、个人信息 |
| 安全配置 | CORS、HSTS、头部 |

## License

MIT
