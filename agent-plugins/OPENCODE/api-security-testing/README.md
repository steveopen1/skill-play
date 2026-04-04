# API Security Testing - OpenCode 插件

全自动 API 安全测试插件，专为 OpenCode 设计。

## 安装方式

### 方式一：复制到项目 .opencode 目录
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

### 使用 Agent
```
@cyber-supervisor 对 https://target.com 进行完整 API 安全测试
```

### 使用 Skill
```
skills_api_security_testing https://target.com
```

### 使用 Python 测试引擎
```bash
cd api-security-testing
python3 core/deep_api_tester_v55.py https://target.com output.md
```

## 目录结构

```
api-security-testing/              # 插件根目录
├── skills/                       # Skills 目录
│   └── api-security-testing/     # Skill 子目录
│       └── SKILL.md             # Skill 定义
├── commands/                     # Commands 目录
│   └── *.md                     # Command 文件
├── plugins/                      # Plugins 目录
│   └── cyber-supervisor.js      # 赛博监工插件
├── agents/                       # Agents 目录
│   ├── cyber-supervisor.md      # 赛博监工 Agent
│   ├── probing-miner.md        # 探测挖掘专家
│   └── resource-specialist.md   # 资源探测专家
├── core/                         # Python 测试引擎
│   ├── deep_api_tester_v55.py  # API 深度测试
│   ├── browser_tester.py       # 浏览器测试
│   ├── collectors/             # 采集器
│   ├── analyzers/              # 分析器
│   └── cloud_storage_tester.py # 云存储测试
├── references/                   # 参考文档
│   └── vulnerabilities/        # 漏洞测试 (12个)
├── opencode.json               # 插件配置
└── README.md
```

## 功能特性

- **Playwright JS 动态采集** - 无头浏览器执行 JavaScript
- **API 端点智能发现** - JS 解析 + 流量拦截
- **漏洞检测** - SQLi/XSS/IDOR/敏感数据/安全头部
- **赛博监工** - 自动监测进度、失败升级
- **Markdown 报告生成** - 自动生成测试报告
- **Python 测试引擎** - core/ 提供完整测试能力

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
