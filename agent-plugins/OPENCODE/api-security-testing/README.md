# API Security Testing - OpenCode 插件

全自动 API 安全测试插件，专为 OpenCode 设计。

## 安装方式

### 方式一：复制到项目 .opencode 目录
```bash
# 将插件内容复制到 .opencode/ 目录（不是嵌套目录）
cp -r api-security-testing/* <your-project>/.opencode/
```

### 方式二：复制到全局配置
```bash
cp -r api-security-testing/* ~/.config/opencode/
```

### 方式三：Marketplace 安装（如支持）
```bash
/plugin marketplace add https://github.com/steveopen1/skill-play
/plugin install api-security-testing
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

插件目录结构符合 OpenCode 规范：

```
api-security-testing/
├── skills/                       # Skills（直接可用）
│   └── api-security-testing/     # Skill 名称
│       └── SKILL.md             # Skill 定义
├── agents/                       # Agents（通过 @ 调用）
│   ├── cyber-supervisor.md      # 赛博监工
│   ├── probing-miner.md        # 探测挖掘专家
│   └── resource-specialist.md   # 资源探测专家
├── plugins/                      # Plugins（自动加载）
│   └── cyber-supervisor.js      # 赛博监工插件
├── commands/                     # Commands（/ 命令）
│   └── *.md
├── core/                         # Python 测试引擎
├── references/                   # 参考文档
└── opencode.json               # 配置
```

安装后 `.opencode/` 目录结构：

```
.opencode/
├── skills/
│   └── api-security-testing/
│       └── SKILL.md
├── agents/
│   ├── cyber-supervisor.md
│   ├── probing-miner.md
│   └── resource-specialist.md
├── plugins/
│   └── cyber-supervisor.js
└── opencode.json
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
