# API Security Testing - OpenCode 插件

全自动 API 安全测试插件，专为 OpenCode 设计。

## 安装方式

### 方式一：复制到项目
```bash
cp -r api-security-testing <your-project>/.opencode/skills/
```

### 方式二：复制到全局配置
```bash
cp -r api-security-testing ~/.config/opencode/skills/
```

### 方式三：克隆仓库
```bash
git clone https://github.com/steveopen1/skill-play.git
cd skill-play/agent-plugins/OPENCODE
# 复制到你的项目 .opencode 目录
```

## 使用方法

### 激活 Skill
```
/api-security-testing scan https://target.com
```

### 赛博监工控制
```
/cyber-supervisor on    # 开启监督
/cyber-supervisor off   # 关闭监督
/cyber-supervisor status  # 查看状态
```

## 目录结构

```
api-security-testing/
├── .opencode/
│   ├── skills/
│   │   └── api-security-testing/
│   │       └── SKILL.md       # Agent Skill 定义
│   └── plugins/
│       └── cyber-supervisor.js  # 赛博监工插件
├── opencode.json               # 配置
└── README.md
```

## 功能特性

- ✅ Playwright JS 动态采集
- ✅ API 端点智能发现
- ✅ 漏洞检测 (SQLi/XSS/IDOR)
- ✅ 赛博监工自动监督
- ✅ Markdown 报告生成

## 权限配置

在 `opencode.json` 中配置：

```json
{
  "permission": {
    "skill": {
      "*": "allow",
      "api-security-testing": "allow"
    }
  }
}
```

## License

MIT