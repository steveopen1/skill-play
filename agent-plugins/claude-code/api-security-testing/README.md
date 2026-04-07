# API Security Testing - Claude Code 插件

**全自动 API 安全审计 Skill** — 基于 Claude Code Agent Teams 的多智能体协作安全分析框架

> 用户只需提供目标 URL，Skill 自动完成从侦察到生成完整安全报告的全流程。

---

## 前置条件

### 1. 安装 Claude Code CLI

```bash
# macOS
brew install claude-code

# 或通过 npm
npm install -g @anthropic-ai/claude-code

# 验证安装
claude --version
```

详细安装说明请参考 [Claude Code 官方文档](https://docs.anthropic.com/en/docs/claude-code)。

### 2. Python 依赖

本插件需要以下 Python 包：

```bash
# 核心依赖
pip install playwright requests beautifulsoup4

# 安装 Playwright 浏览器（必须）
playwright install chromium

# 如果需要处理 HTTPS 证书问题
pip install urllib3 certifi
```

---

## 安装

### 方式一：复制到用户 Skills 目录（推荐）

```bash
# 克隆仓库
git clone https://github.com/steveopen1/skill-play.git

# 复制插件到用户目录
cp -r skill-play/agent-plugins/claude-code/api-security-testing ~/.claude/skills/api-security-testing

# 验证安装
ls ~/.claude/skills/api-security-testing
```

### 方式二：项目内使用

如果希望在项目目录内使用：

```bash
# 在项目根目录创建 .claude 目录
mkdir -p .claude/skills

# 复制插件
cp -r agent-plugins/claude-code/api-security-testing .claude/skills/api-security-testing
```

### 方式三：npm 安装（未来支持）

```bash
npm install @steveopen1/claude-code-api-security-testing
```

---

## 使用方法

### 方式一：直接对话（推荐）

在 Claude Code 中直接发出指令：

```
安全测试 https://target.com
```

### 方式二：使用完整命令

```
/api-security-testing:scan https://target.com
```

### 方式三：多种触发方式

```
# 基础安全测试
安全测试 https://target.com
漏洞检测 https://target.com
渗透测试 https://target.com

# 完整流程测试
全流程测试 https://target.com
完整测试 https://target.com
API安全评估 https://target.com

# 指定目标
帮我测试 https://example.com 的安全性
对这个API进行安全审计 https://api.target.com
```

---

## 工作流程

```
用户输入: "安全测试 https://example.com"
         │
         ▼
┌─────────────────────────────────────┐
│  Phase 1: 侦察与发现                 │
│  ├─ HTTP/HTTPS 探测                 │
│  ├─ 技术栈识别 (SPA/传统)            │
│  └─ API 端点发现                    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 2: 分析与分类                  │
│  ├─ 端点分类 (认证/用户/订单/配置)    │
│  ├─ 响应类型分析 (JSON/HTML/WAF)     │
│  └─ 敏感信息识别                     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 3: 漏洞测试                   │
│  ├─ SQL注入测试                      │
│  ├─ IDOR越权测试                    │
│  ├─ JWT测试                         │
│  ├─ 敏感信息泄露                    │
│  └─ 业务逻辑测试                    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 4: 验证与确认                 │
│  ├─ 10维度验证                      │
│  ├─ 误报排除                        │
│  └─ 利用链构造                      │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 5: 报告生成                   │
│  └─ 安全评估报告                    │
└─────────────────────────────────────┘
```

---

## 目录结构

```
api-security-testing/
├── .claude-plugin/
│   └── plugin.json                  # 插件清单
├── commands/                        # 命令定义
│   ├── api-security-testing.md
│   └── api-security-testing-scan.md
├── agents/
│   └── cyber-supervisor.md          # 赛博监工 Agent
├── skills/
│   └── api-security-testing/
│       └── SKILL.md                 # Skill 定义（核心）
├── core/                            # Python 测试引擎
│   ├── collectors/                  # 信息采集
│   ├── analyzers/                  # 分析模块
│   ├── testers/                    # 测试模块
│   └── verifiers/                 # 验证模块
├── references/                     # 参考文档
│   └── vulnerabilities/            # 漏洞知识库 (12个)
├── examples/                        # 使用示例
└── templates/                      # 测试模板
```

---

## 漏洞覆盖

| 类别 | 说明 |
|------|------|
| SQL注入 | 布尔盲注、时间盲注、报错注入 |
| IDOR | 水平越权、垂直越权 |
| JWT | Token伪造、算法绕过 |
| 敏感信息 | 密码泄露、密钥暴露、个人信息 |
| 业务逻辑 | 订单篡改、支付绕过 |
| 安全配置 | CORS、HSTS、头部安全 |

---

## Python 工具模块

插件提供了独立的 Python 测试工具，可以单独使用：

```bash
# 进入 core 目录
cd core

# 运行完整测试
python3 deep_api_tester_v55.py https://target.com output.md

# 单独使用各模块
python3 -c "from collectors.browser_collect import BrowserCollector; ..."
```

---

## 赛博监工

自动监督机制，失败时自动压力升级：

| 失败次数 | 等级 | 动作 |
|---------|------|------|
| 2次 | L1 | 切换方法 |
| 3次 | L2 | 深度分析 |
| 5次 | L3 | 7点检查清单 |
| 7次+ | L4 | 绝望模式 |

---

## 重要

- 仅用于合法授权的安全测试
- 测试前确保有书面授权

---

## License

MIT
