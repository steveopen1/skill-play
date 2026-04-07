# API Security Testing Suite

多版本 API 安全测试 Skill 集合。

## 目录结构

```
skill-play/
├── agent-plugins/                       # Agent 插件 (开箱即用)
│   ├── CLAUDE-CODE/                   # Claude Code 插件
│   └── OPENCODE/                      # OpenCode 插件
│
├── api-security-testing-refactored/     # Skill 重构版
│   ├── SKILL.md                       # Skill 入口
│   ├── core/                          # 核心能力模块
│   ├── references/                    # 参考文档
│   └── examples/                      # 使用示例
│
├── API-Security-Testing-Optimized/   # Skill 优化版
│   ├── SKILL.md                       # Skill 入口
│   ├── core/                          # 核心能力模块
│   ├── references/                    # 参考文档
│   └── templates/                     # 报告模板
│
├── security-testing/                   # Payload 知识库
│   ├── SKILL.md                       # Skill 入口
│   └── data/                          # Payload 数据
│
└── README.md
```

---

## Agent 插件

### Claude Code 插件

开箱即用的 Claude Code 插件，内置赛博监工自动监督。

```bash
claude --plugin-dir ./agent-plugins/CLAUDE-CODE/api-security-testing
```

| 命令 | 说明 |
|------|------|
| `/api-security-testing:scan [URL]` | 完整扫描 |
| `/api-security-testing:hook on/off` | 开启/关闭赛博监工 |

### OpenCode 插件

开箱即用的 OpenCode 插件，内置赛博监工自动监督。

**安装方式：**

```bash
# 方式1: npm 安装（推荐）
npm install opencode-api-security-testing

# 方式2: 复制到项目 .opencode 目录
cp -r agent-plugins/OPENCODE/api-security-testing <project>/.opencode/skills/
```

### 使用方式

```
@cyber-supervisor 对 https://target.com 进行完整 API 安全测试
```

---

## api-security-testing-refactored

符合 skill-creator 规范的 Skill 重构版。

### 设计理念

| 理念 | 说明 |
|------|------|
| Skill 是框架 | SKILL.md 定义决策流程，core/ 提供执行能力 |
| 语义分析优先 | 路径模式只是线索，需要分析接口语义 |
| 模块化能力池 | core/ 是能力池，根据目标特征动态组合 |

### 触发词

- 安全测试、安全审计、渗透测试
- 漏洞检测、安全评估
- api安全、接口安全

### 强制要求

1. **必须使用 Playwright** 进行 JS 动态采集
2. **必须拦截所有 XHR/Fetch 请求**
3. **必须模拟用户交互** 触发动态 API
4. **必须处理 HTTPS 证书问题**

---

## API-Security-Testing-Optimized

Skill 优化版，集成推理引擎和策略池。

### 核心能力

- **多维度漏洞检测** - D1-D6 综合评分
- **云存储检测** - OSS/COS/S3/MinIO
- **GraphQL 检测** - 嵌套遍历/权限绕过
- **推理引擎** - 智能决策

### 漏洞判定算法

```
RiskScore = D1×0.15 + D2×0.20 + D3×0.25 + D4×0.20 + D5×0.15 + D6×0.05
```

---

## security-testing

渗透测试 Payload 知识库。

### 漏洞类别

| 类别 | 说明 |
|------|------|
| SQL 注入 | MySQL/MSSQL/PostgreSQL/Oracle/MongoDB/Redis |
| XSS | 反射型、存储型、DOM 型 |
| SSRF | 敏感 URI、绕过技术 |
| CSRF | Token 绕过 |

### 攻击链模板

每个漏洞目录包含：
- 基础 Payload
- WAF 绕过
- 攻击链
- 检测脚本

---

## 赛博监工 (Cyber Supervisor)

自主监督机制，失败时自动压力升级。参考 **oh-my-openagent** 的 orchestration 模式。

### Agent 角色

| Agent | 模式参考 | 职责 |
|-------|---------|------|
| cyber-supervisor | Sisyphus (主协调器) | Task.launch 委派子 agent |
| probing-miner | Hephaestus (深度工作者) | 漏洞挖掘、攻击链构造 |
| resource-specialist | Hephaestus (深度工作者) | Playwright 动态采集 |

### 压力升级

| 失败次数 | 等级 | 动作 |
|---------|------|------|
| 2次 | L1 | 切换方法 |
| 3次 | L2 | Task.launch 委派 resource-specialist |
| 5次 | L3 | Task.launch 委派 probing-miner |
| 7次+ | L4 | 组合委派两个 agent |

### Task.launch 委派 (OpenCode)

```javascript
// 委派资源采集
await Task.launch("resource-specialist", {
  description: "采集目标 JS 资源",
  prompt: `目标: ${targetUrl}\n使用 Playwright 采集动态内容。`
})

// 委派漏洞挖掘
await Task.launch("probing-miner", {
  description: "挖掘 SQL 注入",
  prompt: `端点: ${endpoint}\n参考漏洞指南进行测试。`
})
```

### Claude Code 委派

Claude Code 使用主对话请求方式委派：

```
请生成一个 endpoint-specialist subagent 来探测 /admin/api/users 端点
```

---

## License

MIT
