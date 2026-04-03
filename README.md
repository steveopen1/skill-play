# API Security Testing Suite

安全测试技能集合，包含多种形态的实现。

## 目录结构

```
skill-play/
├── apsec/                          # Claude Code CLI 插件形态
│   ├── .claude-plugin/            # 插件配置
│   │   └── plugin.json
│   ├── skills/                    # Skill 文件
│   ├── agents/                    # 赛博监工 Agent
│   ├── hooks/                     # Hook 配置
│   ├── core/                      # 核心模块 (50+ Python 文件)
│   ├── references/                # 参考文档
│   ├── examples/                   # 示例
│   ├── templates/                 # 模板
│   ├── resources/                  # 资源
│   └── scripts/                    # 脚本
│
├── api-security-testing-refactored/ # Skill Refactored 形态
│   ├── SKILL.md                   # 主 Skill 文件
│   ├── core/                      # 核心能力池
│   ├── references/                 # 参考文档
│   ├── examples/                   # 示例
│   ├── resources/                 # 资源
│   ├── scripts/                   # 脚本
│   └── templates/                  # 模板
│
└── API-Security-Testing-Optimized/ # Optimized 形态
    ├── SKILL.md                   # 主 Skill 文件
    ├── core/                      # 核心模块
    └── ...
```

## 三种形态说明

### 1. Claude Code CLI 插件 (`apsec/`)

符合 Claude Code 官方插件规范的完整插件形态：

```bash
# 使用
claude --plugin-dir ./apsec

/apsec 安全测试 https://target.com
```

**特点**:
- 符合 Claude Code 插件规范
- Hook 机制支持赛博监工自动循环
- 一键安装使用

### 2. Skill Refactored (`api-security-testing-refactored/`)

Skill 参考实现，包含完整文档和测试案例：

```markdown
使用 Skill 指导进行测试
```

**特点**:
- 完整的测试流程文档
- 丰富的漏洞测试模板
- 详细的验证标准

### 3. API-Security-Testing-Optimized (`API-Security-Testing-Optimized/`)

高级编排器版本，集成 Reasoning Engine 和 Strategy Pool：

```python
from orchestrator import EnhancedAgenticOrchestrator
```

**特点**:
- 智能编排器
- 推理引擎
- 策略池
- 测试循环

## 共同特性

- ✅ Playwright 强制 JS 动态采集
- ✅ 6 阶段完整测试流程
- ✅ 赛博监工持续监督
- ✅ 10 维度漏洞验证
- ✅ 利用链构造

## 安装方式

### Claude Code CLI 插件安装

```bash
# 方式一: 使用插件目录
claude --plugin-dir ./apsec

# 方式二: 复制到插件目录
cp -r apsec ~/.claude/plugins/apsec
```

### Skill 形态安装

```bash
# 复制到 OpenClaw skills 目录
cp -r api-security-testing-refactored ~/.openclaw/skills/
cp -r API-Security-Testing-Optimized ~/.openclaw/skills/
```

## License

MIT