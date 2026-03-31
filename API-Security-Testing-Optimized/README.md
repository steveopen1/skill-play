# API Security Testing Skill v3.0

[![Version](https://img.shields.io/badge/version-3.0-blue)](https://github.com/steveopen1/skill-play)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Agent 驱动的自动化 API 渗透测试专家**

## 核心特性

### Agentic Reasoning Engine
- 多层级推理: Surface → Context → Causal → Strategic
- 8 种推理规则自动触发
- 洞察驱动的闭环测试

### 动态策略系统
- 8 种预定义策略自动切换
- WAF 绕过、限速自适应、敏感操作保护
- 基于上下文的智能决策

### 全维度上下文感知
- 技术栈识别 (前端/后端/数据库/WAF)
- 网络环境监控 (代理/限速)
- 安全态势分析 (认证/敏感度)

## 快速开始

### 作为 Skill 使用

```bash
# 完整扫描
请对这个 API 进行全面的安全测试

# 检查特定漏洞
帮我检查有没有 SQL 注入漏洞

# 生成报告
生成一份 API 安全测试报告
```

### 作为脚本使用

```bash
# 安装依赖
pip install -r requirements.txt

# 运行测试
python -m scripts.orchestrator https://target.com
```

## 目录结构

```
api-security-testing/
├── SKILL.md                      # Skill 入口文档 (YAML frontmatter)
├── README.md                     # 本文件
├── requirements.txt              # Python 依赖
├── scripts/
│   ├── __init__.py
│   ├── orchestrator.py         # 增强型编排器
│   ├── reasoning_engine.py      # 推理引擎
│   ├── context_manager.py       # 上下文管理器
│   ├── strategy_pool.py        # 策略池
│   ├── testing_loop.py         # 测试循环
│   ├── api_tester.py           # API 测试器
│   └── report_generator.py      # 报告生成器
├── resources/
│   ├── sqli.json               # SQL 注入 payload
│   ├── xss.json                # XSS payload
│   └── dom_xss.json            # DOM XSS payload
├── examples/
│   └── usage-examples.md        # 使用示例
└── templates/
    └── api_test.yaml           # 测试流程模板
```

## 漏洞测试维度

| 维度 | 说明 | 组件 |
|------|------|------|
| V1 | SQL 注入 | Boolean/Union/Error/Blind |
| V2 | XSS | Reflected/Stored/DOM |
| V3 | 命令注入 | RCE 测试 |
| V4 | 路径遍历 | LFI/RFI |
| V5 | IDOR | 越权测试 |
| V6 | 认证绕过 | JWT/Session |
| V7 | 速率限制 | 暴力防护 |
| V8 | 信息泄露 | API 文档 |

## 测试流程

```
1. 侦察 (Recon)     → 识别入口点、技术栈
2. 发现 (Discovery) → 端点枚举、JS 分析
3. 推理 (Reasoning) → 数据流分析、策略选择
4. 测试 (Testing)   → 漏洞检测、验证
5. 报告 (Reporting) → 生成修复建议
```

## 编程接口

```python
from scripts.orchestrator import EnhancedAgenticOrchestrator

orch = EnhancedAgenticOrchestrator("https://target.com")
result = orch.execute(max_iterations=100, max_duration=3600)

# 获取洞察
insights = orch.get_insights()

# 获取上下文
context = orch.get_context()
```

## 道德声明

本工具**仅限授权测试使用**。

- ✅ 用于自己拥有的系统
- ✅ 用于获得书面授权的系统
- ✅ 用于安全研究和教育目的

---

*最后更新：2026-03-31*
